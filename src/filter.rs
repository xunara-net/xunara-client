use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use ipnet::IpNet;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Packet {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
}

impl Packet {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let version = bytes.first()? >> 4;
        let (source, destination, protocol, offset, length) = match version {
            4 if bytes.len() >= 20 => {
                let offset = usize::from(bytes[0] & 15) * 4;
                let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
                // 不支持 IP 分片的首版一律丢弃，不能只检查首片端口后放行其余分片。
                if offset < 20
                    || offset > bytes.len()
                    || length != bytes.len()
                    || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0
                {
                    return None;
                }
                (
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).ok()?)),
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).ok()?)),
                    bytes[9],
                    offset,
                    length,
                )
            }
            6 if bytes.len() >= 40 => {
                let length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]])) + 40;
                if length != bytes.len() {
                    return None;
                }
                (
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)),
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?)),
                    bytes[6],
                    40,
                    length,
                )
            }
            _ => return None,
        };
        let (source_port, destination_port) = match protocol {
            6 | 17 if length >= offset + if protocol == 6 { 20 } else { 8 } => (
                u16::from_be_bytes([bytes[offset], bytes[offset + 1]]),
                u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]),
            ),
            1 | 58 if length >= offset + 8 => {
                let identifier =
                    if matches!((protocol, bytes[offset]), (1, 0 | 8) | (58, 128 | 129)) {
                        u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]])
                    } else {
                        0
                    };
                (identifier, identifier)
            }
            _ => return None,
        };
        Some(Self {
            source,
            destination,
            protocol,
            source_port,
            destination_port,
        })
    }

    fn reversed(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            source_port: self.destination_port,
            destination_port: self.source_port,
            ..self
        }
    }
}

enum AddressMatch {
    Any,
    Network(IpNet),
    Range(IpAddr, IpAddr),
}

impl AddressMatch {
    fn parse(raw: &str) -> Option<Self> {
        if raw == "*" {
            return Some(Self::Any);
        }
        if let Ok(network) = raw.parse::<IpNet>() {
            return Some(Self::Network(network));
        }
        if let Ok(address) = raw.parse::<IpAddr>() {
            return Some(Self::Network(address.into()));
        }
        let (first, last) = raw.split_once('-')?;
        let (first, last) = (first.parse::<IpAddr>().ok()?, last.parse::<IpAddr>().ok()?);
        if first.is_ipv4() != last.is_ipv4() || first > last {
            return None;
        }
        Some(Self::Range(first, last))
    }

    fn contains(&self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Network(network) => network.contains(&address),
            Self::Range(first, last) => {
                first.is_ipv4() == address.is_ipv4() && *first <= address && address <= *last
            }
        }
    }
}

struct Destination {
    address: AddressMatch,
    first: u16,
    last: u16,
}
struct Rule {
    sources: Vec<AddressMatch>,
    destinations: Vec<Destination>,
    protocols: Vec<u8>,
}

#[derive(Default)]
pub struct Filter {
    rules: Vec<Rule>,
    responses: HashMap<Packet, Instant>,
}

impl Filter {
    pub fn compile(values: &[Value]) -> Result<Self> {
        ensure!(values.len() <= 4096, "ACL 规则超过精简客户端上限");
        let mut rules = Vec::new();
        for value in values {
            // 应用能力授权不等于网络访问权限；不支持的旧位掩码规则也不能扩大解释。
            if value
                .get("CapGrant")
                .and_then(Value::as_array)
                .is_some_and(|grants| !grants.is_empty())
                || value
                    .get("SrcBits")
                    .and_then(Value::as_array)
                    .is_some_and(|bits| !bits.is_empty())
            {
                continue;
            }
            let sources = value
                .get("SrcIPs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter_map(AddressMatch::parse)
                .collect::<Vec<_>>();
            let mut destinations = Vec::new();
            for destination in value
                .get("DstPorts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(address) = destination
                    .get("IP")
                    .and_then(Value::as_str)
                    .and_then(AddressMatch::parse)
                else {
                    continue;
                };
                let first = destination
                    .pointer("/Ports/First")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let last = destination
                    .pointer("/Ports/Last")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                ensure!(first <= last && last <= 65535, "ACL 端口范围无效");
                destinations.push(Destination {
                    address,
                    first: first as u16,
                    last: last as u16,
                });
            }
            let protocols = match value.get("IPProto").and_then(Value::as_array) {
                Some(values) if !values.is_empty() => values
                    .iter()
                    .filter_map(Value::as_u64)
                    .filter_map(|value| value.try_into().ok())
                    .collect(),
                _ => vec![1, 6, 17, 58],
            };
            rules.push(Rule {
                sources,
                destinations,
                protocols,
            });
        }
        Ok(Self {
            rules,
            responses: HashMap::new(),
        })
    }

    pub fn outgoing(&mut self, packet: Packet) {
        self.responses.retain(|_, expiry| *expiry > Instant::now());
        if self.responses.len() >= 4096 {
            self.responses.clear();
        }
        self.responses
            .insert(packet.reversed(), Instant::now() + Duration::from_secs(60));
    }

    pub fn incoming(&mut self, packet: Packet) -> bool {
        self.established(packet) || self.permits(packet)
    }

    pub fn permits(&self, packet: Packet) -> bool {
        self.rules.iter().any(|rule| {
            rule.protocols.contains(&packet.protocol)
                && rule
                    .sources
                    .iter()
                    .any(|source| source.contains(packet.source))
                && rule.destinations.iter().any(|destination| {
                    destination.address.contains(packet.destination)
                        && (matches!(packet.protocol, 1 | 58)
                            || (destination.first <= packet.destination_port
                                && packet.destination_port <= destination.last))
                })
        })
    }

    pub fn established(&self, packet: Packet) -> bool {
        self.responses
            .get(&packet)
            .is_some_and(|expiry| *expiry > Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn packet() -> Packet {
        Packet {
            source: "100.64.1.1".parse().unwrap(),
            destination: "192.168.50.2".parse().unwrap(),
            protocol: 6,
            source_port: 42000,
            destination_port: 443,
        }
    }

    #[test]
    fn default_deny_ports_protocols_and_stateful_return() {
        let mut filter = Filter::default();
        assert!(!filter.incoming(packet()));
        filter.outgoing(packet());
        assert!(filter.incoming(packet().reversed()));
        let mut wrong = packet().reversed();
        wrong.destination_port += 1;
        assert!(!filter.incoming(wrong));
        let mut filter = Filter::compile(&[json!({"SrcIPs":["100.64.1.0/24"],"IPProto":[6],"DstPorts":[{"IP":"192.168.50.2","Ports":{"First":443,"Last":443}}]})]).unwrap();
        assert!(filter.incoming(packet()));
        let mut wrong = packet();
        wrong.protocol = 17;
        assert!(!filter.incoming(wrong));
        wrong = packet();
        wrong.destination_port = 22;
        assert!(!filter.incoming(wrong));
    }

    #[test]
    fn capabilities_and_unknown_selectors_never_grant_traffic() {
        let mut filter = Filter::compile(&[
            json!({"SrcIPs":["*"],"CapGrant":[{"Dsts":["*"],"Caps":["admin"]}]}),
        ])
        .unwrap();
        assert!(!filter.incoming(packet()));
        assert!(AddressMatch::parse("cap:admin").is_none());
        assert!(
            AddressMatch::parse("100.64.0.1-100.64.0.9")
                .unwrap()
                .contains("100.64.0.5".parse().unwrap())
        );
    }

    #[test]
    fn rejects_truncation_fragments_and_ipv6_extensions() {
        assert!(Packet::parse(&[0x45; 8]).is_none());
        let mut bytes = [0; 28];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
        bytes[9] = 17;
        assert!(Packet::parse(&bytes).is_some());
        bytes[6] = 0x20;
        assert!(Packet::parse(&bytes).is_none());
        let mut ipv6 = [0; 48];
        ipv6[0] = 0x60;
        ipv6[5] = 8;
        ipv6[6] = 44;
        assert!(Packet::parse(&ipv6).is_none());
    }
}
