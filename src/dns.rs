use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

use anyhow::{Context, Result, ensure};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, Name, RData, Record, rdata::PTR},
};
use ipnet::IpNet;

use crate::{
    config::Config,
    model::{DnsResolver, NetworkMap},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Dns(SocketAddr),
    PeerHttp(SocketAddr),
}

impl Target {
    pub fn address(&self) -> SocketAddr {
        match self {
            Self::Dns(address) | Self::PeerHttp(address) => *address,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsPlan {
    pub address: IpAddr,
    pub domains: Vec<String>,
    pub addresses: Vec<IpAddr>,
    records: BTreeMap<Name, Vec<RData>>,
    routes: BTreeMap<Name, Vec<Target>>,
    defaults: Vec<Target>,
    tunnel_routes: Vec<IpNet>,
    exit: bool,
}

pub enum Answer {
    Local(Message),
    Forward(Vec<Target>),
}

impl DnsPlan {
    pub fn new(
        config: &Config,
        map: &NetworkMap,
        local: &[IpNet],
        fallback: &[IpAddr],
    ) -> Result<Option<Self>> {
        // 出口模式必须同时接管解析，防止把查询发给原 Wi-Fi 的 DNS。
        if !config.accept_dns && config.exit_node_id.is_empty() {
            return Ok(None);
        }
        let node = map.node.as_ref().context("DNS 缺少本机映射")?;
        let peers = map.nodes()?;
        let occupied = node
            .addresses
            .iter()
            .chain(peers.iter().flat_map(|peer| peer.addresses.iter()))
            .copied()
            .collect::<Vec<_>>();
        let address = (100..=254)
            .map(|last| IpAddr::from([100, 100, 100, last]))
            .chain((1..=254).map(|last| IpAddr::from([198, 18, 0, last])))
            .find(|address| {
                !local
                    .iter()
                    .chain(&occupied)
                    .any(|prefix| prefix.contains(address))
            })
            .context("找不到不与局域网冲突的 VPN DNS 地址，请调整网络配置")?;
        let mut plan = Self {
            address,
            domains: Vec::new(),
            addresses: node.addresses.iter().map(IpNet::addr).collect(),
            records: BTreeMap::new(),
            routes: BTreeMap::new(),
            defaults: Vec::new(),
            tunnel_routes: Vec::new(),
            exit: !config.exit_node_id.is_empty(),
        };
        for domain in &map.dns.domains {
            plan.domains.push(
                valid_name(domain)?
                    .to_ascii()
                    .trim_end_matches('.')
                    .to_owned(),
            );
        }
        if map.dns.proxied {
            for peer in std::iter::once(node)
                .chain(peers.iter())
                .filter(|peer| peer.valid())
            {
                if peer.name.is_empty() {
                    continue;
                }
                let name = valid_name(&peer.name)?;
                for address in &peer.addresses {
                    plan.add(name.clone(), RData::from(address.addr()));
                    plan.add(Name::from(address.addr()), RData::PTR(PTR(name.clone())));
                }
            }
            if let Some((_, suffix)) = node.name.trim_end_matches('.').split_once('.') {
                plan.routes.insert(valid_name(suffix)?, Vec::new());
            }
        }
        for record in &map.dns.extra_records {
            if !record.record_type.is_empty() {
                continue;
            }
            if let Ok(address) = record.value.parse::<IpAddr>() {
                plan.add(valid_name(&record.name)?, RData::from(address));
            }
        }
        for (suffix, resolvers) in &map.dns.routes {
            plan.routes.insert(valid_name(suffix)?, targets(resolvers)?);
        }
        for peer in peers.iter().filter(|peer| peer.valid()) {
            plan.tunnel_routes.extend(
                peer.addresses
                    .iter()
                    .map(|prefix| IpNet::from(prefix.addr())),
            );
            if config.accept_routes {
                plan.tunnel_routes.extend(
                    peer.allowed_ips
                        .iter()
                        .filter(|prefix| prefix.prefix_len() > 0),
                );
            }
        }
        plan.tunnel_routes.retain(|route| {
            !local
                .iter()
                .any(|prefix| prefix.contains(&route.addr()) || route.contains(&prefix.addr()))
        });
        if plan.exit {
            // 与官方客户端一致，使用选中出口广告的 peerapi4/6 DNS-over-WireGuard 服务。
            if let Some(peer) = peers
                .iter()
                .find(|peer| peer.stable_id == config.exit_node_id && peer.exit_node())
                && let Some(hostinfo) = &peer.hostinfo
            {
                for address in &peer.addresses {
                    let proto = if address.addr().is_ipv4() {
                        "peerapi4"
                    } else {
                        "peerapi6"
                    };
                    if let Some(service) = hostinfo
                        .services
                        .iter()
                        .find(|service| service.proto == proto && service.port > 0)
                    {
                        plan.defaults.push(Target::PeerHttp(SocketAddr::new(
                            address.addr(),
                            service.port,
                        )));
                    }
                }
            }
            // 没有出口解析器就 SERVFAIL，绝不回退本地网络或其他出口。
        } else {
            plan.defaults = targets(&map.dns.resolvers)?;
            if plan.defaults.is_empty() {
                plan.defaults = targets(&map.dns.fallback_resolvers)?;
            }
            if plan.defaults.is_empty() {
                plan.defaults = fallback
                    .iter()
                    .map(|address| Target::Dns(SocketAddr::new(*address, 53)))
                    .collect();
            }
        }
        Ok(Some(plan))
    }

    fn add(&mut self, name: Name, data: RData) {
        let records = self.records.entry(name.to_lowercase()).or_default();
        if !records.contains(&data) {
            records.push(data);
        }
    }

    pub fn tunneled(&self, target: &Target) -> bool {
        self.exit
            || self
                .tunnel_routes
                .iter()
                .any(|prefix| prefix.contains(&target.address().ip()))
    }

    pub fn answer(&self, query: &Message) -> Answer {
        let question = &query.queries[0];
        let mut name = question.name().to_lowercase();
        name.set_fqdn(true);
        if let Some(records) = self.records.get(&name) {
            let mut response = reply(query, ResponseCode::NoError);
            response.metadata.authoritative = true;
            if question.query_class() == DNSClass::IN {
                response.answers.extend(
                    records
                        .iter()
                        .filter(|record| record.record_type() == question.query_type())
                        .map(|record| {
                            Record::from_rdata(question.name().clone(), 60, record.clone())
                        }),
                );
            }
            return Answer::Local(response);
        }
        if let Some((_, targets)) = self
            .routes
            .iter()
            .filter(|(suffix, _)| suffix.zone_of(&name))
            .max_by_key(|(suffix, _)| suffix.num_labels())
        {
            if targets.is_empty() {
                let mut response = reply(query, ResponseCode::NXDomain);
                response.metadata.authoritative = true;
                return Answer::Local(response);
            }
            if !self.exit {
                return Answer::Forward(targets.clone());
            }
        }
        Answer::Forward(self.defaults.clone())
    }
}

fn valid_name(raw: &str) -> Result<Name> {
    ensure!(
        !raw.is_empty() && raw.len() <= 254 && raw.is_ascii(),
        "DNS 域名无效"
    );
    let mut name = Name::from_ascii(raw)?.to_lowercase();
    name.set_fqdn(true);
    Ok(name)
}

fn targets(resolvers: &[DnsResolver]) -> Result<Vec<Target>> {
    resolvers
        .iter()
        .map(|resolver| {
            let address = resolver
                .addr
                .parse::<IpAddr>()
                .map(|address| SocketAddr::new(address, 53))
                .or_else(|_| resolver.addr.parse::<SocketAddr>())
                .context("本版 DNS 解析器须为 IP 或 IP:端口")?;
            ensure!(
                address.port() > 0
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast(),
                "DNS 解析器地址无效"
            );
            Ok(Target::Dns(address))
        })
        .collect()
}

pub fn query(bytes: &[u8]) -> Result<Message> {
    ensure!((12..=16384).contains(&bytes.len()), "DNS 请求长度无效");
    let query = Message::from_vec(bytes)?;
    ensure!(
        query.metadata.message_type == MessageType::Query
            && query.metadata.op_code == OpCode::Query
            && query.queries.len() == 1
            && query.answers.is_empty()
            && query.authorities.is_empty(),
        "只接受单问题 DNS 查询"
    );
    Ok(query)
}

pub fn reply(query: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.response_code = code;
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries = query.queries.clone();
    response.edns = query.edns.clone();
    response
}

pub fn verified(query: &Message, bytes: &[u8]) -> Result<Message> {
    let response = Message::from_vec(bytes)?;
    ensure!(
        response.metadata.message_type == MessageType::Response
            && response.metadata.id == query.metadata.id
            && response.queries == query.queries
            && response.metadata.op_code == query.metadata.op_code,
        "DNS 回包不属于当前查询"
    );
    Ok(response)
}

pub fn encode(response: &Message, limit: usize) -> Result<Vec<u8>> {
    let bytes = response.to_vec()?;
    if bytes.len() <= limit {
        return Ok(bytes);
    }
    Ok(response.truncate().to_vec()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{op::Query, rr::RecordType};
    use serde_json::json;

    fn map() -> NetworkMap {
        let mut map = NetworkMap::default();
        map.apply(json!({"Node":{"ID":1,"Key":"own","Name":"phone.mesh.test.","MachineAuthorized":true,"Addresses":["100.80.0.1/32"]},
            "Peers":[{"ID":2,"Key":"peer","Name":"nas.mesh.test.","MachineAuthorized":true,"Addresses":["100.80.0.2/32","fd7a:115c:a1e0::2/128"]}],
            "DNSConfig":{"Proxied":true,"Domains":["mesh.test"],"Routes":{"office.test":[{"Addr":"10.77.0.1:5353"}]},"Resolvers":[{"Addr":"9.9.9.9"}],"ExtraRecords":[{"Name":"extra.mesh.test","Value":"10.0.0.5"}]}})).unwrap();
        map
    }
    fn ask(name: &str, kind: RecordType) -> Message {
        let mut query = Message::query();
        query
            .queries
            .push(Query::query(Name::from_ascii(name).unwrap(), kind));
        query
    }
    #[test]
    fn opt_in_records_reverse_split_and_no_private_query_leak() {
        assert!(
            DnsPlan::new(&Config::default(), &map(), &[], &[])
                .unwrap()
                .is_none()
        );
        let plan = DnsPlan::new(
            &Config {
                accept_dns: true,
                ..Config::default()
            },
            &map(),
            &[],
            &[],
        )
        .unwrap()
        .unwrap();
        for (name, kind) in [
            ("NaS.Mesh.Test.", RecordType::A),
            ("nas.mesh.test", RecordType::AAAA),
            ("2.0.80.100.in-addr.arpa", RecordType::PTR),
            ("extra.mesh.test", RecordType::A),
        ] {
            let Answer::Local(response) = plan.answer(&ask(name, kind)) else {
                panic!("must resolve locally")
            };
            assert_eq!(response.answers.len(), 1);
        }
        let Answer::Local(response) = plan.answer(&ask("missing.mesh.test", RecordType::A)) else {
            panic!("private name leaked")
        };
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        let Answer::Forward(targets) = plan.answer(&ask("foo.office.test", RecordType::A)) else {
            panic!("split")
        };
        assert_eq!(targets[0].address().port(), 5353);
        let Answer::Forward(targets) = plan.answer(&ask("example.com", RecordType::A)) else {
            panic!("default")
        };
        assert_eq!(
            targets[0].address().ip(),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }
    #[test]
    fn dns_address_retreats_on_lan_conflict_and_exit_never_falls_back() {
        let config = Config {
            exit_node_id: "missing-exit".into(),
            ..Config::default()
        };
        let plan = DnsPlan::new(
            &config,
            &map(),
            &["100.100.100.0/24".parse().unwrap()],
            &["8.8.8.8".parse().unwrap()],
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.address, "198.18.0.1".parse::<IpAddr>().unwrap());
        let Answer::Forward(targets) = plan.answer(&ask("example.com", RecordType::A)) else {
            panic!("default")
        };
        assert!(targets.is_empty());
        let mut response = reply(&ask("example.com", RecordType::A), ResponseCode::NoError);
        response.metadata.id += 1;
        assert!(
            verified(
                &ask("example.com", RecordType::A),
                &response.to_vec().unwrap()
            )
            .is_err()
        );
        assert!(query(&[0; 12]).is_err());
        let mut bytes = vec![0; 12];
        bytes[5] = 1;
        bytes.extend([0xc0, 12, 0, 1, 0, 1]);
        assert!(query(&bytes).is_err());
    }
}
