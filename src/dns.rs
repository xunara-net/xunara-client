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
    Encrypted {
        address: SocketAddr,
        name: String,
        path: Option<String>,
    },
}

impl Target {
    pub fn address(&self) -> SocketAddr {
        match self {
            Self::Dns(address) | Self::PeerHttp(address) => *address,
            Self::Encrypted { address, .. } => *address,
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
    peer_defaults: Option<Vec<Target>>,
    tunnel_routes: Vec<IpNet>,
    exit: bool,
    pub dnssec_validate: bool,
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
        fallback: &[SocketAddr],
    ) -> Result<Option<Self>> {
        // 出口模式必须同时接管解析，防止把查询发给原 Wi-Fi 的 DNS。
        if !config.accept_dns && config.exit_node_id.is_empty() {
            return Ok(None);
        }
        let node = map.node.as_ref().context("DNS 缺少本机映射")?;
        let peers = map.nodes()?;
        let mut occupied = node
            .addresses
            .iter()
            .chain(peers.iter().flat_map(|peer| peer.addresses.iter()))
            .copied()
            .collect::<Vec<_>>();
        // 不仅避让设备地址，也避让远程已批准网段与解析器，防止 DNS 转发重新进入自己。
        occupied.extend(
            peers
                .iter()
                .flat_map(|peer| peer.allowed_ips.iter())
                .filter(|prefix| prefix.prefix_len() > 0),
        );
        occupied.extend(
            map.dns
                .resolvers
                .iter()
                .chain(&map.dns.fallback_resolvers)
                .chain(map.dns.routes.values().flatten())
                .filter_map(|resolver| {
                    resolver.addr.parse::<IpAddr>().ok().or_else(|| {
                        resolver
                            .addr
                            .parse::<SocketAddr>()
                            .ok()
                            .map(|address| address.ip())
                    })
                })
                .map(IpNet::from),
        );
        occupied.extend(fallback.iter().map(|address| IpNet::from(address.ip())));
        for peer in &peers {
            occupied.extend(
                peer.self_v4_masq
                    .map(IpAddr::V4)
                    .into_iter()
                    .chain(peer.self_v6_masq.map(IpAddr::V6))
                    .map(IpNet::from),
            );
        }
        for resolver in map
            .dns
            .resolvers
            .iter()
            .chain(&map.dns.fallback_resolvers)
            .chain(map.dns.routes.values().flatten())
            .chain(&config.dns_resolvers)
        {
            occupied.extend(
                resolver
                    .bootstrap_resolution
                    .iter()
                    .copied()
                    .map(IpNet::from),
            );
            occupied.extend(
                targets(std::slice::from_ref(resolver))?
                    .iter()
                    .map(|target| IpNet::from(target.address().ip())),
            );
        }
        occupied.extend(
            map.dns
                .extra_records
                .iter()
                .filter_map(|record| record.value.parse::<IpAddr>().ok())
                .map(IpNet::from),
        );
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
            peer_defaults: None,
            tunnel_routes: Vec::new(),
            exit: !config.exit_node_id.is_empty(),
            dnssec_validate: config.dnssec_validate,
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
            if !matches!(record.record_type.as_str(), "" | "A" | "AAAA") {
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
            plan.defaults = targets(if config.dns_resolvers.is_empty() {
                &map.dns.resolvers
            } else {
                &config.dns_resolvers
            })?;
            if plan.defaults.is_empty() {
                plan.defaults = targets(&map.dns.fallback_resolvers)?;
            }
            if plan.defaults.is_empty() {
                plan.defaults = fallback.iter().copied().map(Target::Dns).collect();
            }
            // 官方 Android 出口的 peerapi 使用宿主解析器，不把平台公共 DNS 当作手机系统 DNS。
            // 显式指定的加密解析器或 DNSSEC 仍走用户配置，不能因出口查询绕过这些安全设置。
            if config.dns_resolvers.is_empty() && !config.dnssec_validate && !fallback.is_empty() {
                plan.peer_defaults = Some(fallback.iter().copied().map(Target::Dns).collect());
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

    pub fn answer_for_peer(&self, query: &Message) -> Answer {
        match (self.answer(query), &self.peer_defaults) {
            // MagicDNS 和权威 NXDOMAIN 仍在本地回答，不能向运营商泄露网络内设备名。
            (Answer::Forward(_), Some(targets)) => Answer::Forward(targets.clone()),
            (answer, _) => answer,
        }
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

pub fn targets(resolvers: &[DnsResolver]) -> Result<Vec<Target>> {
    resolvers
        .iter()
        .map(|resolver| -> Result<Vec<Target>> {
            ensure!(
                resolver.addr.len() <= 2048 && resolver.bootstrap_resolution.len() <= 4,
                "DNS 解析器配置超过上限"
            );
            if resolver.addr.starts_with("https://") || resolver.addr.starts_with("tls://") {
                let url = url::Url::parse(&resolver.addr)?;
                ensure!(
                    url.username().is_empty()
                        && url.password().is_none()
                        && url.query().is_none()
                        && url.fragment().is_none(),
                    "加密 DNS 地址不可包含凭据、查询参数或片段"
                );
                let name = url
                    .host_str()
                    .context("DNS 解析器缺少主机名")?
                    .trim_matches(['[', ']'])
                    .to_owned();
                let https = url.scheme() == "https";
                ensure!(
                    https || url.path().is_empty() || url.path() == "/",
                    "DoT 仅填写主机和端口"
                );
                let port = url.port().unwrap_or(if https { 443 } else { 853 });
                ensure!(port > 0, "DNS 解析器端口无效");
                let addresses = if let Ok(address) = name.parse::<IpAddr>() {
                    vec![address]
                } else {
                    resolver.bootstrap_resolution.clone()
                };
                ensure!(
                    !addresses.is_empty(),
                    "域名形式的 DoH / DoT 解析器需要引导 IP，避免 VPN DNS 递归"
                );
                return addresses
                    .into_iter()
                    .map(|address| {
                        ensure!(
                            !address.is_unspecified() && !address.is_multicast(),
                            "DNS 引导地址无效"
                        );
                        Ok(Target::Encrypted {
                            address: SocketAddr::new(address, port),
                            name: name.clone(),
                            path: https.then(|| {
                                if url.path().is_empty() {
                                    "/dns-query".to_owned()
                                } else {
                                    url.path().to_owned()
                                }
                            }),
                        })
                    })
                    .collect();
            }
            let address = resolver
                .addr
                .parse::<IpAddr>()
                .map(|address| SocketAddr::new(address, 53))
                .or_else(|_| resolver.addr.parse::<SocketAddr>())
                .context("DNS 解析器须为 IP、IP:端口、https:// 或 tls:// 地址")?;
            ensure!(
                address.port() > 0
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast(),
                "DNS 解析器地址无效"
            );
            Ok(vec![Target::Dns(address)])
        })
        .collect::<Result<Vec<_>>>()
        .map(|groups| groups.into_iter().flatten().collect())
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
    let mut response = Message::from_vec(bytes)?;
    ensure!(
        response.metadata.message_type == MessageType::Response
            && response.metadata.id == query.metadata.id
            && response.queries == query.queries
            && response.metadata.op_code == query.metadata.op_code,
        "DNS 回包不属于当前查询"
    );
    response.metadata.authentic_data = false;
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
    #[test]
    fn encrypted_resolvers_require_safe_urls_and_explicit_bootstrap() {
        for address in [
            "http://resolver.test/dns-query",
            "https://user:secret@resolver.test/dns-query",
            "https://resolver.test/dns-query?token=secret",
            "tls://resolver.test/path",
            "https://resolver.test/dns-query",
        ] {
            assert!(
                targets(&[DnsResolver {
                    addr: address.into(),
                    ..DnsResolver::default()
                }])
                .is_err()
            );
        }
        for address in [
            "https://resolver.test/dns-query",
            "tls://resolver.test:8853",
        ] {
            let parsed = targets(&[DnsResolver {
                addr: address.into(),
                bootstrap_resolution: vec!["192.0.2.53".parse().unwrap()],
            }])
            .unwrap();
            assert_eq!(parsed.len(), 1);
            assert!(
                matches!(&parsed[0], Target::Encrypted { name, .. } if name == "resolver.test")
            );
        }
        assert!(matches!(
            targets(&[DnsResolver {
                addr: "https://[2001:db8::53]/dns-query".into(),
                ..DnsResolver::default()
            }])
            .unwrap()[0],
            Target::Encrypted { .. }
        ));
    }
    use hickory_proto::{op::Query, rr::RecordType};
    use serde_json::json;

    fn map() -> NetworkMap {
        let mut map = NetworkMap::default();
        map.apply(json!({"Node":{"ID":1,"Key":"own","Name":"phone.mesh.test.","MachineAuthorized":true,"Addresses":["100.80.0.1/32"]},
            "Peers":[{"ID":2,"Key":"peer","Name":"nas.mesh.test.","MachineAuthorized":true,"Addresses":["100.80.0.2/32","fd7a:115c:a1e0::2/128"]}],
            "DNSConfig":{"Proxied":true,"Domains":["mesh.test"],"Routes":{"office.test":[{"Addr":"10.77.0.1:5353"}]},"Resolvers":[{"Addr":"9.9.9.9"}],"ExtraRecords":[{"Name":"extra.mesh.test","Type":"A","Value":"10.0.0.5"},{"Name":"extra6.mesh.test","Type":"AAAA","Value":"fd7a:115c:a1e0::5"}]}})).unwrap();
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
            ("extra6.mesh.test", RecordType::AAAA),
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
            &["8.8.8.8:53".parse().unwrap()],
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

    #[test]
    fn system_dns_retains_ipv6_scope_without_changing_local_network_prefixes() {
        let mut map = map();
        map.dns.resolvers.clear();
        let address = "[fe80::1%7]:53".parse::<SocketAddr>().unwrap();
        let plan = DnsPlan::new(
            &Config {
                accept_dns: true,
                ..Config::default()
            },
            &map,
            &[],
            &[address],
        )
        .unwrap()
        .unwrap();
        let Answer::Forward(targets) = plan.answer(&ask("example.com", RecordType::A)) else {
            panic!("fallback")
        };
        assert_eq!(targets[0].address(), address);
    }

    #[test]
    fn dns_address_avoids_remote_subnets_and_its_own_upstream() {
        let mut map = map();
        map.apply(json!({"PeersChanged":[{"ID":2,"Key":"peer","MachineAuthorized":true,"Addresses":["100.80.0.2/32"],"AllowedIPs":["100.100.100.0/24"]}]})).unwrap();
        let config = Config {
            accept_dns: true,
            ..Config::default()
        };
        let plan = DnsPlan::new(&config, &map, &[], &[]).unwrap().unwrap();
        assert_eq!(plan.address, "198.18.0.1".parse::<IpAddr>().unwrap());
        map.peers.clear();
        map.dns.resolvers = vec![DnsResolver {
            addr: "100.100.100.100".into(),
            ..DnsResolver::default()
        }];
        let plan = DnsPlan::new(&config, &map, &[], &[]).unwrap().unwrap();
        assert_eq!(plan.address, "100.100.100.101".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn peer_dns_preserves_local_names_explicit_security_and_selected_exit() {
        let fallback = ["192.0.2.53:53".parse().unwrap()];
        let config = Config {
            accept_dns: true,
            ..Config::default()
        };
        let plan = DnsPlan::new(&config, &map(), &[], &fallback)
            .unwrap()
            .unwrap();
        let question = ask("example.com", RecordType::A);
        let Answer::Forward(normal) = plan.answer(&question) else {
            panic!("network DNS");
        };
        let Answer::Forward(peer) = plan.answer_for_peer(&question) else {
            panic!("physical DNS");
        };
        assert_eq!(normal[0].address(), "9.9.9.9:53".parse().unwrap());
        assert_eq!(peer[0].address(), fallback[0]);
        for name in [
            "nas.mesh.test",
            "missing.mesh.test",
            "2.0.80.100.in-addr.arpa",
        ] {
            assert!(matches!(
                plan.answer_for_peer(&ask(name, RecordType::A)),
                Answer::Local(_)
            ));
        }
        for secured in [
            Config {
                dnssec_validate: true,
                ..config.clone()
            },
            Config {
                dns_resolvers: vec![DnsResolver {
                    addr: "https://192.0.2.54/dns-query".into(),
                    ..DnsResolver::default()
                }],
                ..config.clone()
            },
            Config {
                exit_node_id: "missing-exit".into(),
                ..config.clone()
            },
        ] {
            let plan = DnsPlan::new(&secured, &map(), &[], &fallback)
                .unwrap()
                .unwrap();
            let Answer::Forward(normal) = plan.answer(&question) else {
                panic!("network DNS");
            };
            let Answer::Forward(peer) = plan.answer_for_peer(&question) else {
                panic!("peer DNS");
            };
            assert_eq!(normal, peer);
            assert!(!peer.iter().any(|target| target.address() == fallback[0]));
            if !secured.exit_node_id.is_empty() {
                assert!(peer.is_empty());
            }
        }
    }
}
