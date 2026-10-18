use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use anyhow::{Result, ensure};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: u64,
    #[serde(rename = "StableID")]
    pub stable_id: String,
    pub user: u64,
    pub name: String,
    pub key: String,
    pub disco_key: String,
    pub addresses: Vec<IpNet>,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Vec<IpNet>,
    pub primary_routes: Vec<IpNet>,
    pub endpoints: Vec<SocketAddr>,
    #[serde(rename = "HomeDERP")]
    pub home_derp: u16,
    #[serde(rename = "DERP")]
    pub legacy_derp: String,
    pub key_expiry: Option<String>,
    pub expired: bool,
    pub is_jailed: bool,
    pub machine_authorized: bool,
    pub hostinfo: Option<Hostinfo>,
    #[serde(rename = "SelfNodeV4MasqAddrForThisPeer")]
    pub self_v4_masq: Option<Ipv4Addr>,
    #[serde(rename = "SelfNodeV6MasqAddrForThisPeer")]
    pub self_v6_masq: Option<Ipv6Addr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourcePolicy {
    key: String,
    addresses: Vec<IpNet>,
    allowed_ips: Vec<IpNet>,
    expiry: Option<String>,
    authorized: bool,
    masq_v4: Option<Ipv4Addr>,
    masq_v6: Option<Ipv6Addr>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Hostinfo {
    #[serde(rename = "OS")]
    pub os: String,
    pub services: Vec<Service>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Service {
    pub proto: String,
    pub port: u16,
}

impl Node {
    pub(crate) fn source_policy(&self) -> SourcePolicy {
        SourcePolicy {
            key: self.key.clone(),
            addresses: self.addresses.clone(),
            allowed_ips: self.allowed_ips.clone(),
            expiry: self.key_expiry.clone(),
            authorized: self.valid(),
            masq_v4: self.self_v4_masq,
            masq_v6: self.self_v6_masq,
        }
    }

    pub fn exit_node(&self) -> bool {
        self.valid()
            && !self.stable_id.is_empty()
            && self
                .allowed_ips
                .contains(&"0.0.0.0/0".parse().expect("constant prefix"))
            && self
                .allowed_ips
                .contains(&"::/0".parse().expect("constant prefix"))
    }
    pub fn relay_region(&self) -> u16 {
        if self.home_derp > 0 {
            self.home_derp
        } else {
            self.legacy_derp
                .strip_prefix("127.3.3.40:")
                .and_then(|region| region.parse().ok())
                .unwrap_or(0)
        }
    }

    pub fn valid(&self) -> bool {
        !self.expired
            && self.self_v4_masq.is_none_or(|address| {
                !address.is_unspecified()
                    && !address.is_loopback()
                    && !address.is_multicast()
                    && !address.is_broadcast()
            })
            && self.self_v6_masq.is_none_or(|address| {
                !address.is_unspecified() && !address.is_loopback() && !address.is_multicast()
            })
            && !self.is_jailed
            && self.machine_authorized
            && self.key_expiry.as_ref().is_none_or(|expiry| {
                expiry.starts_with("0001-")
                    || time::OffsetDateTime::parse(
                        expiry,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .is_ok_and(|expiry| expiry > time::OffsetDateTime::now_utc())
            })
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpNode {
    pub host_name: String,
    pub cert_name: String,
    #[serde(rename = "DERPPort")]
    pub derp_port: i32,
    #[serde(rename = "STUNPort")]
    pub stun_port: i32,
    #[serde(rename = "IPv4")]
    pub ipv4: String,
    #[serde(rename = "STUNOnly")]
    pub stun_only: bool,
    pub insecure_for_tests: bool,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpRegion {
    pub region_code: String,
    pub region_name: String,
    pub nodes: Vec<DerpNode>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpMap {
    pub regions: BTreeMap<u16, DerpRegion>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DnsConfig {
    pub proxied: bool,
    pub domains: Vec<String>,
    pub resolvers: Vec<DnsResolver>,
    pub fallback_resolvers: Vec<DnsResolver>,
    #[serde(deserialize_with = "dns_routes")]
    pub routes: BTreeMap<String, Vec<DnsResolver>>,
    pub extra_records: Vec<DnsRecord>,
}

fn dns_routes<'de, Deserializer: serde::Deserializer<'de>>(
    deserializer: Deserializer,
) -> std::result::Result<BTreeMap<String, Vec<DnsResolver>>, Deserializer::Error> {
    let routes = Option::<BTreeMap<String, Option<Vec<DnsResolver>>>>::deserialize(deserializer)?
        .unwrap_or_default();
    Ok(routes
        .into_iter()
        .map(|(suffix, resolvers)| (suffix, resolvers.unwrap_or_default()))
        .collect())
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DnsResolver {
    pub addr: String,
    pub bootstrap_resolution: Vec<std::net::IpAddr>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DnsRecord {
    pub name: String,
    #[serde(rename = "Type")]
    pub record_type: String,
    pub value: String,
}

#[derive(Clone, Default)]
pub struct NetworkMap {
    pub node: Option<Node>,
    pub peers: BTreeMap<u64, Value>,
    pub derp: DerpMap,
    pub dns: DnsConfig,
    pub filter: Vec<Value>,
    pub user_profiles: BTreeMap<u64, UserProfile>,
    filter_groups: BTreeMap<String, Vec<Value>>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct UserProfile {
    #[serde(rename = "ID")]
    pub id: u64,
    pub login_name: String,
}

impl NetworkMap {
    pub fn apply(&mut self, update: Value) -> Result<()> {
        ensure!(update.is_object(), "网络映射必须为 JSON 对象");
        if let Some(authority) = update.get("TKAInfo").filter(|value| !value.is_null()) {
            ensure!(authority.is_object(), "Tailnet Lock 状态格式无效");
            // 尚未实现本机信任根与 AUM 同步时，不能靠控制面声称“已签名”继续传输。
            ensure!(
                authority.get("Disabled").and_then(Value::as_bool) == Some(true),
                "此网络启用了 Tailnet Lock；本版本尚未完成本机签名链验证，已拒绝建立不受保护的连接"
            );
        }
        if let Some(profiles) = update.get("UserProfiles").and_then(Value::as_array) {
            ensure!(profiles.len() <= 512, "用户展示资料超过上限");
            for profile in profiles {
                let profile: UserProfile = serde_json::from_value(profile.clone())?;
                ensure!(profile.login_name.len() <= 320, "用户展示名称超过上限");
                self.user_profiles.insert(profile.id, profile);
            }
            ensure!(self.user_profiles.len() <= 512, "用户展示资料超过上限");
        }
        if let Some(node) = update.get("Node").filter(|node| !node.is_null()) {
            self.node = Some(serde_json::from_value(node.clone())?);
        }
        if let Some(derp) = update.get("DERPMap").filter(|derp| !derp.is_null()) {
            self.derp = serde_json::from_value(derp.clone())?;
        }
        // 与官方 MapResponse 一致：缺失 / null 表示沿用，空对象表示显式清空。
        if let Some(dns) = update.get("DNSConfig").filter(|dns| !dns.is_null()) {
            let dns: DnsConfig = serde_json::from_value(dns.clone())?;
            ensure!(
                dns.domains.len() <= 256
                    && dns.domains.iter().all(|domain| domain.len() <= 253)
                    && dns.resolvers.len() <= 16
                    && dns.fallback_resolvers.len() <= 16
                    && dns.routes.len() <= 256
                    && dns
                        .routes
                        .iter()
                        .all(|(suffix, resolvers)| suffix.len() <= 253 && resolvers.len() <= 16)
                    && dns.extra_records.len() <= 4096
                    && dns
                        .resolvers
                        .iter()
                        .chain(&dns.fallback_resolvers)
                        .chain(dns.routes.values().flatten())
                        .all(|resolver| resolver.addr.len() <= 2048
                            && resolver.bootstrap_resolution.len() <= 4),
                "DNS 搜索域超过上限"
            );
            self.dns = dns;
        }
        if let Some(peers) = update.get("Peers").and_then(Value::as_array) {
            self.peers.clear();
            self.put_peers(peers)?;
        }
        if let Some(peers) = update.get("PeersChanged").and_then(Value::as_array) {
            self.put_peers(peers)?;
        }
        if let Some(removed) = update.get("PeersRemoved").and_then(Value::as_array) {
            for peer in removed {
                if let Some(identity) = peer.as_u64() {
                    self.peers.remove(&identity);
                }
            }
        }
        if let Some(patches) = update.get("PeersChangedPatch").and_then(Value::as_array) {
            for patch in patches {
                if let Some(peer) = patch
                    .get("NodeID")
                    .and_then(Value::as_u64)
                    .and_then(|identity| self.peers.get_mut(&identity))
                    && let (Some(peer), Some(patch)) = (peer.as_object_mut(), patch.as_object())
                {
                    for (key, value) in patch {
                        // PeerChange.DERPRegion 不是 Node 字段名，不能直接复制后让 serde 忽略。
                        if key == "DERPRegion"
                            && value
                                .as_u64()
                                .is_some_and(|region| region > 0 && region <= 65535)
                        {
                            peer.insert("HomeDERP".into(), value.clone());
                        } else if !value.is_null()
                            && (matches!(
                                key.as_str(),
                                "Endpoints"
                                    | "Key"
                                    | "DiscoKey"
                                    | "KeyExpiry"
                                    | "Online"
                                    | "LastSeen"
                                    | "CapMap"
                                    | "KeySignature"
                            ) || key == "Cap" && value.as_u64().is_some_and(|cap| cap > 0))
                        {
                            peer.insert(key.clone(), value.clone());
                        }
                    }
                }
            }
        }
        if let Some(filter) = update
            .get("PacketFilter")
            .filter(|filter| !filter.is_null())
        {
            self.filter_groups
                .insert("base".into(), serde_json::from_value(filter.clone())?);
        }
        if let Some(groups) = update.get("PacketFilters").and_then(Value::as_object) {
            if let Some(clear) = groups.get("*") {
                ensure!(clear.is_null(), "ACL 清空标记必须为 null");
                self.filter_groups.clear();
            }
            for (name, value) in groups {
                if name == "*" {
                    continue;
                }
                if value.is_null() {
                    self.filter_groups.remove(name);
                } else {
                    self.filter_groups
                        .insert(name.clone(), serde_json::from_value(value.clone())?);
                }
            }
        }
        ensure!(self.filter_groups.len() <= 256, "ACL 分组超过上限");
        self.filter = self.filter_groups.values().flatten().cloned().collect();
        ensure!(self.peers.len() <= 256, "精简客户端最多处理 256 个可见节点");
        Ok(())
    }

    fn put_peers(&mut self, peers: &[Value]) -> Result<()> {
        for peer in peers {
            let node: Node = serde_json::from_value(peer.clone())?;
            ensure!(node.id != 0 && !node.key.is_empty(), "节点缺少身份");
            self.peers.insert(node.id, peer.clone());
        }
        Ok(())
    }

    pub fn nodes(&self) -> Result<Vec<Node>> {
        self.peers
            .values()
            .cloned()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unimplemented_tailnet_lock_cannot_silently_accept_an_authority() {
        let mut map = NetworkMap::default();
        assert!(
            map.apply(serde_json::json!({"TKAInfo":{"Head":"unverified-head"}}))
                .is_err()
        );
        assert!(map.apply(serde_json::json!({"TKAInfo":{}})).is_err());
        assert!(
            map.apply(serde_json::json!({"TKAInfo":{"Disabled":true}}))
                .is_ok()
        );
        assert!(map.apply(serde_json::json!({"TKAInfo":null})).is_ok());
    }
    use serde_json::json;

    #[test]
    fn derp_patch_updates_node_field_and_zero_does_not_clear_home() {
        let mut map = NetworkMap::default();
        map.apply(json!({"Peers":[{"ID":1,"Key":"key","HomeDERP":0,"MachineAuthorized":false}]}))
            .unwrap();
        map.apply(
            json!({"PeersChangedPatch":[{"NodeID":1,"DERPRegion":900,"MachineAuthorized":true}]}),
        )
        .unwrap();
        assert_eq!(map.nodes().unwrap()[0].relay_region(), 900);
        assert!(!map.nodes().unwrap()[0].machine_authorized);
        map.apply(json!({"PeersChangedPatch":[{"NodeID":1,"DERPRegion":0}]}))
            .unwrap();
        assert_eq!(map.nodes().unwrap()[0].relay_region(), 900);
    }

    #[test]
    fn merge_deltas_without_resurrecting_removed_peers_or_filters() {
        let mut map = NetworkMap::default();
        map.apply(json!({"Peers":[{"ID":1,"Key":"key","Endpoints":["127.0.0.1:1"]}], "PacketFilter": [{"SrcIPs":["*"]}]})).unwrap();
        map.apply(json!({"PeersChangedPatch":[{"NodeID":1,"Endpoints":["127.0.0.1:2"]}]}))
            .unwrap();
        assert_eq!(map.nodes().unwrap()[0].endpoints[0].port(), 2);
        map.apply(json!({"PeersRemoved":[1],"PacketFilter":[]}))
            .unwrap();
        assert!(map.peers.is_empty() && map.filter.is_empty());
        map.apply(json!({"PeersChangedPatch":[{"NodeID":1,"Key":"old"}]}))
            .unwrap();
        assert!(map.peers.is_empty());
    }

    #[test]
    fn named_filters_follow_upstream_add_remove_and_clear_semantics() {
        let mut map = NetworkMap::default();
        map.apply(json!({"PacketFilters":{"base":[{"SrcIPs":["a"]}],"other":[{"SrcIPs":["b"]}]}}))
            .unwrap();
        assert_eq!(map.filter.len(), 2);
        map.apply(json!({"PacketFilter":[]})).unwrap();
        assert_eq!(map.filter.len(), 1);
        map.apply(json!({"PacketFilters":{"other":null}})).unwrap();
        assert!(map.filter.is_empty());
        map.apply(json!({"PacketFilters":{"base":[{}]}})).unwrap();
        map.apply(json!({"PacketFilters":{"*":null,"new":[{}]}}))
            .unwrap();
        assert_eq!(map.filter.len(), 1);
        map.apply(json!({"PacketFilters":{"*":null}})).unwrap();
        assert!(map.filter.is_empty());
    }

    #[test]
    fn dns_deltas_preserve_and_clear_metadata_without_changing_system_dns() {
        let mut map = NetworkMap::default();
        map.apply(json!({"DNSConfig":{"Proxied":true,"Domains":["example.test"]}}))
            .unwrap();
        map.apply(json!({"DNSConfig":null})).unwrap();
        assert!(map.dns.proxied);
        assert_eq!(map.dns.domains, vec!["example.test"]);
        map.apply(json!({})).unwrap();
        assert!(map.dns.proxied);
        map.apply(json!({"DNSConfig":{}})).unwrap();
        assert!(!map.dns.proxied && map.dns.domains.is_empty());
        assert!(
            map.apply(json!({"DNSConfig":{"Domains":["x".repeat(254)]}}))
                .is_err()
        );
    }
}
#[test]
fn source_policy_changes_on_identity_routes_and_masquerade_but_not_display_or_transport() {
    let original = Node {
        key: "nodekey:first".into(),
        machine_authorized: true,
        addresses: vec!["100.80.0.1/32".parse().unwrap()],
        ..Node::default()
    };
    let mut changed = original.clone();
    changed.name = "renamed.core.test.".into();
    changed.home_derp = 900;
    changed.endpoints = vec!["192.0.2.1:41641".parse().unwrap()];
    assert_eq!(original.source_policy(), changed.source_policy());
    changed.key = "nodekey:another-machine".into();
    assert_ne!(original.source_policy(), changed.source_policy());
    changed = original.clone();
    changed.allowed_ips = vec!["192.168.1.0/24".parse().unwrap()];
    assert_ne!(original.source_policy(), changed.source_policy());
    changed = original.clone();
    changed.self_v4_masq = Some("100.80.9.1".parse().unwrap());
    assert_ne!(original.source_policy(), changed.source_policy());
    changed = original.clone();
    changed.machine_authorized = false;
    assert_ne!(original.source_policy(), changed.source_policy());
}
