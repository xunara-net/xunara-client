use std::{collections::BTreeMap, net::SocketAddr};

use anyhow::{Result, ensure};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: u64,
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
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Hostinfo {
    #[serde(rename = "OS")]
    pub os: String,
}

impl Node {
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
}

#[derive(Clone, Default)]
pub struct NetworkMap {
    pub node: Option<Node>,
    pub peers: BTreeMap<u64, Value>,
    pub derp: DerpMap,
    pub dns: DnsConfig,
    pub filter: Vec<Value>,
    filter_groups: BTreeMap<String, Vec<Value>>,
}

impl NetworkMap {
    pub fn apply(&mut self, update: Value) -> Result<()> {
        ensure!(update.is_object(), "网络映射必须为 JSON 对象");
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
                dns.domains.len() <= 256 && dns.domains.iter().all(|domain| domain.len() <= 253),
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
                        if key != "NodeID" && !value.is_null() {
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
    use serde_json::json;

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
