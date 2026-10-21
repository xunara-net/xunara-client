use std::{
    collections::BTreeSet,
    os::fd::OwnedFd,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;

use crate::{config::Config, model::NetworkMap};

/// 平台层只负责操作系统权限和 TUN，不参与人类身份或设备审批。
pub trait Host: Send + Sync {
    fn protect(&self, descriptor: i32) -> Result<()>;
    fn configure(&self, configuration: &VpnConfiguration) -> Result<OwnedFd>;
    fn local_networks(&self) -> Result<Vec<IpNet>>;
    fn local_endpoints(&self, port: u16) -> Vec<String>;
    fn dns_servers(&self) -> Result<Vec<std::net::SocketAddr>> {
        Ok(Vec::new())
    }
    fn event(&self, value: &Value);
}

static HOST: RwLock<Option<Arc<dyn Host>>> = RwLock::new(None);

pub fn install(host: Arc<dyn Host>) -> Result<()> {
    let mut active = HOST.write().map_err(|_| anyhow::anyhow!("平台锁已损坏"))?;
    ensure!(active.is_none(), "已有移动客户端运行");
    *active = Some(host);
    Ok(())
}

/// 必须在运行时、隧道和后台任务全部销毁之后调用。
pub fn uninstall() {
    if let Ok(mut active) = HOST.write() {
        *active = None;
    }
}

pub fn host() -> Result<Arc<dyn Host>> {
    HOST.read()
        .map_err(|_| anyhow::anyhow!("平台锁已损坏"))?
        .clone()
        .context("移动平台尚未初始化")
}

pub fn publish(value: &Value) {
    if let Ok(host) = host() {
        host.event(value);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VpnConfiguration {
    pub addresses: Vec<IpNet>,
    pub routes: Vec<IpNet>,
    pub skipped_routes: Vec<IpNet>,
    pub mtu: u16,
    pub dns_servers: Vec<std::net::IpAddr>,
    pub search_domains: Vec<String>,
}

impl VpnConfiguration {
    pub fn from_map(config: &Config, map: &NetworkMap, local: &[IpNet]) -> Result<Self> {
        Self::from_map_with_dns(config, map, local, &[])
    }

    pub fn from_map_with_dns(
        config: &Config,
        map: &NetworkMap,
        local: &[IpNet],
        fallback: &[std::net::SocketAddr],
    ) -> Result<Self> {
        let node = map.node.as_ref().context("缺少本机映射")?;
        ensure!(node.valid(), "设备未授权或已过期");
        ensure!(!config.snat, "Android 使用用户态转发，不修改内核 NAT");
        let addresses = node
            .addresses
            .iter()
            .map(|prefix| IpNet::from(prefix.addr()))
            .collect::<BTreeSet<_>>();
        ensure!(
            !addresses.is_empty() && addresses.len() <= 16,
            "本机地址数量无效"
        );
        // 手机已有 LAN 优先，不能用更具体的 VPN 路由悄悄截走内网流量。
        ensure!(
            addresses
                .iter()
                .all(|address| !overlaps_any(*address, local)),
            "设备地址与当前局域网冲突，请在用户中心调整地址"
        );
        let mut routes = BTreeSet::new();
        for peer in map.nodes()?.into_iter().filter(|peer| peer.valid()) {
            routes.extend(
                peer.addresses
                    .iter()
                    .map(|prefix| IpNet::from(prefix.addr())),
            );
            if config.accept_routes {
                routes.extend(
                    peer.allowed_ips
                        .into_iter()
                        .filter(|prefix| prefix.prefix_len() > 0),
                );
            }
        }
        routes.retain(|route| route.prefix_len() > 0 && !addresses.contains(route));
        let skipped_routes = routes
            .iter()
            .filter(|route| overlaps_any(**route, local))
            .copied()
            .collect();
        routes.retain(|route| !overlaps_any(*route, local));
        // 显式选定出口后始终保留接管路由；出口撤销/离线不能静默泄露到本地公网。
        if !config.exit_node_id.is_empty() {
            let mut excluded = local.to_vec();
            excluded.extend(
                [
                    "0.0.0.0/8",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "224.0.0.0/4",
                    "::1/128",
                    "fe80::/10",
                    "ff00::/8",
                ]
                .into_iter()
                .map(|prefix| prefix.parse::<IpNet>().expect("constant prefix")),
            );
            for default in ["0.0.0.0/0", "::/0"] {
                let mut remaining = vec![default.parse::<IpNet>()?];
                for exclusion in &excluded {
                    remaining = remaining
                        .into_iter()
                        .flat_map(|route| subtract(route, *exclusion))
                        .collect();
                    ensure!(remaining.len() <= 4096, "出口排除路由超过上限");
                }
                routes.extend(remaining);
            }
        }
        routes.extend(addresses.iter().copied());
        // 操作系统与内核必须使用相同的退避输入，否则系统向旧地址发包而代理监听新地址。
        let dns = crate::dns::DnsPlan::new(config, map, local, fallback)?;
        if let Some(address) = dns.as_ref().map(|dns| dns.address) {
            routes.insert(address.into());
        }
        ensure!(routes.len() <= 4096, "移动端路由超过上限");
        Ok(Self {
            addresses: addresses.into_iter().collect(),
            routes: routes.into_iter().collect(),
            skipped_routes,
            mtu: config.mtu,
            dns_servers: dns
                .as_ref()
                .map(|dns| vec![dns.address])
                .unwrap_or_default(),
            search_domains: dns.map(|dns| dns.domains).unwrap_or_default(),
        })
    }
}

// 在用户态拆分默认路由，兼容 Android 8–12 没有 excludeRoute 的 Builder。
fn subtract(route: IpNet, excluded: IpNet) -> Vec<IpNet> {
    if excluded.prefix_len() <= route.prefix_len() && excluded.contains(&route.addr()) {
        return Vec::new();
    }
    if !route.contains(&excluded.addr()) {
        return vec![route];
    }
    route
        .subnets(route.prefix_len() + 1)
        .expect("splittable prefix")
        .flat_map(|child| subtract(child, excluded))
        .collect()
}

fn overlaps_any(route: IpNet, networks: &[IpNet]) -> bool {
    networks
        .iter()
        .filter(|network| network.prefix_len() > 0)
        .any(|network| network.contains(&route.addr()) || route.contains(&network.addr()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map() -> NetworkMap {
        let mut map = NetworkMap::default();
        map.apply(json!({"Node":{"ID":1,"Key":"nodekey:own","MachineAuthorized":true,"Addresses":["100.80.0.1/24"]},
            "Peers":[{"ID":2,"Key":"nodekey:peer","MachineAuthorized":true,"Addresses":["100.80.0.2/24"],
            "AllowedIPs":["100.80.0.2/32","192.168.8.0/24","10.77.0.0/16","0.0.0.0/0"]}]})).unwrap();
        map
    }

    #[test]
    fn mobile_routes_are_host_scoped_and_preserve_lan() {
        let configuration = VpnConfiguration::from_map(
            &Config {
                accept_routes: true,
                ..Config::default()
            },
            &map(),
            &["192.168.8.0/24".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(
            configuration.addresses,
            vec!["100.80.0.1/32".parse::<IpNet>().unwrap()]
        );
        assert!(
            configuration
                .routes
                .contains(&"10.77.0.0/16".parse().unwrap())
        );
        assert!(
            !configuration
                .routes
                .iter()
                .any(|route| route.prefix_len() == 0)
        );
        assert_eq!(
            configuration.skipped_routes,
            vec!["192.168.8.0/24".parse::<IpNet>().unwrap()]
        );
        let config = Config {
            accept_routes: false,
            ..Config::default()
        };
        let configuration = VpnConfiguration::from_map(&config, &map(), &[]).unwrap();
        assert_eq!(configuration.routes.len(), 2);
    }

    #[test]
    fn mobile_preserves_own_lan_and_rejects_kernel_snat() {
        assert!(
            VpnConfiguration::from_map(
                &Config::default(),
                &map(),
                &["100.80.0.0/24".parse().unwrap()]
            )
            .is_err()
        );
        let mut map = map();
        map.node.as_mut().unwrap().machine_authorized = false;
        assert!(VpnConfiguration::from_map(&Config::default(), &map, &[]).is_err());
        let config = Config {
            snat: true,
            ..Config::default()
        };
        assert!(VpnConfiguration::from_map(&config, &self::map(), &[]).is_err());
    }

    #[test]
    fn exit_preserves_lan_and_keeps_blackhole_when_peer_is_removed() {
        let config = Config {
            exit_node_id: "exit-stable".into(),
            ..Config::default()
        };
        let local = vec!["192.168.8.0/24".parse().unwrap()];
        let mut map = map();
        let before = VpnConfiguration::from_map(&config, &map, &local).unwrap();
        assert!(
            before
                .routes
                .iter()
                .any(|route| route.contains(&"1.1.1.1".parse::<std::net::IpAddr>().unwrap()))
        );
        assert!(
            before.routes.iter().any(
                |route| route.contains(&"2606:4700::1111".parse::<std::net::IpAddr>().unwrap())
            )
        );
        assert!(
            !before
                .routes
                .iter()
                .any(|route| route.contains(&"192.168.8.2".parse::<std::net::IpAddr>().unwrap()))
        );
        assert_eq!(before.dns_servers.len(), 1);
        map.peers.clear();
        let after = VpnConfiguration::from_map(&config, &map, &local).unwrap();
        assert!(
            after
                .routes
                .iter()
                .any(|route| route.contains(&"1.1.1.1".parse::<std::net::IpAddr>().unwrap()))
        );
    }

    #[test]
    fn os_dns_and_proxy_share_the_same_collision_retreat() {
        let config = Config {
            accept_dns: true,
            ..Config::default()
        };
        let map = map();
        let fallback = ["100.100.100.100:53".parse().unwrap()];
        let proxy = crate::dns::DnsPlan::new(&config, &map, &[], &fallback)
            .unwrap()
            .unwrap();
        let configuration =
            VpnConfiguration::from_map_with_dns(&config, &map, &[], &fallback).unwrap();
        assert_eq!(
            proxy.address,
            "100.100.100.101".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(configuration.dns_servers, vec![proxy.address]);
        assert!(configuration.routes.contains(&proxy.address.into()));
        assert!(
            !configuration
                .routes
                .contains(&"100.100.100.100/32".parse().unwrap())
        );
    }
}
