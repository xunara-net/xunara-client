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
}

impl VpnConfiguration {
    pub fn from_map(config: &Config, map: &NetworkMap, local: &[IpNet]) -> Result<Self> {
        let node = map.node.as_ref().context("缺少本机映射")?;
        ensure!(node.valid(), "设备未授权或已过期");
        ensure!(
            config.advertise_routes.is_empty() && !config.snat,
            "Android 仅接收子网路由，不提供需要 root 的子网转发"
        );
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
        // 即使暂时没有其他设备，仍只安装本机 host route，不接管默认出口和 DNS。
        routes.extend(addresses.iter().copied());
        ensure!(routes.len() <= 4096, "移动端路由超过上限");
        Ok(Self {
            addresses: addresses.into_iter().collect(),
            routes: routes.into_iter().collect(),
            skipped_routes,
            mtu: config.mtu,
        })
    }
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
    fn mobile_rejects_own_lan_overlap_and_router_mode() {
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
}
