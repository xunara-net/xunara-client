use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: String,
    pub state_dir: PathBuf,
    pub interface: String,
    pub hostname: String,
    pub listen: SocketAddr,
    pub advertise_routes: Vec<IpNet>,
    pub accept_routes: bool,
    pub accept_dns: bool,
    pub exit_node_id: String,
    pub snat: bool,
    pub mtu: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: String::new(),
            state_dir: "/var/lib/xunara-client".into(),
            interface: "xunara0".into(),
            hostname: "xunara-linux".into(),
            listen: "0.0.0.0:41641".parse().expect("constant socket"),
            advertise_routes: Vec::new(),
            accept_routes: false,
            accept_dns: false,
            exit_node_id: String::new(),
            snat: false,
            mtu: 1280,
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let config: Self =
            serde_json::from_slice(&std::fs::read(path)?).context("配置文件不是有效 JSON")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        server_url(&self.server)?;
        ensure!(
            self.exit_node_id.len() <= 128
                && self
                    .exit_node_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
            "出口节点标识无效"
        );
        #[cfg(target_os = "linux")]
        ensure!(
            !self.accept_dns && self.exit_node_id.is_empty(),
            "DNS 与出口选择仅由 Android VPN 管理；Linux 不修改系统 DNS 或默认路由"
        );
        ensure!(self.state_dir.is_absolute(), "状态目录必须为绝对路径");
        ensure!(
            valid_interface(&self.interface),
            "网卡名称必须为 1–15 位字母、数字或下划线"
        );
        ensure!(
            !self.hostname.is_empty()
                && self.hostname.len() <= 63
                && self
                    .hostname
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "设备名称必须为 1–63 位字母、数字或连字符"
        );
        ensure!(
            (1280..=1420).contains(&self.mtu),
            "MTU 必须在 1280–1420 之间"
        );
        ensure!(
            self.listen.is_ipv4(),
            "首版外层监听使用 IPv4；隧道内支持 IPv4 / IPv6"
        );
        ensure!(self.advertise_routes.len() <= 64, "最多广播 64 个子网");
        for route in &self.advertise_routes {
            ensure!(
                route.prefix_len() > 0 && route.addr() == route.network(),
                "子网必须是规范 CIDR；首版不支持默认路由 / Exit Node"
            );
            ensure!(
                !route.addr().is_loopback()
                    && !route.addr().is_multicast()
                    && !route.addr().is_unspecified(),
                "不能广播回环、多播或未指定地址"
            );
        }
        Ok(())
    }
}

pub fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn server_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("控制面地址无效")?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.host_str().is_some()
            && url.path() == "/",
        "使用控制面根地址，不能包含凭据、查询或租户路径"
    );
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "公网控制面必须使用有效 HTTPS；HTTP 仅允许回环测试"
    );
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_unsafe_configuration() {
        for raw in [
            "http://example.com",
            "https://u:p@example.com",
            "https://example.com/t/a",
            "https://example.com/?token=x",
        ] {
            assert!(server_url(raw).is_err());
        }
        assert!(server_url("http://127.0.0.1:9000").is_ok());
        assert!(server_url("https://fakeop4.onbed.cn:9090").is_ok());
        for name in [
            "",
            "../../x",
            "eth0;reboot",
            "name-with-dash",
            "abcdefghijklmnop",
        ] {
            assert!(!valid_interface(name));
        }
        let config = Config {
            server: "https://example.com".into(),
            advertise_routes: vec!["0.0.0.0/0".parse().unwrap()],
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }
}
