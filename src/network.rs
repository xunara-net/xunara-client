use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io,
    net::{IpAddr, SocketAddr},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde_json::Value;
use tokio::{
    io::{AsyncWriteExt, unix::AsyncFd},
    process::Command,
};

use crate::{
    config::{Config, valid_interface},
    model::NetworkMap,
};

pub struct Tun {
    descriptor: AsyncFd<File>,
    pub name: String,
}

impl Tun {
    pub async fn create(config: &Config) -> Result<Self> {
        ensure!(valid_interface(&config.interface), "无效网卡名称");
        ensure!(
            !Path::new("/sys/class/net").join(&config.interface).exists(),
            "网卡已经存在，拒绝接管其他程序网卡"
        );
        let descriptor = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        let mut request = [0u8; 40];
        request[..config.interface.len()].copy_from_slice(config.interface.as_bytes());
        request[16..18].copy_from_slice(&(0x0001u16 | 0x1000 | 0x8000).to_ne_bytes());
        // SAFETY: Linux TUNSETIFF 接收 ifreq；缓冲至少 40 字节且名称/flags 已初始化。
        let created =
            unsafe { libc::ioctl(descriptor.as_raw_fd(), 0x400454ca, request.as_mut_ptr()) };
        ensure!(
            created == 0,
            "创建独占 TUN 失败：{}",
            io::Error::last_os_error()
        );
        // SAFETY: fd 由 File 独占持有，只在 AsyncFd 销毁时关闭；没有外部代码重用此 fd。
        let descriptor = unsafe { AsyncFd::register(descriptor)? };
        let tun = Self {
            descriptor,
            name: config.interface.clone(),
        };
        ip(&[
            "link",
            "set",
            "dev",
            &tun.name,
            "mtu",
            &config.mtu.to_string(),
            "up",
        ])
        .await?;
        Ok(tun)
    }

    pub async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.descriptor.readable().await?;
            match ready.try_io(|descriptor| {
                // SAFETY: bytes 是有效的可写切片，fd 在 AsyncFd 生命周期内有效。
                let length = unsafe {
                    libc::read(
                        descriptor.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                };
                if length < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(length as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    pub async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        loop {
            let mut ready = self.descriptor.writable().await?;
            match ready.try_io(|descriptor| {
                // SAFETY: bytes 是有效的只读切片，fd 在 AsyncFd 生命周期内有效。
                let length = unsafe {
                    libc::write(descriptor.as_raw_fd(), bytes.as_ptr().cast(), bytes.len())
                };
                if length < 0 {
                    Err(io::Error::last_os_error())
                } else if length as usize != bytes.len() {
                    Err(io::Error::new(io::ErrorKind::WriteZero, "short TUN packet"))
                } else {
                    Ok(())
                }
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }
}

pub async fn ip(arguments: &[&str]) -> Result<Vec<u8>> {
    command("ip", arguments, None).await
}

async fn command(program: &str, arguments: &[&str], input: Option<&str>) -> Result<Vec<u8>> {
    let path = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|directory| Path::new(directory).join(program))
        .find(|path| path.is_file())
        .context("缺少 iproute2 或 nftables 系统工具")?;
    let mut command = Command::new(path);
    command
        .args(arguments)
        .kill_on_drop(true)
        .stdin(if input.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .context("无法写入规则")?
            .write_all(input.as_bytes())
            .await?;
    }
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
    ensure!(
        output.status.success(),
        "系统网络命令失败：{program}（请检查权限或已有配置）"
    );
    ensure!(output.stdout.len() <= 4 << 20, "系统网络响应过大");
    Ok(output.stdout)
}

#[derive(Default)]
pub struct Routes {
    addresses: BTreeSet<IpNet>,
    installed: BTreeSet<IpNet>,
    nat: Option<String>,
    approved: BTreeSet<IpNet>,
}

impl Routes {
    pub async fn apply(&mut self, config: &Config, map: &NetworkMap) -> Result<()> {
        let node = map.node.as_ref().context("缺少本机网络映射")?;
        ensure!(node.valid(), "设备未授权或已过期");
        let desired = node
            .addresses
            .iter()
            .map(|prefix| IpNet::from(prefix.addr()))
            .collect::<BTreeSet<_>>();
        ensure!(
            !desired.is_empty() && desired.len() <= 16,
            "本机地址数量无效"
        );
        for address in self.addresses.difference(&desired) {
            ip(&[
                family(address),
                "address",
                "del",
                &address.to_string(),
                "dev",
                &config.interface,
            ])
            .await?;
        }
        for address in desired.difference(&self.addresses) {
            let existing: Value = serde_json::from_slice(
                &ip(&[family(address), "-j", "route", "show", "table", "main"]).await?,
            )?;
            ensure!(
                !conflicts(*address, &existing, &config.interface),
                "本机隧道地址与现有局域网冲突，拒绝接管；请在控制台调整网段"
            );
            ip(&[
                family(address),
                "address",
                "add",
                &address.to_string(),
                "dev",
                &config.interface,
            ])
            .await?;
        }
        self.addresses = desired;
        let mut routes = BTreeSet::new();
        for peer in map.nodes()?.into_iter().filter(|peer| peer.valid()) {
            routes.extend(
                peer.addresses
                    .iter()
                    .map(|address| IpNet::from(address.addr())),
            );
            if config.accept_routes {
                routes.extend(
                    peer.allowed_ips
                        .into_iter()
                        .filter(|route| route.prefix_len() > 0),
                );
            }
        }
        routes.retain(|route| !self.addresses.contains(route));
        for route in self.installed.difference(&routes) {
            ip(&[
                family(route),
                "route",
                "del",
                &route.to_string(),
                "dev",
                &config.interface,
                "proto",
                "99",
            ])
            .await?;
        }
        self.installed.retain(|route| routes.contains(route));
        for route in routes
            .difference(&self.installed)
            .copied()
            .collect::<Vec<_>>()
        {
            let existing: Value = serde_json::from_slice(
                &ip(&[family(&route), "-j", "route", "show", "table", "main"]).await?,
            )?;
            if conflicts(route, &existing, &config.interface) {
                eprintln!("保留本地网络：跳过冲突路由 {route}");
                continue;
            }
            ip(&[
                family(&route),
                "route",
                "add",
                &route.to_string(),
                "dev",
                &config.interface,
                "proto",
                "99",
            ])
            .await?;
            self.installed.insert(route);
        }
        let approved = node
            .allowed_ips
            .iter()
            .filter(|route| config.advertise_routes.contains(route))
            .copied()
            .collect::<BTreeSet<_>>();
        if approved != self.approved {
            self.clear_nat().await?;
            if config.snat && !approved.is_empty() {
                let table = format!("xunara_{}", config.interface);
                let mut rules = format!(
                    "create table inet {table}\nadd chain inet {table} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n"
                );
                for route in &approved {
                    let protocol = if route.addr().is_ipv4() { "ip" } else { "ip6" };
                    rules.push_str(&format!("add rule inet {table} postrouting iifname \"{}\" {protocol} daddr {route} masquerade\n", config.interface));
                }
                // nft 批处理原子提交；只新增自己的表，不 flush 主机防火墙。
                command("nft", &["-f", "-"], Some(&rules)).await?;
                self.nat = Some(table);
            }
            self.approved = approved;
        }
        Ok(())
    }

    pub fn local_destination(&self, address: IpAddr) -> bool {
        self.addresses.iter().any(|local| local.contains(&address))
            || self.approved.iter().any(|route| route.contains(&address))
    }

    pub fn local_source(&self, address: IpAddr) -> bool {
        self.local_destination(address)
    }

    pub fn remote_destination(&self, address: IpAddr) -> bool {
        !self.local_destination(address)
            && self.installed.iter().any(|route| route.contains(&address))
    }

    pub async fn clear_nat(&mut self) -> Result<()> {
        if let Some(table) = &self.nat {
            command("nft", &["delete", "table", "inet", table], None).await?;
            self.nat = None;
        }
        Ok(())
    }

    pub async fn stop(&mut self, interface: &str) -> Result<()> {
        self.clear_nat().await?;
        ip(&["link", "set", "dev", interface, "down"]).await?;
        Ok(())
    }
}

pub fn family(prefix: &IpNet) -> &'static str {
    if prefix.addr().is_ipv4() { "-4" } else { "-6" }
}

pub fn conflicts(route: IpNet, existing: &Value, interface: &str) -> bool {
    existing.as_array().into_iter().flatten().any(|entry| {
        if entry.get("dev").and_then(Value::as_str) == Some(interface) {
            return false;
        }
        let Some(prefix) = entry.get("dst").and_then(Value::as_str).and_then(|prefix| {
            prefix
                .parse::<IpNet>()
                .ok()
                .or_else(|| prefix.parse::<IpAddr>().ok().map(IpNet::from))
        }) else {
            return false;
        };
        prefix.prefix_len() > 0
            && (prefix.contains(&route.addr()) || route.contains(&prefix.addr()))
    })
}

pub fn forwarding_ready(config: &Config) -> Result<()> {
    for (ipv4, file) in [
        (true, "/proc/sys/net/ipv4/ip_forward"),
        (false, "/proc/sys/net/ipv6/conf/all/forwarding"),
    ] {
        if config
            .advertise_routes
            .iter()
            .any(|route| route.addr().is_ipv4() == ipv4)
        {
            ensure!(
                std::fs::read_to_string(file)?.trim() == "1",
                "请先显式开启内核转发：{file}=1；客户端不会擅自更改全局 sysctl"
            );
        }
    }
    Ok(())
}

pub fn local_endpoints(port: u16, excluded_interface: &str) -> Vec<String> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs 初始化 head；成功后仅在 freeifaddrs 前遍历系统提供的有效链表。
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }
    let mut current = head;
    let mut endpoints = BTreeSet::new();
    while !current.is_null() {
        // SAFETY: current 来自尚未释放的 ifaddrs 链表，ifa_name 是以 NUL 结尾的系统字符串。
        let entry = unsafe { &*current };
        // SAFETY: ifa_name 的生命周期由 getifaddrs 所分配的链表持有。
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_string_lossy();
        if name != excluded_interface
            && !entry.ifa_addr.is_null()
            && entry.ifa_flags & libc::IFF_UP as u32 != 0
        {
            // SAFETY: ifa_addr 非空；检查 AF_INET 后才按 sockaddr_in 读取。
            let family = unsafe { (*entry.ifa_addr).sa_family };
            if family == libc::AF_INET as u16 {
                // SAFETY: 族已确认 AF_INET，内核提供的结构为 sockaddr_in。
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                let address = std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
                if !address.is_loopback() && !address.is_unspecified() && !address.is_multicast() {
                    endpoints.insert(SocketAddr::new(address.into(), port).to_string());
                }
            }
        }
        current = entry.ifa_next;
    }
    // SAFETY: head 是本函数 getifaddrs 成功返回的原始链表，只释放一次。
    unsafe { libc::freeifaddrs(head) };
    endpoints.into_iter().take(32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn local_lan_wins_over_conflicting_overlay_or_subnet() {
        let existing = json!([{"dst":"100.100.100.0/24","dev":"eth0"},{"dst":"default","dev":"eth0"},{"dst":"100.64.1.1/32","dev":"xunara0"}]);
        assert!(conflicts(
            "100.100.100.100/32".parse().unwrap(),
            &existing,
            "xunara0"
        ));
        assert!(conflicts(
            "100.100.0.0/16".parse().unwrap(),
            &existing,
            "xunara0"
        ));
        assert!(!conflicts(
            "100.64.1.2/32".parse().unwrap(),
            &existing,
            "xunara0"
        ));
        assert!(!conflicts(
            "100.64.1.1/32".parse().unwrap(),
            &existing,
            "xunara0"
        ));
    }
}
