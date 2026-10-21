use std::{
    io,
    net::IpAddr,
    os::fd::{AsRawFd, OwnedFd},
};

use anyhow::{Result, ensure};
use tokio::io::unix::AsyncFd;

use crate::{
    config::Config,
    mobile::{self, VpnConfiguration},
    model::NetworkMap,
};

#[derive(Default)]
pub struct Tun {
    descriptor: Option<AsyncFd<OwnedFd>>,
}

impl Tun {
    pub async fn create(_config: &Config) -> Result<Self> {
        Ok(Self::default())
    }

    pub fn install(&mut self, descriptor: Option<OwnedFd>) -> Result<()> {
        if let Some(descriptor) = descriptor {
            // SAFETY: descriptor 由 VpnService.detachFd 独占移交；只调整该 fd 的状态。
            let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
            ensure!(flags >= 0, "无法读取 TUN 状态");
            // SAFETY: fd 在本函数期间由 OwnedFd 保持有效，设置非阻塞供 Tokio 使用。
            let updated = unsafe {
                libc::fcntl(
                    descriptor.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            };
            ensure!(updated >= 0, "无法设置 TUN 非阻塞模式");
            // SAFETY: AsyncFd 接管 OwnedFd；旧描述符在替换时自动关闭，绝不重复关闭。
            self.descriptor = Some(unsafe { AsyncFd::register(descriptor)? });
        }
        Ok(())
    }

    pub fn close(&mut self) {
        self.descriptor = None;
    }

    pub async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        let Some(descriptor) = &self.descriptor else {
            // 首张合法映射到达以前不创建空 VPN，也不伪报已连接。
            return std::future::pending().await;
        };
        loop {
            let mut ready = descriptor.readable().await?;
            match ready.try_io(|descriptor| {
                // SAFETY: bytes 可写且 fd 在 AsyncFd 生命周期内有效。
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
        let descriptor = self
            .descriptor
            .as_ref()
            .ok_or_else(|| io::Error::other("VPN 尚未建立"))?;
        loop {
            let mut ready = descriptor.writable().await?;
            match ready.try_io(|descriptor| {
                // SAFETY: bytes 在 syscall 期间可读；fd 没有跨所有权边界复制。
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

#[derive(Default)]
pub struct Routes {
    configuration: Option<VpnConfiguration>,
    pending: Option<OwnedFd>,
}

impl Routes {
    pub async fn apply(&mut self, config: &Config, map: &NetworkMap) -> Result<()> {
        let host = mobile::host()?;
        let configuration = VpnConfiguration::from_map_with_dns(
            config,
            map,
            &host.local_networks()?,
            &host.dns_servers()?,
        )?;
        if self.configuration.as_ref() != Some(&configuration) {
            self.pending = Some(host.configure(&configuration)?);
            self.configuration = Some(configuration);
        }
        Ok(())
    }

    pub fn take_descriptor(&mut self) -> Option<OwnedFd> {
        self.pending.take()
    }

    pub fn local_destination(&self, address: IpAddr) -> bool {
        self.configuration.as_ref().is_some_and(|configuration| {
            configuration
                .addresses
                .iter()
                .any(|network| network.contains(&address))
        })
    }

    pub fn local_source(&self, address: IpAddr) -> bool {
        self.local_destination(address)
    }

    pub fn remote_destination(&self, address: IpAddr) -> bool {
        !self.local_destination(address)
            && self.configuration.as_ref().is_some_and(|configuration| {
                configuration
                    .routes
                    .iter()
                    .any(|route| route.contains(&address))
            })
    }

    pub async fn clear_nat(&mut self) -> Result<()> {
        Ok(())
    }

    pub async fn stop(&mut self, _interface: &str) -> Result<()> {
        self.configuration = None;
        self.pending = None;
        Ok(())
    }
}

pub fn forwarding_ready(config: &Config) -> Result<()> {
    ensure!(
        !config.snat,
        "Android 使用免 Root 用户态转发，不允许修改内核 SNAT"
    );
    Ok(())
}

pub fn local_endpoints(port: u16, _excluded_interface: &str) -> Vec<String> {
    mobile::host()
        .map(|host| host.local_endpoints(port))
        .unwrap_or_default()
}
