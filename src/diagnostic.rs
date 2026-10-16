use std::{
    net::IpAddr,
    sync::mpsc::SyncSender,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, ensure};
use rand_core::{OsRng, RngCore};
use serde::Serialize;

use crate::filter::Packet;

pub struct PingRequest {
    pub peer: u64,
    pub reply: SyncSender<Result<PingResult>>,
}

#[derive(Debug, Serialize)]
pub struct PingResult {
    pub address: IpAddr,
    pub rtt_ms: f64,
    pub path: &'static str,
    pub relay_region: u16,
}

struct Pending {
    peer: u64,
    source: IpAddr,
    target: IpAddr,
    token: [u8; 20],
    sent: Instant,
    reply: SyncSender<Result<PingResult>>,
}

#[derive(Default)]
pub struct Pings {
    pending: Vec<Pending>,
    last_start: Option<Instant>,
}

impl Pings {
    pub fn start(
        &mut self,
        request: PingRequest,
        source: IpAddr,
        target: IpAddr,
    ) -> Option<Vec<u8>> {
        if self.pending.len() >= 4
            || self
                .last_start
                .is_some_and(|started| started.elapsed() < Duration::from_millis(500))
        {
            let _ = request
                .reply
                .try_send(Err(anyhow!("检测过于频繁，请稍后重试")));
            return None;
        }
        let mut token = [0; 20];
        OsRng.fill_bytes(&mut token);
        let bytes = match echo(source, target, &token, false) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = request.reply.try_send(Err(error));
                return None;
            }
        };
        let sent = Instant::now();
        self.last_start = Some(sent);
        self.pending.push(Pending {
            peer: request.peer,
            source,
            target,
            token,
            sent,
            reply: request.reply,
        });
        Some(bytes)
    }

    /// 调用方必须先完成 WireGuard 身份、来源和 ACL 校验，不能用探测旁路授权。
    pub fn receive(&mut self, peer: u64, bytes: &[u8], path: &'static str, region: u16) -> bool {
        let Some(packet) = Packet::parse(bytes) else {
            return false;
        };
        let Some(index) = self.pending.iter().position(|pending| {
            pending.peer == peer
                && pending.source == packet.destination
                && pending.target == packet.source
                && pending.sent.elapsed() < Duration::from_secs(8)
                && is_reply(bytes, &pending.token)
        }) else {
            return false;
        };
        let pending = self.pending.swap_remove(index);
        let _ = pending.reply.try_send(Ok(PingResult {
            address: pending.target,
            rtt_ms: pending.sent.elapsed().as_secs_f64() * 1000.0,
            path,
            relay_region: region,
        }));
        true
    }

    pub fn expire(&mut self) {
        self.pending.retain(|pending| {
            if pending.sent.elapsed() < Duration::from_secs(8) {
                return true;
            }
            let _ = pending.reply.try_send(Err(anyhow!(
                "检测超时：设备可能离线，或 ACL / 防火墙未允许 ICMP"
            )));
            false
        });
    }
}

impl Drop for Pings {
    fn drop(&mut self) {
        for pending in &self.pending {
            let _ = pending
                .reply
                .try_send(Err(anyhow!("连接已断开，请重新检测")));
        }
    }
}

fn echo(source: IpAddr, target: IpAddr, token: &[u8; 20], reply: bool) -> Result<Vec<u8>> {
    ensure!(
        source.is_ipv4() == target.is_ipv4(),
        "没有相同地址族的本机地址"
    );
    let offset = if source.is_ipv4() { 20 } else { 40 };
    let mut bytes = vec![0; offset + 24];
    let length = bytes.len() as u16;
    match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[6] = 0x40;
            bytes[8] = 64;
            bytes[9] = 1;
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&target.octets());
            let checksum = checksum(&bytes[..20], 0);
            bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
            bytes[offset] = if reply { 0 } else { 8 };
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&24u16.to_be_bytes());
            bytes[6] = 58;
            bytes[7] = 64;
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&target.octets());
            bytes[offset] = if reply { 129 } else { 128 };
        }
        _ => unreachable!(),
    }
    bytes[offset + 4..].copy_from_slice(token);
    let checksum = checksum(&bytes[offset..], pseudo_sum(&bytes, offset));
    bytes[offset + 2..offset + 4].copy_from_slice(&checksum.to_be_bytes());
    Ok(bytes)
}

fn is_reply(bytes: &[u8], token: &[u8; 20]) -> bool {
    let Some(packet) = Packet::parse(bytes) else {
        return false;
    };
    let offset = if packet.source.is_ipv4() {
        usize::from(bytes[0] & 15) * 4
    } else {
        40
    };
    bytes.len() == offset + 24
        && matches!((packet.protocol, bytes[offset]), (1, 0) | (58, 129))
        && bytes[offset + 1] == 0
        && bytes[offset + 4..] == *token
        && (!packet.source.is_ipv4() || checksum(&bytes[..offset], 0) == 0)
        && checksum(&bytes[offset..], pseudo_sum(bytes, offset)) == 0
}

fn pseudo_sum(bytes: &[u8], offset: usize) -> u32 {
    if bytes[0] >> 4 != 6 {
        return 0;
    }
    // ICMPv6 包含 IPv6 伪首部；ICMPv4 不包含，不能混用两种校验和。
    bytes[8..40]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum::<u32>()
        + (bytes.len() - offset) as u32
        + 58
}

fn checksum(bytes: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    #[test]
    fn echo_checks_both_families_and_rejects_corruption() {
        for (source, target) in [("100.80.0.1", "100.80.0.2"), ("fd7a::1", "fd7a::2")] {
            let source = source.parse().unwrap();
            let target = target.parse().unwrap();
            let token = [17; 20];
            let request = echo(source, target, &token, false).unwrap();
            assert!(!is_reply(&request, &token));
            let mut reply = echo(target, source, &token, true).unwrap();
            assert!(is_reply(&reply, &token));
            assert!(!is_reply(&reply, &[18; 20]));
            reply[12] ^= 1;
            assert!(!is_reply(&reply, &token));
        }
        assert!(
            echo(
                "100.80.0.1".parse().unwrap(),
                "fd7a::2".parse().unwrap(),
                &[0; 20],
                false
            )
            .is_err()
        );
    }

    #[test]
    fn replies_are_bound_to_peer_addresses_and_nonce_and_only_complete_once() {
        let mut pings = Pings::default();
        let (reply, receiver) = sync_channel(1);
        let source = "100.80.0.1".parse().unwrap();
        let target = "100.80.0.2".parse().unwrap();
        pings
            .start(PingRequest { peer: 2, reply }, source, target)
            .unwrap();
        let token = pings.pending[0].token;
        let reply = echo(target, source, &token, true).unwrap();
        assert!(!pings.receive(3, &reply, "direct", 0));
        assert!(!pings.receive(
            2,
            &echo("100.80.0.3".parse().unwrap(), source, &token, true).unwrap(),
            "direct",
            0
        ));
        assert!(pings.receive(2, &reply, "relay", 901));
        assert!(!pings.receive(2, &reply, "direct", 0));
        let result = receiver.try_recv().unwrap().unwrap();
        assert_eq!(result.address, target);
        assert_eq!(result.path, "relay");
        assert_eq!(result.relay_region, 901);
    }

    #[test]
    fn pending_probes_are_rate_limited_expired_and_cancelled() {
        let mut pings = Pings::default();
        let source = "100.80.0.1".parse().unwrap();
        let target = "100.80.0.2".parse().unwrap();
        let (reply, receiver) = sync_channel(1);
        pings
            .start(PingRequest { peer: 2, reply }, source, target)
            .unwrap();
        let (reply, limited) = sync_channel(1);
        assert!(
            pings
                .start(PingRequest { peer: 2, reply }, source, target)
                .is_none()
        );
        assert!(limited.try_recv().unwrap().is_err());
        pings.pending[0].sent = Instant::now() - Duration::from_secs(9);
        pings.expire();
        assert!(receiver.try_recv().unwrap().is_err());
        assert!(pings.pending.is_empty());
        pings.last_start = None;
        let (reply, cancelled) = sync_channel(1);
        pings
            .start(PingRequest { peer: 2, reply }, source, target)
            .unwrap();
        drop(pings);
        assert!(cancelled.try_recv().unwrap().is_err());
    }
}
