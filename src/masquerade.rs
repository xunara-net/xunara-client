use std::{borrow::Cow, net::IpAddr};

use ipnet::IpNet;

use crate::{filter::Packet, model::Node};

fn alias(peer: &Node, ipv4: bool) -> Option<IpAddr> {
    if ipv4 {
        peer.self_v4_masq.map(IpAddr::V4)
    } else {
        peer.self_v6_masq.map(IpAddr::V6)
    }
    .filter(|address| {
        !address.is_unspecified() && !address.is_loopback() && !address.is_multicast()
    })
}

/// 只转换本机 host 地址，不把手机背后的网段或其他租户地址套用同一映射。
pub fn outgoing<'packet>(
    bytes: &'packet [u8],
    local: &[IpNet],
    peer: &Node,
) -> Option<Cow<'packet, [u8]>> {
    let packet = Packet::parse(bytes)?;
    let Some(address) = alias(peer, packet.source.is_ipv4()) else {
        return Some(Cow::Borrowed(bytes));
    };
    let native = local
        .iter()
        .map(IpNet::addr)
        .find(|address| address.is_ipv4() == packet.source.is_ipv4());
    if native != Some(packet.source) || packet.source == address {
        return Some(Cow::Borrowed(bytes));
    }
    let mut output = bytes.to_vec();
    rewrite(&mut output, address, true)?;
    Some(Cow::Owned(output))
}

/// 调用方必须已按 WireGuard 密钥识别 peer；不能按源 IP 从别人的共享映射查找别名。
pub fn incoming(bytes: &mut [u8], local: &[IpNet], peer: &Node) -> Option<()> {
    let packet = Packet::parse(bytes)?;
    if alias(peer, packet.destination.is_ipv4()) != Some(packet.destination) {
        return Some(());
    }
    let native = local
        .iter()
        .map(IpNet::addr)
        .find(|address| address.is_ipv4() == packet.destination.is_ipv4())?;
    rewrite(bytes, native, false)
}

pub fn rewrite(bytes: &mut [u8], address: IpAddr, source: bool) -> Option<()> {
    let packet = Packet::parse(bytes)?;
    if packet.source.is_ipv4() != address.is_ipv4() {
        return None;
    }
    let (offset, start, replacement) = match address {
        IpAddr::V4(address) => (
            usize::from(bytes[0] & 15) * 4,
            if source { 12 } else { 16 },
            address.octets().to_vec(),
        ),
        IpAddr::V6(address) => (40, if source { 8 } else { 24 }, address.octets().to_vec()),
    };
    let original = bytes[start..start + replacement.len()].to_vec();
    let checksum_offset = match packet.protocol {
        6 => Some(offset + 16),
        17 => Some(offset + 6),
        58 => Some(offset + 2),
        1 => None,
        _ => return None,
    };
    if let Some(checksum_offset) = checksum_offset {
        let checksum = u16::from_be_bytes([bytes[checksum_offset], bytes[checksum_offset + 1]]);
        // IPv4 UDP 的零表示未启用校验，不能把它“修复”为一个看似有效的校验和。
        if checksum != 0 || packet.protocol != 17 {
            let updated = adjusted(checksum, &original, &replacement);
            let updated = if updated == 0 && packet.protocol == 17 {
                u16::MAX
            } else {
                updated
            };
            bytes[checksum_offset..checksum_offset + 2].copy_from_slice(&updated.to_be_bytes());
        } else if address.is_ipv6() {
            return None;
        }
    }
    if address.is_ipv4() {
        let checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
        bytes[10..12].copy_from_slice(&adjusted(checksum, &original, &replacement).to_be_bytes());
    }
    bytes[start..start + replacement.len()].copy_from_slice(&replacement);
    Some(())
}

fn adjusted(checksum: u16, original: &[u8], replacement: &[u8]) -> u16 {
    let mut sum = u32::from(!checksum);
    for (old, new) in original
        .as_chunks::<2>()
        .0
        .iter()
        .zip(replacement.as_chunks::<2>().0.iter())
    {
        sum += u32::from(!u16::from_be_bytes([old[0], old[1]]))
            + u32::from(u16::from_be_bytes([new[0], new[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp(source: &str, destination: &str) -> Vec<u8> {
        let source: IpAddr = source.parse().unwrap();
        let destination: IpAddr = destination.parse().unwrap();
        let offset = if source.is_ipv4() { 20 } else { 40 };
        let mut bytes = vec![0; offset + 8];
        if let (IpAddr::V4(source), IpAddr::V4(destination)) = (source, destination) {
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&destination.octets());
        } else if let (IpAddr::V6(source), IpAddr::V6(destination)) = (source, destination) {
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&8u16.to_be_bytes());
            bytes[6] = 17;
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&destination.octets());
            bytes[offset + 6..offset + 8].copy_from_slice(&0x1234u16.to_be_bytes());
        }
        bytes[offset..offset + 2].copy_from_slice(&53000u16.to_be_bytes());
        bytes[offset + 2..offset + 4].copy_from_slice(&53u16.to_be_bytes());
        bytes[offset + 4..offset + 6].copy_from_slice(&8u16.to_be_bytes());
        bytes
    }

    #[test]
    fn peer_scoped_translation_preserves_native_routes_and_other_aliases() {
        let local = [
            "100.80.0.1/32".parse().unwrap(),
            "fd7a:115c:a1e0::1/128".parse().unwrap(),
        ];
        let peer = Node {
            self_v4_masq: Some("100.96.0.1".parse().unwrap()),
            self_v6_masq: Some("fd7a:115c:a1e0:ffff::1".parse().unwrap()),
            ..Node::default()
        };
        for (native, remote, masqueraded) in [
            ("100.80.0.1", "100.96.0.2", "100.96.0.1"),
            (
                "fd7a:115c:a1e0::1",
                "fd7a:115c:a1e0:ffff::2",
                "fd7a:115c:a1e0:ffff::1",
            ),
        ] {
            let original = udp(native, remote);
            let translated = outgoing(&original, &local, &peer).unwrap();
            assert_eq!(
                Packet::parse(&translated).unwrap().source,
                masqueraded.parse::<IpAddr>().unwrap()
            );
            let mut returned = udp(remote, masqueraded);
            incoming(&mut returned, &local, &peer).unwrap();
            assert_eq!(
                Packet::parse(&returned).unwrap().destination,
                native.parse::<IpAddr>().unwrap()
            );
            let mut unrelated = udp(remote, native);
            let original = unrelated.clone();
            incoming(&mut unrelated, &local, &peer).unwrap();
            assert_eq!(unrelated, original);
        }
        let subnet = udp("192.168.10.7", "100.96.0.2");
        assert!(matches!(
            outgoing(&subnet, &local, &peer),
            Some(Cow::Borrowed(_))
        ));
        let extended = [local[0], "100.80.0.7/32".parse().unwrap()];
        let secondary = udp("100.80.0.7", "100.96.0.2");
        assert!(matches!(
            outgoing(&secondary, &extended, &peer),
            Some(Cow::Borrowed(_))
        ));
        let mut wrong_peer = udp("100.96.0.2", "100.96.0.1");
        incoming(&mut wrong_peer, &local, &Node::default()).unwrap();
        assert_eq!(
            Packet::parse(&wrong_peer).unwrap().destination,
            "100.96.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn address_rewrite_is_reversible_and_keeps_disabled_ipv4_udp_checksum() {
        for (source, destination, replacement) in [
            ("100.80.0.1", "100.96.0.2", "100.96.0.1"),
            (
                "fd7a:115c:a1e0::1",
                "fd7a:115c:a1e0:ffff::2",
                "fd7a:115c:a1e0:ffff::1",
            ),
        ] {
            let original = udp(source, destination);
            let mut bytes = original.clone();
            rewrite(&mut bytes, replacement.parse().unwrap(), true).unwrap();
            rewrite(&mut bytes, source.parse().unwrap(), true).unwrap();
            assert_eq!(bytes, original);
            if source.contains('.') {
                assert_eq!(&bytes[26..28], &[0, 0]);
            }
        }
        assert!(rewrite(&mut [0; 8], "100.96.0.1".parse().unwrap(), true).is_none());
    }
}
