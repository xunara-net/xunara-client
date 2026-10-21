use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::Packet;

pub(super) fn quoted_packet(bytes: &[u8]) -> Option<Packet> {
    let outer = Packet::parse(bytes)?;
    let offset = if outer.source.is_ipv4() {
        usize::from(bytes[0] & 15) * 4
    } else {
        40
    };
    let kind = *bytes.get(offset)?;
    if !matches!((outer.protocol, kind), (1, 3 | 11 | 12) | (58, 1..=4)) {
        return None;
    }
    let quote = bytes.get(offset + 8..)?;
    // ICMP 允许只引用原 IP 头和八字节载荷，不能放宽普通数据包的完整长度检查。
    let (source, destination, protocol, header, length) = match quote.first()? >> 4 {
        4 if outer.source.is_ipv4() && quote.len() >= 28 => {
            if u16::from_be_bytes([quote[6], quote[7]]) & 0x3fff != 0 {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&quote[12..16]).ok()?)),
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&quote[16..20]).ok()?)),
                quote[9],
                usize::from(quote[0] & 15) * 4,
                usize::from(u16::from_be_bytes([quote[2], quote[3]])),
            )
        }
        6 if outer.source.is_ipv6() && quote.len() >= 48 => (
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&quote[8..24]).ok()?)),
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&quote[24..40]).ok()?)),
            quote[6],
            40,
            usize::from(u16::from_be_bytes([quote[4], quote[5]])) + 40,
        ),
        _ => return None,
    };
    if outer.destination != source || header < 20 || quote.len() < header + 8 {
        return None;
    }
    let (source_port, destination_port) = match protocol {
        6 | 17 if length >= header + if protocol == 6 { 20 } else { 8 } => (
            u16::from_be_bytes([quote[header], quote[header + 1]]),
            u16::from_be_bytes([quote[header + 2], quote[header + 3]]),
        ),
        1 | 58
            if length >= header + 8
                && matches!(
                    (source.is_ipv4(), protocol, quote[header]),
                    (true, 1, 8) | (false, 58, 128)
                ) =>
        {
            let identifier = u16::from_be_bytes([quote[header + 4], quote[header + 5]]);
            (identifier, identifier)
        }
        _ => return None,
    };
    Some(Packet {
        source,
        destination,
        protocol,
        source_port,
        destination_port,
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::filter::Filter;

    fn error(ipv6: bool, kind: u8, quote_length: usize) -> Vec<u8> {
        let header = if ipv6 { 40 } else { 20 };
        let mut bytes = vec![0; header + 8 + header + quote_length];
        if ipv6 {
            bytes[0] = 0x60;
            let payload = (bytes.len() - 40) as u16;
            bytes[4..6].copy_from_slice(&payload.to_be_bytes());
            bytes[6] = 58;
            bytes[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
            bytes[24..40]
                .copy_from_slice(&"fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap().octets());
        } else {
            bytes[0] = 0x45;
            let length = bytes.len() as u16;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 1;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[100, 80, 0, 1]);
        }
        bytes[header] = kind;
        let quote = &mut bytes[header + 8..];
        if ipv6 {
            quote[0] = 0x60;
            quote[4..6].copy_from_slice(&1200u16.to_be_bytes());
            quote[6] = 6;
            quote[8..24]
                .copy_from_slice(&"fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap().octets());
            quote[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        } else {
            quote[0] = 0x45;
            quote[2..4].copy_from_slice(&1200u16.to_be_bytes());
            quote[9] = 6;
            quote[12..16].copy_from_slice(&[100, 80, 0, 1]);
            quote[16..20].copy_from_slice(&[198, 51, 100, 1]);
        }
        quote[header..header + 2].copy_from_slice(&40000u16.to_be_bytes());
        quote[header + 2..header + 4].copy_from_slice(&443u16.to_be_bytes());
        bytes
    }

    #[test]
    fn errors_require_a_live_matching_outbound_flow_for_both_families() {
        for (ipv6, kinds) in [(false, vec![3, 11, 12]), (true, vec![1, 2, 3, 4])] {
            for kind in kinds {
                let bytes = error(ipv6, kind, 8);
                let outbound = quoted_packet(&bytes).unwrap();
                let mut filter = Filter::default();
                assert!(!filter.related_error(&bytes));
                filter.outgoing(outbound);
                assert!(filter.related_error(&bytes));
                assert!(!filter.established(Packet::parse(&bytes).unwrap()));
                let mut changed = bytes.clone();
                let header = if ipv6 { 40 } else { 20 };
                changed[header + 8 + header + 3] ^= 1;
                assert!(!filter.related_error(&changed));
                filter
                    .responses
                    .insert(outbound.reversed(), Instant::now() - Duration::from_secs(1));
                assert!(!filter.related_error(&bytes));
            }
        }
    }

    #[test]
    fn redirects_truncated_quotes_wrong_local_address_and_fragments_are_rejected() {
        for ipv6 in [false, true] {
            let bytes = error(ipv6, if ipv6 { 2 } else { 3 }, 8);
            let header = if ipv6 { 40 } else { 20 };
            let mut changed = bytes.clone();
            changed[header] = if ipv6 { 137 } else { 5 };
            assert!(quoted_packet(&changed).is_none());
            for length in 0..bytes.len() {
                assert!(quoted_packet(&bytes[..length]).is_none());
            }
            changed = bytes.clone();
            changed[if ipv6 { 39 } else { 19 }] ^= 1;
            assert!(quoted_packet(&changed).is_none());
            changed = bytes.clone();
            changed[header + 8 + 6] = if ipv6 { 44 } else { 0x20 };
            assert!(quoted_packet(&changed).is_none());
            changed = bytes.clone();
            changed[header + 8 + if ipv6 { 6 } else { 9 }] = if ipv6 { 1 } else { 58 };
            assert!(quoted_packet(&changed).is_none());
            assert!(Packet::parse(&bytes[header + 8..]).is_none());
        }
    }
}
