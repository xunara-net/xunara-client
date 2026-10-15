use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, AeadCore},
};
use rand_core::{OsRng, RngCore};

pub const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";

pub fn transaction() -> [u8; 12] {
    let mut transaction = [0; 12];
    OsRng.fill_bytes(&mut transaction);
    transaction
}

pub fn seal(private: &[u8; 32], public: &[u8; 32], message: &[u8]) -> Option<Vec<u8>> {
    let secret = SecretKey::from(*private);
    let cipher = SalsaBox::new(&PublicKey::from(*public), &secret);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let encrypted = cipher.encrypt(&nonce, message).ok()?;
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(secret.public_key().as_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&encrypted);
    Some(bytes)
}

pub fn open(private: &[u8; 32], expected: &[u8; 32], bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 78 || !bytes.starts_with(MAGIC) || &bytes[6..38] != expected {
        return None;
    }
    SalsaBox::new(&PublicKey::from(*expected), &SecretKey::from(*private))
        .decrypt(bytes[38..62].into(), &bytes[62..])
        .ok()
}

pub fn ping(transaction: [u8; 12], node: &[u8; 32]) -> Vec<u8> {
    let mut bytes = vec![1, 0];
    bytes.extend_from_slice(&transaction);
    bytes.extend_from_slice(node);
    bytes
}

pub fn pong(transaction: &[u8], source: SocketAddr) -> Vec<u8> {
    let mut bytes = vec![2, 0];
    bytes.extend_from_slice(transaction);
    append_address(&mut bytes, source);
    bytes
}

pub fn call_me_maybe(endpoints: &[SocketAddr]) -> Vec<u8> {
    let mut bytes = vec![3, 0];
    for address in endpoints.iter().take(32) {
        append_address(&mut bytes, *address);
    }
    bytes
}

fn append_address(bytes: &mut Vec<u8>, address: SocketAddr) {
    let ipv6 = match address.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    bytes.extend_from_slice(&ipv6.octets());
    bytes.extend_from_slice(&address.port().to_be_bytes());
}

pub fn address(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() != 18 {
        return None;
    }
    let ipv6 = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[..16]).ok()?);
    let ip = ipv6
        .to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V6(ipv6));
    let port = u16::from_be_bytes(bytes[16..18].try_into().ok()?);
    if !ip.is_ipv4() || ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() || port == 0 {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}

pub fn stun_request(transaction: [u8; 12]) -> Vec<u8> {
    let mut bytes = vec![0, 1, 0, 20, 0x21, 0x12, 0xa4, 0x42];
    bytes.extend_from_slice(&transaction);
    bytes.extend_from_slice(&[0x80, 0x22, 0, 8]);
    bytes.extend_from_slice(b"tailnode");
    let mut checksum = !0u32;
    for byte in &bytes {
        checksum ^= u32::from(*byte);
        for _ in 0..8 {
            checksum = (checksum >> 1) ^ (0xedb88320u32 & 0u32.wrapping_sub(checksum & 1));
        }
    }
    let fingerprint = !checksum ^ 0x5354554e;
    bytes.extend_from_slice(&[0x80, 0x28, 0, 4]);
    bytes.extend_from_slice(&fingerprint.to_be_bytes());
    bytes
}

pub fn stun_response(bytes: &[u8], expected: &[u8; 12]) -> Option<SocketAddr> {
    if bytes.len() < 20
        || bytes[..2] != [1, 1]
        || bytes[4..8] != [0x21, 0x12, 0xa4, 0x42]
        || &bytes[8..20] != expected
    {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if bytes.len() != length + 20 {
        return None;
    }
    let mut attributes = &bytes[20..];
    while attributes.len() >= 4 {
        let kind = u16::from_be_bytes([attributes[0], attributes[1]]);
        let length = usize::from(u16::from_be_bytes([attributes[2], attributes[3]]));
        let padded = (length + 3) & !3;
        if attributes.len() < padded + 4 {
            return None;
        }
        let value = &attributes[4..4 + length];
        if kind == 0x20 && value.len() == 8 && value[1] == 1 {
            let port = u16::from_be_bytes([value[2], value[3]]) ^ 0x2112;
            let address = Ipv4Addr::new(
                value[4] ^ 0x21,
                value[5] ^ 0x12,
                value[6] ^ 0xa4,
                value[7] ^ 0x42,
            );
            if port == 0
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_loopback()
            {
                return None;
            }
            return Some(SocketAddr::new(address.into(), port));
        }
        attributes = &attributes[4 + padded..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disco_roundtrip_authenticates_both_keys_and_ciphertext() {
        let first = SecretKey::generate(&mut OsRng);
        let second = SecretKey::generate(&mut OsRng);
        let message = ping(transaction(), first.public_key().as_bytes());
        let mut sealed = seal(&first.to_bytes(), second.public_key().as_bytes(), &message).unwrap();
        assert_eq!(
            open(&second.to_bytes(), first.public_key().as_bytes(), &sealed).unwrap(),
            message
        );
        sealed[70] ^= 1;
        assert!(open(&second.to_bytes(), first.public_key().as_bytes(), &sealed).is_none());
        assert!(open(&[9; 32], first.public_key().as_bytes(), &sealed).is_none());
    }

    #[test]
    fn stun_request_matches_upstream_fixture() {
        let bytes = stun_request([0; 12]);
        assert_eq!(bytes.len(), 40);
        assert_eq!(&bytes[20..32], b"\x80\x22\x00\x08tailnode");
        assert!(stun_response(&bytes, &[0; 12]).is_none());
        assert!(address(&[0; 18]).is_none());
    }
}
