#[test]
#[ignore = "requires tests/compat Go fixture"]
fn stun_wire_encoding_is_accepted_by_official_tailscale_parser() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/compat-fixture");
    let bytes = xunara_client::discovery::stun_request([0; 12]);
    let response = std::process::Command::new(&fixture)
        .args(["-mode", "stun-vector", "-target", &hex::encode(&bytes)])
        .output()
        .expect("build tests/compat fixture first");
    assert!(
        response.status.success(),
        "official STUN parser rejected Rust request"
    );
    let mut corrupt = bytes;
    corrupt[30] ^= 1;
    let response = std::process::Command::new(fixture)
        .args(["-mode", "stun-vector", "-target", &hex::encode(&corrupt)])
        .output()
        .unwrap();
    assert!(
        !response.status.success(),
        "official parser accepted corrupted fingerprint"
    );
}

#[test]
#[ignore = "requires tests/compat Go fixture"]
fn masquerade_matches_official_tailscale_checksum_rewrites() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/compat-fixture");
    for ipv4 in [true, false] {
        for protocol in if ipv4 { [6, 17, 1] } else { [6, 17, 58] } {
            for source in [true, false] {
                let offset = if ipv4 { 20 } else { 40 };
                let mut bytes = vec![0; offset + 24];
                if ipv4 {
                    bytes[0] = 0x45;
                    bytes[2..4].copy_from_slice(&44u16.to_be_bytes());
                    bytes[9] = protocol;
                    bytes[12..16].copy_from_slice(&[100, 80, 0, 1]);
                    bytes[16..20].copy_from_slice(&[100, 96, 0, 2]);
                    bytes[10..12].copy_from_slice(&0x1234u16.to_be_bytes());
                } else {
                    bytes[0] = 0x60;
                    bytes[4..6].copy_from_slice(&24u16.to_be_bytes());
                    bytes[6] = protocol;
                    bytes[8..24].copy_from_slice(
                        &"fd7a:115c:a1e0::1"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
                    );
                    bytes[24..40].copy_from_slice(
                        &"fd7a:115c:a1e0:ffff::2"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
                    );
                }
                bytes[offset..offset + 2].copy_from_slice(&53000u16.to_be_bytes());
                bytes[offset + 2..offset + 4].copy_from_slice(&53u16.to_be_bytes());
                if protocol == 6 {
                    bytes[offset + 12] = 0x50;
                }
                if protocol == 17 {
                    bytes[offset + 4..offset + 6].copy_from_slice(&24u16.to_be_bytes());
                }
                let checksum = offset
                    + if protocol == 6 {
                        16
                    } else if protocol == 17 {
                        6
                    } else {
                        2
                    };
                bytes[checksum..checksum + 2].copy_from_slice(&0xab12u16.to_be_bytes());
                let target = if ipv4 {
                    "100.96.0.1"
                } else {
                    "fd7a:115c:a1e0:ffff::1"
                };
                let mut child = Command::new(&fixture)
                    .args(["-mode", "masq-vector", "-target", target])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                let input = serde_json::json!({"Packet":hex::encode(&bytes),"Source":source});
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(input.to_string().as_bytes())
                    .unwrap();
                let result = child.wait_with_output().unwrap();
                assert!(result.status.success(), "upstream checksum fixture failed");
                let expected: String = serde_json::from_slice(&result.stdout).unwrap();
                xunara_client::masquerade::rewrite(&mut bytes, target.parse().unwrap(), source)
                    .unwrap();
                assert_eq!(
                    hex::encode(bytes),
                    expected,
                    "masquerade differs: ipv4={ipv4}, protocol={protocol}, source={source}"
                );
            }
        }
    }
}
