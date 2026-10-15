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
