use std::{path::PathBuf, time::Duration};

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use url::Url;

#[derive(Deserialize)]
struct Endpoint {
    url: String,
    certificate: String,
}

#[tokio::test]
#[ignore = "requires an operator-provided XUNARA_LIVE_DERP_CONFIG file"]
async fn configured_derp_completes_tls_upgrade_and_server_greeting() {
    let filename = PathBuf::from(std::env::var_os("XUNARA_LIVE_DERP_CONFIG").unwrap());
    let endpoint: Endpoint = serde_json::from_slice(&std::fs::read(filename).unwrap()).unwrap();
    let url = Url::parse(&endpoint.url).unwrap();
    assert_eq!(url.scheme(), "https");
    assert!(url.username().is_empty());
    assert!(url.password().is_none());
    assert!(url.query().is_none());
    assert!(url.fragment().is_none());
    assert_eq!(url.path(), "/derp");
    let stream = xunara_client::transport::connect(&url, &endpoint.certificate, None)
        .await
        .expect("DERP TCP/TLS connection failed");
    println!("PASS DERP TCP/TLS certificate verification");
    let upgraded = xunara_client::transport::upgrade(&url, stream, "DERP", &[])
        .await
        .expect("DERP HTTP upgrade failed");
    println!("PASS DERP HTTP upgrade");
    let mut stream = hyper_util::rt::TokioIo::new(upgraded);
    let greeting = tokio::time::timeout(Duration::from_secs(10), async {
        let kind = stream.read_u8().await.unwrap();
        let length = stream.read_u32().await.unwrap() as usize;
        assert_eq!(kind, 1);
        assert!((40..=65568).contains(&length));
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await.unwrap();
        payload
    })
    .await
    .expect("DERP greeting timed out");
    assert_eq!(&greeting[..8], b"DERP\xf0\x9f\x94\x91");
    println!("PASS DERP server greeting before client admission");
}
