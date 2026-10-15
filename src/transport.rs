use std::{fmt::Debug, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use url::Url;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<Stream: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for Stream {}
pub type Stream = Box<dyn AsyncStream>;

pub async fn connect(url: &Url, certificate: &str, target: Option<&str>) -> Result<Stream> {
    let host = url.host_str().context("缺少服务器主机")?;
    let port = url.port_or_known_default().context("缺少服务器端口")?;
    let target = target.filter(|target| !target.is_empty()).unwrap_or(host);
    let socket =
        tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((target, port))).await??;
    socket.set_nodelay(true)?;
    if url.scheme() == "http" {
        ensure!(
            socket.peer_addr()?.ip().is_loopback(),
            "非回环网络不能使用未加密 HTTP"
        );
        return Ok(Box::new(socket));
    }
    ensure!(url.scheme() == "https", "不支持的连接协议");
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut configuration = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = if let Some(pin) = certificate.strip_prefix("sha256-raw:") {
        let mut digest = [0; 32];
        hex::decode_to_slice(pin, &mut digest).context("DERP 证书指纹无效")?;
        configuration
            .dangerous()
            .set_certificate_verifier(Arc::new(PinnedCertificate(digest)));
        host
    } else if certificate.is_empty() {
        host
    } else {
        certificate
    };
    configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(configuration));
    let secured = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(ServerName::try_from(name.to_owned())?, socket),
    )
    .await??;
    Ok(Box::new(secured))
}

#[derive(Debug)]
struct PinnedCertificate([u8; 32]);

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 只替代 CA/域名验证；握手签名仍由 rustls 校验，不能用“接受所有证书”实现 pin。
        if Sha256::digest(certificate.as_ref()).as_slice() != self.0 {
            return Err(rustls::Error::General(
                "DERP certificate pin mismatch".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub async fn upgrade(
    url: &Url,
    stream: Stream,
    protocol: &str,
    headers: &[(&str, String)],
) -> Result<hyper::upgrade::Upgraded> {
    use bytes::Bytes;
    use http_body_util::Empty;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let mut request = http::Request::get(url.as_str())
        .header("Host", authority(url))
        .header("Connection", "Upgrade")
        .header("Upgrade", protocol);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        sender.send_request(request.body(Empty::<Bytes>::new())?),
    )
    .await??;
    ensure!(
        response.status() == http::StatusCode::SWITCHING_PROTOCOLS,
        "服务器拒绝协议升级（HTTP {}）",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get("Upgrade")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case(protocol)),
        "服务器返回了错误的升级协议"
    );
    Ok(hyper::upgrade::on(response).await?)
}

pub fn authority(url: &Url) -> String {
    url[url::Position::BeforeHost..url::Position::AfterPort].to_owned()
}
