use std::{
    io::{Read, Write},
    sync::{Arc, OnceLock},
};

use anyhow::{Result, ensure};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};

pub fn configuration() -> Arc<ClientConfig> {
    static CONFIGURATION: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIGURATION
        .get_or_init(|| {
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone()
}

/// TLS 状态机仅处理加密字节，实际 TCP 仍由受保护的 socket 或原 WireGuard 路由承载。
pub struct Session(ClientConnection);

impl Session {
    pub fn new(name: &str, request: &[u8]) -> Result<Self> {
        Self::with_configuration(name, request, configuration())
    }

    fn with_configuration(
        name: &str,
        request: &[u8],
        configuration: Arc<ClientConfig>,
    ) -> Result<Self> {
        let mut connection =
            ClientConnection::new(configuration, ServerName::try_from(name.to_owned())?)?;
        connection.writer().write_all(request)?;
        Ok(Self(connection))
    }

    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut input = std::io::Cursor::new(bytes);
        while input.position() < bytes.len() as u64 {
            if self.0.read_tls(&mut input)? == 0 {
                break;
            }
            self.0.process_new_packets()?;
        }
        let mut plain = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            match self.0.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    plain.extend_from_slice(&buffer[..length]);
                    ensure!(plain.len() <= 65535 + 8192, "DNS TLS 回包过大");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(plain)
    }

    pub fn output(&mut self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while self.0.wants_write() {
            self.0.write_tls(&mut bytes)?;
            ensure!(bytes.len() <= 65535 + 8192, "DNS TLS 请求过大");
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_stream_validates_hostname_ca_and_preserves_plaintext() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["resolver.test".to_owned()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let trusted = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        for (name, trust, succeeds) in [
            ("resolver.test", trusted.clone(), true),
            ("wrong.test", trusted, false),
            ("resolver.test", configuration(), false),
        ] {
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
                )
                .unwrap();
            let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut client =
                Session::with_configuration(name, b"private DNS query", trust).unwrap();
            let mut received = Vec::new();
            let result: Result<()> = (|| {
                for _attempt in 0..12 {
                    let output = client.output()?;
                    assert!(
                        !output
                            .windows(b"private DNS query".len())
                            .any(|window| window == b"private DNS query")
                    );
                    server.read_tls(&mut std::io::Cursor::new(output))?;
                    server.process_new_packets()?;
                    if !server.is_handshaking() {
                        let mut plain = [0; 128];
                        if let Ok(length) = server.reader().read(&mut plain)
                            && length > 0
                        {
                            assert_eq!(&plain[..length], b"private DNS query");
                            server.writer().write_all(b"authenticated answer")?;
                        }
                    }
                    let mut output = Vec::new();
                    server.write_tls(&mut output)?;
                    received.extend(client.receive(&output)?);
                    if !received.is_empty() {
                        break;
                    }
                }
                ensure!(
                    received == b"authenticated answer",
                    "TLS application data missing"
                );
                Ok(())
            })();
            assert_eq!(
                result.is_ok(),
                succeeds,
                "unexpected TLS verification result for {name}"
            );
        }
    }
}
