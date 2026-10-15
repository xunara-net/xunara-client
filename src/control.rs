use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, Bytes, BytesMut};
use http_body_util::{BodyExt, Empty, Limited};
use serde_json::{Value, json};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, watch},
};
use ts_keys::{Export, MachineKeyPair};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    VERSION,
    config::Config,
    model::NetworkMap,
    state::{Identity, public_key},
    transport,
};

pub const CAPABILITY_VERSION: u16 = 115;
const MAX_MAP_FRAME: usize = 16 << 20;

#[derive(Clone)]
pub struct Client {
    sender: h2::client::SendRequest<Bytes>,
    node_key: String,
}

impl Client {
    pub async fn connect(url: &Url, identity: &Identity) -> Result<Self> {
        let key_url = url.join(&format!("/key?v={CAPABILITY_VERSION}"))?;
        let stream = transport::connect(url, "", None).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::get(key_url.as_str())
            .header("Host", transport::authority(url))
            .header("Connection", "close")
            .body(Empty::<Bytes>::new())?;
        let response =
            tokio::time::timeout(Duration::from_secs(15), sender.send_request(request)).await??;
        ensure!(
            response.status().is_success(),
            "控制面公钥请求失败（HTTP {}）",
            response.status()
        );
        let body = tokio::time::timeout(
            Duration::from_secs(15),
            Limited::new(response.into_body(), 16 * 1024).collect(),
        )
        .await?
        .map_err(|_| anyhow::anyhow!("控制面公钥响应无效或超过上限"))?
        .to_bytes();
        let keys: Value = serde_json::from_slice(&body)?;
        let remote: ts_keys::MachinePublicKey = keys
            .get("publicKey")
            .and_then(Value::as_str)
            .context("缺少控制面 Noise 公钥")?
            .parse()?;
        let machine = Export::<MachineKeyPair>::from_bytes(identity.machine).import();
        let node_key = public_key(&identity.node, "nodekey:");
        let capability = ts_capabilityversion::CapabilityVersion::V115;
        let (handshake, initial) = ts_control_noise::Handshake::initialize(
            &format!("Tailscale Control Protocol v{CAPABILITY_VERSION}"),
            &machine,
            &remote,
            capability,
        );
        let stream = transport::connect(url, "", None).await?;
        let upgraded = transport::upgrade(
            &url.join("/ts2021")?,
            stream,
            "tailscale-control-protocol",
            &[
                ("X-Tailscale-Handshake", initial),
                ("Ts-Lb", node_key.clone()),
            ],
        )
        .await?;
        let mut encrypted = tokio::time::timeout(
            Duration::from_secs(15),
            handshake.complete(hyper_util::rt::TokioIo::new(upgraded), &machine),
        )
        .await??;
        let mut magic = [0; 5];
        tokio::time::timeout(Duration::from_secs(15), encrypted.read_exact(&mut magic)).await??;
        let prefix = if magic == [255, 255, 255, b'T', b'S'] {
            let length = encrypted.read_u32().await? as usize;
            ensure!(length <= 64 * 1024, "早期 Noise 数据超过上限");
            let mut early = vec![0; length];
            tokio::time::timeout(Duration::from_secs(15), encrypted.read_exact(&mut early))
                .await??;
            let _: Value = serde_json::from_slice(&early)?;
            Vec::new()
        } else {
            magic.to_vec()
        };
        let stream = Prefixed {
            inner: encrypted,
            prefix: std::io::Cursor::new(prefix),
        };
        let (sender, connection) = h2::client::handshake(stream).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { sender, node_key })
    }

    pub async fn post(&self, path: &str, value: &Value) -> Result<h2::RecvStream> {
        let mut sender = self.sender.clone().ready().await?;
        let request = http::Request::post(path)
            .header("Content-Type", "application/json")
            .header("Ts-Lb", &self.node_key)
            .body(())?;
        let (response, mut body) = sender.send_request(request, false)?;
        body.send_data(Bytes::from(serde_json::to_vec(value)?), true)?;
        let response = tokio::time::timeout(Duration::from_secs(30), response).await??;
        ensure!(
            response.status().is_success(),
            "控制面请求失败（HTTP {}）",
            response.status()
        );
        Ok(response.into_body())
    }

    pub async fn register(&self, config: &Config, auth_key: &str) -> Result<bool> {
        let mut request = json!({"Version":CAPABILITY_VERSION,"NodeKey":self.node_key,"Hostinfo":hostinfo(config, 0)});
        if !auth_key.is_empty() {
            request["Auth"] = json!({"AuthKey":auth_key});
        }
        let mut response = self.post("/machine/register", &request).await?;
        let mut bytes = Vec::new();
        while let Some(chunk) =
            tokio::time::timeout(Duration::from_secs(30), response.data()).await?
        {
            let chunk = chunk?;
            response.flow_control().release_capacity(chunk.len())?;
            ensure!(bytes.len() + chunk.len() <= 64 * 1024, "注册响应过大");
            bytes.extend_from_slice(&chunk);
        }
        let result: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            result
                .get("Error")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty),
            "注册被拒绝，请检查密钥、设备额度或审批状态"
        );
        if let Some(auth_url) = result
            .get("AuthURL")
            .and_then(Value::as_str)
            .filter(|url| !url.is_empty())
        {
            let target = Url::parse(auth_url)?;
            let origin = Url::parse(&config.server)?;
            ensure!(
                target.origin() == origin.origin()
                    && target.username().is_empty()
                    && target.password().is_none(),
                "拒绝跨站设备授权地址"
            );
            #[cfg(target_os = "linux")]
            eprintln!("请在浏览器登录自己的账号并批准设备：{target}");
            #[cfg(target_os = "android")]
            crate::mobile::publish(&json!({"type":"authorization","url":target.as_str()}));
            return Ok(false);
        }
        ensure!(
            result
                .get("MachineAuthorized")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            "设备尚未授权"
        );
        Ok(true)
    }

    pub async fn open_map(
        &self,
        config: &Config,
        identity: &Identity,
        endpoints: &[String],
        region: u16,
    ) -> Result<h2::RecvStream> {
        self.post(
            "/machine/map",
            &json!({"Version":CAPABILITY_VERSION,"NodeKey":self.node_key,
            "DiscoKey":public_key(&identity.disco,"discokey:"),"Hostinfo":hostinfo(config,region),
            "Endpoints":endpoints,"Stream":true,"KeepAlive":true,"Compress":""}),
        )
        .await
    }

    pub async fn update_endpoints(
        &self,
        config: &Config,
        identity: &Identity,
        endpoints: &[String],
        region: u16,
    ) -> Result<()> {
        let _response = self
            .post(
                "/machine/map",
                &json!({"Version":CAPABILITY_VERSION,"NodeKey":self.node_key,
            "DiscoKey":public_key(&identity.disco,"discokey:"),"Hostinfo":hostinfo(config,region),
            "Endpoints":endpoints,"Stream":false,"OmitPeers":true}),
            )
            .await?;
        Ok(())
    }
}

fn hostinfo(config: &Config, region: u16) -> Value {
    json!({"Hostname":config.hostname,"OS":std::env::consts::OS,"IPNVersion":format!("xunara-client/{VERSION}"),
        "RoutableIPs":config.advertise_routes,"NetInfo":{"PreferredDERP":region}})
}

pub async fn run(
    config: Arc<Config>,
    identity: Arc<Identity>,
    auth_key: Zeroizing<String>,
    endpoints: watch::Receiver<Vec<String>>,
    maps: mpsc::Sender<NetworkMap>,
) -> Result<()> {
    let url = crate::config::server_url(&config.server)?;
    let mut retry = 1;
    loop {
        match session(
            &config,
            &identity,
            &url,
            auth_key.trim(),
            endpoints.clone(),
            &maps,
        )
        .await
        {
            Ok(()) => bail!("网络映射接收端已停止"),
            Err(error) => {
                #[cfg(target_os = "linux")]
                {
                    eprintln!("控制连接失败：{error:#}");
                    eprintln!("控制面连接中断；重试间隔 {retry} 秒，失联超过 120 秒后停止转发");
                }
                #[cfg(target_os = "android")]
                {
                    // 只显示本地错误上下文；注册响应正文、请求对象和密钥不进入诊断。
                    crate::mobile::publish(
                        &json!({"type":"reconnecting","message":format!("连接失败：{error}；{retry} 秒后重试")}),
                    );
                }
                tokio::time::sleep(Duration::from_secs(retry)).await;
                retry = (retry * 2).min(30);
            }
        }
    }
}

async fn session(
    config: &Config,
    identity: &Identity,
    url: &Url,
    auth_key: &str,
    mut endpoints: watch::Receiver<Vec<String>>,
    maps: &mpsc::Sender<NetworkMap>,
) -> Result<()> {
    let client = Client::connect(url, identity).await?;
    loop {
        if client.register(config, auth_key).await? {
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let mut map = NetworkMap::default();
    let initial = endpoints.borrow().clone();
    let mut incoming = client.open_map(config, identity, &initial, 0).await?;
    let mut bytes = BytesMut::new();
    let mut home = 0;
    let mut expiry = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            chunk = tokio::time::timeout(Duration::from_secs(90), incoming.data()) => {
                let chunk = chunk?.context("映射流已结束")??;
                incoming.flow_control().release_capacity(chunk.len())?;
                ensure!(bytes.len() + chunk.len() <= MAX_MAP_FRAME + 4, "网络映射缓冲超过上限");
                bytes.extend_from_slice(&chunk);
                while bytes.len() >= 4 {
                    let length = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
                    ensure!(length > 0 && length <= MAX_MAP_FRAME, "网络映射帧长度无效");
                    if bytes.len() < length + 4 { break; }
                    bytes.advance(4);
                    let update: Value = serde_json::from_slice(&bytes.split_to(length))?;
                    map.apply(update)?;
                    if !map.node.as_ref().is_some_and(|node| node.valid()) {
                        let _ = maps.send(map.clone()).await;
                        bail!("设备已失效、撤销或未授权");
                    }
                    if home == 0 { home = map.derp.regions.keys().next().copied().unwrap_or(0); }
                    if maps.send(map.clone()).await.is_err() { return Ok(()); }
                }
            }
            changed = endpoints.changed() => {
                changed?;
                let advertised = endpoints.borrow().clone();
                client.update_endpoints(config, identity, &advertised, home).await?;
            }
            _ = expiry.tick() => {
                ensure!(map.node.as_ref().is_none_or(|node| node.valid()), "设备密钥已过期");
                let advertised = endpoints.borrow().clone();
                client.update_endpoints(config, identity, &advertised, home).await?;
            }
        }
    }
}

struct Prefixed<Stream> {
    inner: Stream,
    prefix: std::io::Cursor<Vec<u8>>,
}

impl<Stream: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Prefixed<Stream> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            let length = std::io::Read::read(&mut self.prefix, output.initialize_unfilled())?;
            output.advance(length);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(context, output)
    }
}

impl<Stream: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Prefixed<Stream> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(context, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
