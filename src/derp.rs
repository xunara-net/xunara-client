use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, AeadCore},
};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use url::Url;

use crate::{
    model::{DerpMap, DerpNode},
    transport,
};

pub struct Received {
    pub region: u16,
    pub peer: [u8; 32],
    pub bytes: Vec<u8>,
}
struct Outbound {
    peer: [u8; 32],
    bytes: Vec<u8>,
}
struct Worker {
    definition: Vec<DerpNode>,
    sender: mpsc::Sender<Outbound>,
    health: watch::Receiver<Option<Duration>>,
    preferred: watch::Sender<bool>,
    started: Instant,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct Heartbeat(Option<([u8; 8], Instant)>);

impl Heartbeat {
    fn ping(&mut self) -> Result<[u8; 8]> {
        ensure!(self.0.is_none(), "DERP 心跳未收到匹配回应");
        let mut nonce = [0; 8];
        OsRng.fill_bytes(&mut nonce);
        self.0 = Some((nonce, Instant::now()));
        Ok(nonce)
    }

    fn pong(&mut self, payload: &[u8]) -> Option<Duration> {
        let (nonce, started) = self.0?;
        if nonce.as_slice() != payload || started.elapsed() >= Duration::from_secs(15) {
            return None;
        }
        self.0 = None;
        Some(started.elapsed())
    }
}

#[derive(Default)]
pub struct Hub {
    workers: BTreeMap<u16, Worker>,
    attempted: BTreeMap<u16, Instant>,
    home: u16,
}

impl Hub {
    pub fn home_region(&self) -> u16 {
        if self
            .workers
            .get(&self.home)
            .is_some_and(|worker| worker.health.borrow().is_some() && !worker.task.is_finished())
        {
            self.home
        } else {
            0
        }
    }

    pub fn update(
        &mut self,
        map: &DerpMap,
        regions: &[u16],
        private: [u8; 32],
        incoming: mpsc::Sender<Received>,
    ) -> Result<()> {
        let definitions = map
            .regions
            .iter()
            .filter_map(|(region, configuration)| {
                let nodes = configuration
                    .nodes
                    .iter()
                    .filter(|node| !node.stun_only)
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>();
                (*region != 0 && !nodes.is_empty()).then_some((*region, nodes))
            })
            .collect::<BTreeMap<_, _>>();
        self.attempted
            .retain(|region, _| definitions.contains_key(region));
        self.workers.retain(|region, worker| {
            let keep = definitions.get(region) == Some(&worker.definition);
            if !keep {
                worker.task.abort();
                self.attempted.remove(region);
            }
            keep
        });
        let eligible = |region: &u16| {
            map.regions.get(region).is_some_and(|configuration| {
                !configuration.no_measure_no_home && !configuration.avoid
            })
        };
        let healthy = |region: &u16| {
            eligible(region)
                && self
                    .workers
                    .get(region)
                    .is_some_and(|worker| worker.health.borrow().is_some())
        };
        // 已有可用 home 保持稳定；只有经过 TLS、DERP 身份握手和匹配 Pong 的连接才能上报。
        if !healthy(&self.home) {
            self.home = self
                .workers
                .iter()
                .filter(|(region, _)| healthy(region))
                .min_by_key(|(region, worker)| (*worker.health.borrow(), **region))
                .map_or(0, |(region, _)| *region);
        }
        let mut wanted = regions
            .iter()
            .filter(|region| definitions.contains_key(region))
            .copied()
            .collect::<BTreeSet<_>>();
        if self.home != 0 {
            wanted.insert(self.home);
        }
        ensure!(wanted.len() <= 32, "需要连接的 DERP 区域超过首版上限");
        if self.home == 0 {
            // 无 home 时最多并行四条候选连接，轮换失败区域；不能永久困在最小编号上。
            let mut candidates = definitions
                .keys()
                .filter(|region| eligible(region) && !wanted.contains(region))
                .copied()
                .collect::<Vec<_>>();
            candidates.sort_by_key(|region| {
                let probing = self
                    .workers
                    .get(region)
                    .is_some_and(|worker| worker.started.elapsed() < Duration::from_secs(15));
                (!probing, self.attempted.get(region).copied(), *region)
            });
            wanted.extend(candidates.into_iter().take(4.min(32 - wanted.len())));
        }
        self.workers.retain(|region, worker| {
            if wanted.contains(region) {
                return true;
            }
            worker.task.abort();
            false
        });
        for region in wanted {
            if let Some(worker) = self.workers.get(&region) {
                worker.preferred.send_if_modified(|preferred| {
                    let updated = region == self.home;
                    let changed = *preferred != updated;
                    *preferred = updated;
                    changed
                });
                continue;
            }
            let nodes = definitions[&region].clone();
            let definition = nodes.clone();
            let (sender, receiver) = mpsc::channel(128);
            let (health_sender, health) = watch::channel(None);
            let (preferred, preference) = watch::channel(region == self.home);
            let incoming = incoming.clone();
            let task = tokio::spawn(async move {
                reconnect(
                    region,
                    nodes,
                    private,
                    receiver,
                    incoming,
                    health_sender,
                    preference,
                )
                .await;
            });
            let started = Instant::now();
            self.attempted.insert(region, started);
            self.workers.insert(
                region,
                Worker {
                    definition,
                    sender,
                    health,
                    preferred,
                    started,
                    task,
                },
            );
        }
        Ok(())
    }

    pub fn send(&self, region: u16, peer: [u8; 32], bytes: &[u8]) {
        if bytes.len() <= 65536
            && let Some(worker) = self.workers.get(&region)
        {
            let _ = worker.sender.try_send(Outbound {
                peer,
                bytes: bytes.to_vec(),
            });
        }
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        for worker in self.workers.values() {
            worker.task.abort();
        }
    }
}

async fn reconnect(
    region: u16,
    nodes: Vec<DerpNode>,
    private: [u8; 32],
    mut outgoing: mpsc::Receiver<Outbound>,
    incoming: mpsc::Sender<Received>,
    health: watch::Sender<Option<Duration>>,
    mut preferred: watch::Receiver<bool>,
) {
    let mut attempt = 0;
    loop {
        let node = &nodes[attempt % nodes.len()];
        let result = session(
            region,
            node,
            private,
            &mut outgoing,
            &incoming,
            &health,
            &mut preferred,
        )
        .await;
        health.send_replace(None);
        if result.is_ok() || outgoing.is_closed() {
            return;
        }
        eprintln!("DERP {region} 暂不可用，等待重连");
        attempt += 1;
        tokio::time::sleep(Duration::from_secs((attempt as u64).min(10))).await;
    }
}

async fn session(
    region: u16,
    node: &DerpNode,
    private: [u8; 32],
    outgoing: &mut mpsc::Receiver<Outbound>,
    incoming: &mpsc::Sender<Received>,
    health: &watch::Sender<Option<Duration>>,
    preferred: &mut watch::Receiver<bool>,
) -> Result<()> {
    let port = if node.derp_port == 0 {
        443
    } else {
        u16::try_from(node.derp_port)?
    };
    ensure!(
        !node.host_name.contains(['/', '?', '#', '@', '\r', '\n']) && !node.host_name.is_empty(),
        "DERP 主机无效"
    );
    let scheme = if node.insecure_for_tests {
        "http"
    } else {
        "https"
    };
    let mut url = Url::parse(&format!("{scheme}://{}", node.host_name))?;
    url.set_port(Some(port))
        .map_err(|_| anyhow::anyhow!("DERP 端口无效"))?;
    url.set_path("/derp");
    let stream = transport::connect(&url, &node.cert_name, Some(&node.ipv4)).await?;
    let upgraded = transport::upgrade(&url, stream, "DERP", &[]).await?;
    let mut stream = hyper_util::rt::TokioIo::new(upgraded);
    let (kind, greeting) = read_frame(&mut stream).await?;
    ensure!(
        kind == 1 && greeting.len() >= 40 && &greeting[..8] == b"DERP\xf0\x9f\x94\x91",
        "DERP 握手魔数无效"
    );
    let public: [u8; 32] = greeting[8..40].try_into()?;
    ensure!(public != [0; 32], "DERP 公钥无效");
    let secret = SecretKey::from(private);
    let cipher = SalsaBox::new(&PublicKey::from(public), &secret);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let information =
        serde_json::to_vec(&json!({"version":2,"CanAckPings":true,"AppName":"xunara-client"}))?;
    let encrypted = cipher
        .encrypt(&nonce, information.as_slice())
        .map_err(|_| anyhow::anyhow!("DERP 身份加密失败"))?;
    let mut payload = secret.public_key().as_bytes().to_vec();
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&encrypted);
    write_frame(&mut stream, 2, &payload).await?;
    let (kind, information) = read_frame(&mut stream).await?;
    ensure!(
        kind == 3 && information.len() >= 40,
        "DERP 未接受客户端身份"
    );
    let clear = cipher
        .decrypt(information[..24].into(), &information[24..])
        .map_err(|_| anyhow::anyhow!("DERP 服务端身份校验失败"))?;
    let _: serde_json::Value = serde_json::from_slice(&clear)?;
    let preference = *preferred.borrow_and_update();
    write_frame(&mut stream, 7, &[u8::from(preference)]).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (control, mut received_control) = mpsc::channel::<(u8, Vec<u8>)>(8);
    let incoming = incoming.clone();
    let mut reading = AbortOnDrop(tokio::spawn(async move {
        loop {
            let (kind, payload) = read_frame(&mut reader).await?;
            match kind {
                5 if payload.len() >= 32 => {
                    let peer = payload[..32].try_into()?;
                    if incoming
                        .send(Received {
                            region,
                            peer,
                            bytes: payload[32..].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        return Ok::<(), anyhow::Error>(());
                    }
                }
                0x12 | 0x13 if payload.len() == 8 => {
                    if control.try_send((kind, payload)).is_err() {
                        bail!("DERP 心跳积压");
                    }
                }
                0x15 => bail!("DERP 请求重连"),
                _ => {}
            }
        }
    }));
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut heartbeat = Heartbeat::default();
    loop {
        tokio::select! {
            result = &mut reading.0 => return result?,
            Some((kind, payload)) = received_control.recv() => {
                if kind == 0x12 {
                    write_frame(&mut writer,0x13,&payload).await?;
                } else if let Some(rtt) = heartbeat.pong(&payload) {
                    health.send_replace(Some(rtt));
                }
            }
            changed = preferred.changed() => {
                changed?;
                let preference = *preferred.borrow_and_update();
                write_frame(&mut writer,7,&[u8::from(preference)]).await?;
            }
            packet = outgoing.recv() => {
                let Some(packet) = packet else { return Ok(()); };
                let mut payload = packet.peer.to_vec(); payload.extend_from_slice(&packet.bytes);
                write_frame(&mut writer,4,&payload).await?;
            }
            _ = ticker.tick() => {
                let nonce = heartbeat.ping()?;
                write_frame(&mut writer,0x12,&nonce).await?;
            }
        }
    }
}

struct AbortOnDrop<Output>(JoinHandle<Output>);
impl<Output> Drop for AbortOnDrop<Output> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> Result<(u8, Vec<u8>)> {
    tokio::time::timeout(Duration::from_secs(90), async {
        let kind = stream.read_u8().await?;
        let length = stream.read_u32().await? as usize;
        ensure!(length <= 65568, "DERP 帧超过上限");
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await?;
        Ok((kind, payload))
    })
    .await
    .context("DERP 读超时")?
}

async fn write_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    kind: u8,
    payload: &[u8],
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        stream.write_u8(kind).await?;
        stream.write_u32(payload.len() as u32).await?;
        stream.write_all(payload).await?;
        stream.flush().await?;
        Ok(())
    })
    .await
    .context("DERP 写超时")?
}

#[cfg(test)]
mod tests;
