use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use boringtun::{
    noise::{Tunn, TunnResult, rate_limiter::RateLimiter},
    x25519,
};
use ipnet::IpNet;
use serde_json::json;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
};

use crate::{
    config::Config,
    derp::{Hub, Received},
    diagnostic::{PingRequest, Pings},
    discovery,
    dns_stack::DnsProxy,
    filter::{Filter, Packet},
    forwarding::Forwarder,
    masquerade,
    model::{LocalState, NetworkMap, Node},
    network::{self, Routes, Tun},
    state::{Identity, Store, parse_key},
};

#[derive(Clone, Copy)]
enum Path {
    Udp(SocketAddr),
    Derp(u16),
}
enum Output {
    Wire(Vec<u8>),
    Plain(Vec<u8>),
    Done,
    Invalid,
}

impl From<TunnResult<'_>> for Output {
    fn from(result: TunnResult<'_>) -> Self {
        match result {
            TunnResult::WriteToNetwork(bytes) => Self::Wire(bytes.to_vec()),
            TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                Self::Plain(bytes.to_vec())
            }
            TunnResult::Done => Self::Done,
            TunnResult::Err(_) => Self::Invalid,
        }
    }
}

struct Peer {
    node: Node,
    key: [u8; 32],
    disco: Option<[u8; 32]>,
    tunnel: Tunn,
    index: u32,
    direct: Option<(SocketAddr, Instant)>,
    probes: VecDeque<([u8; 12], SocketAddr, Instant)>,
    extra_endpoints: Vec<SocketAddr>,
}

impl Peer {
    fn direct_address(&self, now: Instant) -> Option<SocketAddr> {
        let lifetime = if self.disco.is_some() {
            Duration::from_millis(6500)
        } else {
            Duration::from_secs(5)
        };
        self.direct
            .filter(|(_, confirmed)| now.saturating_duration_since(*confirmed) < lifetime)
            .map(|(address, _)| address)
    }

    fn authenticated_udp(&mut self, source: SocketAddr, now: Instant) {
        // 收到 WireGuard 只证明入站可达；Disco 节点必须用往返探测确认回程。
        // 无 Disco 的纯 WireGuard 对端才短暂沿用已认证的源地址。
        if self.disco.is_none() {
            self.direct = Some((source, now));
        }
    }

    fn confirm_pong(&mut self, source: SocketAddr, transaction: &[u8], now: Instant) -> bool {
        let Some(position) = self.probes.iter().position(|(expected, target, sent)| {
            expected.as_slice() == transaction
                && *target == source
                && now.saturating_duration_since(*sent) < Duration::from_secs(10)
        }) else {
            return false;
        };
        // 消耗已匹配的事务，重放的 Pong 不能再次延长直连信任。
        self.probes.remove(position);
        self.direct = Some((source, now));
        true
    }

    fn maintain(&mut self, scratch: &mut [u8], initial_budget: &mut u8) -> Output {
        let action = Output::from(self.tunnel.update_timers(scratch));
        if matches!(action, Output::Done)
            && *initial_budget > 0
            && self.tunnel.persistent_keepalive().is_some()
            && self.tunnel.time_since_last_handshake().is_none()
        {
            // 与官方 WireGuard 启用 persistent keepalive 时相同，重连主动建立新会话。
            // 纯接收端不能等远端旧会话过期才恢复；限额只消耗实际发出的首握手。
            let action = Output::from(self.tunnel.format_handshake_initiation(scratch, false));
            if matches!(action, Output::Wire(_)) {
                *initial_budget -= 1;
            }
            return action;
        }
        action
    }

    fn endpoints(&self) -> Vec<SocketAddr> {
        self.node
            .endpoints
            .iter()
            .chain(&self.extra_endpoints)
            .filter(|address| {
                address.is_ipv4()
                    && !address.ip().is_loopback()
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast()
                    && address.port() != 0
            })
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(16)
            .collect()
    }

    fn source_allowed(&self, packet: Packet, exit: bool) -> bool {
        self.node
            .addresses
            .iter()
            .chain(&self.node.allowed_ips)
            .any(|network| {
                (network.prefix_len() > 0 || (exit && self.node.exit_node()))
                    && network.contains(&packet.source)
            })
    }

    fn prefix(&self, packet: Packet, accept_routes: bool, exit: bool) -> Option<u8> {
        self.node
            .addresses
            .iter()
            .chain(if accept_routes || exit {
                self.node.allowed_ips.iter()
            } else {
                [].iter()
            })
            .filter(|network| {
                (network.prefix_len() > 0 && accept_routes
                    || network.prefix_len() == 0 && exit && self.node.exit_node()
                    || self.node.addresses.contains(network))
                    && network.contains(&packet.destination)
            })
            .map(IpNet::prefix_len)
            .max()
    }
}

#[derive(Default, serde::Serialize)]
struct ReceiveStats {
    tun_packets: u64,
    tun_source_drops: u64,
    dns_queries: u64,
    encrypted_packets: u64,
    decrypt_errors: u64,
    decoded_packets: u64,
    invalid_packets: u64,
    source_drops: u64,
    destination_drops: u64,
    acl_drops: u64,
    related_icmp: u64,
    untracked_exit_drops: u64,
}

pub struct Engine {
    config: Arc<Config>,
    identity: Arc<Identity>,
    socket: Arc<UdpSocket>,
    tun: Tun,
    routes: Routes,
    peers: BTreeMap<u64, Peer>,
    map: NetworkMap,
    filter: Filter,
    last_map: Option<Instant>,
    next_index: u32,
    hub: Hub,
    derp_input: mpsc::Receiver<Received>,
    derp_output: mpsc::Sender<Received>,
    endpoints: watch::Sender<LocalState>,
    stun: Vec<([u8; 12], SocketAddr, Instant)>,
    mapped: BTreeMap<SocketAddr, Instant>,
    own_node: [u8; 32],
    limiter: Arc<RateLimiter>,
    received_bytes: u64,
    sent_bytes: u64,
    ticks: u64,
    budget: u32,
    diagnostic_input: Option<mpsc::Receiver<PingRequest>>,
    pings: Pings,
    dns: Option<DnsProxy>,
    forwarding: Option<Forwarder>,
    receive_stats: ReceiveStats,
}

impl Engine {
    pub async fn new(
        config: Arc<Config>,
        identity: Arc<Identity>,
        endpoints: watch::Sender<LocalState>,
    ) -> Result<Self> {
        network::forwarding_ready(&config)?;
        let socket = Arc::new(UdpSocket::bind(config.listen).await?);
        #[cfg(target_os = "android")]
        {
            use std::os::fd::AsRawFd;
            crate::mobile::host()?.protect(socket.as_raw_fd())?;
        }
        let local = network::local_endpoints(socket.local_addr()?.port(), &config.interface);
        endpoints.send_replace(LocalState {
            endpoints: local,
            home_derp: 0,
        });
        let tun = Tun::create(&config).await?;
        let own_node = *crypto_box::SecretKey::from(identity.node)
            .public_key()
            .as_bytes();
        let limiter = Arc::new(RateLimiter::new(&x25519::PublicKey::from(own_node), 50));
        let (derp_output, derp_input) = mpsc::channel(256);
        Ok(Self {
            config,
            identity,
            socket,
            tun,
            routes: Routes::default(),
            peers: BTreeMap::new(),
            map: NetworkMap::default(),
            filter: Filter::default(),
            last_map: None,
            next_index: 1,
            hub: Hub::default(),
            derp_input,
            derp_output,
            endpoints,
            stun: Vec::new(),
            mapped: BTreeMap::new(),
            own_node,
            limiter,
            received_bytes: 0,
            sent_bytes: 0,
            ticks: 0,
            budget: 100,
            diagnostic_input: None,
            pings: Pings::default(),
            dns: None,
            forwarding: None,
            receive_stats: ReceiveStats::default(),
        })
    }

    pub fn enable_diagnostics(&mut self, requests: mpsc::Receiver<PingRequest>) {
        self.diagnostic_input = Some(requests);
    }

    pub async fn run(&mut self, mut maps: mpsc::Receiver<NetworkMap>, store: &Store) -> Result<()> {
        let mut udp = vec![0; 65568];
        let mut packet = vec![0; 65536];
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        let mut dns_ticker = tokio::time::interval(Duration::from_millis(20));
        dns_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            enum Event {
                Map(Option<Box<NetworkMap>>),
                Udp(std::io::Result<(usize, SocketAddr)>),
                Packet(std::io::Result<usize>),
                Derp(Option<Received>),
                Ping(Option<PingRequest>),
                Tick,
                Dns,
            }
            let event = tokio::select! {
                map = maps.recv() => Event::Map(map.map(Box::new)),
                received = self.socket.recv_from(&mut udp) => Event::Udp(received),
                length = self.tun.read(&mut packet) => Event::Packet(length),
                received = self.derp_input.recv() => Event::Derp(received),
                request = async {
                    match self.diagnostic_input.as_mut() {
                        Some(requests) => requests.recv().await,
                        None => std::future::pending().await,
                    }
                } => Event::Ping(request),
                _ = ticker.tick() => Event::Tick,
                _ = async { if self.dns.is_some() || self.forwarding.is_some() {dns_ticker.tick().await;} else {std::future::pending::<()>().await;} } => Event::Dns,
            };
            match event {
                Event::Map(map) => {
                    self.apply(*map.context("控制面任务已停止")?).await?;
                    self.status(store)?;
                }
                Event::Udp(received) => {
                    if let Ok((length, source)) = received {
                        self.receive(None, Path::Udp(source), &udp[..length])
                            .await?;
                    }
                }
                Event::Packet(length) => {
                    let length = length?;
                    self.outgoing(&packet[..length]).await?;
                }
                Event::Derp(Some(received)) => {
                    self.receive(
                        Some(received.peer),
                        Path::Derp(received.region),
                        &received.bytes,
                    )
                    .await?
                }
                Event::Derp(None) => anyhow::bail!("中继输入已停止"),
                Event::Ping(Some(request)) => self.ping(request).await?,
                Event::Ping(None) => self.diagnostic_input = None,
                Event::Tick => {
                    self.pings.expire();
                    self.tick().await?;
                    #[cfg(target_os = "android")]
                    crate::mobile::publish(&self.snapshot());
                    if self.ticks.is_multiple_of(10) {
                        self.status(store)?;
                    }
                }
                Event::Dns => {
                    self.poll_dns().await?;
                    self.poll_forwarding().await?;
                }
            }
        }
    }

    fn fresh(&self) -> bool {
        self.last_map
            .is_some_and(|received| received.elapsed() < Duration::from_secs(120))
            && self.map.node.as_ref().is_some_and(Node::valid)
    }

    async fn apply(&mut self, map: NetworkMap) -> Result<()> {
        let node = map.node.as_ref().context("缺少设备映射")?;
        ensure!(
            node.valid() && parse_key(&node.key, "nodekey:")? == self.own_node,
            "本机映射密钥不匹配或未授权"
        );
        let nodes = map.nodes()?;
        let source_changed = self
            .map
            .node
            .as_ref()
            .is_none_or(|previous| previous.source_policy() != node.source_policy())
            || self.peers.len() != nodes.iter().filter(|peer| peer.valid()).count()
            || nodes.iter().filter(|peer| peer.valid()).any(|node| {
                self.peers
                    .get(&node.id)
                    .is_none_or(|previous| previous.node.source_policy() != node.source_policy())
            });
        let stable_ids = nodes
            .iter()
            .filter(|node| !node.stable_id.is_empty())
            .map(|node| &node.stable_id)
            .collect::<Vec<_>>();
        ensure!(
            stable_ids.iter().collect::<BTreeSet<_>>().len() == stable_ids.len(),
            "网络映射含重复 StableID，拒绝不明确的出口身份"
        );
        let keys = nodes
            .iter()
            .filter(|node| node.valid())
            .map(|node| parse_key(&node.key, "nodekey:"))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            keys.iter().collect::<BTreeSet<_>>().len() == keys.len()
                && !keys.contains(&self.own_node),
            "网络映射含重复或本机 peer key"
        );
        let filter = Filter::compile(&map.filter)?;
        #[cfg(target_os = "android")]
        {
            let forwarding = crate::forwarding::Plan::new(&self.config, &map)?;
            let reset_forwarding = self.forwarding.as_ref().map(Forwarder::plan)
                != forwarding.as_ref()
                || self.map.filter != map.filter
                || !self.fresh();
            if reset_forwarding {
                // 路由撤销、来源 / 机器密钥或 ACL 变化时销毁旧连接和后台拨号，不能沿用旧授权。
                self.forwarding = forwarding.map(Forwarder::new);
            }
            let host = crate::mobile::host()?;
            let mut dns_config = (*self.config).clone();
            dns_config.accept_dns |= self
                .forwarding
                .as_ref()
                .is_some_and(|router| router.plan().exit());
            let plan = crate::dns::DnsPlan::new(
                &dns_config,
                &map,
                &host.local_networks()?,
                &host.dns_servers()?,
            )?;
            if self.dns.as_ref().map(DnsProxy::plan) != plan.as_ref() || reset_forwarding {
                self.dns = plan.map(DnsProxy::new).transpose()?;
            }
            if let (Some(router), Some(dns)) = (&mut self.forwarding, &self.dns) {
                router.set_dns(dns.api_sender());
            }
        }
        self.routes.apply(&self.config, &map).await?;
        #[cfg(target_os = "android")]
        self.tun.install(self.routes.take_descriptor())?;
        self.peers.retain(|identity, _| {
            nodes
                .iter()
                .any(|node| node.id == *identity && node.valid())
        });
        for node in nodes.into_iter().filter(Node::valid) {
            let key = parse_key(&node.key, "nodekey:")?;
            let disco = if node.disco_key.is_empty() {
                None
            } else {
                Some(parse_key(&node.disco_key, "discokey:")?)
            };
            if let Some(peer) = self.peers.get_mut(&node.id).filter(|peer| peer.key == key) {
                if peer.disco != disco {
                    peer.direct = None;
                    peer.probes.clear();
                }
                peer.node = node;
                peer.disco = disco;
                continue;
            }
            ensure!(self.next_index < 1 << 24, "隧道索引已耗尽，请重启客户端");
            let index = self.next_index;
            self.next_index += 1;
            let tunnel = Tunn::new(
                self.identity.node.into(),
                key.into(),
                None,
                Some(20),
                index,
                Some(self.limiter.clone()),
            );
            self.peers.insert(
                node.id,
                Peer {
                    node,
                    key,
                    disco,
                    tunnel,
                    index,
                    direct: None,
                    probes: VecDeque::new(),
                    extra_endpoints: Vec::new(),
                },
            );
        }
        if self.map.filter != map.filter || source_changed || !self.fresh() {
            // IP 被重新分配或 peer 密钥 / 共享别名变化后，不把旧连接的回包许可授予新机器。
            self.filter = filter;
        }
        self.map = map;
        self.last_map = Some(Instant::now());
        self.update_relays()?;
        Ok(())
    }

    fn update_relays(&mut self) -> Result<()> {
        let regions = self
            .peers
            .values()
            .map(|peer| peer.node.relay_region())
            .filter(|region| *region > 0)
            .collect::<BTreeSet<_>>();
        self.hub.update(
            &self.map.derp,
            &regions.into_iter().collect::<Vec<_>>(),
            self.identity.node,
            self.derp_output.clone(),
        )?;
        let home = self.hub.home_region();
        self.endpoints.send_if_modified(|local| {
            if local.home_derp == home {
                return false;
            }
            // HomeDERP 是实际能收回包的连接，不是 DERPMap 中最小的区域编号。
            local.home_derp = home;
            true
        });
        Ok(())
    }

    async fn outgoing(&mut self, bytes: &[u8]) -> Result<()> {
        if !self.fresh() {
            return Ok(());
        }
        let Some(packet) = Packet::parse(bytes) else {
            return Ok(());
        };
        self.receive_stats.tun_packets += 1;
        if !self.routes.local_source(packet.source) {
            self.receive_stats.tun_source_drops += 1;
            return Ok(());
        }
        if let Some(dns) = self.dns.as_mut().filter(|dns| dns.local(bytes)) {
            self.receive_stats.dns_queries += 1;
            dns.ingest(bytes);
            return Ok(());
        }
        if !self.routes.remote_destination(packet.destination) {
            return Ok(());
        }
        let selected = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.node.valid())
            .filter_map(|(identity, peer)| {
                peer.prefix(
                    packet,
                    self.config.accept_routes,
                    !self.config.exit_node_id.is_empty()
                        && self.config.exit_node_id == peer.node.stable_id,
                )
                .map(|prefix| (*identity, prefix))
            })
            .max_by_key(|(_, prefix)| *prefix)
            .map(|(identity, _)| identity);
        let Some(selected) = selected else {
            return Ok(());
        };
        self.filter.outgoing(packet);
        self.sent_bytes += bytes.len() as u64;
        let mut output = vec![0; 65568];
        let Some(bytes) = self.map.node.as_ref().and_then(|node| {
            masquerade::outgoing(bytes, &node.addresses, &self.peers[&selected].node)
        }) else {
            return Ok(());
        };
        let action = Output::from(
            self.peers
                .get_mut(&selected)
                .context("peer 已删除")?
                .tunnel
                .encapsulate(&bytes, &mut output),
        );
        if let Output::Wire(bytes) = action {
            self.transmit(selected, None, &bytes).await;
        }
        Ok(())
    }

    async fn poll_dns(&mut self) -> Result<()> {
        let packets = self.dns.as_mut().map(DnsProxy::poll).unwrap_or_default();
        if !self.fresh() {
            return Ok(());
        }
        for bytes in packets {
            if let Some(packet) = Packet::parse(&bytes) {
                if self.routes.local_destination(packet.destination) {
                    self.tun.write(&bytes).await?;
                } else {
                    self.outgoing(&bytes).await?;
                }
            }
        }
        Ok(())
    }

    async fn poll_forwarding(&mut self) -> Result<()> {
        if !self.fresh() || self.peers.values().any(|peer| !peer.node.valid()) {
            self.forwarding = None;
            return Ok(());
        }
        let packets = self
            .forwarding
            .as_mut()
            .map(Forwarder::poll)
            .unwrap_or_default();
        for (identity, bytes) in packets {
            let Some(peer) = self
                .peers
                .get_mut(&identity)
                .filter(|peer| peer.node.valid())
            else {
                continue;
            };
            let mut output = vec![0; 65568];
            let Some(node) = self.map.node.as_ref() else {
                continue;
            };
            let Some(bytes) = masquerade::outgoing(&bytes, &node.addresses, &peer.node) else {
                continue;
            };
            let action = Output::from(peer.tunnel.encapsulate(&bytes, &mut output));
            self.sent_bytes += bytes.len() as u64;
            if let Output::Wire(bytes) = action {
                self.transmit(identity, None, &bytes).await;
            }
        }
        Ok(())
    }

    async fn ping(&mut self, request: PingRequest) -> Result<()> {
        let addresses = (|| -> Result<_> {
            ensure!(self.fresh(), "网络映射已失效，请连接后重试");
            let peer = self
                .peers
                .get(&request.peer)
                .filter(|peer| peer.node.valid())
                .context("设备不在当前授权网络内")?;
            let node = self.map.node.as_ref().context("本机尚未授权")?;
            let (source, target) = peer
                .node
                .addresses
                .iter()
                .filter(|address| self.routes.remote_destination(address.addr()))
                .find_map(|target| {
                    node.addresses
                        .iter()
                        .find(|source| source.addr().is_ipv4() == target.addr().is_ipv4())
                        .map(|source| (source.addr(), target.addr()))
                })
                .context("没有可用的设备路由，可能与手机局域网冲突")?;
            Ok((source, target))
        })();
        match addresses {
            Ok((source, target)) => {
                if let Some(bytes) = self.pings.start(request, source, target) {
                    // 诊断走同一 WireGuard / 路由 / 回包 ACL，不使用 App 自身被豁免的 socket。
                    self.outgoing(&bytes).await?;
                }
            }
            Err(error) => {
                let _ = request.reply.try_send(Err(error));
            }
        }
        Ok(())
    }

    async fn transmit(&self, identity: u64, path: Option<Path>, bytes: &[u8]) {
        let Some(peer) = self.peers.get(&identity) else {
            return;
        };
        if let Some(path) = path {
            match path {
                Path::Udp(address) => {
                    if self.socket.send_to(bytes, address).await.is_err() {
                        self.hub.send(peer.node.relay_region(), peer.key, bytes);
                    }
                }
                Path::Derp(region) => self.hub.send(region, peer.key, bytes),
            }
            return;
        }
        if let Some(address) = peer.direct_address(Instant::now()) {
            if self.socket.send_to(bytes, address).await.is_err() {
                self.hub.send(peer.node.relay_region(), peer.key, bytes);
            }
        } else {
            for address in peer.endpoints() {
                let _ = self.socket.send_to(bytes, address).await;
            }
            self.hub.send(peer.node.relay_region(), peer.key, bytes);
        }
    }

    async fn receive(&mut self, known: Option<[u8; 32]>, path: Path, bytes: &[u8]) -> Result<()> {
        if !self.fresh() {
            return Ok(());
        }
        if let Path::Udp(source) = path
            && bytes.len() >= 20
            && bytes[4..8] == [0x21, 0x12, 0xa4, 0x42]
        {
            for (transaction, target, sent) in &self.stun {
                if source == *target
                    && sent.elapsed() < Duration::from_secs(10)
                    && let Some(mapped) = discovery::stun_response(bytes, transaction)
                {
                    self.mapped.insert(mapped, Instant::now());
                }
            }
            self.publish_endpoints()?;
            return Ok(());
        }
        if bytes.starts_with(discovery::MAGIC) {
            if self.budget == 0 {
                return Ok(());
            }
            self.budget -= 1;
            self.disco(known, path, bytes).await;
            return Ok(());
        }
        let parsed = match Tunn::parse_incoming_packet(bytes) {
            Ok(packet) => packet,
            Err(_) => return Ok(()),
        };
        let receiver = match parsed {
            boringtun::noise::Packet::HandshakeInit(_) => None,
            boringtun::noise::Packet::HandshakeResponse(response) => {
                Some(response.receiver_idx >> 8)
            }
            boringtun::noise::Packet::PacketCookieReply(cookie) => Some(cookie.receiver_idx >> 8),
            boringtun::noise::Packet::PacketData(packet) => {
                self.receive_stats.encrypted_packets += 1;
                Some(packet.receiver_idx >> 8)
            }
        };
        if receiver.is_none() {
            if self.budget == 0 {
                return Ok(());
            }
            self.budget -= 1;
        }
        let candidates = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                peer.node.valid()
                    && known.is_none_or(|known| known == peer.key)
                    && receiver.is_none_or(|receiver| receiver == peer.index)
            })
            .map(|(identity, _)| *identity)
            .collect::<Vec<_>>();
        let mut scratch = vec![0; 65568];
        for identity in candidates {
            let source = match path {
                Path::Udp(address) => Some(address.ip()),
                Path::Derp(_) => None,
            };
            let result = self
                .peers
                .get_mut(&identity)
                .context("peer 丢失")?
                .tunnel
                .decapsulate(source, bytes, &mut scratch);
            let action = Output::from(result);
            if matches!(action, Output::Invalid) {
                if receiver.is_some() {
                    self.receive_stats.decrypt_errors += 1;
                }
                continue;
            }
            let authenticated = match &action {
                Output::Plain(_) => true,
                Output::Done => bytes.first() == Some(&4),
                Output::Wire(bytes) => matches!(bytes.first(), Some(2 | 4)),
                Output::Invalid => false,
            };
            if authenticated && let Path::Udp(address) = path {
                self.peers
                    .get_mut(&identity)
                    .context("peer 丢失")?
                    .authenticated_udp(address, Instant::now());
            }
            self.process(identity, path, action).await?;
            for _ in 0..256 {
                let action = Output::from(
                    self.peers
                        .get_mut(&identity)
                        .context("peer 丢失")?
                        .tunnel
                        .decapsulate(None, &[], &mut scratch),
                );
                if matches!(action, Output::Done | Output::Invalid) {
                    break;
                }
                self.process(identity, path, action).await?;
            }
            break;
        }
        Ok(())
    }

    async fn process(&mut self, identity: u64, path: Path, output: Output) -> Result<()> {
        match output {
            Output::Wire(bytes) => self.transmit(identity, Some(path), &bytes).await,
            Output::Plain(mut bytes) => {
                self.receive_stats.decoded_packets += 1;
                // 解密后的对端身份已固定；先按该 peer 还原本机地址，再做 ACL 和连接状态检查。
                let Some(node) = self.map.node.as_ref() else {
                    return Ok(());
                };
                let Some(peer) = self.peers.get(&identity) else {
                    return Ok(());
                };
                if masquerade::incoming(&mut bytes, &node.addresses, &peer.node).is_none() {
                    self.receive_stats.invalid_packets += 1;
                    return Ok(());
                }
                let Some(packet) = Packet::parse(&bytes) else {
                    self.receive_stats.invalid_packets += 1;
                    return Ok(());
                };
                if !peer.source_allowed(
                    packet,
                    !self.config.exit_node_id.is_empty()
                        && self.config.exit_node_id == peer.node.stable_id,
                ) || self.peers.iter().any(|(other, peer)| {
                    *other != identity
                        && peer
                            .node
                            .addresses
                            .iter()
                            .any(|address| address.contains(&packet.source))
                }) {
                    self.receive_stats.source_drops += 1;
                    return Ok(());
                }
                if !self.routes.local_destination(packet.destination)
                    && !self
                        .forwarding
                        .as_ref()
                        .is_some_and(|router| router.plan().handles(packet))
                {
                    self.receive_stats.destination_drops += 1;
                    return Ok(());
                }
                let peer_source = self.peers[&identity]
                    .node
                    .addresses
                    .iter()
                    .chain(
                        self.peers[&identity]
                            .node
                            .allowed_ips
                            .iter()
                            .filter(|prefix| prefix.prefix_len() > 0),
                    )
                    .any(|prefix| prefix.contains(&packet.source));
                let related_error = self.filter.related_error(&bytes);
                let allowed = if peer_source {
                    if self
                        .forwarding
                        .as_ref()
                        .is_some_and(|router| router.plan().peer_dns(packet))
                    {
                        // 与官方 peerapi 一致：出口 DNS 单独检查 autogroup:internet 探针，
                        // 不把可见 peer 或持有 HTTP 连接误当成互联网访问授权。
                        self.filter.permits(Packet {
                            destination: if packet.source.is_ipv4() {
                                "0.0.0.0"
                            } else {
                                "2000::"
                            }
                            .parse()
                            .expect("constant address"),
                            destination_port: 53,
                            protocol: 6,
                            ..packet
                        })
                    } else {
                        self.filter.incoming(packet) || related_error
                    }
                } else {
                    self.filter.established(packet) || related_error
                };
                if allowed {
                    if related_error {
                        self.receive_stats.related_icmp += 1;
                    }
                    let (path, region) = match path {
                        Path::Udp(_) => ("direct", 0),
                        Path::Derp(region) => ("relay", region),
                    };
                    if let Some(router) = self
                        .forwarding
                        .as_mut()
                        .filter(|router| router.plan().handles(packet))
                    {
                        router.ingest(identity, &bytes);
                    } else if let Some(dns) = self.dns.as_mut().filter(|dns| dns.upstream(&bytes)) {
                        dns.ingest(&bytes);
                    } else if !self.pings.receive(identity, &bytes, path, region) {
                        self.tun.write(&bytes).await?;
                    }
                    self.received_bytes += bytes.len() as u64;
                } else {
                    self.receive_stats.acl_drops += 1;
                    if !peer_source {
                        self.receive_stats.untracked_exit_drops += 1;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn disco(&mut self, known: Option<[u8; 32]>, path: Path, bytes: &[u8]) {
        if bytes.len() < 78 {
            return;
        }
        let Some(identity) = self
            .peers
            .iter()
            .find(|(_, peer)| {
                peer.node.valid()
                    && known.is_none_or(|key| key == peer.key)
                    && peer.disco.is_some_and(|disco| bytes[6..38] == disco)
            })
            .map(|(identity, _)| *identity)
        else {
            return;
        };
        let Some(peer) = self.peers.get_mut(&identity) else {
            return;
        };
        let Some(disco) = peer.disco else {
            return;
        };
        let Some(message) = discovery::open(&self.identity.disco, &disco, bytes) else {
            return;
        };
        if message.len() < 2 || message[1] != 0 {
            return;
        }
        match (message[0], path) {
            (1, Path::Udp(source)) if message.len() >= 14 => {
                if message.len() >= 46 && message[14..46] != [0; 32] && message[14..46] != peer.key
                {
                    return;
                }
                let pong = discovery::pong(&message[2..14], source);
                if let Some(bytes) = discovery::seal(&self.identity.disco, &disco, &pong) {
                    let _ = self.socket.send_to(&bytes, source).await;
                }
            }
            (2, Path::Udp(source)) if message.len() >= 32 => {
                peer.confirm_pong(source, &message[2..14], Instant::now());
            }
            (3, Path::Derp(_)) => {
                let (addresses, remainder) = message[2..].as_chunks::<18>();
                if !remainder.is_empty() {
                    return;
                }
                peer.extra_endpoints = addresses
                    .iter()
                    .filter_map(|bytes| discovery::address(bytes))
                    .take(16)
                    .collect();
                self.probe(identity).await;
            }
            _ => {}
        }
    }

    async fn probe(&mut self, identity: u64) {
        let Some(peer) = self.peers.get_mut(&identity) else {
            return;
        };
        let Some(disco) = peer.disco else {
            return;
        };
        peer.probes
            .retain(|(_, _, sent)| sent.elapsed() < Duration::from_secs(10));
        for target in peer.endpoints() {
            if peer.probes.len() >= 32 {
                break;
            }
            let transaction = discovery::transaction();
            if let Some(bytes) = discovery::seal(
                &self.identity.disco,
                &disco,
                &discovery::ping(transaction, &self.own_node),
            ) {
                let _ = self.socket.send_to(&bytes, target).await;
                peer.probes.push_back((transaction, target, Instant::now()));
            }
        }
    }

    async fn tick(&mut self) -> Result<()> {
        self.ticks += 1;
        self.budget = 100;
        self.limiter.reset_count();
        if !self.fresh() {
            self.filter = Filter::default();
            self.forwarding = None;
            return Ok(());
        }
        self.update_relays()?;
        let identities = self.peers.keys().copied().collect::<Vec<_>>();
        let mut scratch = vec![0; 65568];
        let mut initial_budget = 16;
        for identity in identities {
            if !self.peers[&identity].node.valid() {
                continue;
            }
            let action = self
                .peers
                .get_mut(&identity)
                .context("peer 丢失")?
                .maintain(&mut scratch, &mut initial_budget);
            if let Output::Wire(bytes) = action {
                self.transmit(identity, None, &bytes).await;
            }
            if self.ticks % 10 == 1 {
                self.probe(identity).await;
                let peer = &self.peers[&identity];
                if let Some(disco) = peer.disco {
                    let endpoints = self
                        .endpoints
                        .borrow()
                        .endpoints
                        .iter()
                        .filter_map(|endpoint| endpoint.parse().ok())
                        .collect::<Vec<_>>();
                    if let Some(bytes) = discovery::seal(
                        &self.identity.disco,
                        &disco,
                        &discovery::call_me_maybe(&endpoints),
                    ) {
                        self.hub.send(peer.node.relay_region(), peer.key, &bytes);
                    }
                }
            }
        }
        if self.ticks % 30 == 1 {
            self.stun.clear();
            for region in self.map.derp.regions.values().take(4) {
                if let Some(node) = region.nodes.iter().find(|node| node.stun_port >= 0) {
                    let port = if node.stun_port == 0 {
                        3478
                    } else {
                        node.stun_port as u16
                    };
                    let host = if node.ipv4.is_empty() {
                        &node.host_name
                    } else {
                        &node.ipv4
                    };
                    if let Ok(Ok(addresses)) = tokio::time::timeout(
                        Duration::from_secs(2),
                        tokio::net::lookup_host((host.as_str(), port)),
                    )
                    .await
                        && let Some(target) =
                            addresses.filter(SocketAddr::is_ipv4).find(|address| {
                                !address.ip().is_unspecified() && !address.ip().is_multicast()
                            })
                    {
                        let transaction = discovery::transaction();
                        self.socket
                            .send_to(&discovery::stun_request(transaction), target)
                            .await?;
                        self.stun.push((transaction, target, Instant::now()));
                    }
                }
            }
            self.publish_endpoints()?;
        }
        Ok(())
    }

    fn publish_endpoints(&mut self) -> Result<()> {
        self.mapped
            .retain(|_, seen| seen.elapsed() < Duration::from_secs(120));
        let mut endpoints =
            network::local_endpoints(self.socket.local_addr()?.port(), &self.config.interface);
        endpoints.extend(self.mapped.keys().take(8).map(ToString::to_string));
        endpoints.sort();
        endpoints.dedup();
        self.endpoints.send_if_modified(|old| {
            if old.endpoints == endpoints {
                false
            } else {
                old.endpoints = endpoints;
                true
            }
        });
        Ok(())
    }

    pub fn status(&self, store: &Store) -> Result<()> {
        let mut snapshot = self.snapshot();
        #[cfg(target_os = "android")]
        crate::mobile::publish(&snapshot);
        // 移动端节点清单只经内存回调传递，避免扩大磁盘状态与 CLI 读取上限。
        snapshot
            .as_object_mut()
            .expect("snapshot object")
            .remove("devices");
        snapshot
            .as_object_mut()
            .expect("snapshot object")
            .remove("dns");
        store.write("status.json", &snapshot)
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let now = Instant::now();
        json!({"type":"status","version":crate::VERSION,"updated_at":time::OffsetDateTime::now_utc().unix_timestamp(),
            "online":self.fresh(),"interface":self.config.interface,"addresses":self.map.node.as_ref().map(|node| &node.addresses),
            "peers":self.peers.len(),"direct_peers":self.peers.values().filter(|peer| peer.direct_address(now).is_some()).count(),
            "relay":{"home_region":self.hub.home_region(),"connected":self.hub.home_region()!=0},
            "bytes_received":self.received_bytes,"bytes_sent":self.sent_bytes,"advertised_routes":self.config.advertised_routes(),
            "receive_stats":self.receive_stats,
            "forwarding":{"requested":self.config.advertised_routes(),"active":self.fresh() && self.forwarding.is_some(),"approved":self.forwarding.as_ref().map(|router|&router.plan().routes),"flows":self.forwarding.as_ref().map_or(0,Forwarder::flows)},
            "self_name":self.map.node.as_ref().map(|node| &node.name),"key_expiry":self.map.node.as_ref().and_then(|node| node.key_expiry.as_ref()),
            "owner_login":self.map.node.as_ref().and_then(|node|self.map.user_profiles.get(&node.user)).map(|profile|&profile.login_name),
            "dns":{"enabled":self.map.dns.proxied,"domains":self.map.dns.domains,"active":self.fresh() && self.dns.is_some() && (self.config.accept_dns || !self.config.exit_node_id.is_empty()),"address":self.dns.as_ref().map(|dns|dns.plan().address),"dnssec_validate":self.fresh() && self.dns.as_ref().is_some_and(|dns|dns.plan().dnssec_validate) && (self.config.accept_dns || !self.config.exit_node_id.is_empty()),"statistics":self.dns.as_ref().map(DnsProxy::statistics)},
            "exit_node":{"selected_id":self.config.exit_node_id,"available":self.fresh() && !self.config.exit_node_id.is_empty() && self.peers.values().any(|peer|peer.node.stable_id==self.config.exit_node_id && peer.node.exit_node()),
                "online":self.peers.values().find(|peer|peer.node.stable_id==self.config.exit_node_id).and_then(|peer|self.fresh().then_some(peer.node.online).flatten())},
            "devices":self.peers.values().map(|peer| json!({"id":peer.node.id.to_string(),"name":peer.node.name,"addresses":peer.node.addresses,
                "os":peer.node.hostinfo.as_ref().map(|hostinfo| &hostinfo.os),"key_expiry":peer.node.key_expiry,"stable_id":peer.node.stable_id,"exit_node":peer.node.exit_node(),
                "online":self.fresh().then_some(peer.node.online).flatten(),"last_seen":peer.node.last_seen,
                "routes":peer.node.allowed_ips.iter().filter(|prefix| prefix.prefix_len()>0 && prefix.prefix_len() < if prefix.addr().is_ipv4(){32}else{128}).collect::<Vec<_>>(),
                "authorized":peer.node.valid(),"path":if peer.direct_address(now).is_some(){"direct"}else{"relay"},
                "relay_name":self.map.derp.regions.get(&peer.node.relay_region()).map(|region| if region.region_name.is_empty(){&region.region_code}else{&region.region_name}),
                "relay_region":peer.node.relay_region()})).collect::<Vec<_>>()})
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.last_map = None;
        self.pings = Pings::default();
        self.dns = None;
        self.forwarding = None;
        self.peers.clear();
        self.hub = Hub::default();
        #[cfg(target_os = "android")]
        self.tun.close();
        self.routes.stop(&self.config.interface).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit() -> Peer {
        Peer {
            node: Node {
                stable_id: "selected-exit".into(),
                machine_authorized: true,
                addresses: vec!["100.80.0.2/32".parse().unwrap()],
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                ..Node::default()
            },
            key: [2; 32],
            disco: None,
            tunnel: Tunn::new([1; 32].into(), [2; 32].into(), None, None, 1, None),
            index: 1,
            direct: None,
            probes: VecDeque::new(),
            extra_endpoints: Vec::new(),
        }
    }

    #[test]
    fn disco_peers_never_trust_or_renew_a_return_path_from_incoming_wireguard_alone() {
        let mut peer = exit();
        peer.disco = Some([3; 32]);
        let source = "192.0.2.10:41641".parse().unwrap();
        let now = Instant::now();
        peer.authenticated_udp(source, now);
        assert_eq!(peer.direct_address(now), None);
        peer.direct = Some((source, now));
        peer.authenticated_udp(source, now + Duration::from_secs(6));
        assert_eq!(peer.direct_address(now + Duration::from_millis(6500)), None);
        let other = "192.0.2.11:41641".parse().unwrap();
        peer.authenticated_udp(other, now + Duration::from_secs(7));
        assert_eq!(peer.direct, Some((source, now)));
    }

    #[test]
    fn pong_requires_a_fresh_single_use_transaction_and_its_actual_udp_target() {
        let mut peer = exit();
        peer.disco = Some([3; 32]);
        let target = "192.0.2.10:41641".parse().unwrap();
        let other = "192.0.2.11:41641".parse().unwrap();
        let now = Instant::now();
        peer.probes.push_back(([7; 12], target, now));
        assert!(!peer.confirm_pong(other, &[7; 12], now));
        assert!(!peer.confirm_pong(target, &[8; 12], now));
        assert_eq!(peer.direct_address(now), None);
        assert!(peer.confirm_pong(target, &[7; 12], now));
        assert!(peer.probes.is_empty());
        assert_eq!(peer.direct_address(now), Some(target));
        assert!(!peer.confirm_pong(target, &[7; 12], now + Duration::from_secs(1)));
        assert_eq!(peer.direct, Some((target, now)));
        assert_eq!(peer.direct_address(now + Duration::from_millis(6500)), None);
        peer.probes.push_back(([9; 12], target, now));
        assert!(!peer.confirm_pong(target, &[9; 12], now + Duration::from_secs(10)));
    }

    #[test]
    fn wireguard_only_peers_keep_a_short_authenticated_endpoint_without_disco() {
        let mut peer = exit();
        let source = "192.0.2.10:41641".parse().unwrap();
        let now = Instant::now();
        peer.authenticated_udp(source, now);
        assert_eq!(peer.direct_address(now), Some(source));
        assert_eq!(peer.direct_address(now + Duration::from_secs(5)), None);
    }

    #[test]
    fn receive_only_peer_starts_a_bounded_handshake_without_waiting_for_old_sessions() {
        let mut peer = exit();
        peer.tunnel = Tunn::new([1; 32].into(), [2; 32].into(), None, Some(20), 1, None);
        let mut scratch = [0; 1024];
        let mut budget = 0;
        assert!(matches!(
            peer.maintain(&mut scratch, &mut budget),
            Output::Done
        ));
        budget = 1;
        let Output::Wire(handshake) = peer.maintain(&mut scratch, &mut budget) else {
            panic!("new peer did not initiate a handshake");
        };
        assert_eq!(handshake.len(), 148);
        assert_eq!(handshake[0], 1);
        assert_eq!(budget, 0);
        budget = 1;
        assert!(matches!(
            peer.maintain(&mut scratch, &mut budget),
            Output::Done
        ));
        assert_eq!(budget, 1);
    }

    #[test]
    fn default_routes_and_internet_sources_only_belong_to_selected_authorized_exit() {
        let mut peer = exit();
        let packet = Packet {
            source: "100.80.0.1".parse().unwrap(),
            destination: "203.0.113.77".parse().unwrap(),
            protocol: 6,
            source_port: 50000,
            destination_port: 443,
        };
        assert_eq!(peer.prefix(packet, true, false), None);
        assert_eq!(peer.prefix(packet, false, true), Some(0));
        let reply = Packet {
            source: packet.destination,
            destination: packet.source,
            source_port: 443,
            destination_port: 50000,
            ..packet
        };
        assert!(!peer.source_allowed(reply, false));
        assert!(peer.source_allowed(reply, true));
        peer.node.allowed_ips.pop();
        assert_eq!(peer.prefix(packet, true, true), None);
        assert!(!peer.source_allowed(reply, true));
        peer.node.machine_authorized = false;
        assert!(!peer.node.exit_node());
    }
}
