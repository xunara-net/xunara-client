use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ipnet::IpNet;
use rand_core::{OsRng, RngCore};
use smoltcp::{
    iface::{Config as StackConfig, Interface, SocketHandle, SocketSet},
    socket::{tcp, udp},
    time::{Duration as StackDuration, Instant as StackInstant},
    wire::{
        HardwareAddress, Icmpv4Packet, Icmpv6Packet, IpAddress, IpCidr, Ipv4Packet, Ipv6Packet,
    },
};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
    task::JoinSet,
};

use crate::{config::Config, filter::Packet, model::NetworkMap, packet_stack::Queue};

const FLOW_LIMIT: usize = 128;
const PEER_LIMIT: usize = 32;
const DNS_FLOW_LIMIT: usize = 64;
const DNS_PEER_LIMIT: usize = 32;
pub const PEER_API_PORT: u16 = 44444;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub routes: Vec<IpNet>,
    blocked: Vec<IpNet>,
    peers: Vec<(u64, crate::model::SourcePolicy)>,
    addresses: Vec<IpAddr>,
}

impl Plan {
    pub fn new(config: &Config, map: &NetworkMap) -> Result<Option<Self>> {
        let Some(node) = map.node.as_ref().filter(|node| node.valid()) else {
            return Ok(None);
        };
        let mut routes = config
            .advertised_routes()
            .into_iter()
            .filter(|route| node.allowed_ips.contains(route))
            .collect::<Vec<_>>();
        // 出口必须双栈共同获批，单个默认路由不能造成隐式部分接管。
        if !routes
            .iter()
            .any(|route| route.addr().is_ipv4() && route.prefix_len() == 0)
            || !routes
                .iter()
                .any(|route| route.addr().is_ipv6() && route.prefix_len() == 0)
        {
            routes.retain(|route| route.prefix_len() > 0);
        }
        if routes.is_empty() {
            return Ok(None);
        }
        let mut blocked = [
            "0.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/3",
            "::/128",
            "::1/128",
            "fe80::/10",
            "ff00::/8",
            "::ffff:0:0/96",
        ]
        .into_iter()
        .map(str::parse)
        .collect::<std::result::Result<Vec<IpNet>, _>>()?;
        blocked.extend(
            node.addresses
                .iter()
                .map(|address| IpNet::from(address.addr())),
        );
        let mut peers = Vec::new();
        for peer in map.nodes()?.into_iter().filter(|peer| peer.valid()) {
            blocked.extend(
                peer.addresses
                    .iter()
                    .map(|address| IpNet::from(address.addr())),
            );
            peers.push((peer.id, peer.source_policy()));
        }
        Ok(Some(Self {
            routes,
            blocked,
            peers,
            addresses: node.addresses.iter().map(IpNet::addr).collect(),
        }))
    }

    pub fn allows(&self, destination: IpAddr) -> bool {
        !self
            .blocked
            .iter()
            .any(|route| route.contains(&destination))
            && self.routes.iter().any(|route| route.contains(&destination))
    }

    pub fn exit(&self) -> bool {
        self.routes.iter().any(|route| route.prefix_len() == 0)
    }

    pub fn peer_dns(&self, packet: Packet) -> bool {
        self.exit()
            && packet.protocol == 6
            && packet.destination_port == PEER_API_PORT
            && self.addresses.contains(&packet.destination)
    }

    pub fn handles(&self, packet: Packet) -> bool {
        self.allows(packet.destination) || self.peer_dns(packet)
    }
}

struct Stack {
    device: Queue,
    interface: Interface,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
}

impl Stack {
    fn new(packet: Packet) -> Result<Self> {
        let mut device = Queue::default();
        let mut config = StackConfig::new(HardwareAddress::Ip);
        config.random_seed = OsRng.next_u64();
        let mut interface = Interface::new(config, &mut device, StackInstant::from_millis(0));
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(
                    packet.destination.into(),
                    if packet.destination.is_ipv4() {
                        32
                    } else {
                        128
                    },
                ))
                .expect("one per-flow address");
        });
        match packet.destination {
            IpAddr::V4(address) => {
                interface
                    .routes_mut()
                    .add_default_ipv4_route(address)
                    .map_err(|_| anyhow::anyhow!("转发 IPv4 路由已满"))?;
            }
            IpAddr::V6(address) => {
                interface
                    .routes_mut()
                    .add_default_ipv6_route(address)
                    .map_err(|_| anyhow::anyhow!("转发 IPv6 路由已满"))?;
            }
        }
        let mut sockets = SocketSet::new(Vec::new());
        let endpoint = (IpAddress::from(packet.destination), packet.destination_port);
        let handle = if packet.protocol == 6 {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 32768]),
                tcp::SocketBuffer::new(vec![0; 32768]),
            );
            socket.set_timeout(Some(StackDuration::from_secs(180)));
            socket.set_ack_delay(None);
            socket
                .listen(endpoint)
                .map_err(|_| anyhow::anyhow!("转发 TCP 端点无效"))?;
            sockets.add(socket)
        } else {
            let mut socket = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
            );
            socket
                .bind(endpoint)
                .map_err(|_| anyhow::anyhow!("转发 UDP 端点无效"))?;
            sockets.add(socket)
        };
        Ok(Self {
            device,
            interface,
            sockets,
            handle,
        })
    }

    fn poll(&mut self, now: StackInstant) {
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
    }
}

enum Backend {
    Api {
        input: Vec<u8>,
        output: Vec<u8>,
        written: usize,
        pending: bool,
    },
    Tcp {
        stream: Option<TcpStream>,
        write_closed: bool,
    },
    Udp {
        socket: UdpSocket,
        pending: VecDeque<Vec<u8>>,
    },
}

struct Flow {
    id: u64,
    peer: u64,
    stack: Stack,
    backend: Backend,
    seen: Instant,
}

#[derive(Default, serde::Serialize)]
pub struct Statistics {
    data_capacity_drops: u64,
    dns_capacity_drops: u64,
}

/// 只接收 Engine 已完成机器来源与 ACL 校验的包；没有监听物理网卡的代理端口。
/// 每条流独立用户态栈和受保护 socket，回包始终绑定原始 WireGuard peer。
pub struct Forwarder {
    plan: Plan,
    flows: HashMap<Packet, Flow>,
    connects: JoinSet<(u64, Result<TcpStream>)>,
    pings: JoinSet<(u64, Option<Vec<u8>>)>,
    started: Instant,
    budget_at: Instant,
    budget: usize,
    dns_budget: usize,
    statistics: Statistics,
    next_id: u64,
    dns: Option<mpsc::Sender<crate::dns_stack::ApiRequest>>,
    api_tasks: JoinSet<(u64, Vec<u8>)>,
}

impl Forwarder {
    pub fn new(plan: Plan) -> Self {
        Self {
            plan,
            flows: HashMap::new(),
            connects: JoinSet::new(),
            pings: JoinSet::new(),
            started: Instant::now(),
            budget_at: Instant::now(),
            budget: 64,
            dns_budget: 64,
            statistics: Statistics::default(),
            next_id: 0,
            dns: None,
            api_tasks: JoinSet::new(),
        }
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn set_dns(&mut self, sender: mpsc::Sender<crate::dns_stack::ApiRequest>) {
        self.dns = Some(sender);
    }
    pub fn flows(&self) -> usize {
        self.flows.len() + self.pings.len()
    }

    pub fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    pub fn ingest(&mut self, peer: u64, bytes: &[u8]) {
        let Some(packet) = Packet::parse(bytes).filter(|packet| self.plan.handles(*packet)) else {
            return;
        };
        if let Some(flow) = self.flows.get_mut(&packet) {
            if flow.peer == peer && flow.stack.device.input.len() < 8 {
                flow.seen = Instant::now();
                flow.stack.device.input.push_back(bytes.to_vec());
            }
            return;
        }
        if self.budget_at.elapsed() >= Duration::from_secs(1) {
            self.budget_at = Instant::now();
            self.budget = 64;
            self.dns_budget = 64;
        }
        let dns = self.plan.peer_dns(packet);
        let mut class_count = 0;
        let mut peer_count = 0;
        for flow in self.flows.values() {
            if matches!(flow.backend, Backend::Api { .. }) == dns {
                class_count += 1;
                peer_count += usize::from(flow.peer == peer);
            }
        }
        // DNS 是出口的引导服务，不能被浏览器空闲 TCP / QUIC 流占满业务额度后饿死。
        // 两类分别限流与限额；DNS 仍只接受经过原有机器身份、来源和 ACL 校验的 peerapi。
        if dns {
            if self.dns_budget == 0
                || class_count >= DNS_FLOW_LIMIT
                || peer_count >= DNS_PEER_LIMIT
                || self.api_tasks.len() >= DNS_FLOW_LIMIT
            {
                self.statistics.dns_capacity_drops += 1;
                return;
            }
            self.dns_budget -= 1;
        } else {
            if self.budget == 0
                || class_count >= FLOW_LIMIT
                || peer_count >= PEER_LIMIT
                || self.connects.len() >= FLOW_LIMIT
            {
                self.statistics.data_capacity_drops += 1;
                return;
            }
            self.budget -= 1;
        }
        if matches!(packet.protocol, 1 | 58) {
            if self.pings.len() < 16
                && let Some(reply) = echo_reply(bytes)
            {
                self.pings.spawn(async move {
                    let response = ping(packet.destination).await.ok().map(|()| reply);
                    (peer, response)
                });
            }
            return;
        }
        if packet.destination_port == 0 || packet.source_port == 0 {
            return;
        }
        if packet.protocol == 6 {
            let offset = if packet.source.is_ipv4() {
                usize::from(bytes[0] & 15) * 4
            } else {
                40
            };
            if bytes[offset + 13] & 0x12 != 0x02 {
                return;
            }
        }
        let Ok(mut stack) = Stack::new(packet) else {
            return;
        };
        if packet.protocol == 6 && !self.plan.peer_dns(packet) {
            // 与官方用户态转发一致：物理连接成功后才回复 SYN-ACK。
            // 否则不可达 IPv6 会假报连接成功，阻止应用回退到可用的 IPv4。
            stack
                .sockets
                .get_mut::<tcp::Socket>(stack.handle)
                .pause_synack(true);
        }
        stack.device.input.push_back(bytes.to_vec());
        stack.poll(self.now());
        let Some(id) = self.next_id.checked_add(1) else {
            return;
        };
        self.next_id = id;
        let target = SocketAddr::new(packet.destination, packet.destination_port);
        let backend = if self.plan.peer_dns(packet) {
            if stack.sockets.get::<tcp::Socket>(stack.handle).state() != tcp::State::SynReceived {
                return;
            }
            Backend::Api {
                input: Vec::new(),
                output: Vec::new(),
                written: 0,
                pending: false,
            }
        } else if packet.protocol == 6 {
            // 只有栈接受了有效 SYN 才打开外层连接，校验和错误不能触发 LAN 探测。
            if stack.sockets.get::<tcp::Socket>(stack.handle).state() != tcp::State::SynReceived {
                return;
            }
            self.connects
                .spawn(async move { (id, connect(target).await) });
            Backend::Tcp {
                stream: None,
                write_closed: false,
            }
        } else {
            if !stack.sockets.get::<udp::Socket>(stack.handle).can_recv() {
                return;
            }
            let Ok(socket) = datagram(target) else {
                return;
            };
            Backend::Udp {
                socket,
                pending: VecDeque::new(),
            }
        };
        self.flows.insert(
            packet,
            Flow {
                id,
                peer,
                stack,
                backend,
                seen: Instant::now(),
            },
        );
    }

    fn now(&self) -> StackInstant {
        StackInstant::from_millis(self.started.elapsed().as_millis().min(i64::MAX as u128) as i64)
    }

    pub fn poll(&mut self) -> Vec<(u64, Vec<u8>)> {
        while let Some(Ok((id, result))) = self.connects.try_join_next() {
            if let Some(flow) = self.flows.values_mut().find(|flow| flow.id == id)
                && let Backend::Tcp { stream, .. } = &mut flow.backend
            {
                match result {
                    Ok(connected) => {
                        *stream = Some(connected);
                        flow.stack
                            .sockets
                            .get_mut::<tcp::Socket>(flow.stack.handle)
                            .pause_synack(false);
                    }
                    Err(_) => flow
                        .stack
                        .sockets
                        .get_mut::<tcp::Socket>(flow.stack.handle)
                        .abort(),
                }
            }
        }
        let mut output = Vec::new();
        while let Some(Ok((id, response))) = self.api_tasks.try_join_next() {
            if let Some(flow) = self.flows.values_mut().find(|flow| flow.id == id)
                && let Backend::Api { output, .. } = &mut flow.backend
            {
                *output = response;
            }
        }
        while let Some(Ok((peer, Some(reply)))) = self.pings.try_join_next() {
            output.push((peer, reply));
        }
        let now = self.now();
        self.flows.retain(|packet, flow| {
            flow.stack.poll(now);
            let active = match &mut flow.backend {
                Backend::Api {
                    input,
                    output,
                    written,
                    pending,
                } => {
                    let socket = flow.stack.sockets.get_mut::<tcp::Socket>(flow.stack.handle);
                    if socket.can_recv() && !*pending {
                        let _ = socket.recv(|bytes| {
                            input.extend_from_slice(bytes);
                            (bytes.len(), ())
                        });
                        if input.len() > 49152 {
                            socket.abort();
                        } else {
                            match api_query(input) {
                                Ok(Some(query)) => {
                                    *pending = true;
                                    let id = flow.id;
                                    let dns = self.dns.clone();
                                    self.api_tasks
                                        .spawn(async move { (id, api_answer(dns, query).await) });
                                    input.clear();
                                }
                                Err(_) => {
                                    *pending = true;
                                    *output = http_response(400, b"Invalid DNS request");
                                }
                                Ok(None) => {}
                            }
                        }
                    }
                    if *written < output.len()
                        && socket.can_send()
                        && let Ok(length) = socket.send_slice(&output[*written..])
                    {
                        *written += length;
                    }
                    if !output.is_empty() && *written == output.len() {
                        socket.close();
                    }
                    socket.is_open() && flow.seen.elapsed() < Duration::from_secs(30)
                }
                Backend::Tcp {
                    stream,
                    write_closed,
                } => {
                    let socket = flow.stack.sockets.get_mut::<tcp::Socket>(flow.stack.handle);
                    if let Some(stream) = stream {
                        let mut activity = false;
                        let mut write_failed = false;
                        if socket.can_recv() {
                            let _ = socket.recv(|bytes| match stream.try_write(bytes) {
                                Ok(length) => {
                                    activity = length > 0;
                                    (length, ())
                                }
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (0, ()),
                                _ => {
                                    write_failed = true;
                                    (0, ())
                                }
                            });
                        }
                        if write_failed {
                            socket.abort();
                        }
                        if !matches!(
                            socket.state(),
                            tcp::State::SynReceived | tcp::State::Listen | tcp::State::SynSent
                        ) && !socket.may_recv()
                            && !*write_closed
                        {
                            // SAFETY: stream 持有 fd；只关闭写半边，仍接收后端的最后响应。
                            unsafe {
                                libc::shutdown(stream.as_raw_fd(), libc::SHUT_WR);
                            }
                            *write_closed = true;
                        }
                        if socket.can_send() {
                            let mut closed = false;
                            let mut failed = false;
                            let _ = socket.send(|bytes| match stream.try_read(bytes) {
                                Ok(0) => {
                                    closed = true;
                                    (0, ())
                                }
                                Ok(length) => {
                                    activity |= length > 0;
                                    (length, ())
                                }
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (0, ()),
                                _ => {
                                    failed = true;
                                    (0, ())
                                }
                            });
                            if closed {
                                socket.close();
                            }
                            if failed {
                                socket.abort();
                            }
                        }
                        if activity {
                            flow.seen = Instant::now();
                        }
                    }
                    let idle = if matches!(
                        socket.state(),
                        tcp::State::SynReceived | tcp::State::SynSent
                    ) {
                        30
                    } else {
                        180
                    };
                    socket.is_open()
                        && !socket.is_listening()
                        && flow.seen.elapsed() < Duration::from_secs(idle)
                }
                Backend::Udp { socket, pending } => {
                    let endpoint = (IpAddress::from(packet.source), packet.source_port);
                    let server = flow.stack.sockets.get_mut::<udp::Socket>(flow.stack.handle);
                    while pending.len() < 8 {
                        let Ok((bytes, remote)) = server.recv() else {
                            break;
                        };
                        if remote.endpoint == endpoint.into() {
                            pending.push_back(bytes.to_vec());
                        }
                    }
                    while let Some(bytes) = pending.pop_front() {
                        match socket.try_send(&bytes) {
                            Ok(_) => {
                                flow.seen = Instant::now();
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                pending.push_front(bytes);
                                break;
                            }
                            _ => {}
                        }
                    }
                    let mut bytes = [0; 65535];
                    for _attempt in 0..8 {
                        if !server.can_send() {
                            break;
                        }
                        let Ok(length) = socket.try_recv(&mut bytes) else {
                            break;
                        };
                        if length <= if packet.source.is_ipv4() { 1252 } else { 1232 } {
                            let _ = server.send_slice(&bytes[..length], endpoint);
                            flow.seen = Instant::now();
                        }
                    }
                    flow.seen.elapsed() < Duration::from_secs(60)
                }
            };
            flow.stack.poll(now);
            for bytes in flow.stack.device.output.drain(..) {
                if Packet::parse(&bytes).is_some_and(|reply| {
                    reply.source == packet.destination
                        && reply.destination == packet.source
                        && reply.protocol == packet.protocol
                        && reply.source_port == packet.destination_port
                        && reply.destination_port == packet.source_port
                }) {
                    output.push((flow.peer, bytes));
                }
            }
            active
        });
        output
    }
}

fn protect(socket: &impl AsRawFd) -> Result<()> {
    #[cfg(target_os = "android")]
    crate::mobile::host()?.protect(socket.as_raw_fd())?;
    #[cfg(not(target_os = "android"))]
    let _ = socket;
    Ok(())
}

fn api_query(bytes: &[u8]) -> Result<Option<hickory_proto::op::Message>> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    let httparse::Status::Complete(offset) = request.parse(bytes)? else {
        ensure!(bytes.len() <= 32768, "DNS 请求头过大");
        return Ok(None);
    };
    ensure!(
        offset <= 32768
            && !request
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("Transfer-Encoding")),
        "不接受分块 DNS 请求"
    );
    let path = request.path.unwrap_or("");
    ensure!(
        path.starts_with('/') && !path.starts_with("//"),
        "DNS 请求路径无效"
    );
    let target = url::Url::parse(&format!("http://peer.invalid{path}"))?;
    ensure!(
        target.path() == "/dns-query"
            && target.host_str() == Some("peer.invalid")
            && target.fragment().is_none(),
        "只提供出口 DNS 接口"
    );
    let query = match request.method {
        Some("GET") => {
            let values = target
                .query_pairs()
                .filter(|(key, _)| key == "dns")
                .map(|(_, value)| value.into_owned())
                .collect::<Vec<_>>();
            ensure!(
                values.len() == 1 && values[0].len() <= 21846 && bytes.len() == offset,
                "DNS 参数无效"
            );
            URL_SAFE_NO_PAD.decode(&values[0])?
        }
        Some("POST") => {
            ensure!(
                target.query().is_none()
                    && request
                        .headers
                        .iter()
                        .any(|header| header.name.eq_ignore_ascii_case("Content-Type")
                            && header.value == b"application/dns-message"),
                "DNS 内容类型无效"
            );
            let lengths = request
                .headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case("Content-Length"))
                .collect::<Vec<_>>();
            ensure!(lengths.len() == 1, "DNS 长度头无效");
            let length = std::str::from_utf8(lengths[0].value)?.parse::<usize>()?;
            ensure!((12..=16384).contains(&length), "DNS 请求长度无效");
            if bytes.len() < offset + length {
                return Ok(None);
            }
            ensure!(bytes.len() == offset + length, "不接受流水线 DNS 请求");
            bytes[offset..].to_vec()
        }
        _ => anyhow::bail!("不支持的 DNS 请求方法"),
    };
    Ok(Some(crate::dns::query(&query)?))
}

async fn api_answer(
    sender: Option<mpsc::Sender<crate::dns_stack::ApiRequest>>,
    query: hickory_proto::op::Message,
) -> Vec<u8> {
    let Some(sender) = sender else {
        return http_response(503, b"DNS unavailable");
    };
    let (reply, response) = oneshot::channel();
    if sender
        .try_send(crate::dns_stack::ApiRequest { query, reply })
        .is_err()
    {
        return http_response(503, b"DNS unavailable");
    }
    match tokio::time::timeout(Duration::from_secs(14), response).await {
        Ok(Ok(response)) => match response.to_vec() {
            Ok(bytes) => http_response(200, &bytes),
            Err(_) => http_response(502, b"DNS failed"),
        },
        _ => http_response(502, b"DNS failed"),
    }
}

fn http_response(code: u16, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.0 {code} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        if code == 200 { "OK" } else { "Error" },
        if code == 200 {
            "application/dns-message"
        } else {
            "text/plain"
        },
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

async fn connect(target: SocketAddr) -> Result<TcpStream> {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    protect(&socket)?;
    let stream = tokio::time::timeout(Duration::from_secs(5), socket.connect(target)).await??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn datagram(target: SocketAddr) -> Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.set_nonblocking(true)?;
    protect(&socket)?;
    socket.connect(target)?;
    Ok(UdpSocket::from_std(socket)?)
}

async fn ping(target: IpAddr) -> Result<()> {
    let family = if target.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let protocol = if target.is_ipv4() {
        libc::IPPROTO_ICMP
    } else {
        libc::IPPROTO_ICMPV6
    };
    // SAFETY: socket 不接收指针；成功的 fd 立即交给 OwnedFd，绝不使用原始特权 socket。
    let descriptor = unsafe {
        libc::socket(
            family,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    ensure!(descriptor >= 0, "系统未允许免 Root ICMP 探测");
    // SAFETY: 只有此处持有新 fd，随后通过标准库移交给 Tokio。
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let socket = std::net::UdpSocket::from(descriptor);
    protect(&socket)?;
    socket.connect(SocketAddr::new(target, 0))?;
    let socket = UdpSocket::from_std(socket)?;
    let mut token = [0; 18];
    OsRng.fill_bytes(&mut token);
    let mut request = vec![0; 24];
    request[0] = if target.is_ipv4() { 8 } else { 128 };
    request[6..].copy_from_slice(&token);
    if target.is_ipv4() {
        Icmpv4Packet::new_unchecked(&mut request[..]).fill_checksum();
    }
    socket.send(&request).await?;
    let mut response = [0; 2048];
    let length = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut response)).await??;
    ensure!(
        length == request.len()
            && response[0] == if target.is_ipv4() { 0 } else { 129 }
            && response[1] == 0
            && response[6..length] == token,
        "未收到匹配的真实 ICMP 回包"
    );
    Ok(())
}

fn echo_reply(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut reply = bytes.to_vec();
    match bytes.first()? >> 4 {
        4 => {
            let mut ip = Ipv4Packet::new_checked(&mut reply[..]).ok()?;
            if !ip.verify_checksum() {
                return None;
            }
            let source = ip.src_addr();
            let target = ip.dst_addr();
            let mut echo = Icmpv4Packet::new_checked(ip.payload_mut()).ok()?;
            if echo.msg_type() != smoltcp::wire::Icmpv4Message::EchoRequest
                || echo.msg_code() != 0
                || !echo.verify_checksum()
            {
                return None;
            }
            echo.set_msg_type(smoltcp::wire::Icmpv4Message::EchoReply);
            echo.fill_checksum();
            ip.set_src_addr(target);
            ip.set_dst_addr(source);
            ip.fill_checksum();
        }
        6 => {
            let mut ip = Ipv6Packet::new_checked(&mut reply[..]).ok()?;
            let source = ip.src_addr();
            let target = ip.dst_addr();
            let mut echo = Icmpv6Packet::new_checked(ip.payload_mut()).ok()?;
            if echo.msg_type() != smoltcp::wire::Icmpv6Message::EchoRequest
                || echo.msg_code() != 0
                || !echo.verify_checksum(&source, &target)
            {
                return None;
            }
            echo.set_msg_type(smoltcp::wire::Icmpv6Message::EchoReply);
            echo.fill_checksum(&target, &source);
            ip.set_src_addr(target);
            ip.set_dst_addr(source);
        }
        _ => return None,
    }
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Node;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn map() -> NetworkMap {
        let mut map = NetworkMap::default();
        map.node = Some(Node {
            machine_authorized: true,
            addresses: vec!["100.80.0.1/32".parse().unwrap()],
            allowed_ips: vec![
                "100.80.0.1/32".parse().unwrap(),
                "192.168.8.0/24".parse().unwrap(),
            ],
            ..Node::default()
        });
        map
    }

    #[test]
    fn only_explicit_and_approved_routes_can_forward_and_host_scoped_targets_are_blocked() {
        let config = Config {
            advertise_routes: vec![
                "192.168.8.0/24".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
            ],
            ..Config::default()
        };
        let plan = Plan::new(&config, &map()).unwrap().unwrap();
        assert!(plan.allows("192.168.8.2".parse().unwrap()));
        assert!(!plan.allows("10.1.2.3".parse().unwrap()));
        assert!(Plan::new(&Config::default(), &map()).unwrap().is_none());
        let mut map = map();
        let config = Config {
            advertise_exit: true,
            ..Config::default()
        };
        map.node
            .as_mut()
            .unwrap()
            .allowed_ips
            .push("0.0.0.0/0".parse().unwrap());
        assert!(Plan::new(&config, &map).unwrap().is_none());
        map.node
            .as_mut()
            .unwrap()
            .allowed_ips
            .push("::/0".parse().unwrap());
        let plan = Plan::new(&config, &map).unwrap().unwrap();
        assert!(plan.exit());
        for target in ["1.1.1.1", "2606:4700::1111", "192.168.8.2"] {
            assert!(plan.allows(target.parse().unwrap()));
        }
        for target in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "100.80.0.1",
        ] {
            assert!(!plan.allows(target.parse().unwrap()), "{target}");
        }
        map.node.as_mut().unwrap().allowed_ips.clear();
        assert!(Plan::new(&config, &map).unwrap().is_none());
    }

    fn client(target: SocketAddr, protocol: u8) -> (Packet, Stack) {
        client_from_port(target, protocol, 40960)
    }

    fn client_from_port(target: SocketAddr, protocol: u8, source_port: u16) -> (Packet, Stack) {
        let source: IpAddr = if target.is_ipv4() {
            "100.80.0.9"
        } else {
            "fd7a:115c:a1e0::9"
        }
        .parse()
        .unwrap();
        let packet = Packet {
            source,
            destination: target.ip(),
            protocol,
            source_port,
            destination_port: target.port(),
        };
        let reverse = Packet {
            source: packet.destination,
            destination: packet.source,
            source_port: packet.destination_port,
            destination_port: packet.source_port,
            ..packet
        };
        let mut stack = Stack::new(reverse).unwrap();
        if protocol == 6 {
            let socket = stack.sockets.get_mut::<tcp::Socket>(stack.handle);
            socket.abort();
            socket
                .connect(
                    stack.interface.context(),
                    (IpAddress::from(target.ip()), target.port()),
                    (IpAddress::from(source), packet.source_port),
                )
                .unwrap();
        }
        (packet, stack)
    }

    fn private_test_router(target: IpAddr) -> Forwarder {
        // 单测只为访问本机临时测试服务移除 loopback 限制；生产 Plan::new 永不允许回环。
        Forwarder::new(Plan {
            routes: vec![target.into()],
            blocked: Vec::new(),
            peers: Vec::new(),
            addresses: Vec::new(),
        })
    }

    fn exchange(client: &mut Stack, router: &mut Forwarder) {
        let now = router.now();
        client.poll(now);
        for bytes in client.device.output.drain(..) {
            router.ingest(7, &bytes);
        }
        for (peer, bytes) in router.poll() {
            assert_eq!(peer, 7);
            client.device.input.push_back(bytes);
        }
        client.poll(now);
    }

    fn dns_query() -> Vec<u8> {
        let mut query = hickory_proto::op::Message::query();
        query.metadata.id = 1234;
        query.queries.push(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("phone.core.test.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        query.to_vec().unwrap()
    }

    #[test]
    fn peerapi_rejects_other_paths_smuggling_and_unbounded_or_invalid_dns() {
        for request in [
            "GET /other HTTP/1.1\r\n\r\n",
            "PUT /dns-query HTTP/1.1\r\n\r\n",
            "GET //evil.test/dns-query HTTP/1.1\r\n\r\n",
            "POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 12\r\nContent-Length: 12\r\n\r\n",
            "POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 999999\r\n\r\n",
            "GET /dns-query?dns=AAAA HTTP/1.1\r\n\r\n",
        ] {
            assert!(api_query(request.as_bytes()).is_err(), "{request}");
        }
        assert!(api_query(b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 100\r\n\r\n").unwrap().is_none());
        assert!(api_query(&vec![b'a'; 32769]).is_err());
    }

    #[tokio::test]
    async fn peerapi_doh_get_and_post_use_the_same_magicdns_resolver_without_physical_listener() {
        for (post, occupied_peers) in [(false, 0), (true, 0), (true, 1), (true, 2), (true, 4)] {
            let mut map = map();
            let node = map.node.as_mut().unwrap();
            node.name = "phone.core.test.".into();
            node.allowed_ips.extend([
                "0.0.0.0/0".parse::<IpNet>().unwrap(),
                "::/0".parse::<IpNet>().unwrap(),
            ]);
            map.dns.proxied = true;
            map.dns.domains = vec!["core.test".into()];
            let config = Config {
                advertise_exit: true,
                accept_dns: true,
                ..Config::default()
            };
            let mut router = Forwarder::new(Plan::new(&config, &map).unwrap().unwrap());
            let mut held = Vec::new();
            if occupied_peers > 0 {
                router
                    .plan
                    .blocked
                    .retain(|route| *route != "127.0.0.0/8".parse::<IpNet>().unwrap());
                for index in 0..PEER_LIMIT * occupied_peers {
                    if index == 64 {
                        router.budget_at -= Duration::from_secs(1);
                    }
                    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let target = backend.local_addr().unwrap();
                    let (_, mut sender) = client(target, 17);
                    sender
                        .sockets
                        .get_mut::<udp::Socket>(sender.handle)
                        .send_slice(b"occupied", target)
                        .unwrap();
                    sender.poll(router.now());
                    for packet in sender.device.output.drain(..) {
                        router.ingest(7 + (index / PEER_LIMIT) as u64, &packet);
                    }
                    held.push(backend);
                }
                assert_eq!(router.flows(), PEER_LIMIT * occupied_peers);
            }
            let mut dns = crate::dns_stack::DnsProxy::new(
                crate::dns::DnsPlan::new(&config, &map, &[], &[])
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            router.set_dns(dns.api_sender());
            let (_, mut client) = client(
                SocketAddr::new("100.80.0.1".parse().unwrap(), PEER_API_PORT),
                6,
            );
            let query = dns_query();
            let request = if post {
                let mut request = format!("POST /dns-query HTTP/1.0\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", query.len()).into_bytes();
                request.extend_from_slice(&query);
                request
            } else {
                format!(
                    "GET /dns-query?dns={} HTTP/1.0\r\n\r\n",
                    URL_SAFE_NO_PAD.encode(query)
                )
                .into_bytes()
            };
            let mut sent = false;
            let mut response = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                assert!(dns.poll().is_empty());
                exchange(&mut client, &mut router);
                let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
                if socket.can_send() && !sent {
                    assert_eq!(socket.send_slice(&request).unwrap(), request.len());
                    sent = true;
                }
                if socket.can_recv() {
                    let _ = socket.recv(|bytes| {
                        response.extend_from_slice(bytes);
                        (bytes.len(), ())
                    });
                }
                if response.windows(4).any(|bytes| bytes == [100, 80, 0, 1]) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(response.starts_with(b"HTTP/1.0 200 OK\r\n"), "{response:?}");
            let start = response
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap()
                + 4;
            let answer = hickory_proto::op::Message::from_vec(&response[start..]).unwrap();
            assert_eq!(answer.metadata.id, 1234);
            assert!(!answer.answers.is_empty());
        }
    }

    #[tokio::test]
    async fn peerapi_capacity_is_bounded_per_peer_and_globally_without_consuming_data_slots() {
        let mut map = map();
        map.node.as_mut().unwrap().allowed_ips.extend([
            "0.0.0.0/0".parse::<IpNet>().unwrap(),
            "::/0".parse::<IpNet>().unwrap(),
        ]);
        let config = Config {
            advertise_exit: true,
            ..Config::default()
        };
        let mut router = Forwarder::new(Plan::new(&config, &map).unwrap().unwrap());
        let target = SocketAddr::new("100.80.0.1".parse().unwrap(), PEER_API_PORT);
        for (peer, attempts, accepted) in [
            (7, DNS_PEER_LIMIT + 1, DNS_PEER_LIMIT),
            (8, DNS_PEER_LIMIT, DNS_FLOW_LIMIT),
            (9, 1, DNS_FLOW_LIMIT),
        ] {
            for _ in 0..attempts {
                let port = 40000 + router.next_id as u16;
                let (_, mut sender) = client_from_port(target, 6, port);
                sender.poll(router.now());
                for packet in sender.device.output.drain(..) {
                    router.ingest(peer, &packet);
                }
            }
            assert_eq!(router.flows(), accepted);
        }
        assert_eq!(router.statistics.dns_capacity_drops, 2);
        assert_eq!(router.budget, 64);
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        router
            .plan
            .blocked
            .retain(|route| *route != "127.0.0.0/8".parse::<IpNet>().unwrap());
        let target = backend.local_addr().unwrap();
        let (_, mut sender) = client(target, 17);
        sender
            .sockets
            .get_mut::<udp::Socket>(sender.handle)
            .send_slice(b"data", target)
            .unwrap();
        sender.poll(router.now());
        for packet in sender.device.output.drain(..) {
            router.ingest(7, &packet);
        }
        assert_eq!(router.flows(), DNS_FLOW_LIMIT + 1);
        assert_eq!(router.statistics.data_capacity_drops, 0);
    }

    #[tokio::test]
    async fn tcp_waits_for_real_backend_before_accepting_and_rejects_failed_dials() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let unavailable = if address.starts_with('[') {
                TcpSocket::new_v6().unwrap()
            } else {
                TcpSocket::new_v4().unwrap()
            };
            unavailable.bind(address.parse().unwrap()).unwrap();
            let target = unavailable.local_addr().unwrap();
            let (_, mut client) = client(target, 6);
            let mut router = private_test_router(target.ip());
            client.poll(router.now());
            for bytes in client.device.output.drain(..) {
                router.ingest(7, &bytes);
            }
            for (_, bytes) in router.poll() {
                let offset = if target.is_ipv4() {
                    usize::from(bytes[0] & 15) * 4
                } else {
                    40
                };
                assert_ne!(
                    bytes[offset + 13] & 0x12,
                    0x12,
                    "SYN-ACK before physical connect"
                );
                client.device.input.push_back(bytes);
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline && router.flows() > 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                for (_, bytes) in router.poll() {
                    let offset = if target.is_ipv4() {
                        usize::from(bytes[0] & 15) * 4
                    } else {
                        40
                    };
                    assert_ne!(
                        bytes[offset + 13] & 0x12,
                        0x12,
                        "failed backend advertised success"
                    );
                    client.device.input.push_back(bytes);
                }
                client.poll(router.now());
                assert_ne!(
                    client.sockets.get::<tcp::Socket>(client.handle).state(),
                    tcp::State::Established
                );
            }
            assert_eq!(router.flows(), 0);
            assert_eq!(
                client.sockets.get::<tcp::Socket>(client.handle).state(),
                tcp::State::Closed
            );
        }
    }

    #[tokio::test]
    async fn real_tcp_backend_relays_both_families_and_preserves_half_close() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(address).await.unwrap();
            let target = listener.local_addr().unwrap();
            let backend = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                socket.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, b"request");
                socket.write_all(b"response").await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let (_, mut client) = client(target, 6);
            let mut router = private_test_router(target.ip());
            let mut sent = false;
            let mut response = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                exchange(&mut client, &mut router);
                let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
                if socket.can_send() && !sent {
                    assert_eq!(socket.send_slice(b"request").unwrap(), 7);
                    socket.close();
                    sent = true;
                }
                if socket.can_recv() {
                    let _ = socket.recv(|bytes| {
                        response.extend_from_slice(bytes);
                        (bytes.len(), ())
                    });
                }
                if response == b"response" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(response, b"response", "{address}");
            backend.await.unwrap();
        }
    }

    #[tokio::test]
    async fn real_udp_backend_is_bound_to_original_peer_and_drop_closes_resources() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let backend = UdpSocket::bind(address).await.unwrap();
            let target = backend.local_addr().unwrap();
            let (packet, mut client) = client(target, 17);
            let mut router = private_test_router(target.ip());
            client
                .sockets
                .get_mut::<udp::Socket>(client.handle)
                .send_slice(b"first", (IpAddress::from(target.ip()), target.port()))
                .unwrap();
            exchange(&mut client, &mut router);
            let mut bytes = [0; 100];
            let deadline = Instant::now() + Duration::from_secs(2);
            let (length, remote) = loop {
                exchange(&mut client, &mut router);
                if let Ok(received) = backend.try_recv_from(&mut bytes) {
                    break received;
                }
                assert!(Instant::now() < deadline, "UDP 未送达真实后端");
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            assert_eq!(&bytes[..length], b"first");
            backend.send_to(b"reply", remote).await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut reply = None;
            while Instant::now() < deadline {
                exchange(&mut client, &mut router);
                if let Ok((bytes, _)) = client.sockets.get_mut::<udp::Socket>(client.handle).recv()
                {
                    reply = Some(bytes.to_vec());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(reply.as_deref(), Some(&b"reply"[..]));
            client
                .sockets
                .get_mut::<udp::Socket>(client.handle)
                .send_slice(b"spoof", (IpAddress::from(target.ip()), target.port()))
                .unwrap();
            client.poll(router.now());
            let forged = client.device.output.pop_front().unwrap();
            router.ingest(8, &forged);
            router.poll();
            assert_eq!(router.flows[&packet].peer, 7);
            assert!(
                tokio::time::timeout(Duration::from_millis(50), backend.recv_from(&mut bytes))
                    .await
                    .is_err()
            );
            drop(router);
        }
    }

    #[tokio::test]
    #[ignore = "requires unprivileged ICMP ping socket permission"]
    async fn real_icmp_ping_checks_both_address_families() {
        ping("127.0.0.1".parse().unwrap()).await.unwrap();
        ping("::1".parse().unwrap()).await.unwrap();
    }
}
