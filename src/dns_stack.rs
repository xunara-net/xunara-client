use std::{
    collections::{BTreeMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use hickory_proto::op::{Message, ResponseCode};
use rand_core::{OsRng, RngCore};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::{tcp, udp},
    time::{Duration as StackDuration, Instant as StackInstant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot},
    task::JoinSet,
};

use crate::{
    dns::{self, Answer, DnsPlan, Target},
    filter::Packet,
    packet_stack::Queue,
};

const LIMIT: usize = 64;
const TCP_LIMIT: usize = 8;
const MAX_RESPONSE: usize = 65535;

#[derive(Default, serde::Serialize)]
pub struct Statistics {
    queries: u64,
    responses: u64,
    servfail: u64,
    nxdomain: u64,
    timeouts: u64,
    peer_queries: u64,
    peer_responses: u64,
    peer_servfail: u64,
}

enum Client {
    Udp(IpEndpoint, usize),
    Tcp(usize, u64),
    Validation(oneshot::Sender<Message>),
    Api(oneshot::Sender<Message>),
}
struct Listener {
    handle: SocketHandle,
    generation: u64,
    input: Vec<u8>,
    output: Vec<u8>,
    written: usize,
    busy: bool,
}
struct Upstream {
    handle: SocketHandle,
    target: Target,
    input: Vec<u8>,
    output: Vec<u8>,
    written: usize,
    started: Instant,
    tls: Option<crate::dns_tls::Session>,
}
struct Pending {
    client: Client,
    query: Message,
    targets: VecDeque<Target>,
    upstream: Option<Upstream>,
    direct: bool,
}

/// 有界 DNS 专用 TCP/IP 端点，不代理应用的任意 TCP 流，也不监听手机物理网卡。
pub struct DnsProxy {
    plan: DnsPlan,
    device: Queue,
    interface: Interface,
    sockets: SocketSet<'static>,
    udp: SocketHandle,
    listeners: Vec<Listener>,
    pending: BTreeMap<u64, Pending>,
    retired: Vec<SocketHandle>,
    tasks: JoinSet<(u64, Result<Message>)>,
    next_id: u64,
    next_port: u16,
    started: Instant,
    validator: crate::dns_validate::Validator,
    validation_requests: mpsc::Receiver<crate::dns_validate::Request>,
    api_sender: mpsc::Sender<ApiRequest>,
    api_requests: mpsc::Receiver<ApiRequest>,
    statistics: Statistics,
}

pub struct ApiRequest {
    pub query: Message,
    pub reply: oneshot::Sender<Message>,
}

impl DnsProxy {
    pub fn new(plan: DnsPlan) -> Result<Self> {
        let mut device = Queue::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = OsRng.next_u64();
        let mut interface = Interface::new(config, &mut device, StackInstant::from_millis(0));
        ensure!(
            plan.addresses.len() < smoltcp::config::IFACE_MAX_ADDR_COUNT,
            "DNS 本机地址数量超过端点容量"
        );
        ensure!(
            plan.addresses
                .iter()
                .all(|address| !address.is_unspecified()
                    && !address.is_multicast()
                    && !address.is_loopback()),
            "DNS 本机地址无效"
        );
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(
                    plan.address.into(),
                    if plan.address.is_ipv4() { 32 } else { 128 },
                ))
                .expect("bounded addresses");
            for address in &plan.addresses {
                addresses
                    .push(IpCidr::new(
                        (*address).into(),
                        if address.is_ipv4() { 32 } else { 128 },
                    ))
                    .expect("bounded addresses");
            }
        });
        interface
            .routes_mut()
            .add_default_ipv4_route("100.100.100.100".parse()?)
            .map_err(|_| anyhow::anyhow!("DNS IPv4 路由已满"))?;
        interface
            .routes_mut()
            .add_default_ipv6_route("fd7a:115c:a1e0::53".parse()?)
            .map_err(|_| anyhow::anyhow!("DNS IPv6 路由已满"))?;
        let mut sockets = SocketSet::new(Vec::new());
        let mut server = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65536]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65536]),
        );
        server
            .bind((IpAddress::from(plan.address), 53))
            .map_err(|_| anyhow::anyhow!("DNS UDP 监听失败"))?;
        let udp = sockets.add(server);
        let mut listeners = Vec::new();
        for _ in 0..TCP_LIMIT {
            let mut socket = tcp_socket();
            socket
                .listen((IpAddress::from(plan.address), 53))
                .map_err(|_| anyhow::anyhow!("DNS TCP 监听失败"))?;
            listeners.push(Listener {
                handle: sockets.add(socket),
                generation: 0,
                input: Vec::new(),
                output: Vec::new(),
                written: 0,
                busy: false,
            });
        }
        let (validator, validation_requests) = crate::dns_validate::Validator::new();
        let (api_sender, api_requests) = mpsc::channel(32);
        Ok(Self {
            plan,
            device,
            interface,
            sockets,
            udp,
            listeners,
            pending: BTreeMap::new(),
            retired: Vec::new(),
            tasks: JoinSet::new(),
            next_id: 0,
            next_port: 49152 + (OsRng.next_u32() % 8192) as u16,
            started: Instant::now(),
            validator,
            validation_requests,
            api_sender,
            api_requests,
            statistics: Statistics::default(),
        })
    }

    pub fn plan(&self) -> &DnsPlan {
        &self.plan
    }

    pub fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    pub fn api_sender(&self) -> mpsc::Sender<ApiRequest> {
        self.api_sender.clone()
    }

    pub fn local(&self, bytes: &[u8]) -> bool {
        Packet::parse(bytes).is_some_and(|packet| {
            packet.destination == self.plan.address
                && packet.destination_port == 53
                && matches!(packet.protocol, 6 | 17)
                && self.plan.addresses.contains(&packet.source)
        })
    }

    pub fn upstream(&self, bytes: &[u8]) -> bool {
        Packet::parse(bytes).is_some_and(|packet| {
            packet.protocol == 6
                && self.pending.values().any(|pending| {
                    pending.upstream.as_ref().is_some_and(|upstream| {
                        let socket = self.sockets.get::<tcp::Socket>(upstream.handle);
                        socket.remote_endpoint().is_some_and(|remote| {
                            IpAddr::from(remote.addr) == packet.source
                                && remote.port == packet.source_port
                        }) && socket.local_endpoint().is_some_and(|local| {
                            IpAddr::from(local.addr) == packet.destination
                                && local.port == packet.destination_port
                        })
                    })
                })
        })
    }

    pub fn ingest(&mut self, bytes: &[u8]) {
        if self.device.input.len() < 256 {
            self.device.input.push_back(bytes.to_vec());
        }
    }

    /// 输出由 Engine 按目的地址分流：DNS 回包写 TUN，上游请求仍走同一 WireGuard/ACL。
    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        let now = StackInstant::from_millis(
            self.started.elapsed().as_millis().min(i64::MAX as u128) as i64,
        );
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        while let Some(Ok((id, response))) = self.tasks.try_join_next() {
            if let Some(pending) = self.pending.get_mut(&id) {
                pending.direct = false;
            }
            match response {
                Ok(response) => self.complete(id, response),
                Err(error) if error.is::<tokio::time::error::Elapsed>() => {
                    self.statistics.timeouts += 1;
                }
                Err(_) => {}
            }
        }
        let mut requests = Vec::new();
        let socket = self.sockets.get_mut::<udp::Socket>(self.udp);
        while let Ok((bytes, metadata)) = socket.recv() {
            if let Ok(query) = dns::query(bytes) {
                requests.push((
                    Client::Udp(
                        metadata.endpoint,
                        usize::from(query.max_payload()).clamp(512, 1232),
                    ),
                    query,
                ));
            }
        }
        for (index, listener) in self.listeners.iter_mut().enumerate() {
            let socket = self.sockets.get_mut::<tcp::Socket>(listener.handle);
            if !socket.is_open() {
                listener.generation += 1;
                listener.busy = false;
                listener.input.clear();
                listener.output.clear();
                listener.written = 0;
                let _ = socket.listen((IpAddress::from(self.plan.address), 53));
            }
            if socket.can_recv() {
                let mut bytes = [0; 4096];
                while let Ok(length) = socket.recv_slice(&mut bytes) {
                    if length == 0 {
                        break;
                    }
                    listener.input.extend_from_slice(&bytes[..length]);
                    if listener.input.len() > 16386 {
                        socket.abort();
                        break;
                    }
                }
            }
            if !listener.output.is_empty() && socket.can_send() {
                if let Ok(length) = socket.send_slice(&listener.output[listener.written..]) {
                    listener.written += length;
                }
                if listener.written == listener.output.len() {
                    listener.output.clear();
                    listener.written = 0;
                    listener.busy = false;
                }
            }
            if !listener.busy && listener.input.len() >= 2 {
                let length =
                    usize::from(u16::from_be_bytes([listener.input[0], listener.input[1]]));
                if !(12..=16384).contains(&length) {
                    socket.abort();
                    continue;
                }
                if listener.input.len() >= length + 2 {
                    let query = dns::query(&listener.input[2..length + 2]);
                    listener.input.drain(..length + 2);
                    match query {
                        Ok(query) => {
                            listener.busy = true;
                            requests.push((Client::Tcp(index, listener.generation), query));
                        }
                        Err(_) => socket.abort(),
                    }
                }
            }
            if socket.state() == tcp::State::CloseWait
                && !listener.busy
                && listener.output.is_empty()
            {
                socket.close();
            }
        }
        for (client, query) in requests {
            self.request(client, query);
        }
        while let Ok(request) = self.validation_requests.try_recv() {
            self.request(Client::Validation(request.reply), request.query);
        }
        while let Ok(request) = self.api_requests.try_recv() {
            self.request(Client::Api(request.reply), request.query);
        }
        let mut completed = Vec::new();
        let mut failed = Vec::new();
        for (id, pending) in &mut self.pending {
            if let Some(upstream) = &mut pending.upstream {
                if upstream.written == upstream.output.len() {
                    upstream.output.clear();
                    upstream.written = 0;
                }
                let socket = self.sockets.get_mut::<tcp::Socket>(upstream.handle);
                if socket.can_send()
                    && upstream.written < upstream.output.len()
                    && let Ok(length) = socket.send_slice(&upstream.output[upstream.written..])
                {
                    upstream.written += length;
                }
                if socket.can_recv() {
                    let mut bytes = [0; 4096];
                    while let Ok(length) = socket.recv_slice(&mut bytes) {
                        if length == 0 {
                            break;
                        }
                        let plain = if let Some(tls) = &mut upstream.tls {
                            match tls.receive(&bytes[..length]) {
                                Ok(plain) => plain,
                                Err(_) => {
                                    failed.push(*id);
                                    break;
                                }
                            }
                        } else {
                            bytes[..length].to_vec()
                        };
                        upstream.input.extend(plain);
                        if upstream.input.len() > MAX_RESPONSE + 8192 {
                            break;
                        }
                    }
                }
                if let Some(tls) = &mut upstream.tls {
                    if failed.contains(id) {
                        continue;
                    }
                    match tls.output() {
                        Ok(bytes) => upstream.output.extend(bytes),
                        Err(_) => {
                            failed.push(*id);
                            continue;
                        }
                    }
                }
                let response = upstream_response(
                    &upstream.target,
                    &upstream.input,
                    !socket.may_recv()
                        && !matches!(
                            socket.state(),
                            tcp::State::SynSent | tcp::State::SynReceived
                        ),
                );
                match response {
                    Ok(Some(bytes)) => match dns::verified(&pending.query, &bytes) {
                        Ok(response) => completed.push((*id, response)),
                        Err(_) => failed.push(*id),
                    },
                    Err(_) => failed.push(*id),
                    Ok(None) => {
                        // 官方 peerapi 自身允许五秒解析，不能在连接成功后仍用四秒总预算提前撤销。
                        // 建连仍有短超时；已连接出口沿用官方 DNS 的十秒上限，不回退手机原网络。
                        let budget = if matches!(upstream.target, Target::PeerHttp(_))
                            && !matches!(
                                socket.state(),
                                tcp::State::SynSent | tcp::State::SynReceived
                            ) {
                            Duration::from_secs(10)
                        } else {
                            Duration::from_secs(4)
                        };
                        let timed_out = upstream.started.elapsed() > budget;
                        if timed_out || !socket.is_open() {
                            if timed_out {
                                self.statistics.timeouts += 1;
                            }
                            failed.push(*id);
                        }
                    }
                }
            }
        }
        for (id, response) in completed {
            self.complete(id, response);
        }
        for id in failed {
            self.clear_upstream(id);
        }
        let ready = self
            .pending
            .iter()
            .filter(|(_, pending)| !pending.direct && pending.upstream.is_none())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in ready {
            self.forward(id);
        }
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        // abort 后 tuple 直到 RST 入队才清空；is_open 已经为 false，不能据此提前回收。
        self.retired.retain(|handle| {
            if self
                .sockets
                .get::<tcp::Socket>(*handle)
                .remote_endpoint()
                .is_none()
            {
                self.sockets.remove(*handle);
                false
            } else {
                true
            }
        });
        self.device.output.drain(..).collect()
    }

    fn request(&mut self, client: Client, query: Message) {
        if matches!(&client, Client::Udp(..) | Client::Tcp(..)) {
            self.statistics.queries += 1;
        } else if matches!(&client, Client::Api(_)) {
            self.statistics.peer_queries += 1;
        }
        let answer = if matches!(&client, Client::Api(_)) {
            self.plan.answer_for_peer(&query)
        } else {
            self.plan.answer(&query)
        };
        match answer {
            Answer::Local(response) => self.respond(client, &response),
            Answer::Forward(targets) => {
                let internal = matches!(&client, Client::Validation(_));
                if self.pending.len() >= if internal { LIMIT } else { LIMIT / 2 } {
                    self.respond(client, &dns::reply(&query, ResponseCode::ServFail));
                    return;
                }
                self.next_id += 1;
                let validate = self.plan.dnssec_validate && !internal;
                self.pending.insert(
                    self.next_id,
                    Pending {
                        client,
                        query,
                        targets: if validate {
                            VecDeque::new()
                        } else {
                            targets.into_iter().take(3).collect()
                        },
                        upstream: None,
                        direct: validate,
                    },
                );
                if validate {
                    let validator = self.validator.clone();
                    let id = self.next_id;
                    let query = self.pending[&id].query.clone();
                    self.tasks
                        .spawn(async move { (id, validator.query(query).await) });
                }
            }
        }
    }

    fn forward(&mut self, id: u64) {
        // 终止帧受回压时暂停新连接，保留待选解析器，不另建无界清理队列。
        if self.retired.len() >= LIMIT {
            return;
        }
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        let Some(target) = pending.targets.pop_front() else {
            let response = dns::reply(&pending.query, ResponseCode::ServFail);
            self.complete(id, response);
            return;
        };
        if !self.plan.tunneled(&target) {
            let mut targets = vec![target];
            while pending
                .targets
                .front()
                .is_some_and(|target| !self.plan.tunneled(target))
            {
                targets.push(pending.targets.pop_front().expect("checked resolver"));
            }
            pending.direct = true;
            let query = pending.query.clone();
            self.tasks
                .spawn(async move { (id, direct_resolvers(targets, query).await) });
            return;
        }
        let Some(source) = self
            .plan
            .addresses
            .iter()
            .find(|address| address.is_ipv4() == target.address().is_ipv4())
        else {
            return;
        };
        let Ok(mut output) = upstream_request(&target, &pending.query) else {
            return;
        };
        let tls = if let Target::Encrypted { name, .. } = &target {
            let Ok(mut tls) = crate::dns_tls::Session::new(name, &output) else {
                return;
            };
            let Ok(encrypted) = tls.output() else {
                return;
            };
            output = encrypted;
            Some(tls)
        } else {
            None
        };
        let mut socket = tcp_socket();
        let local = (IpAddress::from(*source), self.next_port);
        self.next_port = if self.next_port == 65535 {
            49152
        } else {
            self.next_port + 1
        };
        if socket
            .connect(
                self.interface.context(),
                (
                    IpAddress::from(target.address().ip()),
                    target.address().port(),
                ),
                local,
            )
            .is_err()
        {
            return;
        }
        pending.upstream = Some(Upstream {
            handle: self.sockets.add(socket),
            target,
            input: Vec::new(),
            output,
            written: 0,
            started: Instant::now(),
            tls,
        });
    }

    fn clear_upstream(&mut self, id: u64) {
        if let Some(upstream) = self
            .pending
            .get_mut(&id)
            .and_then(|pending| pending.upstream.take())
        {
            // SocketSet::remove 不会终止 TCP。先发 RST，再释放句柄，
            // 否则已完成查询仍占用出口的每设备连接额度，浏览器会逐渐只剩 SERVFAIL。
            self.sockets.get_mut::<tcp::Socket>(upstream.handle).abort();
            self.retired.push(upstream.handle);
        }
    }
    fn complete(&mut self, id: u64, response: Message) {
        self.clear_upstream(id);
        if let Some(pending) = self.pending.remove(&id) {
            self.respond(pending.client, &response);
        }
    }
    fn respond(&mut self, client: Client, response: &Message) {
        // 只统计应用 DNS 消息，不把 TCP ACK、校验器递归或 peerapi 内部请求当成手机查询。
        if matches!(&client, Client::Udp(..) | Client::Tcp(..)) {
            self.statistics.responses += 1;
            match response.metadata.response_code {
                ResponseCode::ServFail => self.statistics.servfail += 1,
                ResponseCode::NXDomain => self.statistics.nxdomain += 1,
                _ => {}
            }
        } else if matches!(&client, Client::Api(_)) {
            self.statistics.peer_responses += 1;
            if response.metadata.response_code == ResponseCode::ServFail {
                self.statistics.peer_servfail += 1;
            }
        }
        match client {
            Client::Validation(reply) | Client::Api(reply) => {
                let _ = reply.send(response.clone());
            }
            Client::Udp(endpoint, limit) => {
                if let Ok(bytes) = dns::encode(response, limit) {
                    let _ = self
                        .sockets
                        .get_mut::<udp::Socket>(self.udp)
                        .send_slice(&bytes, endpoint);
                }
            }
            Client::Tcp(index, generation) => {
                if let Some(listener) = self
                    .listeners
                    .get_mut(index)
                    .filter(|listener| listener.generation == generation)
                {
                    if let Ok(bytes) = dns::encode(response, MAX_RESPONSE) {
                        listener.output = frame(&bytes);
                        listener.written = 0;
                    } else {
                        self.sockets.get_mut::<tcp::Socket>(listener.handle).abort();
                    }
                }
            }
        }
    }
}

fn tcp_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 32768]),
        tcp::SocketBuffer::new(vec![0; 32768]),
    );
    socket.set_timeout(Some(StackDuration::from_secs(15)));
    socket.set_ack_delay(None);
    socket
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut output = (bytes.len() as u16).to_be_bytes().to_vec();
    output.extend_from_slice(bytes);
    output
}
fn upstream_request(target: &Target, query: &Message) -> Result<Vec<u8>> {
    let bytes = query.to_vec()?;
    match target {
        Target::Dns(_) | Target::Encrypted { path: None, .. } => Ok(frame(&bytes)),
        Target::PeerHttp(_) | Target::Encrypted { path: Some(_), .. } => {
            let (host, path) = match target {
                Target::Encrypted {
                    name,
                    path: Some(path),
                    address,
                } => (
                    format!(
                        "{}:{}",
                        if name.contains(':') {
                            format!("[{name}]")
                        } else {
                            name.clone()
                        },
                        address.port()
                    ),
                    path.as_str(),
                ),
                _ => (target.address().to_string(), "/dns-query"),
            };
            let mut output=format!("POST {path} HTTP/1.0\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).into_bytes();
            output.extend(bytes);
            Ok(output)
        }
    }
}
fn upstream_response(target: &Target, bytes: &[u8], closed: bool) -> Result<Option<Vec<u8>>> {
    ensure!(bytes.len() <= MAX_RESPONSE + 8192, "DNS 响应超过上限");
    match target {
        Target::Dns(_) | Target::Encrypted { path: None, .. } => {
            if bytes.len() < 2 {
                ensure!(!closed, "DNS 连接提前关闭");
                return Ok(None);
            }
            let length = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
            ensure!(length >= 12, "DNS 响应过短");
            if bytes.len() >= length + 2 {
                Ok(Some(bytes[2..length + 2].to_vec()))
            } else {
                ensure!(!closed, "DNS 回包不完整");
                Ok(None)
            }
        }
        Target::PeerHttp(_) | Target::Encrypted { path: Some(_), .. } => {
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut response = httparse::Response::new(&mut headers);
            let httparse::Status::Complete(offset) = response.parse(bytes)? else {
                ensure!(bytes.len() <= 8192 && !closed, "DNS HTTP 头无效");
                return Ok(None);
            };
            ensure!(response.code == Some(200), "出口 DNS 服务拒绝请求");
            ensure!(
                response
                    .headers
                    .iter()
                    .any(|header| header.name.eq_ignore_ascii_case("Content-Type")
                        && header.value.starts_with(b"application/dns-message")),
                "出口 DNS 内容类型无效"
            );
            ensure!(
                !response
                    .headers
                    .iter()
                    .any(|header| header.name.eq_ignore_ascii_case("Transfer-Encoding")),
                "DNS HTTP/1.0 不接受分块响应"
            );
            let lengths = response
                .headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case("Content-Length"))
                .collect::<Vec<_>>();
            ensure!(lengths.len() <= 1, "出口 DNS 长度头重复");
            let body = &bytes[offset..];
            if let Some(header) = lengths.first() {
                let length = std::str::from_utf8(header.value)?.parse::<usize>()?;
                ensure!((12..=MAX_RESPONSE).contains(&length), "出口 DNS 长度无效");
                if body.len() >= length {
                    return Ok(Some(body[..length].to_vec()));
                }
            } else if closed {
                return Ok(Some(body.to_vec()));
            }
            ensure!(!closed, "出口 DNS 回包不完整");
            Ok(None)
        }
    }
}

async fn direct_resolvers(targets: Vec<Target>, query: Message) -> Result<Message> {
    let mut tasks = JoinSet::new();
    for (index, target) in targets.into_iter().take(3).enumerate() {
        let query = query.clone();
        tasks.spawn(async move {
            // 有界错峰并发与官方多解析器竞争一致，避免首个 DNS 黑洞拖死全部手机解析。
            tokio::time::sleep(Duration::from_millis(index as u64 * 150)).await;
            direct(&target, &query).await
        });
    }
    let mut soft_error = None;
    let mut failure = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(response))
                if matches!(
                    response.metadata.response_code,
                    ResponseCode::ServFail | ResponseCode::Refused
                ) =>
            {
                soft_error = Some(response);
            }
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(error)) => failure = Some(error),
            Err(error) => failure = Some(error.into()),
        }
    }
    if let Some(response) = soft_error {
        return Ok(response);
    }
    Err(failure.unwrap_or_else(|| anyhow::anyhow!("DNS 没有可用解析器")))
}

async fn direct(target: &Target, query: &Message) -> Result<Message> {
    if matches!(target, Target::PeerHttp(_)) {
        bail!("出口 DNS 只能走加密隧道");
    }
    let address = target.address();
    tokio::time::timeout(Duration::from_secs(4), async {
        let mut upstream = query.clone();
        upstream.metadata.id = OsRng.next_u32() as u16;
        // 普通网络 DNS 优先 UDP；连接到指定解析器并核对随机事务，截断或不可用再回退 TCP。
        if matches!(target, Target::Dns(_))
            && let Ok(Ok(mut response)) =
                tokio::time::timeout(Duration::from_secs(1), direct_udp(address, &upstream)).await
            && !response.metadata.truncation
        {
            response.metadata.id = query.metadata.id;
            return Ok(response);
        }
        let socket = if address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        #[cfg(target_os = "android")]
        {
            use std::os::fd::AsRawFd;
            crate::mobile::host()?.protect(socket.as_raw_fd())?;
        }
        let stream = socket.connect(address).await?;
        let mut stream: crate::transport::Stream = if let Target::Encrypted { name, .. } = target {
            Box::new(
                tokio_rustls::TlsConnector::from(crate::dns_tls::configuration())
                    .connect(
                        rustls::pki_types::ServerName::try_from(name.to_owned())?,
                        stream,
                    )
                    .await?,
            )
        } else {
            Box::new(stream)
        };
        stream
            .write_all(&upstream_request(target, &upstream)?)
            .await?;
        let mut bytes = Vec::new();
        loop {
            let mut buffer = [0; 4096];
            let length = stream.read(&mut buffer).await?;
            bytes.extend_from_slice(&buffer[..length]);
            if let Some(bytes) = upstream_response(target, &bytes, length == 0)? {
                let mut response = dns::verified(&upstream, &bytes)?;
                response.metadata.id = query.metadata.id;
                return Ok(response);
            }
        }
    })
    .await
    .context("DNS 上游查询超时")?
}

async fn direct_udp(address: std::net::SocketAddr, query: &Message) -> Result<Message> {
    let socket = tokio::net::UdpSocket::bind(if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        crate::mobile::host()?.protect(socket.as_raw_fd())?;
    }
    socket.connect(address).await?;
    socket.send(&query.to_vec()?).await?;
    let mut bytes = vec![0; 65535];
    let length = socket.recv(&mut bytes).await?;
    dns::verified(query, &bytes[..length])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires public HTTPS connectivity; independently validates real DNSSEC chains"]
    async fn real_doh_dnssec_accepts_signed_domain_and_rejects_bogus_chain() {
        let (validator, mut requests) = crate::dns_validate::Validator::new();
        let target = Target::Encrypted {
            address: "1.1.1.1:443".parse().unwrap(),
            name: "cloudflare-dns.com".into(),
            path: Some("/dns-query".into()),
        };
        let worker = tokio::spawn(async move {
            while let Some(request) = requests.recv().await {
                let response = direct(&target, &request.query)
                    .await
                    .expect("public DoH transport failed");
                let _ = request.reply.send(response);
            }
        });
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.metadata.authentic_data = true;
        query.queries.push(Query::query(
            Name::from_ascii("cloudflare.com.").unwrap(),
            RecordType::A,
        ));
        let response = validator
            .query(query.clone())
            .await
            .expect("real DNSSEC chain must validate");
        assert!(response.metadata.authentic_data);
        assert!(!response.answers.is_empty());
        assert!(response.edns.is_none());
        assert!(
            response
                .answers
                .iter()
                .all(|record| !record.record_type().is_dnssec())
        );
        let mut legacy_query = query.clone();
        legacy_query.metadata.authentic_data = false;
        let legacy = validator.query(legacy_query).await.unwrap();
        assert!(!legacy.metadata.authentic_data);
        assert!(legacy.edns.is_none());
        assert!(!legacy.answers.is_empty());
        assert!(
            legacy
                .answers
                .iter()
                .all(|record| !record.record_type().is_dnssec())
        );
        query.queries[0] = Query::query(
            Name::from_ascii("xunara-dnssec-proof.invalid.").unwrap(),
            RecordType::A,
        );
        let negative = validator
            .query(query.clone())
            .await
            .expect("signed NXDOMAIN proof must validate");
        assert_eq!(negative.metadata.response_code, ResponseCode::NXDomain);
        assert!(negative.metadata.authentic_data);
        query.queries[0] = Query::query(
            Name::from_ascii("dnssec-failed.org.").unwrap(),
            RecordType::A,
        );
        assert!(validator.query(query).await.is_err());
        worker.abort();
        let _ = worker.await;
    }
    use crate::{config::Config as ClientConfig, model::NetworkMap};
    use hickory_proto::{
        op::Query,
        rr::{Name, RecordType},
    };
    use serde_json::json;

    async fn dns_listeners() -> (tokio::net::UdpSocket, tokio::net::TcpListener) {
        // TCP 和 UDP 独立分配临时端口；仅在测试端口碰撞时重新预约，不重试实际 DNS 断言。
        for _attempt in 0..16 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            match tokio::net::UdpSocket::bind(listener.local_addr().unwrap()).await {
                Ok(socket) => return (socket, listener),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
                Err(error) => panic!("DNS test socket: {error}"),
            }
        }
        panic!("no free dual-protocol DNS test port");
    }

    #[tokio::test]
    async fn direct_dns_uses_udp_and_falls_back_to_tcp_for_truncated_answers() {
        for truncated in [false, true] {
            let (socket, listener) = dns_listeners().await;
            let address = socket.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let mut bytes = [0; 4096];
                let (length, source) = socket.recv_from(&mut bytes).await.unwrap();
                let query = dns::query(&bytes[..length]).unwrap();
                let mut response = dns::reply(&query, ResponseCode::NoError);
                response.answers.push(hickory_proto::rr::Record::from_rdata(
                    query.queries[0].name().clone(),
                    60,
                    hickory_proto::rr::RData::from("203.0.113.77".parse::<IpAddr>().unwrap()),
                ));
                let mut datagram = response.clone();
                datagram.metadata.truncation = truncated;
                socket
                    .send_to(&datagram.to_vec().unwrap(), source)
                    .await
                    .unwrap();
                if truncated {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let length = stream.read_u16().await.unwrap() as usize;
                    let mut request = vec![0; length];
                    stream.read_exact(&mut request).await.unwrap();
                    assert_eq!(dns::query(&request).unwrap().metadata.id, query.metadata.id);
                    stream
                        .write_all(&frame(&response.to_vec().unwrap()))
                        .await
                        .unwrap();
                }
            });
            let mut query = Message::query();
            query.queries.push(Query::query(
                Name::from_ascii("external.public.test.").unwrap(),
                RecordType::A,
            ));
            let response = direct(&Target::Dns(address), &query).await.unwrap();
            assert_eq!(response.metadata.id, query.metadata.id);
            assert!(!response.metadata.truncation);
            assert_eq!(response.answers.len(), 1);
            task.await.unwrap();
        }
    }

    async fn answering_resolver(socket: tokio::net::UdpSocket) {
        let mut bytes = [0; 4096];
        let (length, source) = socket.recv_from(&mut bytes).await.unwrap();
        let query = dns::query(&bytes[..length]).unwrap();
        let mut response = dns::reply(&query, ResponseCode::NoError);
        response.answers.push(hickory_proto::rr::Record::from_rdata(
            query.queries[0].name().clone(),
            60,
            hickory_proto::rr::RData::from("203.0.113.77".parse::<IpAddr>().unwrap()),
        ));
        socket
            .send_to(&response.to_vec().unwrap(), source)
            .await
            .unwrap();
    }

    async fn await_answer(
        server: &mut DnsProxy,
        mut response: oneshot::Receiver<Message>,
    ) -> Message {
        tokio::time::timeout(Duration::from_millis(900), async {
            loop {
                assert!(server.poll().is_empty());
                if let Ok(response) = response.try_recv() {
                    return response;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("健康的备用 DNS 不应等待首个解析器超时")
    }

    #[tokio::test]
    async fn healthy_dns_does_not_wait_for_an_unreachable_first_resolver() {
        let (blackhole, _tcp_blackhole) = dns_listeners().await;
        let (healthy, _tcp_healthy) = dns_listeners().await;
        let mut map = NetworkMap::default();
        map.apply(json!({"Node":{"ID":1,"Key":"own","MachineAuthorized":true,"Addresses":["100.80.0.1/32"]},
            "DNSConfig":{"Resolvers":[{"Addr":blackhole.local_addr().unwrap().to_string()},{"Addr":healthy.local_addr().unwrap().to_string()}]}})).unwrap();
        let config = ClientConfig {
            accept_dns: true,
            ..ClientConfig::default()
        };
        let mut server =
            DnsProxy::new(DnsPlan::new(&config, &map, &[], &[]).unwrap().unwrap()).unwrap();
        let worker = tokio::spawn(answering_resolver(healthy));
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("external.public.test.").unwrap(),
            RecordType::A,
        ));
        let (reply, response) = oneshot::channel();
        server.request(Client::Validation(reply), query);
        assert_eq!(await_answer(&mut server, response).await.answers.len(), 1);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn exit_peer_dns_uses_the_providers_physical_resolver() {
        let (blackhole, _tcp_blackhole) = dns_listeners().await;
        let (healthy, _tcp_healthy) = dns_listeners().await;
        let physical = healthy.local_addr().unwrap();
        let mut map = NetworkMap::default();
        map.apply(json!({"Node":{"ID":1,"Key":"own","MachineAuthorized":true,"Addresses":["100.80.0.1/32"]},
            "DNSConfig":{"Resolvers":[{"Addr":blackhole.local_addr().unwrap().to_string()}]}})).unwrap();
        let config = ClientConfig {
            accept_dns: true,
            advertise_exit: true,
            ..ClientConfig::default()
        };
        let mut server = DnsProxy::new(
            DnsPlan::new(&config, &map, &[], &[physical])
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let worker = tokio::spawn(answering_resolver(healthy));
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("external.public.test.").unwrap(),
            RecordType::A,
        ));
        let (reply, response) = oneshot::channel();
        server
            .api_sender()
            .try_send(ApiRequest { query, reply })
            .unwrap();
        assert_eq!(await_answer(&mut server, response).await.answers.len(), 1);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn resolver_race_ignores_soft_errors_but_preserves_nxdomain_and_cancels_losers() {
        for code in [
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::NXDomain,
        ] {
            let (first, _tcp_first) = dns_listeners().await;
            let (second, _tcp_second) = dns_listeners().await;
            let targets = vec![
                Target::Dns(first.local_addr().unwrap()),
                Target::Dns(second.local_addr().unwrap()),
            ];
            let worker = tokio::spawn(async move {
                let mut bytes = [0; 4096];
                let (length, source) = first.recv_from(&mut bytes).await.unwrap();
                let query = dns::query(&bytes[..length]).unwrap();
                first
                    .send_to(&dns::reply(&query, code).to_vec().unwrap(), source)
                    .await
                    .unwrap();
            });
            let mut query = Message::query();
            query.metadata.id = 1234;
            query.queries.push(Query::query(
                Name::from_ascii("external.public.test.").unwrap(),
                RecordType::A,
            ));
            if code == ResponseCode::NXDomain {
                let response = direct_resolvers(targets, query).await.unwrap();
                assert_eq!(response.metadata.response_code, code);
                assert_eq!(response.metadata.id, 1234);
                let mut bytes = [0; 4096];
                assert!(
                    tokio::time::timeout(Duration::from_millis(300), second.recv_from(&mut bytes))
                        .await
                        .is_err()
                );
            } else {
                let healthy = tokio::spawn(answering_resolver(second));
                let response = tokio::time::timeout(
                    Duration::from_millis(900),
                    direct_resolvers(targets, query),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(response.metadata.response_code, ResponseCode::NoError);
                assert_eq!(response.metadata.id, 1234);
                assert_eq!(response.answers.len(), 1);
                healthy.await.unwrap();
            }
            worker.await.unwrap();
        }
    }

    fn proxy() -> DnsProxy {
        let mut map = NetworkMap::default();
        map.apply(json!({"Node":{"ID":1,"Name":"phone.mesh.test.","Key":"key","MachineAuthorized":true,"Addresses":["100.80.0.1/32","fd7a:115c:a1e0::1/128"]},
            "Peers":[{"ID":2,"Name":"nas.mesh.test.","Key":"peer","MachineAuthorized":true,"Addresses":["100.80.0.2/32"]}],
            "DNSConfig":{"Proxied":true,"Routes":{"mesh.test":null},"Domains":["mesh.test"]}})).unwrap();
        DnsProxy::new(
            DnsPlan::new(
                &ClientConfig {
                    accept_dns: true,
                    ..ClientConfig::default()
                },
                &map,
                &[],
                &[],
            )
            .unwrap()
            .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn exit_dns_completion_releases_peer_tcp_flows_before_the_next_queries() {
        let mut client_map = NetworkMap::default();
        client_map.apply(json!({
            "Node":{"ID":2,"Name":"client.mesh.test.","Key":"client","MachineAuthorized":true,"Addresses":["100.80.0.2/32"]},
            "Peers":[{"ID":1,"StableID":"exit","Name":"exit.mesh.test.","Key":"exit","MachineAuthorized":true,"Addresses":["100.80.0.1/32"],"AllowedIPs":["0.0.0.0/0","::/0"],"Hostinfo":{"Services":[{"Proto":"peerapi4","Port":44444}]}}]
        })).unwrap();
        let mut exit_map = NetworkMap::default();
        exit_map.apply(json!({
            "Node":{"ID":1,"Name":"exit.mesh.test.","Key":"exit","MachineAuthorized":true,"Addresses":["100.80.0.1/32"],"AllowedIPs":["0.0.0.0/0","::/0"]},
            "Peers":[{"ID":2,"Name":"client.mesh.test.","Key":"client","MachineAuthorized":true,"Addresses":["100.80.0.2/32"]}],
            "DNSConfig":{"ExtraRecords":[{"Name":"public.example","Type":"A","Value":"192.0.2.1"}]}
        })).unwrap();
        let client_config = ClientConfig {
            exit_node_id: "exit".into(),
            ..ClientConfig::default()
        };
        let exit_config = ClientConfig {
            accept_dns: true,
            advertise_exit: true,
            ..ClientConfig::default()
        };
        let mut client = DnsProxy::new(
            DnsPlan::new(&client_config, &client_map, &[], &[])
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let mut exit_dns = DnsProxy::new(
            DnsPlan::new(&exit_config, &exit_map, &[], &[])
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let mut router = crate::forwarding::Forwarder::new(
            crate::forwarding::Plan::new(&exit_config, &exit_map)
                .unwrap()
                .unwrap(),
        );
        router.set_dns(exit_dns.api_sender());
        for attempt in 0..48 {
            let mut query = Message::query();
            query.queries.push(Query::query(
                Name::from_ascii("public.example.").unwrap(),
                RecordType::A,
            ));
            let (sender, mut response) = oneshot::channel();
            client.request(Client::Api(sender), query);
            let deadline = Instant::now() + Duration::from_millis(800);
            let answer = loop {
                assert!(exit_dns.poll().is_empty());
                for bytes in client.poll() {
                    router.ingest(2, &bytes);
                }
                for (_, bytes) in router.poll() {
                    client.ingest(&bytes);
                }
                if let Ok(answer) = response.try_recv() {
                    break answer;
                }
                assert!(
                    Instant::now() < deadline,
                    "DNS query {attempt} stalled with {} retained exit flows",
                    router.flows()
                );
                tokio::task::yield_now().await;
            };
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
            assert_eq!(answer.answers.len(), 1);
            for _ in 0..8 {
                for bytes in client.poll() {
                    router.ingest(2, &bytes);
                }
                for (_, bytes) in router.poll() {
                    client.ingest(&bytes);
                }
                tokio::task::yield_now().await;
            }
        }
        assert!(
            router.flows() <= 1,
            "completed DNS requests left {} exit flows",
            router.flows()
        );
    }

    #[test]
    fn completed_upstream_keeps_its_reset_until_output_backpressure_clears() {
        let mut server = proxy();
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("public.example.").unwrap(),
            RecordType::A,
        ));
        let (sender, _) = oneshot::channel();
        server.request(Client::Api(sender), query.clone());
        let identity = server.next_id;
        server
            .pending
            .get_mut(&identity)
            .unwrap()
            .targets
            .push_back(Target::PeerHttp("100.80.0.2:44444".parse().unwrap()));
        server.forward(identity);
        let handle = server.pending[&identity].upstream.as_ref().unwrap().handle;
        server.device.output.extend((0..256).map(|_| vec![0]));
        server.complete(identity, dns::reply(&query, ResponseCode::NoError));
        assert_eq!(server.poll().len(), 256);
        assert_eq!(server.retired, vec![handle]);
        assert!(
            server
                .sockets
                .get::<tcp::Socket>(handle)
                .remote_endpoint()
                .is_some()
        );
        let packets = server.poll();
        assert!(server.retired.is_empty());
        assert_eq!(packets.len(), 1);
        let packet = smoltcp::wire::Ipv4Packet::new_checked(&packets[0][..]).unwrap();
        let reset = smoltcp::wire::TcpPacket::new_checked(packet.payload()).unwrap();
        assert!(reset.rst());
        assert_eq!(reset.dst_port(), 44444);
    }

    #[test]
    fn reset_backpressure_does_not_consume_a_pending_resolver_or_allocate_unbounded_sockets() {
        let mut server = proxy();
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("public.example.").unwrap(),
            RecordType::A,
        ));
        let (sender, _) = oneshot::channel();
        server.request(Client::Api(sender), query);
        let identity = server.next_id;
        server
            .pending
            .get_mut(&identity)
            .unwrap()
            .targets
            .push_back(Target::PeerHttp("100.80.0.2:44444".parse().unwrap()));
        server
            .retired
            .extend((0..LIMIT).map(|_| server.sockets.add(tcp_socket())));
        server.forward(identity);
        assert!(server.pending[&identity].upstream.is_none());
        assert_eq!(server.pending[&identity].targets.len(), 1);
        assert_eq!(server.sockets.iter().count(), LIMIT + TCP_LIMIT + 1);
    }

    #[test]
    fn connected_exit_dns_can_finish_after_four_seconds_without_premature_failover() {
        let mut server = proxy();
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("external.public.test.").unwrap(),
            RecordType::A,
        ));
        let (sender, mut response) = oneshot::channel();
        server.request(Client::Api(sender), query.clone());
        let identity = server.next_id;
        server
            .pending
            .get_mut(&identity)
            .unwrap()
            .targets
            .push_back(Target::PeerHttp("100.80.0.2:1".parse().unwrap()));
        server.forward(identity);
        let mut device = Queue::default();
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            StackInstant::from_millis(0),
        );
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new("100.80.0.2".parse().unwrap(), 32))
                .unwrap()
        });
        interface
            .routes_mut()
            .add_default_ipv4_route("100.100.100.100".parse().unwrap())
            .unwrap();
        let mut sockets = SocketSet::new(Vec::new());
        let mut socket = tcp_socket();
        socket
            .listen(("100.80.0.2".parse::<IpAddress>().unwrap(), 1))
            .unwrap();
        let handle = sockets.add(socket);
        let mut received_request = false;
        for tick in 0..200 {
            for bytes in server.poll() {
                device.input.push_back(bytes);
            }
            interface.poll(StackInstant::from_millis(tick), &mut device, &mut sockets);
            for bytes in device.output.drain(..) {
                server.ingest(&bytes);
            }
            if sockets.get::<tcp::Socket>(handle).can_recv() {
                received_request = true;
                break;
            }
        }
        assert!(
            received_request,
            "peerapi must complete a real TCP handshake and receive the HTTP request"
        );
        server
            .pending
            .get_mut(&identity)
            .unwrap()
            .upstream
            .as_mut()
            .unwrap()
            .started = Instant::now() - Duration::from_millis(4500);
        for bytes in server.poll() {
            device.input.push_back(bytes);
        }
        assert!(
            server.pending.contains_key(&identity),
            "a connected official peerapi can legitimately take more than four seconds to answer"
        );
        let answer = dns::reply(&query, ResponseCode::NoError).to_vec().unwrap();
        let mut http = format!("HTTP/1.0 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", answer.len()).into_bytes();
        http.extend(answer);
        sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&http)
            .unwrap();
        for tick in 200..400 {
            interface.poll(StackInstant::from_millis(tick), &mut device, &mut sockets);
            for bytes in device.output.drain(..) {
                server.ingest(&bytes);
            }
            for bytes in server.poll() {
                device.input.push_back(bytes);
            }
            if let Ok(response) = response.try_recv() {
                assert_eq!(response.metadata.response_code, ResponseCode::NoError);
                return;
            }
        }
        panic!("the valid delayed peerapi response was not delivered");
    }

    #[test]
    fn statistics_separate_queries_responses_timeouts_and_internal_requests() {
        let mut server = proxy();
        let client = || Client::Udp(IpEndpoint::new("100.80.0.1".parse().unwrap(), 53000), 512);
        let question = |name| {
            let mut query = Message::query();
            query
                .queries
                .push(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            query
        };
        server.request(client(), question("nas.mesh.test."));
        server.request(client(), question("missing.mesh.test."));
        let (reply, _) = oneshot::channel();
        server.request(Client::Api(reply), question("nas.mesh.test."));
        server.request(client(), question("external.public.test."));
        let identity = server.next_id;
        server
            .pending
            .get_mut(&identity)
            .unwrap()
            .targets
            .push_back(Target::PeerHttp("100.80.0.2:1".parse().unwrap()));
        server.forward(identity);
        server
            .pending
            .get_mut(&identity)
            .unwrap()
            .upstream
            .as_mut()
            .unwrap()
            .started = Instant::now() - Duration::from_secs(5);
        server.poll();
        let statistics = serde_json::to_value(server.statistics()).unwrap();
        assert_eq!(
            statistics,
            json!({"queries":3,"responses":3,"servfail":1,"nxdomain":1,"timeouts":1,"peer_queries":1,"peer_responses":1,"peer_servfail":0})
        );
    }

    #[test]
    fn local_dns_serves_real_udp_and_tcp_packets() {
        for tcp in [false, true] {
            let mut server = proxy();
            let mut device = Queue::default();
            let mut interface = Interface::new(
                Config::new(HardwareAddress::Ip),
                &mut device,
                StackInstant::from_millis(0),
            );
            interface.update_ip_addrs(|addresses| {
                addresses
                    .push(IpCidr::new("100.80.0.1".parse().unwrap(), 32))
                    .unwrap();
            });
            interface
                .routes_mut()
                .add_default_ipv4_route("100.100.100.100".parse().unwrap())
                .unwrap();
            let mut sockets = SocketSet::new(Vec::new());
            let endpoint = (IpAddress::from(server.plan.address), 53);
            let handle = if tcp {
                let mut socket = tcp_socket();
                socket
                    .connect(
                        interface.context(),
                        endpoint,
                        ("100.80.0.1".parse::<IpAddress>().unwrap(), 53000),
                    )
                    .unwrap();
                sockets.add(socket)
            } else {
                let mut socket = udp::Socket::new(
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 8192]),
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 8192]),
                );
                socket
                    .bind(("100.80.0.1".parse::<IpAddress>().unwrap(), 53000))
                    .unwrap();
                sockets.add(socket)
            };
            let mut query = Message::query();
            query.queries.push(Query::query(
                Name::from_ascii("nas.mesh.test.").unwrap(),
                RecordType::A,
            ));
            let bytes = query.to_vec().unwrap();
            let mut sent = false;
            let mut received = Vec::new();
            for tick in 0..200 {
                if !sent {
                    if tcp {
                        let socket = sockets.get_mut::<tcp::Socket>(handle);
                        if socket.can_send() {
                            socket.send_slice(&frame(&bytes)).unwrap();
                            sent = true;
                        }
                    } else {
                        sockets
                            .get_mut::<udp::Socket>(handle)
                            .send_slice(&bytes, endpoint)
                            .unwrap();
                        sent = true;
                    }
                }
                interface.poll(StackInstant::from_millis(tick), &mut device, &mut sockets);
                for packet in device.output.drain(..) {
                    assert!(server.local(&packet));
                    server.ingest(&packet);
                }
                for packet in server.poll() {
                    device.input.push_back(packet);
                }
                if tcp {
                    let socket = sockets.get_mut::<tcp::Socket>(handle);
                    let mut bytes = [0; 2048];
                    if let Ok(length) = socket.recv_slice(&mut bytes) {
                        received.extend_from_slice(&bytes[..length]);
                    }
                } else if let Ok((bytes, _)) = sockets.get_mut::<udp::Socket>(handle).recv() {
                    received = bytes.to_vec();
                }
                let response = if tcp {
                    upstream_response(
                        &Target::Dns("100.100.100.100:53".parse().unwrap()),
                        &received,
                        false,
                    )
                    .unwrap()
                } else if received.is_empty() {
                    None
                } else {
                    Some(received.clone())
                };
                if let Some(bytes) = response {
                    let response = dns::verified(&query, &bytes).unwrap();
                    assert_eq!(response.answers.len(), 1);
                    break;
                }
            }
            assert!(!received.is_empty(), "DNS transport failed: TCP={tcp}");
        }
    }
    #[test]
    fn tcp_frames_and_exit_http_are_bounded_and_not_redirected() {
        let target = Target::Dns("100.80.0.2:53".parse().unwrap());
        let bytes = vec![0; 12];
        let framed = frame(&bytes);
        assert!(
            upstream_response(&target, &framed[..8], false)
                .unwrap()
                .is_none()
        );
        assert!(upstream_response(&target, &framed[..8], true).is_err());
        assert_eq!(
            upstream_response(&target, &framed, false).unwrap().unwrap(),
            bytes
        );
        let target = Target::PeerHttp("100.80.0.2:40000".parse().unwrap());
        assert!(
            upstream_response(
                &target,
                b"HTTP/1.0 302 Found\r\nLocation: https://evil.invalid\r\n\r\n",
                true
            )
            .is_err()
        );
        let mut response=b"HTTP/1.0 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 12\r\n\r\n".to_vec();
        response.extend(&bytes);
        assert_eq!(
            upstream_response(&target, &response, false)
                .unwrap()
                .unwrap(),
            bytes
        );
    }
}
