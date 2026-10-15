# Xunara Client — 精简 Rust 客户端

面向 Linux 服务器 / 路由器的最小客户端。无 GUI、Web 管理面、文件传输、SSH 服务或 Go 运行时；只保留加密组网、直接连接、DERP 回退和子网转发。

**这是首版最小实现，不是官方 Tailscale 客户端的完整替代品。** 先在测试网络验证，再部署关键业务。当前外层 UDP 使用 IPv4，隧道处理 IPv4 / IPv6 的 TCP、UDP 和 ICMP；不支持 IP 分片或 IPv6 扩展头。可见节点上限 256。

## 已实现

- 使用现有 `/key`、TS2021 / Noise、注册与流式网络映射接口；服务端无需修改。
- 预授权密钥或浏览器登录、设备审批；机器身份与人类账号分离。
- BoringTun WireGuard 加密、节点密钥绑定、源地址验证、防重放和握手限流。
- 官方 Disco Ping / Pong / CallMeMaybe、UDP 直连、STUN 外网端点发现。
- DERP v2、CA 校验 / 精确证书 pin、自动重连与 UDP 不通时回退。
- IPv4 / IPv6 设备地址、显式接收已批准路由、广播子网、内核子网转发。
- 可选 nftables 子网 SNAT，只创建自己的表，不清空现有防火墙。
- 下发 ACL / Grants 网络规则、增量规则组、端口/协议限制、出站回复状态。
- 0700 状态目录、0600 原子身份文件、实例锁、撤销 / 过期处理、失联超时拒绝转发。
- SIGINT / SIGTERM 关闭 TUN、清理本程序 NAT 表；状态文件不包含私钥或授权密钥。

## 下载与启动

预编译文件发布在本仓库 [Releases](https://github.com/xunara-net/xunara-client/releases)。首版提供 Linux AMD64 / ARM64 的静态 musl 单文件，不需要安装 Rust、Go 或 OpenSSL。下载后先按同一发布的 `SHA256SUMS` 校验。

系统依赖：`/dev/net/tun`、`iproute2`、`CAP_NET_ADMIN`；启用 `snat` 还需 `nftables`。不接管系统 DNS，不添加 `100.100.100.100` 路由，不修改默认路由或全局转发开关。

```sh
sudo install -m 0755 ./xunara-client_linux_amd64 /usr/local/bin/xunara-client
sudo install -d -m 0700 /etc/xunara-client /var/lib/xunara-client
sudo install -m 0600 config.example.json /etc/xunara-client/config.json
sudo xunara-client run --config /etc/xunara-client/config.json
```

默认进入浏览器授权流程。打开终端提示的正式根站点授权链接，登录自己的账号并批准设备，不要使用他人的管理员会话。

免交互接入：在用户中心创建属于当前网络的预授权密钥，保存为当前运行用户所有的 **0600 普通文件**，再运行：

```sh
sudo xunara-client run --config /etc/xunara-client/config.json \
  --auth-key-file /run/secrets/xunara-auth-key
sudo xunara-client status --state-dir /var/lib/xunara-client
```

命令行不接受明文 token；不要把密钥写进 URL、命令历史、Git 或日志。首次连接前先保存机器 / 节点 / Disco 私钥；重启继续使用同一身份。每个控制面必须使用独立状态目录，损坏身份不会被静默覆盖。

## 子网转发

路由器配置：

```json
{
  "server": "https://fakeop4.onbed.cn:9090",
  "state_dir": "/var/lib/xunara-client",
  "hostname": "home-router",
  "advertise_routes": ["192.168.50.0/24"],
  "snat": true
}
```

1. 管理员显式开启内核转发，例如 `sudo sysctl -w net.ipv4.ip_forward=1`；需要持久化时由运维写入自己的 sysctl 配置。
2. 启动后，在用户中心批准广播的子网路由。广播不等于批准，客户端不会自行授权。
3. 访问方设置 `"accept_routes": true`。同时配置允许目标子网 / 端口的 ACL。
4. `snat: true` 使用独立 nftables 表；`snat: false` 时，局域网网关必须配置到组网地址的回程路由。现有主机 FORWARD 防火墙仍需放行，客户端不会绕过它。

**已有 LAN 优先**：与已有主路由表的非默认网段冲突时，导入路由会被跳过并提示；本机虚拟地址冲突时拒绝启动配置，不能接管本地内网。请在控制台改用不冲突地址。不会凭客户端偏好更改服务器分配的地址。

## 暂不支持

GUI、Windows / macOS / Android、MagicDNS、接管 DNS、Exit Node、Tailnet Lock、跨租户设备共享 / 地址 masquerade、服务发布、SSH、文件传输、UDP Peer Relay、自动升级、内核 WireGuard 后端。子网默认路由 `/0` 明确拒绝。无法理解的网络协议 / 规则不会被解释成放行。

UDP STUN 是打洞与地址发现，**不是 UDP 业务中继**；DERP 业务回退仍通过 TLS / TCP。后续 UDP Peer Relay 必须遵循官方分配 / 授权协议，不能把裸 UDP 转发器伪装为兼容实现。

首版直连探测约每 10 秒一次，路径缓存最长 25 秒；网络切换后的回退可能需要数十秒。尚不提供客户端自动密钥轮换或完整诊断面板。

## 构建与验证

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
```

完整网络验收需在相邻目录放置 `xunara-server`，再构建**仅测试使用**的 Go fixture：

```sh
(cd tests/compat && go build -o ../../target/compat-fixture .)
cargo test --locked --test upstream -- --ignored
sh scripts/test-netns.sh
```

测试使用独立 user / network namespace、两台 Rust 节点和独立 LAN：验证注册、加密 TCP / ICMP、拒绝端口、审批后的子网转发、与官方 Go tsnet 双向通信、阻断 UDP 后的证书 pin DERP 回退及恢复。安装了 nftables 时可用 `XUNARA_TEST_SNAT=true sh scripts/test-netns.sh` 复测无 LAN 回程路由的 SNAT 场景。不创建生产账号，不修改宿主机路由 / sysctl / DNS。需要允许 unprivileged user namespace；受限 CI 可在隔离 namespace 内用 root 执行 `--inside`。

静态双架构发布构建：`sh scripts/build-release.sh v0.1.0 /tmp/xunara-client-release`。详见 [架构与边界](docs/architecture.md) 和 [安全说明](SECURITY.md)。
