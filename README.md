# Xunara Client — 精简 Rust 客户端

面向 Linux 服务器 / 路由器的最小客户端。无 GUI、Web 管理面、文件传输、SSH 服务或 Go 运行时；只保留加密组网、直接连接、DERP 回退和子网转发。

本仓库同时提供 Android 的 Rust 数据面适配接口；Flutter 界面与 APK 位于独立 [xunara-android](https://github.com/xunara-net/xunara-android) 仓库，不混入 Linux CLI。

Android 适配层支持显式启用 VPN MagicDNS 和选择出口：DNS UDP/TCP 本地端点、设备 A/AAAA/PTR、IP 解析器与分流、出口 peerapi DNS-over-WireGuard。所选出口撤销后保留 VPN 内的阻断，LAN 优先；默认均关闭。详见 Android 仓库的 `docs/dns-exit-accounts.md`。这些选项不开放给 Linux CLI，不更改 Linux 宿主 DNS 或默认路由。

Android 0.4 增加自定义 DoH / DoT 与本机 DNSSEC：域名解析器使用明确的引导 IP，校验 CA 与主机名，不使用系统解析器递归解析自己。DNSSEC 使用 Hickory 的本地签名链验证，不照抄上游 AD。加密上游失败不降级明文；出口模式仍只使用所选出口的加密隧道 DNS。

Android 适配层另提供免 Root 的子网 / 出口转发：只有用户请求、控制面批准与 ACL 同时允许才接收远端流量，TCP / UDP 使用有界用户态栈和受保护 socket，ICMP Echo 核对真实回包。出口 DNS 使用 WireGuard 内的官方 peerapi 服务；不在物理网卡开放代理端口。配置与验收说明见 Android 仓库的 `docs/phone-forwarding.md`。

TCP 转发只有在真实物理连接成功后才完成隧道内握手，失败时拒绝连接；不会提前发送 SYN-ACK。这样出口没有可用 IPv6 时，支持双栈回退的应用仍能尝试经同一出口访问 IPv4，不会把连接失败拖到 TLS 阶段；这不等于出口失效后允许手机直连。

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
- 按官方 SelfNodeV4/V6MasqAddrForThisPeer 处理共享地址转换：按已认证 peer 的别名转换本机地址，并更新 IPv4 / TCP / UDP / ICMPv6 校验和，不改 Machine / Node 身份。

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

本仓库内的 GUI、Windows / macOS、Linux 系统 MagicDNS / 默认出口、完整 Tailnet Lock、服务发布、SSH、文件传输、UDP Peer Relay、自动升级、内核 WireGuard 后端。Linux 广播子网默认路由 `/0` 仍明确拒绝。无法理解的网络协议 / 规则不会被解释成放行。启用 Tailnet Lock 的映射明确拒绝，不把未实现的本机信任根验证伪装为已支持。跨租户共享已通过真实 Rust 路由器与 Android 的双栈别名、重叠原地址、ACL / 子网隔离、接受 / 撤销及其他用户 / 租户拒绝验收，具体环境边界见 Android 仓库的 `docs/verification.md`。

## Android 平台接口

Android 通过 `mobile::Host` 注入系统授权后的 TUN、套接字保护、当前 LAN 与状态回调。`network_android` 不执行 `ip` / `nft`，不调用 `/dev/net/tun`，不引入 Android JNI 或 Flutter 依赖；宿主代码在独立应用仓库维护。

移动端默认只访问私网，用户可明确选择广播子网或提供出口；提供本机出口与使用其他出口互斥。所有 TCP / UDP / ICMP 外层 socket 在使用前调用 `VpnService.protect`；TUN 只在收到授权映射后创建，地址使用 host prefix，冲突 LAN 优先，默认出口和 DNS 保持不变。界面状态不包含机器私钥或预授权密钥；详细节点状态仅经内存回调，不扩张 CLI 的磁盘状态文件。

转发流绑定已认证 peer 与五元组，不共享机器或账号会话；ACL、机器来源、批准路由或共享别名改变时销毁旧流。`receive_stats` 只记录聚合收包 / 拒绝计数，不记录地址、报文、密钥或业务内容；计数属于当前内核实例，不是长期审计。

具体 Android 版本、APK 签名、模拟器与真机验收边界以应用仓库记录为准，不能将 Linux 发布二进制当成 Android 可执行文件。

宿主可通过有界诊断通道请求指定可见设备的 ICMP Echo。探测使用真实 WireGuard / DERP 数据面，遵循已安装路由、对端身份、来源与 ACL 校验；仅匹配本次随机 nonce 的回包，返回实际路径与往返时间。未知节点、LAN 冲突、映射过期、超时与断开均返回失败，不使用管理连接或 Disco 成功冒充业务连通。诊断不需要 root，不启动外部 `ping` 命令。

移动状态同时包含设备系统、密钥到期时间、已批准子网、中继名称、控制面 MagicDNS 元信息和本机 DNS / DNSSEC 是否已启用。DNS 缺失 / null 沿用，空对象显式清空；只保存用户开关不等于已生效，实际状态须由运行中的 DNS 数据面给出。

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

双安卓公网出口专项由相邻 `xunara-android/scripts/test-android-exit-pair.sh` 编排。fixture 的 `XUNARA_TEST_ANDROID_PAIR=true` 仅用于该隔离测试：使用默认放行策略和 `114.114.114.114` / `1.1.1.1`，由两台安卓之间的真实 WireGuard / DERP 转发验证公网 IP 与 DNS，而不是返回测试域名的固定答案。此模式启动监听前检查 rootless 用户映射和仅有回环网卡的独立网络，拒绝在宿主启动无认证测试入口；生产客户端不读取该开关。

该专项另需 `(cd tests/compat && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o ../../target/compat-web-probe .)`。测试 helper 的 `web-probe` 模式由 x86_64 模拟器的 shell UID 临时执行，经过 VPN DNS 解析及出口下载真实 HTTPS 页面，并按系统 CA 校验证书链和主机名；它不是生产客户端或 Go sidecar，不进入 APK。

`target/compat-fixture -mode live-probe -dir <私有目录>` 可用于获授权的现网出口专项诊断。目录权限必须为 0700，`auth-key` 必须为 0600 普通文件，使用单独签发的短期、单次、临时设备密钥；不得借用手机私钥、人类会话或平台管理员令牌。目录内 `live.json` 包含 `server`（HTTPS 根地址）、`hostname`（本轮唯一诊断设备名）、`exit_id`（指定出口 stable ID）、`expected_ipv4_prefix`（预期租户网段）。工具验证租户地址和出口批准状态，只改变临时设备自己的偏好，不改宿主路由；分别记录两族隧道、出口 DNS、默认 HTTPS 与强制 IPv4 / IPv6 结果。诊断完成不表示检查全部成功，需逐项阅读结果；结束删除本轮临时节点、密钥及私有身份目录，不公开原始凭据。

静态双架构发布构建：`sh scripts/build-release.sh v0.1.0 /tmp/xunara-client-release`。详见 [架构与边界](docs/architecture.md) 和 [安全说明](SECURITY.md)。
