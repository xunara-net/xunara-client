# 最小客户端设计

## What changed

独立 `xunara-net/xunara-client` Rust 仓库，单进程、单线程 Tokio 事件循环：

```text
Config / 私有身份文件
        ↓
官方 Noise 组件 → HTTP/2 控制客户端 → 完整/增量 NetworkMap
        ↓                                    ↓
Linux TUN ← ACL + Cryptokey routing ← BoringTun WireGuard
                                             ↓
                                 UDP / Disco / STUN / DERP v2
```

`control`、`model`、`filter`、`network`、`engine`、`derp`、`discovery` 各有明确边界。不链接既有 Go Agent 或完整的 tsnet 用户态 TCP 栈，不把平台 UI、账号 Session、计费或文件服务引入数据面。

Android 使用同一 `engine` / `control` / ACL / WireGuard / DERP，只有 `network_android` 替换 Linux 的网卡与路由操作。`mobile::Host` 是向外的平台接口，不依赖 Kotlin / Flutter；应用持有 VpnService，逐个保护外层 socket，移交 TUN fd 的唯一所有权。未取得有效映射时 TUN 读取保持挂起，不用空 VPN 冒充已接入。平台路由计划的单测覆盖 host prefix、跳过 LAN 冲突、拒绝默认路由和拒绝 Android 转发模式。

参考 [Android VPN 官方文档](https://developer.android.com/develop/connectivity/vpn) 和 [Tailscale Android 套接字保护实现](https://github.com/tailscale/tailscale/blob/v1.104.1/net/netns/netns_android.go)。协议 wire 没有 Android 专有分支；只按运行平台报告既有 Hostinfo.OS。

`diagnostic` 的 ICMPv4 / ICMPv6 Echo 遵循 [RFC 792](https://www.rfc-editor.org/rfc/rfc792) / [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443)。最多四条未完成请求、500ms 发起间隔、8 秒超时。应用只能传可见 peer ID，不能任意构造报文或指定外部目的地址。回包必须先经过通常的 WireGuard / peer 来源 / ACL 检查，再匹配 peer、两端地址、随机 identifier / sequence / payload、校验和；使用完成后即删除，防止重放。路径取实际收到回包的 UDP / DERP，不根据配置猜测。

DNS 元信息按官方 [tailcfg.DNSConfig](https://github.com/tailscale/tailscale/blob/v1.104.1/tailcfg/tailcfg.go) 增量语义读取，不安装解析器、不添加 DNS 路由；详细设备与 DNS 列表仅留在移动回调内存中，CLI 磁盘状态不随之膨胀。

## Why

最小体积目标优先 Linux CLI 和内核 IP 转发，而非复制完整客户端产品。只复用官方 Rust 上游的底层 Noise / key 组件；官方高层库仍未提供当前所需的完整子网路由与私有 DERP 产品能力，因此不直接把该库包装成“已经完成”的客户端。

WireGuard 使用 Cloudflare BoringTun 的固定发布版本。路由、ACL、DERP 帧和 Disco 编码按当前 Tailscale Go 上游核对，再以真实 Go 客户端和 Xunara 服务端做跨实现测试。协议参考：

- [官方 Rust Noise](https://github.com/tailscale/tailscale-rs/tree/v0.6.1)
- [Tailscale DERP](https://github.com/tailscale/tailscale/blob/v1.104.1/derp/derp.go)
- [Tailscale Disco](https://github.com/tailscale/tailscale/blob/v1.104.1/disco/disco.go)
- [Tailscale STUN](https://github.com/tailscale/tailscale/blob/v1.104.1/net/stun/stun.go)
- [BoringTun](https://github.com/cloudflare/boringtun)

## Compatibility impact

不更改 Xunara Server、官方客户端、TS2021、Noise 或 DERP 的 wire 类型。这个仓库是现有兼容接口的独立消费者，不是为 WebUI 新增专有协议，也不把旧 `/api/agent/v1` 业务 Agent 等同于组网数据面。首版能力版本 115 与当前 Xunara 最低门槛一致。

网络映射处理完整节点、增删和节点补丁。`PacketFilters` 按官方规则合并命名规则组：`null` 删除、`"*": null` 清空；旧 `PacketFilter` 对应 `base` 组。每个新连接从空映射和默认拒绝开始，不能继承旧连接已撤销的规则。

不宣称兼容所有 Headscale / Tailscale Server 版本。未知的高级能力不自动启用：Tailnet Lock、共享 masquerade、Peer Relay、IPv6 扩展头和分片等须单独实现与测试。

## Security impact

- 控制面根地址必须正式 HTTPS；仅允许回环 HTTP 测试，不接受用户名密码、查询或租户路径。
- Machine key 负责 Noise 机器认证；Node key 负责 WireGuard / DERP；Disco key 只负责路径发现，不能相互代替。
- 仅可信映射中已授权且未过期的节点创建隧道；成功解密后仍检查来源网段、本机 / 已批准目的网段和 ACL。
- 路由广播不等于批准；仅广播与服务端本机 `AllowedIPs` 的交集允许从 TUN 进入本地子网。
- 回包状态有数量与寿命上限，策略变化立即清空。未知 selector、应用 capability 不产生网络放行。
- 控制面静默超过 120 秒停转发；显式撤销 / 过期映射立即停止。
- UDP / DERP 队列、映射大小、帧长度、节点数、候选端点、握手、Disco 探测都有上限。
- 静态 pin 必须精确匹配叶证书 SHA-256，TLS 握手签名仍需验证。
- 不覆盖已有网卡，不替换已有路由，不调整系统 DNS / 默认路由 / 全局转发，不重置主机防火墙。
- NAT 使用排他 `create table`，已有同名表必须报错而不是接管；其行为按 [nftables 官方手册](https://www.netfilter.org/projects/nftables/manpage.html) 核对。

## Tests

`cargo` 单测覆盖配置、密钥文件、锁、状态损坏、映射/ACL增量、ACL默认拒绝与返回状态、分片拒绝、Disco 认证、STUN编码、LAN冲突。`scripts/test-netns.sh` 为真实 TUN / WireGuard / 官方客户端 / 子网 / DERP 的整体验证入口；不将只有模拟 HTTP 的测试当作数据面验收。

## Android 加密 DNS 与共享地址（2026-10-18）

### What changed

`Target::Encrypted` 在既有 DNS 专用 TCP 栈上承载 DoT 或 HTTPS POST；物理网络用受保护 socket，网内解析器仍走 WireGuard / ACL。TLS 状态机由 rustls 校验 CA / 主机名。域名形式需 BootstrapResolution，避免改完 VPN DNS 后递归查询解析器自身。HTTPS 使用 HTTP/1.0 有界消息，不接受重定向或分块响应。

DNSSEC 由 Hickory 0.26.3 的 DnssecDnsHandle 验证根信任锚、DNSKEY / DS / RRSIG 和否定证明。验证子查询通过有界通道回到原 DNS 路由，不能偷开一个绕过出口的验证解析器。向上游索取 CD 原始材料，清除原始 AD；只有本地验证后才设置 AD。资源上限包含 64 个 DNS 请求、外部请求保留内部递归额度、512 项验证缓存、NSEC3 迭代限制和 12 秒整体验证期限。

响应在完成本机验证后按原始查询投影：未设置 DO 时移除未显式请求的 DNSSEC 记录，AD 仅在已验证且客户端设置 DO / AD 时置位；EDNS 不继承验证器追加的算法选项。遵循 [RFC 4035 §3.2.1](https://www.rfc-editor.org/rfc/rfc4035.html#section-3.2.1) 与 [RFC 6840 §5.6–5.8](https://www.rfc-editor.org/rfc/rfc6840.html#section-5.6)，避免普通手机解析器收到不兼容响应。

共享 masquerade 的源转换位于原出站状态跟踪之后；目的还原位于认证 peer 解密之后、原来源和 ACL 验证之前。别名只属于对应 WireGuard peer，不用 IP 查到另一个租户的映射；本机后方的子网地址不套用本机别名。IPv4 UDP 未启用校验时保留零，IPv6 零 UDP 校验拒绝。

### Why

不能只把 HTTPS URL 保存到 UI，实际却继续用明文解析；DNSSEC 也不能靠上游 AD 位置假。跨租户共享不等于合并身份或跳过 ACL，必须按上游的 peer 专属地址转换实现。

### Compatibility impact

保持官方 DNSConfig / Resolver.BootstrapResolution 和 SelfNodeV4/V6MasqAddrForThisPeer wire 字段；无服务端新端点、迁移或客户端协议分叉。Linux 仍不接管系统 DNS / 默认路由。Tailnet Lock 完整参与仍未完成，启用状态明确拒绝，不能宣称已验证签名。

### Security impact

不允许 URL 凭据 / query / fragment，不跳过证书验证，不在加密 DNS 或签名失败时退回明文。原始上游 AD 不可信；MagicDNS 的控制面本地记录不冒充 DNSSEC 签名。第三方应用自带 HTTPS DNS 不能安全透明改写，手机界面只提供准确检测与用户设置入口。

### Tests

Rust 规范与协议测试、临时 CA 的 TLS 正向 / 错域名 / 非可信 CA 测试、伪 AD 拒绝；公共 HTTPS 实测签名链、签名 NXDOMAIN 与 dnssec-failed.org 拒绝。`tests/compat` 用官方 Go checksum 对照双栈 TCP / UDP / ICMP 的地址改写。真实 Linux namespace 的官方 tsnet / TUN / 子网 / ACL / DERP 回退与 SNAT 回归通过。Android 36 x86_64 实测 DoH、DoT、DNSSEC、MagicDNS、切网、应用分流、出口与身份切换通过；不冒充跨租户共享专项或 ARM64 真机验收。

## 2026-10-20：TCP 转发先拨号后接受

### What changed

`Forwarder` 启用固定 smoltcp 0.14.0 的 `socket-tcp-pause-synack`，普通转发在处理首个 SYN 前暂停 SYN-ACK，物理 socket 连接成功才恢复；失败走原来的 abort / RST。客户端取消握手后已回到 Listen 的流及时释放。本机 peerapi DNS 没有物理 TCP 后端，不延迟其握手。

### Why

现网专项发现同一手机出口的 DNS 和 IPv4 HTTPS 可用，IPv6 HTTPS 却在握手后重置。旧实现先回复 SYN-ACK，再异步建立物理连接；双栈应用误判 IPv6 已连通，停止 IPv4 竞争，最终在 TLS 读写时报错。官方 Tailscale v1.104.1 的 `wgengine/netstack.forwardTCP` 同样先拨物理后端，成功后才调用 `getClient` 接受客户端，失败发送 RST。

### Compatibility impact

只纠正 Android 用户态 TCP 转发的连接语义，不改 TS2021、Noise、WireGuard、DERP、DNSConfig、批准路由或服务端。保持真实双栈支持，不全局禁用 IPv6，不篡改 DNS AAAA 答案；由支持 Happy Eyeballs 的应用选择可用地址。

### Security impact

所有外层 socket 继续先 protect，流仍绑定认证 peer、五元组和既有 ACL。IPv4 回退仍经过用户指定出口，不是出口不可用时绕过 VPN。物理拨号有超时，握手取消与失败不留下可用的假连接；诊断只使用独立的临时机器身份。

### Tests

双栈回归在修复前明确捕获提前 SYN-ACK，修复后验证物理连接失败从未进入 Established 且流被释放；原真实双栈 TCP / 半关闭回归保持通过。`tests/compat` 增加不可达 IPv6 与可用 IPv4 的同域名 fixture，由官方 tsnet 验证手机出口拒绝失败的 IPv6 拨号，并自动回退同一出口的 IPv4；Android 专项执行情况以应用仓库验收记录为准。
