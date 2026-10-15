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
