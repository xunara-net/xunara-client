# 出口故障源码对照与中继回程修复（2026-10-20）

## What changed

修复 Rust 内核把 DERPMap 最小编号直接上报为 PreferredDERP 的问题。现在由数据面确认 TLS、DERP 身份握手和随机 Ping / 匹配 Pong，再把实际可用 home 经 LocalState 通知控制连接。普通端点刷新不能覆盖已确认的 home，只有当前 home 发送 NotePreferred=true。

没有可用 home 时最多并行四个额外候选，15 秒后轮换；连接总数仍限制为 32。已有可用 home 保持稳定，掉线、心跳不匹配、区域删除或节点定义变化后重新选择。STUN-only 不建立 DERP 业务连接，NoMeasureNoHome / Avoid 不作为本机候选，但仍允许连接已知 peer 所在区域。这里是可达性选择，不宣称实现了官方完整的地理测量、延迟历史或 HomeParams 评分算法。

## Why

按以下链路对照了 Xunara、官方 Go 核心及 Android 源码，而不是仅检查管理 API：

| 阶段 | Xunara 路径 | 官方参考 / 确认的边界 |
| --- | --- | --- |
| 机器认证、增量映射 | control、model；服务端 recordMapRequest / mapper | TS2021、Noise、MapRequest / MapResponse；人类会话不代替机器认证 |
| 出口批准 | forwarding::Plan、Node::exit_node；服务端 EffectiveRoutes | tsaddr.ContainsExitRoutes 要求 IPv4 / IPv6 两个默认路由同时有效 |
| 出口选择、路由 | Engine::outgoing、mobile::VpnConfiguration、network_android | 只使用明确选定的 StableID；失效不直连，LAN 优先 |
| DNS | dns、dns_stack、dns_tls、dns_validate | peerapi.handleDNSQuery 的 WireGuard 内 HTTP 服务；官方显式设置 Content-Length，不是分块响应不兼容 |
| 转发 | Forwarder、packet_stack、masquerade、filter | netstack 的实际连接完成后才完成 TCP 握手；回包需机器来源、地址、ACL / 状态校验 |
| 直连 | discovery、Engine::disco / transmit / receive | magicsock endpoint 的双向 Disco 确认；只收到 WireGuard 不延长回程信任 |
| 中继回程 | Hub、control::session、Engine::update_relays | magicsock 的 home 连接、NotePreferred、netcheck 的可用性测量和 DERP Ping / Pong |
| Android 系统层 | VpnService、UnderlayMonitor、JNI、AppController | 官方 IPNService / App 的 TUN、protect、底层网络；此次不重新合入未经完整验证的显式网卡绑定候选 |

本次未获得官方商业控制面的服务端源码；使用的是公开协议、官方客户端 / DERP 服务端实现和本地独立控制面测试，不声称阅读了完整官方商业服务端，也不把 Headscale 当作官方控制面。

### 可复现故障

隔离网络下增加编号 1 的不可达 DERP，同时保留已验证证书的官方 Go DERP 900。旧内核仍把两台 Rust 节点的 home 上报为 1：UDP 可用时 TCP / ICMP 正常；阻断一侧出站 UDP 后，中继恢复测试失败。日志显示 DERP 1 不断重连，即使 DERP 900 实际可连接，也没有正确发布回程。

修复后，同一测试自动把两台设备的 home 上报为 900；证书 pin、真实 TUN、官方 Go tsnet 双向互通、子网、ACL 拒绝及 UDP 阻断 / 恢复全部通过。这个差异可以解释“控制在线、已批准，却没有业务回包”的一种实际原因；不能仅凭它认定用户两台物理手机的全部问题均已解决。

## Compatibility impact

- 不修改服务端、数据库、审批、套餐、ACL、TS2021、Noise、WireGuard、DNS 或 DERP wire 格式。
- 使用官方已有 PreferredDERP、NotePreferred、Ping / Pong；控制连接不再猜测本机 home。
- LocalState 是 Rust 与调用方之间的内部接口，Android 需要同步更新固定 Git 内核及重建 JNI；只更新 Flutter 页面不会带入修复。
- 中继切换仍指向原 peer / 所选出口，不切换用户选定的出口设备，也不回退公网直连。

## Security impact

- CA / 精确证书 pin、DERP 身份解密、WireGuard、来源检查和 ACL 均保留。
- Pong 必须匹配随机事务、15 秒窗口并单次消耗；无效或重放回应不能证明连接健康。连接失败立即撤销本地健康确认。
- 限制候选数、连接数、每连接队列和帧长；停止时中止候选、连接与读取任务，不引入后台永久探测进程。
- 状态只增加 home 区域编号和连接确认，不输出密钥、账号会话或报文内容。
- 生产检查仅只读查看 demo 的设备和版本；本轮检查时四台原设备均离线。临时人类会话已经单独撤销，没有修改原手机的身份、批准、DNS 或 ACL。

## Tests

- Rust fmt / clippy / 全目标单测；新增心跳防重放、只选确认连接、稳定 home、故障重选、定义变化、NoMeasureNoHome / STUN-only 和有界轮换。
- Go 兼容 fixture build / vet / test / race；官方 STUN 编码与共享地址校验和跨实现测试。
- `XUNARA_TEST_UNREACHABLE_DERP=true sh scripts/test-netns.sh`：修复前失败、修复后完整通过；CI 加入同项。
- 普通及 SNAT 专项同样使用真实隔离 TUN / LAN、官方 tsnet 和证书 pin 中继，不用 JSON 模拟代替业务流量。
- Android 固定内核、最终 APK 与 VPN / 出口实测结果另见应用仓库验证记录；物理 NX769J / Xiaomi 现场仍需在线复测。

## 上游入口

- [官方 home DERP 与 NotePreferred](https://github.com/tailscale/tailscale/blob/v1.104.1/wgengine/magicsock/derp.go)
- [官方可达性测量](https://github.com/tailscale/tailscale/blob/v1.104.1/net/netcheck/netcheck.go)
- [DERP Ping / Pong 帧](https://github.com/tailscale/tailscale/blob/v1.104.1/derp/derp.go)
- [出口 peerapi DNS](https://github.com/tailscale/tailscale/blob/v1.104.1/ipn/ipnlocal/peerapi.go)
