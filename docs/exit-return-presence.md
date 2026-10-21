# 出口回包、DNS 等待预算与设备在线状态

## What changed

- 保留 Node.Online / LastSeen，并按官方语义处理 PeerSeenChange、OnlineChange 和 PeersChangedPatch；缺失表示沿用，未知不是离线，删除的节点不能被状态增量复活。
- 向移动端传递三态在线报告、最近在线及所选出口在线报告。控制映射失效时不沿用旧的在线结论；在线变化不撤销机器身份、重置连接许可或自动更换出口。
- ICMPv4 不可达 / 超时 / 参数问题、ICMPv6 错误仅在引用尚有效的本机出站连接时放行。允许标准的截短引用，但普通数据包仍必须完整；不放行重定向、未知连接、过期连接、错误地址族或分片引用。
- 已连接的出口 peerapi DNS 参照官方 DNS 的十秒预算；尚未完成 TCP 建连仍保留四秒快速失败。增加真实 DNS 消息、生成响应、SERVFAIL、NXDOMAIN 和上游超时统计，不导出域名或报文。
- 增加绑定 DERP 连接代次的反向路由：只从已通过 WireGuard 校验的当前 peer 学习。已知 home 已连接时仍优先使用原 home；未知或尚未连接时可沿同一 peer 实际来包的活跃中继回包。连接重建、PeerGone 和节点移除使旧提示失效，不修改控制面的 HomeDERP。

## Why

1. 旧模型丢弃 Online / LastSeen，增量合并也忽略 OnlineChange / PeerSeenChange。新增回归在旧实现上仍保留 Online=true，实际失败；修复后可正确同步真假和清空最近在线。
2. 普通 TCP / UDP 回包可用五元组反向匹配，ICMP 错误却引用原连接而不是复用其五元组。旧内核因此把有效网络控制报文当成无许可的新连接。在真实隔离 TUN / 独立 LAN 下，允许的 UDP 请求访问关闭端口，旧二进制只能超时；新实现让原 UDP socket 收到内核的 ECONNREFUSED，不需要给 LAN 开放任意 ICMP。
3. 官方出口 peerapi 自身允许五秒解析，官方 DNS 查询资源预算为十秒。回归以真实用户态 TCP 完成握手并交付 HTTP 请求，再把已等待时长设为 4.5 秒；旧实现提前失败，新实现能交付合法答复。这是可控时钟预算回归，不是物理链路延迟实测。
4. 扩展共享回归还实测到另一个回程问题：请求已通过来源和 ACL，Linux 内核也生成了 Echo Reply，但共享 peer 的 home 仍为 0，旧发送逻辑直接丢掉回复。只修正夹具 ACL 或等待本机中继握手都不能解决。官方 magicsock 会从活跃 DERP 连接学习同一 peer 的反向路由；本实现补齐该逻辑，并更严格地要求 WireGuard 已认证。

这些是可复现的客户端差异，但不能仅据此认定它们解释了特定物理手机的全部断网。
同样，旧 receive_stats.dns_queries 实际数的是发往 VPN DNS 的 IP 包，包括 TCP 控制包，不能将其当作成功查询次数。新消息统计来自 DNS 代理；生成响应不代表系统或应用已收到，代理重建后该组统计重新开始。

## Compatibility impact

不新增或修改 TS2021、Noise、WireGuard、MapResponse、DNS 或 DERP wire 字段。
Online 是协调服务器连接报告，不是业务健康或授权；仍保持来源验证、明确选择出口、LAN 优先及失败关闭。
Android 需固定新的 Git 内核并重新构建 JNI，单独改 Flutter 页面不会修复数据面。
本次不替换已发布的 Linux v0.1.0 资产，静态构建仅作为本轮验证与后续发布输入。

## Security impact

ICMP 仍先经过固定 peer / WireGuard 身份、来源网段、其他设备地址冲突与本机目的地校验，随后核对引用的本机连接和有效期。没有照搬上游直接接受所有 ICMP 错误的宽松规则，也不因 DNS 慢而回退物理网络或其他出口。并发与缓存容量限制仍保留。
在线与统计只增加有界元数据，不加入人类会话、机器私钥、Auth Key、查询名称或 payload。

## Tests

- Rust fmt / clippy / 全目标测试；新增在线增量、连接策略不随在线变化清空、IPv4 / IPv6 ICMP 关联与拒绝、DNS 延迟答复和消息统计回归。
- 真实 namespace 的 TUN、官方 tsnet 双向互通、批准子网、拒绝 ACL、相关 ICMP、单向 UDP、证书 pin 中继与恢复；普通、SNAT 和坏首个 DERP 场景。
- Go fixture build / vet / test / race；上游 STUN / 校验和兼容向量另行显式执行，不将默认 ignored 的测试记为已执行。
- Android 两 ABI、最终 APK 与混合客户端的执行结果记录在 Android 仓库，未执行前不据此宣称真机恢复。

后续 Android 扩展回归先发现夹具策略遗漏：为验证相关 ICMP 而收窄来源时，只保留了本地设备池，漏掉共享 IPv4 别名池。新增回归先在原策略上失败，再显式纳入服务端定义的 ShareMasqIPv4Prefix；独立 LAN / 公网来源仍被拒绝，真实 namespace 相关 ICMP 回归通过。此项只改夹具，不修改生产 ACL；修正后仍失败的共享回程另由上述反向路由缺失解释，不能把局部夹具修复冒充整个扩展回归通过。

## 固定上游参考

- [Node.Online / LastSeen 与 MapResponse 状态增量](https://github.com/tailscale/tailscale/blob/v1.98.8/tailcfg/tailcfg.go)
- [官方 MapResponse 合并顺序](https://github.com/tailscale/tailscale/blob/v1.98.8/control/controlclient/map.go)
- [官方 ICMP 入站处理](https://github.com/tailscale/tailscale/blob/v1.98.8/wgengine/filter/filter.go)
- [peerapi 五秒解析预算](https://github.com/tailscale/tailscale/blob/v1.98.8/ipn/ipnlocal/peerapi.go)
- [DNS 查询十秒预算](https://github.com/tailscale/tailscale/blob/v1.98.8/net/dns/resolver/tsdns.go)
- [官方 DERP 反向路由、连接绑定和 PeerGone 处理](https://github.com/tailscale/tailscale/blob/v1.98.8/wgengine/magicsock/derp.go)
