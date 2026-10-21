# Android MagicDNS 与出口解析修复

## What changed

- 保留现有本机 MagicDNS、设备正向 / 反向记录、搜索域和权威 NXDOMAIN；不把 Go 客户端或第二套协议内核塞进 Rust 最小客户端。
- 出口 peerapi 查询在没有显式自定义解析器 / DNSSEC 时，使用手机物理网络提供的 DNS，而不是把控制面公共 DNS 误当作 Android 系统解析器。普通手机应用仍遵循网络 DNS 配置。
- 直接可达的同组上游最多三个，间隔 150 毫秒启动有界竞争。SERVFAIL / REFUSED 等待其他配置内解析器；有效 NXDOMAIN 直接返回。赢家完成后取消其余请求。
- Android 系统 DNS 地址与内部代理采用相同的物理 DNS 退避输入，避免系统仍向旧地址查询。
- 出口查询 / 响应 / SERVFAIL 单独计数，不与本机 VPN DNS 消息混算，不导出查询域名或报文。

## Why

对照官方 Android 1.98.8 的 [VPN DNS 配置](https://github.com/tailscale/tailscale-android/blob/1.98.8-t1241b225b-gbcbaf1889/libtailscale/net.go)、[出口宿主解析](https://github.com/tailscale/tailscale/blob/v1.98.8/net/dns/resolver/tsdns.go)及[上游竞争和软错误处理](https://github.com/tailscale/tailscale/blob/v1.98.8/net/dns/resolver/forwarder.go)，旧版顺序等待首个解析器，且出口 peerapi 复用平台公共 DNS；手机 IP 能联网不等于这些公共 DNS 可达。

两个独立回归先在旧代码失败：首个 DNS 黑洞时备用 DNS 未被及时请求；平台 DNS 黑洞时出口没有使用已知可用的手机 DNS。修复后分别约 160 毫秒、10 毫秒完成受校验答复。时间来自本机真实 UDP 测试，不是运营商网络实测，也不能单独证明用户手机故障全部消失。

## Compatibility impact

不改服务端、数据库、机器身份、审批、ACL、TS2021、Noise、WireGuard、DNSConfig 或 DERP wire。Linux 仍不接管系统 DNS / 默认路由。
这是对官方行为的 Rust 适配，不宣称复制了官方全部系统解析器实现：Android 严格私人 DNS、应用自带 DoH 和系统缓存仍受 Android / 应用自身控制。

## Security impact

消费者选定出口后仍只查询该出口，不竞争手机原网络或其他出口；出口被撤销后仍失败关闭。
物理 DNS 竞争只在既有计划允许直连的目标之间进行，不额外添加公共解析器、不跨分流规则；解析器地址、随机事务 ID 和原始问题仍校验。
MagicDNS 和权威 NXDOMAIN 在本地终止。用户显式配置的 DoH / DoT / DNSSEC 不被宿主默认 DNS 绕过，TLS 证书与主机名验证保持不变。

## Tests

- 两项 DNS 黑洞回归完成红绿对照；另覆盖 SERVFAIL / REFUSED、NXDOMAIN、取消输家、物理 DNS 与显式安全配置隔离、固定出口失败关闭和系统 / 代理地址一致。
- Rust fmt、clippy、64 项普通单测、两项显式执行的官方 STUN / 共享地址兼容向量通过。
- Go 隔离夹具 build、vet、test、race 通过；不可达 DNS 开关只影响已隔离的双安卓场景，不改变普通网络夹具。
- 实际 Android VPN 与发布包验收记录由 Android 仓库保存；本记录不将本机单测冒充真机验收。
- 最终 `607d7bc` 内核在 Android 36 x86_64 的实际 Release 上完成双玄序出口 / 官方 Android 消费端的公网 DNS 和验证证书的 HTTPS；旧版 IP 成功而 DNS 超时的对照、完整隔离回归及加密 DNS 扩展未通过的边界见 [Android 记录](https://github.com/xunara-net/xunara-android/blob/main/docs/magicdns-fix.md)。
