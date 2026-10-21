# Android MagicDNS 与出口解析修复

## 现网出口建连预算与 NAT 候选回程

### What changed

- 选定出口的 DNS-over-WireGuard 从 TCP SYN 开始使用每个上游尝试十秒的预算，不在握手后重新计时；移除握手阶段单独四秒提前失败的旧分支。
- DNS 快照区分建连超时、响应超时、提前关闭及无效响应，只增加固定整数计数，不记录查询名、地址、HTTP 内容或密钥。
- 经过既有 WireGuard 认证或合法 Disco Ping 验证的实际 UDP 来源可成为短期 NAT 候选，优先参加新的往返探测。最多保存八个候选、有效期两分钟；完整目标清单仍不超过十六项。

### Why

专用 Android 36 模拟器实际接入现网 NX769J 后，0.5.8 仍出现 `odata.cc` 系统解析失败及 SERVFAIL；同一模拟器切换官方 Android 1.98.8、选择同一出口后，系统解析和 DNS UDP / TCP 可用。新增脱敏统计确认多次失败发生于 SYN 阶段，而不是无效 DNS 响应或身份审批。

单独延长预算后的现网连续查询仍有一次超时，不能据此宣布完成。继续对照上游发现，旧实现只回 Pong，却没有把实际认证来包来源加入后续探测；NAT 实际映射不一定等于控制面或 STUN 公告的地址。新增候选后仍必须取得匹配当前目标及一次性事务的 Pong，不能把收到来包直接当成双向直连。

### Compatibility impact

对照固定版本官方 [DNS 查询预算](https://github.com/tailscale/tailscale/blob/v1.98.8/net/dns/resolver/tsdns.go)及[认证 Ping 候选学习](https://github.com/tailscale/tailscale/blob/v1.98.8/wgengine/magicsock/magicsock.go)。不修改 TS2021、Noise、MapResponse、WireGuard、Disco、STUN、DNSConfig 或 DERP wire。普通解析器预算、出口选择和 LAN 避让不变；不可达的不同地址族可能依次尝试，不宣称整个多地址查询只有十秒。

### Security impact

未知、过期、错误事务或源地址不匹配的 Pong 仍不能建立或延长直连。候选不跨节点密钥或租户复用，不接受回环、多播、未指定地址或零端口；候选学习不授予 ACL、机器或人类身份权限。出口不可用仍失败关闭，不切换到手机物理 DNS 或其他出口。

### Tests

- 两项回归分别在旧握手预算和旧候选学习行为上失败；修复后通过。另覆盖候选容量、优先级、过期、无效地址及仍须 Pong 认证的边界。
- Rust fmt / clippy / 全目标测试；显式运行官方 STUN / 共享地址向量；Go 夹具 build / vet / test / race；真实隔离 TUN、官方 tsnet、ACL、子网、单向 UDP、DERP 回退与恢复通过。
- 现网混合测试首轮完成独立使用端 64 次 `odata.cc` UDP DNS 查询，64 次有效答复；此时所选 NX769J 路径仍报告中继，不将候选学习单测冒充该手机已建立 UDP 直连。
- 浏览器与最终 APK 的后续验收记录在 Android 仓库；物理使用端尚未安装本轮内核，不能宣称原手机问题全部消失。

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

## DNS 页面配置元数据

移动端内存快照单独提供 `dns.resolvers` 和 `dns.routes`，来源仅为已验证网络映射中的全局解析器及分流配置；空的分流上游仍表示本地权威域。页面参考[固定版本官方 Android DNS 设置](https://github.com/tailscale/tailscale-android/blob/1.98.8-t1241b225b-gbcbaf1889/android/src/main/java/com/tailscale/ipn/ui/view/DNSSettingsView.kt)，不把 `dns.address` 的内部 VPN 监听地址展示成上游服务器。

这是本地展示字段，不修改控制面 DNSConfig、解析计划、系统路由或机器身份。内部监听地址保留给系统配置与验收探针，新增上游配置不写入 CLI 持久化状态。单测覆盖解析器、分流的空上游以及 null 保留 / 空对象清空的映射增量语义；元数据测试通过不能作为用户手机 DNS 已修复的证明。

## 出口 DNS 连接清理

### What changed

隧道内 DNS 上游完成或失败时，先由 smoltcp 显式终止 TCP；待终止帧实际入队后，才移除 socket。输出回压期间保留待发送终止帧，并有界暂停新连接，不消耗尚未尝试的解析器。

### Why

原来的 `SocketSet::remove` 仅释放本地对象，不发送 FIN / RST。出口保留已完成查询的 TCP 状态，占满每设备 32 条连接后，后续 DNS 甚至正常出口连接都会等待超时。此前低次数 DNS / HTTPS 测试没有覆盖这种积累。

使用真实 TCP 报文连接本内核的 DNSProxy 与 Forwarder，旧代码在第 33 次查询停滞，出口恰好保留 32 条流；新代码连续完成 48 次并回收连接。真实用户域名也已复现使用端 SERVFAIL、出口系统解析和 HTTPS 成功的差异，但仍需更新物理使用端后复测，不能将单测当成真机结论。

### Compatibility impact

对照[官方 DNS HTTP 客户端](https://github.com/tailscale/tailscale/blob/v1.98.8/net/dns/resolver/forwarder.go)的响应 / 连接关闭，以及固定依赖 smoltcp 0.14.0 的 `abort` / `dispatch` 语义，实现标准 TCP 清理。不改 TS2021、DNSConfig、WireGuard、DNSSEC、ACL 或系统路由，也不提高出口连接配额。终止报文仍走原出口的 WireGuard 与现有来源 / ACL 检查。

### Security impact

选定出口失败仍关闭，不因失败回退手机物理 DNS 或其他设备。保留连接配额与内存边界；已消费完整响应后不保留可继续代理任意业务的旧连接。测试探针仅用于外部 Android shell UID，不进入 APK，不引入 Go sidecar。

### Tests

回归覆盖超过出口单设备限额的连续查询、输出队列满时不丢终止帧、有界回压时不消耗备用解析器。Go 隔离夹具增加固定解析器的连续 64 次 A / AAAA 查询探针；它不使用应用缓存或系统备用解析器，并限制单次及总体期限。实际 TUN / 官方兼容与 Android 验收另记录，不能用本地报文测试替代。
