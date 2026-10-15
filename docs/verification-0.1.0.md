# v0.1.0 验收记录

日期：2026-10-15。Xunara Server 固定 `dd158e973358a01f15c5e6e79c0a38d35afb3989`，官方 Go 协议 / tsnet 参考 `tailscale.com v1.104.1`。

## 已通过

- `cargo clippy --locked --all-targets -- -D warnings`；11 项 Rust 单测。
- 独立 STUN 跨实现契约：Rust 产生请求，由官方 Go 解析器验证；损坏指纹拒绝。
- 真实 Linux TUN：两台 Rust 节点通过 TS2021 注册，加密 TCP 与 ICMP 可达，未允许 TCP 端口不可达。
- 独立 LAN namespace：只广播不自批路由，通过管理 API 批准后可访问 LAN 服务。
- nftables SNAT：LAN 没有组网回程路由时仍可访问；正常停止清除自身 NAT 表。
- 持久身份重启：不提供原预授权密钥仍完成机器重新注册；已有同名 nftables 表时明确拒绝，并保留原有表 / 标记链。
- 官方 Go tsnet ↔ Rust 双向 TCP；屏蔽 UDP 后仍经精确证书 pin DERP 传输，解除屏蔽后恢复。
- 同一网络脚本在本机隔离 user/net namespace 及 Ubuntu 24.04 Docker 隔离网络中通过；Go fixture 使用 `-race` 构建后再次通过。
- systemd 单元在临时 mount namespace 中提供真实可执行文件后通过 `systemd-analyze verify`；没有写入宿主机 `/usr/local/bin`。
- Linux AMD64 / ARM64 静态 musl 编译；AMD64 直接执行、ARM64 通过 QEMU 执行 `--version`。

## 不在验收结论内

- 没有完成全客户端第三方审计，不宣称生产级完整替代。
- ARM64 尚未在物理设备执行真实 TUN / LAN 场景。
- 没有承诺 MagicDNS、系统 DNS、Exit Node、Tailnet Lock、跨租户共享、IPv6 扩展头 / 分片、GUI 或移动端。
- 没有把 STUN 当作 UDP 业务中继；公网 UDP 映射须独立验证。
- 没有在生产机器安装 Rust 组网客户端或更改已有设备、账号和默认路由；正式中继升级另记在 xunara-deploy。

重跑入口：`scripts/test-netns.sh`，以及启用 `XUNARA_TEST_SNAT=true` 的 SNAT 分支。fixture 只包含隔离测试接口，不随 Rust 二进制发布。
