# Rust 最小客户端开发规则

- 本仓库只负责组网数据面与必要的控制客户端；禁止重新混入 GUI、账号中心、计费、文件传输或 Go sidecar。
- 保持官方 TS2021 / Noise / WireGuard / Disco / STUN / DERP 兼容。先查 symbol、调用链、上游与测试，再改协议；不能为了体积省掉认证、ACL 或来源校验。
- Machine / Node / Disco 私钥与人类账号 Session 分离。秘密只能从受保护文件读取，禁止 URL、argv、日志或 Git 泄露。
- 路由只 add 本程序自己的项；不覆盖已有网卡，不修改默认路由、系统 DNS 或全局转发开关。冲突优先保留 LAN。
- 使用中文注释说明安全边界和必要的 unsafe；不用注释重复代码字面含义。
- 私有状态必须原子写入、0600 / 0700、持久化且有实例锁；损坏时拒绝覆盖身份。
- Rust 修改运行 `cargo fmt --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --all-targets`。
- 组网、ACL、路由、DERP 修改还必须运行 `scripts/test-netns.sh`，不得用模拟 JSON 测试替代真实 TUN / 官方客户端 / 子网验收。
- 发布前构建静态 musl，核对架构、SHA256SUMS、源提交和已验证的功能边界。不能宣称已支持未实现的协议或操作系统。
- Git 使用中文标题，提交说明包含 What changed / Why / Compatibility impact / Security impact / Tests。
