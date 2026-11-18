# Oryn 依赖修补

来源：smoltcp-rs/smoltcp，0.11.0（crates.io），commit ce420118efff83b47767389500ef1562f5074b55，0BSD。保留 LICENSE-0BSD.txt。

用途：WireGuard / Tailscale 出站内部 Netstack 的动态 TCP 缓冲（Oryn_dev/docs/oryncore/plans/plan-wg-dynamic-tcp-buffer.md）。

- src/socket/tcp.rs：
  - 新字段 `rx_capacity_max` 与 `set_rx_capacity_max`：窗口缩放按上限计算（`new` 与 `reset` 都使用它），使接收缓冲可在握手后扩大；
  - `replace_rx_buffer` / `replace_tx_buffer`：换缓冲并按序保留已缓冲数据；有乱序数据暂存、新容量放不下已有数据或超过缩放上限时拒绝；
  - `remote_window`：只读暴露对端通告的窗口；
  - 测试模块末尾 3 个 `test_oryn_*` 测试。
- src/lib.rs：加 `#![allow(warnings, clippy::all)]`。作为 path 依赖时 Cargo 不再压低上游告警，Oryn 只开部分 feature，上游有大量未使用告警。
- 其它文件未改。

升级 smoltcp 时：重新应用上述接口，运行 smoltcp 的 TCP 测试（`cargo test --lib --no-default-features --features std,alloc,proto-ipv4,proto-ipv6,medium-ip,socket-tcp socket::tcp`；需要上游 dev-dependencies，在本仓库外的副本里运行）与 `cargo test -p oryn-wireguard`。2026-11-18 应用补丁后 152 个 TCP 测试全部通过（其中 3 个为新增的 `test_oryn_*`）。
