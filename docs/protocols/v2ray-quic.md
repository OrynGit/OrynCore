# V2Ray QUIC 传输（`network: quic`）

参照 sing-box `transport/v2rayquic`（1.12.8 / 1.13.14）核对行为，未移植其代码。Trojan / VLESS / VMess 可用。QUIC 基础层与 Hysteria2 / TUIC 共用，见 [quic.md](quic.md)。

- 同一出站的所有 Flow 共享一条 QUIC 连接，每个 Flow 一个双向流；协议首部是流的第一段数据。连接建立、重连、空闲关闭、`network_changed` / `sleep` / `wake` 的处理与 Hysteria2 / TUIC 相同。
- 必须启用 TLS，不能用 Reality。ALPN 缺省 `h3`；显式写了 `alpn` 时每一项都必须是 `h3`。
- 拥塞控制固定为 BBR，不使用 Brutal、Salamander、端口跳跃与 QUIC 数据报。
- 每连接并发双向流上限 `MAX_BIDI = 128`（本端计数），满载时新 Flow 失败，不排队。
- 不实现 V2Ray 的 QUIC 头部加密（`security` / `key`）。分享链接带这类参数时导入被拒绝并说明原因。
- 服务器地址每次建立连接时经现有解析路径解析；配置了 `dialer-proxy` 时 QUIC 的 UDP 经由另一个出站，见 [dialer-proxy.md](dialer-proxy.md)。
- 编入需要 `quic` feature（默认已开）；`--no-default-features` 构建里这类节点跳过并警告 `network quic is not compiled in`。

## 测试

独立对端是带 `with_quic` 的 sing-box 的 `quic` 传输入站：Trojan / VLESS / VMess 的 70000 字节 TCP 往返、UDP 往返、20 条并发 Flow 共享连接；sing-box 1.12.8 与 1.13.14 通过。p2_engine 的 `quic` 例走真实 Engine，64 条并发 Flow 的 RSS 增量约 0（流缓冲在连接级别，见 [measurements/p2-rss-0.7.0.tsv](../../../docs/oryncore/measurements/p2-rss-0.7.0.tsv)）。
