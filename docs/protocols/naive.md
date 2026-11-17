# NaïveProxy（`type: naive`）

实现在 `oryn-outbound/src/naive.rs`。纯 Rust，不用 Cronet：TLS 用 `oryn-tls`（可用浏览器指纹），HTTP/2 用 `h2` crate；`quic: true` 使用 QUIC ALPN `h3`、`h3` + `h3-quinn` 客户端和有界 `H3Stream`。填充协议按 NaïveProxy 的公开说明与 sing-box `protocol/naive/inbound_conn.go` 独立实现。

## 请求

每个 Flow 一个 HTTP/2 CONNECT 流（authority 形式 `host:port`），首部：`proxy-authorization: Basic …`（有用户名或口令时）、`padding`（30–61 个字符：16 个取自 `!#$()+<>?@[]^\`{}` 的随机字符，其余 `~`）、配置的 `headers`。响应必须是 200。同一出站的 Flow 共享有界的 h2 连接池（最多 4 条连接、每条 32 个流，与 gRPC 相同，见 [grpc.md](grpc.md)）。

## 填充

每个方向的前 8 个数据块写成「数据长度 u16 + 填充长度 u8 + 数据 + 零填充（0–255 字节）」，之后是原始字节。读方向按同样的规则剥掉。

## 与 Chrome 的差异

SETTINGS 的首部表大小（65536）与首部列表上限（256 KiB）按 Chrome 取值；窗口仍用有界的值（连接 4 MiB 预算，单流 128 KiB – 2 MiB 随流数调整，见 grpc.md），Chrome 的 6 / 15 MiB 窗口超出 Extension 的内存预算。`h2` crate 不能调整伪首部顺序与 SETTINGS 顺序。这两点使 HTTP/2 指纹与 Chrome 不完全一致（TLS 层的 ClientHello 由 `client-fingerprint` 决定）。

## HTTP/3、UDP 与限制

`quic: true` 时，客户端以 TLS ALPN `h3` 建立 QUIC 连接，用 `h3_quinn::Connection` 驱动 HTTP/3 CONNECT；authority、Basic Authorization、`padding` 和自定义 headers 与 HTTP/2 路径保持一致，响应状态必须为 200。每个 Flow 使用一个有界 `H3Stream`：发送命令队列最多 8 项，每次写入最多 16 KiB，读取按 h3 数据块消费；驱动关闭、写入背压和取消都返回明确错误。该路径不会退回 HTTP/2；若构建未包含 QUIC 能力，会返回 `naive HTTP/3 is not compiled in`。

`udp: true` 时 UDP 仍走 UoT（[uot.md](uot.md)），版本默认 2。H3 目前没有独立的连接池、0-RTT 或 QUIC DATAGRAM UDP 语义。不能用 Reality（配置错误）。

补验后，H3 发送任务由 Flow 持有；丢弃 Flow 时停止接收并取消任务，发送 guard 负责重置尚未正常结束的发送流，包括任务首次 poll 前被取消的情况。正常 shutdown 等待已接受数据并发送 FIN，不重置上传方向，下行仍可读。只取消一次 flush 并保留 Flow 时，之后可继续排空同一份数据。上述行为已在真实本机 QUIC / TLS / H3 小窗口背压下验证，且不关闭共享连接上的其他 Flow，见 [补验记录](../../../docs/oryncore/audits/audit-vision-h3-followup.md)。

## 互通

sing-box 1.14 的 naive 入站（TLS + h2）：普通 TLS 与 `client-fingerprint: chrome`，TCP（70 KB、16 条并发）、UoT 的 UDP（3 / 1200 / 8000 字节），错误口令。HTTP/3 已接入 h3 客户端路径，但仍需独立 NaïveProxy/sing-box H3 服务端完成 TLS、CONNECT、填充、TCP 并发和 UoT UDP 验收；当前 h2 互通结果不能替代 H3 验收。
