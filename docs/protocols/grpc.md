# gRPC / gun

按 gRPC HTTP/2 线格式及 gun 的 protobuf `bytes` 字段 1 实现：POST `/{service}/Tun`，`content-type: application/grpc`、`te: trailers`。每个 Flow 是一个 gRPC 流；同一出站的 Flow 共享有界的 TLS h2 连接池（，实现在 `oryn-transport/src/h2pool.rs`，`network: h2` 传输复用同一个池，见 [h2.md](h2.md)）；配置和实际协商均要求 h2。

消息为压缩标志 0、u32 protobuf 长度、field 1 的 key / varint 长度 / 字节。消息最大 64 KiB、单次写入最大 16 KiB；流接收窗口 128 KiB – 2 MiB（随连接上的流数调整，见下）、h2 发送缓冲 32 KiB、HTTP 首部 16 KiB。写入等待 h2 capacity，解析保留碎片状态；压缩、异常 HTTP / gRPC 状态、畸形长度与截断返回错误。先发送协议首部再等响应，兼容延迟发响应的服务端。

## 连接池

| 项 | 上限 |
|---|---|
| 每出站 h2 连接 | 4 |
| 每连接并发流 | min(32, 服务端 `SETTINGS_MAX_CONCURRENT_STREAMS`) |
| 每出站并发 Flow | 128；满载时新 Flow 失败，不排队 |
| 连接接收窗口 | 4 MiB（= 各流窗口之和的预算）：一个读者停滞只占自己的流窗口，不阻塞同连接的其他流 |
| 流接收窗口 | 4 MiB ÷ 连接上的流数，取 2 的幂并限制在 128 KiB – 2 MiB：1–2 条流 2 MiB，3 条 1 MiB，8 条 512 KiB，32 条 128 KiB |
| 空闲连接 | 无流 30 秒后关闭，每 10 秒检查 |

- 新 Flow 先用第一条存活且流数未满的连接；都满且不足 4 条时新建。新建期间持有池锁，并发 Flow 等这一条，不同时拨出多条。
- 连接失效（驱动结束、GOAWAY、TLS / TCP 错误）：其上的 Flow 读写返回错误；连接移出池。复用的连接在发请求时失败，换新连接重试一次；新建的连接失败直接返回错误。
- 每个 Flow 持有连接的引用；出站重建后，旧连接在最后一个 Flow 结束时关闭。
- 新连接收到服务端 SETTINGS 之前按 32 计算流数；服务端上限更小时，多出的流由 h2 排队到有流结束，受代理握手超时约束。

## 测试

单元测试使用 64 字节窗口及碎片回显；连接池测试覆盖多流共享一条连接、第 33 个流新建连接、服务端流数上限 2 时用满 4 条连接后失败、服务端断开后已有流报错且新流重建、空闲回收。独立测试覆盖 Trojan / VLESS / VMess 的 TCP、UDP、select、40 条并发 Flow 共享连接（sing-box 1.12.8 / 1.13.14）与真实 Engine 健康检查。本机 RSS：64 条并发 Flow 的增量由每 Flow 一条连接时的 2.52 MiB 降到 0.20 MiB（p2_engine，见 [changelog-0.6.0.md](../../../docs/oryncore/changelog/changelog-0.6.0.md)）。

## 流窗口

h2 单流吞吐约等于「窗口的一半 ÷ 往返时延」（`h2` 在释放过半窗口后才补发 WINDOW_UPDATE）。原来固定 128 KiB 的窗口在回环上看不出问题，真机 Wi-Fi（往返 5.5 ms）上单流下载只有 91 Mbit/s（同条件 TCP 350 Mbit/s），往返 50 ms 时只剩约 10 Mbit/s。Go 实现（Xray、sing-box、mihomo）默认 4 MiB 流窗口。

现在窗口随这条连接上的流数调整：连接窗口固定 4 MiB 作为预算，单流窗口 = 预算 ÷ 流数（2 的幂，128 KiB – 2 MiB），流数变化时由连接的驱动任务通过 SETTINGS `INITIAL_WINDOW_SIZE` 下发（`h2` 同时只允许一条未确认的 SETTINGS，失败则稍后重试）。因此一条连接缓存的未读数据上限仍是 4 MiB，与旧的固定值一致，少数读者停滞也不会占满连接窗口。`h2pool` 的延迟链路回归测试：单流下载 16 MiB 在 20 ms 往返下从约 3.3 s 变为 0.22 s，旧值下该测试失败。
