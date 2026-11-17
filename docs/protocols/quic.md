# QUIC 基础层（oryn-quic）

Hysteria2、TUIC 与 V2Ray QUIC 传输（[v2ray-quic.md](v2ray-quic.md)）共用。设计核对 quinn 0.11（已在 DoQ / DoH3 使用）与 `oryn-dns` 的 `PacketConnSocket`。本文件的窗口、队列和超时最初是保守估算；后来窗口按真机往返时延（见下「窗口与队列」）修正，其余仍未经真机验证。

## 职责

`oryn-quic` 提供：

- quinn 客户端配置：TLS 沿用 `oryn-tls`（系统证书、SHA-256 固定、`skip-cert-verify`、SNI、ALPN）。
- 自定义 `AsyncUdpSocket`：数据报通道来自 `oryn-udp` 的 `DatagramFactory`（直连是 UDP 套接字；配置了 `dialer-proxy` 时是另一个出站的 UDP，见 [dialer-proxy.md](dialer-proxy.md)），之上可选 Salamander、可选端口跳跃。对 quinn 呈现稳定的对端地址。
- 拥塞控制接入：BBR、Cubic、NewReno 用 quinn 自带实现。Brutal 只在 Hysteria2 配置了带宽时由该出站装上，算法见 [hysteria2.md](hysteria2.md)。
- 每个出站一条可复用的 QUIC 连接：建立、复用、失败后按需重连、空闲关闭。
- 数据报收发，队列有硬上限。
- 响应 `network_changed`、`sleep`、`wake`。不使用 QUIC 连接迁移。

出站实现仍放在 `oryn-outbound`，类型是普通 `Outbound`。策略组和健康检查不增加分支。

## 连接

- 每个出站同时最多一条可用连接。替换时旧连接与新握手最多重叠 10 秒，随后中止旧连接。重叠期间连接对象不超过 2 个。
- 连接空闲 30 秒（没有流，也没有数据报）后关闭。有活动流时，quinn keepalive 间隔 15 秒，只为撑过 30 秒空闲超时。
- 握手超时 10 秒。失败后按 1 秒、2 秒、4 秒再试，最多 3 次。三次都失败则本次 Flow 失败。没有后台重试循环；下一次用户 Flow 可以再试。
- 收到 `network_changed`：中止该出站的 QUIC 连接。下一次 Flow 重新拨号。
- `sleep`：停止 keepalive，不在睡眠中重试。
- `wake`：若仍有活动流，立刻发一次 keepalive；5 秒内没有进展则中止连接，下一次读写重新拨号。

这些信号不走新的 FFI 类型。Extension 在已有的 JSON 命令上增加 `sleep` 与 `wake`。`PacketTunnelProvider.sleep()` / `wake()` 把命令交给 Core。`network_changed` 在清 DNS 缓存和 UDP 会话之后，通知下面的生命周期对象。

生命周期不用全局表。构建出站时，需要这些信号的出站登记到 Engine 的有界列表，条目数等于这类出站的个数。列表里只有 `on_network_changed` / `on_sleep` / `on_wake`。

## 窗口与队列

覆盖 quinn 的默认窗口。默认值面向高带宽，不适合 Extension。

| 项 | 上限 |
|---|---|
| 连接接收窗口 | 6 MiB（原 512 KiB） |
| 每流接收窗口 | 1 MiB（原 64 KiB） |
| 发送窗口 | 1 MiB（原 256 KiB） |
| 每连接双向流（本端计数） | 128（原为 32） |
| 每连接单向流（对端可对我们打开的上限） | 128（原 16） |
| 数据报接收缓冲 | 128 KiB |
| 数据报发送缓冲 | 64 KiB |
| UDP 套接字收发队列 | 各 64 个数据报，每个最多 2048 字节 |
| quinn UDP 负载上限 | 1200 字节 |

这一调整依据真机数据：QUIC 在流窗口用掉一半后才补发额度，单流吞吐约等于「窗口的一半 ÷ 往返时延」，64 KiB 在 5.5 ms 往返下只有 45–50 Mbit/s（Hysteria2、TUIC、V2Ray QUIC 都是这个数；同一台手机上 TCP 为 350 Mbit/s），往返 100 ms 时只剩约 3 Mbit/s；发送窗口同理（256 KiB 在 100 ms 往返下约 20 Mbit/s）。放大后一条连接缓存的未读数据上限从 512 KiB 变为 6 MiB（每出站一条连接）；每流 1 MiB 使得不超过 5 条读者停滞的流不会占满连接窗口。quinn 没有窗口自动调整，这些是静态值。

队列满时丢弃该数据报，由 QUIC 重传可靠流。不可靠数据报丢了就丢了，不无限排队。流数量达到上限时，新的 Flow 失败，不等待把窗口撑大。128 的取值来自本机并发测试（见下），TUIC 的 `max-open-streams` 仍可把它调小。

单向流的额度只在流读完后归还。TUIC `udp-relay-mode: quic` 每个 UDP 包占一条单向流，sing-box（quic-go）在额度用尽时**直接丢包**而不是排队，所以 16 条不够：24 个并发 UDP 会话时只有 16–19 个能收到回包。上调到 128 后同样的测试全部通过，也不会增加内存上限——流只有真正打开才占状态，总量仍受连接接收窗口约束。

套接字实现从 `PacketConnSocket` 收紧队列长度。Salamander 和端口跳跃包在这个套接字里，不放进 quinn。

## 端口跳跃与混淆的套接字

quinn 只看到一个固定的对端 `SocketAddr`。

- 发送：取出 quinn 给出的数据报，先做 Salamander（若启用），再把目的端口改成当前跳跃端口。
- 接收：先解除 Salamander，再把源端口改回 quinn 所知道的那个端口，然后交给 quinn。
- 因此换端口不会变成 QUIC 路径迁移，也不会因为源端口变化被 quinn 丢掉。

端口集合与间隔由 Hysteria2 配置决定。没有跳跃时目的端口不变。

## 并发

每连接并发 TCP 从 32 放宽到 128。本机 RSS 增量（sing-box 对端，连接上各做一次 1 KiB 往返并保持打开；见 [measurements/concurrency-0.7.0.tsv](../../../docs/oryncore/measurements/concurrency-0.7.0.tsv)）：

| 协议 | 32 条 | 64 条 | 128 条 |
|---|---|---|---|
| Hysteria2 | 2.1 MiB | 2.4 MiB | 3.0 MiB |
| TUIC | 1.6 MiB | 1.8 MiB | 2.3 MiB |

流缓冲在连接级别（连接窗口 512 KiB、每流窗口 64 KiB），增长很慢，所以放宽到 128 的内存代价小。完整 Engine（lwIP + Router）下 Hysteria2 128 条的进程 RSS 增量为 5.5 MiB，TUIC 为 0.06 MiB（[measurements/p3-rss-0.7.0.tsv](../../../docs/oryncore/measurements/p3-rss-0.7.0.tsv)）。这些是本机进程的数字，不是 iOS Extension 的内存。

## 网络与构建

`oryn-quic` 由 `quic` feature 控制，`hysteria2` / `tuic` 依赖它，三者默认开启，Extension 发布构建包含它们。`--no-default-features` 的精简构建里，对应 `type` 与 `network: quic` 在配置阶段跳过，警告为英语：`proxy {name}: hysteria2 is not compiled in and was ignored`（`tuic` 与 `network quic` 同样）。

## 补充

- 混淆：`QuicParams.obfs` 为 `Salamander`、`XPlus`（Hysteria v1）或 `Gecko`（Hysteria2），见 [hysteria.md](hysteria.md) 与 [hysteria2.md](hysteria2.md#gecko08x)。
- 0-RTT：`QuicParams.zero_rtt`（TUIC `reduce-rtt`）。TLS 配置在一个出站内复用，会话票据才能留到下一次拨号；票据缓存 32 张（rustls 按每服务器 8 张折算服务器数，折算成 1 时新条目会被立刻淘汰，所以不能设得更小）。握手结果经 `QuicClient::handshake` 交给出站；握手 10 秒未完成则关闭连接。
- `Rendezvous`：对端在 NAT 之后时（Hysteria2 Realm），由出站提供的打洞过程给出数据报通道与对端地址，此时不做端口跳跃改写。
- 发送错误：套接字发送遇到 `WouldBlock` 或 `ENOBUFS`（Darwin 55 / Linux 105，macOS 的小 UDP 发送缓冲在突发时会返回）都按丢包处理，由 QUIC 重传；发送任务只在通道关闭（`BrokenPipe`）时结束。此前 ENOBUFS 会结束发送任务，整条连接随之停住。
- Brutal 拥塞窗口修正见 [hysteria2.md](hysteria2.md#拥塞控制)。

`quinn` 已经因为 DoQ / DoH3 在二进制里。本层新增的是会话、套接字和 Brutal，不新增 QUIC 实现。

## 数据报收发的开销与路径 MTU

主机采样（TUIC，`sample` 工具）显示活跃 CPU 里约七成是每个数据报一次的 `sendto` / `recvfrom` 系统调用，加密只占很小一块；千兆有线下 QUIC 族单线程 CPU 受限的原因在此。不走 iOS 私有的 `sendmsg_x` / `recvmsg_x` 批量接口（有审核风险），改用可移植的办法降低每个包的固定开销：

1. **路径 MTU 探测。** quinn 只有在套接字的 `may_fragment()` 为 false 时才做 MTU 探测，自定义套接字一直用默认值 true，包大小因此永远停在 1200 字节。现在直连 UDP 通道给套接字设「不分片」标志（Darwin `IP_DONTFRAG` / `IPV6_DONTFRAG`，Linux `IP_MTU_DISCOVER=DO`），`may_fragment()` 返回 false，quinn 把包从 1200 探测到路径允许的上限（默认上限 1452）。同样吞吐下数据报数量少约 21%。经由其它出站的通道和带混淆（Salamander / XPlus / Gecko / wechat-video）的连接不支持，保持固定 1200。
2. **接收批量。** 接收任务等到一个包后，用新加的 `Datagrams::try_recv_from` 把已到达的积压一次取完（上限 64 个），`poll_recv` 一次向 quinn 交出多个包，省掉每个包一次的任务唤醒和轮询。
3. **发送批量。** 发送任务被唤醒后把队列里积压的包一起发完（上限 64 个）。

系统调用次数本身没有减少（仍是一包一次），预期收益是数据报数量约 −21% 加每包的唤醒 / 分配开销下降；没有量化，真机上看 CPU 秒 / GiB。

## UDP 会话收包队列

TUIC / Hysteria2 / Hysteria v1 的每个 UDP 会话原来用 8 个包的收包队列，读取方被调度延迟一两毫秒（40 Mbit/s、约 3.3k 包/秒）队列就满、后到的包被丢弃，这就是千兆吞吐报告里 QUIC 族下行丢包 9–29%（TUIC `quic` 模式因为每个包一条单向流、任务完成顺序不定而更严重）的主要嫌疑。现在队列按包数和字节数双重限制：最多 128 个包、256 KiB（`inbox::SESSION_PACKETS` / `SESSION_BYTES`；数据报最大约 64 KiB，只按包数限制内存没有上界），空队列时总是收下，大包不会永远进不来。该修改尚未测量。

