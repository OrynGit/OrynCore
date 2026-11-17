# 多路复用

依据 sing-mux v0.3.3 的线格式：协议先连接 `sp.mux.sing-box.arpa:444`，会话握手为 version 1、protocol（smux=0、yamux=1、h2mux=2）、padding 开关。每个子流发送 u16 flags 与 SOCKS 地址，然后读取一字节状态；UDP 带 u16 长度，可选逐包地址。

采用 smux v1、现成 yamux crate、已有 h2。池、待发送队列、单流接收缓冲均有硬上限；smux v1 没有逐流流控：某条流的接收缓冲（128 KiB）满时，读取任务等待它被消费（与 xtaci/smux 一样阻塞整个会话，由承载 TCP 窗口让对端减速）；会话里只有这条流时一直等待；同一会话还有其他流被挡住、且等待超过 10 秒时，才视为该流停止读取并只关闭该流。新建会话的握手不持有池锁，并发进行，握手中的会话计入连接上限。池满时（会话数与每会话流数都到上限）新请求等待空位，不再立即返回 `pool capacity reached`；有会话或流释放时通知等待者，整体受连接超时约束。yamux 的打开请求排队发给会话任务，流上限取 `max-streams × 2`，连接接收窗口随流数放大（yamux 要求不小于 `256 KiB × 流数`，否则库内部 panic）。流 `Drop` 时发 FIN 遇到队列满，后台有界等待 10 秒再决定是否中止会话，不会因一次关闭多条流而中止共享会话。min-streams 为优先复用门槛，max-streams 为每会话上限。空闲会话 30 秒后回收。yamux 库负责其流控与状态机，不新增网络工作线程。依赖许可与体积在验收时记录。

完成声明依赖独立 sing-box 对端的三种协议、TCP / UDP、TLS / WS 及慢流和故障测试。

## Brutal 带宽交换

`smux.brutal-opts`（`enabled`、`up`、`down`，单位 Mbps，各 1–10000）对应 sing-mux 的 Brutal。会话建立后，在会话的第一条子流上向目的地 `_BrutalBwExchange` 发送本端的接收带宽（`down` × 125000，字节 / 秒，u64 大端），读取状态字节：成功时服务端再回一个 u64（它的接收带宽，客户端读走后丢弃），失败时回 uvarint 长度加消息，消息作为错误返回（最多读 1024 字节）。交换失败，整个会话建立失败，节点表现为连接失败，而不是静默降级。

**iOS 不允许进程设置本机 TCP 拥塞控制，所以 Oryn 只做带宽交换，不实现 Brutal 拥塞算法**：`up` 只做取值校验，不影响交换；之后的发送速率由系统决定。`up` / `down` 取第一个数字，后面的单位文字被忽略（`100 Mbps` 读作 100），超出 1–10000 或缺少其中一个是整份配置失败。`brutal-opts` 只在 `smux.enabled: true` 且 `brutal-opts.enabled: true` 时读取；`smux.enabled` 不是 true 时整个 `smux` 块（含 `brutal-opts`）都被忽略，不产生警告。

测试：交换帧按 sing-mux `brutal.go` 的格式核对；单元测试用按该格式写的服务端替身覆盖成功、服务端回错误消息、被拒绝、截断四条路径。**没有与 sing-box 互通**：sing-box 的 Brutal 服务端只在 Linux 上可用，本机是 macOS，无法验证真实服务端的接受路径。

## h2mux 流控窗口

连接窗口固定为 4 MiB 预算（`H2_WINDOW_BUDGET`），单流接收窗口随会话里的流数在预算内调整：1–2 条流 2 MiB，32 条 128 KiB（`h2_stream_window`，与 gRPC 连接池共用）。流数由租约的建立 / 释放驱动，经 `oryn_transport::drive_with_window` 的驱动任务下发 `SETTINGS_INITIAL_WINDOW_SIZE`；h2 同时只允许一条未确认的 SETTINGS，驱动任务在被拒绝时 25 ms 后重试。一个会话缓存的未读数据上限不变（4 MiB 预算）。

此前写死的 64 KiB 单流 / 256 KiB 连接窗口让单流下载在往返约 6 ms 时只有 ~67 Mbit/s；改后同一条件（本机延迟代理，`testbed delay`）单流下载约 1.8 Gbit/s，4 流约 3.4 Gbit/s（回环上两端同机，绝对值偏高，只看新旧对比）。上传方向不变：它受对端通告的窗口限制，不受本端窗口影响。回归测试 `h2mux_stream_window_follows_the_number_of_streams`。

## yamux 单流窗口的余量

yamux 0.13 的单流接收窗口从 256 KiB 起按往返时延自动翻倍，但每条流能超出 256 KiB 的部分来自「连接窗口 − 流数上限 × 256 KiB」。连接窗口恰好设为 `流数上限 × 256 KiB` 时余量为 0，窗口永远长不上去：主机延迟代理（往返约 6 ms）下单流下载只有约 213 Mbit/s，4 流约 930（16 流不受影响，约 3650）。现在连接窗口再加 4 MiB 余量（`YAMUX_WINDOW_HEADROOM`），活跃的流分享这部分，一个会话缓存的未读数据上限随之多出这么多。上传方向受对端（hashicorp yamux 的 256 KiB 窗口）限制，本端改不了。该修改尚未测量。

