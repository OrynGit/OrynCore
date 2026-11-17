# TUIC v5

只做协议版本 `0x05`。线格式按公开规范独立实现。规范仓库本身是 GPL-3.0，协议文本声明协议构想可以自由实现；本客户端不复制该仓库或 sing-quic 的源码。多字节整数为大端。

TUIC v4（只有 `token`、没有 `uuid`）跳过节点并警告。`udp-over-stream` 与 0-RTT（`reduce-rtt`）已支持，见文末。

## 认证

TLS 握手完成后，从当前连接导出 32 字节令牌：

- 标签：UUID 的 16 字节
- 上下文：口令的原始字节

使用 quinn 的 `export_keying_material`。这要求握手已经完成：0-RTT 时认证在后台等握手完成后再发（见文末）。

令牌写在一条单向流上，并在打开任何中继流之前写完：

```text
u8  0x05
u8  0x00
16  UUID
32  令牌
```

服务器没有标准的成功响应。认证失败时服务器可能直接关掉连接；连接被关则本次拨号失败。不实现令牌重放测试里的 0-RTT 会话票。错误 UUID 或错误口令由互通测试覆盖：导出材料不同，服务器应拒绝。

## TCP

每个 TCP Flow 一条双向流：

```text
u8  0x05
u8  0x01
地址
```

地址编码：

| 类型 | 值 | 内容 |
|---|---|---|
| 无 | 0xff | 无地址与端口，只用于 UDP 非首片 |
| 域名 | 0x00 | u8 长度 + 域名 + u16 端口 |
| IPv4 | 0x01 | 4 字节 + u16 端口 |
| IPv6 | 0x02 | 16 字节 + u16 端口 |

写完地址后，流上的后续字节就是 TCP 载荷。服务器不回应连接命令。写关闭对应 QUIC FIN。服务器连不上目标时可能关掉这条流，客户端把流错误当作该 Flow 失败，不拆掉整条 QUIC 连接。

## UDP

两种模式，默认 `native`。

- `native`：每片一个 QUIC 数据报。片长取 `max-udp-relay-packet-size` 与当前数据报可用空间（扣掉帧头与地址）中较小的一个。
- `quic`：每片一条单向流，写完即结束。回程同样是每包一条单向流：Oryn 为每条入站单向流起一个读取任务（期限 10 秒、单包最多 64 KiB，超出或超时就 `STOP_SENDING` 丢弃），不在读循环里内联读取；同时存在的任务数受 QUIC 单向流额度（128，见 [quic.md](quic.md)）限制。

同一关联 ID 的回程使用客户端该会话**第一片**所用的模式。

包命令：

```text
u8  0x05
u8  0x02
u16 关联 ID
u16 包 ID
u8  分片总数
u8  分片序号
u16 本片载荷长度（只计载荷，不含地址；与官方 tuic、sing-quic、mihomo 一致）
地址
本片载荷
```

未分片时总数为 1。非首片地址类型为 `0xff`。关联 ID 由客户端分配，同一 QUIC 连接上要复用服务器的同一 UDP 套接字时保持同一个 ID。分配时循环递增（回绕、跳过 0 和仍在使用的 ID），与 sing-box、tuic 参考客户端一致，不复用刚释放的最小 ID：服务端对旧关联的清理是异步的（sing-quic 的 `onDestroy` 按 ID 无条件删除），立刻复用同一个 ID 会偶发丢首包。

会话结束时发单向流 `Dissociate`（类型 `0x03` + u16 关联 ID）。空闲 30 秒也发送并丢掉本地状态。QUIC 连接断开时读循环退出并关闭所有会话的接收队列，队列里剩下的包读完后 `recv_from` 返回错误，不等空闲超时。

分片上限与 Hysteria2 相同：每出站 32 个会话、重组缓冲 128 KiB、每会话 4 个未完成包、每包最多 16 片、等待 3 秒。`max-udp-relay-packet-size` 默认 1500，允许 1–2048；超出则整份配置失败。已支持字段的非法值都是整份配置失败；不支持的写法跳过该节点并警告。更大的 UDP 载荷按这个尺寸切片，总上限仍受重组缓冲约束，超出则丢弃。

## 心跳与拥塞控制

有活动的中继任务时，每隔 `heartbeat-interval` 毫秒发一个 QUIC 数据报：版本 `0x05`、类型 `0x04`、无载荷。默认 10000。允许 1000–60000。缺省或 0 用默认值。没有活动任务时不发，连接按 [quic.md](quic.md) 的 30 秒空闲关闭。

`congestion-controller` 只接受 `bbr`（默认）、`cubic`、`new_reno`，映射到 quinn 自带实现。`bbr_meta_v1`、`bbr_meta_v2` 警告后用标准 BBR，`bbr-profile`、`cwnd` 忽略并警告。未写时默认 BBR（之前是 Cubic，千兆有线下 native 模式慢一半），显式写 `cubic` 的仍照配置。

## 配置

| 字段 | 处理 |
|---|---|
| server、port、uuid、password | v5 必填。同时出现 `token` 时忽略 token 并警告 |
| udp-relay-mode | `native` 或 `quic`，默认 native |
| congestion-controller | 见上 |
| heartbeat-interval | 毫秒 |
| sni、alpn、skip-cert-verify、fingerprint | 沿用现有 TLS。alpn 默认 `h3` |
| disable-sni | true 时不发送 SNI；证书固定仍生效 |
| reduce-rtt | 忽略并警告 |
| max-udp-relay-packet-size | 1–2048，默认 1500 |
| udp | 默认 false |
| max-open-streams | 若小于内部上限 128 则采用它（最小 1）；更大则钳到 128 并警告 |
| udp-over-stream、fast-open、request-timeout、ip、name-cert-verify | 忽略并警告 |

只有 `token` 的 v4 节点跳过。feature `tuic` 默认开启；`--no-default-features` 的精简构建里跳过并警告未编译。可配置 `dialer-proxy`，见 [dialer-proxy.md](dialer-proxy.md)。

## 验收时要覆盖的行为

本机替身先测两种 UDP 模式、三种拥塞控制、错误 UUID / 口令、心跳只在有任务时发送、分片丢失。独立对端用带 `with_quic` 的 sing-box，显式运行。不测 0-RTT。

## udp-over-stream 与 0-RTT

- `udp-over-stream: true`：UDP 不再走 TUIC 的 UDP 中继，而是在一条 TUIC TCP 流上跑 UoT（[uot.md](uot.md)），目标为 UoT 的魔法地址。`udp-over-stream-version` 为 1（旧版，默认，与 mihomo 相同）或 2（请求与第一个数据报合并写出，sing-box 的写法）。
- `reduce-rtt: true`：有会话票据时以 0-RTT 建立 QUIC 连接（quinn `into_0rtt`），之前打开的 TCP 流立即发出请求；TLS 导出材料要等握手完成才有，所以认证在后台握手完成后发出，服务端在认证到达前缓存这些流（与 sing-quic 的 clientHandshake 相同）。没有票据或服务端不允许 0-RTT 时按 1-RTT 建连；服务端拒绝 0-RTT 时，0-RTT 期间打开的流失败，之后的流正常。默认关闭：0-RTT 数据可以被重放。会话票据缓存见 [quic.md](quic.md)。

互通：sing-box 1.14 的 tuic 入站（`zero_rtt_handshake: true`）：UoS v1 / v2 的 TCP 与 UDP（sing-box 的 UoT 读缓冲放不下 30000 字节的包，测到 8000），网络变化后两次以 0-RTT 重连并被接受；服务端不允许 0-RTT 时退回 1-RTT；错误口令（认证在握手后发出，服务端关闭连接）。
