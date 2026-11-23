# Hysteria2

按 Hysteria 2 公开协议独立实现（认证伪装成 HTTP/3、TCP 请求帧、UDP 数据报、Brutal 的速率语义、Salamander）。不移植 sing-quic。sing-quic 只在以后的互通测试里当行为对照。wire 格式如下，多字节整数为大端，varint 用 QUIC 编码。

Hysteria v1 见 [hysteria.md](hysteria.md)。支持 Gecko 混淆与 Realm（见下文两节，依据 sing-quic v0.7.0-beta.4，出处见 Oryn_dev/docs/oryncore/provenance.md）。

## 认证

QUIC ALPN 默认 `h3`，可用 `alpn` 覆盖，但列表里必须有 `h3`，否则整份配置失败。已支持字段的非法值都是整份配置失败；不支持的写法跳过该节点并警告。连接建立后用已有的 `h3` / `h3-quinn` 0.0.10 发**一次**请求，不手写 HTTP/3。

`quinn::Connection` 可以克隆。一份交给 h3，另一份在认证成功后 `open_bi` 发 TCP 帧、并收发数据报。h3 驱动任务只接受对端发起的流，不接管本端 `open_bi` 的流。驱动任务与这条 QUIC 连接同生共死，保证 HTTP/3 控制流继续有效。认证之后不再发第二个 HTTP 请求。

实现时用本机 h3 服务端做一条测试：同一连接上先完成 `/auth`，再打开一条自定义双向流。若 h3 驱动复位这条流，再改为手写最小 HTTP/3 请求，并在笔记里改正；设计先采用 h3 crate。

请求：

```text
:method POST
:path /auth
:authority hysteria
Hysteria-Auth: <password 原文>
Hysteria-CC-RX: <下行字节/秒，十进制；没有 down 则为 0>
Hysteria-Padding: <16–64 字节随机>
```

`password` 可以省略，这时认证头为空字符串，并警告一次。口令原样放入 `Hysteria-Auth`，不做哈希。

成功时状态码必须是 233。其它状态视为认证失败，关闭 QUIC 连接，不发送代理帧。响应头：

- `Hysteria-UDP`：`false` 时 `bind_udp` 失败。缺省按 `true`。
- `Hysteria-CC-RX`：服务器接收速率（字节/秒），`0` 表示不限制，`auto` 表示客户端上传改用 BBR。

## TCP

每个 TCP Flow 一条 QUIC 双向流。客户端先写：

```text
varint 0x401
varint 地址长度
bytes  地址（host:port）
varint 填充长度
bytes  16–64 字节随机填充
```

IPv6 写成 `[addr]:port`，域名和 IPv4 写成 `host:port`。

服务器回应：

```text
u8     状态（0x00 成功，0x01 失败）
varint 消息长度
bytes  消息
varint 填充长度
bytes  填充
```

状态非 0 时，把消息作为该 Flow 的错误并关闭流。成功后双向转发字节。写方向关闭对应 QUIC FIN；读到对端 FIN 或流错误则结束。填充只存在于请求和响应头，不插入应用数据。

## UDP

承载在 QUIC 不可靠数据报上。每个数据报：

```text
u32    会话 ID
u16    包 ID
u8     分片序号（从 0 起）
u8     分片总数
varint 地址长度
bytes  地址（host:port，每一片都带）
bytes  载荷
```

未分片时总数为 1，包 ID 与分片序号置 0。分片的包每次换一个非 0 的包 ID（会话内递增），避免某片丢失后与下一个包的分片拼在一起。

载荷上限 4096 字节（协议的 `MaxUDPSize`，参考服务端会把更大的包截断）。客户端对更大的包直接返回错误，不发出去。会话 ID 由客户端生成，在该出站的活动会话中唯一。协议没有关闭帧；会话空闲 30 秒后丢掉。QUIC 连接断开时读循环退出并关闭所有会话的接收队列（剩下的包读完后 `recv_from` 返回错误），不等空闲超时；并发的首批会话通过同一把锁共享同一个 UDP 中心，不会各建一个而让回包被别的读任务抢走。服务器若已忘记该 ID，按新会话处理，这是协议规定的行为。

分片：同一包 ID 的每一片到齐才交付。缺一片则整包丢弃。上限（未经真机验证）：

| 项 | 上限 |
|---|---|
| 每出站 UDP 会话 | 32 |
| 每出站重组缓冲 | 128 KiB |
| 每会话未完成的包 | 4 |
| 每包分片数 | 16 |
| 分片等待 | 3 秒 |

超过这些上限的包直接丢弃，不扩大缓冲。`PacketConn` 仍是逐包寻址。

## 拥塞控制

`up` / `down` 都缺省或为 0：使用 quinn BBR，`Hysteria-CC-RX` 发送 0。

只配置了一侧：配置的那一侧用 Brutal，另一侧用 BBR。`down` 换成字节/秒写入 `Hysteria-CC-RX`。`up` 是客户端发送速率。服务器若返回 `auto`，上传改为 BBR；返回 `0` 时上传仍按配置的 `up`。

速率是十进制：裸数字表示 Mbps，`30 Mbps` 等于 30×10^6 bit/s，再除以 8 得到字节/秒。接受 `bps` / `kbps` / `mbps` / `gbps`，可带 `/s`，大小写不敏感。超过 1000 Mbps 或单位无法识别时，整份配置失败，避免错误配置把发送速率放到没有意义的量级。

Brutal 第一版是固定速率，**不做丢包补偿**。它不是线格式的一部分，不影响互通，只影响本端发送有多激进。发送窗口不超过 [quic.md](quic.md) 的 256 KiB。拥塞窗口取 `速率 × 平滑 RTT × 2`，夹在 10 个数据报和 256 KiB 之间（已修正：原来只取 `速率 × RTT`、下限 1 个数据报，在本机 RTT 下窗口只有一两个包，突发的 16 条并发流会停在拥塞窗口上直到超时；×2 与 sing-quic 的 Brutal 相同）。实现 quinn 的 `Controller`，不复制参考实现的源码。

`bbr-profile` 忽略并警告，BBR 用 quinn 自带实现。

## Salamander

可选。`obfs` 为空则关闭。算法来自公开协议，不是移植：

```text
wire = 8 字节随机盐 || (QUIC 包每个字节 xor BLAKE2b-256(password || 盐)[i % 32])
```

口令短于 4 字节时整份配置失败。解不开或短于 8 字节的包丢弃。哈希用 `blake2`（MIT OR Apache-2.0），只为 BLAKE2b-256；ring 没有这个算法。混淆在自定义 UDP 套接字上，位于端口改写之外侧：先混淆，再改目的端口；接收时先还原，再把源端口改回稳定地址。

## Gecko

`obfs: gecko`、`obfs-password`（至少 4 字节）、`obfs-min-packet-size`（默认 512）、`obfs-max-packet-size`（默认 1200，最大 2048）；写 0 与不写相同，取默认值（与 sing-quic、mihomo 一致）。在套接字层实现（`oryn-quic/src/socket.rs`）：

- 先按 Salamander 处理每个包。
- QUIC 长首部包（握手阶段）再拆成 2–8 片，每片前加 5 字节首部（标志 0x80、消息 ID、`序号 << 4 | 总数`、填充长度 u16），并把每片填充到 [min, max] 之间的随机长度；短首部包不拆。
- 接收端按消息 ID 重组：最多 8 个待重组消息，8 秒过期，满时丢弃最旧的。

## 端口跳跃

`ports` 存在时忽略 `port`，并警告 `port` 被忽略。格式为逗号分隔的单端口或闭区间，例如 `443,20000-50000`。端口 0、大于 65535、或起点大于终点，整份配置失败。集合按区间保存，按区间宽度均匀抽样，不展开成大数组。

`hop-interval` 单位是秒，默认 30。单个整数表示固定间隔；`15-30` 表示每次在闭区间内随机取一个整数秒。出现逗号或无法解析时，整份配置失败。间隔小于 5 秒时钳到 5 秒并警告，避免过密地更换套接字目的端口。

初始端口在集合里随机选取。之后按间隔更换。上层 QUIC 连接保持不动，见 [quic.md](quic.md)。

## 配置

| 字段 | 处理 |
|---|---|
| server、port / ports、password | 见上。server 与至少一个端口必填 |
| up、down | 见拥塞控制 |
| obfs、obfs-password | `salamander` 或空 |
| sni、alpn、skip-cert-verify、fingerprint | 沿用现有 TLS 语义 |
| hop-interval、udp | udp 默认 false；false 时不提供 UDP |
| bbr-profile | 忽略并警告 |
| `obfs: gecko` 与包大小字段、`realm-opts` | 支持，见上文与下文 |

feature `hysteria2` 默认开启；`--no-default-features` 的精简构建里跳过并警告未编译。节点进入普通出站表，可配置 `dialer-proxy`（QUIC 的 UDP 经由另一个出站，见 [dialer-proxy.md](dialer-proxy.md)）。每连接并发 TCP 上限 128，见 [quic.md](quic.md)。

## 验收时要覆盖的行为

本机替身先测：错误密码、状态码不是 233、错误 SNI、混淆口令不一致、分片丢失、超限丢弃、Brutal 与 BBR 的切换、端口改写对 quinn 仍是同一对端。独立对端再用带 `with_quic` 的 sing-box，显式运行。本设计不包含这次互通运行。

## Realm

`realm-opts`（mihomo 写法，`enable: true` 才生效）：`server-url`（http 或 https）、`token`、`realm-id`（1–64 个字母、数字、`-`、`_`，首字符为字母或数字）、`stun-servers`（必填，最多 8 项，缺省端口 3478）、`sni` / `skip-cert-verify` / `fingerprint`（访问会合服务器的 TLS）。有 Realm 时 `server` / `port` 可省略（TLS 名称依次取 `sni`、`server`、会合服务器的主机名），与端口跳跃互斥。`certificate` / `private-key` / `name-cert-verify` / `alpn` 忽略并警告；端口映射（UPnP / NAT-PMP）未移植，mihomo 也没有对应字段。

实现在 `oryn-outbound/src/realm.rs`（移植自 sing-quic v0.7.0-beta.4 的 `hysteria2/realm` 客户端部分），通过 `oryn-quic` 的 `Rendezvous` 接口接入 QUIC 拨号：

1. 每个有 STUN 服务器的地址族各开一个 UDP 套接字（经 `DatagramFactory`，`dialer-proxy` 时同样经由上游出站），向 STUN 服务器发 Binding 请求，按 0.5 / 2 / 4 秒三轮重发，收集 XOR-MAPPED-ADDRESS。
2. 生成打洞元数据（16 字节 nonce、32 字节混淆密钥），向会合服务器 `POST {path}/v1/{realm-id}/connect`（`Authorization: Bearer <token>`，JSON，最多上报 8 个地址）。https 用 TLS + HTTP/2（ALPN h2），http 用 HTTP/2 prior knowledge；10 秒超时，响应最多 64 KiB。
3. 用返回的服务端地址与元数据在各套接字上并发打洞：每 100 毫秒向全部候选地址发 Hello（8 字节盐 + 以 SHA-256(密钥 ‖ 盐) 异或的「魔数、类型、nonce、随机填充」），收到对端的 Hello（回 Ack）或 Ack 即成功，最多 10 秒；IPv4 端口相近时补上可能的对称 NAT 端口（每主机最多 32 个）。
4. QUIC 跑在胜出的套接字上，对端为打洞得到的地址（不做端口跳跃改写）；其余套接字关闭。网络变化后重新打洞。

互通：sing-box 1.14 的 `hysteria-realm` 服务（明文 h2c 与 TLS 两种）+ 启用 realm 的 hysteria2 入站 + 测试里的最小 STUN 服务器，Salamander 与 Gecko 各一轮：TCP、UDP、网络变化后重连、错误令牌、不存在的 realm。
