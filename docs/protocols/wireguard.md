# WireGuard 出站

WireGuard 只是一个 `Outbound`。它不取代 Packet Tunnel，也不把 IP 包交给 Router。用户态协议用 boringtun（BSD-3-Clause）的 Noise 与计时器，不用它的 TUN 设备层。隧道内的 TCP/IP 用 smoltcp（0BSD）。两者都是纯 Rust。不移植 wireguard-go。

包的路径停在本 crate 内：

```text
connect_tcp / bind_udp
        │  字节流 / 数据报
        ▼
     smoltcp          ← 第二个 Netstack，私有
        │  IP 包
        ▼
     boringtun        ← 加密，每个对端一个 Noise 会话
        │
        ▼
   外层数据报通道 → 各对端（直连是 UDP 套接字；dialer-proxy 时经另一个出站）
```

对外没有返回 IP 包的接口。测试要断言 crate 的公开面只有 Flow 接口，Router 测试里看不到这些包。

## 对端与密钥

支持一个或多个对端（最多 8 个）。

- 没有 `peers`：使用顶层的 `server`、`port`、`public-key`、可选的 `pre-shared-key`、`reserved`、`allowed-ips`，即一个对端。
- 有 `peers`（1–8 项）：每项都有这些字段；顶层同名对端字段若同时存在则忽略并警告。`private-key`、`ip` / `ipv6`、`mtu`、`persistent-keepalive`、`udp`、`dns` 等仍是顶层字段，所有对端共用一个本地身份。`peers` 为空或多于 8 项：跳过节点并警告。
- 每个对端各自有 Noise 会话、握手状态、端点与保留字段。发往隧道的 IP 包按目的地址在各对端 `allowed-ips` 里取**最长前缀**选择对端；收到的包必须落在发送它的对端（按外层来源地址确定）的 `allowed-ips` 内。
- 目标不在任一对端的 `allowed-ips` 内：该 Flow 失败（错误信息含 `allowed-ips`），明文不从这台设备另送一份。
- `amnezia-wg-option`（或写作 `amneziawg`）：见下文 AmneziaWG。
- `dialer-proxy`、`refresh-server-ip-interval`：见下文。

`private-key`、`public-key`、可选 `pre-shared-key` 都是标准 Base64，解码后 32 字节，否则整份配置失败。已支持字段的非法值都是整份配置失败；不支持的写法跳过该节点并警告。`ip` 与 `ipv6` 至少有一个，否则跳过节点并警告。带前缀则用作 smoltcp 地址前缀；裸地址用 /32 或 /128。

`allowed-ips` 必填，至少一条。缺了就跳过节点并警告，不默认成全隧道。目标 IP 不在任一前缀内时，该 Flow 失败，明文不从这台设备另送一份。

`server` 若是域名，用现有解析路径解析**对端端点**。这发生在隧道建立之前，不能走隧道内 DNS。`remote-dns-resolve` 不管端点，只管理 Flow 的目标。

## 保留字段与计时器

`reserved` 是 3 字节。写法为三个 0–255 的整数，或解码后恰好 3 字节的 Base64 字符串。默认全 0。非法值使整份配置失败。

boringtun 封装后，发送前把 UDP 载荷的第 2 到第 4 字节改成这 3 字节（第 1 字节仍是消息类型）。接收不按保留字段过滤：交给 boringtun 之前把这 3 字节清零（合法消息此处为 0；带保留字段的服务端在回包里也会写入，不清零 boringtun 会拒收）。

互通：sing-box 1.13.14 的 WireGuard 端点在 peer 里配置 `reserved: [1,2,3]`。它只在知道对端端点之后才在发出的包里写保留字段，所以测试用一个固定端口的 UDP 中继充当 Oryn 的端点，并统计两个方向带保留字段的包：Oryn 发出的包全部带 `[1,2,3]`，sing-box 发出的包也全部带，TCP 与 UDP 往返通过。保留字段与对端不符时握手是否失败，没有单独测试。

事件循环是**一个 Tokio 任务**，跑在进程级的 WG 工作线程上（`resources.rs`），不占用 Core 事件循环线程。工作线程数按资源档位：`desktop_high` 为 min(4, 核数 / 2)，其余为 1。线程常驻进程，各出站的引擎按轮转分配到工作线程。引擎同时驱动 smoltcp、各对端的 `update_timers` 和外层数据报通道，睡到下一计时器或通道可读为止。通道可读时一次最多取 32 个数据报（`try_recv_from`）。握手、重试、放弃都是按对端各自进行的：一个对端不可达不影响其它对端。

- `persistent-keepalive` 单位秒，默认 0（关闭）。非 0 时小于 10 秒钳到 10 秒并警告。
- 握手发出后 5 秒没有响应，再试，最多 3 次。之后停止。挂起的 Flow 失败。任务休眠，直到下一次 `connect_tcp`、`bind_udp`、`wake` 或 `network_changed`。对端不可达时不空转。实现：重发由 boringtun 按 5 秒计时器完成，15 秒内没有会话就丢掉 boringtun 状态（停止重发）、失败全部 TCP Flow 并休眠。没有会话时，发往该对端的包最多暂存 16 个（`PEER_QUEUE`），再多的丢弃，由隧道内 TCP 重传；不交给 boringtun 自己的 256 包队列。握手完成以握手响应（类型 2）被 boringtun 接受为准，不能比较 `time_since_last_handshake` 与开始时间：boringtun 的「当前时间」只在 `update_timers` 时更新，会话建立时刻可能早于开始时刻，比较永远不成立，15 秒后会误判为握手超时并重置所有连接（已修复的缺陷，见 [changelog-0.7.0.md](../../../docs/apple/changelog/changelog-0.7.0.md)）。
- `connect_tcp` 在三次握手完成后才返回；对端 RST 返回连接被拒，20 秒未建立返回超时。
- `network_changed`：丢掉外层数据报通道，下次使用时重新握手。
- `wake`：若配置了 keepalive 则立即发送；否则在会话已超过空闲时间时做一次握手探测。失败则标记不可用，规则同上。
- `sleep`：不发送 keepalive。

## 内部栈

smoltcp 只开 `medium-ip`、IPv4、IPv6、TCP、UDP。不开以太网、DHCP 和 smoltcp 自带 DNS 套接字。

| 项 | 上限 | 未经真机验证的占用 |
|---|---|---|
| TCP 套接字 | 64 | 每连接从接收 16 KiB + 发送 8 KiB 开始，按需扩容到上限（默认 256 / 128 KiB，见下文「TCP 缓冲（动态）」），连接关闭即释放；全部连接合计不超过预算（默认 6 MiB） |
| UDP 套接字 | 16 | 每方向 8 个包、max(8 × MTU, 8192) 字节 |
| 待加密发送队列 | 32 个包 | 满则 TCP 回压，UDP 丢弃 |
| 对端无会话时的暂存 | 每对端 16 个包 | 多出的丢弃，由 TCP 重传 |
| 交给用户 / 从用户取 | 每方向 2 块 × 4 KiB | 在 smoltcp 缓冲之外 |
| MTU | 默认 1280，允许 1280–1420 | 低于 mihomo 示例里的 1408，留给外层 UDP/IP |

满载时新的 `connect_tcp` / `bind_udp` 失败，不增加套接字，也不扩大缓冲。MTU 超出范围时整份配置失败。

### TCP 缓冲（动态）

隧道内每条 TCP 从小缓冲开始，按需扩容，空闲时收回；本出站全部连接的合计受预算限制。方案见 [plan-wg-dynamic-tcp-buffer.md](../../../docs/oryncore/plans/plan-wg-dynamic-tcp-buffer.md)。

三个 Oryn 扩展字段（mihomo 没有），单位字节，只接受整数。超出范围时整份配置失败。

| 字段 | 默认 | 范围 | 含义 |
|---|---|---|---|
| `tcp-rx-buffer` | 262144 | 16384–4194304 | 每条连接接收缓冲的上限，即通告窗口上限 |
| `tcp-tx-buffer` | 131072 | 8192–4194304 | 每条连接发送缓冲的上限 |
| `tcp-buffer-budget` | max(6 MiB, 接收上限 + 发送上限) | 接收上限 + 发送上限 至 67108864 | 本出站全部隧道内 TCP 的缓冲合计上限 |

- 新连接以接收 16 KiB、发送 8 KiB 开始（不超过上限），按这个大小计入预算；放不下时 `connect_tcp` 失败，错误为 `wireguard tcp buffer budget exhausted`。
- 接收缓冲：对端把窗口用到剩不足 1/8、之后本端又读到不超过 1/4 时翻倍。本端读得慢时缓冲一直接近满，不扩容。
- 发送缓冲：有待发数据而缓冲已满、对端窗口不小于当前容量、且上次扩容后已确认至少半个缓冲时翻倍。
- 扩容超出预算就不扩。连接 5 秒没有收发且两个缓冲为空时回到初始大小；对端按旧窗口多发的部分会被丢弃并重传。
- 窗口缩放在握手时按上限协商（smoltcp 补丁，见 `vendor/smoltcp/ORYN_PATCHES.md`），扩容不需要重新协商。
- 除了本出站的 `tcp-buffer-budget`，所有 WG / Tailscale 出站还共享一个进程级预算，由 Core 按资源档位设置：
  - `mobile_plus`（iOS）6 MiB；
  - `constrained`（Android、macOS / Linux 默认）4 MiB；
  - `desktop_high` 64 MiB。
  两者同时生效，任一放不下都会拒绝新连接或停止扩容。
- 内存压力（只有 iOS 宿主上报可用内存）：
  - elevated：不扩容，空闲 1 秒即收回；
  - critical：不扩容，扩容过的缓冲一空就收回。
  等级取宿主上报值与按可用内存推出的值中较高者（见 `Oryn_for_Apple/docs/development.md` 的 `pressure` 命令）。
- 用量见 `stats` 的 `wireguard_buffers`。方案见 [plan-wg-worker-and-global-budget.md](../../../docs/oryncore/plans/plan-wg-worker-and-global-budget.md)。
- 平台层只选资源档位，不改这些字段。本地配置编辑器不写这些字段，只能在导入的 YAML 中设置。

`udp: false`（默认）时 `bind_udp` 返回不支持。TCP 仍可用。

## 吞吐与并发

单条 TCP 的吞吐上限是 窗口 / RTT。本机基准：sing-box 1.13.14 WireGuard 端点 + 本机回环，两者之间放一个带单向延迟的 UDP 中继，每个方向各传同样多的数据，按总量除以总耗时算。下表是扫描 smoltcp 每方向 TCP 缓冲得到的 MiB/s（RTT 为往返延迟，0 表示无额外延迟；数据与扫描条件见 [measurements/wireguard-tcp-throughput-0.7.0.tsv](../../../docs/oryncore/measurements/wireguard-tcp-throughput-0.7.0.tsv)）：

| 缓冲 | RTT 0 | RTT 20 ms | RTT 80 ms |
|---|---|---|---|
| 8 KiB（早期取值） | 2.47 | 0.29 | 0.09 |
| 16 KiB | 4.27 | 0.56 | 0.18 |
| 32 KiB | 9.65 | 1.12 | 0.35 |
| 64 KiB | 18.12 | 2.16 | 0.68 |

吞吐与窗口成正比，符合 窗口 / RTT。最终取接收缓冲 64 KiB、发送缓冲 32 KiB（下载比上传常见），在这个取值下同一基准的总吞吐为 9.58 / 1.16 / 0.35 MiB/s（RTT 0 / 20 / 80 ms），比早期的 8 KiB 提高约 4 倍。（当时以为 smoltcp 的 ACK 延迟已关闭，实际代码一直是默认的 10 ms，那个基准本身也受中继限制。）

2026-11-18 用本机基准 `tests/wg_throughput.rs` 复测，发现延迟 ACK 会让下行在接收缓冲填满后，每次窗口更新都多等约 10 ms：RTT 0 时下行只有 62 Mbps。现在建立连接时调用 `set_ack_delay(None)`，每个数据段立即 ACK，RTT 0 下行 1.1 Gbps（M4，单线程跑满）。数据见 [measurements/wireguard-cpu-2026-11-18.md](../../../docs/oryncore/measurements/wireguard-cpu-2026-11-18.md)。

测试中还发现并修正了一个与吞吐无关的问题：smoltcp 重组乱序数据的段数默认只有 4，窗口变大后乱序到达的包会被丢弃并造成重传，所以打开了 `assembler-max-segment-count-32`。

每出站并发 TCP：从 32 条放宽到 64 条。本机 RSS 增量（sing-box 对端，连接上各做一次 1 KiB 往返并保持打开；见 [measurements/concurrency-0.7.0.tsv](../../../docs/oryncore/measurements/concurrency-0.7.0.tsv)）：32 条 2.2 MiB、64 条 4.1 MiB；第 65 条以 `wireguard tcp socket limit reached` 失败，不增加套接字也不扩大缓冲。完整 Engine（lwIP + Router）下 64 条的进程 RSS 增量为 3.3 MiB（[measurements/p3-rss-0.7.0.tsv](../../../docs/oryncore/measurements/p3-rss-0.7.0.tsv)）。这些都是本机进程的数字，不是 iOS Extension 的内存。

## IP 分片

smoltcp 0.11 只做 IPv4 分片：它的 `proto-ipv6-fragmentation` 只服务 6LoWPAN，普通 IPv6 不重组也不切片；IPv4 切片时第一片载荷为 `MTU − 20`，默认 MTU 1280 下偏移不是 8 的倍数，接收方无法正确重组。所以 smoltcp 的分片功能保持关闭，由本 crate 的 `frag.rs` 处理，两族同一套：

- 接收：解密并通过 `allowed-ips` 检查后、交给 smoltcp 之前重组。IPv4 改写总长度、清分片位、重算首部校验和；IPv6 去掉分片首部，允许它前面有逐跳 / 路由 / 目的选项首部。
- 发送：UDP 载荷不超过 MTU − 28（IPv4）/ MTU − 48（IPv6）时仍走 smoltcp；更大的数据报由本 crate 生成 UDP 首部与校验和，按 8 字节对齐切片，整组放入设备发送队列，队列放不下整组时整组丢弃。TCP 不变，MSS 仍由 MTU 决定。

| 项 | 上限 | 未经真机验证的占用 |
|---|---|---|
| 重组后 / 切片前的 IP 包 | 8192 字节：UDP 载荷 IPv4 ≤ 8164、IPv6 ≤ 8144，更大的在 `send_to` 返回错误 | 覆盖 EDNS 4096 的 DNS 响应与 1500 MTU 下的应用数据报 |
| 同时重组的数据报 | 4 个（两族合计），满时淘汰最旧的 | 最多 32 KiB，按需分配 |
| 每个数据报的分片数 | 64 | |
| 重组超时 | 15 秒（RFC 791 的初值），超时整组丢弃 | |
| 重叠、长度不一致、非最后一片不是 8 的倍数 | 整组丢弃（RFC 5722）；完全相同的重复分片忽略 | |

自行生成的分片标识从随机值开始递增（IPv4 取低 16 位）。分片同样只存在于本 crate 内。

## AmneziaWG 1.0

`amnezia-wg-option`（也接受 `amneziawg`）。变形只发生在外层数据报上，包在 boringtun 之外（`amnezia.rs`）：发送前对 boringtun 产出的标准消息变形，收到后先还原成标准消息再交给 boringtun。

| 字段 | 范围 | 默认 | 作用 |
|---|---|---|---|
| `jc` | 0–128 | 4 | 每次握手发起前发送的垃圾包个数 |
| `jmin` / `jmax` | 0–1280，`jmin ≤ jmax` | 40 / 70 | 垃圾包长度范围 |
| `s1` / `s2` | 0–1280，`s1 + 56 ≠ s2` | 0 / 0 | 握手发起 / 握手响应消息前面填充的随机字节数 |
| `h1`–`h4` | 1–2³²−1，四个互不相同 | 1 / 2 / 3 / 4 | 握手发起、握手响应、Cookie 应答、数据消息的类型值 |

- 接收时带填充的握手消息按「填充 + 标准长度」识别，再核对填充之后的类型值；标准类型值（1–4）在自定义头部下不是合法消息，垃圾包与长度不符的数据报丢弃。
- 1.5 / 2.0 的 `i1`–`i5`、`j1`–`j3`、`itime`、`s3`、`s4` 忽略并警告（线格式未实现，对端若要求这些字段会握手失败）。
- 没有开启或所有字段为默认值且 `jc: 0` 时与标准 WireGuard 的线格式相同。
- 测试：`amnezia.rs` 单元测试（往返、垃圾包只出现在握手发起之前、拒绝标准类型与畸形数据报）；进程内对端使用独立写的变形 / 还原实现做双向互通（TCP 与 UDP）。**本机没有 amneziawg-go，也没有与真实 AmneziaWG 服务端的互通。**

## 服务器地址刷新（`refresh-server-ip-interval`）

对端 `server` 是域名时，端点解析用现有解析路径（不走隧道内 DNS）。

- 未配置或 `0`：每次建立 TCP / UDP 会话时都解析（解析器自己有缓存）。
- 配置 10–86400 秒：解析结果按这个间隔复用，到期后下一次使用时重新解析。
- 单个对端解析失败时沿用它上一次的地址；全部对端失败才算失败（没有历史则报 `cannot resolve wireguard endpoint`）。
- 某对端的地址变化：引擎丢掉该对端旧的 Noise 会话（对新地址无效），在新地址上重新握手。没有后台定时器：只在有人使用隧道时才解析，休眠期间不唤醒。

## dialer-proxy

外层数据报通道可以经由另一个出站（`dialer-proxy`，见 [dialer-proxy.md](dialer-proxy.md)）：引擎向 `oryn-udp` 的 `DatagramFactory` 要到对端的通道，直连时是 UDP 套接字，链式时是目标出站的 `bind_udp`（例如支持 UDP 的 SOCKS5）。测试：外层 UDP 经 sing-box 的 SOCKS5 UDP ASSOCIATE 中转，TCP 与 UDP 在隧道里往返通过；中转消失后新连接得不到响应，已建立的隧道不会回退直连。

## DNS

两条路径互不代替。

未设置 `remote-dns-resolve`（默认）：出站拿到的 `TargetAddr` 与其它出站相同。已经是 IP 就在隧道里连接。嗅探把目标改成域名时，走现有 `Resolver`（查询仍经 Router）。本出站不为这种情况再开一只到公网 DNS 的套接字。

设置了 `remote-dns-resolve`：`dns` 必须是 1–4 个服务器，缺省端口 53，否则整份配置失败。Flow 上能找到域名（映射或嗅探）时，只向这些服务器发普通 DNS；查询封装进 smoltcp，经已建立的隧道出去。有 IPv4 地址时查 A，有 IPv6 地址时查 AAAA；答案按 A 在前排列，取第一个落在 `allowed-ips` 内的地址。答案只给这一次连接用，不写回 Flow，不第二次做规则匹配。Flow 上没有域名时连接原来的 IP。查询超时 3 秒，按列表顺序各试一次。出站内部缓存最多 32 条，TTL 30 秒。

这样满足已确认的决策：只有声明了 `remote-dns-resolve` 才做隧道内解析；未声明时不新增一条绕过隧道的解析。端点域名除外，见上文，否则隧道无法建立。

## 依赖

引入前核对传递依赖，只要 Noise 所需的部分：

| crate | 许可 | 用途 |
|---|---|---|
| boringtun | BSD-3-Clause | 握手、加解密、计时器。不启用设备 / TUN |
| smoltcp | 0BSD | 出站内部的 IP 栈，功能见上 |

`x25519-dalek` 已在树内。若 boringtun 再拉一套重复的加密库，实现时在许可页记明，并尽量与 ring 已覆盖的算法对齐；不为它引入 C++。实现落地时更新 `THIRD_PARTY_NOTICES.md`、`docs/licenses-*.md`。本设计不新增移植文件，`Oryn_dev/docs/oryncore/provenance.md` 无新条目。

## 构建与互通

feature `wireguard` 默认开启，Extension 发布构建包含它；`--no-default-features` 的精简构建里该类型被跳过并警告 `not compiled in`。

默认测试是进程内的 boringtun 对端（加一个 smoltcp 回显），不依赖外部程序。对端的分片重组与切片、AmneziaWG 变形是测试里独立写的实现，用来交叉检验 `frag.rs` 与 `amnezia.rs`；`frag.rs` 自身的单元测试用 smoltcp 的 wire 解析校验生成包的首部与 UDP 校验和。

与 sing-box 的互通是显式测试（需要带 `with_gvisor` 与 WireGuard 的 sing-box 1.13.14，通过 `ORYN_SING_BOX` 指定），不是默认 `cargo test` 的前置：TCP、UDP、隧道内 DNS、保留字段、`dialer-proxy`、两个端点作为同一节点的两个对端、`allowed-ips` 之外与错误公钥的失败路径、大 UDP 分片。没有这个二进制时，验收停在自写对端。

## 验收时要覆盖的行为

TCP、UDP、IP 目标、`remote-dns-resolve` 打开与关闭、握手重试后停止、keepalive、套接字数与缓冲满载、目标不在 `allowed-ips` 时失败。并确认 IP 包没有出现在 `oryn-wireguard` 之外。还覆盖两族大 UDP（MTU 边界、1472、4096、上限）的双向分片：进程内对端与 sing-box 1.13.14 WireGuard 端点。覆盖多对端（路由、同时使用、一端消失另一端仍可用）、AmneziaWG、端点刷新与保留字段互通。
