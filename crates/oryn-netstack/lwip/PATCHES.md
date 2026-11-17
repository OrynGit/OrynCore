# lwIP 本地修改

来源：lwIP 2.2.1（`STABLE-2_2_1_RELEASE`，https://github.com/lwip-tcpip/lwip），BSD 许可证，见 `COPYING`。

只保留了 `src/core` 与 `src/include`，删除了 compat、altcp、apps 以及 PPP 源码（PPP 头文件保留，`init.c` 需要）。

| 文件 | 修改 | 原因 |
|---|---|---|
| `core/ipv4/ip4.c` `ip4_input_accept()` | 定义 `ORYN_ACCEPT_ALL` 时，接口 up 即接收 | 虚拟接口需要接收发往任意目的 IP 的数据包 |
| `core/ipv6/ip6.c` `ip6_input_accept()` | 同上 | 同上 |

所有修改都包在 `#ifdef ORYN_ACCEPT_ALL` 中，由 `oryn-netstack/build.rs` 定义。
| `include/lwip/tcp.h` `struct tcp_pcb`、`include/lwip/priv/tcp_priv.h` `tcp_ack()` | 定义 `ORYN_ACK_STRETCH` 时，已接收超过 `ORYN_ACK_BULK_SEGS` 个段的连接每 `ORYN_ACK_EVERY` 个段才确认一次（新连接仍每 2 个段），pcb 里多 3 字节计数 | 真机大流量上行时每秒十几万个 ACK 都要写线程发一次、内核入站线程处理一次 |
