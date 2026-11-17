/*
 * Oryn 的 lwIP 配置。
 *
 * 用途：只作为用户态 TCP/IP 栈，把隧道里的 IP 包还原成 TCP 连接。
 * - NO_SYS=1，单线程驱动（Core 的事件循环线程）。
 * - UDP 不经过 lwIP，由 Rust 直接解析。
 * - 内存全部来自固定大小的静态池，满载时 lwIP 返回 ERR_MEM，由上层做背压。
 */
#ifndef ORYN_LWIPOPTS_H
#define ORYN_LWIPOPTS_H

#define NO_SYS                          1
#define LWIP_TIMERS                     1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0
#define LWIP_RAW                        0
#define LWIP_UDP                        0
#define LWIP_TCP                        1
#define LWIP_CALLBACK_API               1
#define LWIP_EVENT_API                  0

#define LWIP_IPV4                       1
#define LWIP_IPV6                       1
#define LWIP_ICMP                       1
#define LWIP_ICMP6                      1
#define LWIP_ARP                        0
#define LWIP_ETHERNET                   0
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_ACD                        0
#define LWIP_IGMP                       0
#define LWIP_DNS                        0
#define LWIP_IPV6_MLD                   0
#define LWIP_IPV6_AUTOCONFIG            0
#define LWIP_IPV6_DHCP6                 0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT   0
#define LWIP_ND6_QUEUEING               0
#define LWIP_IPV6_NUM_ADDRESSES         1
#define LWIP_IPV6_SCOPES                0
#define IP_FORWARD                      0
#define LWIP_IPV6_FORWARD               0
#define IP_REASSEMBLY                   1
#define IP_FRAG                         1
#define LWIP_IPV6_REASS                 1
#define LWIP_IPV6_FRAG                  1
#define IPV6_FRAG_COPYHEADER            1
#define MEMP_NUM_REASSDATA              16
#define MEMP_NUM_FRAG_PBUF              32
#define IP_REASS_MAX_PBUFS              64

#define LWIP_SINGLE_NETIF               1
#define LWIP_NETIF_LOOPBACK             0
#define LWIP_HAVE_LOOPIF                0
#define LWIP_NETIF_STATUS_CALLBACK      0
#define LWIP_NETIF_LINK_CALLBACK        0

/* 内存：固定上限。堆放 TCP 发送队列的数据（每连接最多 TCP_SND_BUF），4 MiB 能容纳 8 条满窗口的连接。
 * 实测：改用系统 malloc + 总量上限虽然去掉了 mem_malloc 热点，但 4 条以上并发下行连接的总吞吐从 13 Gbps 掉到 3 Gbps
 *（malloc 的 madvise / 跨线程释放开销），不要这样改。 */
#define MEM_LIBC_MALLOC                 0
#define MEMP_MEM_MALLOC                 0
#define MEM_ALIGNMENT                   8
#define MEM_SIZE                        (4 * 1024 * 1024)
#define MEMP_NUM_PBUF                   64
#define MEMP_NUM_TCP_PCB                1024
#define MEMP_NUM_TCP_PCB_LISTEN         128
#define MEMP_NUM_TCP_SEG                4096
#define PBUF_POOL_SIZE                  32

/* TCP：针对 iOS Extension 调小窗口与缓冲 */
/* MSS 只是编译期上限：实际 MSS 取 min(TCP_MSS, 虚拟接口 MTU - 40)，由 Core 的 mtu 选项决定。 */
#define TCP_MSS                         4024
#define TCP_WND                         (256 * 1024)
#define TCP_SND_BUF                     (256 * 1024)
#define LWIP_DISABLE_TCP_SANITY_CHECKS  1
#define PBUF_POOL_BUFSIZE               1600
#define TCP_SND_QUEUELEN                192
#define TCP_QUEUE_OOSEQ                 1
#define TCP_OOSEQ_MAX_PBUFS             16
#define TCP_LISTEN_BACKLOG              0
#define LWIP_TCP_KEEPALIVE              0
#define LWIP_TCP_TIMESTAMPS             0
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                  3
#define LWIP_TCP_SACK_OUT               0
#define SO_REUSE                        1

/* 大流量接收时拉长 ACK 间隔（lwip/PATCHES.md） */
#define ORYN_ACK_STRETCH                1
#define ORYN_ACK_EVERY                  8
#define ORYN_ACK_BULK_SEGS              256

/* 隧道里的包由系统协议栈生成，校验和可信，不再校验；输出时生成 */
#define CHECKSUM_CHECK_IP               0
#define CHECKSUM_CHECK_TCP              0
#define CHECKSUM_CHECK_ICMP             0
#define CHECKSUM_CHECK_ICMP6            0

#define LWIP_STATS                      0
#define LWIP_NETIF_API                  0
#define LWIP_TCPIP_CORE_LOCKING         0
#define LWIP_ERRNO_STDINCLUDE           1

/* 路由钩子：所有输出都走唯一的虚拟接口 */
#define LWIP_HOOK_FILENAME              "oryn_lwip_hooks.h"
#define LWIP_HOOK_IP4_ROUTE_SRC(src, dest) oryn_lwip_route4((src), (dest))
#define LWIP_HOOK_IP6_ROUTE(src, dest)     oryn_lwip_route6((src), (dest))

#endif /* ORYN_LWIPOPTS_H */
