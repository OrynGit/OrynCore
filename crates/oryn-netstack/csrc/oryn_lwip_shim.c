/*
 * lwIP 与 Rust 之间的薄胶水层。
 *
 * 只做两件事：
 * 1. 创建唯一的虚拟接口，把 lwIP 输出的 IP 包交给 Rust；
 * 2. 包装 Rust 侧无法直接使用的 lwIP 宏与结构体字段。
 *
 * 所有函数只能在 Core 事件循环线程调用。
 */
#include <string.h>

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/timeouts.h"

/* 输出回调直接拿到 pbuf 链，由接收方一次性拷进自己的缓冲（少一次经静态中转区的整包拷贝）。 */
typedef void (*oryn_output_fn)(void *ctx, const struct pbuf *p);

static struct netif g_netif;
static int g_initialized = 0;
static oryn_output_fn g_output = NULL;
static void *g_output_ctx = NULL;

static err_t oryn_netif_output_pbuf(struct pbuf *p)
{
  if (g_output == NULL) {
    return ERR_OK;
  }
  g_output(g_output_ctx, p);
  return ERR_OK;
}

static err_t oryn_netif_output4(struct netif *netif, struct pbuf *p, const ip4_addr_t *addr)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(addr);
  return oryn_netif_output_pbuf(p);
}

static err_t oryn_netif_output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *addr)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(addr);
  return oryn_netif_output_pbuf(p);
}

static err_t oryn_netif_init(struct netif *netif)
{
  netif->name[0] = 'o';
  netif->name[1] = 'r';
  netif->output = oryn_netif_output4;
  netif->output_ip6 = oryn_netif_output6;
  return ERR_OK;
}

struct netif *oryn_lwip_route4(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  LWIP_UNUSED_ARG(src);
  LWIP_UNUSED_ARG(dest);
  return &g_netif;
}

struct netif *oryn_lwip_route6(const ip6_addr_t *src, const ip6_addr_t *dest)
{
  LWIP_UNUSED_ARG(src);
  LWIP_UNUSED_ARG(dest);
  return &g_netif;
}

/* 进程内只初始化一次 lwIP；之后只更新输出回调与 MTU。 */
void oryn_lwip_setup(uint16_t mtu, oryn_output_fn output, void *ctx)
{
  if (!g_initialized) {
    lwip_init();
    netif_add_noaddr(&g_netif, NULL, oryn_netif_init, ip_input);
    netif_set_default(&g_netif);
    netif_set_up(&g_netif);
    netif_set_link_up(&g_netif);
    g_initialized = 1;
  }
  g_netif.mtu = mtu;
#if LWIP_IPV6
  g_netif.mtu6 = mtu;
#endif
  g_output = output;
  g_output_ctx = ctx;
}

/* 输入一个 IP 包。数据会被复制，调用返回后即可释放。 */
int8_t oryn_lwip_input(const uint8_t *data, size_t len)
{
  if (len == 0 || len > 0xFFFF) {
    return ERR_VAL;
  }
  struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
  if (p == NULL) {
    return ERR_MEM;
  }
  if (pbuf_take(p, data, (u16_t)len) != ERR_OK) {
    pbuf_free(p);
    return ERR_BUF;
  }
  err_t err = g_netif.input(p, &g_netif);
  if (err != ERR_OK) {
    pbuf_free(p);
  }
  return err;
}

/* ACK 拉长（lwIP 补丁 ORYN_ACK_STRETCH）会让不足 ORYN_ACK_EVERY 个段的尾巴等 250 ms 的慢定时器才确认，发送端的重传
 * 定时器先到期就会伪重传并砍拥塞窗口（真机单流上行偶发掉到 4.5 Gbps、发送端 18 个重传而没有任何丢包计数）。
 * Core 每批输入处理完调用这里：有延迟确认挂着就立即发出去，吞吐期间仍是每 8 段一个 ACK，批尾不再等定时器。 */
u8_t oryn_ack_dirty = 0;

void oryn_lwip_flush_acks(void)
{
  if (oryn_ack_dirty) {
    oryn_ack_dirty = 0;
    tcp_fasttmr();
  }
}

void oryn_lwip_check_timeouts(void)
{
  sys_check_timeouts();
}

uint32_t oryn_lwip_sleeptime(void)
{
  return sys_timeouts_sleeptime();
}

/* 在任意地址的指定端口上监听（IPv4 + IPv6）。失败返回 NULL。 */
struct tcp_pcb *oryn_tcp_listen(uint16_t port, void *arg, tcp_accept_fn accept)
{
  struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (pcb == NULL) {
    return NULL;
  }
  ip_set_option(pcb, SOF_REUSEADDR);
  if (tcp_bind(pcb, IP_ANY_TYPE, port) != ERR_OK) {
    tcp_abort(pcb);
    return NULL;
  }
  struct tcp_pcb *lpcb = tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG);
  if (lpcb == NULL) {
    tcp_abort(pcb);
    return NULL;
  }
  tcp_arg(lpcb, arg);
  tcp_accept(lpcb, accept);
  return lpcb;
}

/* 注意：lwIP 的 tcp_sndbuf() 宏把结果截成 16 位（最大 65535），窗口缩放下必须直接读 snd_buf。 */
uint32_t oryn_tcp_sndbuf(const struct tcp_pcb *pcb)
{
  return (uint32_t)pcb->snd_buf;
}

/* 新连接的初始接收窗口。lwIP 的 tcp_recved 每消费一批数据就把窗口加上同样多（上限 TCP_WND），
 * 所以快的连接很快涨到满窗口，慢的连接（出站拥塞）只会缓冲初始窗口那么多，不会让每条连接都占 TCP_WND 的内存。 */
void oryn_tcp_init_rcv_wnd(struct tcp_pcb *pcb, uint32_t wnd)
{
  pcb->rcv_wnd = wnd;
  pcb->rcv_ann_wnd = wnd;
}

void oryn_tcp_nagle_disable(struct tcp_pcb *pcb)
{
  tcp_nagle_disable(pcb);
}

/*
 * 取出连接的四元组。addr 输出为 16 字节，IPv4 时只用前 4 字节。
 * 返回 4 或 6。
 */
int oryn_tcp_endpoints(const struct tcp_pcb *pcb,
                       uint8_t *local_addr, uint16_t *local_port,
                       uint8_t *remote_addr, uint16_t *remote_port)
{
  *local_port = pcb->local_port;
  *remote_port = pcb->remote_port;
  if (IP_IS_V6_VAL(pcb->local_ip)) {
    memcpy(local_addr, ip_2_ip6(&pcb->local_ip)->addr, 16);
    memcpy(remote_addr, ip_2_ip6(&pcb->remote_ip)->addr, 16);
    return 6;
  }
  memcpy(local_addr, &ip_2_ip4(&pcb->local_ip)->addr, 4);
  memcpy(remote_addr, &ip_2_ip4(&pcb->remote_ip)->addr, 4);
  return 4;
}

uint16_t oryn_pbuf_tot_len(const struct pbuf *p)
{
  return p->tot_len;
}

/* 停止时释放全部连接与监听，使下一个 Engine 从干净状态开始。 */
/* 诊断：统计 lwIP 的 TCP pcb（active / time-wait / listen），out 长度为 3。 */
void oryn_lwip_pcb_counts(uint32_t *out)
{
  struct tcp_pcb *p;
  struct tcp_pcb_listen *l;
  uint32_t n = 0;
  for (p = tcp_active_pcbs; p != NULL; p = p->next) n++;
  out[0] = n;
  n = 0;
  for (p = tcp_tw_pcbs; p != NULL; p = p->next) n++;
  out[1] = n;
  n = 0;
  for (l = tcp_listen_pcbs.listen_pcbs; l != NULL; l = l->next) n++;
  out[2] = n;
}

void oryn_lwip_reset(void)
{
  while (tcp_active_pcbs != NULL) {
    tcp_abort(tcp_active_pcbs);
  }
  while (tcp_tw_pcbs != NULL) {
    tcp_abort(tcp_tw_pcbs);
  }
  while (tcp_listen_pcbs.listen_pcbs != NULL) {
    struct tcp_pcb_listen *l = tcp_listen_pcbs.listen_pcbs;
    tcp_arg((struct tcp_pcb *)l, NULL);
    tcp_close((struct tcp_pcb *)l);
  }
  while (tcp_bound_pcbs != NULL) {
    tcp_abort(tcp_bound_pcbs);
  }
  g_output = NULL;
  g_output_ctx = NULL;
}
