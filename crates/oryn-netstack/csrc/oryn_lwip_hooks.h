#ifndef ORYN_LWIP_HOOKS_H
#define ORYN_LWIP_HOOKS_H

struct netif;
struct netif *oryn_lwip_route4(const ip4_addr_t *src, const ip4_addr_t *dest);
struct netif *oryn_lwip_route6(const ip6_addr_t *src, const ip6_addr_t *dest);

#endif /* ORYN_LWIP_HOOKS_H */
