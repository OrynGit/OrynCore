# dialer-proxy（链式代理）

`dialer-proxy: 名称` 让节点经由另一个出站拨出，行为与 mihomo 的同名字段一致。所有协议节点都支持（SOCKS5 / HTTP / SS / Trojan / VLESS / VMess / AnyTLS / Hysteria2 / TUIC / WireGuard）。

```yaml
proxies:
  - {name: hop, type: socks5, server: hop.example, port: 1080, udp: true}
  - {name: far, type: trojan, server: far.example, port: 443, password: p, dialer-proxy: hop}
```

## 做法

| 节点用什么拨号 | 链路 |
|---|---|
| TCP（SOCKS5、HTTP、SS、Trojan、VLESS、VMess、AnyTLS、TLS / ShadowTLS / 插件之下的字节流） | 下层拨号器换成目标出站的 `connect_tcp` |
| UDP 数据报（Hysteria2、TUIC、V2Ray QUIC、WireGuard、SOCKS5 UDP、SS 原生 UDP） | 数据报通道换成目标出站的 `bind_udp`（`oryn-udp` 的 `DatagramFactory`，`oryn-outbound/src/chain.rs` 提供链式实现） |

- **链在出站内部**：节点构建时就持有目标出站的引用，不再经过 Router。Flow 仍然只做一次规则匹配（`RouteDecision` 已经定下第一个出站），符合「一个 Flow 一次匹配」的原则。
- 目标可以是另一个节点、一条链上的中间节点，或策略组；目标是策略组时，使用组当时选中的成员。
- 目标出站必须能提供对应的能力：链式 UDP 要求目标出站能 `bind_udp`（例如目标是 `udp: true` 的 SOCKS5、Trojan、Hysteria2 等）。目标不支持时，经由它的 UDP 节点的该次连接失败，不会悄悄回退直连。
- 经 `bind_udp` 的数据报通道有界：每个方向队列 256 个数据报，最大 65535 字节，队列满时丢弃新数据报（UDP 语义，由上层协议重传），不拆通道。

## 校验

| 情况 | 结果 |
|---|---|
| 指向自己 | 整份配置失败 |
| 指向不存在的名称 | 整份配置失败 |
| 链成环（节点之间，或节点与策略组成员之间） | 整份配置失败，指出环上的名称 |
| 目标因不支持而被忽略（例如 `type: unknown-protocol`） | 该节点改为 REJECT 并警告，**不会**直连 |

## 测试

`oryn-config` 测试覆盖解析、多级链、经由策略组、三类环与「目标被忽略则拒绝」。独立对端测试：中转是 sing-box 的 SOCKS5 入站（带 UDP ASSOCIATE），终点是 sing-box 的 Trojan（TCP）与 Hysteria2（QUIC 的 UDP 经 SOCKS5 UDP 中转，数据报 3 / 1200 / 4000 字节）；中转消失后，经由它的节点全部不可用，没有流量直连。
