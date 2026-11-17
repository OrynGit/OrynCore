# Shadowsocks 插件（SIP003）

插件只改变「到 SS 服务器的 TCP 字节流」，SS 自己的加密与分帧不变，所以实现为 SS 出站下面的一层 `Dialer`（`oryn-outbound/src/ss_plugin.rs`）。同一节点只能有一个插件。SS 的原生 UDP 不经过插件（与 ShadowTLS 相同）；需要 UDP 走同一条 TCP 时用 [uot.md](uot.md) 或 smux。

| `plugin` | 支持 | 说明 |
|---|---|---|
| `shadow-tls` | v1 / v2 / v3 | 见 [shadowtls.md](shadowtls.md) |
| `obfs` / `simple-obfs` | `mode: http` / `tls` | 本文 |
| `v2ray-plugin` | `mode: websocket`，可加 TLS 与 Mux.Cool | 本文 |
| `gost-plugin`、`restls`、`kcptun`、其它 | 不支持 | 跳过节点并警告 `unsupported plugin` |

## simple-obfs（`obfs`）

线格式依据 simple-obfs 的行为，参照 sing-box `transport/simple-obfs`（源自 Dreamacro/clash，GPL-3.0）；移植文件的出处登记在 [Oryn_dev/docs/oryncore/provenance.md](../../../docs/oryncore/provenance.md)。实现在 `oryn-transport/src/obfs.rs`。

- `plugin-opts.mode`：`http`（默认）或 `tls`；其它值整份配置失败。`host` 缺省 `bing.com`（与 sing-box 一致），不含空白与控制字符，最长 253 字节。
- HTTP：第一次写出把 SS 首包作为请求体，伪装成带 `Upgrade: websocket` 的 `GET`；第一次读取先跳过响应首部（最多 16 KiB，超过视为不是 simple-obfs 服务端）。之后是裸字节流。
- TLS：第一次写出把 SS 首包放进伪造 ClientHello 的 session ticket 扩展；之后每次写出是一条 TLS 应用数据记录（每条最多 16 KiB）。读取时先跳过 ServerHello（96 字节）与 ChangeCipherSpec（6 字节）这两条固定大小的记录，之后逐条解记录。没有真正的 TLS 握手，也不校验证书。

## v2ray-plugin（`v2ray-plugin`）

| `plugin-opts` | 默认 | 说明 |
|---|---|---|
| `mode` | `websocket` | 只支持 websocket；`quic` 等跳过节点并警告 |
| `tls` | false | 打开后用 `oryn-tls`，ALPN 固定 `http/1.1`；SNI 取 `host`，未配置时取服务器地址 |
| `host` | 空 | 非空时作 WebSocket `Host` 首部，同时是 TLS 的 SNI |
| `path` | `/` | 必须以 `/` 开头 |
| `headers` | — | 附加的 WebSocket 请求首部，规则同 `ws-opts.headers` |
| `mux` | true | V2Ray Mux.Cool，见下（与 mihomo 相同，缺省开启；App 生成的配置总是显式写出） |
| `fingerprint`、`skip-cert-verify` | — | 沿用现有 TLS 语义（叶证书 SHA-256 固定；跳过系统信任校验） |
| `v2ray-http-upgrade` | — | 不支持，整份配置失败 |

WebSocket 部分复用 [websocket.md](websocket.md) 的实现与上限，不发送 early data。

### Mux.Cool 的单会话封装

`mux: true` 时 SS 的每条 TCP 连接都在自己的 WebSocket 里作为**一个 Mux.Cool 会话**，不做多路复用；这样做只是为了与启用了 mux 的 v2ray-plugin 服务端兼容，没有复用连接带来的省握手收益。帧格式依据 V2Ray Mux.Cool 规范，参照 sing-vmess `mux_wrapper.go`，出处登记在 Oryn_dev/docs/oryncore/provenance.md；实现在 `oryn-outbound/src/muxcool.rs`。

- 写出：第一帧是 New（会话 0、TCP、目的地 `v1.mux.cool:666`，随帧带上首批数据），之后每帧是 Keep，每帧载荷最多 16 KiB。
- 读取：解析帧首部，Keep 帧的数据交给调用方，End 为 EOF，带 Error 选项的帧表示对端关闭连接；KeepAlive 帧忽略；元数据长度不在 4–1024 字节内则关闭连接。

## 测试

- 本机没有 simple-obfs 与 v2ray-plugin 的服务端，所以测试里独立写了两个插件服务端：读写与 simple-obfs 一致的 HTTP / TLS 伪装、以及 v2ray-plugin 的 WebSocket（±TLS，±Mux.Cool 解帧），后接 sing-box 的 SS 入站。它们是按线格式单独实现的，不复用被测代码，但仍然是同一个人写的，与真实 simple-obfs / v2ray-plugin 服务端的互通**没有**验证。
- 覆盖：`obfs` 两种模式、`v2ray-plugin` 的 TLS × mux 四种组合，每种 70000 字节往返与连续 3 条新连接。
- 单元测试覆盖拆包读取、取消读取不丢字节、超长响应首部、畸形记录与 Mux.Cool 的元数据上限。

## gost-plugin

`plugin: gost-plugin`，`plugin-opts` 与 v2ray-plugin 相同（`mode` 只支持 websocket，`tls`、`host`、`path`、`headers`、`mux`（默认 true）、`fingerprint`、`skip-cert-verify`）。WebSocket ± TLS 与 v2ray-plugin 共用；`mux: true` 时在 WebSocket 上建立一个 smux v1 会话、只开一个流，流关闭时会话随之关闭（与 mihomo `transport/gost` 相同），实现为 `oryn-outbound/src/mux.rs` 的 `smux_single`。

互通：gost v2.12.0 的 `ss+ws`、`ss+mws`、`ss+wss`、`ss+mwss` 服务端，70000 字节往返与连续新连接。
