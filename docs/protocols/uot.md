# UDP over TCP（UoT）

UDP 数据报经一条 TCP 流承载。线格式移植自 sing `common/uot`（v0.8.11），实现在 `oryn-outbound/src/uot.rs`，出处登记在 [Oryn_dev/docs/oryncore/provenance.md](../../../docs/oryncore/provenance.md)。使用者：AnyTLS（固定 v2，见 [anytls.md](anytls.md)）与 Shadowsocks（`udp-over-tcp`，v1 或 v2）。

## 线格式

| | v1 | v2 |
|---|---|---|
| 流的目标地址 | `sp.udp-over-tcp.arpa:0` | `sp.v2.udp-over-tcp.arpa:0` |
| 请求 | 没有 | `isConnect:u8` + socks5 地址 |
| 每包 | 地址族（`0` IPv4 / `1` IPv6 / `2` 域名，域名为长度 + 字节）+ 地址 + 端口 u16 + 长度 u16 + 载荷 | 相同 |

- Oryn 总是逐包寻址：v2 请求的 `isConnect` 写 0，地址为首个目标（对应 sing 的 ListenPacket），请求与第一个数据报合并写出。
- 双向帧格式相同。载荷最多 65535 字节；接收缓冲最多一个完整帧（65535 + 261 字节）。解析状态留在连接内，`recv_from` 被取消不丢字节；未知地址族、空域名关闭这条 UDP 会话。

## Shadowsocks

```yaml
- name: SS UoT
  type: ss
  server: example.com
  port: 8388
  cipher: aes-128-gcm
  password: secret
  udp: true                 # 必须同时为 true，false 时仍禁止 UDP
  udp-over-tcp: true
  udp-over-tcp-version: 2   # 1 或 2，默认 1
```

- 每条 UDP 会话用一条新的 SS TCP 连接，目标是上表的魔法地址，因此会经过节点配置的插件（ShadowTLS、obfs、v2ray-plugin）与 smux；这也是 ShadowTLS 节点上让 UDP 走同一承载的办法之一。
- 打开 `udp-over-tcp` 后不再使用 SS 的原生 UDP，服务端不需要独立的 UDP 入站。
- `udp-over-tcp-version` 不是 1 / 2 是整份配置失败；非 SS 节点写这两个字段时忽略并警告。

## 与 sing-box 的差异（行为，不是缺陷）

- v1 没有请求首部。sing-box（1.12.8 / 1.13.14）的 direct 出站不解析数据报里的域名，收到域名目标会关闭整条 UoT 流（sing 自己的客户端也是如此），所以 v1 与 sing-box 互通时只能发往 IP 目标。Oryn 的 UDP Flow 只向绑定时的目标发送，目标是 IP 时不受影响；目标是域名时，v1 与 sing-box 服务端不能互通（测试只覆盖 IP 目标）。
- v2 把首个目标放在请求里，首个目标是域名时由服务端解析，回包来源映射回该域名。之后单个数据报若带有与首个目标不同的域名，同样会被 sing-box 的 direct 出站关闭整条流。

## 测试

v2 线格式与 sing 的 `uot` 解析器逐字节核对（离线 Go 程序）；v1 与 v2 只差魔法地址与有无请求；单元测试覆盖碎片读取、取消、65535 字节帧与非法地址族。与 sing-box 1.12.8 / 1.13.14 互通：SS 入站的 v1（IP 目标）与 v2（IP 目标、以域名为首个目标）、AnyTLS 入站的 v2（IP 目标、8000 字节包、域名首个目标）。p2_engine 走 Engine 的 UDP 路径。
