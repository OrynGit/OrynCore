# Hysteria v1（`type: hysteria`）

实现在 `oryn-outbound/src/hysteria.rs`，线格式依据 sing-quic v0.6.1 的 `hysteria`（出处见 Oryn_dev/docs/oryncore/provenance.md）。QUIC 连接、Brutal、端口跳跃与套接字层混淆复用 `oryn-quic`（[quic.md](quic.md)）。

## 配置

`auth-str`（原始字节）或 `auth`（Base64），最多 1024 字节；`up` / `down` 必填（可带单位，或 `up-speed` / `down-speed` 以 Mbps 计），不低于协议下限 16384 字节/秒；`obfs` 为 XPlus 口令；`ports` / `hop-interval` 端口跳跃；ALPN 默认 `hysteria`。`protocol` 支持 `udp`、`wechat-video`（别名 `wechat`）和 `faketcp`。

`wechat-video` 已接入 QUIC 套接字层：每个 UDP 包增加固定 13 字节标识和递增序号；若同时设置 `obfs`，先应用 XPlus，再包裹 WeChat Video 首部。解析、坏包丢弃、IPv4/IPv6、端口跳跃和 QUIC 数据报仍受现有有界队列与重组预算限制。

`faketcp` 只做配置识别，没有实现：参考实现依赖 Linux 原始套接字与防火墙规则，Oryn 在所有平台都不支持。配置照常加载并给出警告，经该节点的连接返回 `hysteria faketcp transport is not implemented; use protocol udp or wechat-video`，不会退回普通 UDP 或 TCP。`obfs-protocol` 可作为 mihomo 兼容别名；`recv-window*`、`disable_mtu_discovery`、`fast-open` 等未实现字段仍忽略并警告。

## 线格式

- 控制流：每条 QUIC 连接先开一个双向流，写 ClientHello（版本 3、上行与下行字节/秒、认证），读 ServerHello（成功标志、服务端接收速率、消息）。Brutal 发送速率取 min(服务端接收速率, 本端上行)。控制流在连接存活期间保持打开。
- TCP：每个 Flow 一个双向流，请求（UDP 标志、主机、端口）与第一段数据一起写出，读取前先读响应（成功标志、会话 ID、消息）。服务端先说话的应用：读之前把请求单独发出。第一段数据的缓冲有上限。
- UDP：每个会话一个双向流（请求带 UDP 标志，响应里有会话 ID，流保持打开），数据走 QUIC 数据报：会话 ID、主机、端口、包 ID、分片序号与总数、长度、数据。超出数据报容量时分片；重组预算 128 KiB、每会话 4 个待重组包、等待 3 秒，最多 16 片。
- XPlus 混淆：每个 UDP 包前 16 字节随机盐，载荷与 SHA-256(口令 + 盐) 循环异或。

## 互通

sing-box 1.14 的 hysteria 入站：混淆开 / 关，TCP（含 70 KB 与 16 条并发）、UDP（含需要分片的 3000 / 8000 字节），错误认证。
