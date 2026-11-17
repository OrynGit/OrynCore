# WebSocket 传输笔记

依据 RFC 6455，客户端 framing / Upgrade 复用 MIT tokio-tungstenite（关闭默认 TLS，TLS 由 oryn-tls 提供）。

把二进制消息适配成 AsyncRead / AsyncWrite；客户端掩码、分片、ping/pong、close 由库处理。读缓冲 8 KiB，消息 / 帧 64 KiB，写分块 16 KiB，有界写缓冲；拒绝文本数据。Upgrade 验证 accept 与状态码，不把任意 HTTP 响应当作字节流。path 的 ed 查询参数编译为 early-data 上限；Trojan 上限不足 56 时禁用 early data 保持认证头完整。early data 将协议请求前缀放到指定请求头，使用 URL-safe Base64 无填充，剩余通过 WS 帧发送。

互通核对 sing-box transport/v2raywebsocket/server.go、conn.go（v1.12.8）；未移植其代码。tungstenite 的子协议可不被服务端选中修补符合 RFC6455，见 Oryn_dev/docs/oryncore/provenance.md。
