# Oryn 依赖修补

来源：snapview/tungstenite-rs，0.28.0，commit 2d4abe8dba23b283c1a3d2f4f4937c2f9a8d91e7，MIT / Apache-2.0。保留 LICENSE-*。

- src/handshake/client.rs：允许服务端不选择请求中的子协议，符合 RFC 6455 §4.2.2。代理 early data 复用 Sec-WebSocket-Protocol 时 sing-box 不返回该头。仍校验响应状态、Upgrade、Connection、Accept、未经请求与不匹配的返回子协议。

升级时运行 early data 默认头与自定义头互通测试；不降低其它 Upgrade 校验。
