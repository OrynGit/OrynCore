# HTTPUpgrade

配置采用 `network: ws` 与 `ws-opts.v2ray-http-upgrade: true`；发送 GET / Host / Connection: Upgrade / Upgrade: websocket，校验 101、Upgrade 与 Connection 后切换裸字节流，不使用 WebSocket 帧。自定义 Host 替换默认 Host，禁止配置覆盖保留的握手 / 消息长度首部。

响应首部最多 32 KiB，握手不预读后续协议数据。沿用 path / headers 校验，不发送 WebSocket early data；使用 TLS 时 ALPN 只接受 http/1.1。Trojan / VLESS / VMess 共用该传输，与独立对端验证 TCP / UDP / select，真实 Engine 验证小请求和健康检查。
