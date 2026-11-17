# Mekya HTTP 外层

Mekya 是 VMess mKCP 的 HTTP 外层承载。每个上传批次由一个或多个 `u16` 大端长度前缀 packet 组成，不能把 HTTP 字节直接交给 mKCP 解析器。Oryn 使用有界 channel、请求尺寸、写延迟和并发写连接；请求失败会向 KCP Flow 传播，不会静默改走裸 UDP。

HTTP/1.1 批次使用有限 `Content-Length` POST，HTTP/2 批次使用独立请求流；TLS ALPN 为 `h2` 时选择 HTTP/2，否则选择 HTTP/1.1。每批次复用同一个 `X-Session-ID`，响应中的 bundle 按 packet 边界拆分后交给同一 mKCP 状态机。URL 省略时由节点服务器地址补成 `https://<server>/`。

```yaml
network: mekya
tls: true
mekya-opts:
  url: https://cdn.example.com/mekya
  max-request-size: 65536
  max-write-delay: 50
  max-simultaneous-write-connections: 2
  packet-writing-buffer: 256
  kcp:
    mtu: 1350
    tti: 50
    header: none
```

Mekya 目前从 StreamProxy 的 Dialer 和 TLS 路径拨号，使用有限 HTTP/1.1/HTTP/2 请求；固定 mihomo v1.19.32 对端的 2 项测试已通过，覆盖 H1/H2、seed/header、bundle 编码、响应分块、下行轮询、取消与队列回压。mihomo 完整请求调度、连接池恢复、随机 header 分布和 VMess UDP 组合仍需独立对端矩阵验收。
