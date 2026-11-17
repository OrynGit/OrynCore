# ShadowQUIC / JLS v3

参照 mihomo v1.19.32 及其固定 jls-tls / jls-quic-go 版本，见 [Oryn_dev/docs/oryncore/provenance.md](../../../docs/oryncore/provenance.md)。

## 认证

JLS 在 TLS 1.3 ClientHello / ServerHello 的 random 中携带认证结果：将包含 TLS 握手头的完整 Hello 的 random 清零（ClientHello 还将 PSK binder 清零），以 SHA-256(password + hello) 为 AES-256 密钥、SHA-256(username + hello) 为 **32 字节 GCM nonce**，加密 16 字节随机种子得到 32 字节认证 random。禁止 HRR / ECH / 浏览器定制叠加。

vendored rustls 使用默认 None 的专用钩子，在 transcript 和 PSK binder 计算前生成 ClientHello random，同步引擎状态；原始 ServerHello 必须先通过 JLS，再进入证书处理。只有 JLS 专用配置使用认证 random 代替证书链/签名校验，TLS Finished 和 transcript 验证保持不变。普通 TLS 不进入该分支；错误凭据、普通 TLS 对端不能降级通过。

zero-rtt 默认 false。开启后只使用该节点独立持有的单张已认证票据，缓存不落盘、不跨节点共享；重连早期请求被拒绝时重开 1-RTT 流。测试会实际断言服务端接受 early data，不用配置/解析测试替代。

## 代理请求

TCP：每条 QUIC 双向流写入 0x01 + SOCKS5 地址，随后转发字节流。UDP：双向控制流写 0x03（DATAGRAM）或 0x04（单向流）+ unspecified SOCKS5 地址；后续地址 + u16 ID 注册该连接内的方向上下文。DATAGRAM 为 u16 ID + 载荷；UDP-over-stream 为单向流首 u16 ID，然后重复 u16 长度 + 载荷。未知 ID 的少量数据可暂存等待控制流，严禁无限映射/缓存。

客户端 DNS、链式代理、会话重建使用 Oryn 原有 Resolver、DatagramFactory、QuicClient；每条 Flow 只路由一次。up/down 使用 mihomo 私有 Brutal 带宽扩展，支持协商失败继续使用普通拥塞控制。Oryn Brutal 沿用现有固定速率实现，不声称与上游丢包补偿行为相同。

## 支持边界

- QUIC v1（mihomo 默认）支持；当前 quinn-proto 不实现 v2。仅 v2 的节点被忽略并警告，混合 v1/v2 列表明确警告后使用 v1，不伪造 v2。
- CUBIC / NewReno / 标准 BBR 及初始 cwnd 支持。BBR conservative/aggressive 暂未实现，配置警告后使用标准 BBR；不是静默等价。
- 每节点最多 32 条 Flow，导入的更大 max-open-streams 夹到 32 并警告；每流接收窗口最多 256 KiB、连接接收窗口最多 1 MiB，夹值警告。默认 64 KiB / 512 KiB，发送窗口 256 KiB。
- UDP 每关联最多 32 个目的地址；全连接最多 256 个发送/接收上下文；未知 ID 总共最多 8 包/64 KiB、2 s 到期；每关联队列 8 包；接收单向流任务最多 32 个。
- UDP-over-stream 负载最多 8192 字节；DATAGRAM 无分片，受协商 MTU / max-datagram-frame-size 限制，过大的包明确报错。
- JLS 的底层加密和普通 TLS 的证书校验是不同语义；不接受 skip-cert-verify 作为关闭 JLS 认证的开关。
- 网络切换和睡眠关闭旧 QUIC 连接；唤醒/下一条 Flow 重建。票据可跨同节点连接使用，凭据不进入日志。
