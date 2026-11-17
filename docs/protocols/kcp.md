# mKCP / VMess KCP

Oryn 的 mKCP 适配层现在使用 mihomo/Xray 的大端线格式：16 位 conversation、DATA/ACK/PING/TERMINATE 命令、绝对接收窗口、乱序重排和有限 RTO 重传。发送缓存、接收缓存、选择性 ACK（最多 128 项）和坏包计数都有上限；连接关闭时不会把超限数据继续留在队列中。

`seed` 非空时使用 `SHA-256(seed)[0..16]` 作为 AES-128-GCM 密钥，包内带随机 12 字节 nonce 和标准 16 字节 tag。没有 seed 时使用 mihomo 风格的 FNV-1a 长度认证与有界异或扰动。header 支持 `none`、`srtp`、`utp`、`wechat`/`wechat-video`、`dtls` 和 `wireguard`；`wechat` 在配置编译时归一化为 `wechat-video`。

裸 mKCP 通过 UDP 建立，要求外层 `security: none`。`mekya-opts` 是单独的 HTTP 外层：VMess 的每个上传批次用 `u16` 大端长度加 packet，HTTP/1.1 使用有限 `Content-Length` POST，HTTP/2 使用独立请求流；TLS ALPN 由拨号结果选择。Mekya 的上传请求大小、延迟、并发写连接和 channel 都有限制。

```yaml
network: kcp
kcp-opts:
  mtu: 1350                 # 576–1500，默认 1350
  tti: 50                   # 10–500 ms
  uplink-capacity: 5        # MB/s
  downlink-capacity: 20     # MB/s
  congestion: false
  write-buffer-size: 2097152
  read-buffer-size: 2097152
  header: wechat-video      # none/srtp/utp/wechat/dtls/wireguard
  seed: optional-secret
```

```yaml
network: mekya              # VMess；外层必须 TLS
mekya-opts:
  url: https://cdn.example/mekya
  max-request-size: 65536
  max-write-delay: 50
  max-simultaneous-write-connections: 2
  kcp:
    mtu: 1350
    header: none
```

`network: kcp` 在 VLESS/Trojan 中仍作为 Oryn 扩展入口并发出警告；mihomo 兼容入口是 VMess。当前实现已覆盖本机线格式向量、AES-GCM 向量、乱序/ACK 和 HTTP bundle 测试；固定 mihomo v1.19.32 对端的 4 项测试已通过，覆盖六类 header、seed、低 MTU、丢包/乱序/重复、shutdown 和错误 seed。更长时间的丢包恢复、各 header 的随机字段分布以及 VMess UDP 组合仍需单独验收。

## 吞吐报告里的 mKCP

千兆吞吐报告里 mKCP 单流下载 10–25 Mbit/s，4 流 37–51。主机上用 mihomo 自带客户端对同一服务端量：缺省容量的 `mkcp-none` 70、容量放开的 `mkcp-none-seed` 574 Mbit/s，说明服务端没问题，是 Oryn 接收端的问题。主机采样（`sample`）显示进程几乎全在等待，不是 CPU 受限；加计数器后看到每秒 7–10k 个数据报到达，其中约一半因为「落在窗口外」被丢弃，另有重复段，丢掉的靠对端超时重传，实际有效吞吐只有三成。原因与改动：

1. **确认合并。** 原来每个数据报回两个确认（收到时一个带选择确认列表、累计前进后又一个），对端（Go 实现里每个确认要遍历整个在途窗口）忙于处理确认而不是发数据。现在像 mihomo / xray 的客户端一样把确认攒起来：累计 16 个数据报或等 2 ms 发一个累计确认加乱序列表；安静 8 ms 之后的第一个数据报仍立即确认，请求 / 应答的延迟不受影响。
2. **按通告过的窗口收包。** 原来用「当前剩余信用」判断是否收下，读端稍慢、信用缩小时，窗口内早已在路上的包被大量丢弃。现在记录已经通告给对端的窗口上界（只增不减），在它之内的新包都收下；乱序缓存与待读队列各自仍不超过一个接收窗口，内存有界。
3. **接收窗口按容量算。** 对端的发送窗口是「容量 × tti」，并且每个 tick 最多发出它的 20 倍；本端窗口比它小，窗口外的包只能丢弃重传。接收窗口去掉「缓冲的一半」和 1024 段上限，改为 `min(缓冲 ÷ 段长, 容量窗口)`、上限 4096 段；缺省配置下仍是 ~776 段，与之前一致。发送窗口保持原样（没有拥塞控制时窗口越大突发越大）。
4. **UDP 接收缓冲。** 所有直连 UDP 通道（`oryn-udp`）的接收缓冲放大到 2 MiB（系统缺省约 256 KiB，装不下对端一个 tick 的突发）；发送缓冲保持缺省，放大后没有拥塞控制的发送端会一口气发满窗口，上传反而更慢。
5. 选择确认列表排序后二分查找（原来线性查找，在途窗口最多 1024 段）。

主机 A/B（同一服务端，Mbit/s，往返约 1 ms，机器有其它负载，数据有 ±30% 的波动）：缺省容量 `mkcp-none` 单流下载 16–25 → 63–82、4 流 52–94 → 369–410；容量放开的 `mkcp-none-seed` 单流 10–25 → 49–65、4 流 15–45 → 207–392（最后一轮：投递修复之后）；上传无可分辨的差别（±30% 波动）。仍低于 mihomo 自带客户端（574），差距还没有查清。确认合并之后 TCP 小包往返（`rtt64`）一度从 ~1 ms 变成 ~4 ms（确认延迟为 0 时反而 ~28 ms），事件追踪显示原因是一个早就存在的延迟：由乱序缓存前进到待读队列的数据要等**下一个事件**才推给读端（推送在顺序前进之前），原来每个数据报回两个确认、对端的确认和 ping 很快带来下一个事件，掩盖了它；确认变少之后下一个事件是 50 ms 后的 tick。现在顺序前进之后立即再推一次，并加一个「读端腾出通道空位就醒来」的分支（顺带解决读端慢时窗口迟迟不更新）。修复后 `rtt64` 回到 0–1 ms。

测试台里除 `mkcp-none`（保留缺省作基线）外，服务端与客户端都设 `uplink-capacity` / `downlink-capacity` 100 MB/s，客户端读写缓冲 8 MiB（Oryn 的 `read-buffer-size` / `write-buffer-size` 单位是字节，xray 系是 MB，写错单位会被拒绝）。

注意：服务端 mihomo 的 mKCP 在被大流量冲击之后会卡住（所有新连接都报 `mKCP flush failed`），测试时需要重启容器。

## 丢弃流时通知对端

真机上 mKCP 第一个高速节点之后，同一台服务端的新连接全部 `mKCP flush failed`（主机上也能复现，重启容器才恢复）。`KcpStream` 被丢弃时原来直接中止后台任务、什么都不发，对端带着整个发送窗口（缺省 ~1.5k 段）一直重传到 30 秒空闲超时，高速测试留下的这些僵尸会话把服务端拖住。现在丢弃时先通知后台任务给对端发两个 Terminate 再退出，500 ms 后兜底中止（任务卡住也不会泄漏）。

