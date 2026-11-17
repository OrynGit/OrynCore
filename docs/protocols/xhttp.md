# XHTTP / SplitHTTP

Oryn 已接入有界的 `stream-one`、`stream-up`、`packet-up` 和 `auto`。当前承载使用 TLS 上的 HTTP/2 连接池；每条连接最多 32 个流、连接池最多 4 条连接，空闲连接约 30 秒回收。`reuse-settings` 还可以进一步限制并发、连接数、请求次数、复用次数和连接寿命，所有值在配置阶段有上限。

`stream-one` 在一条 POST 请求上承载双向字节流。`stream-up` 先建立独立 GET 下载流，再用同一个 session 建立上传流；`download-settings` 可以提供独立 host、path 和 headers。`packet-up` 使用独立 GET 下载，上传按 `x-seq` 递增顺序提交 POST，同时在途最多 `min(sc-max-buffered-posts, 8)` 条（服务端按序号重排，Xray 默认最多缓存 30 条乱序请求）；在途满时通过回压让写等待，任何一条 POST 失败都会结束当前 Flow 的上传、读和后续写。`flush` 与 TCP 一样不等待确认，`shutdown` 等所有块被确认；建立 Flow 时的协议首部会等到服务端确认，所以首个 POST 被拒绝时返回的是连接错误。串行等待每个响应时单流上传只有「每往返一块」，在 20 ms 往返下约 6 Mbit/s；流水线后同一条件下 4 MiB 只需 0.24 s（对比 6.5 s，`h2pool` 的延迟链路回归测试）。`auto` 遵循 mihomo 的安全条件：Reality 无下载端时选 `stream-one`，Reality 带下载端时选 `stream-up`，普通 TLS 选 `packet-up`。

```yaml
network: xhttp
xhttp-opts:
  path: /xhttp
  method: POST
  mode: auto
  headers:
    Host: [cdn.example.com]
  no-grpc-header: false
  x-padding-bytes: 100-1000
  x-padding-obfs-mode: false
  x-padding-placement: queryInHeader   # queryInHeader/header/query/cookie
  x-padding-method: repeat-x           # repeat-x/tokenish
  uplink-http-method: POST
  uplink-data-placement: body          # body/header/cookie/auto
  uplink-data-key: data
  uplink-chunk-size: 16384
  session-placement: path              # path/query/header/cookie
  session-key: x_session
  seq-placement: path
  seq-key: x_seq
  sc-max-each-post-bytes: 65536
  sc-min-posts-interval-ms: 0
  session-table: hex
  session-length: 16
  sc-max-buffered-posts: 16
  download-settings:
    host: [download.example.com]
    path: /down
    headers:
      X-Download: ok
  reuse-settings:
    max-concurrency: 16
    max-connections: 2
    c-max-reuse-times: 1000
    h-max-request-times: 10000
    h-max-reusable-secs: 3600
```

默认 padding 使用 `Referer` 中的 `x_padding` 查询参数；obfs 模式可以改放在 header、query 或 cookie。packet-up 的 body 数据保持二进制，header/cookie 使用无填充 URL-safe Base64，body 方式按 `sc-max-each-post-bytes`（默认 64 KiB，上限按块 64 KiB 截断）分块，header / cookie 方式按 `uplink-chunk-size` 与它的较小值分块。Session/Seq 的 body placement 会在配置阶段拒绝，避免被静默忽略。

对照固定 mihomo v1.19.32 确认 payload 不支持 query/path；此前接受 query 并发送空 body 的行为已删除，配置层及运行时均明确拒绝。Session/Seq 的 query 仍支持，两者不可混淆。见 [协议审查](../../../docs/oryncore/audits/protocol-reference-audit-mihomo-round2.md)。

当前 XHTTP 运行时明确限制为 HTTP/2；HTTP/1.1、HTTP/3、独立下载 TLS 安全配置以及完整 Reality 组合矩阵不在这一有界实现内。固定 mihomo v1.19.32 对端的 3 项测试已通过，覆盖模式矩阵、padding、Session/Seq、独立下载、请求轮换和 reuse；真实长时运行、取消和 4xx/5xx 仍需继续验收。

## 上行吞吐

千兆吞吐报告里 gRPC / h2 / XHTTP 上行只有下行的 60–85%。h2 每条流的发送缓冲从 32 KiB 提到 128 KiB（`SEND_BUFFER`，h2mux 同），单次写入从 16 KiB 提到 64 KiB（`WRITE_CHUNK`）：真机上 xray gRPC 上行 360–570 → 700–870（DIRECT 同一轮 ~895），sing-box gRPC 无可分辨的变化。

packet-up 曾加过「在途 POST 满时合并写入」，**已撤销**：主机 6 ms 往返下单流上行 285 → 245、4 流 1300 → 1230，真机上 packet-up 上行 302→246、327→169 也没有改善，反而更差。packet-up 上行没有被在途数 × 块大小限制，瓶颈在别处，尚未查清。
