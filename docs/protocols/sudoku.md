# Sudoku

参考 mihomo v1.19.32（88dcbf7f1614a67c3b36b848ee3592dfa92ada36），来源台账见 [Oryn_dev/docs/oryncore/provenance.md](../../../docs/oryncore/provenance.md)。

## 数据路径

Rust Outbound → KIP / AEAD → Sudoku 编码 → raw / HTTPMask → Dialer。UDP Flow 在同一个加密流上使用 StartUoT 与逐包地址、长度；目标域名在发送前经普通 Resolver 解析为 IP，代理服务器域名由 Dialer 的代理 Resolver 解析。不会创建本地 SOCKS 入站。

支持 chacha20-poly1305、aes-128-gcm、none；PSK 字符串、32 字节压缩 Ed25519 公钥、32 字节主标量与 64 字节 split 私钥（十六进制）按 mihomo 的优先级规范化。随机密钥和 nonce 使用系统随机源；Go math/rand 仅用于兼容编码表的排列。

KIP ClientHello 携带时间、user hash、nonce、X25519 临时公钥、特性和表提示；服务器回复 nonce 和公钥之后，用 HKDF 的会话方向密钥替换 PSK 方向密钥。AES/ChaCha 记录格式为 u16 长度 + epoch:u32 + seq:u64 + AEAD 密文；epoch/seq 同时作为 nonce 和 AAD，校验顺序和重放，每 32 MiB 轮换 epoch。none 保持上游明文记录语义，不提供 AEAD 认证或加密。

## 编码表

ASCII / entropy、两种上下行异构布局、custom-table/custom-tables 均支持。pure 下行使用四提示数独编码；packed 下行使用 6 位打包与 marker 对齐。始终发送合法 table hint，解决上行 ASCII 无法区分多个 entropy 下行表的问题。表最多 8 个，按节点懒创建、共享 288 网格映射；每字节最多保留 8 个合法谜面，线格式兼容但编码分布不保证与 Go 完全一致。

padding 是 0–100 的插入比例。仅提供 min/max 中一个时遵循 mihomo 自动夹齐另一个默认值；两个都指定且 min > max 则报错。

## HTTPMask 与复用

支持关闭、legacy、ws、stream、poll、auto，以及 HTTPS 和 path-root。stream/poll 在 /session 的 ed 参数中发送编码后的 KIP ClientHello，读取 token、upload-seq 能力和 ed 响应；上传使用递增 seq，重试沿用相同序号。下行消费有界 HTTP/1.1 chunked 及 EOF trailer，poll 使用 Base64 行。auto 先试 stream，失败后改试 poll；不自动退回裸连接。WS 使用 HMAC Bearer/query auth，握手在升级后完成，不强制 WS early-data 优化。

multiplex:on 使用 Sudoku 自有 9 字节帧头（类型/u32 stream ID/u32 长度）在共享加密会话内承载多条 TCP Flow；UDP 仍使用独立 UoT 会话。auto 仅复用允许 keep-alive 的 HTTP 连接，不启用会话复用。HTTP/2 承载未实现，HTTPS ALPN 固定 http/1.1；通用 TLS 指纹/Reality 不作为 Sudoku 专用配置开放。

## 上限与生命周期

每节点最多 32 个活跃 Flow。发送 AEAD 明文分段 4096 字节；接收兼容 u16 最大记录长度。复用每流入队 4 × 16 KiB、公共发送队列 32 条，最大复用帧 256 KiB；队列满背压，慢读可能阻塞同会话其它流。HTTP 头 16 KiB、单行 4 KiB（Base64 行 64 KiB）、分块 1 MiB 但每次只读取 4096 字节、HTTP 空闲池 8 条、关闭请求同时最多 8 条且限时 1 s。UDP 载荷最多 8192 字节。

网络切换/睡眠取消旧流、共享会话并清空 HTTP 空闲池；唤醒后重建。关闭逻辑流、超时或取消归还 Flow 名额；所有后台读取/写入都归属于连接或会话。测试与已知差异见 [changelog-sudoku-shadowquic.md](../../../docs/oryncore/changelog/changelog-sudoku-shadowquic.md)。

## HTTPMask 上传批量

stream / poll 的上传每个 POST 要等响应，服务端要求 `seq` 严格递增、不接受乱序（`409 sequence gap`），所以只能串行。上行吞吐 = 每批字节数 ÷ 一次请求的耗时，批越小越被往返时延拖住：原来每个 POST 最多 16 KiB，且请求头与主体分两次写出；真机（往返 5.5 ms，`multiplex: off` 即每个请求一条新 TCP 连接）上只有 1 Mbit/s。现在与 mihomo 客户端一样，上一个 POST 等响应期间应用写入的数据在桥里累积，下一次一次取走，最多 64 KiB 一批（poll 模式每行最多 16 KiB 原文的 Base64），请求头与主体合成一次写出。应用到隧道的桥容量同为 64 KiB，每条隧道多占 64 KiB 缓冲。

## 吞吐与 CPU

千兆吞吐报告里 Sudoku 下载约 150、上传 70–90 Mbit/s，每传 1 GiB 要 81 秒 CPU。主机采样（`no-httpmask`）里活跃时间的前几位是：解码里每 4 个线上字节一次的 `unique`（四个提示位集合求交）、`Security::feed` 的逐字节解码循环，以及编码里每次调用都向系统取 256 字节随机数的 `getentropy`。两处改动，尚未测量：

1. `Table::encode` 改用线程本地 CSPRNG（`rand`），不再每次调用 `getentropy`，也不再「每个决定取一个字节再取模」。
2. `unique` 固定 5 个字（288 个网格），去掉迭代器与提前返回分支，让编译器展开。

编码本身仍是每个明文字节展开成 4 个线上字节，这是线格式决定的，CPU 上限不会消失。HTTPMask `poll` / `stream` 的上传是协议本身的「一个 POST 等一个响应」（与 mihomo 一样每批最多 64 KiB，见 `UPLOAD_BATCH`），吞吐受往返时延限制，只能靠 `multiplex` 让多个隧道并行，不是实现缺陷。

第二轮（同日）：上传相位的采样里，从 ChaCha 逐次取随机数（每个明文字节 6 次以上）比编码本身还重。填充长度、谜面选择、提示顺序只是线上形态的随机化，不是密钥材料（mihomo 用 math/rand），`Table::encode` 改为每次调用从线程本地 CSPRNG 取一个种子，再用 xoshiro（`rand` 的 `small_rng` 特性，不增加依赖）取数。第一轮改动的主机 A/B：下载 170–270 → 210–445，上传 105–134 → 97–126（无可分辨的变化，所以才有这一轮）；这一轮尚未测量。

