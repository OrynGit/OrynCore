# VLESS Encryption

实现：oryn-protocol/src/vless_encryption.rs。对照 Xray 26.3.27 的完整客户端握手；出处与许可见 Oryn_dev/docs/oryncore/provenance.md。

## 配置

VLESS 节点新增 encryption（空或 none 表示不启用）：

    encryption: mlkem768x25519plus.native.1rtt.<服务端公钥>

- 模式：native、xorpub、random。xorpub 对 NFS 公钥 / 密文作 AES-CTR 变换；random 另对记录首部作连续 AES-CTR 变换。
- 握手：1rtt、0rtt。0rtt 首次仍完整握手，服务端返回有效票据后才能复用；每出站只保存一张票据，重载时清除，不持久化到磁盘。
- 公钥：1–8 个，以点号分隔；无填充 URL-safe Base64，解码后为 X25519 32 字节或 ML-KEM-768 1184 字节。ML-KEM 公钥做模数校验，X25519 握手拒绝低阶点。
- 可选 padding：公钥前插入“概率-最小值-最大值”，长度、间隔（毫秒）交替，最多 16 项。第一项概率必须 100，长度至少 35；总长度最多 65553 字节，总间隔最多 3000 毫秒。省略沿用 Xray 默认分布。
- App 编辑器的 Encryption 字段、配置持久化及 vless:// 的 encryption 参数保持同样字符串和校验。
- 当前不支持 Encryption 与 Vision 同时启用，配置时明确报错。普通 TCP、TLS、WebSocket/WSS、gRPC 组合已与 Xray 实测。

## 线格式与密钥

1. 客户端发送 16 字节 IV，随后发送 NFS relay 链（每个 X25519 relay 32 字节，ML-KEM relay 1088 字节，相邻 relay 间含下一个公钥的 BLAKE3 摘要和 CTR 绑定）。
2. 用最后一个 NFS 共享密钥派生握手 AES-256-GCM key：BLAKE3 derive-key，context 是原始 IV 字节。采用 vendored blake3 的安全字节上下文 API，不把随机字节强转为 UTF-8。
3. 完整握手的客户端 PFS 公钥为 ML-KEM-768 公钥 1184 字节 + X25519 公钥 32 字节；加密长度占 18 字节，公钥密文占 1232 字节，随后为加密 padding 长度及 padding。
4. 服务端 PFS 密文固定 1136 字节，使用全 FF nonce；认证通过后再进行解封装，得到 ML-KEM 32 + X25519 32 + NFS 32 共 96 字节联合密钥。
5. 上下行 AEAD 的 BLAKE3 上下文分别是客户端和服务端的 PFS 公开交换数据。服务端另发送加密票据及 padding。敏感材料使用 zeroize 清理。
6. nonce 为 96 位大端计数器，先递增再使用（首条为 1）。按 Xray 规则在回绕记录后以该条完整记录派生新密钥；有专门测试覆盖。
7. 数据记录为 5 字节 TLS application-data 形状首部（23,3,3,length）+ AES-GCM 密文/tag，未混淆首部参与 AAD。

## 生命周期与上限

每次写最多接收 8192 字节；缓冲只有一条待发记录，背压由 AsyncWrite 传播。接收密文记录上限 16640 字节，错误首部、认证失败、截断后关闭该方向。取消读取会保留首部、密文进度。完整握手最多 65535 字节服务端 padding，所有握手受出站 10 秒超时控制。

0-RTT 每次仍生成新的 NFS 共享密钥；票据过期或服务端拒绝时清除缓存。拒绝时当前 Flow 失败，下一 Flow 完整握手，不自动重发已发送的应用数据。用户选择 0rtt 才启用票据复用。

数据链路：Dialer → Security → Transport → Encryption → VLESS。VLESS UUID/目标地址等首部在 Encryption 建立后发送，不会作为明文 WS early data 发出。

## 验证

- Xray 26.3.27（commit d2758a023cd7f4174a5a5fa4ff66e487d4342ba0），本机源码编译，仅监听 127.0.0.1。
- 3 种模式 × 3 组 NFS 密钥（X25519、ML-KEM、X25519→ML-KEM→X25519）× 2 种握手，覆盖 TCP 1 / 8192 / 131073 字节、半关闭、UDP 1 / 1200 / 8190 字节。每种 0rtt 组合都明确检查首次完整、后续复用。
- 默认/自定义 padding、错误密钥、Xray 重启后票据失效及下次完整握手。
- 真实 Outbound：TCP、WS、TLS、WSS、gRPC。真实 Engine：策略组、健康检查、UDP 和 8 条并发 TCP；本机 RSS 增量约 1.61 MiB（调试进程趋势，不代表 iOS）。
- 独立 Go BLAKE3/AES-GCM 二进制上下文向量、篡改、超长/截断记录、单字节背压、nonce 回绕换钥、取消读、过期票据等单元测试。

对端限制：此版 Xray 的 VLESS UDP 会把超过 8192 字节的入包拆为多个转发数据报，返回路径上限 8190 字节；不能据此宣称大 UDP 包完整互通。Encryption 字节流本身的大记录已通过 TCP 测试。
