# VMess

依据：[V2Fly VMess 公开规范](https://www.v2fly.org/developer/protocols/vmess.html)。认证使用 AEAD 命令密钥及嵌套 HMAC-SHA256 KDF；旧版 alterId 按 sing-vmess v0.2.7（commit 3a8da1e3baff96ba453501e0959863fec2c30977）的首个派生 ID 行为兼容。公开规范与参考行为有差异时，独立对端测试决定是否可声明支持。

- UUID 严格 16 字节；每次连接重新生成请求密钥、IV、响应认证字节与认证 nonce。
- AEAD、CFB、none / zero；CFB 与 MD5 仅用于历史协议兼容。`zero` 与 `none` 在线上相同：security 字节为 5（NONE），TCP 不分块、UDP 分块，与 sing-vmess 客户端一致（V2Ray 客户端同样把 zero 落成 NONE 并去掉分块）；不发送 6（ZERO），sing-vmess 服务端不接受 6。较新的 Xray / V2Ray 服务端已移除 NONE，`none` / `zero` 节点只能对接接受 NONE 的服务端（mihomo、sing-box 等）。
- 帧最大 65535 字节；每方向最多 65536 个 AEAD nonce，耗尽后必须断开，禁止重用 nonce。
- 读取状态保留在连接内，取消读取不能丢字节；写入最多缓存一帧，满载回压。
- 响应认证、长度、FNV、AEAD 标签必须验证；错误后连接不可继续。
- UDP 默认首目标绑定；packetaddr / XUDP 已与独立对端验证多目标往返；packetaddr 只接受 IP。

新增 md-5 / sha3 是规范要求的哈希，aes 与 crc32fast 已存在于依赖树。不会引入线程或全局缓存；静态大小及 RSS 在工作包验收时记录。独立对端通过 AEAD / 旧版、五种 cipher、四种传输与可选标志矩阵。认证负例覆盖错误 UUID、过期时钟、截断与首部破坏；AEAD 重放被对端过滤。参考服务端旧版路径不做重放过滤且跳过命令头 FNV 校验，Oryn 客户端不能保证旧服务端的抗重放；本机负例对旧版破坏版本字节，负载 FNV / AEAD 标签在 Oryn 读取侧仍验证。
