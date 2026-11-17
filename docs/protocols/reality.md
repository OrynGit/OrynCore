# Reality 协议笔记

参考 SagerNet/sing-box common/tls/reality_client.go @ 573c6179ab4fc1b9ecb8f049299bb1dfe8babc97（GPL-3.0-or-later，见文件头与 Oryn_dev/docs/oryncore/provenance.md），以及 XTLS/REALITY 的 TLS 1.3 认证方式。

ClientHello session ID 为 32 字节：加密前 16 字节为 version [1,8,1,0]、时间戳 u32 BE、short-id [8]。TLS X25519 私钥与配置服务器公钥共享秘密，用 HKDF-SHA256（salt=random 前 20 字节，info=REALITY）导出 32 字节 authKey。AES-256-GCM nonce=random 后 12 字节，AAD 为含零 session ID 的完整 ClientHello 握手编码（包括握手头），密文 16 字节 + tag 16 字节替换 session ID。

服务端临时 Ed25519 证书 signature 必须等于 HMAC-SHA512(authKey, Ed25519 public key)；仍验证 TLS CertificateVerify / Finished。普通网站的合法证书也不能代替 Reality 认证。失败关闭，不做 HTTP fallback 探测。

连接禁用会话复用 / early data，避免认证绑定跨连接。Reality 只使用 TLS 1.3，不处理 HRR；相同 TLS X25519 key share 必须是实际可完成的密钥交换，不能替换成无私钥的随机数据。字段 public-key / short-id 与 mihomo 保持一致，不实现 flow。
