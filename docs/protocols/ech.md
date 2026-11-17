# ECH 与 X25519MLKEM768

TLS 配置中的 `ech-config` 是已 Base64 解码的 ECHConfigList。Oryn 使用 vendored rustls 的 ECH 客户端和 aws-lc-rs HPKE provider；开启 `prefer-post-quantum` 后，provider 优先发送 `X25519MLKEM768` 混合 key share。

ECH 只支持 TLS 1.3，不能与 Reality、浏览器 ClientHello 模板或证书固定同时使用。ECH 配置由配置管理层提供，Core 不在数据面发起 DNS 查询。

V2Ray QUIC 传输目前不支持 ECH，配置层明确拒绝，不退回无 ECH 的连接。ECH + 证书固定也由配置层和 TLS API 双重拒绝，不允许静默忽略固定校验。回归与兼容边界见 [协议审查第四批](../../../docs/oryncore/audits/protocol-reference-audit-singbox-round4.md)。
