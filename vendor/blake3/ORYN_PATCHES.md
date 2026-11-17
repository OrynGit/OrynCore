# Oryn patch

BLAKE3 1.8.7, commit f3149ec5bb5449af877ba20377a11008ff499fa2.

2026-10-02：增加 Hasher::new_derive_key_bytes；与 new_derive_key 使用相同的 DERIVE_KEY_CONTEXT / DERIVE_KEY_MATERIAL，接受任意字节以匹配 VLESS Encryption。保留上游 Apache-2.0 许可。
