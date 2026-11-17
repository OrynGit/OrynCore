# Oryn 依赖修补

来源：shadowsocks-rust 生态的 shadowsocks-crypto 0.6.2（crates.io 发布包，git 86dbc757e7c51c9d072aeabbcc758d50622f1db5），MIT。保留 LICENSE。

- src/kind.rs、src/v1/aeadcipher/{mod.rs, aes192_gcm.rs}：增加 AEAD 加密方式 `aes-192-gcm`（`AES_192_GCM`）。ring 不支持 AES-192，固定用 RustCrypto `aes-gcm` 的 `AesGcm<Aes192, U12>`；`v1-aead` feature 因此依赖 `aes`。sing-box、mihomo 支持这个加密方式，上游没有。
- src/kind.rs、src/v1/streamcipher/{mod.rs, chacha20.rs}：增加流式加密 `xchacha20`（`XCHACHA20`，24 字节 IV，RustCrypto `chacha20` 的 `XChaCha20`），对应 mihomo / sing-shadowsocks 的同名加密方式。

不修改已有加密方式的实现。升级时逐项复核，并跑 SS 本机与独立对端互通。
- src/v1/aeadcipher/sm4_gcm_cipher.rs：返回类型补上省略的生命周期 `Ctr32BE<'_>`，消除新版 rustc 的 `mismatched_lifetime_syntaxes` 告警（作为路径依赖时会显示）。行为不变。
