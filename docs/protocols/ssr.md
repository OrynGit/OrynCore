# ShadowsocksR 与 SS 的旧流式加密

## SS 加密方式

| 种类 | 加密方式 | 来源 |
|---|---|---|
| AEAD | `aes-192-gcm` | shadowsocks-crypto 没有这个种类，由 vendored 修补（`OrynCore/vendor/shadowsocks-crypto/ORYN_PATCHES.md`，RustCrypto `AesGcm<Aes192, U12>`） |
| AEAD | `xchacha20-ietf-poly1305` | shadowsocks-rust 的额外 AEAD |
| 流式 | `aes-128/192/256-ctr`、`aes-128/192/256-cfb`、`camellia-128/192/256-cfb`、`rc4-md5`、`chacha20-ietf`、`xchacha20` | shadowsocks-rust 的 `stream-cipher`；`xchacha20` 由同一修补加入 |

流式加密没有完整性保护：篡改的数据会被解密成垃圾而不是报错。按用户决定，它们与其它加密方式一样对待（不需要显式开关、不额外警告、不单独分组）；编辑器在 SSR 的说明里提示一次。

## ShadowsocksR（`type: ssr`）

实现在 `oryn-outbound/src/ssr/`，结构与 mihomo v1.19.32 `transport/ssr` 相同（出处见 Oryn_dev/docs/oryncore/provenance.md）：

- 写方向：应用数据 → 协议插件 → 流式加密（首包带 IV）→ 混淆 → TCP；读方向相反。
- 第一个写出就是目的地址（协议插件把认证与地址一起打包），所以混淆的握手在连接时完成。
- UDP 不经过混淆：地址 + 数据 → 协议插件的包编码 → 流式加密（每包一个 IV）。

| 协议 | 说明 |
|---|---|
| `origin` | 不加东西，等同普通 SS |
| `auth_sha1_v4` | 首包 CRC32 + HMAC-SHA1 认证，之后 Adler-32 分块 |
| `auth_aes128_md5` / `auth_aes128_sha1` | 用户 ID 与 AES-128-CBC 加密的认证块，分块 HMAC；`protocol-param` 为 `用户ID:密钥` |
| `auth_chain_a` / `auth_chain_b` | 在前者基础上加 RC4 二层加密与 XorShift128+ 随机填充；`_b` 的填充长度表另外派生 |

| 混淆 | 说明 |
|---|---|
| `plain` | 不混淆 |
| `http_simple` / `http_post` | 首包伪装成 HTTP GET / POST，`obfs-param` 为 Host（可带 `#` 自定义首部） |
| `random_head` | 首包前加随机头 |
| `tls1.2_ticket_auth`（含 `_fastauth`） | 伪装 TLS 1.2 握手（session ticket 携带数据），之后按 TLS 记录分帧 |

上限：读方向未解出的数据最多 64 KiB，混淆首部最多 16 KiB；超过即断开。

## 互通

- 旧流式加密 12 种：Python shadowsocksr 服务端（`origin` + `plain`，OpenSSL 3 需加载 legacy provider 才有 RC4 / CFB / Camellia）与 `test-support/peers/ssstream`（Go，chacha20-ietf / xchacha20 / rc4-md5），TCP 与 UDP。
- `aes-192-gcm`、`xchacha20-ietf-poly1305`：sing-box 1.14 的 SS 入站。
- SSR：Python shadowsocksr 服务端，6 种协议 × 5 种混淆的 TCP，每种协议的 UDP，多种加密方式，错误口令。
