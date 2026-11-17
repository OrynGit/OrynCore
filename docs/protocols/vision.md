# VLESS Vision（`flow: xtls-rprx-vision`）

实现在 `oryn-outbound/src/vision.rs`，移植自 sing-vmess `vless/vision.go`（commit 3aed155119a1，即 sing-box 1.14.0 所用版本），出处登记在 [Oryn_dev/docs/oryncore/provenance.md](../../../docs/oryncore/provenance.md)。

## 条件

- 只能用于 VLESS + TCP 传输 + TLS / Reality；其它传输或没有 TLS 是配置错误（Swift 校验同样拦截）。
- VLESS 请求带 flow 附加字段（protobuf 字段 1：`0x0A, len, "xtls-rprx-vision"`）。
- UDP 走 XUDP（命令 Mux + flow 附加字段），与 sing-box 一致；`packet-encoding` 不影响 Vision 的 UDP。

## 填充与直写

- 写方向：前 8 个内层包加 Vision 填充帧（第一帧带 16 字节 UUID 前缀；命令 Continue / End / Direct；内容长度与填充长度各 u16）。每次填充写入的明文最多 8192 字节（Xray 的块大小），否则内容长度会超出 u16。
- 内层 TLS 识别：观察前 8 个包；看到 TLS 1.3 ServerHello（supported_versions 0x0304，套件 0x1301–0x1304）后进入「直写」：客户端在第一条内层应用数据前发 Direct 命令，此后上行字节绕过外层 TLS 直接写 TCP；服务端同样在下行切换。内层是 TLS 1.2 或非 TLS 时只做填充，不直写。
- 读切换点：切换点之后的字节在 TCP 上紧跟最后一条外层 TLS 记录。rustls 会一次解密缓冲里的所有完整记录，把切换后的内层记录也当外层记录解密而失败。所以外层 TLS 下面垫了一层 `RecordReader`：填充阶段每次只交给 rustls 一条记录；外层读取用 `poll_fill_buf` / `consume` 而不是 `poll_read`（后者会继续解密后续记录并推迟报错）。切换时套接字里剩下的就是原始字节，不需要修改 rustls。
- 服务端先说话的应用：读之前还没写过时，先写一个空的填充帧，让服务端收到请求。
- 直写切换时与 sing-vmess 一样等待 5 ms。

## 上限

填充阶段每次最多处理一条 TLS 记录（16 KiB 明文）；没有额外队列。

补验后，首个 UUID 与 5 字节填充头可以任意分片，包含每条 TLS 记录仅一个字节的情况。前缀确认进度保存在连接内，取消读取不丢失；候选 UUID 不匹配时原样恢复，EOF 前不足完整 UUID 的普通数据也不丢弃。已识别的 Vision 帧遇到截断或非法命令则关闭流，错误后不再继续读写。End / Direct 的同记录尾部保持原样，Direct 完成前不解除逐记录读取限制。单次待交付内容最多一条 TLS 明文加尚未确认的前缀（不超过 16 KiB + 15 字节），不累积整个大帧。详细验证见 [补验记录](../../../docs/oryncore/audits/audit-vision-h3-followup.md)。

## 互通

sing-box 1.14.0 的 VLESS 入站（`flow: xtls-rprx-vision`），TLS 与 Reality 两种：内层 TLS 1.3（触发双向直写）、TLS 1.2、非 TLS；70 KB 往返与 16 条并发；UDP（XUDP）；没有 flow 的用户被拒绝。测试在 `oryn-outbound/tests/p5.rs`。
