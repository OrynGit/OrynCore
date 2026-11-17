# Oryn 本机 TLS 修补

来源 rustls/rustls，rustls 0.23.45，commit 2976d90fd1c2db6b518700dd101b714069cfcb17。保留 LICENSE-APACHE / LICENSE-ISC / LICENSE-MIT。

- crypto/mod.rs：OrynClientHello 定制接口与 ActiveKeyExchange 的默认拒绝 Reality 派生接口；默认配置不使用。
- client/client_conn.rs / builder.rs：可选定制器（默认为 None）。
- msgs/handshake.rs：ClientHello 保留定制 raw 编码，同一编码进入网络和握手 transcript；普通解析默认 None。
- client/hs.rs：在 ClientHello 生成完成后调用定制器；限制 16 KiB，解析并核对 random / 版本 / 压缩参数，更新 session ID、cipher 与实际发送的扩展 ID。
- ech.rs 与上游测试：ClientHello 字面量补默认值，普通 ECH 行为不变。

不修改 TLS cipher / record layer / CertificateVerify / Finished 校验。不在 socket 上单独改写 ClientHello，避免 transcript 不一致。不兼容自定义 ClientHello 与真实 ECH / resumption 同时使用。

升级必须复核上述接口，并跑普通 TLS / 指纹 HRR / Reality 独立互通及 DNS 加密传输回归。

## ShadowQUIC JLS v3（2026-10-02）

方案：docs/plans/plan-sudoku-shadowquic.md。增加默认 None 的 OrynJlsAuth / oryn_jls 握手钩子：ClientHello 构造完成且 PSK binder 计算前写入认证 random，并同步引擎 random；TLS 1.3 原始 ServerHello 在证书处理前必须通过 JLS 校验；明确拒绝 JLS + HRR / ECH / 浏览器定制。JLS 专用配置在 oryn-tls 中封装，采用认证 random 代替证书签名认证，仍校验 transcript / Finished；普通配置不进入此分支。
