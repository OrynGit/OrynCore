# Oryn 依赖修补

来源：shadowsocks-rust crates/shadowsocks，1.23.2，commit 8f9419efa56d3b7db2b7d3cc0423b0bfd37565ea，MIT。保留 LICENSE。

- src/relay/udprelay/aead_2022.rs：取消线程局部 UDP cipher 缓存（上游容量 102400）；每包派生，控制 Extension 内存并避免 key 指针缓存寿命问题。这是内存约束修正，不是性能优化。
- src/relay/tcprelay/proxy_stream/client.rs：零初始化 TCP padding，替代 advance_mut 未初始化区域，避免发送未初始化内存。
- src/relay/udprelay/aead_2022.rs：同时初始化 padding / nonce / tag 预留空间。
- src/relay/mod.rs：无 payload 首包的随机 padding 长度改为 1–900，遵守 SIP022 必须有 padding 的要求。
- src/security/replay/mod.rs：TCP salt LRU 加容量 64 的硬上限；Oryn 每 TCP 连接单独 Context，通常只使用两项。

升级时逐项复核修补并运行 P1 本机与 sing-box 互通测试。
