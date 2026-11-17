# Shadowsocks 协议笔记

依据 SIP004 / SIP022：https://shadowsocks.org/doc/aead.html 、https://shadowsocks.org/doc/sip022.html 。复用 MIT 许可 shadowsocks-rust 1.23.2 协议库，不移植 sing-box 代码。

AEAD TCP：随机 salt，HKDF 子密钥，独立认证的长度与数据块；UDP：salt + 加密的 SOCKS 地址和数据。2022 使用 Base64 PSK、BLAKE3 派生、时间戳、会话及包编号，TCP 校验请求 salt 绑定，UDP 校验客户端会话、时间戳和滑动窗口。允许 AES 身份密钥链。

TCP 用 ProxyClientStream::from_stream 包装 Dialer 流，不用库的拨号器或 DNS。每连接独立 Context，库的 TCP salt 缓存限制 64 项，通常仅请求/响应两个条目；UDP 使用底层 crypto_io，不用库的会话管理；本机修补取消线程局部 102400 项 cipher 缓存。Oryn 对收到的 server session 设置 4 个上限和 64 位重放窗口。关闭库默认 DNS / stream cipher 功能，复用 ring，避免引入 aws-lc。

空首包建立握手以支持 server-first 应用并避免库超大首包拼接；无 payload 时非零 padding，所有预留字节初始化。本机库修补见 vendor/shadowsocks/ORYN_PATCHES.md。
