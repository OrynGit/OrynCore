# Trojan 协议笔记

依据官方 https://trojan-gfw.github.io/trojan/protocol 。独立实现，未移植外部代码。

握手：SHA-224(password) 的 56 字节小写十六进制 + CRLF + command(1 TCP / 3 UDP) + SOCKS 地址 + CRLF。TLS 为必需安全层，WS 可叠加在 TLS 上。UDP 每包为 SOCKS 地址 + 长度 u16 BE + CRLF + payload；按包寻址。密码不写日志。响应直接为应用数据。

互通核对 sing-box 1.12.8 对认证前缀的单次读取行为；early data 上限不足 56 字节时回退正常 WS 帧发送握手，不拆开认证前缀。未移植源码。UDP reader 保留取消前读取的字节，兼容 Engine select!，小缓冲截断不破坏下一帧。
