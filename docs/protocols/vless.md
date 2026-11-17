# VLESS 协议笔记

依据 https://xtls.github.io/development/protocols/vless.html 。独立实现，未移植外部代码。

请求：version=0、UUID(16)、addons length=0、command(1 TCP / 2 UDP)、port u16 BE、address type(1 IPv4 / 2 域名 / 3 IPv6)、地址。响应读取 version=0 和 addons length，再丢弃有界附加数据（最多 255 字节）。响应头延迟至首次读取，避免服务端等待首包导致死锁。UDP 帧是 u16 BE 长度 + payload，绑定首次目标；非首次目标明确拒绝。TLS / WS 均由下层组合。Vision（`flow: xtls-rprx-vision`）支持，见 [vision.md](vision.md)；Reality 见 [reality.md](reality.md)。
