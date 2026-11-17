# ClientHello 模板数据

来源 metacubex/utls v1.8.0，u_parrots.go @ 8b5753f5737a9e173f6ebc85edb6cdd144301c71，BSD-3-Clause，保留 LICENSE（Copyright 2017 Google Inc.; Copyright (c) 2009 The Go Authors）。

| 文件 | uTLS ClientHelloID | 版本 |
|---|---|---|
| chrome.bin | HelloChrome_120 | Chrome 120 |
| firefox.bin | HelloFirefox_120 | Firefox 120 |
| safari.bin | HelloSafari_16_0 | Safari 16 |
| ios.bin | HelloIOS_14 | iOS 14 |
| edge.bin | HelloEdge_106 | Edge 106 |
| android.bin | HelloAndroid_11_OkHttp | Android 11 OkHttp（TLS 1.2） |
| 360.bin | Hello360_11_0 | 360 11 |
| qq.bin | HelloQQ_11_1 | QQ 11.1 |

用 UClient(Config{ServerName:"example.com"}, ID).BuildHandshakeState() 的 Hello.Raw[4:] 导出，包含 ClientHello body，不包含握手或 record header。数据只描述模板；捕获的随机值 / 公钥不能在运行时复用。browser.rs 会动态替换 random、session ID、SNI、ALPN、GREASE、ECH GREASE 与 key shares。实际 Wire / TLS 握手测试核对模板内容。

不声称覆盖所有 uTLS ID / 所有当前浏览器版本。模板中的旧 TLS suite / group 仅为 wire 指纹；连接仅可协商 rustls / ring 实际实现的 TLS 1.2 / 1.3 cipher 与群，不支持 TLS 1.0 / 1.1 或 CBC / RSA key exchange。真实 ECH、HTTP/2 指纹、PQ key share 不在本轮范围。
