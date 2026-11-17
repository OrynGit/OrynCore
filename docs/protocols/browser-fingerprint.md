# TLS 浏览器指纹笔记

只定制 ClientHello，不改变 TLS 密钥调度与 record layer。普通 TLS / DNS 仍用原来的 rustls + ring 默认 ClientHello；只有节点显式配置 client-fingerprint 或 Reality 默认 chrome 时使用模板。

来源为 metacubex/utls u_parrots.go @ 8b5753f5737a9e173f6ebc85edb6cdd144301c71，BSD-3-Clause。Copyright 2017 Google Inc. / Copyright (c) 2009 The Go Authors。模板导出版本和生成方法见 oryn-tls/src/profiles/README.md，完整许可随 App 打包。

模板保留 cipher 顺序、扩展列表 / 顺序、群、签名算法、ALPN、证书压缩、GREASE / ECH GREASE 形状；SNI、ALPN（用户配置优先）、random、session ID、真实 X25519 / P256 shares 动态重建。Chrome 随机化扩展顺序，HRR 保留首次 GREASE / 顺序 / ECH GREASE，更新实际 key share / cookie。GREASE key share group 必须同时存在于 supported groups。Firefox 的第二个 P256 share 有真实私钥，不伪造不可完成的 share。

本机 rustls 修补让定制编码同时进入网络和 transcript，并更新 session ID / 实际扩展 / cipher 元数据。不能仅在 socket 上改写字节，否则 Finished 失配。handshake body 上限 16 KiB，模板状态仅保留在当前连接，没有全局积累缓存；禁用 resumption / 实际 ECH，保留正常 CertificateVerify / Finished / 信任链校验。

固定版本不是当前所有浏览器的精确指纹，也不伪装 HTTP/2 / TCP 栈或后续 TLS record 细节。backend 只支持 rustls / ring 实际实现的 TLS 1.2 / 1.3 AEAD，不支持模板里旧 CBC / RSA key exchange / FFDHE / PQ；服务端选择这些能力会明确失败，不静默降级。Android 11 OkHttp 仅 TLS 1.2。HTTP CONNECT / WS 默认 ALPN 限 http/1.1。

验证使用实际双向 TLS 握手，不仅检查静态数组；核对 cipher、扩展、群、signature、SNI、随机 key share，并覆盖普通 TLS 1.2 与 HRR。独立对端覆盖 Reality、WS、UDP、策略组和真实 Engine。真机运行内存仍未测量。
