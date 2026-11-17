# Tailscale Rust 组件

来源 tailscale/tailscale-rs，commit f4781c480e8d1376aed89f737beefe7425e8b866，BSD-3-Clause。仅引入 TS2021 Noise、密钥、Noise IK、工具与 capability 类型；不引入 runtime / netstack / control 网络客户端。保留上游算法实现与测试，增加出处注释。所有网络连接、HTTP/H2、map 帧大小和 DERP 队列由 Oryn 限制。
