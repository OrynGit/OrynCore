# ShadowTLS v1 / v2 / v3

按公开协议及 sing-shadowtls v0.2.1-fcd445d33c11 核对；认证与记录层改写自其 `client.go`、`v2_client.go`、`v2_conn.go`、`v2_hash.go`、`v3_client.go`、`v3_conn.go`，出处登记在 [Oryn_dev/docs/oryncore/provenance.md](../../../docs/oryncore/provenance.md)。只有 Shadowsocks 节点可用，以 `plugin: shadow-tls` 配置；SS 只在 TCP 拨号侧叠加 ShadowTLS，其原生 UDP 能力不经过 TLS（需要 UDP 走同一承载时见 [uot.md](uot.md) 或 smux）。

```yaml
plugin: shadow-tls
plugin-opts:
  version: 3          # 1 / 2 / 3，必填
  host: cover.example # 握手伪装目标的域名（SNI），必填
  password: secret    # v2 / v3 必填，v1 没有密码
  alpn: [h2, http/1.1]  # 可选，最多 16 项
skip-cert-verify: false
```

证书验证默认开启（对 `host` 校验），测试自签名目标通过显式 `skip-cert-verify`。

## v3（TLS 1.3）

ClientHello session ID 的后 4 字节是密码 HMAC-SHA1 截断值。服务端随机数初始化握手记录认证、C / S 两个方向的滚动 HMAC；伪装握手仍由 rustls 检查 Finished 和签名，握手后移除 TLS 加密状态，交换带 4 字节认证前缀的应用记录。

## v2（TLS 1.2）

- 握手期间双方照常做一次真实的 TLS 1.2 握手（对伪装目标）。客户端对握手期间**读到的全部字节**做 HMAC-SHA1（密钥为密码），取前 8 字节，随第一次写出的数据发给服务端作为认证。
- 之后双向都是 TLS 应用数据记录（类型 23、版本 TLS 1.2），每条记录的载荷是代理流的字节；那 8 字节认证放在客户端第一条记录的载荷最前面。
- 伪装握手要求目标支持 TLS 1.2。目标只支持 TLS 1.3 时握手失败。

## v1（TLS 1.2）

- 客户端与伪装目标完成一次 TLS 1.2 握手（服务端按配置把握手转发给伪装目标）。握手完成之后，底层连接就是裸的代理流，没有任何记录封装，也没有认证 —— v1 靠「握手后才切换」混过检测，强度弱于 v2 / v3。
- 同样要求目标是 TLS 1.2。

## 上限与失败

记录与缓存均有上限；认证失败关闭连接，不尝试普通 TLS 或未认证回退。v2 的服务端在密码错误时会把连接转给握手服务器，客户端随后读不到有效数据，表现为连接不可用。

## 测试

v3 与 sing-box 的 shadowtls 入站互通。v1 / v2：与 sing-box 1.12.8 / 1.13.14 的 shadowtls 入站（`version: 1` / `2`，`detour` 到内层 SS 入站，握手目标是本机 TLS 1.2 服务）互通，70000 字节与连续新连接；v2 密码错误时连接不可用。配置解析、版本分支与密码必填规则由 `oryn-config` 测试覆盖，Swift 编辑器有同样的校验。
