# HTTP/1.1 首部伪装（`network: http`）

V2Ray / mihomo 的 HTTP 伪装传输，参照 sing-box `transport/v2rayhttp` 的 HTTP/1.1 路径核对行为，未移植其代码。Trojan / VLESS / VMess 可用，TLS 可有可无（Trojan 总是 TLS）。

- 客户端写出 `METHOD path HTTP/1.1` 请求首部，协议首部紧跟在首部之后一起写出；服务端回 `HTTP/1.1 200` 响应首部。两边首部之后都是原始字节，没有分块或长度分帧。
- `http-opts`：
  - `method`：默认 `GET`，1–16 个 ASCII 字母。
  - `path`：mihomo 写成候选列表（最多 8 项），Oryn 取第一项，默认 `/`；规则与 h2 的 path 相同。
  - `headers`：每个首部取值列表的第一项；最多 16 个；名称不能是 `Connection` / `Upgrade` / `Content-Length` / `Transfer-Encoding`。`Host` 的取值列表（最多 8 项）取第一项作 `Host`，没有配置时用服务器地址。
- 响应首部最多 32 KiB。逐字节读到 `\r\n\r\n`，不多读：之后的字节属于上层协议。
- 使用 TLS 时 ALPN 每一项都必须是 `http/1.1`，否则整份配置失败。
- 实现在 `oryn-transport/src/http1.rs`，复用 HTTPUpgrade 的裸字节流类型。

## 测试

单元测试覆盖请求格式、响应首部超限、拆包与首部后紧跟数据。独立对端是 sing-box 的 `http` 传输入站（`method: POST`）：Trojan 经 TLS（`http/1.1`），VLESS / VMess 明文；TCP 70000 字节往返、UDP 往返，path 写错时连接失败；sing-box 1.12.8 与 1.13.14 通过。p2_engine 的 `http` 例走真实 Engine。
