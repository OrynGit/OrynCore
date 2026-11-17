# SSH（`type: ssh`）

实现在 `oryn-outbound/src/ssh.rs`，SSH 协议由 russh 0.63（Apache-2.0）实现，只开 `ring` 与 `rsa` feature：不引入 aws-lc / C 代码与 zlib。字段与 mihomo 相同。

## 行为

- 同一出站共享一条 SSH 连接，每个 Flow 打开一个 `direct-tcpip` 通道；连接断开后下一个 Flow 重新握手（握手超时 15 秒），已断开时重试一次。
- 认证依次尝试私钥（RSA 签名按服务端 `server-sig-algs` 选 SHA-2）与密码。
- `host-key` 非空时服务端主机公钥必须与其中之一一致，证书一律拒绝。为空时首次连接即信任（TOFU）：公钥记录到数据目录下的 `ssh_known_hosts`（每行 `host:port 算法 base64`），之后同一 `host:port` 必须出示同一公钥，变化即拒绝连接（删掉对应行可接受新公钥）；没有数据目录时才退回不校验（与 mihomo 相同）并记警告日志。`host-key-algorithms` 设置首选主机密钥算法。
- 客户端标识随机取 `SSH-2.0-OpenSSH_7.x / 8.x`（与 mihomo 相同）。
- 每个通道的接收窗口 512 KiB，通道消息缓冲 32 条；保活 30 秒。
- UDP 默认关闭；Oryn 网关扩展见下文。私钥只接受内联文本（OpenSSH / PEM / PuTTY），文件路径是配置错误；私钥或主机公钥无法解析时节点按 REJECT 处理。

## 体积

russh 及其依赖（ssh-key、RSA / ECDSA / Ed25519、ML-KEM 等）使 Extension 的可执行文件增加约 2.8 MB（Release，14.48 MB 对比去掉 SSH 的 11.72 MB），静态库增加约 20.7 MB。记录在 `Oryn_dev/docs/oryncore/measurements/appex-size-0.8.x.tsv` 与 `static-size.tsv`。

## 互通

`test-support/peers/sshserver`（Go `x/crypto/ssh`，只作测试）：密码、Ed25519 私钥、RSA 私钥、带口令的私钥、主机公钥固定 + `host-key-algorithms`；10 B 与 300 KB 往返、16 个并发通道；错误密码、主机公钥不符、未授权私钥均失败。

## UDP 网关（Oryn 扩展，默认关闭）

参照用户提供的 Shadowrocket 选项，支持 BadVPN 与 tun2proxy 两种 UDP 网关协议。这不是 SSH 原生 UDP，也不是 mihomo 的 SSH 字段；本机 mihomo v1.19.32 的 SSH 明确设置 UDP: false。

- oryn-ssh-udp：off / badvpn / tun2proxy，缺省 off。普通 udp: true 不会打开扩展。
- oryn-ssh-udp-server：SSH 服务器侧网关 TCP 地址，缺省 127.0.0.1:7300；允许 IPv4 和方括号 IPv6。
- 通过现有 SSH direct-tcpip 通道访问该地址；无需本机 SOCKS 监听，不自动在远端安装或启动服务。
- BadVPN 帧长度/ID 为小端，IPv6 flag=8，首次目标使用 rebind flag=2；地址端口为网络序。域名交给 Oryn Core 解析，DNS 标志不设置，避免远端覆盖已选 DNS 上游。
- tun2proxy 帧长度/ID 为大端，data flag=2，地址采用 SOCKS5 格式，可交给网关解析域名；keepalive=1，error=32。
- 每 Flow 一个网关 SSH 通道，每出站上限 32，每通道最多 64 个目标；ID 不回绕复用。每个方向只保留一帧，最大 65535 字节，UDP payload 最多 65507 字节（还受地址首部和服务器 MTU 限制）。取消读写保留进度，接收小缓冲会截断数据但消耗完整帧。
- 每 5 秒发送网关保活，写入最多等待 10 秒；通道中断或网关返回错误使当前 UDP Flow 失败，新 Flow 可新建通道；Drop 终止保活任务并释放通道额度。

链接和节点 JSON 示例：

    ssh://user:pass@ssh.example:22?oryn-ssh-udp=badvpn&oryn-ssh-udp-server=127.0.0.1%3A7300

    {"type":"ssh","name":"SSH UDP","server":"ssh.example","port":22,"username":"user","password":"pass","oryn-ssh-udp":"tun2proxy","oryn-ssh-udp-server":"127.0.0.1:7300"}

单节点 JSON 支持粘贴、文件/URL 导入和 ssh://Base64(JSON)。完整 JSON 配置（含 proxies）由 Core 按 YAML 的 JSON 子集解析；私钥、主机密钥等字段会保留，无法表示的参数会报错。App 本地 JSON 也使用上述两个 Oryn 参数名持久化。

服务器由用户自行部署对应网关，例如：

    badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 64 --udp-mtu 65507
    udpgw-server --listen-addr 127.0.0.1:7300

BadVPN 默认只允许 3 个 TCP 客户端。Oryn 每 UDP Flow 使用一条网关通道，因此上例显式增加 max-clients，避免多条 UDP Flow 被服务器拒绝；Oryn 自身仍限制为每出站 32 条。

两种协议不通用，选项须与服务器相符。测试的 tun2proxy 0.8.4 官方网关为每个请求新建 UDP 套接字且只接收一次响应，因此不能宣称它提供稳定源端口或任意服务端推送；需要持续 UDP 会话时优先使用 BadVPN。Oryn 客户端不会在两种协议之间猜测切换。
