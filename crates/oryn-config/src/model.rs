//! 解析后的运行时配置。数据面只使用这里的结构，不再读取 YAML。

use std::net::IpAddr;

use crate::{DomainPattern, IpCidr, TargetAddr};
use oryn_module::{ModuleFormat, ModuleIR};

pub const TAG_DIRECT: &str = "DIRECT";
pub const TAG_REJECT: &str = "REJECT";
pub const TAG_GLOBAL: &str = "GLOBAL";

pub const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_MMDB_URL: &str =
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb";
pub const DEFAULT_BOOTSTRAP: [&str; 2] = ["119.29.29.29", "223.5.5.5"];
pub const DEFAULT_NAMESERVER: [&str; 3] = ["8.8.8.8", "1.1.1.1", "9.9.9.9"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rule" => Some(Mode::Rule),
            "global" => Some(Mode::Global),
            "direct" => Some(Mode::Direct),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Rule => "rule",
            Mode::Global => "global",
            Mode::Direct => "direct",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub mode: Mode,
    /// `error` / `warn` / `info` / `debug` / `off`
    pub log_level: String,
    /// 下标即策略编号。
    pub outbounds: Vec<OutboundSpec>,
    /// 按顺序 first-match；最后一条一定是 `Final`。
    pub rules: Vec<RuleSpec>,
    pub providers: Vec<ProviderSpec>,
    /// 代理集合（`proxy-providers`）。集合的节点已经展开在 `outbounds` 里。
    pub proxy_providers: Vec<ProxyProviderSpec>,
    pub dns: DnsSpec,
    pub hosts: Vec<HostEntry>,
    pub sniffer: SnifferSpec,
    pub geoip: GeoIpSpec,
    pub modules: Vec<ModuleSpec>,
    pub mitm: MitmSpec,
    pub force_http_hosts: Vec<String>,
    pub raw_tcp_hosts: Vec<String>,
    /// 被忽略的内容与其它非致命问题。
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ModuleSpec {
    pub url: Option<String>,
    pub format: Option<ModuleFormat>,
    pub enabled: bool,
    pub update_interval: u64,
    pub arguments: Vec<(String, String)>,
    pub policy_map: Vec<(String, String)>,
    /// 模块环境变量，脚本通过 `ctx.env` 读取。
    pub env: std::collections::BTreeMap<String, String>,
    pub inline: Option<ModuleIR>,
    /// 模块引用的脚本 / 数据文件。`Arc` 共享：`RuntimeState` 的 `config` 与 `base_config`、
    /// 重新加载时的上一份配置都指向同一份，不随配置 `clone()` 复制（资源最多 8 MiB）。
    pub resources: std::sync::Arc<oryn_module::Resources>,
}

impl RuntimeConfig {
    pub fn outbound_index(&self, name: &str) -> Option<usize> {
        self.outbounds.iter().position(|o| o.name == name)
    }

    pub fn direct_index(&self) -> usize {
        self.outbound_index(TAG_DIRECT).expect("DIRECT 总是存在")
    }

    pub fn global_index(&self) -> usize {
        self.outbound_index(TAG_GLOBAL).expect("GLOBAL 总是存在")
    }
}

#[derive(Debug, Clone)]
pub struct OutboundSpec {
    pub name: String,
    pub kind: OutboundKind,
    /// `dialer-proxy`：经由另一个出站（`RuntimeConfig::outbounds` 的下标）拨出。
    pub dialer: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSpec {
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub fingerprint: Option<[u8; 32]>,
    pub client_fingerprint: Option<String>,
    pub reality: Option<RealitySpec>,
    /// ECH 配置列表（DNS HTTPS 记录中的 `ech` 参数，Base64 解码后的 wire bytes）。
    pub ech: Option<EchSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchSpec {
    pub config: Vec<u8>,
}

/// Reality 身份材料，不是普通证书固定值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySpec {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
}

pub const CLIENT_FINGERPRINTS: &[&str] = &[
    "chrome", "firefox", "safari", "ios", "edge", "android", "360", "qq", "random",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsSpec {
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub max_early_data: usize,
    pub early_data_header: String,
}

/// 代理流的传输层。每一层只负责把字节流转换成下一层看到的字节流。
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportSpec {
    Tcp,
    Ws(WsSpec),
    HttpUpgrade(HttpUpgradeSpec),
    Grpc(GrpcSpec),
    /// HTTP/2：每个 Flow 一个 PUT 请求流，请求体与响应体是原始字节。
    H2(H2Spec),
    /// HTTP/1.1 首部伪装：请求与响应首部之后是原始字节。
    Http(HttpSpec),
    /// XHTTP / SplitHTTP：HTTP/2 请求承载原始双向流。
    XHttp(XHttpSpec),
    /// mKCP：KCP 数据报承载原始双向流。
    Kcp(KcpSpec),
    /// Mekya：HTTP/1.1 或 HTTP/2 请求承载 mKCP packet bundle。
    Mekya(MekyaSpec),
    /// V2Ray QUIC：共享一条 QUIC 连接，每个 Flow 一个双向流。
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Spec {
    /// `:authority` 候选；空时使用 `www.example.com`（V2Ray 的默认）。
    pub hosts: Vec<String>,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSpec {
    pub method: String,
    pub path: String,
    /// 除 Host 之外的附加首部（名称，值）。
    pub headers: Vec<(String, String)>,
    /// `Host` 首部候选；空时使用连接的服务器地址。
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUpgradeSpec {
    pub path: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpSpec {
    pub hosts: Vec<String>,
    pub path: String,
    pub method: String,
    pub mode: String,
    pub headers: Vec<(String, String)>,
    pub no_grpc_header: bool,
    pub uplink_http_method: String,
    pub uplink_data_placement: String,
    pub uplink_data_key: String,
    pub uplink_chunk_size: usize,
    pub session_placement: String,
    pub session_key: String,
    pub seq_placement: String,
    pub seq_key: String,
    pub sc_max_each_post_bytes: usize,
    pub sc_min_posts_interval_ms: u64,
    /// XHTTP 请求首部填充；范围已经在配置编译阶段限制。
    pub padding: XHttpPaddingSpec,
    /// stream-up / packet-up 的独立下载请求；独立端点与 TLS 仍经过同一 Dialer。
    pub download: Option<XHttpDownloadSpec>,
    /// XHTTP 连接复用上限。所有值均为有界的 0 表示不额外限制。
    pub reuse: XHttpReuseSpec,
    /// packet-up 的 body/header/cookie/query 数据 placement。
    pub session_table: String,
    pub session_length: usize,
    pub sc_max_buffered_posts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpPaddingSpec {
    pub min: usize,
    pub max: usize,
    pub obfs_mode: bool,
    pub key: String,
    pub header: String,
    pub placement: String,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpDownloadSpec {
    pub server: TargetAddr,
    pub security: SecuritySpec,
    pub transport: Box<XHttpSpec>,
    pub hosts: Vec<String>,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XHttpReuseSpec {
    pub min_max_concurrency: usize,
    pub min_max_connections: usize,
    pub min_max_reuse_times: usize,
    pub min_max_request_times: usize,
    pub min_max_reusable_secs: u64,
    pub max_concurrency: usize,
    pub max_connections: usize,
    pub max_reuse_times: usize,
    pub max_request_times: usize,
    pub max_reusable_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KcpSpec {
    pub mtu: u16,
    pub tti: u16,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub read_buffer_size: usize,
    pub write_buffer_size: usize,
    pub header: String,
    pub seed: Option<String>,
}

/// Mekya 外层参数。`kcp` 是内层 mKCP 配置，HTTP 参数全部有界。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MekyaSpec {
    pub url: String,
    pub h2_pool_size: usize,
    pub max_write_delay_ms: u64,
    pub max_request_size: usize,
    pub polling_interval_initial_ms: u64,
    pub max_write_size: usize,
    pub max_write_duration_ms: u64,
    pub max_simultaneous_write_connections: usize,
    pub packet_writing_buffer: usize,
    pub kcp: KcpSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcSpec {
    pub service_name: String,
}

/// 安全层。Reality 是 TlsSpec.reality 的一种 TLS ClientHello 配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecuritySpec {
    None,
    Tls(TlsSpec),
    ShadowTls(ShadowTlsSpec),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowTlsSpec {
    /// 1、2 或 3。
    pub version: u8,
    pub skip_cert_verify: bool,
    pub host: String,
    /// v1 没有密码。
    pub password: String,
    pub alpn: Vec<String>,
}

/// simple-obfs：在 TCP 上伪装成 HTTP 或 TLS 握手。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObfsSpec {
    pub tls: bool,
    pub host: String,
}

/// v2ray-plugin（只有 websocket 模式）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2RayPluginSpec {
    pub tls: Option<TlsSpec>,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// V2Ray Mux.Cool。
    pub mux: bool,
}

/// Shadowsocks 的 SIP003 插件。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SsPlugin {
    #[default]
    None,
    ShadowTls(ShadowTlsSpec),
    Obfs(ObfsSpec),
    V2Ray(V2RayPluginSpec),
    /// gost-plugin（websocket）：字段与 v2ray-plugin 相同，`mux` 是每条连接一个 smux v1 会话。
    Gost(V2RayPluginSpec),
}

/// 协议层的可选复用配置。W0 只建立数据模型，具体协议在 W3 实现。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxSpec {
    pub protocol: MuxProtocol,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub padding: bool,
    pub only_tcp: bool,
    /// Brutal：只与服务端交换带宽。iOS 不能设置 TCP 拥塞控制。
    pub brutal: Option<BrutalSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrutalSpec {
    pub up_mbps: u32,
    pub down_mbps: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxProtocol {
    Smux,
    H2Mux,
    Yamux,
}

#[derive(Debug, Clone)]
pub enum PacketEncoding {
    Default,
    PacketAddr,
    Xudp,
}

#[derive(Debug, Clone)]
pub struct StreamProxySpec {
    pub server: TargetAddr,
    pub udp: bool,
    pub security: SecuritySpec,
    pub transport: TransportSpec,
    pub mux: Option<MuxSpec>,
    pub packet_encoding: PacketEncoding,
    /// VLESS `flow: xtls-rprx-vision`。只用于 TCP 传输 + TLS / Reality；UDP 经 XUDP。
    pub vision: bool,
    /// VLESS Encryption 的客户端配置字符串（mlkem768x25519plus.*）。
    pub vless_encryption: Option<crate::VlessEncryptionSpec>,
}

impl StreamProxySpec {
    /// 只读访问器，安全层 / 传输层枚举是配置的唯一来源。
    pub fn tls(&self) -> Option<&TlsSpec> {
        if let SecuritySpec::Tls(t) = &self.security {
            Some(t)
        } else {
            None
        }
    }
    pub fn ws(&self) -> Option<&WsSpec> {
        if let TransportSpec::Ws(w) = &self.transport {
            Some(w)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnyTlsSpec {
    pub server: TargetAddr,
    pub password: String,
    pub tls: TlsSpec,
    pub idle_check_secs: u64,
    pub idle_timeout_secs: u64,
    pub min_idle_sessions: usize,
    /// UDP 经 UoT v2 承载在会话的一个流上。
    pub udp: bool,
}

#[derive(Debug, Clone)]
pub struct VmessSpec {
    pub uuid: [u8; 16],
    pub alter_id: u16,
    pub cipher: String,
    pub global_padding: bool,
    pub authenticated_length: bool,
}

/// QUIC 拥塞控制。Brutal 只由 Hysteria2 在配置了带宽时使用，不在这个枚举里。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicCongestion {
    Bbr,
    Cubic,
    NewReno,
}

/// 闭区间端口集合，按区间保存，不展开。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSet {
    pub ranges: Vec<(u16, u16)>,
    pub count: u32,
}

impl PortSet {
    /// `n` 取 `0..count`。按区间宽度均匀落到一个端口。
    pub fn pick(&self, n: u32) -> u16 {
        let mut left = n % self.count.max(1);
        for &(start, end) in &self.ranges {
            let width = u32::from(end - start) + 1;
            if left < width {
                return start + left as u16;
            }
            left -= width;
        }
        self.ranges.first().map(|r| r.0).unwrap_or(1)
    }
}

#[derive(Debug, Clone)]
pub struct Hysteria2Spec {
    pub server: TargetAddr,
    /// 非空时忽略 `server` 的端口，改走跳跃。
    pub ports: Option<PortSet>,
    pub password: String,
    /// 字节/秒。`None` 表示该方向用 BBR。
    pub up_bps: Option<u64>,
    pub down_bps: Option<u64>,
    pub obfs_password: Option<String>,
    /// `obfs: gecko` 的线上包大小范围（最小、最大）；None 表示 Salamander 或不混淆。
    pub gecko: Option<(u16, u16)>,
    pub tls: TlsSpec,
    pub hop_min_secs: u64,
    pub hop_max_secs: u64,
    pub udp: bool,
    /// `realm-opts`：经会合服务器打洞连接 NAT 后的服务端。此时 `server` 只用于 TLS 名称。
    pub realm: Option<RealmSpec>,
}

/// Hysteria Realm（sing-box 1.14 的会合服务）客户端参数。
#[derive(Debug, Clone)]
pub struct RealmSpec {
    /// 会合服务器：`https` 走 TLS + HTTP/2，`http` 走明文 HTTP/2（prior knowledge）。
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// URL 里的路径前缀（不含结尾的 `/`），请求路径为 `{path}/v1/{realm-id}/connect`。
    pub path: String,
    pub token: String,
    pub realm_id: String,
    /// STUN 服务器，至少一个；缺省端口 3478。
    pub stun_servers: Vec<TargetAddr>,
    /// 访问会合服务器的 TLS 参数。
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub fingerprint: Option<[u8; 32]>,
}

/// Sudoku 节点；HTTP mask 与会话复用均在出站内部实现。
#[derive(Debug, Clone)]
pub struct SudokuSpec {
    pub server: TargetAddr,
    pub key: String,
    pub aead: String,
    pub padding_min: u8,
    pub padding_max: u8,
    pub table_type: String,
    pub tables: Vec<String>,
    pub pure_downlink: bool,
    pub http_disabled: bool,
    pub http_mode: String,
    pub http_tls: bool,
    pub http_host: String,
    pub path_root: String,
    pub multiplex: String,
    pub tls: Option<TlsSpec>,
}
/// ShadowQUIC / JLS v3。QUIC 参数在配置阶段限制到 Extension 的资源预算。
#[derive(Debug, Clone)]
pub struct ShadowQuicSpec {
    pub server: TargetAddr,
    pub username: String,
    pub password: String,
    pub sni: String,
    pub alpn: Vec<String>,
    pub udp_over_stream: bool,
    pub zero_rtt: bool,
    pub keep_alive_ms: u64,
    pub congestion: String,
    pub cwnd: u32,
    pub stream_window: u32,
    pub receive_window: u32,
    pub max_streams: usize,
    pub max_datagram: usize,
    pub disable_mtu_discovery: bool,
    pub up_bps: u64,
    pub down_bps: u64,
}

/// Mieru v3：底层传输与是否转发 UDP Flow 相互独立。
#[derive(Debug, Clone)]
pub struct MieruSpec {
    pub server: TargetAddr,
    pub port_end: u16,
    pub transport_udp: bool,
    pub username: String,
    pub password: String,
    pub udp: bool,
    /// 每个载体允许共享的会话数，OFF 为 1；全节点上限随资源档位设定（64–512）。
    pub multiplexing: usize,
    pub no_wait: bool,
    pub traffic_pattern: crate::MieruTrafficPattern,
}

/// Snell v6 的记录模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnellMode {
    /// 流量画像：前缀、填充、交错与分块都由 PSK 派生。
    Default,
    /// v4 式 AEAD 记录，无填充。
    Unshaped,
    /// 不加密，只有首部分帧（仅用于外层已有加密的场合）。
    UnsafeRaw,
}

#[derive(Debug, Clone)]
pub struct SnellSpec {
    pub server: TargetAddr,
    pub psk: String,
    /// 4、5 或 6。v5 使用 v4 兼容记录层，但保留声明版本供 v5 专用能力判断。
    pub version: u8,
    /// v4 的 `obfs-opts`（simple-obfs 的 http / tls）。
    pub obfs: Option<ObfsSpec>,
    /// v6 的 `mode`。
    pub mode: SnellMode,
    pub reuse: bool,
    pub udp: bool,
}

/// NaïveProxy：TLS + HTTP/2/HTTP/3 CONNECT，前 8 个数据块带填充。
#[derive(Debug, Clone)]
pub struct NaiveSpec {
    pub server: TargetAddr,
    pub username: String,
    pub password: String,
    pub tls: TlsSpec,
    /// 使用 HTTP/3（QUIC）承载 CONNECT；缺省为 HTTP/2。
    pub quic: bool,
    /// 附加在 CONNECT 请求上的首部（sing-box 的 `extra_headers`）。
    pub headers: Vec<(String, String)>,
    /// `udp: true` 时 UDP 走 UoT，值为版本（缺省 2，与 sing-box 相同）。
    pub uot: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshUdpMode {
    BadVpn,
    Tun2Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshUdpSpec {
    pub mode: SshUdpMode,
    /// SSH 服务器侧 UDP 网关的 TCP 监听地址。
    pub server: std::net::SocketAddr,
}

/// SSH 出站：每个 Flow 一个 `direct-tcpip` 通道，同一出站共享一条 SSH 连接。
#[derive(Debug, Clone)]
pub struct SshSpec {
    pub server: TargetAddr,
    pub username: String,
    pub password: Option<String>,
    /// 内联的私钥（OpenSSH / PEM / PuTTY 格式文本）。
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    /// `authorized_keys` 格式的主机公钥；为空时不校验（与 mihomo 相同）。
    pub host_keys: Vec<String>,
    pub host_key_algorithms: Vec<String>,
    /// Oryn 扩展：默认 None，普通 mihomo udp 字段不启用。
    pub udp_gateway: Option<SshUdpSpec>,
}

/// 与 sing-box 的会合服务一致：每次最多上报 8 个地址。
pub const REALM_MAX_ADDRESSES: usize = 8;
pub const REALM_MAX_STUN_SERVERS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

#[derive(Debug, Clone)]
pub struct TuicSpec {
    pub server: TargetAddr,
    pub uuid: [u8; 16],
    pub password: String,
    pub udp_relay: UdpRelayMode,
    pub congestion: QuicCongestion,
    pub heartbeat_ms: u64,
    pub tls: TlsSpec,
    pub disable_sni: bool,
    pub max_udp_packet: usize,
    pub max_streams: usize,
    pub udp: bool,
    /// `udp-over-stream`：UDP 改走 TUIC TCP 流上的 UoT，值为 UoT 版本（1 或 2）。
    pub udp_over_stream: Option<u8>,
    /// `reduce-rtt`：有会话票据时以 0-RTT 建立 QUIC 连接。
    pub reduce_rtt: bool,
}

#[derive(Debug, Clone)]
pub struct WireGuardPeerSpec {
    pub endpoint: TargetAddr,
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<IpCidr>,
    pub reserved: [u8; 3],
    /// 本对端的 persistent keepalive（秒，0 关闭），`None` 沿用接口级 `keepalive_secs`。
    /// 配置文件没有对应字段；Tailscale 只给有直连端点的对端开启。
    pub keepalive_secs: Option<u16>,
}

/// AmneziaWG 1.0：握手前垃圾包、握手填充与消息类型替换。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmneziaSpec {
    pub jc: u8,
    pub jmin: u16,
    pub jmax: u16,
    pub s1: u16,
    pub s2: u16,
    pub h: [u32; 4],
}

#[derive(Debug, Clone)]
pub struct WireGuardSpec {
    /// 至少一个；多个时按目的地址匹配 `allowed_ips`（最长前缀）选择对端。
    pub peers: Vec<WireGuardPeerSpec>,
    pub private_key: [u8; 32],
    pub address_v4: Option<(std::net::Ipv4Addr, u8)>,
    pub address_v6: Option<(std::net::Ipv6Addr, u8)>,
    pub mtu: u16,
    pub keepalive_secs: u16,
    pub udp: bool,
    pub remote_dns: bool,
    pub dns: Vec<std::net::SocketAddr>,
    pub amnezia: Option<AmneziaSpec>,
    /// 定期重新解析对端域名的间隔（秒）。
    pub refresh_secs: Option<u64>,
    /// 隧道内 TCP 的缓冲与合计预算（Oryn 扩展）。
    pub tcp_buffers: WireGuardTcpBuffers,
}

/// WireGuard 隧道内 smoltcp TCP 的动态缓冲：`tcp-rx-buffer`、`tcp-tx-buffer`（每连接上限）、
/// `tcp-buffer-budget`（全部连接合计），单位字节。连接从 `RX_INITIAL` / `TX_INITIAL` 开始按需扩容。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireGuardTcpBuffers {
    pub rx: usize,
    pub tx: usize,
    /// 本出站全部 TCP 连接的接收 + 发送缓冲合计上限。
    pub budget: usize,
}

impl WireGuardTcpBuffers {
    pub const RX_DEFAULT: usize = 256 * 1024;
    pub const TX_DEFAULT: usize = 128 * 1024;
    /// 配置允许的最小上限，也是新连接的初始大小。
    pub const RX_MIN: usize = 16 * 1024;
    pub const TX_MIN: usize = 8 * 1024;
    pub const RX_INITIAL: usize = Self::RX_MIN;
    pub const TX_INITIAL: usize = Self::TX_MIN;
    pub const BUFFER_MAX: usize = 4 * 1024 * 1024;
    /// 默认预算：与改为动态缓冲之前「64 条 64 + 32 KiB 连接」的最坏内存相同。
    pub const BUDGET_DEFAULT: usize = 6 * 1024 * 1024;
    pub const BUDGET_MAX: usize = 64 * 1024 * 1024;

    /// 未写 `tcp-buffer-budget` 时的预算：至少容纳一条用满上限的连接。
    pub fn default_budget(rx: usize, tx: usize) -> usize {
        Self::BUDGET_DEFAULT.max(rx + tx).min(Self::BUDGET_MAX)
    }
}

impl Default for WireGuardTcpBuffers {
    fn default() -> Self {
        Self {
            rx: Self::RX_DEFAULT,
            tx: Self::TX_DEFAULT,
            budget: Self::default_budget(Self::RX_DEFAULT, Self::TX_DEFAULT),
        }
    }
}

/// mihomo Tailscale 节点；enabled 是默认关闭的 Oryn 扩展。
#[derive(Debug, Clone)]
pub struct TailscaleSpec {
    pub enabled: bool,
    pub hostname: Option<String>,
    pub auth_key: Option<String>,
    pub control_url: String,
    pub state_dir: String,
    pub ephemeral: bool,
    pub udp: bool,
    pub accept_routes: Option<bool>,
    pub exit_node: Option<String>,
    pub exit_node_allow_lan_access: Option<bool>,
}

#[derive(Debug, Clone)]
pub enum OutboundKind {
    Direct,
    Reject,
    Socks5 {
        server: TargetAddr,
        auth: Option<ProxyAuth>,
        udp: bool,
        tls: Option<TlsSpec>,
    },
    Http {
        server: TargetAddr,
        auth: Option<ProxyAuth>,
        tls: Option<TlsSpec>,
    },
    Shadowsocks {
        server: TargetAddr,
        cipher: String,
        password: String,
        udp: bool,
        plugin: SsPlugin,
        /// UDP over TCP 的版本（1 或 2）。
        uot: Option<u8>,
        mux: Option<MuxSpec>,
    },
    Trojan {
        stream: StreamProxySpec,
        password: String,
    },
    Vless {
        stream: StreamProxySpec,
        uuid: [u8; 16],
    },
    Vmess {
        stream: StreamProxySpec,
        protocol: VmessSpec,
    },
    AnyTls(AnyTlsSpec),
    /// ShadowsocksR（0.8.x）。
    Ssr(SsrSpec),
    Sudoku(SudokuSpec),
    ShadowQuic(ShadowQuicSpec),
    Mieru(MieruSpec),
    Snell(SnellSpec),
    Naive(NaiveSpec),
    Ssh(SshSpec),
    Hysteria2(Hysteria2Spec),
    /// Hysteria v1（0.8.x）。
    Hysteria(HysteriaSpec),
    Tuic(TuicSpec),
    WireGuard(WireGuardSpec),
    Tailscale(TailscaleSpec),
    Group(GroupSpec),
}

impl OutboundKind {
    /// 出站连接的远端服务器地址（诊断展示用）；直连、拒绝、策略组与 Tailscale 没有。
    pub fn server_addr(&self) -> Option<&TargetAddr> {
        match self {
            OutboundKind::Socks5 { server, .. }
            | OutboundKind::Http { server, .. }
            | OutboundKind::Shadowsocks { server, .. } => Some(server),
            OutboundKind::Trojan { stream, .. }
            | OutboundKind::Vless { stream, .. }
            | OutboundKind::Vmess { stream, .. } => Some(&stream.server),
            OutboundKind::AnyTls(s) => Some(&s.server),
            OutboundKind::Ssr(s) => Some(&s.server),
            OutboundKind::Sudoku(s) => Some(&s.server),
            OutboundKind::ShadowQuic(s) => Some(&s.server),
            OutboundKind::Mieru(s) => Some(&s.server),
            OutboundKind::Snell(s) => Some(&s.server),
            OutboundKind::Naive(s) => Some(&s.server),
            OutboundKind::Ssh(s) => Some(&s.server),
            OutboundKind::Hysteria2(s) => Some(&s.server),
            OutboundKind::Hysteria(s) => Some(&s.server),
            OutboundKind::Tuic(s) => Some(&s.server),
            OutboundKind::WireGuard(s) => s.peers.first().map(|p| &p.endpoint),
            _ => None,
        }
    }
}

impl OutboundKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            OutboundKind::Direct => "direct",
            OutboundKind::Reject => "reject",
            OutboundKind::Socks5 { .. } => "socks5",
            OutboundKind::Http { .. } => "http",
            OutboundKind::Shadowsocks { .. } => "ss",
            OutboundKind::Trojan { .. } => "trojan",
            OutboundKind::Vless { .. } => "vless",
            OutboundKind::Vmess { .. } => "vmess",
            OutboundKind::AnyTls(_) => "anytls",
            OutboundKind::Ssr(_) => "ssr",
            OutboundKind::Sudoku(_) => "sudoku",
            OutboundKind::ShadowQuic(_) => "shadowquic",
            OutboundKind::Mieru(_) => "mieru",
            OutboundKind::Snell(_) => "snell",
            OutboundKind::Naive(_) => "naive",
            OutboundKind::Ssh(_) => "ssh",
            OutboundKind::Hysteria2(_) => "hysteria2",
            OutboundKind::Hysteria(_) => "hysteria",
            OutboundKind::Tuic(_) => "tuic",
            OutboundKind::WireGuard(_) => "wireguard",
            OutboundKind::Tailscale(_) => "tailscale",
            OutboundKind::Group(g) => g.kind.type_name(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GroupSpec {
    pub smart: crate::SmartSpec,
    pub kind: GroupKind,
    /// `RuntimeConfig::outbounds` 的下标。
    pub members: Vec<usize>,
    pub health: HealthSpec,
    pub disable_udp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    Smart,
    Select,
    UrlTest { tolerance_ms: u32 },
    Fallback,
    LoadBalance(LbStrategy),
}

impl GroupKind {
    pub fn type_name(self) -> &'static str {
        match self {
            GroupKind::Smart => "smart",
            GroupKind::Select => "select",
            GroupKind::UrlTest { .. } => "url-test",
            GroupKind::Fallback => "fallback",
            GroupKind::LoadBalance(_) => "load-balance",
        }
    }

    /// 是否需要定期健康检查。
    pub fn needs_health_check(self) -> bool {
        !matches!(self, GroupKind::Select | GroupKind::Smart)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbStrategy {
    ConsistentHashing,
    RoundRobin,
    StickySessions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSpec {
    pub url: String,
    pub interval_secs: u64,
    pub timeout_ms: u64,
    pub lazy: bool,
}

impl Default for HealthSpec {
    fn default() -> Self {
        HealthSpec {
            url: DEFAULT_TEST_URL.into(),
            interval_secs: 300,
            timeout_ms: 5000,
            lazy: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// `RuntimeConfig::outbounds` 的下标。
    Outbound(usize),
    /// 跳过本条规则，继续匹配。
    Pass,
}

#[derive(Debug, Clone)]
pub enum RuleKind {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainWildcard(String),
    DomainRegex(String),
    IpCidr(IpCidr),
    /// 大写国家代码，或 `LAN`。
    GeoIp(String),
    /// 目的 IP 的自治系统号（ASN 数据库）。
    IpAsn(u32),
    DstPort(Vec<PortRange>),
    Network(NetworkKind),
    /// `PROTOCOL`：按连接的应用层协议匹配（路由前读首包判断）。
    Protocol(ProtocolKind),
    /// `USER-AGENT`：明文 HTTP 请求的 User-Agent，`*` / `?` 通配符，不区分大小写。
    UserAgent(String),
    /// `URL-REGEX`：明文 HTTP 请求的完整地址（`http://主机/路径`）。
    UrlRegex(String),
    /// `PROCESS-NAME`：Android 应用包名。iOS 不支持，解析时忽略。
    ProcessName(String),
    /// `RuntimeConfig::providers` 的下标。
    RuleSet(usize),
    /// `AND` / `OR` / `NOT`：子规则各自带 `no-resolve`。`NOT` 只有一条子规则。
    Logic(LogicOp, Vec<SubRule>),
    /// 用源地址代替目的地址匹配（`SRC-IP-CIDR` 等，或 IP 类规则末尾的 `src`）。
    /// 只包裹 IP / 端口 / 规则集类规则；域名与网络类型不变。
    Src(Box<RuleKind>),
    Final,
}

impl RuleKind {
    /// 是否需要 GEOIP / ASN 数据库（`GEOIP,LAN` 除外）。
    pub fn needs_geo_db(&self) -> bool {
        match self {
            RuleKind::GeoIp(c) => c != "LAN",
            RuleKind::IpAsn(_) => true,
            RuleKind::Logic(_, subs) => subs.iter().any(|s| s.kind.needs_geo_db()),
            RuleKind::Src(k) => k.needs_geo_db(),
            _ => false,
        }
    }
}

/// `PROTOCOL` 规则的取值。`TCP` / `UDP` 与 `NETWORK` 相同，其余需要首包。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Tcp,
    Udp,
    /// 明文 HTTP 请求。
    Http,
    /// TCP 上的 TLS（不区分 HTTPS 与其它 TLS 协议）。
    Https,
    /// QUIC Initial 包。
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicOp {
    And,
    Or,
    Not,
}

#[derive(Debug, Clone)]
pub struct SubRule {
    pub kind: RuleKind,
    pub no_resolve: bool,
}

#[derive(Debug, Clone)]
pub struct RuleSpec {
    pub kind: RuleKind,
    pub policy: Policy,
    /// Fake-IP Flow 不对本条 IP 类规则做真实解析。
    pub no_resolve: bool,
    /// 展示用原文。
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    Domain,
    IpCidr,
    Classical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFormat {
    Text,
    Yaml,
}

/// `domain` 规则集中 `.a.com` 的含义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainStyle {
    /// 只匹配子域名。
    Mihomo,
    /// 匹配 `a.com` 及子域名（Surge 域名集）。
    Surge,
}

#[derive(Debug, Clone)]
pub enum ProviderSource {
    Http {
        url: String,
        /// 自动更新间隔；`None` 表示不自动更新（本地没有缓存时仍会下载）。
        interval_secs: Option<u64>,
        /// 下载走哪里：默认遵循分流规则，`proxy: DIRECT` 为直连，也可以指定某个节点或策略组。
        via: ProviderVia,
        /// 0 表示不限制。
        size_limit: u64,
        /// 相对于数据目录的缓存文件路径。
        cache_path: String,
    },
    File {
        /// 相对于数据目录。
        path: String,
    },
    Inline {
        payload: Vec<String>,
    },
}

/// 代理集合。节点在解析配置时从内联内容或缓存展开为普通出站。
#[derive(Debug, Clone)]
pub struct ProxyProviderSpec {
    pub name: String,
    pub source: ProxyProviderSource,
    /// 集合的节点在 `RuntimeConfig::outbounds` 中的下标。
    pub members: Vec<usize>,
    /// 集合自带的健康检查（`health-check`）：定期测试集合的全部节点，结果供各策略组显示与选择。
    pub health: Option<HealthSpec>,
    /// 解析时是否拿到了内容（内联、文件或缓存）。
    pub loaded: bool,
    /// 内容存在但无法使用时的原因。
    pub error: Option<String>,
}

/// 订阅、规则集等远程资源下载使用的出站。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderVia {
    /// 与普通流量一样遵循分流规则（按订阅地址的域名匹配）。
    Rules,
    /// `RuntimeConfig::outbounds` 的下标（DIRECT 也是其中之一）。
    Outbound(usize),
}

#[derive(Debug, Clone)]
pub enum ProxyProviderSource {
    Http {
        url: String,
        interval_secs: Option<u64>,
        /// 下载走哪里：默认遵循分流规则，`proxy: DIRECT` 为直连，也可以指定某个节点或策略组。
        via: ProviderVia,
        size_limit: u64,
        /// 相对数据目录。
        cache_path: String,
        headers: Vec<(String, String)>,
    },
    /// 相对数据目录。
    File {
        path: String,
    },
    Inline,
}

impl ProxyProviderSpec {
    /// 需要从数据目录读取的文件（http 的缓存或 file 的路径）。
    pub fn file_path(&self) -> Option<&str> {
        match &self.source {
            ProxyProviderSource::Http { cache_path, .. } => Some(cache_path),
            ProxyProviderSource::File { path } => Some(path),
            ProxyProviderSource::Inline => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderSpec {
    pub name: String,
    pub source: ProviderSource,
    pub behavior: Behavior,
    pub format: ProviderFormat,
    pub domain_style: DomainStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProto {
    Tailscale,
    Udp,
    Tcp,
    Tls,
    Https,
    H3,
    Quic,
}

impl DnsProto {
    pub fn default_port(self) -> u16 {
        match self {
            DnsProto::Tailscale | DnsProto::Udp | DnsProto::Tcp => 53,
            DnsProto::Tls | DnsProto::Quic => 853,
            DnsProto::Https | DnsProto::H3 => 443,
        }
    }

    pub fn is_encrypted(self) -> bool {
        !matches!(self, DnsProto::Udp | DnsProto::Tcp)
    }
}

/// 查询发往该服务器时使用的出站。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsVia {
    /// 由 `respect-rules` 决定。
    Default,
    Rules,
    Direct,
    Outbound(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSpec {
    /// 原文，用于展示与连接复用。
    pub raw: String,
    pub proto: DnsProto,
    /// IP 或域名。
    pub host: String,
    pub port: u16,
    /// DoH / DoH3 的路径。
    pub path: String,
    pub via: DnsVia,
    pub ecs: Option<IpCidr>,
    pub ecs_override: bool,
    pub skip_cert_verify: bool,
    pub disable_ipv4: bool,
    pub disable_ipv6: bool,
}

impl ServerSpec {
    pub fn host_ip(&self) -> Option<IpAddr> {
        self.host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .ok()
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamGroup {
    pub name: String,
    pub servers: Vec<ServerSpec>,
}

#[derive(Debug, Clone)]
pub enum ForwardTarget {
    /// `DnsSpec::upstreams` 的下标。
    Upstream(usize),
    Servers(Vec<ServerSpec>),
    Bootstrap,
    Reject,
}

#[derive(Debug, Clone)]
pub enum ForwardMatch {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainWildcard(String),
    DomainRegex(String),
    Pattern(DomainPattern),
    RuleSet(usize),
    Ssid(String),
    Bssid(String),
    Cellular(String),
    Final,
}

#[derive(Debug, Clone)]
pub struct ForwardRule {
    pub matcher: ForwardMatch,
    pub target: ForwardTarget,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RejectResponse {
    #[default]
    Refused,
    NxDomain,
}

/// Fake-IP 过滤名单的匹配方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeIpFilter {
    Domain(DomainPattern),
    /// 含有跨标签通配的 mihomo 写法。
    Glob(String),
    RuleSet(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FakeIpFilterMode {
    /// 名单中的域名走真实上游，其余域名返回 Fake-IP。
    #[default]
    Blacklist,
    /// 只有名单中的域名返回 Fake-IP，其余域名走真实上游。
    Whitelist,
}

/// mihomo 兼容的 Fake-IP 默认过滤名单。
pub const DEFAULT_FAKE_IP_FILTER: &[&str] = &[
    "*.lan",
    "*.local",
    "*.localdomain",
    "*.home.arpa",
    "captive.apple.com",
    "time.apple.com",
    "time.*.com",
    "+.pool.ntp.org",
    "+.stun.*.*",
    "+.msftconnecttest.com",
    "+.msftncsi.com",
    "localhost.ptlogin2.qq.com",
];

#[derive(Debug, Clone)]
pub struct DnsSpec {
    pub bootstrap: Vec<ServerSpec>,
    pub nameserver: Vec<ServerSpec>,
    /// 为空表示未配置代理域名服务器。
    pub proxy_server: Vec<ServerSpec>,
    pub upstreams: Vec<UpstreamGroup>,
    pub forward: Vec<ForwardRule>,
    pub use_hosts: bool,
    pub ipv6: bool,
    pub respect_rules: bool,
    pub skip_cert_verify: bool,
    pub blocked_ips: Vec<IpCidr>,
    pub public_ip_url: Option<String>,
    pub reject_response: RejectResponse,
    /// Fake-IP 地址池，只接受 IPv4；默认是 198.18.0.0/15（运行时跳过 198.18.0.0/24）。
    pub fake_ip_range: IpCidr,
    pub fake_ip_filter: Vec<FakeIpFilter>,
    pub fake_ip_filter_mode: FakeIpFilterMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostValue {
    Ips(Vec<IpAddr>),
    Alias(String),
}

#[derive(Debug, Clone)]
pub struct HostEntry {
    pub pattern: DomainPattern,
    pub value: HostValue,
}

#[derive(Debug, Clone)]
pub struct SniffProto {
    pub enabled: bool,
    pub ports: Vec<PortRange>,
    pub override_destination: bool,
}

impl SniffProto {
    pub fn applies(&self, port: u16) -> bool {
        self.enabled && self.ports.iter().any(|r| r.contains(port))
    }
}

#[derive(Debug, Clone)]
pub struct SnifferSpec {
    pub enable: bool,
    pub force_dns_mapping: bool,
    pub parse_pure_ip: bool,
    pub http: SniffProto,
    pub tls: SniffProto,
    pub quic: SniffProto,
    pub force_domain: Vec<DomainPattern>,
    pub skip_domain: Vec<DomainPattern>,
    pub skip_src: Vec<IpCidr>,
    pub skip_dst: Vec<IpCidr>,
}

#[derive(Debug, Clone)]
pub struct GeoIpSpec {
    pub url: String,
    pub asn_url: Option<String>,
    pub auto_update: bool,
    pub interval_hours: u64,
}

/// Shadowsocks 的 AEAD 加密方式（不含 2022）。
pub const SS_AEAD_CIPHERS: &[&str] = &[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
];

/// Shadowsocks / ShadowsocksR 的旧流式加密与明文方式（没有认证，只为兼容旧服务端或内层已有加密的场景）。
pub const SS_STREAM_CIPHERS: &[&str] = &[
    "none",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
];

/// ShadowsocksR 的协议插件。
pub const SSR_PROTOCOLS: &[&str] = &[
    "origin",
    "auth_sha1_v4",
    "auth_aes128_md5",
    "auth_aes128_sha1",
    "auth_chain_a",
    "auth_chain_b",
];

/// ShadowsocksR 的混淆插件（`tls1.2_ticket_fastauth` 与 `tls1.2_ticket_auth` 相同）。
pub const SSR_OBFS: &[&str] = &[
    "plain",
    "http_simple",
    "http_post",
    "random_head",
    "tls1.2_ticket_auth",
    "tls1.2_ticket_fastauth",
];

#[derive(Debug, Clone)]
pub struct SsrSpec {
    pub server: TargetAddr,
    /// 流式加密方式（`SS_STREAM_CIPHERS`）或 `none`。
    pub cipher: String,
    pub password: String,
    pub protocol: String,
    pub protocol_param: String,
    pub obfs: String,
    pub obfs_param: String,
    pub udp: bool,
}

#[derive(Debug, Clone)]
pub struct HysteriaSpec {
    pub server: TargetAddr,
    /// QUIC 外层承载：udp、wechat-video 或 faketcp（后者未实现，运行时在所有平台拒绝）。
    pub protocol: String,
    pub ports: Option<PortSet>,
    /// `auth-str` 的字节，或 `auth`（Base64）解码后的字节。
    pub auth: Vec<u8>,
    /// 字节/秒，两个方向都必填（协议要求）。
    pub up_bps: u64,
    pub down_bps: u64,
    /// XPlus 混淆口令。
    pub obfs: Option<String>,
    pub tls: TlsSpec,
    pub hop_min_secs: u64,
    pub hop_max_secs: u64,
    pub udp: bool,
}

/// MITM 只对显式主机列表生效；CA 路径由平台传入，不允许远程模块替换。
#[derive(Debug, Clone)]
pub struct MitmSpec {
    pub enabled: bool,
    pub hostnames: Vec<String>,
    pub http2: bool,
    pub auto_quic_block: bool,
    pub skip_server_cert_verify: bool,
}
impl Default for MitmSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            hostnames: vec![],
            http2: true,
            auto_quic_block: true,
            skip_server_cert_verify: false,
        }
    }
}
impl MitmSpec {
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if !self.enabled {
            return false;
        }
        let mut included = false;
        for item in &self.hostnames {
            let (exclude, pattern) = item
                .strip_prefix('-')
                .map_or((false, item.as_str()), |p| (true, p));
            if !crate::listed_host_matches(pattern, Some(host), port, crate::ListedPort::Fixed(443))
            {
                continue;
            }
            if exclude {
                return false;
            }
            included = true;
        }
        included
    }
}
