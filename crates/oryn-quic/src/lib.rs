//! Hysteria2 与 TUIC 共用的 QUIC 客户端。
//!
//! 窗口和队列按设计取保守值，未经真机验证。不使用连接迁移：网络变化时丢掉连接。

mod brutal;
mod negotiated;
pub use negotiated::NegotiatedFactory;
mod session;
mod socket;

pub use brutal::BrutalFactory;
pub use session::{
    zero_rtt_accepted, Congestion, Handshake, Hop, QuicClient, QuicParams, Rendezvous,
};
pub use socket::{Obfs, Salamander};

/// 发送窗口（已发出未确认的字节上限）。吞吐 ≤ 窗口 ÷ 往返时延：256 KiB 在 100 ms 往返下只有约 20 Mbit/s。
pub const SEND_WINDOW: u64 = 1024 * 1024;
/// Brutal 连接的发送窗口。Brutal 按「速率 × RTT × 2」给窗口，固定 1 MiB 会把 100 Mbit/s × 100 ms
/// （2.5 MiB）钳到配置速率的约 40%。只在 Brutal 生效的连接上放宽；未确认数据才占内存，
/// 上限 4 MiB 只在高 RTT 满速上传时触及。
pub const BRUTAL_SEND_WINDOW: u64 = 4 * 1024 * 1024;

/// 连接接收窗口，也是一条连接缓存未读数据的上限。
pub const RECEIVE_WINDOW: u32 = 6 * 1024 * 1024;
/// 每流接收窗口。QUIC 在窗口用掉一半后才补发额度，单流吞吐约等于「窗口的一半 ÷ 往返时延」：
/// 64 KiB 在真机 5.5 ms 往返下只有 45–50 Mbit/s（TCP 同条件 350 Mbit/s）。
/// 连接窗口 6 MiB，所以不超过 5 条读者停滞的流不会占满它、拖住同一连接上的其它流。
pub const STREAM_RECEIVE_WINDOW: u32 = 1024 * 1024;
/// 数据报接收缓冲。
pub const DATAGRAM_RECEIVE: usize = 128 * 1024;
/// 数据报发送缓冲。
pub const DATAGRAM_SEND: usize = 64 * 1024;
/// 客户端同时打开的双向流上限。这是本端计数，不等于对端宣布的上限。
pub const MAX_BIDI: usize = 128;
/// 对端同时可对我们打开的单向流上限。TUIC `udp-relay-mode: quic` 每个 UDP 包占一条单向流，
/// 并发会话多时回包会同时到达；sing-box（quic-go）在额度用尽时直接丢包而不是排队，
/// 所以不能太小。额度只有流读完才归还，也因此天然限制了同时读取的任务数。
pub const MAX_UNI: usize = 128;
/// Hysteria 系协议的 QUIC 保活间隔，与官方客户端默认值相同（10 s，小于两端 30 s 的空闲超时）。
pub const KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(10);
/// quinn 看到的 UDP 负载上限。Salamander 另外加 8 字节盐。
pub const MAX_UDP_PAYLOAD: u16 = 1200;
