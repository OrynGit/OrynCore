//! mihomo/Xray mKCP 字节流适配。
//!
//! 协议格式参考 https://github.com/MetaCubeX/mihomo 的
//! transport/mkcp/{auth,header,packet,segment,conn}.go，
//! commit 88dcbf7f1614a67c3b36b848ee3592dfa92ada36 (v1.19.32)，GPL-3.0。
//! 原文件未含独立版权声明；Rust 状态机按 Oryn 有界 Flow 接口重写。
//!
//! mKCP 与传统 KCP 的线格式不同：segment 使用大端序、conversation 是 16 位，
//! 包级认证在 segment 外层，header 混淆位于认证之前。这里保留一个有界的
//! Tokio 适配层，所有发送、接收、重排和重传缓存都受 KcpSpec 限制。

use oryn_config::KcpSpec;
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM},
    digest,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicU32, Ordering},
    task::{ready, Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::{mpsc, oneshot},
};

const DATA_OVERHEAD: usize = 18;
const ACK_BASE: usize = 17;
const CMD_BASE: usize = 16;
const MAX_PACKET: usize = 1500;
// mihomo 的 seeded MSS 没有扣除 12 字节 nonce；低 MTU 还会把 MSS 提升到
// 576。仅接收侧预留固定余量，自己的输出始终遵守配置 MTU。
pub(crate) const MAX_WIRE_PACKET: usize = MAX_PACKET + 64;
const MAX_BAD_PACKETS: usize = 32;
static NEXT_CONV: AtomicU32 = AtomicU32::new(1);
// 仅限制已 Drop 的关闭 waiter；活跃 KCP 上下文仍由调用方管理，无独立全局数量上限。
static CLOSE_WAITERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);

/// mKCP 的包输入输出。裸 UDP 与 Mekya HTTP 外层共用同一状态机；外层
/// 只负责将完整认证包交给这里，禁止把 HTTP 字节直接混入 KCP 解析器。
pub trait PacketIo: Send + 'static {
    fn send<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;
}

impl PacketIo for UdpSocket {
    fn send<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { UdpSocket::send(self, packet).await.map(|_| ()) })
    }
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move { UdpSocket::recv(self, buf).await })
    }
}

const CMD_ACK: u8 = 0;
const CMD_DATA: u8 = 1;
const CMD_TERMINATE: u8 = 2;
const CMD_PING: u8 = 3;
// mihomo/Xray cap the selective ACK list at 128 entries.  The count is a
// single byte on the wire, but accepting a larger list would permit an ACK
// packet to consume the whole MTU and diverge from the peer's flush policy.
const MAX_ACK_NUMBERS: usize = 128;
/// 确认最多延迟这么久再发，期间到达的数据报合并进同一个确认。
const ACK_DELAY: Duration = Duration::from_millis(2);
/// 攒到这么多个数据报立即确认，让对端的窗口及时前移。
const ACK_BATCH: u32 = 16;

#[derive(Clone, Copy)]
struct HeaderState {
    kind: HeaderKind,
    sequence: u32,
    connection_id: u16,
    epoch: u16,
    dtls_length: u16,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderKind {
    None,
    Srtp,
    Utp,
    Wechat,
    Dtls,
    Wireguard,
}

impl HeaderState {
    fn new(name: &str) -> io::Result<Self> {
        let kind = match name.to_ascii_lowercase().as_str() {
            "" | "none" | "noop" => HeaderKind::None,
            "srtp" => HeaderKind::Srtp,
            "utp" => HeaderKind::Utp,
            "wechat" | "wechat-video" => HeaderKind::Wechat,
            "dtls" => HeaderKind::Dtls,
            "wireguard" => HeaderKind::Wireguard,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported mKCP header type",
                ))
            }
        };
        let mut random = [0u8; 4];
        let _ = SystemRandom::new().fill(&mut random);
        Ok(Self {
            kind,
            // The upstream DTLS-shaped header starts its 32-bit sequence at
            // zero; the other obfuscators intentionally use a random initial
            // value (SRTP/WeChat).  Keeping this distinction matters when a
            // peer compares the first header bytes.
            sequence: if kind == HeaderKind::Dtls {
                0
            } else {
                u32::from_be_bytes(random)
            },
            connection_id: u16::from_be_bytes([random[0], random[1]]),
            epoch: u16::from_be_bytes([random[2], random[3]]),
            dtls_length: 17,
        })
    }
    fn len(self) -> usize {
        match self.kind {
            HeaderKind::None => 0,
            HeaderKind::Srtp | HeaderKind::Utp | HeaderKind::Wireguard => 4,
            HeaderKind::Wechat | HeaderKind::Dtls => 13,
        }
    }
    fn write(&mut self, out: &mut Vec<u8>) {
        match self.kind {
            HeaderKind::None => {}
            HeaderKind::Srtp => {
                self.sequence = self.sequence.wrapping_add(1);
                out.extend_from_slice(&0xb5e8u16.to_be_bytes());
                out.extend_from_slice(&(self.sequence as u16).to_be_bytes());
            }
            HeaderKind::Utp => {
                out.extend_from_slice(&self.connection_id.to_be_bytes());
                out.extend_from_slice(&[1, 0]);
            }
            HeaderKind::Wechat => {
                self.sequence = self.sequence.wrapping_add(1);
                out.extend_from_slice(&[0xa1, 0x08]);
                out.extend_from_slice(&self.sequence.to_be_bytes());
                out.extend_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
            }
            HeaderKind::Dtls => {
                out.extend_from_slice(&[23, 254, 253]);
                out.extend_from_slice(&self.epoch.to_be_bytes());
                out.extend_from_slice(&[0, 0]);
                out.extend_from_slice(&self.sequence.to_be_bytes());
                out.extend_from_slice(&self.dtls_length.to_be_bytes());
                // The upstream header writes sequence zero on the first
                // packet, then advances it for the next datagram.
                self.sequence = self.sequence.wrapping_add(1);
                self.dtls_length = self.dtls_length.saturating_add(17);
                if self.dtls_length > 100 {
                    self.dtls_length = self.dtls_length.saturating_sub(50);
                }
            }
            HeaderKind::Wireguard => out.extend_from_slice(&[4, 0, 0, 0]),
        }
    }
    fn check(self, packet: &[u8]) -> bool {
        match self.kind {
            HeaderKind::None => true,
            HeaderKind::Srtp => packet.len() >= 4 && packet[..2] == [0xb5, 0xe8],
            HeaderKind::Utp => packet.len() >= 4 && packet[2] == 1,
            // Only the fixed trailer occupies bytes 6..13.  Comparing
            // packet[6..] would include the authenticated mKCP body and
            // reject every valid packet carrying a segment.
            HeaderKind::Wechat => {
                packet.len() >= 13
                    && packet[..2] == [0xa1, 0x08]
                    && packet[6..13] == [0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]
            }
            HeaderKind::Dtls => packet.len() >= 13 && packet[..3] == [23, 254, 253],
            HeaderKind::Wireguard => packet.len() >= 4 && packet[..4] == [4, 0, 0, 0],
        }
    }
}

#[derive(Clone)]
struct Segment {
    conv: u16,
    command: u8,
    option: u8,
    timestamp: u32,
    number: u32,
    sending_next: u32,
    payload: Vec<u8>,
    received_at: Instant,
    transmitted: u8,
}

fn put_data(conv: u16, seg: &Segment) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_OVERHEAD + seg.payload.len());
    out.extend_from_slice(&conv.to_be_bytes());
    out.extend_from_slice(&[CMD_DATA, seg.option]);
    out.extend_from_slice(&seg.timestamp.to_be_bytes());
    out.extend_from_slice(&seg.number.to_be_bytes());
    out.extend_from_slice(&seg.sending_next.to_be_bytes());
    out.extend_from_slice(&(seg.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&seg.payload);
    out
}
fn put_ack(conv: u16, window: u32, next: u32, timestamp: u32, list: &[u32]) -> Vec<u8> {
    let count = list.len().min(MAX_ACK_NUMBERS);
    let mut out = Vec::with_capacity(ACK_BASE + count * 4);
    out.extend_from_slice(&conv.to_be_bytes());
    out.extend_from_slice(&[CMD_ACK, 0]);
    out.extend_from_slice(&window.to_be_bytes());
    out.extend_from_slice(&next.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.push(count as u8);
    for sn in &list[..count] {
        out.extend_from_slice(&sn.to_be_bytes());
    }
    out
}
fn put_cmd(conv: u16, command: u8, next: u32, receive_next: u32, rto: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(CMD_BASE);
    out.extend_from_slice(&conv.to_be_bytes());
    out.extend_from_slice(&[command, 0]);
    out.extend_from_slice(&next.to_be_bytes());
    out.extend_from_slice(&receive_next.to_be_bytes());
    out.extend_from_slice(&rto.to_be_bytes());
    out
}

fn parse_segments(mut bytes: &[u8], max_payload: usize) -> Vec<Segment> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let conv = u16::from_be_bytes([bytes[0], bytes[1]]);
        let command = bytes[2];
        let option = bytes[3];
        bytes = &bytes[4..];
        match command {
            CMD_DATA => {
                if bytes.len() < 14 {
                    break;
                }
                let len = u16::from_be_bytes([bytes[12], bytes[13]]) as usize;
                if len > max_payload || bytes.len() < 14 + len {
                    break;
                }
                out.push(Segment {
                    conv,
                    command,
                    option,
                    timestamp: u32::from_be_bytes(bytes[..4].try_into().unwrap()),
                    number: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                    sending_next: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
                    payload: bytes[14..14 + len].to_vec(),
                    received_at: Instant::now(),
                    transmitted: 0,
                });
                bytes = &bytes[14 + len..];
            }
            CMD_ACK => {
                if bytes.len() < 13 {
                    break;
                }
                let count = bytes[12] as usize;
                if count > MAX_ACK_NUMBERS || bytes.len() < 13 + count * 4 {
                    break;
                }
                let mut list = Vec::with_capacity(count);
                for i in 0..count {
                    let at = 13 + i * 4;
                    list.push(u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()));
                }
                out.push(Segment {
                    conv,
                    command,
                    option,
                    timestamp: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
                    number: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                    sending_next: u32::from_be_bytes(bytes[..4].try_into().unwrap()),
                    payload: list.into_iter().flat_map(|v| v.to_be_bytes()).collect(),
                    received_at: Instant::now(),
                    transmitted: 0,
                });
                bytes = &bytes[13 + count * 4..];
            }
            // Xray treats any command other than DATA/ACK as a command-only
            // segment.  Keeping the 12-byte command payload lets us skip an
            // extension command while continuing to parse following segments
            // in the same authenticated datagram.
            _ => {
                if bytes.len() < 12 {
                    break;
                }
                out.push(Segment {
                    conv,
                    command,
                    option,
                    timestamp: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
                    number: u32::from_be_bytes(bytes[..4].try_into().unwrap()),
                    sending_next: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                    payload: Vec::new(),
                    received_at: Instant::now(),
                    transmitted: 0,
                });
                bytes = &bytes[12..];
            }
        }
    }
    out
}

fn simple_seal(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + plain.len());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(plain.len() as u16).to_be_bytes());
    out.extend_from_slice(plain);
    let mut hash = 2166136261u32;
    for b in &out[4..] {
        hash = (hash ^ u32::from(*b)).wrapping_mul(16777619);
    }
    out[..4].copy_from_slice(&hash.to_be_bytes());
    let n = (4 - out.len() % 4) % 4;
    out.resize(out.len() + n, 0);
    for i in 4..out.len() {
        let prior = out[i - 4];
        out[i] ^= prior;
    }
    out.truncate(out.len() - n);
    out
}
fn simple_open(input: &[u8]) -> io::Result<Vec<u8>> {
    if input.len() < 6 || input.len() > MAX_WIRE_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mKCP authenticator",
        ));
    }
    let n = (4 - input.len() % 4) % 4;
    let mut out = input.to_vec();
    out.resize(out.len() + n, 0);
    for i in (4..out.len()).rev() {
        let prior = out[i - 4];
        out[i] ^= prior;
    }
    out.truncate(input.len());
    let mut hash = 2166136261u32;
    for b in &out[4..] {
        hash = (hash ^ u32::from(*b)).wrapping_mul(16777619);
    }
    if u32::from_be_bytes(out[..4].try_into().unwrap()) != hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mKCP authenticator",
        ));
    }
    let len = u16::from_be_bytes([out[4], out[5]]) as usize;
    if len != out.len() - 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mKCP authenticator length",
        ));
    }
    Ok(out[6..].to_vec())
}

fn seal(packet: &[u8], header: &mut HeaderState, key: Option<&LessSafeKey>) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(MAX_PACKET);
    header.write(&mut out);
    if let Some(key) = key {
        let mut nonce_bytes = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| io::Error::other("random source unavailable"))?;
        out.extend_from_slice(&nonce_bytes);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| io::Error::other("invalid mKCP nonce"))?;
        let mut body = packet.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut body)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "mKCP authentication failed")
            })?;
        out.extend_from_slice(&body);
    } else {
        out.extend_from_slice(&simple_seal(packet));
    }
    Ok(out)
}
fn open(packet: &[u8], header: HeaderState, key: Option<&LessSafeKey>) -> io::Result<Vec<u8>> {
    if packet.len() < header.len() || !header.check(packet) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mKCP header",
        ));
    }
    let body = &packet[header.len()..];
    if let Some(key) = key {
        if body.len() < 12 + 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short mKCP ciphertext",
            ));
        }
        let nonce = Nonce::try_assume_unique_for_key(body[..12].try_into().unwrap())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mKCP nonce"))?;
        let mut body = body[12..].to_vec();
        let plaintext_len = key
            .open_in_place(nonce, Aad::empty(), &mut body)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mKCP authentication failed"))?
            .len();
        body.truncate(plaintext_len);
        Ok(body)
    } else {
        simple_open(body)
    }
}

struct Sent {
    seg: Segment,
    fast_acks: u8,
}

/// 有界 AIMD；RTT/RTO 采用平滑估计与 Karn 规则，不把重传样本计入 RTT。
/// 这保持线格式兼容，但不复制 mihomo 的发送批次放大策略。
struct SendControl {
    enabled: bool,
    cap: usize,
    window: usize,
    threshold: usize,
    credit: usize,
    srtt: Option<u32>,
    variance: u32,
    rto_ms: u32,
    min_rto_ms: u32,
}
impl SendControl {
    fn new(enabled: bool, cap: usize, tti: u16) -> Self {
        let min_rto_ms = u32::from(tti.clamp(10, 500)).saturating_mul(2).max(100);
        Self {
            enabled,
            cap,
            window: cap.min(8),
            threshold: cap,
            credit: 0,
            srtt: None,
            variance: 0,
            rto_ms: min_rto_ms,
            min_rto_ms,
        }
    }
    fn limit(&self) -> usize {
        if self.enabled {
            self.window
        } else {
            self.cap
        }
    }
    fn ack(&mut self, count: usize, sample: Option<u32>) {
        if let Some(sample) = sample.filter(|rtt| *rtt < 10_000) {
            let sample = sample.max(1);
            if let Some(srtt) = self.srtt {
                self.variance = (3 * self.variance + srtt.abs_diff(sample)) / 4;
                self.srtt = Some((7 * srtt + sample) / 8);
            } else {
                self.srtt = Some(sample);
                self.variance = sample / 2;
            }
            self.rto_ms = self
                .srtt
                .unwrap()
                .saturating_add(4 * self.variance)
                .clamp(self.min_rto_ms, 3000);
        }
        if !self.enabled || count == 0 {
            return;
        }
        if self.window < self.threshold {
            self.window = (self.window + count).min(self.cap);
        } else {
            self.credit += count;
            if self.credit >= self.window {
                self.credit -= self.window;
                self.window = (self.window + 1).min(self.cap);
            }
        }
    }
    fn loss(&mut self) {
        if self.enabled {
            self.threshold = (self.window / 2).max(2);
            self.window = self.threshold;
            self.credit = 0;
        }
    }
}
enum Command {
    Write(Vec<u8>),
    Flush(oneshot::Sender<io::Result<()>>),
    Shutdown(oneshot::Sender<io::Result<()>>),
}
type ReserveFuture = Pin<
    Box<
        dyn std::future::Future<
                Output = Result<mpsc::OwnedPermit<Command>, mpsc::error::SendError<()>>,
            > + Send,
    >,
>;

/// Return whether `a` is before `b` in the 32-bit serial number space.  The
/// windows are bounded far below 2^31, so RFC 1982's half-range comparison is
/// sufficient and keeps wrap-around connections interoperable.
fn seq_before(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000_0000
}

fn first_unacked(sent: &VecDeque<Sent>, next: u32) -> u32 {
    sent.front().map(|item| item.seg.number).unwrap_or(next)
}

fn payload_size(spec: &KcpSpec) -> io::Result<usize> {
    let overhead = if spec.seed.as_ref().is_some_and(|s| !s.is_empty()) {
        28
    } else {
        6
    };
    Ok(usize::from(spec.mtu).clamp(576, MAX_PACKET)
        - HeaderState::new(&spec.header)?.len()
        - overhead
        - DATA_OVERHEAD)
}

async fn run(
    mut socket: impl PacketIo,
    conv: u16,
    spec: KcpSpec,
    mut rx: mpsc::Receiver<Command>,
    tx: mpsc::Sender<io::Result<Vec<u8>>>,
    closing: std::sync::Arc<tokio::sync::Notify>,
) -> io::Result<()> {
    let mut header = HeaderState::new(&spec.header)?;
    let key = spec
        .seed
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|seed| {
            let hash = digest::digest(&digest::SHA256, seed.as_bytes());
            UnboundKey::new(&AES_128_GCM, &hash.as_ref()[..16])
                .map(LessSafeKey::new)
                .map_err(|_| io::Error::other("invalid mKCP seed key"))
        })
        .transpose()?;
    let mtu = usize::from(spec.mtu).clamp(576, MAX_PACKET);
    let mss = payload_size(&spec)?;
    let rate_window = |capacity: u32| {
        (capacity as usize)
            .saturating_mul(1024 * 1024)
            .saturating_mul(usize::from(spec.tti))
            .saturating_div(1000 * mtu)
            .clamp(8, 4096)
    };
    // 窗口按容量算（与 mihomo / xray 一致），再受缓冲大小限制，满载时停止取写命令，不丢字节。
    // 对端的发送窗口是「容量 × tti」，而且每个 tick 最多发出它的 20 倍：本端接收窗口比对端的小，
    // 窗口外的包就被丢弃、靠超时重传。原来的 1024 段上限与「缓冲的一半」把容量调大后的窗口压在 ~800 段。
    // 发送窗口保持原来的上限：没有拥塞控制时窗口越大突发越大，会冲掉对端的接收缓冲。
    let max_send = (spec.write_buffer_size / mss / 2)
        .clamp(8, 1024)
        .min(rate_window(spec.uplink_capacity));
    let max_recv = (spec.read_buffer_size / mss)
        .clamp(8, 4096)
        .min(rate_window(spec.downlink_capacity));
    let tti = Duration::from_millis(u64::from(spec.tti.clamp(10, 500)));
    let mut tick = tokio::time::interval(tti);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut buf = vec![0u8; MAX_WIRE_PACKET + 1];
    let mut pending = VecDeque::<Segment>::new();
    let mut sent = VecDeque::<Sent>::new();
    let mut recv = BTreeMap::<u32, Segment>::new();
    let mut delivered = VecDeque::<Vec<u8>>::new();
    let started = Instant::now();
    let mut receive_next = 0u32;
    let mut send_next = 0u32;
    let mut remote_window = 32u32;
    let mut bad_packets = 0usize;
    let mut last_ping = Instant::now();
    let mut last_incoming = Instant::now();
    let mut barrier: Option<oneshot::Sender<io::Result<()>>> = None;
    let mut shutdown_requested = false;
    let mut closing_since = None;
    let mut peer_terminated = false;
    let mut control = SendControl::new(spec.congestion, max_send, spec.tti);
    // 已经通告给对端的接收窗口上界（绝对序号，只增不减）。对端按通告过的窗口发包，之后读端变慢、
    // 本端的剩余信用缩小时，窗口内已经在路上的包仍必须收下：按「当前剩余信用」收包，
    // 在读端稍慢时会把窗口内合法的包大量丢掉，对端只能超时重传（主机上 mihomo 服务端的下载丢包过半）。
    let mut advertised = max_recv as u32;
    // 确认合并：每个数据报回一个确认（含选择确认列表）会让对端（Go 实现里每个确认要遍历整个在途窗口）
    // 忙于处理确认而不是发数据。像 mihomo / xray 的客户端一样把确认攒起来：累计 ACK_BATCH 个数据报或
    // 等 ACK_DELAY，发一个累计确认（next 之前全部确认）加乱序列表。
    let mut ack_needed = false;
    let mut ack_count = 0u32;
    let mut ack_deadline = Instant::now();
    let mut ack_timestamp = 0u32;
    let mut last_ack_at = Instant::now();
    // 一段安静之后到达的第一个数据报马上确认（请求 / 应答的往返延迟不能多出确认延迟），
    // 紧接着的突发才合并。
    macro_rules! mark_ack {
        () => {
            if !ack_needed {
                ack_needed = true;
                let now = Instant::now();
                ack_deadline = if now.duration_since(last_ack_at) >= ACK_DELAY * 4 {
                    now
                } else {
                    now + ACK_DELAY
                };
            }
        };
    }
    loop {
        // 同时推进已排序队列和 AsyncRead 队列。即使对端已无新 DATA，读取
        // 腾出的窗口仍会在下一次 tick 通知对端，避免零窗口永久停滞。
        let prior_next = receive_next;
        let prior_delivered = delivered.len();
        // 把待读队列推给读端；推完、顺序前进之后还要再推一次：刚由乱序缓存前进到待读队列的数据
        // 必须马上交给读端，不能等下一个事件（确认合并之后，下一个事件可能是 50 ms 之后的 tick，
        // 请求 / 应答的往返被拉长到一个 tick）。
        macro_rules! push_delivered {
            () => {
                while let Some(data) = delivered.pop_front() {
                    match tx.try_send(Ok(data)) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(Ok(data))) => {
                            delivered.push_front(data);
                            break;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                        Err(mpsc::error::TrySendError::Full(Err(_))) => unreachable!(),
                    }
                }
            };
        }
        push_delivered!();
        while delivered.len() < max_recv {
            let Some(seg) = recv.remove(&receive_next) else {
                break;
            };
            delivered.push_back(seg.payload);
            receive_next = receive_next.wrapping_add(1);
        }
        push_delivered!();
        if prior_next != receive_next || prior_delivered != delivered.len() {
            // 窗口或累计确认前进了：确认可以等一个很短的延迟，和后面到达的数据一起发
            mark_ack!();
        }
        if ack_needed && (ack_count >= ACK_BATCH || Instant::now() >= ack_deadline) {
            let list: Vec<u32> = recv.keys().take(MAX_ACK_NUMBERS).copied().collect();
            let window = receive_next.wrapping_add(max_recv.saturating_sub(delivered.len()) as u32);
            if seq_before(advertised, window) {
                advertised = window;
            }
            let ack = put_ack(conv, window, receive_next, ack_timestamp, &list);
            socket.send(&seal(&ack, &mut header, key.as_ref())?).await?;
            ack_needed = false;
            ack_count = 0;
            ack_timestamp = 0;
            last_ack_at = Instant::now();
        }
        if peer_terminated {
            // Terminate 可能与读端回压同时到达，必须交完已确认的数据再 EOF。
            for data in delivered.drain(..) {
                if tx.send(Ok(data)).await.is_err() {
                    return Ok(());
                }
            }
            return Ok(());
        }
        if pending.is_empty() && sent.is_empty() {
            if let Some(done) = barrier.take() {
                if shutdown_requested {
                    let cmd = put_cmd(conv, CMD_TERMINATE, send_next, receive_next, 100);
                    socket.send(&seal(&cmd, &mut header, key.as_ref())?).await?;
                    closing_since = Some(Instant::now());
                }
                let _ = done.send(Ok(()));
            }
        }
        let first = first_unacked(&sent, pending.front().map_or(send_next, |seg| seg.number));
        // 信用是绝对序号，选择确认产生的空洞不能放行窗口以外的新序号。
        if sent.len() < control.limit()
            && pending
                .front()
                .is_some_and(|s| seq_before(s.number, remote_window))
        {
            let mut seg = pending.pop_front().unwrap();
            seg.sending_next = first;
            seg.timestamp = elapsed_ms(started);
            socket
                .send(&seal(&put_data(conv, &seg), &mut header, key.as_ref())?)
                .await?;
            seg.received_at = Instant::now();
            seg.transmitted = 1;
            sent.push_back(Sent { seg, fast_acks: 0 });
            continue;
        }
        tokio::select! {
            _ = tx.closed() => return Ok(()),
            // 流被丢弃：告诉对端结束这个会话再退出。直接丢弃的话对端会带着整个发送窗口一直重传到
            // 30 秒空闲超时，高速测试之后服务端被这些僵尸会话拖住，新连接全部超时（真机上 mKCP 在
            // 第一个高速节点之后的 `mKCP flush failed`）。
            _ = closing.notified() => {
                let first = first_unacked(&sent, pending.front().map_or(send_next, |seg| seg.number));
                let cmd = put_cmd(conv, CMD_TERMINATE, first, receive_next, 100);
                for _ in 0..2 {
                    let _ = socket.send(&seal(&cmd, &mut header, key.as_ref())?).await;
                }
                return Ok(());
            },
            _ = tokio::time::sleep(ack_deadline.saturating_duration_since(Instant::now())), if ack_needed => {},
            // 读端取走数据、通道腾出空位时立即醒来，把积压的包推给读端并更新窗口；
            // 否则要等下一个事件（对端的包或 tick）才会再推一次，通道装满后窗口关闭、对端停发。
            permit = tx.reserve(), if !delivered.is_empty() => {
                let Ok(permit) = permit else { return Ok(()) };
                if let Some(data) = delivered.pop_front() {
                    permit.send(Ok(data));
                    mark_ack!();
                }
            },
            cmd = rx.recv(), if !shutdown_requested && barrier.is_none() && pending.len() + sent.len() < max_send => {
                match cmd {
                    Some(Command::Write(data)) => {
                        debug_assert!(data.len() <= mss);
                        pending.push_back(Segment { conv, command: CMD_DATA, option: 0,
                            timestamp: 0, number: send_next, sending_next: first,
                            payload: data, received_at: Instant::now(), transmitted: 0 });
                        send_next = send_next.wrapping_add(1);
                    }
                    Some(Command::Flush(done)) => barrier = Some(done),
                    Some(Command::Shutdown(done)) => { barrier = Some(done); shutdown_requested = true; }
                    None => return Ok(()),
                }
            },
            result = socket.recv(&mut buf) => {
                let n = result?;
                if n == 0 || n > MAX_WIRE_PACKET { continue; }
                let body = match open(&buf[..n], header, key.as_ref()) {
                    Ok(body) => body,
                    Err(_) => {
                        bad_packets += 1;
                        if bad_packets >= MAX_BAD_PACKETS {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many invalid mKCP packets"));
                        }
                        continue;
                    }
                };
                bad_packets = 0;
                for seg in parse_segments(&body, MAX_PACKET) {
                    if seg.conv != conv { break; }
                    last_incoming = Instant::now();
                    match seg.command {
                        CMD_DATA => {
                            let offset = seg.number.wrapping_sub(receive_next);
                            // 窗口内（含已经通告过、之后又收缩的部分）的新包都收下；内存仍有界：
                            // 乱序缓存与待读队列各自不超过一个接收窗口。
                            if offset < advertised.wrapping_sub(receive_next)
                                && recv.len() < max_recv
                                && delivered.len() <= max_recv
                            {
                                recv.entry(seg.number).or_insert(seg.clone());
                            }
                            // 旧 DATA 的重传也要得到确认（修复 ACK 丢失），一样合并到下一个确认里。
                            ack_count += 1;
                            ack_timestamp = seg.timestamp;
                            mark_ack!();
                        }
                        CMD_ACK => {
                            // ACK 不得凭空确认尚未发送的序号。过期窗口只保留
                            // 单调增长的一侧，正常乱序不会收回已经发放的信用。
                            if seq_before(send_next, seg.number) { continue; }
                            if seq_before(remote_window, seg.sending_next) {
                                remote_window = seg.sending_next;
                            }
                            let mut selective: Vec<u32> = seg.payload.chunks_exact(4)
                                .map(|c| u32::from_be_bytes(c.try_into().unwrap())).collect();
                            // 每个数据报都会收到一个确认，在途窗口最多 1024 段：线性查找是「段数 × 确认数」，二分查找便宜得多
                            selective.sort_unstable();
                            let acknowledged = |item: &Sent| seq_before(item.seg.number, seg.number)
                                || selective.binary_search(&item.seg.number).is_ok();
                            let now_ms = elapsed_ms(started);
                            let sample = sent.iter().find(|item| acknowledged(item)
                                && item.seg.transmitted == 1 && item.seg.timestamp == seg.timestamp)
                                .map(|_| now_ms.wrapping_sub(seg.timestamp));
                            let max_ack = sent.iter().filter(|item| acknowledged(item))
                                .map(|item| item.seg.number).next_back();
                            let before = sent.len();
                            sent.retain(|item| !acknowledged(item));
                            control.ack(before - sent.len(), sample);
                            if let Some(max_ack) = max_ack {
                                for item in &mut sent {
                                    if seq_before(item.seg.number, max_ack) {
                                        item.fast_acks = item.fast_acks.saturating_add(1);
                                    }
                                }
                            }
                        }
                        CMD_PING | CMD_TERMINATE => {
                            if !seq_before(send_next, seg.sending_next) {
                                sent.retain(|item| !seq_before(item.seg.number, seg.sending_next));
                            }
                            let credit = max_recv.saturating_sub(delivered.len());
                            let window = receive_next.wrapping_add(credit as u32);
                            if seq_before(advertised, window) {
                                advertised = window;
                            }
                            let ack = put_ack(conv, window, receive_next, 0, &[]);
                            socket.send(&seal(&ack, &mut header, key.as_ref())?).await?;
                            if seg.command == CMD_TERMINATE {
                                let reply = put_cmd(conv, CMD_TERMINATE, first_unacked(&sent, pending.front().map_or(send_next, |seg| seg.number)), receive_next, 100);
                                socket.send(&seal(&reply, &mut header, key.as_ref())?).await?;
                                peer_terminated = true;
                            }
                        }
                        _ => {}
                    }
                }
            },
            _ = tick.tick() => {
                let now = Instant::now();
                let rto = Duration::from_millis(u64::from(control.rto_ms));
                let first = first_unacked(&sent, pending.front().map_or(send_next, |seg| seg.number));
                let mut loss = false;
                for item in &mut sent {
                    if now.duration_since(item.seg.received_at) >= rto || item.fast_acks >= 3 {
                        loss = true;
                        item.fast_acks = 0;
                        if item.seg.transmitted >= 16 {
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "mKCP retry budget exhausted"));
                        }
                        item.seg.transmitted += 1;
                        item.seg.received_at = now;
                        item.seg.timestamp = elapsed_ms(started);
                        item.seg.sending_next = first;
                        socket.send(&seal(&put_data(conv, &item.seg), &mut header, key.as_ref())?).await?;
                    }
                }
                if loss { control.loss(); }
                if last_incoming.elapsed() > Duration::from_secs(30) {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "mKCP peer idle timeout"));
                }
                if let Some(since) = closing_since {
                    if now.duration_since(since) >= Duration::from_secs(8) { return Ok(()); }
                    let terminate = put_cmd(conv, CMD_TERMINATE, first, receive_next, rto.as_millis() as u32);
                    socket.send(&seal(&terminate, &mut header, key.as_ref())?).await?;
                } else if last_ping.elapsed() >= Duration::from_secs(3) {
                    let ping = put_cmd(conv, CMD_PING, first, receive_next, rto.as_millis() as u32);
                    socket.send(&seal(&ping, &mut header, key.as_ref())?).await?;
                    last_ping = now;
                }
            }
        }
    }
}
fn elapsed_ms(since: Instant) -> u32 {
    since.elapsed().as_millis().min(u32::MAX as u128) as u32
}

pub struct KcpStream {
    tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    current: Vec<u8>,
    closed: bool,
    reserve: Option<ReserveFuture>,
    max_write: usize,
    write_closed: bool,
    flush_wait: Option<oneshot::Receiver<io::Result<()>>>,
    shutdown_wait: Option<oneshot::Receiver<io::Result<()>>>,
    task: Option<tokio::task::JoinHandle<()>>,
    closing: std::sync::Arc<tokio::sync::Notify>,
}
impl KcpStream {
    async fn connect(peer: SocketAddr, spec: &KcpSpec) -> io::Result<Self> {
        let socket = oryn_udp::iface::bind_udp(peer.is_ipv6()).await?;
        socket.connect(peer).await?;
        Self::connect_io(socket, spec).await
    }

    pub async fn connect_io<S: PacketIo>(socket: S, spec: &KcpSpec) -> io::Result<Self> {
        let conv = (NEXT_CONV.fetch_add(1, Ordering::Relaxed) as u16).max(1);
        let mss = payload_size(spec)?;
        let write_cap = (spec.write_buffer_size / mss / 2).clamp(8, 1024);
        let (tx, cmd_rx) = mpsc::channel(write_cap);
        let (read_tx, rx) = mpsc::channel((spec.read_buffer_size / mss / 2).clamp(8, 128));
        let spec = spec.clone();
        let closing = std::sync::Arc::new(tokio::sync::Notify::new());
        let run_closing = closing.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = run(socket, conv, spec, cmd_rx, read_tx.clone(), run_closing).await
            {
                let _ = read_tx.send(Err(error)).await;
            }
        });
        Ok(Self {
            closing,
            tx,
            rx,
            current: Vec::new(),
            closed: false,
            reserve: None,
            max_write: mss,
            write_closed: false,
            flush_wait: None,
            shutdown_wait: None,
            task: Some(task),
        })
    }
}
pub async fn connect_kcp(peer: SocketAddr, spec: &KcpSpec) -> io::Result<KcpStream> {
    KcpStream::connect(peer, spec).await
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        // PacketIo 的 Drop 同时取消 Mekya HTTP supervisor，不能留下定时重传。
        // 先给 Terminate 机会；500 ms 兜底覆盖 run 卡在 PacketIo::send 的情况。
        self.closing.notify_one();
        let Some(mut task) = self.task.take() else {
            return;
        };
        let abort = task.abort_handle();
        match (
            tokio::runtime::Handle::try_current(),
            CLOSE_WAITERS.try_acquire(),
        ) {
            (Ok(handle), Ok(permit)) => {
                // spawn 前占额并移入 future，未 poll 就取消也会退账。
                handle.spawn(async move {
                    let _permit = permit;
                    if tokio::time::timeout(Duration::from_millis(500), &mut task)
                        .await
                        .is_err()
                    {
                        abort.abort();
                        let _ = task.await;
                    }
                });
            }
            // 满额只中止当前已 Drop 的连接，不驱逐任何活跃流。
            _ => abort.abort(),
        }
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.current.is_empty() {
            let n = self.current.len().min(buf.remaining());
            buf.put_slice(&self.current[..n]);
            self.current.drain(..n);
            return Poll::Ready(Ok(()));
        }
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        match ready!(Pin::new(&mut self.rx).poll_recv(cx)) {
            Some(Ok(data)) => {
                if data.is_empty() {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                self.current = data;
                let n = self.current.len().min(buf.remaining());
                buf.put_slice(&self.current[..n]);
                self.current.drain(..n);
                Poll::Ready(Ok(()))
            }
            Some(Err(error)) => {
                self.closed = true;
                Poll::Ready(Err(error))
            }
            None => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}
impl AsyncWrite for KcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mKCP stream closed",
            )));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // 每个命令只承载一个 mKCP segment，避免后台任务在窗口满载时丢弃同一
        // 次写入的后续分片；调用方会在下一次 poll_write 继续提交余下字节。
        let n = data.len().min(self.max_write);
        if self.reserve.is_none() {
            self.reserve = Some(Box::pin(self.tx.clone().reserve_owned()));
        }
        match self
            .reserve
            .as_mut()
            .expect("reserve future")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(Ok(permit)) => {
                self.reserve = None;
                permit.send(Command::Write(data[..n].to_vec()));
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(_)) => {
                self.closed = true;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mKCP transport closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        if self.flush_wait.is_none() {
            let permit = ready!(self.poll_permit(cx))?;
            let (done, wait) = oneshot::channel();
            permit.send(Command::Flush(done));
            self.flush_wait = Some(wait);
        }
        let result = ready!(Pin::new(self.flush_wait.as_mut().unwrap()).poll(cx));
        self.flush_wait = None;
        Poll::Ready(result.unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mKCP flush failed",
            ))
        }))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed && self.shutdown_wait.is_none() {
            return Poll::Ready(Ok(()));
        }
        if self.shutdown_wait.is_none() {
            let permit = ready!(self.poll_permit(cx))?;
            let (done, wait) = oneshot::channel();
            permit.send(Command::Shutdown(done));
            self.shutdown_wait = Some(wait);
            self.write_closed = true;
        }
        let result = ready!(Pin::new(self.shutdown_wait.as_mut().unwrap()).poll(cx));
        self.shutdown_wait = None;
        Poll::Ready(result.unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mKCP shutdown failed",
            ))
        }))
    }
}
impl KcpStream {
    fn poll_permit(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<mpsc::OwnedPermit<Command>>> {
        if self.reserve.is_none() {
            self.reserve = Some(Box::pin(self.tx.clone().reserve_owned()));
        }
        match ready!(self.reserve.as_mut().unwrap().as_mut().poll(cx)) {
            Ok(permit) => {
                self.reserve = None;
                Poll::Ready(Ok(permit))
            }
            Err(_) => {
                self.reserve = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mKCP transport closed",
                )))
            }
        }
    }
}

#[cfg(test)]
#[path = "kcp_drop_tests.rs"]
mod drop_tests;

#[cfg(test)]
mod tests {
    use super::*;
    struct IdlePacketIo(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for IdlePacketIo {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    impl PacketIo for IdlePacketIo {
        fn send<'a>(
            &'a self,
            _: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
        fn recv<'a>(
            &'a mut self,
            _: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
            Box::pin(std::future::pending())
        }
    }
    #[tokio::test]
    async fn stream_drop_releases_packet_transport() {
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let spec = KcpSpec {
            mtu: 576,
            tti: 10,
            uplink_capacity: 1,
            downlink_capacity: 1,
            congestion: false,
            read_buffer_size: 8192,
            write_buffer_size: 8192,
            header: "none".into(),
            seed: None,
        };
        let stream = KcpStream::connect_io(IdlePacketIo(dropped.clone()), &spec)
            .await
            .unwrap();
        tokio::task::yield_now().await;
        drop(stream);
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::SeqCst));
    }
    #[test]
    fn congestion_reduces_window_and_recovers_with_bounded_rto() {
        let mut control = SendControl::new(true, 32, 10);
        assert_eq!(control.limit(), 8);
        control.ack(8, Some(30));
        assert_eq!(control.limit(), 16);
        control.loss();
        assert_eq!(control.limit(), 8);
        control.ack(8, Some(50));
        assert_eq!(control.limit(), 9);
        for _ in 0..100 {
            control.ack(32, Some(9999));
        }
        assert!(control.limit() <= 32);
        assert_eq!(control.rto_ms, 3000);
        let mut disabled = SendControl::new(false, 32, 10);
        disabled.loss();
        assert_eq!(disabled.limit(), 32);
    }
    #[test]
    fn malformed_packets_are_bounded_and_rejected() {
        assert!(simple_open(&[0; 5]).is_err());
        assert!(simple_open(&vec![0; MAX_WIRE_PACKET + 1]).is_err());
        let mut wire = simple_seal(b"authenticated");
        wire[6] ^= 1;
        assert!(simple_open(&wire).is_err());
        for length in 0..18 {
            let mut truncated = vec![0; length];
            if length > 2 {
                truncated[2] = CMD_DATA;
            }
            assert!(parse_segments(&truncated, 1400).is_empty());
        }
        let mut ack = put_ack(1, 32, 0, 0, &[1]);
        ack[16] = 255;
        assert!(parse_segments(&ack, 1400).is_empty());
    }
    #[test]
    fn segment_uses_mihomo_big_endian_layout() {
        let seg = Segment {
            conv: 7,
            command: CMD_DATA,
            option: 0,
            timestamp: 1,
            number: 2,
            sending_next: 3,
            payload: b"abc".to_vec(),
            received_at: Instant::now(),
            transmitted: 0,
        };
        let bytes = put_data(7, &seg);
        assert_eq!(&bytes[..4], &[0, 7, 1, 0]);
        assert_eq!(&bytes[4..8], &1u32.to_be_bytes());
        assert_eq!(parse_segments(&bytes, 100)[0].payload, b"abc");
    }

    #[test]
    fn ack_segment_matches_mihomo_wire_layout() {
        let wire = put_ack(
            0x1234,
            0x0102_0304,
            0xa0b0_c0d0,
            0x1122_3344,
            &[0x5566_7788, 0x99aa_bbcc],
        );
        assert_eq!(
            wire,
            vec![
                0x12, 0x34, CMD_ACK, 0, // conv/cmd/option
                1, 2, 3, 4, // receivingWindow
                0xa0, 0xb0, 0xc0, 0xd0, // receivingNext
                0x11, 0x22, 0x33, 0x44, // timestamp
                2,    // numberList length
                0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ]
        );
        let parsed = parse_segments(&wire, 100);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].conv, 0x1234);
        assert_eq!(parsed[0].sending_next, 0x0102_0304);
        assert_eq!(parsed[0].number, 0xa0b0_c0d0);
        assert_eq!(
            parsed[0]
                .payload
                .chunks_exact(4)
                .map(|v| u32::from_be_bytes(v.try_into().unwrap()))
                .collect::<Vec<_>>(),
            vec![0x5566_7788, 0x99aa_bbcc]
        );
    }

    #[test]
    fn parser_preserves_conversation_per_segment() {
        let first = put_data(
            0x1111,
            &Segment {
                conv: 0x1111,
                command: CMD_DATA,
                option: 0,
                timestamp: 0,
                number: 0,
                sending_next: 0,
                payload: b"a".to_vec(),
                received_at: Instant::now(),
                transmitted: 0,
            },
        );
        let second = put_data(
            0x2222,
            &Segment {
                conv: 0x2222,
                command: CMD_DATA,
                option: 0,
                timestamp: 0,
                number: 1,
                sending_next: 0,
                payload: b"b".to_vec(),
                received_at: Instant::now(),
                transmitted: 0,
            },
        );
        let mut packet = first;
        packet.extend_from_slice(&second);
        let parsed = parse_segments(&packet, 100);
        assert_eq!(
            parsed.iter().map(|s| s.conv).collect::<Vec<_>>(),
            vec![0x1111, 0x2222]
        );
    }

    #[test]
    fn simple_auth_roundtrip() {
        let input = b"mKCP payload";
        let sealed = simple_seal(input);
        assert_eq!(simple_open(&sealed).unwrap(), input);
    }
    #[test]
    fn ack_wire_layout_and_limit_match_mihomo() {
        let numbers: Vec<u32> = (0..128).collect();
        let bytes = put_ack(0x1234, 0x0102_0304, 0x0506_0708, 0x090a_0b0c, &numbers);
        assert_eq!(&bytes[..4], &[0x12, 0x34, CMD_ACK, 0]);
        assert_eq!(&bytes[4..8], &0x0102_0304u32.to_be_bytes());
        assert_eq!(bytes[16], 128);
        let parsed = parse_segments(&bytes, 1500);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].conv, 0x1234);
        assert_eq!(parsed[0].sending_next, 0x0102_0304);
        assert_eq!(parsed[0].number, 0x0506_0708);
        assert_eq!(parsed[0].payload.len(), 128 * 4);
    }

    #[test]
    fn command_extensions_do_not_desynchronise_datagram() {
        let unknown = put_cmd(7, 0x7f, 11, 12, 13);
        let data = put_data(
            7,
            &Segment {
                conv: 7,
                command: CMD_DATA,
                option: 0,
                timestamp: 1,
                number: 2,
                sending_next: 3,
                payload: b"abc".to_vec(),
                received_at: Instant::now(),
                transmitted: 0,
            },
        );
        let mut packet = unknown;
        packet.extend_from_slice(&data);
        let parsed = parse_segments(&packet, 100);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].command, 0x7f);
        assert_eq!(parsed[0].number, 11);
        assert_eq!(parsed[0].sending_next, 12);
        assert_eq!(parsed[1].payload, b"abc");
    }

    #[test]
    fn simple_auth_matches_mihomo_vector() {
        let sealed = simple_seal(b"mKCP payload");
        assert_eq!(
            sealed,
            [
                0x39, 0xc9, 0x80, 0x18, 0x39, 0xc5, 0xed, 0x53, 0x7a, 0x95, 0xcd, 0x23, 0x1b, 0xec,
                0xa1, 0x4c, 0x7a, 0x88,
            ]
        );
        assert_eq!(simple_open(&sealed).unwrap(), b"mKCP payload");
    }

    #[test]
    fn seed_uses_sha256_prefix_aes128_gcm() {
        let hash = digest::digest(&digest::SHA256, b"interop-seed");
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &hash.as_ref()[..16]).unwrap());
        let header = HeaderState::new("none").unwrap();
        let mut writer_header = header;
        let wire = seal(b"seeded mKCP", &mut writer_header, Some(&key)).unwrap();
        // HeaderState::none places the 12-byte nonce at offset zero; the
        // remainder is AES-GCM ciphertext with the standard 16-byte tag.
        assert_eq!(wire.len(), 12 + 11 + 16);
        assert_eq!(open(&wire, header, Some(&key)).unwrap(), b"seeded mKCP");
    }

    #[test]
    fn aes_gcm_opens_standard_nist_vector() {
        // NIST SP 800-38D, test case 2.  mihomo uses the raw 12-byte nonce
        // followed by the AES-GCM ciphertext and 16-byte tag, so this vector
        // catches accidental nonce truncation or tag placement changes.
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &[0u8; 16]).unwrap());
        let mut wire = vec![0u8; 12];
        wire.extend_from_slice(&[
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78, 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2,
            0x12, 0x57, 0xbd, 0xdf,
        ]);
        let header = HeaderState::new("none").unwrap();
        assert_eq!(open(&wire, header, Some(&key)).unwrap(), vec![0u8; 16]);
    }

    #[test]
    fn data_segment_matches_full_mihomo_golden_vector() {
        let seg = Segment {
            conv: 0x1234,
            command: CMD_DATA,
            option: 0,
            timestamp: 0x0102_0304,
            number: 0x0506_0708,
            sending_next: 0x090a_0b0c,
            payload: b"hello".to_vec(),
            received_at: Instant::now(),
            transmitted: 0,
        };
        let wire = put_data(0x1234, &seg);
        assert_eq!(
            wire,
            vec![
                0x12, 0x34, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o',
            ]
        );
        let parsed = parse_segments(&wire, 1500);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].timestamp, 0x0102_0304);
        assert_eq!(parsed[0].number, 0x0506_0708);
        assert_eq!(parsed[0].sending_next, 0x090a_0b0c);
        assert_eq!(parsed[0].payload, b"hello");
    }

    #[test]
    fn sequence_comparison_wraps_at_u32_boundary() {
        assert!(seq_before(u32::MAX, 0));
        assert!(seq_before(u32::MAX - 1, 0));
        assert!(!seq_before(0, u32::MAX));
        assert!(!seq_before(7, 7));
    }

    #[test]
    fn headers_have_mihomo_shapes() {
        for (name, len) in [
            ("none", 0),
            ("srtp", 4),
            ("utp", 4),
            ("wechat-video", 13),
            ("dtls", 13),
            ("wireguard", 4),
        ] {
            let mut h = HeaderState::new(name).unwrap();
            let mut b = Vec::new();
            h.write(&mut b);
            assert_eq!(b.len(), len);
            assert!(h.check(&b));
        }
        // Header validation must inspect only the fixed 13-byte prefix; the
        // segment body follows it in every real packet.
        let mut wechat = HeaderState::new("wechat-video").unwrap();
        let mut with_body = Vec::new();
        wechat.write(&mut with_body);
        with_body.extend_from_slice(b"segment");
        assert!(wechat.check(&with_body));

        let mut dtls = HeaderState::new("dtls").unwrap();
        let mut dtls_first = Vec::new();
        dtls.write(&mut dtls_first);
        assert_eq!(&dtls_first[7..11], &[0, 0, 0, 0]);
    }
}
