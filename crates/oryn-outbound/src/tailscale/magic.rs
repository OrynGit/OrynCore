//! Tailscale 直连（OrynCore#41）：STUN 端点发现、disco（Ping / Pong / CallMeMaybe）与路径选择。
//! 方案见 Oryn_dev/docs/oryncore/plans/plan-tailscale-disco.md。线格式与计时依据 tailscale main：
//! `disco/disco.go`、`wgengine/magicsock/{magicsock,endpoint}.go`、`tsconst/ping.go`、
//! `tailcfg/{tailcfg,derpmap}.go`（2026-11-24 核对，BSD-3-Clause）；本文件为 Oryn 独立实现。
//!
//! 这里只有状态机：收到的包与每秒一次的 tick 产出 [`Out`]（经 UDP 或经 DERP 发送），由 `Relay`
//! 执行。表都有上限；只对 45 s 内有流量的对端发探测，空闲时不发包。
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

/// disco 魔数 "TS💬"。
pub const DISCO_MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac];
const NONCE: usize = 24;
const HEADER: usize = 6 + 32 + NONCE;
const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;
const TYPE_CALL_ME_MAYBE: u8 = 0x03;
/// 经 DERP 收到的 Pong 里填的源地址（magicsock 的 DerpMagicIP），端口为 region。
const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);

/// 收到最佳地址的 Pong 后，作为唯一路径信任的时长（trustUDPAddrDuration）。
const TRUST: Duration = Duration::from_millis(6500);
/// 向最佳地址心跳的间隔（heartbeatInterval）。
const HEARTBEAT: Duration = Duration::from_secs(3);
/// 超过这么久没有流量即视为空闲，停止心跳与 STUN 刷新（sessionActiveTimeout）。
const ACTIVE: Duration = Duration::from_secs(45);
/// 等待 Pong 的上限（tsconst.DefaultPingTimeout）。
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// 同一端点两次 Ping 的最小间隔（tsconst.DefaultPingInterval）。
const PING_INTERVAL: Duration = Duration::from_secs(5);
/// 延迟高于这个值才定期寻找更好的直连（goodEnoughLatency / upgradeUDPDirectInterval）。
const GOOD_ENOUGH: Duration = Duration::from_millis(5);
const UPGRADE: Duration = Duration::from_secs(60);
/// STUN 周期刷新：20–26 s 随机，略小于常见 30 s 的 UDP NAT 超时。
const STUN_MIN: u64 = 20;
const STUN_SPREAD: u64 = 6;
const STUN_TIMEOUT: Duration = Duration::from_secs(3);

/// 每个对端最多记住的候选地址（与 netmap 每对端端点上限一致）。
pub const MAX_CANDIDATES: usize = 16;
const MAX_PENDING: usize = 8;
/// 上报给控制面的本机端点上限。
const MAX_ENDPOINTS: usize = 8;
/// MapRequest.EndpointTypes（tailcfg.EndpointType）。
pub const ENDPOINT_LOCAL: u8 = 1;
pub const ENDPOINT_STUN: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Out {
    Udp(SocketAddr, Vec<u8>),
    /// 经对端所在 DERP region 发给对端（下标）。
    Derp(usize, Vec<u8>),
}

/// 一个包从哪里来。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    Udp(SocketAddr),
    /// 经 DERP，来自对端（下标），region 是对端的 home DERP。
    Derp(usize, u16),
}

/// 发送 WireGuard 包时选的路径。
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// 可信直连：只走 UDP。
    Udp(SocketAddr),
    /// 直连未确认：UDP 与 DERP 都发。
    Both(SocketAddr),
    Derp,
}

#[derive(Debug, PartialEq, Eq)]
enum Message {
    Ping { tx: [u8; 12], node: Option<[u8; 32]> },
    Pong { tx: [u8; 12], src: SocketAddr },
    CallMeMaybe(Vec<SocketAddr>),
}

fn put_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    let ip = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out.extend_from_slice(&ip.octets());
    out.extend_from_slice(&addr.port().to_be_bytes());
}
fn get_addr(b: &[u8]) -> Option<SocketAddr> {
    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(b.get(..16)?).ok()?);
    let port = u16::from_be_bytes([*b.get(16)?, *b.get(17)?]);
    let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
    Some(SocketAddr::new(ip, port))
}

impl Message {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Self::Ping { tx, node } => {
                out.extend([TYPE_PING, 0]);
                out.extend_from_slice(tx);
                if let Some(node) = node {
                    out.extend_from_slice(node);
                }
            }
            Self::Pong { tx, src } => {
                out.extend([TYPE_PONG, 0]);
                out.extend_from_slice(tx);
                put_addr(&mut out, *src);
            }
            Self::CallMeMaybe(eps) => {
                out.extend([TYPE_CALL_ME_MAYBE, 0]);
                for ep in eps {
                    put_addr(&mut out, *ep);
                }
            }
        }
        out
    }
    /// 版本字节非 0 或长度不对的消息丢弃；尾部多余字节忽略（与 disco.Parse 一致）。
    fn decode(b: &[u8]) -> Option<Self> {
        let (&kind, rest) = b.split_first()?;
        let (&version, body) = rest.split_first()?;
        if version != 0 {
            return None;
        }
        match kind {
            TYPE_PING => {
                let tx = body.get(..12)?.try_into().ok()?;
                let node = body
                    .get(12..44)
                    .and_then(|k| <[u8; 32]>::try_from(k).ok())
                    .filter(|k| *k != [0; 32]);
                Some(Self::Ping { tx, node })
            }
            TYPE_PONG => Some(Self::Pong {
                tx: body.get(..12)?.try_into().ok()?,
                src: get_addr(body.get(12..30)?)?,
            }),
            TYPE_CALL_ME_MAYBE => {
                if body.is_empty() || body.len() % 18 != 0 {
                    return None;
                }
                Some(Self::CallMeMaybe(
                    body.chunks(18)
                        .take(MAX_CANDIDATES)
                        .filter_map(get_addr)
                        .collect(),
                ))
            }
            _ => None,
        }
    }
}

pub fn is_disco(packet: &[u8]) -> bool {
    packet.len() >= HEADER + 16 && packet[..6] == DISCO_MAGIC
}

/// 封装：魔数 | 发送方 disco 公钥 | nonce | NaCl box（发送方私钥 + 接收方公钥）。
fn seal(secret: &SecretKey, ours: &[u8; 32], peer: &[u8; 32], message: &Message) -> Option<Vec<u8>> {
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let sealed = SalsaBox::new(&PublicKey::from(*peer), secret)
        .encrypt(&nonce, message.encode().as_slice())
        .ok()?;
    let mut out = Vec::with_capacity(HEADER + sealed.len());
    out.extend_from_slice(&DISCO_MAGIC);
    out.extend_from_slice(ours);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Some(out)
}
fn open(secret: &SecretKey, packet: &[u8]) -> Option<([u8; 32], Message)> {
    if !is_disco(packet) {
        return None;
    }
    let sender: [u8; 32] = packet[6..38].try_into().ok()?;
    let plain = SalsaBox::new(&PublicKey::from(sender), secret)
        .decrypt(packet[38..HEADER].into(), &packet[HEADER..])
        .ok()?;
    Some((sender, Message::decode(&plain)?))
}

const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const STUN_SOFTWARE: &[u8] = b"tailnode";

/// RFC 5389 绑定请求：SOFTWARE 与 FINGERPRINT 属性（与 tailscale net/stun 相同）。
pub fn stun_request(tx: [u8; 12]) -> Vec<u8> {
    let mut b = Vec::with_capacity(48);
    b.extend([0x00, 0x01, 0, 0]);
    b.extend_from_slice(&STUN_COOKIE);
    b.extend_from_slice(&tx);
    b.extend([0x80, 0x22, 0, STUN_SOFTWARE.len() as u8]);
    b.extend_from_slice(STUN_SOFTWARE);
    // 指纹计算前长度要含指纹属性本身
    let len = (b.len() - 20 + 8) as u16;
    b[2..4].copy_from_slice(&len.to_be_bytes());
    let crc = crc32fast::hash(&b) ^ 0x5354_554e;
    b.extend([0x80, 0x28, 0, 4]);
    b.extend_from_slice(&crc.to_be_bytes());
    b
}
/// 绑定成功响应：交易号与映射地址（XOR-MAPPED-ADDRESS 优先，退回 MAPPED-ADDRESS）。
pub fn stun_response(b: &[u8]) -> Option<([u8; 12], SocketAddr)> {
    if b.len() < 20 || b[0..2] != [0x01, 0x01] || b[4..8] != STUN_COOKIE {
        return None;
    }
    let tx: [u8; 12] = b[8..20].try_into().ok()?;
    let len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let attrs = b.get(20..20 + len)?;
    let (mut xor, mut plain) = (None, None);
    let mut i = 0;
    while i + 4 <= attrs.len() {
        let kind = u16::from_be_bytes([attrs[i], attrs[i + 1]]);
        let n = u16::from_be_bytes([attrs[i + 2], attrs[i + 3]]) as usize;
        let value = attrs.get(i + 4..i + 4 + n)?;
        let parse = |value: &[u8], mask: bool| -> Option<SocketAddr> {
            let family = *value.get(1)?;
            let mut port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]);
            let mut key = STUN_COOKIE.to_vec();
            key.extend_from_slice(&tx);
            if mask {
                port ^= 0x2112;
            }
            let addr = value.get(4..)?;
            let ip = match (family, addr.len()) {
                (1, 4) => {
                    let mut o: [u8; 4] = addr.try_into().ok()?;
                    if mask {
                        o.iter_mut().zip(&key).for_each(|(a, k)| *a ^= k);
                    }
                    IpAddr::from(o)
                }
                (2, 16) => {
                    let mut o: [u8; 16] = addr.try_into().ok()?;
                    if mask {
                        o.iter_mut().zip(&key).for_each(|(a, k)| *a ^= k);
                    }
                    IpAddr::from(o)
                }
                _ => return None,
            };
            Some(SocketAddr::new(ip, port))
        };
        match kind {
            0x0020 => xor = parse(value, true),
            0x0001 => plain = parse(value, false),
            _ => {}
        }
        i += 4 + n.div_ceil(4) * 4;
    }
    Some((tx, xor.or(plain)?))
}

#[derive(Clone, Copy, Debug)]
struct Best {
    addr: SocketAddr,
    latency: Duration,
    trust_until: Instant,
    last_ping: Instant,
}
#[derive(Clone, Copy, Debug)]
struct Candidate {
    addr: SocketAddr,
    last_ping: Option<Instant>,
}
#[derive(Clone, Copy, Debug)]
struct Pending {
    tx: [u8; 12],
    addr: SocketAddr,
    sent: Instant,
}
#[derive(Debug, Default)]
struct PeerPath {
    disco: Option<[u8; 32]>,
    candidates: Vec<Candidate>,
    best: Option<Best>,
    pending: Vec<Pending>,
    active: Option<Instant>,
    last_full: Option<Instant>,
}
impl PeerPath {
    fn add(&mut self, addr: SocketAddr) {
        if self.candidates.iter().any(|c| c.addr == addr) {
            return;
        }
        if self.candidates.len() >= MAX_CANDIDATES {
            // 挤掉最久没 Ping 过的（从没 Ping 过的不挤）
            if let Some(i) = self
                .candidates
                .iter()
                .enumerate()
                .filter(|(_, c)| Some(c.addr) != self.best.map(|b| b.addr))
                .min_by_key(|(_, c)| c.last_ping)
                .map(|(i, _)| i)
            {
                self.candidates.remove(i);
            } else {
                return;
            }
        }
        self.candidates.push(Candidate { addr, last_ping: None });
    }
}

/// 地址加分（magicsock betterAddr）：回环 +50、链路本地 +30、私网 +20、IPv6 +10。
fn bonus(addr: SocketAddr) -> f64 {
    let ip = addr.ip();
    let mut points = 0.0;
    if ip.is_loopback() {
        points += 50.0;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() {
                points += 30.0;
            }
            if v4.is_private() || (v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64) {
                points += 20.0;
            }
        }
        IpAddr::V6(v6) => {
            points += 10.0;
            let seg = v6.segments()[0];
            if seg & 0xffc0 == 0xfe80 {
                points += 30.0;
            }
            if seg & 0xfe00 == 0xfc00 {
                points += 20.0;
            }
        }
    }
    points
}
/// `a` 是否明显好于 `b`：延迟改善换算成百分点再加地址分，改善不到 1% 不换（滞回）。
fn better(a: (SocketAddr, Duration), b: (SocketAddr, Duration)) -> bool {
    if a.0 == b.0 {
        return false;
    }
    let (la, lb) = (a.1.as_secs_f64(), b.1.as_secs_f64());
    let (mut ap, mut bp) = (0.0, 0.0);
    if la < lb && lb > 0.0 {
        ap = (lb - la) / lb * 100.0;
    } else if lb < la && la > 0.0 {
        bp = (la - lb) / la * 100.0;
    }
    ap += bonus(a.0);
    bp += bonus(b.0);
    if ap <= 1.0 && bp == 0.0 {
        return false;
    }
    ap > bp
}

pub struct Magic {
    secret: SecretKey,
    public: [u8; 32],
    node: [u8; 32],
    peers: Vec<PeerPath>,
    by_disco: HashMap<[u8; 32], usize>,
    families: [bool; 2],
    stun_servers: Vec<SocketAddr>,
    stun_pending: Vec<([u8; 12], Instant)>,
    next_stun: Option<Instant>,
    local: Vec<SocketAddr>,
    stunned: Vec<SocketAddr>,
}

impl Magic {
    /// `peers` 为（disco 公钥、netmap 端点），下标与 WireGuard 对端一致。
    /// `families` 为（IPv4、IPv6）套接字是否可用。
    pub fn new(
        secret: SecretKey,
        node: [u8; 32],
        peers: Vec<(Option<[u8; 32]>, Vec<SocketAddr>)>,
        families: [bool; 2],
    ) -> Self {
        let public = *secret.public_key().as_bytes();
        let mut by_disco = HashMap::new();
        let peers = peers
            .into_iter()
            .enumerate()
            .map(|(i, (disco, endpoints))| {
                if let Some(d) = disco {
                    by_disco.insert(d, i);
                }
                let mut path = PeerPath {
                    disco,
                    ..PeerPath::default()
                };
                for ep in endpoints {
                    path.add(ep);
                }
                path
            })
            .collect();
        Self {
            secret,
            public,
            node,
            peers,
            by_disco,
            families,
            stun_servers: Vec::new(),
            stun_pending: Vec::new(),
            next_stun: None,
            local: Vec::new(),
            stunned: Vec::new(),
        }
    }
    fn usable(&self, addr: SocketAddr) -> bool {
        self.families[usize::from(addr.is_ipv6())]
    }
    pub fn set_stun_servers(&mut self, servers: Vec<SocketAddr>) {
        self.stun_servers = servers;
        self.stun_servers.truncate(4);
    }
    /// 本机网卡地址（端口为共享套接字的本地端口）。
    pub fn set_local(&mut self, mut local: Vec<SocketAddr>) {
        local.truncate(MAX_ENDPOINTS);
        self.local = local;
    }
    /// 上报给控制面的端点与类型。
    pub fn endpoints(&self) -> Vec<(SocketAddr, u8)> {
        let mut out: Vec<(SocketAddr, u8)> = Vec::new();
        for (list, kind) in [(&self.stunned, ENDPOINT_STUN), (&self.local, ENDPOINT_LOCAL)] {
            for &addr in list.iter() {
                if out.len() < MAX_ENDPOINTS && !out.iter().any(|(a, _)| *a == addr) {
                    out.push((addr, kind));
                }
            }
        }
        out
    }
    fn ping(&mut self, peer: usize, addr: SocketAddr, now: Instant) -> Option<Out> {
        let disco = self.peers[peer].disco?;
        let tx: [u8; 12] = rand::random();
        let packet = seal(
            &self.secret,
            &self.public,
            &disco,
            &Message::Ping { tx, node: Some(self.node) },
        )?;
        let path = &mut self.peers[peer];
        if path.pending.len() >= MAX_PENDING {
            path.pending.remove(0);
        }
        path.pending.push(Pending { tx, addr, sent: now });
        if let Some(c) = path.candidates.iter_mut().find(|c| c.addr == addr) {
            c.last_ping = Some(now);
        }
        if let Some(best) = path.best.as_mut().filter(|b| b.addr == addr) {
            best.last_ping = now;
        }
        Some(Out::Udp(addr, packet))
    }
    /// 对端的一轮完整探测：给每个候选（限速）发 Ping，并经 DERP 发 CallMeMaybe 附上本机端点。
    fn full_ping(&mut self, peer: usize, now: Instant, out: &mut Vec<Out>) {
        self.peers[peer].last_full = Some(now);
        let due: Vec<SocketAddr> = self.peers[peer]
            .candidates
            .iter()
            .filter(|c| c.last_ping.is_none_or(|t| now.duration_since(t) >= PING_INTERVAL))
            .map(|c| c.addr)
            .filter(|a| self.usable(*a))
            .collect();
        let mut sent = false;
        for addr in due {
            if let Some(o) = self.ping(peer, addr, now) {
                out.push(o);
                sent = true;
            }
        }
        let endpoints: Vec<SocketAddr> = self.endpoints().into_iter().map(|(a, _)| a).collect();
        if sent || self.peers[peer].candidates.is_empty() {
            if let (Some(disco), false) = (self.peers[peer].disco, endpoints.is_empty()) {
                if let Some(p) = seal(&self.secret, &self.public, &disco, &Message::CallMeMaybe(endpoints)) {
                    out.push(Out::Derp(peer, p));
                }
            }
        }
    }
    /// 发送 WireGuard 包前调用：记一次活动，返回路径。
    pub fn route(&mut self, peer: usize, now: Instant) -> Route {
        let Some(path) = self.peers.get_mut(peer) else {
            return Route::Derp;
        };
        path.active = Some(now);
        match path.best {
            Some(best) if now < best.trust_until => Route::Udp(best.addr),
            Some(best) => Route::Both(best.addr),
            None => Route::Derp,
        }
    }
    /// UDP 来源属于哪个对端（WireGuard 包按它交给对应的人造端点）。
    pub fn peer_for(&self, addr: SocketAddr) -> Option<usize> {
        self.peers.iter().position(|p| {
            p.best.is_some_and(|b| b.addr == addr) || p.candidates.iter().any(|c| c.addr == addr)
        })
    }
    /// 处理收到的 STUN 响应。端点集合变化时返回 true。
    pub fn on_stun(&mut self, packet: &[u8]) -> bool {
        let Some((tx, mapped)) = stun_response(packet) else {
            return false;
        };
        let Some(i) = self.stun_pending.iter().position(|(t, _)| *t == tx) else {
            return false;
        };
        self.stun_pending.remove(i);
        if self.stunned.contains(&mapped) {
            return false;
        }
        // 每个地址族只保留最新的一个映射
        self.stunned.retain(|a| a.is_ipv6() != mapped.is_ipv6());
        self.stunned.push(mapped);
        true
    }
    /// 处理收到的 disco 包。
    pub fn on_disco(&mut self, packet: &[u8], via: Via, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        let Some((sender, message)) = open(&self.secret, packet) else {
            return out;
        };
        let Some(&peer) = self.by_disco.get(&sender) else {
            return out;
        };
        if let Via::Derp(from, _) = via {
            if from != peer {
                return out; // DERP 的来源身份与 disco 发送方不符
            }
        }
        match message {
            Message::Ping { tx, .. } => {
                let src = match via {
                    Via::Udp(src) => {
                        self.peers[peer].add(src);
                        src
                    }
                    Via::Derp(_, region) => SocketAddr::new(IpAddr::V4(DERP_MAGIC_IP), region),
                };
                if let Some(p) = seal(&self.secret, &self.public, &sender, &Message::Pong { tx, src }) {
                    out.push(match via {
                        Via::Udp(src) => Out::Udp(src, p),
                        Via::Derp(..) => Out::Derp(peer, p),
                    });
                }
            }
            Message::Pong { tx, .. } => {
                let Via::Udp(src) = via else { return out };
                let path = &mut self.peers[peer];
                let Some(i) = path.pending.iter().position(|p| p.tx == tx && p.addr == src) else {
                    return out;
                };
                let pending = path.pending.remove(i);
                let latency = now.duration_since(pending.sent);
                match path.best {
                    Some(best) if best.addr == src => {
                        path.best = Some(Best { latency, trust_until: now + TRUST, ..best });
                    }
                    Some(best)
                        if now < best.trust_until
                            && !better((src, latency), (best.addr, best.latency)) => {}
                    _ => {
                        path.best = Some(Best {
                            addr: src,
                            latency,
                            trust_until: now + TRUST,
                            last_ping: pending.sent,
                        });
                    }
                }
            }
            Message::CallMeMaybe(eps) => {
                // 只接受经 DERP 的 CallMeMaybe（与 magicsock 一致）：对端请我们向它的端点打洞
                if !matches!(via, Via::Derp(..)) {
                    return out;
                }
                for ep in eps.iter().filter(|e| !e.ip().is_unspecified()) {
                    self.peers[peer].add(*ep);
                    if let Some(c) = self.peers[peer].candidates.iter_mut().find(|c| c.addr == *ep) {
                        c.last_ping = None;
                    }
                }
                for ep in eps {
                    if self.usable(ep) {
                        if let Some(o) = self.ping(peer, ep, now) {
                            out.push(o);
                        }
                    }
                }
            }
        }
        out
    }
    /// 每秒一次：心跳、完整探测、超时回收与 STUN 刷新。
    pub fn tick(&mut self, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        let mut any_active = false;
        for peer in 0..self.peers.len() {
            let path = &mut self.peers[peer];
            // 超时回收；最佳地址的 Ping 超时且已过信任期就撤掉
            let best = path.best.map(|b| b.addr);
            let mut lost_best = false;
            path.pending.retain(|p| {
                let alive = now.duration_since(p.sent) < PING_TIMEOUT;
                if !alive && Some(p.addr) == best {
                    lost_best = true;
                }
                alive
            });
            if lost_best && path.best.is_some_and(|b| now >= b.trust_until) {
                path.best = None;
            }
            if path.disco.is_none() || path.active.is_none_or(|t| now.duration_since(t) >= ACTIVE) {
                continue;
            }
            any_active = true;
            let trusted = path.best.is_some_and(|b| now < b.trust_until);
            let upgrade = path.best.is_some_and(|b| b.latency > GOOD_ENOUGH)
                && path.last_full.is_none_or(|t| now.duration_since(t) >= UPGRADE);
            let full_due = path.last_full.is_none_or(|t| now.duration_since(t) >= PING_INTERVAL);
            if (!trusted && full_due) || upgrade {
                self.full_ping(peer, now, &mut out);
            } else if let Some(best) = self.peers[peer].best {
                if now.duration_since(best.last_ping) >= HEARTBEAT {
                    if let Some(o) = self.ping(peer, best.addr, now) {
                        out.push(o);
                    }
                }
            }
        }
        self.stun_pending
            .retain(|(_, t)| now.duration_since(*t) < STUN_TIMEOUT);
        // 首次立即 STUN；之后只在有活动对端时周期刷新
        let due = self.next_stun.is_none_or(|t| now >= t);
        if due && (self.next_stun.is_none() || any_active) {
            for &server in &self.stun_servers {
                if !self.usable(server) {
                    continue;
                }
                let tx: [u8; 12] = rand::random();
                self.stun_pending.push((tx, now));
                out.push(Out::Udp(server, stun_request(tx)));
            }
            self.stun_pending.truncate(8);
            let jitter = rand::random::<u64>() % (STUN_SPREAD + 1);
            self.next_stun = Some(now + Duration::from_secs(STUN_MIN + jitter));
        }
        out
    }
}

/// 本机网卡上的单播地址（不含回环、链路本地），配合共享套接字端口作为 local 端点。
#[cfg(unix)]
pub fn local_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    // SAFETY: getifaddrs 分配的链表在 freeifaddrs 前有效；只读取 ifa_addr。
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() && out.len() < MAX_ENDPOINTS * 2 {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || ifa.ifa_flags & libc::IFF_UP as libc::c_uint == 0 {
                continue;
            }
            let ip = match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
                }
                libc::AF_INET6 => {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
                }
                _ => continue,
            };
            let skip = ip.is_loopback()
                || ip.is_unspecified()
                || match ip {
                    IpAddr::V4(v4) => v4.is_link_local(),
                    // 链路本地与 tailnet 自身的 ULA 不上报
                    IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80 || v6.segments()[0] == 0xfd7a,
                }
                // 本机 tailnet 地址（100.64.0.0/10）不是可达的物理端点
                || matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64);
            if !skip && !out.contains(&ip) {
                out.push(ip);
            }
        }
        libc::freeifaddrs(head);
    }
    out
}
#[cfg(not(unix))]
pub fn local_addresses() -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(test)]
#[path = "magic_tests.rs"]
mod tests;
