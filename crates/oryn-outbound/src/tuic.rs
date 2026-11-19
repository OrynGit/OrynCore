//! TUIC v5 出站。令牌是 TLS 导出材料。
//!
//! `reduce-rtt` 时以 0-RTT 建连：TLS 导出材料要等握手完成才有，认证在后台握手完成后发出，
//! 这之前打开的流先发出请求，服务器等认证到达后再处理（与 sing-quic 的 clientHandshake 一致）。
//! `udp-over-stream` 时 UDP 走一条 TCP 流上的 UoT（sing-box / mihomo 的写法）。

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::FutureExt;
use oryn_config::{TargetAddr, TuicSpec, UdpRelayMode};
use oryn_quic::{Congestion, QuicClient, QuicParams, MAX_BIDI};

use crate::{
    inbox::{self, Inbox},
    reassembly::Reassembly,
    resolve_target,
    slots::{Counted, Slots},
    BoxStream, Outbound, PacketConn, QuicControl, Resolver,
};

const MAX_SESSIONS: usize = 32;
const REASSEMBLY_BUDGET: usize = 128 * 1024;
const MAX_FRAGMENTS: u8 = 16;
const FRAG_WAIT: Duration = Duration::from_secs(3);
/// 每个关联 ID 同时等待重组的包数。
const PENDING_PER_SESSION: usize = 4;
/// 分片帧固定头：版本、命令、关联 ID、包 ID、总片数、片序号、长度（地址另算）。
const UDP_HEADER: usize = 10;
/// quic 模式下单条单向流承载的 UDP 包（含头）上限与读取期限。
const UNI_PACKET_LIMIT: usize = 64 * 1024;
const UNI_READ_TIMEOUT: Duration = Duration::from_secs(10);

pub struct TuicOutbound {
    name: String,
    spec: TuicSpec,
    resolver: Arc<dyn Resolver>,
    quic: Arc<QuicClient>,
    streams: Slots,
    authed: tokio::sync::Mutex<Option<usize>>,
    auth_tasks: Slots,
    udp: Arc<Mutex<Option<Arc<UdpHub>>>>,
}

impl TuicOutbound {
    pub fn new(
        name: String,
        spec: TuicSpec,
        resolver: Arc<dyn Resolver>,
        datagrams: Arc<dyn oryn_udp::DatagramFactory>,
    ) -> Arc<Self> {
        let congestion = match spec.congestion {
            oryn_config::QuicCongestion::Bbr => Congestion::Bbr,
            oryn_config::QuicCongestion::Cubic => Congestion::Cubic,
            oryn_config::QuicCongestion::NewReno => Congestion::NewReno,
        };
        let alpn = spec
            .tls
            .alpn
            .iter()
            .map(|item| item.as_bytes().to_vec())
            .collect();
        let quic = QuicClient::new(QuicParams {
            datagrams,
            alpn,
            skip_verify: spec.tls.skip_cert_verify,
            fingerprint: spec.tls.fingerprint,
            disable_sni: spec.disable_sni,
            congestion,
            brutal_rate: None,
            obfs: None,
            hop: None,
            rendezvous: None,
            zero_rtt: spec.reduce_rtt,
            keep_alive: None,
        });
        Arc::new(Self {
            name,
            spec,
            resolver,
            quic,
            streams: Slots::default(),
            authed: tokio::sync::Mutex::new(None),
            auth_tasks: Slots::default(),
            udp: Arc::new(Mutex::new(None)),
        })
    }

    async fn connection(&self) -> io::Result<quinn::Connection> {
        let addrs = resolve_target(self.resolver.as_ref(), &self.spec.server).await?;
        let addr = *addrs
            .first()
            .ok_or_else(|| io::Error::other("cannot resolve tuic server"))?;
        let name = self
            .spec
            .tls
            .sni
            .clone()
            .unwrap_or_else(|| match &self.spec.server {
                TargetAddr::Domain(host, _) => host.clone(),
                TargetAddr::Ip(ip) => ip.ip().to_string(),
            });
        let conn = self.quic.connection(addr.ip(), &name, addr.port()).await?;
        self.authenticate(&conn).await?;
        Ok(conn)
    }

    async fn authenticate(&self, conn: &quinn::Connection) -> io::Result<()> {
        let id = conn.stable_id();
        // 普通认证单飞；等待锁的调用取消不会影响正在认证的连接。
        let mut authed = self.authed.lock().await;
        if conn.close_reason().is_some() {
            return Err(io::Error::other(
                "tuic connection closed during authentication",
            ));
        }
        if authed.as_ref() == Some(&id) {
            return Ok(());
        }
        let guard = AuthGuard(Some(conn.clone()));
        match self.quic.handshake(conn) {
            Some(mut handshake) => {
                let conn = conn.clone();
                let uuid = self.spec.uuid;
                let password = self.spec.password.clone();
                // 保留 0-RTT 先发请求的行为，但每个出站至多一个认证驱动，且有期限。
                let slot = self
                    .auth_tasks
                    .acquire(1)
                    .ok_or_else(|| io::Error::other("tuic authentication driver busy"))?;
                tokio::spawn(async move {
                    let _slot = slot;
                    let mut guard = guard;
                    let auth = async {
                        handshake
                            .wait_for(|state| state.is_some())
                            .await
                            .map_err(io::Error::other)?;
                        send_auth(&conn, &uuid, &password).await
                    };
                    if matches!(
                        tokio::time::timeout(UNI_READ_TIMEOUT, auth).await,
                        Ok(Ok(()))
                    ) {
                        guard.0 = None;
                    }
                });
            }
            None => {
                let mut guard = guard;
                tokio::time::timeout(
                    UNI_READ_TIMEOUT,
                    send_auth(conn, &self.spec.uuid, &self.spec.password),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "tuic authentication timed out")
                })??;
                guard.0 = None;
            }
        }
        *authed = Some(id);
        self.spawn_heartbeat(conn.clone());
        Ok(())
    }

    /// 心跳只在有活动任务（TCP 流或这条连接上的 UDP 关联）时发送：没有任务时让连接按
    /// QUIC 空闲超时自然关闭，不为空连接持续耗电（docs/protocols/tuic.md）。
    fn spawn_heartbeat(&self, conn: quinn::Connection) {
        if self.quic.is_asleep() {
            return;
        }
        let interval = Duration::from_millis(self.spec.heartbeat_ms);
        let streams = self.streams.clone();
        let udp = self.udp.clone();
        tokio::spawn(async move {
            let id = conn.stable_id();
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if conn.close_reason().is_some() {
                    break;
                }
                let udp_active = udp.lock().unwrap().as_ref().is_some_and(|hub| {
                    hub.conn.stable_id() == id && !hub.sessions.lock().unwrap().is_empty()
                });
                if streams.used() == 0 && !udp_active {
                    continue;
                }
                let _ = conn.send_datagram(Bytes::from_static(&[0x05, 0x04]));
            }
        });
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn tag(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "tuic"
    }
    fn session_control(&self) -> Option<Arc<dyn crate::SessionControl>> {
        Some(Arc::new(QuicControl(self.quic.clone())))
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        // 名额随流一起释放；失败时 slot 在这里被丢弃，同样归还
        let slot = self
            .streams
            .acquire(self.spec.max_streams.min(MAX_BIDI))
            .ok_or_else(|| io::Error::other("tuic stream limit reached"))?;
        let conn = self.connection().await?;
        let stream = match self.quic.handshake(&conn) {
            // 0-RTT 窗口内：请求头先随 0-RTT 发出，再等握手结果。被拒时这条流已被 reset，
            // 在已转为 1-RTT 的同一连接上重开一条流重发请求头（Oryn_dev/docs/oryncore/plans/plan-0.8.x.md C2 的回退）。
            // 服务端要等握手后才到的认证才处理请求，这里等握手几乎不增加时延。
            Some(mut handshake) if handshake.borrow().is_none() => {
                let first = open_tcp(&conn, target).await;
                let accepted = handshake
                    .wait_for(|state| state.is_some())
                    .await
                    .map(|state| *state == Some(true))
                    .unwrap_or(false);
                match first {
                    Ok(stream) if accepted => stream,
                    _ if conn.close_reason().is_none() => open_tcp(&conn, target).await?,
                    Ok(_) => return Err(io::Error::other("tuic connection closed during 0-RTT")),
                    Err(err) => return Err(err),
                }
            }
            _ => open_tcp(&conn, target).await?,
        };
        Ok(Counted::boxed(stream, slot))
    }
    async fn bind_udp(&self, first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.spec.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tuic udp is disabled",
            ));
        }
        if let Some(version) = self.spec.udp_over_stream {
            let magic = TargetAddr::Domain(crate::uot::magic(version).into(), 0);
            let stream = self.connect_tcp(&magic).await?;
            return Ok(Box::new(crate::uot::UotConn::new(
                stream,
                version,
                first_target,
            )?));
        }
        let conn = self.connection().await?;
        let hub = self.hub(conn)?;
        hub.open(self.spec.udp_relay, self.spec.max_udp_packet)
    }
}

/// 部分写入、错误和取消均关闭连接，不能在同一连接重新写认证来掩盖半帧。
struct AuthGuard(Option<quinn::Connection>);
impl Drop for AuthGuard {
    fn drop(&mut self) {
        if let Some(conn) = &self.0 {
            conn.close(0u32.into(), b"auth");
        }
    }
}

async fn send_auth(conn: &quinn::Connection, uuid: &[u8; 16], password: &str) -> io::Result<()> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|_| io::Error::other("tuic export keying material failed"))?;
    let mut send = conn.open_uni().await.map_err(io::Error::other)?;
    let mut packet = Vec::with_capacity(50);
    packet.push(0x05);
    packet.push(0x00);
    packet.extend_from_slice(uuid);
    packet.extend_from_slice(&token);
    send.write_all(&packet).await.map_err(io::Error::other)?;
    send.finish().map_err(io::Error::other)?;
    Ok(())
}

async fn open_tcp(conn: &quinn::Connection, target: &TargetAddr) -> io::Result<BoxStream> {
    let (mut send, recv) = conn.open_bi().await.map_err(io::Error::other)?;
    let mut header = vec![0x05, 0x01];
    write_addr(&mut header, target);
    send.write_all(&header).await.map_err(io::Error::other)?;
    Ok(Box::new(tokio::io::join(recv, send)))
}

fn write_addr(out: &mut Vec<u8>, target: &TargetAddr) {
    match target {
        TargetAddr::Domain(host, port) => {
            out.push(0x00);
            let host = host.as_bytes();
            out.push(host.len().min(255) as u8);
            out.extend_from_slice(&host[..host.len().min(255)]);
            out.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                out.push(0x02);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
}

type SessionInbox = Arc<Inbox<(Vec<u8>, TargetAddr)>>;

struct UdpHub {
    conn: quinn::Connection,
    sessions: Mutex<HashMap<u16, SessionInbox>>,
    /// 下一个关联 ID 的起点。和参考客户端一样循环递增而不是复用最小空闲 ID：
    /// 服务端对旧关联的清理是异步的，刚释放的 ID 立刻再用会撞上它。
    next_id: AtomicU16,
    reassembly: Mutex<Reassembly<u16, TargetAddr>>,
}

impl TuicOutbound {
    fn hub(&self, conn: quinn::Connection) -> io::Result<Arc<UdpHub>> {
        let id = conn.stable_id();
        Ok(crate::shared_hub(
            &self.udp,
            |hub| hub.conn.stable_id() == id,
            || {
                let hub = Arc::new(UdpHub {
                    conn: conn.clone(),
                    sessions: Mutex::new(HashMap::new()),
                    next_id: AtomicU16::new(1),
                    reassembly: Mutex::new(Reassembly::new(
                        REASSEMBLY_BUDGET,
                        PENDING_PER_SESSION,
                        MAX_FRAGMENTS,
                        FRAG_WAIT,
                    )),
                });
                let reader = hub.clone();
                tokio::spawn(async move { reader.recv_loop().await });
                hub
            },
        ))
    }
}

impl UdpHub {
    fn open(
        self: &Arc<Self>,
        mode: UdpRelayMode,
        max_packet: usize,
    ) -> io::Result<Box<dyn PacketConn>> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= MAX_SESSIONS {
            return Err(io::Error::other("tuic udp session limit reached"));
        }
        // 会话表可能有空洞（旧 PacketConn 已经 Drop），不能用 len()+1，
        // 否则会覆盖仍在使用的关联 ID。
        let id = next_session_id(&sessions, self.next_id.load(Ordering::Relaxed))
            .ok_or_else(|| io::Error::other("tuic udp session id space exhausted"))?;
        self.next_id
            .store(id.wrapping_add(1).max(1), Ordering::Relaxed);
        let inbox = Arc::new(Inbox::with_bytes(
            inbox::SESSION_PACKETS,
            inbox::SESSION_BYTES,
        ));
        sessions.insert(id, inbox.clone());
        drop(sessions);
        Ok(Box::new(TuicPacket {
            id,
            hub: self.clone(),
            mode,
            max_packet,
            rx: inbox,
            packet: AtomicU16::new(0),
        }))
    }

    async fn recv_loop(self: Arc<Self>) {
        loop {
            tokio::select! {
                datagram = self.conn.read_datagram() => {
                    let Ok(bytes) = datagram else { break };
                    self.ingest(&bytes);
                }
                uni = self.conn.accept_uni() => {
                    let Ok(recv) = uni else { break };
                    // 每条单向流一个任务：内联读取会让一条慢流堵住后面所有流和数据报，
                    // 并且推迟归还流额度。同时存在的任务数受 MAX_UNI 限制；读不完的流靠超时回收。
                    let hub = self.clone();
                    tokio::spawn(async move { hub.read_uni(recv).await });
                }
            }
        }
        self.close_sessions();
    }

    /// QUIC 连接已断：让所有会话立刻结束，而不是等上层空闲超时。
    fn close_sessions(&self) {
        for inbox in self.sessions.lock().unwrap().values() {
            inbox.close();
        }
    }

    async fn read_uni(&self, mut recv: quinn::RecvStream) {
        let mut buf = [0u8; 2048];
        let mut data = Vec::new();
        let read = async {
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(n)) if n > 0 => {
                        data.extend_from_slice(&buf[..n]);
                        if data.len() > UNI_PACKET_LIMIT {
                            return false;
                        }
                        // TUIC 的长度字段标出完整帧。对端可能延迟 FIN；完整帧一到就交付并
                        // 停止读取，让 QUIC 尽早归还单向流额度。
                        if complete_uni_frame(&data) {
                            return true;
                        }
                    }
                    Ok(_) => return false,
                    Err(_) => return false,
                }
            }
        };
        if tokio::time::timeout(UNI_READ_TIMEOUT, read)
            .await
            .unwrap_or(false)
        {
            self.ingest(&data);
        }
        let _ = recv.stop(quinn::VarInt::from_u32(0));
    }

    fn ingest(&self, data: &[u8]) {
        let Some((assoc, pkt, total, frag, size, addr, header)) = parse_fragment(data) else {
            return;
        };
        // 未知关联不能进入重组表；否则攻击者可用随机 assoc 消耗全局
        // 分片/元数据预算，且完成后也无法投递。
        if !self.sessions.lock().unwrap().contains_key(&assoc) {
            return;
        }
        let start = 10 + header;
        let payload = data[start..start + size].to_vec();
        let done = self
            .reassembly
            .lock()
            .unwrap()
            .insert(assoc, pkt, frag, total, addr, payload);
        if let Some((body, addr)) = done {
            self.deliver(assoc, body, addr);
        }
    }

    fn deliver(&self, assoc: u16, payload: Vec<u8>, addr: TargetAddr) {
        if let Some(tx) = self.sessions.lock().unwrap().get(&assoc).cloned() {
            let bytes = payload.len();
            let _ = tx.try_send_sized((payload, addr), bytes);
        }
    }
}

/// 解析 TUIC UDP 分片的固定头和地址。只做格式验证；关联 ID 是否
/// 已打开由 `UdpHub::ingest` 检查。
type ParsedFragment = (u16, u16, u8, u8, usize, Option<TargetAddr>, usize);

fn parse_fragment(data: &[u8]) -> Option<ParsedFragment> {
    if data.len() < 11 || data[0] != 0x05 || data[1] != 0x02 {
        return None;
    }
    let assoc = u16::from_be_bytes([data[2], data[3]]);
    let packet = u16::from_be_bytes([data[4], data[5]]);
    let total = data[6];
    let frag = data[7];
    let size = u16::from_be_bytes([data[8], data[9]]) as usize;
    if total == 0 || total > MAX_FRAGMENTS || frag >= total {
        return None;
    }
    let (addr, header) = if frag == 0 {
        // 第 0 片必须有目的地址；0xff 只允许出现在后续分片。
        if data[10] == 0xff {
            return None;
        }
        let (addr, header) = read_addr(&data[10..])?;
        (Some(addr), header)
    } else {
        if data[10] != 0xff {
            return None;
        }
        (None, 1)
    };
    let start = 10 + header;
    if start.checked_add(size)? > data.len() {
        return None;
    }
    Some((assoc, packet, total, frag, size, addr, header))
}

fn complete_uni_frame(data: &[u8]) -> bool {
    if data.len() < 11 || data[..2] != [0x05, 0x02] {
        return false;
    }
    let header = match (data[7], data[10]) {
        (0, 0x00) => data.get(11).map(|len| 4 + *len as usize),
        (0, 0x01) => Some(7),
        (0, 0x02) => Some(19),
        (1.., 0xff) => Some(1),
        _ => None,
    };
    let Some(header) = header else { return false };
    let size = u16::from_be_bytes([data[8], data[9]]) as usize;
    data.len() == 10 + header + size && parse_fragment(data).is_some()
}

struct TuicPacket {
    id: u16,
    hub: Arc<UdpHub>,
    mode: UdpRelayMode,
    max_packet: usize,
    rx: SessionInbox,
    packet: AtomicU16,
}

/// 从 `start` 起（回绕、跳过 0）找第一个没被占用的关联 ID。
fn next_session_id<T>(sessions: &HashMap<u16, T>, start: u16) -> Option<u16> {
    let start = start.max(1);
    (start..=u16::MAX)
        .chain(1..start)
        .find(|candidate| !sessions.contains_key(candidate))
}

#[async_trait]
impl PacketConn for TuicPacket {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        if buf.len() > REASSEMBLY_BUDGET {
            return Err(io::Error::other("tuic udp packet is too large"));
        }
        let mut address = Vec::new();
        write_addr(&mut address, target);
        // 两种模式都按 max-udp-relay-packet-size 切片；native 模式每片还必须装进一个 QUIC 数据报
        let room = match self.mode {
            UdpRelayMode::Native => {
                let datagram = self.hub.conn.max_datagram_size().unwrap_or(1200);
                datagram
                    .saturating_sub(UDP_HEADER + address.len())
                    .clamp(1, self.max_packet.max(1))
            }
            UdpRelayMode::Quic => self.max_packet.max(1),
        };
        let pieces = if buf.is_empty() {
            vec![buf]
        } else {
            buf.chunks(room).collect::<Vec<_>>()
        };
        if pieces.len() > usize::from(MAX_FRAGMENTS) {
            return Err(io::Error::other("tuic udp packet is too large"));
        }
        let packet = self.packet.fetch_add(1, Ordering::Relaxed);
        let total = pieces.len() as u8;
        for (index, piece) in pieces.iter().enumerate() {
            let mut frame = vec![0x05, 0x02];
            frame.extend_from_slice(&self.id.to_be_bytes());
            frame.extend_from_slice(&packet.to_be_bytes());
            frame.push(total);
            frame.push(index as u8);
            frame.extend_from_slice(&(piece.len() as u16).to_be_bytes());
            if index == 0 {
                frame.extend_from_slice(&address);
            } else {
                frame.push(0xff);
            }
            frame.extend_from_slice(piece);
            match self.mode {
                UdpRelayMode::Native => {
                    self.hub
                        .conn
                        .send_datagram(Bytes::from(frame))
                        .map_err(io::Error::other)?;
                }
                UdpRelayMode::Quic => {
                    let mut send = self.hub.conn.open_uni().await.map_err(io::Error::other)?;
                    send.write_all(&frame).await.map_err(io::Error::other)?;
                    send.finish().map_err(io::Error::other)?;
                }
            }
        }
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let Some((payload, addr)) = self.rx.recv().await else {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "tuic udp closed"));
        };
        let n = crate::copy_datagram(&payload, buf, "TUIC");
        Ok((n, addr))
    }
}

impl Drop for TuicPacket {
    fn drop(&mut self) {
        // ID 可能在该 PacketConn 存活期间经历过回收再分配；只移除仍指向
        // 本实例 inbox 的条目，避免旧实例 Drop 时误删新会话。
        let removed = {
            let mut sessions = self.hub.sessions.lock().unwrap();
            if sessions
                .get(&self.id)
                .is_some_and(|inbox| Arc::ptr_eq(inbox, &self.rx))
            {
                sessions.remove(&self.id).is_some()
            } else {
                false
            }
        };
        if !removed {
            return;
        }
        // 与参考端非等待 OpenUniStream 一致：清理只是 best-effort，不占后台
        // 任务/队列，也不等额度。4 字节写入同样只 poll 一次；背压或部分写入
        // 则 reset 本流，不能为了丢失的 Dissociate 关闭正常的共享连接。
        let Some(Ok(mut send)) = self.hub.conn.open_uni().now_or_never() else {
            return;
        };
        let [hi, lo] = self.id.to_be_bytes();
        if matches!(
            send.write_all(&[0x05, 0x03, hi, lo]).now_or_never(),
            Some(Ok(()))
        ) {
            let _ = send.finish();
        } else {
            let _ = send.reset(0u32.into());
        }
    }
}

fn read_addr(data: &[u8]) -> Option<(TargetAddr, usize)> {
    let kind = *data.first()?;
    match kind {
        0xff => Some((TargetAddr::Domain(String::new(), 0), 1)),
        0x00 => {
            let len = *data.get(1)? as usize;
            let host = std::str::from_utf8(data.get(2..2 + len)?).ok()?.to_string();
            let port = u16::from_be_bytes(data.get(2 + len..4 + len)?.try_into().ok()?);
            Some((TargetAddr::Domain(host, port), 4 + len))
        }
        0x01 => {
            let b = data.get(1..7)?;
            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            Some((
                TargetAddr::Ip(std::net::SocketAddr::new(ip.into(), port)),
                7,
            ))
        }
        0x02 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(data.get(1..17)?);
            let port = u16::from_be_bytes(data.get(17..19)?.try_into().ok()?);
            Some((
                TargetAddr::Ip(std::net::SocketAddr::new(
                    std::net::Ipv6Addr::from(octets).into(),
                    port,
                )),
                19,
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "tuic_dissociate_tests.rs"]
mod dissociate_tests;

#[cfg(test)]
#[path = "tuic_auth_tests.rs"]
mod auth_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_short_tuic_frames_are_rejected() {
        for len in 0..11 {
            assert!(parse_fragment(&vec![0; len]).is_none(), "length {len}");
        }
    }

    #[test]
    fn tuic_fragment_zero_requires_address() {
        // fixed header + 0xff (the no-address marker) is invalid for fragment 0
        let mut frame = vec![0x05, 0x02, 1, 0, 0, 1, 2, 0, 0, 0, 0xff];
        assert!(parse_fragment(&frame).is_none());
        frame[7] = 1;
        assert!(parse_fragment(&frame).is_some());
    }

    #[test]
    fn uni_frame_is_deliverable_before_fin() {
        let frame = [
            0x05, 0x02, 0, 1, 0, 2, 1, 0, 0, 3, 0x01, 127, 0, 0, 1, 0, 53, 1, 2, 3,
        ];
        for n in 0..frame.len() {
            assert!(!complete_uni_frame(&frame[..n]), "partial frame at {n}");
        }
        assert!(complete_uni_frame(&frame));
        assert!(!complete_uni_frame(&[frame.as_slice(), &[4]].concat()));
    }

    #[test]
    fn session_id_allocator_skips_live_ids_after_a_hole() {
        let mut sessions = HashMap::new();
        sessions.insert(1, ());
        sessions.insert(3, ());
        assert_eq!(next_session_id(&sessions, 1), Some(2));
        sessions.insert(2, ());
        assert_eq!(next_session_id(&sessions, 1), Some(4));
    }

    #[test]
    fn session_id_allocator_moves_forward_and_wraps_without_zero() {
        let mut sessions = HashMap::new();
        // 刚释放的小 ID 不会被立刻重用：起点之后的第一个空闲 ID 优先
        assert_eq!(next_session_id(&sessions, 5), Some(5));
        sessions.insert(5, ());
        assert_eq!(next_session_id(&sessions, 5), Some(6));
        // 回绕后从 1 开始，永远不返回 0
        assert_eq!(next_session_id(&sessions, u16::MAX), Some(u16::MAX));
        sessions.insert(u16::MAX, ());
        assert_eq!(next_session_id(&sessions, u16::MAX), Some(1));
        assert_eq!(next_session_id(&sessions, 0), Some(1));
        // 全部占满时返回 None
        let full: HashMap<u16, ()> = (1..=u16::MAX).map(|id| (id, ())).collect();
        assert_eq!(next_session_id(&full, 100), None);
    }
}
