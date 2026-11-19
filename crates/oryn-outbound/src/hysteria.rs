//! Hysteria v1 出站。
//!
//! 线格式依据 SagerNet/sing-quic `hysteria`（protocol.go、client.go、packet.go、xplus.go），
//! v0.6.1，commit 见 Oryn_dev/docs/oryncore/provenance.md。Copyright (C) 2023 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
//! 改写为 Oryn 的出站：QUIC 连接、Brutal、端口跳跃与套接字层混淆（XPlus）复用 `oryn-quic`。
//!
//! - 每条 QUIC 连接先开一个控制流：ClientHello（版本 3、上下行字节/秒、认证）→ ServerHello。
//!   Brutal 的发送速率取 min(服务端的接收速率, 本端上行)。控制流在连接存活期间保持打开。
//! - TCP：每个 Flow 一个双向流，请求（UDP 标志、主机、端口）与第一段数据一起写出，读取前先读响应。
//! - UDP：每个会话一个双向流（请求带 UDP 标志，响应里有会话 ID，流保持打开），数据走 QUIC 数据报：
//!   会话 ID、主机、端口、包 ID、分片序号与总数、长度、数据。

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use oryn_config::{HysteriaSpec, TargetAddr};
use oryn_quic::{Congestion, Hop, Obfs, QuicClient, QuicParams, MAX_BIDI};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// FakeTCP 承载未实现（与平台无关）。不退回普通 UDP：那会改变线上特征且服务端未必监听。
const FAKETCP_UNSUPPORTED: &str =
    "hysteria faketcp transport is not implemented; use protocol udp or wechat-video";

use crate::{
    inbox::{self, Inbox},
    reassembly::Reassembly,
    slots::{Counted, Slots},
};
use crate::{resolve_target, BoxStream, Outbound, PacketConn, Resolver, SessionControl};

const PROTOCOL_VERSION: u8 = 3;
const MAX_SESSIONS: usize = 32;
const REASSEMBLY_BUDGET: usize = 128 * 1024;
const MAX_FRAGMENTS: u8 = 16;
const FRAG_WAIT: Duration = Duration::from_secs(3);
const PENDING_PER_SESSION: usize = 4;
/// 服务端消息（ServerHello / 响应）里的文字上限。
const MAX_MESSAGE: usize = 4096;
const MAX_UDP_PAYLOAD: usize = 65_000;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

pub struct HysteriaOutbound {
    name: String,
    spec: HysteriaSpec,
    resolver: Arc<dyn Resolver>,
    quic: Arc<QuicClient>,
    rate: Arc<AtomicU64>,
    auth: std::sync::Mutex<Option<Authed>>,
    /// 认证单飞锁：同一时刻只有一个 Flow 做握手往返。
    auth_flight: tokio::sync::Mutex<()>,
    streams: Slots,
}

struct Authed {
    id: usize,
    /// 控制流：保持打开。
    _control: (quinn::SendStream, quinn::RecvStream),
    hub: Arc<UdpHub>,
}

/// 首控制流不可重试；仅认证单飞锁持有者负责失败/取消时关闭本次连接。
struct AuthGuard(Option<quinn::Connection>);

impl Drop for AuthGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.0.take() {
            if conn.close_reason().is_none() {
                conn.close(2u32.into(), b"authentication incomplete");
            }
        }
    }
}

type SessionInbox = Arc<Inbox<(Vec<u8>, TargetAddr)>>;

struct UdpHub {
    sessions: Mutex<HashMap<u32, SessionInbox>>,
    reassembly: Mutex<Reassembly<u32, TargetAddr>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// 名额随读取任务结束归还（abort 尚未被调度时也计数）。
    keepers: Slots,
}

impl Drop for UdpHub {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }
}

impl HysteriaOutbound {
    pub fn new(
        name: String,
        spec: HysteriaSpec,
        resolver: Arc<dyn Resolver>,
        datagrams: Arc<dyn oryn_udp::DatagramFactory>,
    ) -> Arc<Self> {
        let rate = Arc::new(AtomicU64::new(spec.up_bps));
        let hop = spec.ports.as_ref().map(|ports| Hop {
            ranges: ports.ranges.clone(),
            count: ports.count,
            min: Duration::from_secs(spec.hop_min_secs),
            max: Duration::from_secs(spec.hop_max_secs),
        });
        let obfs = if spec.protocol == "wechat-video" {
            Some(Obfs::WechatVideo {
                key: spec.obfs.as_ref().map(|pw| pw.as_bytes().to_vec()),
                sequence: Arc::new(std::sync::atomic::AtomicU32::new(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos()
                        & 0xffff,
                )),
            })
        } else {
            spec.obfs
                .as_ref()
                .map(|pw| Obfs::XPlus(pw.as_bytes().to_vec()))
        };
        let quic = QuicClient::new(QuicParams {
            datagrams,
            alpn: spec
                .tls
                .alpn
                .iter()
                .map(|a| a.as_bytes().to_vec())
                .collect(),
            skip_verify: spec.tls.skip_cert_verify,
            fingerprint: spec.tls.fingerprint,
            disable_sni: false,
            congestion: Congestion::Bbr,
            brutal_rate: Some(rate.clone()),
            obfs,
            hop,
            rendezvous: None,
            zero_rtt: false,
            // 与官方客户端一致：服务端空闲超时（默认 30 s）前保活，长连接上的流不会因空闲被拆
            keep_alive: Some(oryn_quic::KEEP_ALIVE),
        });
        Arc::new(Self {
            name,
            spec,
            resolver,
            quic,
            rate,
            auth: std::sync::Mutex::new(None),
            auth_flight: tokio::sync::Mutex::new(()),
            streams: Slots::default(),
        })
    }

    async fn peer(&self) -> io::Result<(IpAddr, u16, String)> {
        if self.spec.protocol == "faketcp" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                FAKETCP_UNSUPPORTED,
            ));
        }
        let addrs = resolve_target(self.resolver.as_ref(), &self.spec.server).await?;
        let addr = *addrs
            .first()
            .ok_or_else(|| io::Error::other("cannot resolve hysteria server"))?;
        let name = self
            .spec
            .tls
            .sni
            .clone()
            .unwrap_or_else(|| match &self.spec.server {
                TargetAddr::Domain(host, _) => host.clone(),
                TargetAddr::Ip(ip) => ip.ip().to_string(),
            });
        Ok((addr.ip(), addr.port(), name))
    }

    /// 已认证的连接与它的 UDP 分发器。
    async fn ready(&self) -> io::Result<(quinn::Connection, Arc<UdpHub>)> {
        let (ip, port, name) = self.peer().await?;
        let conn = self.quic.connection(ip, &name, port).await?;
        let cached = |auth: &std::sync::Mutex<Option<Authed>>| {
            auth.lock()
                .unwrap()
                .as_ref()
                .filter(|a| a.id == conn.stable_id() && conn.close_reason().is_none())
                .map(|a| a.hub.clone())
        };
        // 缓存命中不排队：网络往返只在单飞锁内做，已认证连接上的新 Flow 不受慢握手影响
        if let Some(hub) = cached(&self.auth) {
            return Ok((conn, hub));
        }
        let _single = self.auth_flight.lock().await;
        if let Some(hub) = cached(&self.auth) {
            return Ok((conn, hub));
        }
        if let Some(reason) = conn.close_reason() {
            return Err(io::Error::other(reason));
        }
        let mut guard = AuthGuard(Some(conn.clone()));
        let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;
        let mut hello = vec![PROTOCOL_VERSION];
        hello.extend_from_slice(&self.spec.up_bps.to_be_bytes());
        hello.extend_from_slice(&self.spec.down_bps.to_be_bytes());
        hello.extend_from_slice(&(self.spec.auth.len() as u16).to_be_bytes());
        hello.extend_from_slice(&self.spec.auth);
        send.write_all(&hello).await.map_err(io::Error::other)?;
        let ok = recv.read_u8().await.map_err(io::Error::other)? == 1;
        let _server_send = recv.read_u64().await.map_err(io::Error::other)?;
        let server_recv = recv.read_u64().await.map_err(io::Error::other)?;
        let message = read_message(&mut recv).await?;
        if !ok {
            conn.close(2u32.into(), b"auth failed");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "hysteria authentication failed: {}",
                    String::from_utf8_lossy(&message)
                ),
            ));
        }
        // 发送速率不超过服务端的接收速率
        if server_recv > 0 {
            self.rate
                .store(server_recv.min(self.spec.up_bps), Ordering::Relaxed);
        }
        let hub = Arc::new(UdpHub {
            sessions: Mutex::new(HashMap::new()),
            reassembly: Mutex::new(Reassembly::new(
                REASSEMBLY_BUDGET,
                PENDING_PER_SESSION,
                MAX_FRAGMENTS,
                FRAG_WAIT,
            )),
            task: Mutex::new(None),
            keepers: Slots::default(),
        });
        if self.spec.udp {
            let reader = Arc::downgrade(&hub);
            let conn = conn.clone();
            let task = tokio::spawn(async move {
                while let Ok(datagram) = conn.read_datagram().await {
                    let Some(hub) = reader.upgrade() else { break };
                    hub.ingest(&datagram);
                }
                // QUIC 连接已断：让所有会话立刻结束，而不是等上层空闲超时
                if let Some(hub) = reader.upgrade() {
                    for inbox in hub.sessions.lock().unwrap().values() {
                        inbox.close();
                    }
                }
            });
            *hub.task.lock().unwrap() = Some(task);
        }
        *self.auth.lock().unwrap() = Some(Authed {
            id: conn.stable_id(),
            _control: (send, recv),
            hub: hub.clone(),
        });
        guard.0 = None;
        Ok((conn, hub))
    }
}

async fn read_message(recv: &mut quinn::RecvStream) -> io::Result<Vec<u8>> {
    let len = recv.read_u16().await.map_err(io::Error::other)? as usize;
    if len > MAX_MESSAGE {
        return Err(invalid("hysteria message too long"));
    }
    let mut message = vec![0; len];
    recv.read_exact(&mut message)
        .await
        .map_err(io::Error::other)?;
    Ok(message)
}

/// 地址的主机部分（IP 不带方括号）与端口。
fn host_and_port(target: &TargetAddr) -> (String, u16) {
    match target {
        TargetAddr::Ip(addr) => (addr.ip().to_string(), addr.port()),
        TargetAddr::Domain(host, port) => (host.clone(), *port),
    }
}

fn request(udp: bool, target: &TargetAddr) -> io::Result<Vec<u8>> {
    let (host, port) = host_and_port(target);
    if host.len() > u16::MAX as usize {
        return Err(invalid("hysteria host too long"));
    }
    let mut out = vec![u8::from(udp)];
    out.extend_from_slice(&(host.len() as u16).to_be_bytes());
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

async fn read_response(recv: &mut quinn::RecvStream) -> io::Result<u32> {
    let ok = recv.read_u8().await.map_err(io::Error::other)? == 1;
    let session = recv.read_u32().await.map_err(io::Error::other)?;
    let message = read_message(recv).await?;
    if !ok {
        return Err(io::Error::other(format!(
            "hysteria remote error: {}",
            String::from_utf8_lossy(&message)
        )));
    }
    Ok(session)
}

#[async_trait]
impl Outbound for HysteriaOutbound {
    fn tag(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "hysteria"
    }
    fn session_control(&self) -> Option<Arc<dyn SessionControl>> {
        Some(Arc::new(crate::QuicControl(self.quic.clone())))
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let slot = self
            .streams
            .acquire(MAX_BIDI)
            .ok_or_else(|| io::Error::other("hysteria stream limit reached"))?;
        let (conn, _) = self.ready().await?;
        let (send, recv) = conn.open_bi().await.map_err(io::Error::other)?;
        let stream = TcpStream {
            send,
            recv,
            request: Some(request(false, target)?),
            first_written: false,
            response: Response::Pending,
        };
        Ok(Counted::boxed(Box::new(stream), slot))
    }

    async fn bind_udp(&self, first: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.spec.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hysteria udp is disabled",
            ));
        }
        let (conn, hub) = self.ready().await?;
        if conn.max_datagram_size().is_none() {
            return Err(io::Error::other(
                "hysteria server does not support datagrams",
            ));
        }
        if hub.sessions.lock().unwrap().len() >= MAX_SESSIONS {
            return Err(io::Error::other("hysteria udp session limit reached"));
        }
        let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;
        send.write_all(&request(true, first)?)
            .await
            .map_err(io::Error::other)?;
        let id = read_response(&mut recv).await?;
        let inbox = Arc::new(Inbox::with_bytes(
            inbox::SESSION_PACKETS,
            inbox::SESSION_BYTES,
        ));
        {
            let mut sessions = hub.sessions.lock().unwrap();
            if sessions.len() >= MAX_SESSIONS {
                return Err(io::Error::other("hysteria udp session limit reached"));
            }
            if sessions.contains_key(&id) {
                return Err(invalid("hysteria duplicate udp session id"));
            }
            sessions.insert(id, inbox.clone());
        }
        Ok(Box::new(HyPacket::new(id, conn, hub, inbox, send, recv)?))
    }
}

enum Response {
    Pending,
    Reading([u8; 7], usize),
    Message(usize),
    Done,
}

/// TCP 流：请求随第一次写出，读取前先读掉响应。
struct TcpStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// 还没发出去的请求首部（第一次写入时加上第一段数据）。
    request: Option<Vec<u8>>,
    first_written: bool,
    response: Response,
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // 服务端先说话的应用：没写过就先把请求发出去
        this.first_written = true;
        ready!(this.poll_pending(cx))?;
        loop {
            match &mut this.response {
                Response::Done => {
                    return Pin::new(&mut this.recv)
                        .poll_read(cx, out)
                        .map_err(io::Error::other)
                }
                Response::Pending => this.response = Response::Reading([0; 7], 0),
                Response::Reading(head, have) => {
                    while *have < 7 {
                        let mut rb = ReadBuf::new(&mut head[*have..]);
                        ready!(Pin::new(&mut this.recv).poll_read(cx, &mut rb))
                            .map_err(io::Error::other)?;
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        *have += n;
                    }
                    if head[0] != 1 {
                        return Poll::Ready(Err(io::Error::other(
                            "hysteria remote rejected the connection",
                        )));
                    }
                    let len = u16::from_be_bytes([head[5], head[6]]) as usize;
                    if len > MAX_MESSAGE {
                        return Poll::Ready(Err(invalid("hysteria message too long")));
                    }
                    this.response = if len == 0 {
                        Response::Done
                    } else {
                        Response::Message(len)
                    };
                }
                Response::Message(left) => {
                    let mut skip = [0u8; 256];
                    let take = (*left).min(skip.len());
                    let mut rb = ReadBuf::new(&mut skip[..take]);
                    ready!(Pin::new(&mut this.recv).poll_read(cx, &mut rb))
                        .map_err(io::Error::other)?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *left -= n;
                    if *left == 0 {
                        this.response = Response::Done;
                    }
                }
            }
        }
    }
}

impl TcpStream {
    /// 写完还没发出去的请求（首部与第一段数据）。
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(pending) = self.request.as_mut() {
            if pending.is_empty() {
                self.request = None;
                break;
            }
            let n = ready!(Pin::new(&mut self.send).poll_write(cx, pending))
                .map_err(io::Error::other)?;
            pending.drain(..n);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if let Some(req) = this.request.as_mut() {
            if !this.first_written {
                // 请求首部与第一段数据合在一起写出；之后的写入要等它发完（缓冲只有这一段）
                this.first_written = true;
                let take = buf.len().min(16 * 1024);
                req.extend_from_slice(&buf[..take]);
                if let Poll::Ready(Err(e)) = this.poll_pending(cx) {
                    return Poll::Ready(Err(e));
                }
                return Poll::Ready(Ok(take));
            }
        }
        ready!(this.poll_pending(cx))?;
        Pin::new(&mut this.send)
            .poll_write(cx, buf)
            .map_err(io::Error::other)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.first_written = true;
        ready!(this.poll_pending(cx))?;
        Pin::new(&mut this.send)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::other)
    }
}

impl UdpHub {
    fn close_session(&self, id: u32, rx: &SessionInbox) {
        let mut sessions = self.sessions.lock().unwrap();
        rx.close();
        if sessions
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, rx))
        {
            sessions.remove(&id);
        }
    }

    fn ingest(&self, datagram: &[u8]) {
        let Some((session, packet, frag, total, addr, payload)) = parse_datagram(datagram) else {
            return;
        };
        // 查询与投递共用会话锁，避免关闭/ID 复用夹在重组过程中。
        let sessions = self.sessions.lock().unwrap();
        let Some(tx) = sessions.get(&session) else {
            return;
        };
        let done = self.reassembly.lock().unwrap().insert(
            session,
            packet,
            frag,
            total,
            Some(addr),
            payload,
        );
        if let Some((body, addr)) = done {
            let bytes = body.len();
            let _ = tx.try_send_sized((body, addr), bytes);
        }
    }
}

fn parse_datagram(data: &[u8]) -> Option<(u32, u16, u8, u8, TargetAddr, Vec<u8>)> {
    let session = u32::from_be_bytes(data.get(0..4)?.try_into().ok()?);
    let host_len = u16::from_be_bytes(data.get(4..6)?.try_into().ok()?) as usize;
    let host = std::str::from_utf8(data.get(6..6 + host_len)?).ok()?;
    let rest = data.get(6 + host_len..)?;
    let port = u16::from_be_bytes(rest.get(0..2)?.try_into().ok()?);
    let packet = u16::from_be_bytes(rest.get(2..4)?.try_into().ok()?);
    let frag = *rest.get(4)?;
    let total = *rest.get(5)?;
    let len = u16::from_be_bytes(rest.get(6..8)?.try_into().ok()?) as usize;
    let payload = rest.get(8..8 + len)?.to_vec();
    let addr = match host.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::Ip(std::net::SocketAddr::new(ip, port)),
        // 只有域名才分配字符串；IP 地址（回包的常态）直接解析
        Err(_) => TargetAddr::Domain(host.to_string(), port),
    };
    Some((session, packet, frag, total, addr, payload))
}

struct HyPacket {
    id: u32,
    packet: AtomicU16,
    conn: quinn::Connection,
    hub: Arc<UdpHub>,
    rx: SessionInbox,
    /// 每关联至多一个读取任务；Drop 撤销，不另起清理任务。
    keeper: tokio::task::JoinHandle<()>,
}

impl HyPacket {
    fn new(
        id: u32,
        conn: quinn::Connection,
        hub: Arc<UdpHub>,
        rx: SessionInbox,
        send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> io::Result<Self> {
        let Some(slot) = hub.keepers.acquire(MAX_SESSIONS) else {
            hub.close_session(id, &rx);
            return Err(io::Error::other("hysteria udp keeper limit reached"));
        };
        let weak = Arc::downgrade(&hub);
        let inbox = rx.clone();
        let keeper = tokio::spawn(async move {
            let _slot = slot;
            let _send = send;
            let mut buffer = [0; 1024];
            while let Ok(Some(_)) = recv.read(&mut buffer).await {}
            if let Some(hub) = weak.upgrade() {
                hub.close_session(id, &inbox);
            } else {
                inbox.close();
            }
        });
        Ok(Self {
            id,
            packet: AtomicU16::new(1),
            conn,
            hub,
            rx,
            keeper,
        })
    }
}

impl Drop for HyPacket {
    fn drop(&mut self) {
        self.keeper.abort();
        self.hub.close_session(self.id, &self.rx);
    }
}

#[async_trait]
impl PacketConn for HyPacket {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        if !self
            .hub
            .sessions
            .lock()
            .unwrap()
            .get(&self.id)
            .is_some_and(|rx| Arc::ptr_eq(rx, &self.rx))
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "hysteria udp closed",
            ));
        }
        if buf.len() > MAX_UDP_PAYLOAD {
            return Err(io::Error::other("hysteria udp packet too large"));
        }
        let (host, port) = host_and_port(target);
        let max = self.conn.max_datagram_size().unwrap_or(1200);
        let header = 14 + host.len();
        let room = max.saturating_sub(header).max(1);
        let pieces: Vec<&[u8]> = if buf.is_empty() {
            vec![buf]
        } else {
            buf.chunks(room).collect()
        };
        if pieces.len() > MAX_FRAGMENTS as usize {
            return Err(io::Error::other("hysteria udp packet is too large"));
        }
        let total = pieces.len() as u8;
        let packet = if total == 1 {
            0
        } else {
            loop {
                let id = self.packet.fetch_add(1, Ordering::Relaxed);
                if id != 0 {
                    break id;
                }
            }
        };
        for (index, piece) in pieces.iter().enumerate() {
            let mut frame = Vec::with_capacity(header + piece.len());
            frame.extend_from_slice(&self.id.to_be_bytes());
            frame.extend_from_slice(&(host.len() as u16).to_be_bytes());
            frame.extend_from_slice(host.as_bytes());
            frame.extend_from_slice(&port.to_be_bytes());
            frame.extend_from_slice(&packet.to_be_bytes());
            frame.push(index as u8);
            frame.push(total);
            frame.extend_from_slice(&(piece.len() as u16).to_be_bytes());
            frame.extend_from_slice(piece);
            self.conn
                .send_datagram(Bytes::from(frame))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let Some((payload, addr)) = self.rx.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "hysteria udp closed",
            ));
        };
        let n = crate::copy_datagram(&payload, buf, "Hysteria");
        Ok((n, addr))
    }
}

#[cfg(test)]
#[path = "hysteria_auth_tests.rs"]
mod auth_tests;

#[cfg(test)]
#[path = "hysteria_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_datagram_formats() {
        let r = request(false, &TargetAddr::Domain("a.test".into(), 443)).unwrap();
        assert_eq!(r, [0, 0, 6, b'a', b'.', b't', b'e', b's', b't', 1, 187]);
        let r = request(true, &TargetAddr::Ip("[::1]:53".parse().unwrap())).unwrap();
        assert_eq!(&r[..6], &[1, 0, 3, b':', b':', b'1']);
        // 数据报：会话 7、主机 1.2.3.4、端口 53、包 9、第 1/2 片、数据 "hi"
        let mut d = 7u32.to_be_bytes().to_vec();
        d.extend_from_slice(&7u16.to_be_bytes());
        d.extend_from_slice(b"1.2.3.4");
        d.extend_from_slice(&53u16.to_be_bytes());
        d.extend_from_slice(&9u16.to_be_bytes());
        d.extend_from_slice(&[1, 2]);
        d.extend_from_slice(&2u16.to_be_bytes());
        d.extend_from_slice(b"hi");
        let (s, p, f, t, a, payload) = parse_datagram(&d).unwrap();
        assert_eq!((s, p, f, t), (7, 9, 1, 2));
        assert_eq!(a, TargetAddr::Ip("1.2.3.4:53".parse().unwrap()));
        assert_eq!(payload, b"hi");
        assert!(parse_datagram(&d[..d.len() - 1]).is_none());
    }

    struct NoDns;
    #[async_trait]
    impl Resolver for NoDns {
        async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
            Ok(vec![])
        }
    }

    /// FakeTCP 在所有平台都拒绝，文案不能再声称只是 iOS 限制（OrynCore#16）。
    #[tokio::test]
    async fn faketcp_rejected_as_unimplemented() {
        let outbound = HysteriaOutbound::new(
            "test".into(),
            HysteriaSpec {
                server: TargetAddr::Ip("127.0.0.1:443".parse().unwrap()),
                protocol: "faketcp".into(),
                ports: None,
                auth: vec![],
                up_bps: 1_000_000,
                down_bps: 1_000_000,
                obfs: None,
                tls: oryn_config::TlsSpec {
                    skip_cert_verify: true,
                    alpn: vec!["hysteria".into()],
                    sni: None,
                    fingerprint: None,
                    client_fingerprint: None,
                    reality: None,
                    ech: None,
                },
                hop_min_secs: 10,
                hop_max_secs: 20,
                udp: false,
            },
            Arc::new(NoDns),
            Arc::new(oryn_udp::UdpFactory),
        );
        let err = outbound.peer().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert_eq!(err.to_string(), FAKETCP_UNSUPPORTED);
        assert!(!err.to_string().contains("iOS"));
    }
}
