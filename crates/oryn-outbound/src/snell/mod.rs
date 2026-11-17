//! Snell 出站：v4（兼容 Surge 的 v4 / v5 服务端）与 v6（default / unshaped / unsafe-raw 三种模式）。
//!
//! 移植自 sagernet/sing-snell（commit 20f2eaec77c328b7eb7e937fa9c894ee9c8a0057）的客户端部分：
//! snell.go、crypto.go、request.go、address.go、internal/reuse/reuse.go、snellv4/{client,packet,reuse}.go、
//! snellv6/{client,packet,reuse,handshake}.go。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! v4 的 `obfs-opts`（http / tls）就是 simple-obfs 的线格式，与 mihomo 一样复用 `oryn-transport` 的实现。
//! v1–v3 没有可用的独立对端（官方 snell-server 闭源），不实现。
//!
//! 请求：版本 1、命令（TCP 5 / UDP 6）、客户端 ID 长度与内容、TCP 目标（长度前缀主机名 + 端口）。
//! 回复是对端第一条记录的首字节：0 隧道（其后即数据）、2 错误（错误码 + 消息）。
//! 半关闭写一个零长记录；`reuse` 时双方都收到零长记录后，这条 TCP 回到连接池给下一个请求用。
mod udp_shared;
mod v4;
mod v6;

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use oryn_config::{SnellMode, SnellSpec, TargetAddr};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};

use crate::{BoxStream, Dialer, Outbound, PacketConn, Resolver};

pub(super) const HEADER_VERSION: u8 = 0x04;
pub(super) const HEADER_PLAIN: usize = 7;
pub(super) const TAG: usize = 16;
pub(super) const HEADER_CIPHER: usize = HEADER_PLAIN + TAG;
pub(super) const SALT: usize = 16;

const REQUEST_VERSION: u8 = 0x01;
const COMMAND_CONNECT_V2: u8 = 0x05;
const COMMAND_UDP: u8 = 0x06;
const REPLY_TUNNEL: u8 = 0x00;
const REPLY_ERROR: u8 = 0x02;
const UDP_FORWARD: u8 = 0x01;

/// 连接池：sing-snell 的 PoolSize / PoolMaxAge。
const POOL_SIZE: usize = 10;
/// 连接在收到回复前失败时，最多重放这么多已发出的明文（请求 + 数据）。
const REPLAY_LIMIT: usize = 64 * 1024;
/// 新建连接被服务端（或其防火墙）在收到回复前丢弃时，最多换新连接重试的次数。
/// 云服务器常按「每秒新建连接数」限速（实测约每秒 10 个、少量突发），超出的连接会被直接关闭；
/// 指数退避让令牌补充，一次 30 多路的并发测速在约 2 秒内全部排上。
const MAX_RETRIES: u8 = 4;
/// 第一次重试前的退避；之后每次翻倍，再加 0–50% 的随机抖动，避免一批连接同时重试。
const RETRY_BACKOFF: Duration = Duration::from_millis(150);
const POOL_MAX_AGE: Duration = Duration::from_secs(180);
/// 本端关闭后为了复用而丢弃的剩余数据上限（WaitingDiscardLimit）。
const DRAIN_LIMIT: usize = 0x80001;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
/// 每次 `poll_write` 最多接收的明文。
const WRITE_CHUNK: usize = 32 * 1024;
const READ_CHUNK: usize = 16 * 1024;

pub(super) enum Frame {
    Data(Vec<u8>),
    Eof,
}

/// AES-128-GCM，nonce 为 12 字节小端计数器。
pub(super) struct Aead {
    key: LessSafeKey,
    nonce: [u8; 12],
}

impl Aead {
    pub(super) fn new(psk: &[u8], salt: &[u8]) -> io::Result<Self> {
        let key = derive_key(psk, salt)?;
        let key =
            UnboundKey::new(&AES_128_GCM, &key).map_err(|_| io::Error::other("snell: bad key"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            nonce: [0; 12],
        })
    }

    fn advance(&mut self) {
        for byte in self.nonce.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    pub(super) fn seal(&mut self, plain: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut data = plain.to_vec();
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(self.nonce),
                Aad::from(aad),
                &mut data,
            )
            .expect("AES-GCM seal");
        data.extend_from_slice(tag.as_ref());
        self.advance();
        data
    }

    pub(super) fn open(&mut self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, ()> {
        let mut data = sealed.to_vec();
        let len = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(self.nonce),
                Aad::from(aad),
                &mut data,
            )
            .map_err(|_| ())?
            .len();
        data.truncate(len);
        self.advance();
        Ok(data)
    }
}

/// Argon2id(psk, salt, t=3, m=8 KiB, p=1) 取前 16 字节。
fn derive_key(psk: &[u8], salt: &[u8]) -> io::Result<[u8; 16]> {
    let params = argon2::Params::new(8, 3, 1, Some(32))
        .map_err(|_| io::Error::other("snell: argon2 params"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    let mut blocks = [argon2::Block::default(); 8];
    argon
        .hash_password_into_with_memory(psk, salt, &mut out, &mut blocks)
        .map_err(|_| io::Error::other("snell: argon2 failed"))?;
    let mut key = [0u8; 16];
    key.copy_from_slice(&out[..16]);
    Ok(key)
}

pub(super) fn random_salt() -> io::Result<[u8; SALT]> {
    let mut salt = [0u8; SALT];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| io::Error::other("system random source failed"))?;
    Ok(salt)
}

enum Tx {
    V4(v4::Writer),
    Shaped(v6::ShapedWriter),
    Unshaped(v6::UnshapedWriter),
    Raw,
}

impl Tx {
    fn stream(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Tx::V4(w) => w.stream(data, out)?,
            Tx::Shaped(w) => w.stream(data, out),
            Tx::Unshaped(w) => w.stream(data, out),
            Tx::Raw => {
                for chunk in data.chunks(v6::MAX_PAYLOAD) {
                    v6::raw_record(chunk, out);
                }
            }
        }
        Ok(())
    }

    fn packet(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let max = if matches!(self, Tx::V4(_)) {
            v4::MAX_PAYLOAD
        } else {
            v6::MAX_PAYLOAD
        };
        if data.len() > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: payload length exceeds maximum",
            ));
        }
        match self {
            Tx::V4(w) => w.packet(data, out)?,
            Tx::Shaped(w) => w.packet(data, out),
            Tx::Unshaped(w) => w.packet(data, out),
            Tx::Raw => v6::raw_record(data, out),
        }
        Ok(())
    }

    fn zero(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Tx::V4(w) => w.zero(out)?,
            Tx::Shaped(w) => w.zero(out),
            Tx::Unshaped(w) => w.zero(out),
            Tx::Raw => v6::raw_record(&[], out),
        }
        Ok(())
    }
}

enum Rx {
    V4(v4::Reader),
    Shaped(v6::ShapedReader),
    Unshaped(v6::UnshapedReader),
    Raw,
}

impl Rx {
    fn parse(&mut self, psk: &[u8], buf: &mut BytesMut) -> io::Result<Option<Frame>> {
        match self {
            Rx::V4(r) => r.parse(psk, buf),
            Rx::Shaped(r) => r.parse(psk, buf),
            Rx::Unshaped(r) => r.parse(psk, buf),
            Rx::Raw => v6::raw_parse(buf),
        }
    }
}

struct Config {
    spec: SnellSpec,
    profile: Option<Arc<v6::Profile>>,
}

impl Config {
    fn psk(&self) -> &[u8] {
        self.spec.psk.as_bytes()
    }

    fn new_tx(&self) -> io::Result<Tx> {
        Ok(match (self.spec.version, self.spec.mode) {
            (4 | 5, _) => Tx::V4(v4::Writer::new(self.psk())?),
            (_, SnellMode::Default) => Tx::Shaped(v6::ShapedWriter::new(
                self.profile.clone().unwrap(),
                self.psk(),
            )?),
            (_, SnellMode::Unshaped) => Tx::Unshaped(v6::UnshapedWriter::new(self.psk())?),
            (_, SnellMode::UnsafeRaw) => Tx::Raw,
        })
    }

    fn new_rx(&self) -> Rx {
        match (self.spec.version, self.spec.mode) {
            (4 | 5, _) => Rx::V4(v4::Reader::new()),
            (_, SnellMode::Default) => {
                Rx::Shaped(v6::ShapedReader::new(self.profile.clone().unwrap()))
            }
            (_, SnellMode::Unshaped) => Rx::Unshaped(v6::UnshapedReader::new()),
            (_, SnellMode::UnsafeRaw) => Rx::Raw,
        }
    }

    fn request(&self, command: u8, target: Option<&TargetAddr>) -> io::Result<Vec<u8>> {
        let mut out = vec![REQUEST_VERSION, command, 0];
        if let Some(target) = target {
            let host = match target {
                TargetAddr::Domain(host, _) => host.clone(),
                TargetAddr::Ip(addr) => addr.ip().to_string(),
            };
            if host.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snell: host too long",
                ));
            }
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&target.port().to_be_bytes());
        }
        Ok(out)
    }
}

/// 回复记录：返回隧道后的剩余数据。
fn parse_reply(record: &[u8]) -> io::Result<Vec<u8>> {
    match record.first() {
        Some(&REPLY_TUNNEL) => Ok(record[1..].to_vec()),
        Some(&REPLY_ERROR) => {
            let code = record.get(1).copied().unwrap_or(0);
            let len = record.get(2).copied().unwrap_or(0) as usize;
            let message = record
                .get(3..3 + len)
                .map(String::from_utf8_lossy)
                .unwrap_or_default();
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("snell: server error {code}: {message}"),
            ))
        }
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("snell: unexpected reply opcode {other}"),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snell: empty reply",
        )),
    }
}

/// 一条到服务端的 TCP 及其记录层状态；`reuse` 时可以先后承载多个请求。
struct Session {
    io: BoxStream,
    tx: Option<Tx>,
    rx: Rx,
    inbuf: BytesMut,
}

/// 第 `attempt`（从 1 起）次重试前的等待：`RETRY_BACKOFF × 2^(attempt-1)` 加最多 50% 的随机抖动。
fn retry_delay(attempt: u8) -> Duration {
    let base = RETRY_BACKOFF * (1u32 << (attempt.saturating_sub(1).min(6)));
    let mut random = [0u8; 2];
    let jitter = if SystemRandom::new().fill(&mut random).is_ok() {
        base.mul_f64(0.5 * f64::from(u16::from_be_bytes(random)) / f64::from(u16::MAX))
    } else {
        Duration::ZERO
    };
    base + jitter
}

fn no_reply() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "snell: no reply")
}

/// 空闲的池内连接必须“读不到任何东西”：EOF、错误，或服务端空闲时发来的数据都说明它不能再用。
fn session_alive(session: &mut Session) -> bool {
    if !session.inbuf.is_empty() {
        return false;
    }
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut byte = [0u8; 1];
    let mut buf = ReadBuf::new(&mut byte);
    matches!(
        Pin::new(&mut session.io).poll_read(&mut cx, &mut buf),
        Poll::Pending
    )
}

#[derive(Default)]
struct Pool {
    state: Mutex<PoolState>,
}

#[derive(Default)]
struct PoolState {
    sessions: VecDeque<(Session, Instant)>,
    // clear 后尚未退出的旧任务仍占名额，不能通过连续换网突破上限。
    waiting: usize,
    generation: tokio_util::sync::CancellationToken,
}

impl Pool {
    fn generation(&self) -> tokio_util::sync::CancellationToken {
        self.state.lock().unwrap().generation.clone()
    }

    fn take(&self) -> Option<Session> {
        let mut state = self.state.lock().unwrap();
        state
            .sessions
            .retain(|(_, since)| since.elapsed() <= POOL_MAX_AGE);
        state.sessions.pop_back().map(|(session, _)| session)
    }

    fn reserve(
        self: &Arc<Self>,
        generation: tokio_util::sync::CancellationToken,
    ) -> Option<DrainSlot> {
        let mut state = self.state.lock().unwrap();
        state
            .sessions
            .retain(|(_, since)| since.elapsed() <= POOL_MAX_AGE);
        if generation.is_cancelled() || state.sessions.len() + state.waiting >= POOL_SIZE {
            return None;
        }
        state.waiting += 1;
        Some(DrainSlot {
            pool: self.clone(),
            generation,
            waiting: true,
        })
    }

    fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        state.generation.cancel();
        state.generation = tokio_util::sync::CancellationToken::new();
        state.sessions.clear();
    }
}

/// spawn 前取得名额，连未被 poll 就取消的任务也会退账。
struct DrainSlot {
    pool: Arc<Pool>,
    generation: tokio_util::sync::CancellationToken,
    waiting: bool,
}

impl DrainSlot {
    fn put(mut self, mut session: Session) {
        if session.inbuf.is_empty() {
            session.inbuf = BytesMut::new();
        }
        let mut state = self.pool.state.lock().unwrap();
        state.waiting -= 1;
        self.waiting = false;
        // 与 clear 共用锁，防止检查代际后、入池前发生撤销。
        if !self.generation.is_cancelled() {
            state.sessions.push_back((session, Instant::now()));
        }
    }
}

impl Drop for DrainSlot {
    fn drop(&mut self) {
        if self.waiting {
            self.pool.state.lock().unwrap().waiting -= 1;
        }
    }
}

pub(crate) struct SnellOutbound {
    name: String,
    cfg: Arc<Config>,
    dialer: Arc<dyn Dialer>,
    pool: Option<Arc<Pool>>,
    /// 解析 UDP 目标域名（完整 DNS 流程）：共用 UDP 连接按 IP 路由回包。
    resolver: Arc<dyn Resolver>,
    udp_hub: Arc<udp_shared::UdpHub>,
}

impl SnellOutbound {
    pub(crate) fn new(
        name: String,
        spec: SnellSpec,
        dialer: Arc<dyn Dialer>,
        resolver: Arc<dyn Resolver>,
    ) -> Arc<Self> {
        let profile = (spec.version == 6 && spec.mode == SnellMode::Default)
            .then(|| Arc::new(v6::Profile::new(spec.psk.as_bytes())));
        let pool = spec.reuse.then(|| Arc::new(Pool::default()));
        Arc::new(Self {
            name,
            cfg: Arc::new(Config { spec, profile }),
            dialer,
            pool,
            resolver,
            udp_hub: Arc::new(udp_shared::UdpHub::default()),
        })
    }

    /// UDP 目标的 IP 地址：域名用完整 DNS 流程解析，优先 IPv4；解析失败返回 None。
    async fn udp_target_addr(&self, target: &TargetAddr) -> Option<std::net::SocketAddr> {
        match target {
            TargetAddr::Ip(addr) => Some(std::net::SocketAddr::new(
                addr.ip().to_canonical(),
                addr.port(),
            )),
            TargetAddr::Domain(host, port) => {
                let ips = self.resolver.resolve(host).await.ok()?;
                let ip = ips
                    .iter()
                    .find(|ip| ip.is_ipv4())
                    .or_else(|| ips.first())
                    .copied()?;
                Some(std::net::SocketAddr::new(ip.to_canonical(), *port))
            }
        }
    }

    /// 新建一条 Snell UDP 连接：发 UDP 请求并读到回复。返回会话、写端状态和回复之后已读到的记录。
    async fn open_udp(&self) -> io::Result<(Session, Tx, VecDeque<Vec<u8>>)> {
        let mut session = self.dial().await?;
        let mut tx = self.cfg.new_tx()?;
        let mut out = Vec::new();
        tx.stream(&self.cfg.request(COMMAND_UDP, None)?, &mut out)?;
        session.io.write_all(&out).await?;
        session.io.flush().await?;
        let mut queue = VecDeque::new();
        loop {
            match session.rx.parse(self.cfg.psk(), &mut session.inbuf)? {
                Some(Frame::Data(record)) => {
                    let rest = parse_reply(&record)?;
                    if !rest.is_empty() {
                        queue.push_back(rest);
                    }
                    break;
                }
                Some(Frame::Eof) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell: no udp reply",
                    ))
                }
                None => {
                    let mut tmp = vec![0u8; READ_CHUNK];
                    let n = session.io.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell: no udp reply",
                        ));
                    }
                    session.inbuf.extend_from_slice(&tmp[..n]);
                }
            }
        }
        Ok((session, tx, queue))
    }

    /// 把会话挂到共用 UDP 连接上；池满或地址冲突时返回 None，由调用方回退独占连接。
    async fn bind_shared_udp(
        &self,
        addr: std::net::SocketAddr,
    ) -> io::Result<Option<udp_shared::SharedPacket>> {
        if let Some(session) = self.udp_hub.try_bind(addr) {
            return Ok(Some(session));
        }
        let _creating = self.udp_hub.creation_lock().await;
        // 等锁期间可能已有别的会话建好了连接
        if let Some(session) = self.udp_hub.try_bind(addr) {
            return Ok(Some(session));
        }
        if !self.udp_hub.can_grow() {
            return Ok(None);
        }
        let (session, tx, queue) = self.open_udp().await?;
        let conn = udp_shared::SharedConn::start(
            self.cfg.clone(),
            session.io,
            tx,
            session.rx,
            session.inbuf,
            queue,
        );
        log::debug!("snell {}: opened a shared UDP connection", self.name);
        Ok(self.udp_hub.add(conn, addr))
    }

    /// 从池里取一条仍然存活的连接；服务端已经关闭或重置的连接直接丢弃。
    /// 服务端在零长记录之后常常立刻关闭 TCP，而连接要等读到零长记录才放回池，
    /// 所以池里的连接可能在放回后不久就已经失效，取出前必须探测。
    fn take_live_session(&self) -> Option<Session> {
        let pool = self.pool.as_ref()?;
        let mut discarded = 0usize;
        while let Some(mut session) = pool.take() {
            if session_alive(&mut session) {
                log::debug!(
                    "snell {}: reusing a pooled connection ({discarded} dead ones discarded)",
                    self.name
                );
                return Some(session);
            }
            discarded += 1;
        }
        if discarded > 0 {
            log::debug!(
                "snell {}: discarded {discarded} dead pooled connections",
                self.name
            );
        }
        None
    }

    async fn dial(&self) -> io::Result<Session> {
        dial_session(self.cfg.clone(), self.dialer.clone()).await
    }
}

async fn dial_session(cfg: Arc<Config>, dialer: Arc<dyn Dialer>) -> io::Result<Session> {
    let started = Instant::now();
    let stream = dialer.dial_tcp(&cfg.spec.server).await?;
    log::debug!(
        "snell: TCP to node established in {} ms",
        started.elapsed().as_millis()
    );
    let io: BoxStream = match &cfg.spec.obfs {
        None => stream,
        Some(obfs) if obfs.tls => {
            let host = if obfs.host.is_empty() {
                "cloudfront.net"
            } else {
                obfs.host.as_str()
            };
            Box::new(oryn_transport::TlsObfs::new(stream, host))
        }
        Some(obfs) => {
            let host = if obfs.host.is_empty() {
                "bing.com"
            } else {
                obfs.host.as_str()
            };
            Box::new(oryn_transport::HttpObfs::new(
                stream,
                host,
                cfg.spec.server.port(),
            ))
        }
    };
    Ok(Session {
        io,
        tx: None,
        rx: cfg.new_rx(),
        inbuf: BytesMut::new(),
    })
}

#[async_trait]
impl Outbound for SnellOutbound {
    fn tag(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "snell"
    }
    fn session_control(&self) -> Option<Arc<dyn crate::SessionControl>> {
        Some(Arc::new(PoolControl {
            pool: self.pool.clone(),
            udp: self.udp_hub.clone(),
        }))
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        // 拨号前记录代际：换网期间完成的旧拨号也不能回到新池。
        let pool_generation = self.pool.as_ref().map(|pool| pool.generation());
        let request = self.cfg.request(COMMAND_CONNECT_V2, Some(target))?;
        let (session, reused) = match self.take_live_session() {
            Some(session) => (session, true),
            None => {
                log::debug!("snell {}: dialing a new connection", self.name);
                (self.dial().await?, false)
            }
        };
        Ok(Box::new(SnellStream {
            name: self.name.clone(),
            cfg: self.cfg.clone(),
            dialer: self.dialer.clone(),
            reused,
            replay: Some(Vec::new()),
            retries: 0,
            redial: None,
            session: Some(session),
            pool: self.pool.as_ref().map(Arc::downgrade),
            pool_generation,
            request: Some(request),
            reply_read: false,
            read_eof: false,
            zero_sent: false,
            broken: false,
            plain: Vec::new(),
            plain_pos: 0,
            out: Vec::new(),
            out_pos: 0,
        }))
    }
    async fn bind_udp(&self, target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.cfg.spec.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "snell udp is disabled",
            ));
        }
        // 共用连接：目标解析成 IP 后挂到少数几条 Snell UDP 连接上，避免每个会话占一条到节点的连接
        if let Some(addr) = self.udp_target_addr(target).await {
            if let Some(session) = self.bind_shared_udp(addr).await? {
                return Ok(Box::new(session));
            }
            log::debug!(
                "snell {}: shared UDP connections full or conflicting, using a dedicated one",
                self.name
            );
        }
        // 独占连接：先发 UDP 请求并读到回复，之后才能收发数据报（与 sing-snell 相同）
        let (session, tx, queue) = self.open_udp().await?;
        let (read, write) = tokio::io::split(session.io);
        Ok(Box::new(SnellPacket {
            cfg: self.cfg.clone(),
            write: tokio::sync::Mutex::new(PacketWriter::new(write, tx)),
            read: tokio::sync::Mutex::new(PacketReader {
                io: read,
                rx: session.rx,
                inbuf: session.inbuf,
                queue,
            }),
        }))
    }
}

/// 网络变化 / 唤醒后，池里的连接多半已经失效。
struct PoolControl {
    pool: Option<Arc<Pool>>,
    udp: Arc<udp_shared::UdpHub>,
}

impl PoolControl {
    fn clear(&self) {
        if let Some(pool) = &self.pool {
            pool.clear();
        }
        self.udp.clear();
    }
}

impl crate::SessionControl for PoolControl {
    fn on_network_changed(&self) {
        self.clear();
    }
    fn on_sleep(&self) {}
    fn on_wake(&self) {
        self.clear();
    }
}

type SessionFuture = Pin<Box<dyn std::future::Future<Output = io::Result<Session>> + Send>>;

struct SnellStream {
    name: String,
    cfg: Arc<Config>,
    dialer: Arc<dyn Dialer>,
    /// 连接来自池。服务端可能在放回池后不久关闭它（探测与使用之间有竞争窗口），
    /// 所以只有复用的连接才会在收到回复前失败时换新连接重放一次。
    reused: bool,
    /// 收到回复前交给记录层的明文；超过 `REPLAY_LIMIT` 后为 None，不再能重放。
    replay: Option<Vec<u8>>,
    /// 已经换过几次连接（复用失效的重放不计入，只统计新建连接被丢弃后的重试）。
    retries: u8,
    /// 正在新建的替换连接。
    redial: Option<SessionFuture>,
    session: Option<Session>,
    pool: Option<Weak<Pool>>,
    pool_generation: Option<tokio_util::sync::CancellationToken>,
    /// 还没发出的请求首部，与第一段数据合在一条记录里。
    request: Option<Vec<u8>>,
    reply_read: bool,
    read_eof: bool,
    zero_sent: bool,
    broken: bool,
    plain: Vec<u8>,
    plain_pos: usize,
    /// 已加密、尚未写完的字节；同时只有一批，保证缓冲有上限。
    out: Vec<u8>,
    out_pos: usize,
}

impl SnellStream {
    fn encode(&mut self, data: &[u8]) -> io::Result<()> {
        let plain = match self.request.take() {
            Some(mut request) => {
                request.extend_from_slice(data);
                std::borrow::Cow::Owned(request)
            }
            None => std::borrow::Cow::Borrowed(data),
        };
        if !self.reply_read {
            if let Some(replay) = self.replay.as_mut() {
                if replay.len() + plain.len() > REPLAY_LIMIT {
                    self.replay = None;
                } else {
                    replay.extend_from_slice(&plain);
                }
            }
        }
        let session = self.session.as_mut().expect("snell session");
        if session.tx.is_none() {
            session.tx = Some(self.cfg.new_tx()?);
        }
        session.tx.as_mut().unwrap().stream(&plain, &mut self.out)
    }

    /// 连接在收到回复前失败：换一条新连接，重放已发出的明文。
    ///
    /// - 复用来的连接：服务端多半已经关闭了它，任何错误都重放一次（不计入重试次数）。
    /// - 新建的连接：只有「服务端没回复就关闭 / 重置」才重试，最多 `MAX_RETRIES` 次，带退避和抖动；
    ///   这对应云服务器按新建连接速率限速、直接丢弃多余连接的情形，其它错误（超时、协议错误）不重试。
    ///
    /// `Ready(Ok)` 表示已经换好，调用方应重试刚才的操作；不满足条件时返回原错误。
    fn poll_recover(&mut self, cx: &mut Context<'_>, err: io::Error) -> Poll<io::Result<()>> {
        if self.redial.is_none() {
            let dropped = matches!(
                err.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
            );
            let allowed = !self.reply_read
                && self.replay.is_some()
                && (self.reused || (dropped && self.retries < MAX_RETRIES));
            if !allowed {
                self.broken = true;
                return Poll::Ready(Err(err));
            }
            let delay = if self.reused {
                Duration::ZERO
            } else {
                self.retries += 1;
                retry_delay(self.retries)
            };
            log::debug!(
                "snell {}: {} connection failed before reply ({err}); retrying on a new connection in {} ms",
                self.name,
                if self.reused { "reused" } else { "new" },
                delay.as_millis()
            );
            let (cfg, dialer) = (self.cfg.clone(), self.dialer.clone());
            self.redial = Some(Box::pin(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                dial_session(cfg, dialer).await
            }));
        }
        self.poll_redial(cx)
    }

    /// 推进替换连接；没有进行中的替换时立即返回 `Ready(Ok)`。
    fn poll_redial(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(redial) = self.redial.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let result = ready!(redial.as_mut().poll(cx));
        self.redial = None;
        // 只重放一次：新连接不是复用来的。
        self.reused = false;
        let mut session = match result {
            Ok(session) => session,
            Err(err) => {
                self.broken = true;
                return Poll::Ready(Err(err));
            }
        };
        self.out.clear();
        self.out_pos = 0;
        // 保留重放缓冲：这条新连接也可能在回复前失败，需要再次重放
        if let Some(replay) = self.replay.as_deref().filter(|r| !r.is_empty()) {
            let tx = session.tx.insert(self.cfg.new_tx()?);
            tx.stream(replay, &mut self.out)?;
            if self.zero_sent {
                tx.zero(&mut self.out)?;
            }
        }
        self.session = Some(session);
        self.broken = false;
        Poll::Ready(Ok(()))
    }

    fn poll_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_redial(cx))?;
        while self.out_pos < self.out.len() {
            let session = self.session.as_mut().expect("snell session");
            match ready!(Pin::new(&mut session.io).poll_write(cx, &self.out[self.out_pos..])) {
                Ok(0) => ready!(self.poll_recover(cx, io::ErrorKind::WriteZero.into()))?,
                Ok(n) => self.out_pos += n,
                Err(err) => ready!(self.poll_recover(cx, err))?,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// 写完待发数据并 flush 底层连接。连接在收到回复前失败时（包括只在 flush 时才暴露的错误）走恢复流程。
    fn poll_flush_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            ready!(self.poll_out(cx))?;
            let session = self.session.as_mut().expect("snell session");
            match ready!(Pin::new(&mut session.io).poll_flush(cx)) {
                Ok(()) => return Poll::Ready(Ok(())),
                // 恢复成功后回到循环顶部，把重放的明文写到新连接上
                Err(err) => ready!(self.poll_recover(cx, err))?,
            }
        }
    }

    /// 服务端先说话的应用：读之前先把请求发出去。
    fn send_request(&mut self) -> io::Result<()> {
        if self.request.is_some() {
            self.encode(&[])?;
        }
        Ok(())
    }
}

impl AsyncRead for SnellStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_redial(cx))?;
        this.send_request()?;
        if let Poll::Ready(Err(err)) = this.poll_out(cx) {
            return Poll::Ready(Err(err));
        }
        loop {
            if this.plain_pos < this.plain.len() {
                let n = buf.remaining().min(this.plain.len() - this.plain_pos);
                buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                return Poll::Ready(Ok(()));
            }
            let psk = this.cfg.spec.psk.as_bytes();
            let session = this.session.as_mut().expect("snell session");
            let parsed = session.rx.parse(psk, &mut session.inbuf);
            match parsed {
                Err(err) => {
                    this.broken = true;
                    return Poll::Ready(Err(err));
                }
                Ok(Some(Frame::Data(record))) => {
                    let data = if this.reply_read {
                        record
                    } else {
                        this.reply_read = true;
                        this.replay = None;
                        match parse_reply(&record) {
                            Ok(rest) => rest,
                            Err(err) => {
                                this.broken = true;
                                return Poll::Ready(Err(err));
                            }
                        }
                    };
                    this.plain = data;
                    this.plain_pos = 0;
                }
                Ok(Some(Frame::Eof)) => {
                    if !this.reply_read {
                        ready!(this.poll_recover(cx, no_reply()))?;
                        if let Poll::Ready(Err(err)) = this.poll_out(cx) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    this.read_eof = true;
                }
                Ok(None) => {
                    let mut tmp = [0u8; READ_CHUNK];
                    let mut rb = ReadBuf::new(&mut tmp);
                    let failure = match ready!(Pin::new(&mut session.io).poll_read(cx, &mut rb)) {
                        Err(err) => Some(err),
                        // 没有零长记录就断开：连接不能复用；还没收到回复则是错误
                        Ok(()) if rb.filled().is_empty() && !this.reply_read => Some(no_reply()),
                        Ok(()) if rb.filled().is_empty() => {
                            this.broken = true;
                            this.read_eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        Ok(()) => {
                            session.inbuf.extend_from_slice(rb.filled());
                            None
                        }
                    };
                    if let Some(err) = failure {
                        ready!(this.poll_recover(cx, err))?;
                        if let Poll::Ready(Err(err)) = this.poll_out(cx) {
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for SnellStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_out(cx))?;
        if this.zero_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let take = buf.len().min(WRITE_CHUNK);
        this.encode(&buf[..take])?;
        if let Poll::Ready(Err(err)) = this.poll_out(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush_io(cx)
    }

    /// 写零长记录（CloseWrite），不关 TCP：复用时这条连接还要用。
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.zero_sent {
            ready!(this.poll_out(cx))?;
            this.send_request()?;
            let session = this.session.as_mut().expect("snell session");
            session
                .tx
                .as_mut()
                .expect("snell writer")
                .zero(&mut this.out)?;
            this.zero_sent = true;
        }
        this.poll_flush_io(cx)
    }
}

impl Drop for SnellStream {
    fn drop(&mut self) {
        let Some(pool) = self.pool.as_ref().and_then(Weak::upgrade) else {
            return;
        };
        // 复用的前提：请求已发出、回复已读、记录层没出错
        if !self.reply_read || self.broken || self.request.is_some() {
            return;
        }
        let Some(mut session) = self.session.take() else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Some(slot) = self
            .pool_generation
            .take()
            .and_then(|generation| pool.reserve(generation))
        else {
            return;
        };
        let cfg = self.cfg.clone();
        let mut out = std::mem::take(&mut self.out);
        let out_pos = self.out_pos;
        let zero_sent = self.zero_sent;
        let read_eof = self.read_eof;
        handle.spawn(async move {
            let finish = async {
                let mut out = out.split_off(out_pos);
                if !zero_sent {
                    session
                        .tx
                        .as_mut()
                        .ok_or_else(|| io::Error::other("no writer"))?
                        .zero(&mut out)?;
                }
                session.io.write_all(&out).await?;
                session.io.flush().await?;
                // 等对端的零长记录，丢弃中间的数据（有上限）
                let mut discarded = 0usize;
                if !read_eof {
                    loop {
                        match session.rx.parse(cfg.psk(), &mut session.inbuf)? {
                            Some(Frame::Eof) => break,
                            Some(Frame::Data(data)) => {
                                discarded += data.len();
                                if discarded >= DRAIN_LIMIT {
                                    return Err(io::Error::other(
                                        "snell: too much data after close",
                                    ));
                                }
                            }
                            None => {
                                let mut tmp = vec![0u8; READ_CHUNK];
                                let n = session.io.read(&mut tmp).await?;
                                if n == 0 {
                                    return Err(io::ErrorKind::UnexpectedEof.into());
                                }
                                session.inbuf.extend_from_slice(&tmp[..n]);
                            }
                        }
                    }
                }
                Ok::<_, io::Error>(session)
            };
            tokio::select! {
                biased;
                _ = slot.generation.cancelled() => {}
                result = tokio::time::timeout(DRAIN_TIMEOUT, finish) => {
                    if let Ok(Ok(session)) = result {
                        slot.put(session);
                    }
                }
            }
        });
    }
}

struct PacketReader {
    io: ReadHalf<BoxStream>,
    rx: Rx,
    inbuf: BytesMut,
    queue: VecDeque<Vec<u8>>,
}

struct SnellPacket {
    cfg: Arc<Config>,
    write: tokio::sync::Mutex<PacketWriter>,
    read: tokio::sync::Mutex<PacketReader>,
}

/// 密文和偏移属于连接，不能随着单次发送 Future 被取消而丢失。
/// 最多保存一条记录；先补齐旧记录，再推进下一条的密码状态。
struct PacketWriter {
    io: WriteHalf<BoxStream>,
    tx: Tx,
    pending: Vec<u8>,
    pos: usize,
    broken: bool,
}

impl PacketWriter {
    fn new(io: WriteHalf<BoxStream>, tx: Tx) -> Self {
        Self {
            io,
            tx,
            pending: Vec::new(),
            pos: 0,
            broken: false,
        }
    }

    async fn flush_pending(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        while self.pos < self.pending.len() {
            // write 取消时不消费数据；成功后在下一次 await 前保存偏移。
            match self.io.write(&self.pending[self.pos..]).await {
                Ok(0) => {
                    self.broken = true;
                    return Err(io::ErrorKind::WriteZero.into());
                }
                Ok(n) => self.pos += n,
                Err(err) => {
                    self.broken = true;
                    return Err(err);
                }
            }
        }
        if let Err(err) = self.io.flush().await {
            self.broken = true;
            return Err(err);
        }
        self.pending.clear();
        self.pos = 0;
        Ok(())
    }

    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.broken {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.flush_pending().await?;
        match self.tx.packet(packet, &mut self.pending) {
            Ok(()) => {}
            // 超过记录上限的数据报在编码前被拒绝，沿用 UDP 丢弃语义（与 sing-snell 相同：
            // v4 空闲 31 秒后上限回落到首档，v6 只查 MAX_PAYLOAD）。
            Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
                log::debug!(
                    "snell: dropped {} byte UDP packet over record limit",
                    packet.len()
                );
                return Ok(());
            }
            Err(err) => {
                self.broken = true;
                return Err(err);
            }
        }
        self.flush_pending().await
    }
}

fn encode_udp_target(target: &TargetAddr, out: &mut Vec<u8>) -> io::Result<()> {
    match target {
        TargetAddr::Ip(addr) => {
            out.push(0x00);
            match addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    out.push(0x04);
                    out.extend_from_slice(&ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    out.push(0x06);
                    out.extend_from_slice(&ip.octets());
                }
            }
        }
        TargetAddr::Domain(host, _) => {
            if host.is_empty() || host.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snell: invalid udp host",
                ));
            }
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}

/// 回包：地址族（4 / 6）+ IP + 端口 + 载荷。v4 跳过其它地址族的记录，v6 视为错误。
fn decode_udp_response(record: &[u8], v4: bool) -> io::Result<Option<(TargetAddr, &[u8])>> {
    let invalid = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    if v4 && record.len() < 8 {
        return Err(invalid("snell: udp response too short"));
    }
    let ip_len = match record.first() {
        Some(0x04) => 4,
        Some(0x06) => 16,
        _ if v4 => return Ok(None),
        _ => return Err(invalid("snell: bad udp response address")),
    };
    if record.len() < 1 + ip_len + 2 {
        return Err(invalid("snell: udp response too short"));
    }
    let ip: std::net::IpAddr = if ip_len == 4 {
        <[u8; 4]>::try_from(&record[1..5]).unwrap().into()
    } else {
        <[u8; 16]>::try_from(&record[1..17]).unwrap().into()
    };
    let port = u16::from_be_bytes([record[1 + ip_len], record[2 + ip_len]]);
    // 官方 snell-server 的 UDP 套接字是双栈的：IPv4 目标的回包来源写成 `::ffff:a.b.c.d`（族字节 6）。
    // 统一成 IPv4 形式，否则共用连接按目标 IP 路由时对不上号，回包全部被丢弃。
    Ok(Some((
        TargetAddr::Ip(std::net::SocketAddr::new(ip.to_canonical(), port)),
        &record[3 + ip_len..],
    )))
}

#[async_trait]
impl PacketConn for SnellPacket {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        let mut packet = vec![UDP_FORWARD];
        encode_udp_target(target, &mut packet)?;
        packet.extend_from_slice(buf);
        let mut guard = self.write.lock().await;
        guard.send(&packet).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut guard = self.read.lock().await;
        let reader = &mut *guard;
        let v4 = matches!(self.cfg.spec.version, 4 | 5);
        loop {
            if let Some(record) = reader.queue.pop_front() {
                if let Some((from, payload)) = decode_udp_response(&record, v4)? {
                    let n = crate::copy_datagram(payload, buf, "Snell");
                    return Ok((n, from));
                }
                continue;
            }
            match reader.rx.parse(self.cfg.psk(), &mut reader.inbuf)? {
                Some(Frame::Data(record)) => reader.queue.push_back(record),
                Some(Frame::Eof) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell udp closed",
                    ))
                }
                None => {
                    // 取消安全：读到的字节先进 inbuf，再解析
                    let mut tmp = vec![0u8; READ_CHUNK];
                    let n = reader.io.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell udp closed",
                        ));
                    }
                    reader.inbuf.extend_from_slice(&tmp[..n]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    fn test_session(io: tokio::io::DuplexStream) -> Session {
        Session {
            io: Box::new(io),
            tx: None,
            rx: Rx::V4(v4::Reader::new()),
            inbuf: BytesMut::new(),
        }
    }

    #[test]
    fn pooled_session_liveness_probe() {
        // 对端还在、什么也没发：存活。
        let (a, _keep) = tokio::io::duplex(64);
        assert!(session_alive(&mut test_session(a)));
        // 对端已关闭（服务端在零长记录后关闭 TCP）：丢弃。
        let (a, b) = tokio::io::duplex(64);
        drop(b);
        assert!(!session_alive(&mut test_session(a)));
        // 对端空闲时发来了数据：不能复用。
        let (a, mut b) = tokio::io::duplex(64);
        futures_lite_block(async { b.write_all(b"x").await.unwrap() });
        assert!(!session_alive(&mut test_session(a)));
    }

    fn futures_lite_block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }
    use super::*;

    #[test]
    fn argon2_key_matches_go() {
        // golang.org/x/crypto/argon2.IDKey([]byte("psk"), []byte("0123456789abcdef"), 3, 8, 1, 32)[:16]
        let key = derive_key(b"psk", b"0123456789abcdef").unwrap();
        assert_eq!(key.len(), 16);
        assert_eq!(key, derive_key(b"psk", b"0123456789abcdef").unwrap());
        assert_ne!(key, derive_key(b"psk2", b"0123456789abcdef").unwrap());
    }

    #[test]
    fn udp_address_codec() {
        let mut out = Vec::new();
        encode_udp_target(&TargetAddr::Ip("1.2.3.4:53".parse().unwrap()), &mut out).unwrap();
        assert_eq!(out, [0, 4, 1, 2, 3, 4, 0, 53]);
        let record = [4u8, 8, 8, 8, 8, 0, 53, 0xaa];
        let (from, payload) = decode_udp_response(&record, true).unwrap().unwrap();
        assert_eq!(from, TargetAddr::Ip("8.8.8.8:53".parse().unwrap()));
        assert_eq!(payload, [0xaa]);
        assert!(decode_udp_response(&[9u8; 10], true).unwrap().is_none());
        assert!(decode_udp_response(&[9u8; 10], false).is_err());
    }

    #[test]
    fn reply_parsing() {
        assert_eq!(parse_reply(&[0, 1, 2]).unwrap(), vec![1, 2]);
        let err = parse_reply(&[2, 7, 3, b'b', b'a', b'd']).unwrap_err();
        assert!(err.to_string().contains("server error 7: bad"));
    }

    // ---- 复用连接失效后的重放 ----

    fn v4_config() -> Arc<Config> {
        Arc::new(Config {
            spec: SnellSpec {
                server: TargetAddr::Domain("snell.test".into(), 443),
                psk: "test-psk-0123456789".into(),
                version: 4,
                obfs: None,
                mode: SnellMode::Default,
                reuse: true,
                udp: false,
            },
            profile: None,
        })
    }

    fn target() -> TargetAddr {
        TargetAddr::Domain("example.com".into(), 80)
    }

    #[tokio::test]
    async fn cancelled_udp_write_preserves_all_record_modes() {
        use std::future::Future;
        for (version, mode) in [
            (4, SnellMode::Default),
            (5, SnellMode::Default),
            (6, SnellMode::Default),
            (6, SnellMode::Unshaped),
            (6, SnellMode::UnsafeRaw),
        ] {
            let mut spec = v4_config().spec.clone();
            spec.version = version;
            spec.mode = mode;
            let profile = (version == 6 && mode == SnellMode::Default)
                .then(|| Arc::new(v6::Profile::new(spec.psk.as_bytes())));
            let cfg = Arc::new(Config { spec, profile });
            let (client, mut server) = tokio::io::duplex(32);
            let (_, write) = tokio::io::split(Box::new(client) as BoxStream);
            let mut writer = PacketWriter::new(write, cfg.new_tx().unwrap());
            let first = vec![0x41; 500];
            let mut send = Box::pin(writer.send(&first));
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(send.as_mut().poll(&mut cx).is_pending());
            drop(send);
            assert!(writer.pos > 0 && writer.pos < writer.pending.len());
            let peer = async {
                let mut rx = cfg.new_rx();
                let mut input = BytesMut::new();
                let mut records = Vec::new();
                while records.len() < 2 {
                    match rx.parse(cfg.psk(), &mut input).unwrap() {
                        Some(Frame::Data(data)) => records.push(data),
                        Some(Frame::Eof) => panic!("unexpected eof"),
                        None => {
                            let mut buf = [0u8; 4096];
                            let n = server.read(&mut buf).await.unwrap();
                            assert_ne!(n, 0);
                            input.extend_from_slice(&buf[..n]);
                        }
                    }
                }
                records
            };
            let (sent, records) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(writer.send(b"second"), peer)
            })
            .await
            .unwrap();
            sent.unwrap();
            assert_eq!(records, vec![first, b"second".to_vec()]);
            assert!(writer.pending.is_empty());
        }
    }

    #[tokio::test]
    async fn udp_write_error_is_terminal() {
        let cfg = v4_config();
        let (client, peer) = tokio::io::duplex(32);
        let (_, write) = tokio::io::split(Box::new(client) as BoxStream);
        let mut writer = PacketWriter::new(write, cfg.new_tx().unwrap());
        drop(peer);
        assert!(writer.send(b"first").await.is_err());
        let pending = writer.pending.clone();
        assert_eq!(
            writer.send(b"second").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            writer.pending, pending,
            "a broken writer must not encode another record"
        );
    }

    /// 最小的 v4 服务端：第一条记录去掉请求首部后回复“0 + 数据”，之后原样回显。
    async fn fake_server(cfg: Arc<Config>, header_len: usize, mut io: tokio::io::DuplexStream) {
        let mut rx = cfg.new_rx();
        let mut tx = cfg.new_tx().unwrap();
        let mut inbuf = BytesMut::new();
        let mut first = true;
        loop {
            match rx.parse(cfg.psk(), &mut inbuf).unwrap() {
                Some(Frame::Data(record)) => {
                    let mut plain = Vec::new();
                    if first {
                        first = false;
                        plain.push(0);
                        plain.extend_from_slice(&record[header_len.min(record.len())..]);
                    } else {
                        plain.extend_from_slice(&record);
                    }
                    let mut out = Vec::new();
                    tx.stream(&plain, &mut out).unwrap();
                    if io.write_all(&out).await.is_err() {
                        return;
                    }
                }
                Some(Frame::Eof) => {
                    let mut out = Vec::new();
                    tx.zero(&mut out).unwrap();
                    let _ = io.write_all(&out).await;
                    return;
                }
                None => {
                    let mut tmp = [0u8; 4096];
                    match io.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => inbuf.extend_from_slice(&tmp[..n]),
                    }
                }
            }
        }
    }

    struct FakeDialer {
        cfg: Arc<Config>,
        header_len: usize,
        dials: std::sync::atomic::AtomicUsize,
        /// 前 N 次拨号得到的连接，对端直接关闭（模拟服务端 / 防火墙按新建连接速率丢弃连接）。
        drop_first: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl Dialer for FakeDialer {
        async fn dial_tcp(&self, _: &TargetAddr) -> io::Result<BoxStream> {
            self.dials.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (client, server) = tokio::io::duplex(64 * 1024);
            let dropped = self
                .drop_first
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |n| n.checked_sub(1),
                )
                .is_ok();
            if dropped {
                drop(server);
            } else {
                tokio::spawn(fake_server(self.cfg.clone(), self.header_len, server));
            }
            Ok(Box::new(client))
        }
    }

    /// 构造一条流：连接由 `io` 承载，`reused` 表示它来自池。
    fn stream_over(
        cfg: &Arc<Config>,
        dialer: &Arc<FakeDialer>,
        io: tokio::io::DuplexStream,
        reused: bool,
    ) -> SnellStream {
        SnellStream {
            name: "test".into(),
            cfg: cfg.clone(),
            dialer: dialer.clone(),
            reused,
            replay: Some(Vec::new()),
            retries: 0,
            redial: None,
            session: Some(test_session(io)),
            pool: None,
            pool_generation: None,
            request: Some(cfg.request(COMMAND_CONNECT_V2, Some(&target())).unwrap()),
            reply_read: false,
            read_eof: false,
            zero_sent: false,
            broken: false,
            plain: Vec::new(),
            plain_pos: 0,
            out: Vec::new(),
            out_pos: 0,
        }
    }

    fn dialer_for(cfg: &Arc<Config>) -> Arc<FakeDialer> {
        Arc::new(FakeDialer {
            cfg: cfg.clone(),
            header_len: cfg
                .request(COMMAND_CONNECT_V2, Some(&target()))
                .unwrap()
                .len(),
            dials: Default::default(),
            drop_first: Default::default(),
        })
    }

    /// 用真实 v4 记录层、受控 EOF 构造已经收到回复的流。
    fn drain_stream(pool: &Arc<Pool>) -> (SnellStream, tokio::io::DuplexStream) {
        let cfg = v4_config();
        let (client, peer) = tokio::io::duplex(4096);
        let mut stream = stream_over(&cfg, &dialer_for(&cfg), client, false);
        stream.pool = Some(Arc::downgrade(pool));
        stream.pool_generation = Some(pool.generation());
        stream.request = None;
        stream.reply_read = true;
        stream.session.as_mut().unwrap().tx = Some(cfg.new_tx().unwrap());
        (stream, peer)
    }

    async fn settle_drains() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    async fn send_drain_eof(peer: &mut tokio::io::DuplexStream) {
        let mut out = Vec::new();
        v4_config().new_tx().unwrap().zero(&mut out).unwrap();
        // clear 可以先关闭连接；写失败也符合撤销语义。
        let _ = peer.write_all(&out).await;
        settle_drains().await;
    }

    #[tokio::test]
    async fn drain_slow_eof_respects_pool_limit() {
        let pool = Arc::new(Pool::default());
        let mut peers = Vec::new();
        for _ in 0..POOL_SIZE + 3 {
            let (stream, peer) = drain_stream(&pool);
            drop(stream);
            peers.push(peer);
        }
        settle_drains().await;
        // duplex 的写端可同步探测连接是否仍持有。
        let mut retained = 0;
        for peer in &mut peers {
            if peer.write_all(b"x").await.is_ok() {
                retained += 1;
            }
        }
        assert_eq!(
            retained, POOL_SIZE,
            "waiting drains must share the pool cap"
        );
    }

    #[tokio::test]
    async fn drain_ready_and_waiting_share_limit_without_harming_other_streams() {
        let pool = Arc::new(Pool::default());
        let (active, mut active_peer) = drain_stream(&pool);
        let (ready, mut ready_peer) = drain_stream(&pool);
        drop(ready);
        send_drain_eof(&mut ready_peer).await;
        assert_eq!(pool.state.lock().unwrap().sessions.len(), 1);
        let mut peers = Vec::new();
        for _ in 1..POOL_SIZE {
            let (stream, peer) = drain_stream(&pool);
            drop(stream);
            peers.push(peer);
        }
        let (excess, mut excess_peer) = drain_stream(&pool);
        drop(excess);
        assert!(excess_peer.write_all(b"x").await.is_err());
        assert!(active_peer.write_all(b"x").await.is_ok());
        assert!(
            pool.take().is_some(),
            "overflow must not evict ready connection"
        );
        drop(active);
        settle_drains().await;
        let state = pool.state.lock().unwrap();
        assert_eq!(state.waiting, POOL_SIZE);
    }

    #[tokio::test]
    async fn drain_task_drop_returns_slot_before_and_after_poll() {
        let pool = Arc::new(Pool::default());
        for started in [false, true] {
            let slot = pool.reserve(pool.generation()).unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let _slot = slot;
                let _ = tx.send(());
                std::future::pending::<()>().await;
            });
            if started {
                rx.await.unwrap();
            }
            assert_eq!(pool.state.lock().unwrap().waiting, 1);
            pool.clear();
            assert_eq!(pool.state.lock().unwrap().waiting, 1);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(pool.state.lock().unwrap().waiting, 0);
        }
        assert!(pool.reserve(pool.generation()).is_some());
    }

    #[tokio::test]
    async fn drain_active_old_generation_cannot_return_after_clear() {
        let pool = Arc::new(Pool::default());
        let (old, mut peer) = drain_stream(&pool);
        pool.clear();
        drop(old);
        assert!(peer.write_all(b"x").await.is_err());
        assert_eq!(pool.state.lock().unwrap().waiting, 0);
        let (fresh, mut fresh_peer) = drain_stream(&pool);
        drop(fresh);
        send_drain_eof(&mut fresh_peer).await;
        assert!(pool.take().is_some());
    }

    #[tokio::test]
    async fn drain_late_eof_cannot_repopulate_cleared_pool() {
        let pool = Arc::new(Pool::default());
        let (stream, mut peer) = drain_stream(&pool);
        drop(stream);
        settle_drains().await;
        pool.clear();
        send_drain_eof(&mut peer).await;
        assert!(pool.take().is_none(), "old drain returned after clear");
    }

    #[tokio::test]
    async fn reused_connection_closed_after_probe_is_replayed_on_new_connection() {
        let cfg = v4_config();
        let dialer = dialer_for(&cfg);
        // 探测时还活着，之后服务端关闭（Speedtest 并发复用时的竞争窗口）
        let (stale, peer) = tokio::io::duplex(1024);
        let mut stream = stream_over(&cfg, &dialer, stale, true);
        assert!(session_alive(stream.session.as_mut().unwrap()));
        drop(peer);
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut got = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got, b"hello");
        assert_eq!(dialer.dials.load(std::sync::atomic::Ordering::SeqCst), 1);
        // 之后的数据走新连接
        stream.write_all(b" world").await.unwrap();
        let mut more = [0u8; 6];
        stream.read_exact(&mut more).await.unwrap();
        assert_eq!(&more, b" world");
    }

    #[tokio::test]
    async fn reused_connection_failing_on_read_first_is_replayed() {
        // 服务端先说话的应用：先读，请求单独发出，旧连接读到 EOF
        let cfg = v4_config();
        let dialer = dialer_for(&cfg);
        let (stale, peer) = tokio::io::duplex(1024);
        let mut stream = stream_over(&cfg, &dialer, stale, true);
        drop(peer);
        let reader = async {
            let mut got = [0u8; 2];
            stream.read_exact(&mut got).await.map(|_| got)
        };
        // 新连接上服务端只回复 0，不带数据；随后写入的数据被回显
        let result = tokio::time::timeout(Duration::from_millis(500), reader).await;
        assert!(result.is_err(), "no data expected before the app writes");
        assert_eq!(dialer.dials.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fresh_connection_dropped_before_reply_is_retried_with_backoff() {
        // 起始连接被丢弃；第一次重试的新连接也被丢弃，第二次（最后一次）重试成功
        let cfg = v4_config();
        let dialer = dialer_for(&cfg);
        dialer
            .drop_first
            .store(1, std::sync::atomic::Ordering::SeqCst);
        let (io, peer) = tokio::io::duplex(1024);
        drop(peer);
        let mut stream = stream_over(&cfg, &dialer, io, false);
        let started = Instant::now();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut got = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut got))
            .await
            .expect("must recover")
            .unwrap();
        assert_eq!(&got, b"hello");
        // 两次重试各拨一次号：第一次被丢弃，第二次成功
        assert_eq!(dialer.dials.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(
            started.elapsed() >= RETRY_BACKOFF,
            "retries must back off, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn fresh_connection_retries_are_bounded() {
        let cfg = v4_config();
        let dialer = dialer_for(&cfg);
        dialer
            .drop_first
            .store(100, std::sync::atomic::Ordering::SeqCst);
        let (io, peer) = tokio::io::duplex(1024);
        drop(peer);
        let mut stream = stream_over(&cfg, &dialer, io, false);
        let write = stream.write_all(b"hello").await;
        let mut got = [0u8; 1];
        let read = if write.is_ok() {
            stream.read_exact(&mut got).await.map(|_| ())
        } else {
            write
        };
        assert!(read.is_err());
        assert_eq!(
            dialer.dials.load(std::sync::atomic::Ordering::SeqCst),
            MAX_RETRIES as usize
        );
    }

    #[tokio::test]
    async fn non_drop_errors_are_not_retried_on_fresh_connections() {
        let cfg = v4_config();
        let dialer = dialer_for(&cfg);
        let mut stream = stream_over(&cfg, &dialer, tokio::io::duplex(1024).0, false);
        // 超时、协议错误等不是「被丢弃」，不应重试
        let err = io::Error::new(io::ErrorKind::TimedOut, "slow");
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            stream.poll_recover(&mut cx, err),
            Poll::Ready(Err(_))
        ));
        assert!(stream.redial.is_none());
        assert_eq!(dialer.dials.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
