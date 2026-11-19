// 协议握手与 UDP 包装参考 enfein/mieru apis/internal/handshake.go、apis/common/{packet_over_stream,udp_associate}.go
// @ a366b4a2d08a42178704f3126d71f82a27e014a5；Copyright (C) 2025 mieru authors.
// Modified for Oryn: 适配 Flow 出站与 Rust 有界生命周期。
// SPDX-License-Identifier: GPL-3.0-or-later
mod carrier;
#[cfg(test)]
mod key_lifecycle_tests;
mod pattern;
mod session;
#[cfg(test)]
#[path = "session_budget_tests.rs"]
mod session_budget_tests;
mod wire;
use crate::{BoxStream, Dialer, Outbound, PacketConn, Resolver, SessionControl};
use async_trait::async_trait;
use carrier::Carrier;
use oryn_config::{MieruSpec, TargetAddr};
use oryn_protocol::socks5;
use oryn_udp::DatagramFactory;
use std::time::Duration;
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
    sync::{Mutex as AsyncMutex, Semaphore},
};

/// 满载时新连接在会话名额上排队的最长时间；外层 `with_timeout`（10 s）之内。
const SESSION_QUEUE: Duration = Duration::from_secs(2);

struct State {
    carriers: Mutex<Vec<Weak<Carrier>>>,
    generation: AtomicU64,
    sleeping: AtomicBool,
}
impl State {
    fn reset(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let mut carriers = self.carriers.lock().unwrap();
        for c in carriers.drain(..).filter_map(|c| c.upgrade()) {
            c.stop.cancel();
        }
    }
}
impl SessionControl for State {
    fn on_network_changed(&self) {
        self.reset();
    }
    fn on_sleep(&self) {
        self.sleeping.store(true, Ordering::SeqCst);
        self.reset();
    }
    fn on_wake(&self) {
        self.sleeping.store(false, Ordering::SeqCst);
    }
}
pub struct MieruOutbound {
    tag: String,
    spec: MieruSpec,
    dialer: Arc<dyn Dialer>,
    resolver: Arc<dyn Resolver>,
    target_resolver: Arc<dyn Resolver>,
    datagrams: Arc<dyn DatagramFactory>,
    pool: AsyncMutex<Vec<PooledCarrier>>,
    /// 正在建立、尚未进池的载体数。
    connecting: AtomicUsize,
    state: Arc<State>,
    slots: Arc<Semaphore>,
    /// 载体池上限：与会话预算同值（载体按需扩展，官方实现无上限）。
    carrier_limit: usize,
}
struct PooledCarrier {
    carrier: Arc<Carrier>,
    key_time: u64,
}
impl PooledCarrier {
    fn accepts_open(&self, now: u64) -> bool {
        // 官方 v3.38.0 发现阶段尝试前/当前/后 rounded 120 秒槽。
        // 旧 UDP 即使本地还有会话，也不保证 OPEN 到达时服务端仍有旧会话；
        // 因而只让它排空，不再接纳新会话。TCP 首次发现后始终固定 key。
        !self.carrier.packet
            || (self.key_time.saturating_add(60) / 120).abs_diff(now.saturating_add(60) / 120) <= 1
    }

    fn retain(&self, now: u64) -> bool {
        if !self.accepts_open(now) && self.carrier.sessions.lock().unwrap().is_empty() {
            self.carrier.stop.cancel();
        }
        !self.carrier.stop.is_cancelled()
    }
}

/// 「正在建立的载体」计数；丢弃即减一。
struct ConnectingGuard<'a>(&'a AtomicUsize);

impl<'a> ConnectingGuard<'a> {
    fn new(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self(count)
    }
}

impl Drop for ConnectingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl MieruOutbound {
    pub fn new(
        tag: String,
        spec: MieruSpec,
        dialer: Arc<dyn Dialer>,
        resolver: Arc<dyn Resolver>,
        target_resolver: Arc<dyn Resolver>,
        datagrams: Arc<dyn DatagramFactory>,
        sessions: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            tag,
            spec,
            dialer,
            resolver,
            target_resolver,
            datagrams,
            pool: AsyncMutex::new(Vec::new()),
            connecting: AtomicUsize::new(0),
            state: Arc::new(State {
                carriers: Mutex::new(Vec::new()),
                generation: AtomicU64::new(0),
                sleeping: AtomicBool::new(false),
            }),
            slots: Arc::new(Semaphore::new(sessions.max(1))),
            carrier_limit: sessions.max(1),
        })
    }
    async fn connect(&self, target: &TargetAddr, udp: bool) -> io::Result<BoxStream> {
        crate::with_timeout(
            async {
                // 满载时短暂排队而不是立即拒绝：浏览器式突发的连接多为短命，
                // 槽位毫秒级释放（应用关流即归还），排队把硬失败变成小延迟，
                // 对齐官方「从不拒绝」的失败形态（issue #5）。
                let permit =
                    match tokio::time::timeout(SESSION_QUEUE, self.slots.clone().acquire_owned())
                        .await
                    {
                        // 信号量从不关闭，Closed 分支同样按限额拒绝处理。
                        Ok(Ok(permit)) => permit,
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "Mieru active session limit reached",
                            ))
                        }
                    };
                let mut request = vec![5, if udp { 3 } else { 1 }, 0];
                socks5::encode_addr(target, &mut request)?;
                let mut pool = self.pool.lock().await;
                if self.state.sleeping.load(Ordering::SeqCst) {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "Mieru is sleeping",
                    ));
                }
                let now = wire::now();
                pool.retain(|c| c.retain(now));
                let carrier = if let Some(c) = pool.iter().find(|c| {
                    c.accepts_open(now)
                        && c.carrier.sessions.lock().unwrap().len() < self.spec.multiplexing
                }) {
                    c.carrier.clone()
                } else {
                    if pool.len() + self.connecting.load(Ordering::Acquire) >= self.carrier_limit {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "Mieru carrier limit reached",
                        ));
                    }
                    let generation = self.state.generation.load(Ordering::SeqCst);
                    // 建连（DNS + TCP/TLS 或 UDP）期间不持有池锁，否则并发首连全部串行、集体超时；
                    // 正在建立的载体计入上限，取消（超时）时由守卫归还
                    let connecting = ConnectingGuard::new(&self.connecting);
                    drop(pool);
                    let (c, key_time) = Carrier::connect(
                        &self.spec,
                        self.dialer.as_ref(),
                        self.resolver.as_ref(),
                        self.datagrams.as_ref(),
                    )
                    .await?;
                    {
                        let mut registered = self.state.carriers.lock().unwrap();
                        if generation != self.state.generation.load(Ordering::SeqCst)
                            || self.state.sleeping.load(Ordering::SeqCst)
                        {
                            c.stop.cancel();
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "Mieru network changed during connect",
                            ));
                        }
                        // 已取消载体即使还被收尾任务短暂持有，也不占用注册表。
                        registered.retain(|c| c.upgrade().is_some_and(|c| !c.stop.is_cancelled()));
                        registered.push(Arc::downgrade(&c));
                    }
                    pool = self.pool.lock().await;
                    pool.push(PooledCarrier {
                        carrier: c.clone(),
                        key_time,
                    });
                    drop(connecting);
                    c
                };
                let id = loop {
                    let id = u32::from_be_bytes(wire::random()?);
                    if id != 0 && !carrier.sessions.lock().unwrap().contains_key(&id) {
                        break id;
                    }
                };
                let stream = session::open(
                    carrier,
                    id,
                    request,
                    permit,
                    self.slots.clone(),
                    self.carrier_limit,
                );
                drop(pool);
                let mut reply = ReplyStream {
                    inner: stream,
                    header: Vec::with_capacity(262),
                    done: false,
                    failed: false,
                    deadline: None,
                };
                if !self.spec.no_wait {
                    reply.handshake().await?;
                }
                Ok(Box::new(reply) as BoxStream)
            },
            "Mieru handshake",
        )
        .await
    }
}
impl Drop for MieruOutbound {
    fn drop(&mut self) {
        self.state.reset();
    }
}
#[async_trait]
impl Outbound for MieruOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "mieru"
    }
    fn session_control(&self) -> Option<Arc<dyn SessionControl>> {
        Some(self.state.clone())
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        self.connect(target, false).await
    }
    async fn bind_udp(&self, target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.spec.udp {
            return Err(crate::unsupported("Mieru UDP is disabled"));
        }
        let addresses = crate::resolve_target(self.target_resolver.as_ref(), target).await?;
        let stream = self.connect(&TargetAddr::Ip(addresses[0]), true).await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Box::new(Packets {
            resolver: self.target_resolver.clone(),
            reader: AsyncMutex::new(PacketReader {
                inner: reader,
                pending: Vec::new(),
                failed: false,
            }),
            writer: AsyncMutex::new(PacketWriter {
                inner: writer,
                pending: vec![],
                offset: 0,
            }),
        }))
    }
}

/// NO_WAIT 仍检查响应，不把 SOCKS 回复泄漏给应用或忽略拒绝状态。
struct ReplyStream {
    inner: session::Stream,
    header: Vec<u8>,
    done: bool,
    failed: bool,
    /// 握手期限从第一次等待回复时起算，而不是从建连时刻：no_wait 下应用可能很晚才第一次读取。
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl ReplyStream {
    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(wire::bad("Mieru handshake already failed")));
        }
        let mut result = self.poll_handshake_inner(cx);
        let expired = result.is_pending() && {
            let deadline = self
                .deadline
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(crate::CONNECT_TIMEOUT)));
            std::future::Future::poll(deadline.as_mut(), cx).is_ready()
        };
        if expired {
            result = Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Mieru deferred handshake timed out",
            )));
        }
        if matches!(result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }
    fn poll_handshake_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.done {
            let mut byte = [0];
            let mut buf = ReadBuf::new(&mut byte);
            match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Mieru handshake closed",
                    )))
                }
                _ => {}
            }
            self.header.push(byte[0]);
            let h = &self.header;
            if h.len() == 3 && h[..3] != [5, 0, 0] {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "Mieru SOCKS request rejected",
                )));
            }
            if h.len() >= 4 {
                let expected = match h[3] {
                    1 => 10,
                    4 => 22,
                    3 if h.len() >= 5 => 7 + usize::from(h[4]),
                    3 => continue,
                    _ => return Poll::Ready(Err(wire::bad("Mieru invalid reply address"))),
                };
                if h.len() == expected {
                    self.done = true;
                    self.header.clear();
                }
            }
        }
        Poll::Ready(Ok(()))
    }
    async fn handshake(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.poll_handshake(cx)).await
    }
}
impl AsyncRead for ReplyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.poll_handshake(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_read(cx, b),
            r => r,
        }
    }
}
impl AsyncWrite for ReplyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
struct PacketReader {
    inner: ReadHalf<BoxStream>,
    pending: Vec<u8>,
    failed: bool,
}
struct PacketWriter {
    inner: WriteHalf<BoxStream>,
    pending: Vec<u8>,
    offset: usize,
}
struct Packets {
    resolver: Arc<dyn Resolver>,
    reader: AsyncMutex<PacketReader>,
    writer: AsyncMutex<PacketWriter>,
}
#[async_trait]
impl PacketConn for Packets {
    async fn send_to(&self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        if data.len() > 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mieru UDP payload exceeds 8192 bytes",
            ));
        }
        let resolved = crate::resolve_target(self.resolver.as_ref(), target).await?;
        let target = TargetAddr::Ip(resolved[0]);
        let packet = socks5::encode_udp(&target, data)?;
        let mut writer = self.writer.lock().await;
        // 部分写入被取消时，下次调用先发完旧帧，避免破坏数据报边界。
        writer.flush_pending().await?;
        writer.pending.push(0);
        writer
            .pending
            .extend_from_slice(&(packet.len() as u16).to_be_bytes());
        writer.pending.extend_from_slice(&packet);
        writer.pending.push(255);
        writer.flush_pending().await
    }
    async fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut r = self.reader.lock().await;
        if r.failed {
            return Err(wire::bad("Mieru UDP reader closed"));
        }
        loop {
            if r.pending.len() >= 3 {
                let n = usize::from(u16::from_be_bytes([r.pending[1], r.pending[2]]));
                if r.pending[0] != 0 || !(7..=8192 + 262).contains(&n) {
                    r.failed = true;
                    return Err(wire::bad("Mieru invalid UDP frame"));
                }
                if r.pending.len() >= n + 4 {
                    if r.pending[n + 3] != 255 || r.pending[3..6] != [0, 0, 0] {
                        r.failed = true;
                        return Err(wire::bad("Mieru invalid UDP delimiter"));
                    }
                    let (from, data) = socks5::decode_udp(&r.pending[3..n + 3])
                        .ok_or_else(|| wire::bad("Mieru invalid UDP address"))?;
                    let size = crate::copy_datagram(data, out, "Mieru");
                    r.pending.drain(..n + 4);
                    return Ok((size, from));
                }
            }
            let mut scratch = [0; 2048];
            let n = r.inner.read(&mut scratch).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Mieru UDP stream closed",
                ));
            }
            r.pending.extend_from_slice(&scratch[..n]);
        }
    }
}
impl PacketWriter {
    async fn flush_pending(&mut self) -> io::Result<()> {
        while self.offset < self.pending.len() {
            let n = self.inner.write(&self.pending[self.offset..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "Mieru UDP writer closed",
                ));
            }
            self.offset += n;
        }
        self.pending.clear();
        self.offset = 0;
        Ok(())
    }
}

/// UDP 会话累计统计（数据报数、窗口外丢弃、重复、重传、窗口更新），诊断用。
pub fn counters() -> [u64; 5] {
    std::array::from_fn(|i| session::COUNTERS[i].load(std::sync::atomic::Ordering::Relaxed))
}
