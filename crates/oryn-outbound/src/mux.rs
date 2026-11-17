//! sing-mux 头部适配：来源 SagerNet/sing-mux protocol.go、client_conn.go、brutal.go（带宽交换）。
//! commit 1c5ed1c7731c23e0308870b3ce05708e38a208f2（v0.3.3）。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
use crate::{unsupported, with_timeout, BoxStream, Outbound, PacketConn};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use oryn_config::{MuxProtocol, MuxSpec, TargetAddr};
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    task::{ready, Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, oneshot, Mutex, Notify},
};
use tokio_util::{
    compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt},
    sync::PollSender,
};

fn err(s: &str) -> io::Error {
    io::Error::other(s)
}
struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
type OpenReply = oneshot::Sender<io::Result<BoxStream>>;
enum Session {
    Yamux {
        open: mpsc::Sender<OpenReply>,
        driver: Driver,
    },
    H2 {
        send: Mutex<h2::client::SendRequest<Bytes>>,
        /// 目标单流窗口，随会话里的流数调整（驱动任务负责下发）。
        window: tokio::sync::watch::Sender<u32>,
        driver: Driver,
    },
    Smux(smux::Session),
}
impl Session {
    async fn new(mut carrier: BoxStream, spec: &MuxSpec) -> io::Result<Self> {
        let protocol = match spec.protocol {
            MuxProtocol::Smux => 0,
            MuxProtocol::Yamux => 1,
            MuxProtocol::H2Mux => 2,
        };
        carrier
            .write_all(&[1, protocol, u8::from(spec.padding)])
            .await?;
        if spec.padding {
            carrier.write_all(&256u16.to_be_bytes()).await?;
            carrier.write_all(&[0; 256]).await?;
        }
        carrier.flush().await?;
        if spec.padding {
            carrier = Box::new(padding::Padding::new(carrier));
        }
        match spec.protocol {
            MuxProtocol::Smux => Ok(Self::Smux(smux::Session::new(carrier))),
            MuxProtocol::Yamux => {
                let mut config = yamux::Config::default();
                // 准入由本模块按 `max_streams` 控制（见 `lease`）；yamux 自己的上限还会把已被丢弃、
                // 但尚在关闭握手中的流计入，上限设成一样会让刚归还名额的新流立刻被 yamux 拒绝
                // （`maximum number of streams reached`）。这里留出一倍余量；yamux 要求连接接收窗口
                // 不小于 256 KiB × 流数上限，窗口随之放大（只是上限，不是预分配）。
                // yamux 的单流窗口从 256 KiB 起按往返时延自动翻倍，但每条流能超出 256 KiB 的部分
                // 来自「连接窗口 − 流数上限 × 256 KiB」：恰好等于时余量为 0，窗口永远长不上去，
                // 往返 6 ms 时单流下载只有 ~213 Mbit/s。所以再留一份余量让活跃的流分享（只是上限，不预分配）。
                let streams = spec.max_streams.saturating_mul(2);
                config
                    .set_max_num_streams(streams)
                    .set_max_connection_receive_window(Some(
                        streams
                            .saturating_mul(256 * 1024)
                            .saturating_add(YAMUX_WINDOW_HEADROOM),
                    ))
                    .set_split_send_size(16 * 1024);
                let mut conn =
                    yamux::Connection::new(carrier.compat(), config, yamux::Mode::Client);
                // 开流请求排队给驱动任务；队列容量与准入上限一致，并发建流不必逐个等待通道槽位
                let (tx, mut rx) = mpsc::channel::<OpenReply>(spec.max_streams.clamp(1, 64));
                let driver = tokio::spawn(async move {
                    let mut pending = None;
                    std::future::poll_fn(|cx| {
                        // 一次处理完所有已排队的开流请求。完成一个之后必须再轮询队列：
                        // 返回 Ready 的 `poll_recv` 不登记唤醒，否则下一个请求要等到有入站帧才被处理
                        loop {
                            if pending.is_none() {
                                match rx.poll_recv(cx) {
                                    Poll::Ready(Some(reply)) => pending = Some(reply),
                                    Poll::Ready(None) => return Poll::Ready(()),
                                    Poll::Pending => break,
                                }
                            }
                            match conn.poll_new_outbound(cx) {
                                Poll::Ready(result) => {
                                    let _ = pending.take().unwrap().send(
                                        result
                                            .map(|s| Box::new(s.compat()) as BoxStream)
                                            .map_err(io::Error::other),
                                    );
                                }
                                Poll::Pending => break,
                            }
                        }
                        loop {
                            match conn.poll_next_inbound(cx) {
                                Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                                    return Poll::Ready(())
                                }
                                // 客户端不接受对端发起的流：只关掉这一条并继续驱动，
                                // 不能因此结束整个会话（会断掉其上全部 Flow）
                                Poll::Ready(Some(Ok(stream))) => drop(stream),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                    })
                    .await;
                });
                Ok(Self::Yamux {
                    open: tx,
                    driver: Driver(driver),
                })
            }
            MuxProtocol::H2Mux => {
                // 单流窗口固定 64 KiB 时，单流下载 ≈ 窗口的一半 ÷ 往返时延：千兆有线（往返约 3 ms）上只有
                // ~85 Mbit/s。与 gRPC 连接池一样，连接窗口给一个固定预算，单流窗口随会话里的流数在预算内调整
                // （1–2 条流 2 MiB，32 条 128 KiB），一个会话缓存的未读数据上限仍是这个预算。
                let first = oryn_transport::h2_stream_window(1);
                let (send, connection) = h2::client::Builder::new()
                    .initial_window_size(first)
                    .initial_connection_window_size(oryn_transport::H2_WINDOW_BUDGET)
                    .max_send_buffer_size(128 * 1024)
                    .max_header_list_size(16 * 1024)
                    .handshake(carrier)
                    .await
                    .map_err(io::Error::other)?;
                let (window, driver) = oryn_transport::drive_with_window(connection, first);
                Ok(Self::H2 {
                    send: Mutex::new(send),
                    window,
                    driver: Driver(driver),
                })
            }
        }
    }
    /// 会话里的流数变了：h2mux 重新计算单流接收窗口，其它多路复用没有这个概念。
    fn retune(&self, streams: usize) {
        if let Self::H2 { window, .. } = self {
            let target = oryn_transport::h2_stream_window(streams);
            window.send_if_modified(|current| {
                let changed = *current != target;
                *current = target;
                changed
            });
        }
    }
    fn closed(&self) -> bool {
        match self {
            Self::Yamux { driver, .. } | Self::H2 { driver, .. } => driver.0.is_finished(),
            Self::Smux(s) => s.closed(),
        }
    }
    async fn open(&self) -> io::Result<BoxStream> {
        match self {
            Self::Smux(s) => s.open().await,
            Self::Yamux { open, .. } => {
                let (tx, rx) = oneshot::channel();
                // 开流请求排队等驱动任务逐个处理（队列容量为 1）；队列满时必须等待而不是拒绝，
                // 否则同时到来的第二个及之后的 Flow 都会立即失败。整体仍受上层的连接超时约束。
                open.send(tx)
                    .await
                    .map_err(|_| err("yamux session closed"))?;
                rx.await.map_err(|_| err("yamux session closed"))?
            }
            Self::H2 { send, .. } => {
                let mut send = send.lock().await;
                std::future::poll_fn(|cx| send.poll_ready(cx))
                    .await
                    .map_err(io::Error::other)?;
                let request = http::Request::builder()
                    .method("CONNECT")
                    .uri("https://localhost")
                    .body(())
                    .map_err(io::Error::other)?;
                let (response, send) = send
                    .send_request(request, false)
                    .map_err(io::Error::other)?;
                Ok(Box::new(H2Stream {
                    response: Some(response),
                    recv: None,
                    send,
                    read: Bytes::new(),
                    pending: Bytes::new(),
                    closed: false,
                }))
            }
        }
    }
}
/// yamux 连接接收窗口在「流数上限 × 256 KiB」之外的余量：单流窗口可以自动长到 256 KiB + 这个值，
/// 一个会话缓存的未读数据上限随之多出这么多（与 h2mux 的 4 MiB 预算同量级）。
const YAMUX_WINDOW_HEADROOM: usize = 4 * 1024 * 1024;
/// AnyTLS 每个出站的会话上限：超过后按负载共享会话。
/// 每个会话约为一条 TLS 连接加两个任务，与 Trojan 等每 Flow 一条连接的协议同量级。
const ANY_MAX_SESSIONS: usize = 32;
struct Entry {
    session: Arc<Session>,
    active: Arc<AtomicUsize>,
    last: Arc<StdMutex<Instant>>,
}
pub struct MuxOutbound {
    inner: Arc<dyn Outbound>,
    spec: MuxSpec,
    pool: Arc<Mutex<Vec<Entry>>>,
    /// 正在建立（握手中）的会话数。
    connecting: Arc<AtomicUsize>,
    /// 握手结束（成功或失败）时通知。
    ready: Arc<Notify>,
    cleaner: StdMutex<Option<Driver>>,
    any: Option<oryn_config::AnyTlsSpec>,
    udp: bool,
}
impl MuxOutbound {
    pub fn new(inner: Arc<dyn Outbound>, spec: MuxSpec) -> Self {
        Self {
            inner,
            spec,
            pool: Arc::new(Mutex::new(Vec::new())),
            connecting: Arc::new(AtomicUsize::new(0)),
            ready: Arc::new(Notify::new()),
            cleaner: StdMutex::new(None),
            any: None,
            udp: true,
        }
    }
    pub fn set_udp(&mut self, enabled: bool) {
        self.udp = enabled;
    }
    pub fn any(inner: Arc<dyn Outbound>, spec: oryn_config::AnyTlsSpec) -> Self {
        let mut out = Self::new(
            inner,
            // 与 sing-anytls 一样，每个会话同一时间只承载一条流，没有空闲会话就新建；
            // AnyTLS 没有逐流流控，共享会话时一条高速下载会让同会话的其他流排队。
            // 会话数达到上限后才共享，按负载最小选择。
            MuxSpec {
                protocol: MuxProtocol::Smux,
                max_connections: ANY_MAX_SESSIONS,
                min_streams: 1,
                max_streams: 32,
                padding: false,
                only_tcp: true,
                brutal: None,
            },
        );
        out.udp = spec.udp;
        out.any = Some(spec);
        out
    }
    fn start_cleaner(&self) {
        let mut cleaner = self.cleaner.lock().unwrap();
        if cleaner.is_some() {
            return;
        }
        let pool = Arc::downgrade(&self.pool);
        // 0 秒间隔会让 tokio::time::interval panic；不依赖配置层兜底
        let check = self.any.as_ref().map_or(5, |s| s.idle_check_secs).max(1);
        let timeout = Duration::from_secs(self.any.as_ref().map_or(30, |s| s.idle_timeout_secs));
        let min = self.any.as_ref().map_or(0, |s| s.min_idle_sessions);
        *cleaner = Some(Driver(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(check));
            loop {
                tick.tick().await;
                let Some(pool) = pool.upgrade() else {
                    break;
                };
                let mut pool = pool.lock().await;
                let mut idle = pool
                    .iter()
                    .filter(|e| e.active.load(Ordering::Acquire) == 0 && !e.session.closed())
                    .count();
                pool.retain(|e| {
                    if e.session.closed() {
                        return false;
                    }
                    if e.active.load(Ordering::Acquire) == 0
                        && e.last.lock().unwrap().elapsed() >= timeout
                        && idle > min
                    {
                        idle -= 1;
                        false
                    } else {
                        true
                    }
                });
            }
        })));
    }
    async fn open(&self, target: &TargetAddr, udp: bool) -> io::Result<BoxStream> {
        self.start_cleaner();
        with_timeout(
            async {
                let lease = self.lease().await?;
                let mut stream = lease.session.open().await?;
                let mut header = if self.any.is_some() {
                    Vec::new()
                } else {
                    (if udp { 3u16 } else { 0 }).to_be_bytes().to_vec()
                };
                oryn_protocol::socks5::encode_addr(target, &mut header)?;
                stream.write_all(&header).await?;
                stream.flush().await?;
                Ok(Box::new(MuxStream {
                    stream,
                    lease,
                    response: self.any.is_some(),
                }) as BoxStream)
            },
            "multiplex stream",
        )
        .await
    }

    /// 选择可复用的会话，或新建一个，并占用其中一个流名额。
    ///
    /// 新建会话要做一次 TLS 握手，期间不持有池锁，否则并发的新 Flow 会排队等前面每一次握手，
    /// 测速时几十条连接同时建立就会集体超时。正在建立的会话计入 `max_connections`。
    async fn lease(&self) -> io::Result<Lease> {
        let connecting = loop {
            // 先登记等待，再检查池，避免漏掉检查之后才完成的握手
            let ready = self.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            let mut pool = self.pool.lock().await;
            pool.retain(|e| !e.session.closed());
            let total = pool.len() + self.connecting.load(Ordering::Acquire);
            let reusable = pool
                .iter()
                .position(|e| e.active.load(Ordering::Acquire) < self.spec.min_streams)
                .or_else(|| {
                    if total < self.spec.max_connections {
                        return None;
                    }
                    // 会话已满：选负载最小的会话，避免流集中到第一个会话上
                    pool.iter()
                        .enumerate()
                        .map(|(i, e)| (i, e.active.load(Ordering::Acquire)))
                        .filter(|&(_, active)| active < self.spec.max_streams)
                        .min_by_key(|&(_, active)| active)
                        .map(|(i, _)| i)
                });
            if let Some(i) = reusable {
                return Ok(Lease::new(&pool[i], &self.ready));
            }
            if total < self.spec.max_connections {
                // 取消（超时）时由守卫归还名额
                break Connecting::new(&self.connecting, &self.ready);
            }
            // 所有会话都已满，或名额被握手中的会话占用：等有流结束或握手完成后再选，
            // 而不是立即拒绝（sing-mux 同样不拒绝，只是把流压到负载最小的会话上）；
            // 等待受外层的连接超时约束，所以仍然有界。
            drop(pool);
            ready.await;
        };
        let session = self.connect_session().await?;
        let entry = Entry {
            session,
            active: Arc::new(AtomicUsize::new(0)),
            last: Arc::new(StdMutex::new(Instant::now())),
        };
        let lease = Lease::new(&entry, &self.ready);
        self.pool.lock().await.push(entry);
        drop(connecting);
        Ok(lease)
    }

    async fn connect_session(&self) -> io::Result<Arc<Session>> {
        let carrier = self
            .inner
            .connect_tcp(&TargetAddr::Domain("sp.mux.sing-box.arpa".into(), 444))
            .await?;
        let session = Arc::new(if self.any.is_some() {
            Session::Smux(smux::Session::new_any(carrier))
        } else {
            Session::new(carrier, &self.spec).await?
        });
        if let Some(brutal) = &self.spec.brutal {
            let mut stream = session.open().await?;
            brutal_exchange(&mut stream, brutal)
                .await
                .map_err(|e| io::Error::new(e.kind(), format!("brutal exchange: {e}")))?;
        }
        Ok(session)
    }
}
/// 正在建立的会话名额，drop 时归还并唤醒等待名额的请求。
struct Connecting(Arc<AtomicUsize>, Arc<Notify>);
impl Connecting {
    fn new(count: &Arc<AtomicUsize>, ready: &Arc<Notify>) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self(count.clone(), ready.clone())
    }
}
impl Drop for Connecting {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
        self.1.notify_waiters();
    }
}
/// sing-mux 的 Brutal：会话建立后，在目的地为 `_BrutalBwExchange` 的流上发送本端接收带宽，
/// 读取服务端的回应。iOS 不能设置 TCP 拥塞控制，所以只做带宽交换，之后的发送速率由系统决定。
async fn brutal_exchange(
    stream: &mut BoxStream,
    brutal: &oryn_config::BrutalSpec,
) -> io::Result<()> {
    // 流请求：标志（TCP = 0）+ 目的地
    let mut request = vec![0, 0];
    oryn_protocol::socks5::encode_addr(
        &TargetAddr::Domain("_BrutalBwExchange".into(), 0),
        &mut request,
    )?;
    request.extend_from_slice(&(u64::from(brutal.down_mbps) * 125_000).to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;
    // 流的状态字节：0 成功
    if stream.read_u8().await? != 0 {
        return Err(err("multiplex stream rejected the brutal exchange"));
    }
    if stream.read_u8().await? != 0 {
        let _server_receive_bps = stream.read_u64().await?;
        return Ok(());
    }
    // 失败：uvarint 长度 + 消息
    let mut len = 0usize;
    let mut done = false;
    for shift in (0..35).step_by(7) {
        let byte = stream.read_u8().await?;
        len |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            done = true;
            break;
        }
    }
    if !done || len > 1024 {
        return Err(err("multiplex brutal exchange error message is malformed"));
    }
    let mut message = vec![0; len];
    stream.read_exact(&mut message).await?;
    Err(io::Error::other(format!(
        "remote error: {}",
        String::from_utf8_lossy(&message)
    )))
}

struct Lease {
    active: Arc<AtomicUsize>,
    last: Arc<StdMutex<Instant>>,
    session: Arc<Session>,
    /// 流结束时唤醒正在等待名额的新流。
    ready: Arc<Notify>,
}
impl Lease {
    fn new(entry: &Entry, ready: &Arc<Notify>) -> Self {
        let streams = entry.active.fetch_add(1, Ordering::AcqRel) + 1;
        entry.session.retune(streams);
        Self {
            active: entry.active.clone(),
            last: entry.last.clone(),
            session: entry.session.clone(),
            ready: ready.clone(),
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let streams = self.active.fetch_sub(1, Ordering::AcqRel).saturating_sub(1);
        self.session.retune(streams);
        *self.last.lock().unwrap() = Instant::now();
        self.ready.notify_waiters();
    }
}
struct MuxStream {
    stream: BoxStream,
    lease: Lease,
    response: bool,
}
impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.response {
            let mut status = [0];
            let mut b = ReadBuf::new(&mut status);
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut b))?;
            if b.filled().len() != 1 || status[0] != 0 {
                return Poll::Ready(Err(err("multiplex stream rejected or closed")));
            }
            self.response = true;
        }
        Pin::new(&mut self.stream).poll_read(cx, out)
    }
}
impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.lease.session.closed() {
            return Poll::Ready(Err(err("multiplex session closed")));
        }
        Pin::new(&mut self.stream).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
#[async_trait]
impl Outbound for MuxOutbound {
    fn tag(&self) -> &str {
        self.inner.tag()
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        self.open(target, false).await
    }
    async fn bind_udp(&self, target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.udp {
            return Err(unsupported("UDP is disabled for this proxy"));
        }
        if self.any.is_some() {
            // AnyTLS 的 UDP 走会话里的一个 UoT v2 流（sing-box protocol/anytls/outbound.go）
            let magic = TargetAddr::Domain(crate::uot::magic(2).into(), 0);
            let stream = self.open(&magic, false).await?;
            return Ok(Box::new(crate::uot::UotConn::new(stream, 2, target)?));
        }
        if self.spec.only_tcp {
            return self.inner.bind_udp(target).await;
        }
        let stream = self.open(target, true).await?;
        Ok(Box::new(MuxPackets::new(stream)))
    }
}
struct MuxPackets {
    read: Mutex<(tokio::io::ReadHalf<BoxStream>, Vec<u8>)>,
    write: Mutex<crate::FrameWriter<tokio::io::WriteHalf<BoxStream>>>,
}
impl MuxPackets {
    fn new(s: BoxStream) -> Self {
        let (r, w) = tokio::io::split(s);
        Self {
            read: Mutex::new((r, Vec::new())),
            write: Mutex::new(crate::FrameWriter::new(w)),
        }
    }
}
#[async_trait]
impl PacketConn for MuxPackets {
    async fn send_to(&self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        let mut wire = Vec::new();
        oryn_protocol::socks5::encode_addr(target, &mut wire)?;
        let len = u16::try_from(data.len()).map_err(|_| unsupported("mux datagram too large"))?;
        wire.extend(len.to_be_bytes());
        wire.extend(data);
        self.write.lock().await.send(wire).await
    }
    async fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut r = self.read.lock().await;
        loop {
            if let Some((a, h)) = oryn_protocol::socks5::decode_addr(&r.1) {
                if r.1.len() >= h + 2 {
                    let n = u16::from_be_bytes(r.1[h..h + 2].try_into().unwrap()) as usize;
                    if r.1.len() >= h + 2 + n {
                        let count = crate::copy_datagram(&r.1[h + 2..h + 2 + n], out, "mux");
                        r.1.drain(..h + 2 + n);
                        return Ok((count, a));
                    }
                }
            }
            if r.1.len() > 65535 + 262 {
                return Err(err("invalid mux datagram"));
            }
            let mut scratch = [0; 4096];
            let n = r.0.read(&mut scratch).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            r.1.extend_from_slice(&scratch[..n]);
        }
    }
}
struct H2Stream {
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    send: h2::SendStream<Bytes>,
    read: Bytes,
    pending: Bytes,
    closed: bool,
}
impl H2Stream {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            self.send.reserve_capacity(self.pending.len());
            let n = match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(n)) => n.min(self.pending.len()),
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => return Poll::Ready(Err(err("h2mux closed"))),
            };
            if n == 0 {
                continue;
            }
            self.send
                .send_data(self.pending.split_to(n), false)
                .map_err(io::Error::other)?;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(r) = &mut self.response {
            use std::future::Future;
            let r = ready!(Pin::new(r).poll(cx)).map_err(io::Error::other)?;
            if r.status() != 200 {
                return Poll::Ready(Err(err("h2mux request rejected")));
            }
            self.recv = Some(r.into_body());
            self.response = None;
        }
        loop {
            if !self.read.is_empty() {
                let n = out.remaining().min(self.read.len());
                out.put_slice(&self.read[..n]);
                self.read.advance(n);
                return Poll::Ready(Ok(()));
            }
            let recv = self.recv.as_mut().unwrap();
            match ready!(recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    recv.flow_control()
                        .release_capacity(data.len())
                        .map_err(io::Error::other)?;
                    self.read = data;
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}
impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(err("h2mux write closed")));
        }
        ready!(self.drain(cx))?;
        // 与 gRPC 流一致按 64 KiB 收下：大块写入少几轮 poll，发送时仍按 h2 授予的额度切分
        let n = data.len().min(64 * 1024);
        self.pending = Bytes::copy_from_slice(&data[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.drain(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        if !self.closed {
            self.send
                .send_data(Bytes::new(), true)
                .map_err(io::Error::other)?;
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}
mod any_padding;
mod padding;
mod smux;

/// gost-plugin 的复用：在承载流上建立一个 smux v1 会话，只开一个流；流关闭时会话随之关闭。
pub(crate) async fn smux_single(carrier: BoxStream) -> io::Result<BoxStream> {
    let session = smux::Session::new(carrier);
    let stream = session.open().await?;
    Ok(Box::new(SingleSession {
        _session: session,
        stream,
    }))
}

struct SingleSession {
    _session: smux::Session,
    stream: BoxStream,
}

impl AsyncRead for SingleSession {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SingleSession {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// 回归：yamux 的开流队列容量只有 1，同时到来的开流必须排队等待，不能被拒绝。
    #[tokio::test]
    async fn yamux_concurrent_opens_queue_instead_of_failing() {
        use futures_util::io::AsyncWriteExt as _;
        use tokio_util::compat::TokioAsyncReadCompatExt;
        let (client, mut server) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            let mut header = [0u8; 3];
            server.read_exact(&mut header).await.unwrap();
            let mut conn = yamux::Connection::new(
                server.compat(),
                yamux::Config::default(),
                yamux::Mode::Server,
            );
            while let Some(Ok(mut stream)) =
                std::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await
            {
                tokio::spawn(async move {
                    let _ = stream.close().await;
                });
            }
        });
        let spec = MuxSpec {
            protocol: MuxProtocol::Yamux,
            max_connections: 1,
            min_streams: 1,
            max_streams: 64,
            padding: false,
            only_tcp: true,
            brutal: None,
        };
        let session = Arc::new(Session::new(Box::new(client), &spec).await.unwrap());
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let session = session.clone();
                tokio::spawn(
                    async move { session.open().await.map(|_| ()).map_err(|e| e.to_string()) },
                )
            })
            .collect();
        let mut failures = Vec::new();
        for task in tasks {
            if let Err(e) = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap()
            {
                failures.push(e);
            }
        }
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// 回归：h2mux 的单流窗口固定 64 KiB 时，单流下载被往返时延卡死（千兆有线上 ~85 Mbit/s）。
    /// 服务端看到的发送额度就是客户端通告的窗口：单流时应接近连接预算，流数多了再收窄。
    #[tokio::test]
    async fn h2mux_stream_window_follows_the_number_of_streams() {
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<usize>();
        tokio::spawn(async move {
            let mut header = [0u8; 3];
            server.read_exact(&mut header).await.unwrap();
            let mut conn = h2::server::Builder::new()
                .max_send_buffer_size(8 * 1024 * 1024)
                .handshake(server)
                .await
                .unwrap();
            while let Some(Ok((_request, mut respond))) = conn.accept().await {
                let seen = seen_tx.clone();
                tokio::spawn(async move {
                    let mut send: h2::SendStream<Bytes> = respond
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    send.reserve_capacity(8 * 1024 * 1024);
                    let granted = std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .and_then(|r| r.ok())
                        .unwrap_or(0);
                    let _ = seen.send(granted);
                    // 保持流打开，直到客户端断开
                    std::future::pending::<()>().await;
                });
            }
        });
        let spec = MuxSpec {
            protocol: MuxProtocol::H2Mux,
            max_connections: 1,
            min_streams: 1,
            max_streams: 32,
            padding: false,
            only_tcp: true,
            brutal: None,
        };
        let session = Session::new(Box::new(client), &spec).await.unwrap();
        session.retune(1);
        let _first = session.open().await.unwrap();
        let granted = tokio::time::timeout(Duration::from_secs(5), seen_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            granted >= 1024 * 1024,
            "single stream window {granted} should be at least 1 MiB"
        );
    }

    struct Carrier(Arc<AtomicUsize>);
    #[async_trait]
    impl Outbound for Carrier {
        fn tag(&self) -> &str {
            "P"
        }
        fn kind(&self) -> &'static str {
            "anytls"
        }
        async fn connect_tcp(&self, _: &TargetAddr) -> io::Result<BoxStream> {
            self.0.fetch_add(1, Ordering::Relaxed);
            let (stream, mut peer) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut buf = [0; 4096];
                while peer.read(&mut buf).await.is_ok_and(|n| n > 0) {}
            });
            Ok(Box::new(stream))
        }
        async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
            Err(err("TCP only"))
        }
    }
    #[tokio::test]
    async fn brutal_exchange_success_and_remote_error() {
        let spec = oryn_config::BrutalSpec {
            up_mbps: 50,
            down_mbps: 100,
        };
        // 成功：服务端回 状态 0、ok、它的接收带宽
        let (a, mut b) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut request = [0u8; 2 + 1 + 1 + 17 + 2 + 8];
            b.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..2], &[0, 0]);
            assert_eq!(request[2], 3);
            assert_eq!(request[3], 17);
            assert_eq!(&request[4..21], b"_BrutalBwExchange");
            assert_eq!(
                u64::from_be_bytes(request[23..31].try_into().unwrap()),
                100 * 125_000
            );
            let mut reply = vec![0, 1];
            reply.extend_from_slice(&(7_000_000u64).to_be_bytes());
            b.write_all(&reply).await.unwrap();
        });
        let mut stream: BoxStream = Box::new(a);
        brutal_exchange(&mut stream, &spec).await.unwrap();
        server.await.unwrap();
        // 失败：服务端未启用或平台不支持
        let (a, mut b) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut request = [0u8; 31];
            b.read_exact(&mut request).await.unwrap();
            let message = b"brutal is not enabled by the server";
            let mut reply = vec![0, 0, message.len() as u8];
            reply.extend_from_slice(message);
            b.write_all(&reply).await.unwrap();
        });
        let mut stream: BoxStream = Box::new(a);
        let error = brutal_exchange(&mut stream, &spec).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("brutal is not enabled by the server"),
            "{error}"
        );
        server.await.unwrap();
        // 流被拒绝
        let (a, mut b) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut request = [0u8; 31];
            b.read_exact(&mut request).await.unwrap();
            b.write_all(&[1]).await.unwrap();
        });
        let mut stream: BoxStream = Box::new(a);
        assert!(brutal_exchange(&mut stream, &spec).await.is_err());
    }

    fn any_spec(target: &TargetAddr) -> oryn_config::AnyTlsSpec {
        oryn_config::AnyTlsSpec {
            server: target.clone(),
            password: "test".into(),
            tls: oryn_config::TlsSpec {
                sni: None,
                skip_cert_verify: false,
                alpn: Vec::new(),
                fingerprint: None,
                client_fingerprint: None,
                reality: None,
                ech: None,
            },
            idle_check_secs: 30,
            idle_timeout_secs: 30,
            min_idle_sessions: 0,
            udp: false,
        }
    }

    /// 并发的流各占一个会话（不在同一会话上排队），会话满后按负载最小共享。
    #[tokio::test]
    async fn anytls_gives_concurrent_streams_their_own_sessions() {
        let target = TargetAddr::Domain("example.test".into(), 443);
        let count = Arc::new(AtomicUsize::new(0));
        let out = MuxOutbound::any(Arc::new(Carrier(count.clone())), any_spec(&target));
        let mut live = Vec::new();
        for _ in 0..ANY_MAX_SESSIONS {
            live.push(out.connect_tcp(&target).await.unwrap());
        }
        assert_eq!(count.load(Ordering::Relaxed), ANY_MAX_SESSIONS);
        // 会话满：额外的流平均分摊，不会全部落在第一个会话上
        for _ in 0..ANY_MAX_SESSIONS {
            live.push(out.connect_tcp(&target).await.unwrap());
        }
        assert_eq!(count.load(Ordering::Relaxed), ANY_MAX_SESSIONS);
        let pool = out.pool.lock().await;
        assert!(pool.iter().all(|e| e.active.load(Ordering::Acquire) == 2));
        drop(pool);
        // 流结束后会话空闲，下一条流复用它而不是新建
        live.clear();
        drop(out.connect_tcp(&target).await.unwrap());
        assert_eq!(count.load(Ordering::Relaxed), ANY_MAX_SESSIONS);
    }

    /// 握手较慢（300 ms）时，并发建立的会话不能在池锁上排队：
    /// 之前持锁握手，32 条并发连接要 9.6 秒，测速时集体超过 10 秒的连接超时。
    #[tokio::test]
    async fn anytls_handshakes_run_concurrently() {
        struct Slow(Arc<AtomicUsize>);
        #[async_trait]
        impl Outbound for Slow {
            fn tag(&self) -> &str {
                "P"
            }
            fn kind(&self) -> &'static str {
                "anytls"
            }
            async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
                tokio::time::sleep(Duration::from_millis(300)).await;
                Carrier(self.0.clone()).connect_tcp(target).await
            }
            async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
                Err(err("TCP only"))
            }
        }
        let target = TargetAddr::Domain("example.test".into(), 443);
        let count = Arc::new(AtomicUsize::new(0));
        let out = Arc::new(MuxOutbound::any(
            Arc::new(Slow(count.clone())),
            any_spec(&target),
        ));
        let started = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..ANY_MAX_SESSIONS + 8 {
            let out = out.clone();
            let target = target.clone();
            tasks.spawn(async move { out.connect_tcp(&target).await.map(|_| ()) });
        }
        while let Some(r) = tasks.join_next().await {
            // 名额都在握手中时，超出上限的请求等待握手完成后共享会话，而不是失败
            r.unwrap().unwrap();
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(count.load(Ordering::Relaxed), ANY_MAX_SESSIONS);
        assert_eq!(out.connecting.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn anytls_reaps_idle_sessions_and_preserves_minimum() {
        let target = TargetAddr::Domain("example.test".into(), 443);
        let mut pools = Vec::new();
        for minimum in [0, 1] {
            let count = Arc::new(AtomicUsize::new(0));
            let spec = oryn_config::AnyTlsSpec {
                idle_check_secs: 1,
                idle_timeout_secs: 1,
                min_idle_sessions: minimum,
                ..any_spec(&target)
            };
            let out = MuxOutbound::any(Arc::new(Carrier(count.clone())), spec);
            drop(out.connect_tcp(&target).await.unwrap());
            drop(out.connect_tcp(&target).await.unwrap());
            assert_eq!(count.load(Ordering::Relaxed), 1);
            pools.push((out, count, minimum));
        }
        tokio::time::sleep(Duration::from_millis(2200)).await;
        for (out, count, minimum) in pools {
            drop(out.connect_tcp(&target).await.unwrap());
            assert_eq!(
                count.load(Ordering::Relaxed),
                if minimum == 0 { 2 } else { 1 }
            );
        }
    }
}
