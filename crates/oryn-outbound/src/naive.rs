//! NaïveProxy 出站：TLS（可用浏览器指纹）+ HTTP/2/HTTP/3 CONNECT，纯 Rust 实现，不用 Cronet。
//!
//! 填充协议按 sing-box protocol/naive/inbound_conn.go（commit 见 Oryn_dev/docs/oryncore/provenance.md）与 NaïveProxy 的公开说明独立实现：
//! 请求与响应都带 `padding` 首部（30–61 个字符）；之后每个方向的前 8 个数据块写成
//! 「数据长度 u16 + 填充长度 u8 + 数据 + 零填充」，再往后是原始字节。
//!
//! 同一出站的 Flow 共享有界的 h2 连接池（与 gRPC / `network: h2` 相同）。SETTINGS 的首部表大小与首部列表上限按 Chrome 取值，
//! 窗口仍用有界的值（Chrome 的 6 / 15 MiB 窗口超出 Extension 的内存预算），h2 crate 也不能调整伪首部顺序：
//! 这两点使它的 HTTP/2 指纹与 Chrome 不完全一致，见 docs/protocols/naive.md。
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use base64::Engine;
use bytes::{Buf, Bytes};
use oryn_config::{NaiveSpec, TargetAddr};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

#[cfg(feature = "hysteria2")]
use oryn_quic::{Congestion, QuicClient, QuicParams};

use crate::{wrap_tls, BoxStream, Dialer, Outbound, PacketConn};

/// 带填充的数据块个数（每个方向）。
const PADDING_FRAMES: u8 = 8;
const MAX_FRAME: usize = 65535;

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    // 填充只用来扰乱长度，系统随机源失败时退回全零不影响正确性
    let _ = SystemRandom::new().fill(&mut out);
    out
}

/// `padding` 首部：16 个取自固定字符集的随机字符，其余为 `~`，总长 30–61。
fn padding_header() -> String {
    let r = random_bytes::<9>();
    let len = 30 + (r[0] as usize % 32);
    let mut bits = u64::from_le_bytes(r[1..9].try_into().unwrap());
    const CHARS: &[u8; 16] = b"!#$()+<>?@[]^`{}";
    let mut out = String::with_capacity(len);
    for _ in 0..16 {
        out.push(CHARS[(bits & 15) as usize] as char);
        bits >>= 4;
    }
    out.extend(std::iter::repeat_n('~', len - 16));
    out
}

pub(crate) struct NaiveOutbound {
    name: String,
    spec: NaiveSpec,
    dialer: Arc<dyn Dialer>,
    resolver: Arc<dyn crate::Resolver>,
    #[cfg(feature = "hysteria2")]
    quic: Option<Arc<QuicClient>>,
    #[cfg(feature = "hysteria2")]
    h3: AsyncMutex<Option<H3Client>>,
    pool: oryn_transport::GrpcPool,
}

impl NaiveOutbound {
    pub(crate) fn new(
        name: String,
        spec: NaiveSpec,
        dialer: Arc<dyn Dialer>,
        resolver: Arc<dyn crate::Resolver>,
        datagrams: Arc<dyn oryn_udp::DatagramFactory>,
    ) -> Arc<Self> {
        #[cfg(feature = "hysteria2")]
        let quic = spec.quic.then(|| {
            QuicClient::new(QuicParams {
                datagrams,
                alpn: vec![b"h3".to_vec()],
                skip_verify: spec.tls.skip_cert_verify,
                fingerprint: spec.tls.fingerprint,
                disable_sni: false,
                congestion: Congestion::Bbr,
                brutal_rate: None,
                obfs: None,
                hop: None,
                rendezvous: None,
                zero_rtt: false,
            })
        });
        #[cfg(not(feature = "hysteria2"))]
        let _ = datagrams;
        Arc::new(Self {
            name,
            spec,
            dialer,
            resolver,
            #[cfg(feature = "hysteria2")]
            quic,
            #[cfg(feature = "hysteria2")]
            h3: AsyncMutex::new(None),
            pool: oryn_transport::GrpcPool::chrome(),
        })
    }

    #[cfg(feature = "hysteria2")]
    async fn connect_h3(
        &self,
        authority: &str,
        headers: &[(String, String)],
    ) -> io::Result<BoxStream> {
        let (peer, port, server_name) = self.proxy_peer().await?;
        let quic = self.quic.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "naive HTTP/3 is not compiled in",
            )
        })?;
        let conn = quic.connection(peer, &server_name, port).await?;
        let mut send = {
            let mut cached = self.h3.lock().await;
            if cached
                .as_ref()
                .is_some_and(|client| client.id == conn.stable_id())
            {
                cached.as_ref().expect("checked above").send.clone()
            } else {
                let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
                    .await
                    .map_err(io::Error::other)?;
                tokio::spawn(async move {
                    let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                });
                *cached = Some(H3Client {
                    id: conn.stable_id(),
                    send: send.clone(),
                });
                send
            }
        };
        let request = {
            let mut req = http::Request::builder().method("CONNECT").uri(authority);
            for (name, value) in headers {
                req = req.header(name.as_str(), value.as_str());
            }
            req.body(()).map_err(io::Error::other)?
        };
        let mut stream = match send.send_request(request).await {
            Ok(stream) => stream,
            Err(err) => {
                self.invalidate_h3(conn.stable_id()).await;
                return Err(io::Error::other(err));
            }
        };
        let response = match stream.recv_response().await {
            Ok(response) => response,
            Err(err) => {
                self.invalidate_h3(conn.stable_id()).await;
                return Err(io::Error::other(err));
            }
        };
        if response.status().as_u16() != 200 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("naive HTTP/3 server returned HTTP {}", response.status()),
            ));
        }
        let (send, recv) = stream.split();
        Ok(Box::new(H3Stream::new(send, recv)))
    }

    #[cfg(feature = "hysteria2")]
    async fn proxy_peer(&self) -> io::Result<(IpAddr, u16, String)> {
        let port = self.spec.server.port();
        let server_name = self
            .spec
            .tls
            .sni
            .clone()
            .unwrap_or_else(|| match &self.spec.server {
                TargetAddr::Domain(host, _) => host.clone(),
                TargetAddr::Ip(addr) => addr.ip().to_string(),
            });
        let peer = match &self.spec.server {
            TargetAddr::Ip(addr) => addr.ip(),
            TargetAddr::Domain(host, _) => *self
                .resolver
                .resolve(host)
                .await?
                .first()
                .ok_or_else(|| io::Error::other("cannot resolve naive server"))?,
        };
        Ok((peer, port, server_name))
    }

    #[cfg(feature = "hysteria2")]
    async fn invalidate_h3(&self, id: usize) {
        let mut cached = self.h3.lock().await;
        if cached.as_ref().is_some_and(|client| client.id == id) {
            cached.take();
        }
    }
}

#[async_trait]
impl Outbound for NaiveOutbound {
    fn tag(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "naive"
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let authority = match target {
            TargetAddr::Domain(host, port) => format!("{host}:{port}"),
            TargetAddr::Ip(addr) => addr.to_string(),
        };
        let mut headers = Vec::with_capacity(self.spec.headers.len() + 2);
        if !self.spec.username.is_empty() || !self.spec.password.is_empty() {
            let token = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.spec.username, self.spec.password));
            headers.push(("proxy-authorization".to_string(), format!("Basic {token}")));
        }
        headers.push(("padding".to_string(), padding_header()));
        headers.extend(self.spec.headers.iter().cloned());
        if self.spec.quic {
            #[cfg(feature = "hysteria2")]
            {
                // 请求与响应头都要有显式期限，不只靠 QUIC 空闲超时兜底
                let stream = crate::with_timeout(
                    self.connect_h3(&authority, &headers),
                    "naive HTTP/3 CONNECT",
                )
                .await?;
                return Ok(Box::new(Padded::new(stream)));
            }
            #[cfg(not(feature = "hysteria2"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "naive HTTP/3 is not compiled in",
            ));
        }
        let stream = self
            .pool
            .open_connect(&authority, &headers, || async {
                let tcp = self.dialer.dial_tcp(&self.spec.server).await?;
                wrap_tls(tcp, &Some(self.spec.tls.clone()), &self.spec.server).await
            })
            .await?;
        Ok(Box::new(Padded::new(stream)))
    }
    async fn bind_udp(&self, first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        let Some(version) = self.spec.uot else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "naive udp is disabled",
            ));
        };
        let magic = TargetAddr::Domain(crate::uot::magic(version).into(), 0);
        let stream = self.connect_tcp(&magic).await?;
        Ok(Box::new(crate::uot::UotConn::new(
            stream,
            version,
            first_target,
        )?))
    }
}

#[cfg(feature = "hysteria2")]
type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
#[cfg(feature = "hysteria2")]
struct H3Client {
    id: usize,
    send: H3Sender,
}

#[cfg(feature = "hysteria2")]
type H3SendStream = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
#[cfg(feature = "hysteria2")]
type H3RecvStream = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

#[cfg(feature = "hysteria2")]
enum H3Command {
    Data(Bytes, oneshot::Sender<io::Result<()>>),
    Flush(oneshot::Sender<io::Result<()>>),
    Finish(oneshot::Sender<io::Result<()>>),
}

#[cfg(feature = "hysteria2")]
async fn h3_send_worker(mut send: H3SendGuard, mut commands: mpsc::Receiver<H3Command>) {
    while let Some(command) = commands.recv().await {
        match command {
            H3Command::Data(data, ack) => {
                let result = send.stream.send_data(data).await.map_err(io::Error::other);
                let failed = result.is_err();
                let _ = ack.send(result);
                if failed {
                    break;
                }
            }
            H3Command::Flush(ack) => {
                let _ = ack.send(Ok(()));
            }
            H3Command::Finish(ack) => {
                let result = send.stream.finish().await.map_err(io::Error::other);
                send.finished = result.is_ok();
                let _ = ack.send(result);
                break;
            }
        }
    }
}

/// 中止发送任务时必须 RESET_STREAM，不能让底层 Drop 尝试排空未发送的数据。
#[cfg(feature = "hysteria2")]
struct H3SendGuard {
    stream: H3SendStream,
    finished: bool,
}
#[cfg(feature = "hysteria2")]
impl Drop for H3SendGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.stream
                .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

#[cfg(feature = "hysteria2")]
struct H3Stream {
    recv: H3RecvStream,
    writer: H3Writer,
    read_buf: Bytes,
    eof: bool,
    send_task: tokio::task::JoinHandle<()>,
}
#[cfg(feature = "hysteria2")]
impl Drop for H3Stream {
    fn drop(&mut self) {
        self.recv
            .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        self.send_task.abort();
    }
}

/// 写状态独立于接收流，便于验证队列背压和 Future 取消边界。
#[cfg(feature = "hysteria2")]
struct H3Writer {
    commands: mpsc::Sender<H3Command>,
    closed: bool,
    failed: bool,
    pending_write: Option<Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>>,
    pending_flush: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
    pending_shutdown: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
}

#[cfg(feature = "hysteria2")]
impl H3Stream {
    fn new(send: H3SendStream, recv: H3RecvStream) -> Self {
        let (commands, rx) = mpsc::channel(8);
        // guard 在 spawn 前构造，任务尚未被 poll 就取消时也会重置发送方向。
        let send = H3SendGuard {
            stream: send,
            finished: false,
        };
        let send_task = tokio::spawn(h3_send_worker(send, rx));
        Self {
            recv,
            writer: H3Writer::new(commands),
            read_buf: Bytes::new(),
            eof: false,
            send_task,
        }
    }
}

#[cfg(feature = "hysteria2")]
impl H3Writer {
    fn new(commands: mpsc::Sender<H3Command>) -> Self {
        Self {
            commands,
            closed: false,
            failed: false,
            pending_write: None,
            pending_flush: None,
            pending_shutdown: None,
        }
    }

    fn drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Some(pending) = &mut self.pending_write {
            let result = ready!(pending.as_mut().poll(cx));
            self.pending_write = None;
            if let Err(error) = result {
                self.failed = true;
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "hysteria2")]
impl AsyncRead for H3Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if !this.read_buf.is_empty() {
                let take = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf.split_to(take));
                return Poll::Ready(Ok(()));
            }
            if this.eof || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let chunk = ready!(this.recv.poll_recv_data(cx)).map_err(io::Error::other)?;
            let Some(mut chunk) = chunk else {
                this.eof = true;
                return Poll::Ready(Ok(()));
            };
            if !chunk.has_remaining() {
                continue;
            }
            let take = chunk.remaining().min(buf.remaining());
            buf.put_slice(&chunk.copy_to_bytes(take));
            if chunk.has_remaining() {
                this.read_buf = chunk.copy_to_bytes(chunk.remaining());
            }
            return Poll::Ready(Ok(()));
        }
    }
}

#[cfg(feature = "hysteria2")]
impl AsyncWrite for H3Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.pending_flush.is_some() {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        let this = &mut *self;
        ready!(this.drain_write(cx))?;
        {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let data = Bytes::copy_from_slice(&buf[..buf.len().min(16 * 1024)]);
            let len = data.len();
            let commands = this.commands.clone();
            this.pending_write = Some(Box::pin(async move {
                let (ack_tx, ack_rx) = oneshot::channel();
                commands
                    .send(H3Command::Data(data, ack_tx))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "naive HTTP/3 stream closed")
                    })?;
                ack_rx.await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "naive HTTP/3 stream closed")
                })??;
                Ok(len)
            }));
            // 一旦保存当前缓冲，就报告已接受。Pending 只等待此前已接受的数据，
            // 不能在取消后把旧缓冲的长度当作下一次写入的结果。
            Poll::Ready(Ok(len))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return self.poll_shutdown(cx);
        }
        let this = &mut *self;
        ready!(this.drain_write(cx))?;
        if this.pending_flush.is_none() {
            let commands = this.commands.clone();
            this.pending_flush = Some(Box::pin(async move {
                let (ack_tx, ack_rx) = oneshot::channel();
                commands.send(H3Command::Flush(ack_tx)).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "naive HTTP/3 stream closed")
                })?;
                ack_rx.await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "naive HTTP/3 stream closed")
                })?
            }));
        }
        let pending = this.pending_flush.as_mut().expect("pending flush");
        match pending.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending_flush = None;
                this.failed = result.is_err();
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.closed && self.pending_shutdown.is_none() {
            return Poll::Ready(Ok(()));
        }
        if self.pending_shutdown.is_none() {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        let this = &mut *self;
        if this.pending_shutdown.is_none() {
            this.closed = true;
            let commands = this.commands.clone();
            this.pending_shutdown = Some(Box::pin(async move {
                let (ack_tx, ack_rx) = oneshot::channel();
                commands
                    .send(H3Command::Finish(ack_tx))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "naive HTTP/3 stream closed")
                    })?;
                ack_rx.await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "naive HTTP/3 stream closed")
                })?
            }));
        }
        let pending = this.pending_shutdown.as_mut().expect("pending shutdown");
        match pending.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending_shutdown = None;
                this.failed = result.is_err();
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "hysteria2")]
impl AsyncWrite for H3Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// 前 8 个数据块的填充分帧。
struct Padded<S> {
    inner: S,
    written_frames: u8,
    read_frames: u8,
    out: Vec<u8>,
    out_pos: usize,
    read_remaining: usize,
    padding_remaining: usize,
    header: [u8; 3],
    header_have: usize,
}

impl<S> Padded<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            written_frames: 0,
            read_frames: 0,
            out: Vec::new(),
            out_pos: 0,
            read_remaining: 0,
            padding_remaining: 0,
            header: [0; 3],
            header_have: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> Padded<S> {
    fn poll_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Padded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_out(cx))?;
        if this.written_frames >= PADDING_FRAMES {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        // 空写不占用填充帧配额，也不发出零长度块
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(MAX_FRAME);
        let padding = random_bytes::<1>()[0] as usize;
        this.out.reserve(3 + take + padding);
        this.out.extend_from_slice(&(take as u16).to_be_bytes());
        this.out.push(padding as u8);
        this.out.extend_from_slice(&buf[..take]);
        this.out.resize(this.out.len() + padding, 0);
        this.written_frames += 1;
        if let Poll::Ready(Err(err)) = this.poll_out(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_out(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_out(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Padded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.read_remaining > 0 {
                let limit = this.read_remaining.min(buf.remaining());
                let mut sub = ReadBuf::new(buf.initialize_unfilled_to(limit));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                buf.advance(n);
                this.read_remaining -= n;
                return Poll::Ready(Ok(()));
            }
            if this.padding_remaining > 0 {
                let mut skip = [0u8; 256];
                let take = this.padding_remaining.min(skip.len());
                let mut sub = ReadBuf::new(&mut skip[..take]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.padding_remaining -= n;
                continue;
            }
            if this.read_frames >= PADDING_FRAMES {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            while this.header_have < 3 {
                let mut sub = ReadBuf::new(&mut this.header[this.header_have..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                if n == 0 {
                    return if this.header_have == 0 {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                    };
                }
                this.header_have += n;
            }
            this.header_have = 0;
            this.read_frames += 1;
            this.read_remaining = u16::from_be_bytes([this.header[0], this.header[1]]) as usize;
            this.padding_remaining = this.header[2] as usize;
        }
    }
}

#[cfg(test)]
#[path = "naive_audit_tests.rs"]
mod audit_tests;

#[cfg(all(test, feature = "hysteria2"))]
#[path = "naive_h3_tests.rs"]
mod h3_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn padding_header_shape() {
        for _ in 0..32 {
            let header = padding_header();
            assert!((30..=61).contains(&header.len()));
            assert!(header[16..].chars().all(|c| c == '~'));
        }
    }

    #[tokio::test]
    async fn padded_roundtrip_past_padding_frames() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut a = Padded::new(a);
        let mut b = Padded::new(b);
        let chunks: Vec<Vec<u8>> = (0..12).map(|i| vec![i as u8; 100 * (i + 1)]).collect();
        for chunk in &chunks {
            a.write_all(chunk).await.unwrap();
        }
        a.flush().await.unwrap();
        let expected: Vec<u8> = chunks.concat();
        let mut got = vec![0u8; expected.len()];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
    }
}
