//! Mekya HTTP 外层：有限 POST 上传 + 流式 packet bundle 响应。
//!
//! 依据 mihomo v1.19.32 transport/mekya 的线协议独立实现，未移植 Go 源码。
//! 长度为大端 u16，session 为 16 随机字节的 Base64URL。
//! HTTP 缓存、请求并发、队列均有上限，生命周期随 mKCP 关闭。

use base64::Engine;
use bytes::Bytes;
use oryn_config::MekyaSpec;
use std::{
    future::{poll_fn, Future},
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, Mutex, Notify},
    task::{JoinHandle, JoinSet},
};
const MAX_PACKET: usize = 1500;
const MAX_HEADER: usize = 32 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(240);
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub fn encode_bundle(packet: &[u8]) -> io::Result<Vec<u8>> {
    if packet.is_empty() || packet.len() > MAX_PACKET {
        return Err(invalid("Mekya packet length invalid"));
    }
    let mut out = Vec::with_capacity(packet.len() + 2);
    out.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    out.extend_from_slice(packet);
    Ok(out)
}
pub trait MekyaIoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> MekyaIoStream for T {}
pub type MekyaStream = Box<dyn MekyaIoStream>;
/// 工厂必须通过宿主 Dialer 完成外层连接；bool 为实际协商的 h2 ALPN。
pub type MekyaDial = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<(MekyaStream, bool)>> + Send>> + Send + Sync,
>;
struct AbortTask(JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
/// 最多保留一个未完成 bundle；允许 HTTP frame/chunk 包含多个 bundle。
#[derive(Default)]
struct Decoder {
    pending: Vec<u8>,
}
impl Decoder {
    fn feed(&mut self, mut data: &[u8], tx: &mpsc::Sender<Vec<u8>>) -> io::Result<()> {
        while !data.is_empty() {
            if self.pending.len() < 2 {
                let n = (2 - self.pending.len()).min(data.len());
                self.pending.extend_from_slice(&data[..n]);
                data = &data[n..];
                if self.pending.len() < 2 {
                    break;
                }
            }
            let len = u16::from_be_bytes([self.pending[0], self.pending[1]]) as usize;
            // HTTP bundle 与裸 mKCP 接收端共享余量：上游 seeded MSS 未扣 nonce。
            // 仅放宽接收，encode_bundle 与本机发送仍遵守 1500 字节上限。
            if len == 0 || len > crate::kcp::MAX_WIRE_PACKET {
                return Err(invalid("Mekya packet length invalid"));
            }
            let n = (len + 2 - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.pending.len() == len + 2 {
                let packet = self.pending[2..].to_vec();
                self.pending.clear();
                match tx.try_send(packet) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "Mekya reader closed",
                        ));
                    }
                }
                // 满载按数据报语义丢弃，由 mKCP 重传；避免 HTTP 响应与 ACK
                // 上传的双向回压形成环形等待。
            }
        }
        Ok(())
    }
    fn finish(self) -> io::Result<()> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(invalid("Mekya response truncated bundle"))
        }
    }
}
struct Endpoint {
    uri: http::Uri,
    authority: String,
    path: String,
    session: String,
}
impl Endpoint {
    fn new(url: &str, host: &str) -> io::Result<Self> {
        let url = if url.is_empty() {
            format!("https://{host}/")
        } else {
            url.to_owned()
        };
        if url.len() > 2048 || url.contains('#') {
            return Err(invalid("Mekya URL invalid"));
        }
        let uri: http::Uri = url.parse().map_err(|_| invalid("Mekya URL invalid"))?;
        if uri.scheme_str() != Some("https") {
            return Err(invalid("Mekya URL must use https"));
        }
        let authority = uri
            .authority()
            .ok_or_else(|| invalid("Mekya URL authority missing"))?
            .to_string();
        if authority.contains('@') || authority.len() > 512 {
            return Err(invalid("Mekya URL authority invalid"));
        }
        let path = uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_owned();
        Ok(Self {
            uri,
            authority,
            path,
            session: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(crate::random_bytes(16)),
        })
    }
}
async fn read_line<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        if line.len() >= limit {
            return Err(invalid("Mekya HTTP line exceeds limit"));
        }
        line.push(stream.read_u8().await?);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}
struct Ready {
    accepted: AtomicBool,
    notify: Arc<Notify>,
}
impl Ready {
    fn accepted(&self) {
        self.accepted.store(true, Ordering::Release);
        self.notify.notify_one();
    }
}

struct H1Head {
    chunked: bool,
    length: Option<usize>,
    reusable: bool,
}
async fn read_h1_head(stream: &mut MekyaStream) -> io::Result<H1Head> {
    let status = read_line(stream, MAX_HEADER).await?;
    let text = std::str::from_utf8(&status).map_err(|_| invalid("Mekya HTTP status invalid"))?;
    let mut parts = text.split_whitespace();
    let version = parts.next();
    if !matches!(version, Some("HTTP/1.1" | "HTTP/1.0")) || parts.next() != Some("200") {
        return Err(invalid("Mekya HTTP response was not 200"));
    }
    let mut head = H1Head {
        chunked: false,
        length: None,
        reusable: version == Some("HTTP/1.1"),
    };
    let mut total = status.len();
    loop {
        let line = read_line(stream, MAX_HEADER.saturating_sub(total)).await?;
        total += line.len();
        if line == b"\r\n" {
            break;
        }
        let line = std::str::from_utf8(&line).map_err(|_| invalid("Mekya HTTP header invalid"))?;
        let (key, value) = line
            .trim_end()
            .split_once(':')
            .ok_or_else(|| invalid("Mekya HTTP header invalid"))?;
        let value = value.trim();
        if key.eq_ignore_ascii_case("content-length") {
            if head.length.is_some() {
                return Err(invalid("Mekya duplicate Content-Length"));
            }
            head.length = Some(
                value
                    .parse()
                    .map_err(|_| invalid("Mekya Content-Length invalid"))?,
            );
        } else if key.eq_ignore_ascii_case("transfer-encoding") {
            if head.chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(invalid("Mekya Transfer-Encoding invalid"));
            }
            head.chunked = true;
        } else if key.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("close"))
        {
            head.reusable = false;
        }
    }
    if head.chunked && head.length.is_some() {
        return Err(invalid("Mekya ambiguous HTTP framing"));
    }
    Ok(head)
}
async fn read_h1_body(
    stream: &mut MekyaStream,
    head: &H1Head,
    tx: &mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    let mut decoder = Decoder::default();
    let mut scratch = [0u8; 8192];
    if head.chunked {
        loop {
            let line = read_line(stream, 1024).await?;
            let line =
                std::str::from_utf8(&line).map_err(|_| invalid("Mekya HTTP chunk invalid"))?;
            let mut remaining =
                usize::from_str_radix(line.trim().split(';').next().unwrap_or_default(), 16)
                    .map_err(|_| invalid("Mekya HTTP chunk invalid"))?;
            if remaining == 0 {
                let mut total = 0;
                loop {
                    let line = read_line(stream, MAX_HEADER - total).await?;
                    total += line.len();
                    if line == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            while remaining > 0 {
                let n = remaining.min(scratch.len());
                stream.read_exact(&mut scratch[..n]).await?;
                decoder.feed(&scratch[..n], tx)?;
                remaining -= n;
            }
            let mut end = [0; 2];
            stream.read_exact(&mut end).await?;
            if end != *b"\r\n" {
                return Err(invalid("Mekya HTTP chunk terminator invalid"));
            }
        }
    } else {
        let mut remaining = head.length;
        while remaining != Some(0) {
            let n = remaining.unwrap_or(scratch.len()).min(scratch.len());
            let read = stream.read(&mut scratch[..n]).await?;
            if read == 0 {
                if remaining.is_some() {
                    return Err(invalid("Mekya HTTP body truncated"));
                }
                break;
            }
            decoder.feed(&scratch[..read], tx)?;
            if let Some(left) = &mut remaining {
                *left -= read;
            }
        }
    }
    decoder.finish()
}
async fn request_h1(
    mut stream: MekyaStream,
    endpoint: &Endpoint,
    body: &[u8],
    tx: &mpsc::Sender<Vec<u8>>,
    ready: Option<&Ready>,
) -> io::Result<Option<MekyaStream>> {
    let request = format!("POST {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nContent-Length: {}\r\nX-Session-ID: {}\r\nContent-Type: application/octet-stream\r\n\r\n", endpoint.path, endpoint.authority, body.len(), endpoint.session);
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    let head = read_h1_head(&mut stream).await?;
    if let Some(ready) = ready {
        ready.accepted();
    }
    read_h1_body(&mut stream, &head, tx).await?;
    Ok((head.reusable && (head.chunked || head.length.is_some())).then_some(stream))
}
async fn request_h2(
    sender: h2::client::SendRequest<Bytes>,
    endpoint: &Endpoint,
    body: Vec<u8>,
    tx: &mpsc::Sender<Vec<u8>>,
    ready: &Ready,
) -> io::Result<()> {
    let mut sender = sender.ready().await.map_err(io::Error::other)?;
    let request = http::Request::builder()
        .method("POST")
        .uri(endpoint.uri.clone())
        .header("x-session-id", &endpoint.session)
        .header("content-type", "application/octet-stream")
        .header("content-length", body.len())
        .body(())
        .map_err(io::Error::other)?;
    let (response, mut send) = sender
        .send_request(request, body.is_empty())
        .map_err(io::Error::other)?;
    let mut body = Bytes::from(body);
    while !body.is_empty() {
        send.reserve_capacity(body.len().min(16 * 1024));
        let capacity = poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| invalid("Mekya HTTP/2 upload closed"))?
            .map_err(io::Error::other)?;
        if capacity == 0 {
            continue;
        }
        let n = body.len().min(capacity).min(16 * 1024);
        let data = body.split_to(n);
        send.send_data(data, body.is_empty())
            .map_err(io::Error::other)?;
    }
    let response = response.await.map_err(io::Error::other)?;
    if response.status() != http::StatusCode::OK {
        return Err(invalid("Mekya HTTP/2 response was not 200"));
    }
    ready.accepted();
    let mut recv = response.into_body();
    let mut decoder = Decoder::default();
    while let Some(data) = recv.data().await {
        let data = data.map_err(io::Error::other)?;
        decoder.feed(&data, tx)?;
        recv.flow_control()
            .release_capacity(data.len())
            .map_err(io::Error::other)?;
    }
    decoder.finish()
}
enum Connection {
    H1(MekyaStream),
    H2 {
        sender: h2::client::SendRequest<Bytes>,
        _driver: AbortTask,
    },
}
struct Pool {
    slots: Vec<Mutex<Option<Connection>>>,
    next: AtomicUsize,
    dial: MekyaDial,
}
impl Pool {
    async fn request(
        &self,
        endpoint: &Endpoint,
        body: Vec<u8>,
        tx: &mpsc::Sender<Vec<u8>>,
        ready: &Ready,
    ) -> io::Result<()> {
        let slot = &self.slots[self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len()];
        let mut entry = slot.lock().await;
        if entry.is_none() {
            let (stream, h2) = (self.dial)().await?;
            *entry = Some(if h2 {
                let mut builder = h2::client::Builder::new();
                builder
                    .initial_window_size(64 * 1024)
                    .initial_connection_window_size(256 * 1024)
                    .max_concurrent_streams(32)
                    .max_header_list_size(MAX_HEADER as u32);
                let (sender, connection) =
                    builder.handshake(stream).await.map_err(io::Error::other)?;
                let driver = AbortTask(tokio::spawn(async move {
                    let _ = connection.await;
                }));
                Connection::H2 {
                    sender,
                    _driver: driver,
                }
            } else {
                Connection::H1(stream)
            });
        }
        match entry.as_ref().unwrap() {
            Connection::H2 { sender, .. } => {
                let sender = sender.clone();
                drop(entry);
                let result = request_h2(sender, endpoint, body, tx, ready).await;
                if result.is_err() {
                    *slot.lock().await = None;
                }
                result
            }
            Connection::H1(_) => {
                let Some(Connection::H1(stream)) = entry.take() else {
                    unreachable!()
                };
                drop(entry);
                let reusable = request_h1(stream, endpoint, &body, tx, Some(ready)).await?;
                if let Some(stream) = reusable {
                    let mut entry = slot.lock().await;
                    if entry.is_none() {
                        *entry = Some(Connection::H1(stream));
                    }
                }
                Ok(())
            }
        }
    }
}
struct MekyaIo {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    _worker: AbortTask,
}
impl crate::kcp::PacketIo for MekyaIo {
    fn send<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if packet.is_empty() || packet.len() > MAX_PACKET {
                return Err(invalid("Mekya packet length invalid"));
            }
            self.tx
                .send(packet.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Mekya writer closed"))
        })
    }
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let packet = self.rx.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "Mekya reader closed")
            })?;
            if packet.len() > buf.len() {
                return Err(invalid("Mekya packet exceeds mKCP MTU"));
            }
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        })
    }
}
async fn collect_batch(
    rx: &mut mpsc::Receiver<Vec<u8>>,
    deferred: &mut Option<Vec<u8>>,
    spec: &MekyaSpec,
) -> io::Result<Option<Vec<u8>>> {
    let first = if let Some(packet) = deferred.take() {
        Some(packet)
    } else {
        tokio::select! {
            packet = rx.recv() => { if packet.is_none() { return Ok(None); } packet },
            _ = tokio::time::sleep(Duration::from_millis(spec.polling_interval_initial_ms)) => None,
        }
    };
    let Some(first) = first else {
        return Ok(Some(Vec::new()));
    };
    let mut body = encode_bundle(&first)?;
    let deadline = tokio::time::sleep(Duration::from_millis(spec.max_write_delay_ms));
    tokio::pin!(deadline);
    loop {
        let packet = match rx.try_recv() {
            Ok(packet) => packet,
            Err(mpsc::error::TryRecvError::Disconnected) => break,
            Err(mpsc::error::TryRecvError::Empty) if spec.max_write_delay_ms == 0 => break,
            Err(mpsc::error::TryRecvError::Empty) => tokio::select! {
                _ = &mut deadline => break,
                packet = rx.recv() => match packet { Some(packet) => packet, None => break },
            },
        };
        let frame = encode_bundle(&packet)?;
        if body.len() + frame.len() > spec.max_request_size {
            *deferred = Some(packet);
            break;
        }
        body.extend_from_slice(&frame);
    }
    Ok(Some(body))
}
async fn run(
    spec: MekyaSpec,
    endpoint: Endpoint,
    dial: MekyaDial,
    mut rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
) {
    let pool = Arc::new(Pool {
        slots: (0..spec.h2_pool_size.clamp(1, 8))
            .map(|_| Mutex::new(None))
            .collect(),
        next: AtomicUsize::new(0),
        dial,
    });
    let endpoint = Arc::new(endpoint);
    let mut tasks: JoinSet<io::Result<()>> = JoinSet::new();
    let mut handles = std::collections::VecDeque::<(tokio::task::AbortHandle, Arc<Ready>)>::new();
    let notify = Arc::new(Notify::new());
    let mut deferred = None;
    let mut errors = 0;
    loop {
        handles.retain(|(handle, _)| !handle.is_finished());
        // 上游服务器通过新请求淘汰最旧的下载响应。这里主动回收已确认
        // 收到上传的响应，避免长轮询占满并发后，ACK/新上传只能等超时。
        // 未收到 HTTP 200 的上传不得取消，否则可能丢掉尚未送达的请求体。
        while tasks.len() >= spec.max_simultaneous_write_connections.clamp(1, 32) {
            if deferred.is_some() || !rx.is_empty() {
                if let Some(index) = handles
                    .iter()
                    .position(|(_, ready)| ready.accepted.load(Ordering::Acquire))
                {
                    let (handle, _) = handles.remove(index).unwrap();
                    handle.abort();
                }
            }
            let result = tokio::select! {
                result = tasks.join_next() => result,
                packet = rx.recv(), if deferred.is_none() => {
                    let Some(packet) = packet else { return; };
                    deferred = Some(packet);
                    continue;
                }
                _ = notify.notified() => continue,
            };
            match result {
                Some(Ok(Ok(()))) => errors = 0,
                Some(Ok(Err(error))) if error.kind() == io::ErrorKind::InvalidData => return,
                Some(Err(error)) if error.is_cancelled() => {}
                Some(_) => errors += 1,
                None => break,
            }
            if errors >= 8 {
                return;
            }
        }
        while let Some(result) = tasks.try_join_next() {
            match result {
                Ok(Ok(())) => errors = 0,
                Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => return,
                Err(error) if error.is_cancelled() => {}
                _ => errors += 1,
            }
        }
        if errors >= 8 {
            return;
        }
        let body = match collect_batch(&mut rx, &mut deferred, &spec).await {
            Ok(Some(body)) => body,
            _ => return,
        };
        let pool = pool.clone();
        let endpoint = endpoint.clone();
        let tx = tx.clone();
        let ready = Arc::new(Ready {
            accepted: AtomicBool::new(false),
            notify: notify.clone(),
        });
        let request_ready = ready.clone();
        let handle = tasks.spawn(async move {
            tokio::time::timeout(
                REQUEST_TIMEOUT,
                pool.request(&endpoint, body, &tx, &request_ready),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Mekya HTTP request timed out"))?
        });
        handles.push_back((handle, ready));
    }
}

pub async fn connect_kcp_dial(
    spec: &MekyaSpec,
    host: String,
    dial: MekyaDial,
) -> io::Result<crate::KcpStream> {
    let endpoint = Endpoint::new(&spec.url, &host)?;
    if spec.max_request_size < usize::from(spec.kcp.mtu) + 2 || spec.max_request_size > 1024 * 1024
    {
        return Err(invalid("Mekya request limit must fit one mKCP packet"));
    }
    let (tx, writer_rx) = mpsc::channel(spec.packet_writing_buffer.clamp(16, 4096));
    let (reader_tx, rx) = mpsc::channel((spec.kcp.read_buffer_size / MAX_PACKET).clamp(8, 128));
    let worker = AbortTask(tokio::spawn(run(
        spec.clone(),
        endpoint,
        dial,
        writer_rx,
        reader_tx,
    )));
    crate::KcpStream::connect_io(
        MekyaIo {
            tx,
            rx,
            _worker: worker,
        },
        &spec.kcp,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decoder_accepts_seeded_peer_nonce_margin_but_keeps_send_mtu() {
        let (tx, mut rx) = mpsc::channel(2);
        let mut decoder = Decoder::default();
        // mihomo MTU=1500 的 seeded 满 MSS 包另带 12 字节 nonce。
        let mut bundle = 1512u16.to_be_bytes().to_vec();
        bundle.extend_from_slice(&[0x5a; 1512]);
        for part in bundle.chunks(7) {
            decoder.feed(part, &tx).unwrap();
        }
        assert_eq!(rx.try_recv().unwrap(), vec![0x5a; 1512]);
        decoder.finish().unwrap();
        assert!(encode_bundle(&[0; 1501]).is_err(), "local output MTU is unchanged");
        let mut decoder = Decoder::default();
        assert!(decoder.feed(&1565u16.to_be_bytes(), &tx).is_err());
    }

    #[test]
    fn bundles_allow_merged_frames_and_reject_truncation() {
        let (tx, mut rx) = mpsc::channel(8);
        let frame = encode_bundle(&[5; 1500]).unwrap();
        let merged = [frame.clone(), frame].concat();
        let mut decoder = Decoder::default();
        for chunk in merged.chunks(71) {
            decoder.feed(chunk, &tx).unwrap();
        }
        decoder.finish().unwrap();
        assert_eq!(rx.try_recv().unwrap(), vec![5; 1500]);
        assert_eq!(rx.try_recv().unwrap(), vec![5; 1500]);
        let mut decoder = Decoder::default();
        decoder.feed(b"\0\x03ab", &tx).unwrap();
        assert!(decoder.finish().is_err());
        assert!(encode_bundle(&[]).is_err());
    }
    #[tokio::test]
    async fn h1_streams_bundles_before_response_ends_and_reuses() {
        let (client, mut server) = tokio::io::duplex(32 * 1024);
        let (tx, mut rx) = mpsc::channel(8);
        let task = tokio::spawn(async move {
            let endpoint = Endpoint::new("https://proxy.test/mekya?a=1", "unused").unwrap();
            request_h1(
                Box::new(client),
                &endpoint,
                &encode_bundle(b"abc").unwrap(),
                &tx,
                None,
            )
            .await
            .unwrap()
        });
        let server_task = tokio::spawn(async move {
            let mut length = 0;
            loop {
                let line = read_line(&mut server, MAX_HEADER).await.unwrap();
                if line.starts_with(b"Content-Length: ") {
                    length = 5;
                }
                if line == b"\r\n" {
                    break;
                }
            }
            let mut body = vec![0; length];
            server.read_exact(&mut body).await.unwrap();
            assert_eq!(body, b"\0\x03abc");
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n\0\x03abc\r\n",
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            server.write_all(b"0\r\nX-T: ok\r\n\r\n").await.unwrap();
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            b"abc"
        );
        assert!(task.await.unwrap().is_some());
        server_task.await.unwrap();
    }
    #[tokio::test]
    async fn h1_rejects_truncated_and_ambiguous_responses() {
        for response in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n\0\x03ab"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\0\x03ab"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"[..],
        ] {
            let (client, mut server) = tokio::io::duplex(4096);
            let response = response.to_vec();
            let server_task = tokio::spawn(async move {
                loop {
                    if read_line(&mut server, MAX_HEADER).await.unwrap() == b"\r\n" {
                        break;
                    }
                }
                server.write_all(&response).await.unwrap();
            });
            let (tx, _rx) = mpsc::channel(8);
            let endpoint = Endpoint::new("https://proxy.test/", "unused").unwrap();
            assert!(request_h1(Box::new(client), &endpoint, &[], &tx, None)
                .await
                .is_err());
            server_task.await.unwrap();
        }
    }
}
