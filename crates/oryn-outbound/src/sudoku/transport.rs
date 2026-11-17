// HTTPMask 线协议移植自 MetaCubeX/mihomo transport/sudoku/obfs/httpmask
// @ 88dcbf7f1614a67c3b36b848ee3592dfa92ada36，GPL-3.0；原文件未单列版权声明。
// Oryn：仅 HTTP/1.1，头/分块/队列有界；上传序号用于有界重试，连接池最多 8 条。
use super::{bad, now, record};
use crate::{BoxStream, Dialer};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use oryn_config::{SudokuSpec, TargetAddr};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{
        AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
        DuplexStream, ReadBuf,
    },
    sync::Semaphore,
    time::Instant,
};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig};
use tokio_util::sync::CancellationToken;
struct Idle {
    io: BufReader<BoxStream>,
    at: Instant,
}
pub struct HttpPool {
    idle: Mutex<Vec<Idle>>,
    closing: Arc<Semaphore>,
}
impl Default for HttpPool {
    fn default() -> Self {
        Self {
            idle: Mutex::new(vec![]),
            closing: Arc::new(Semaphore::new(8)),
        }
    }
}
impl HttpPool {
    pub fn clear(&self) {
        self.idle.lock().unwrap().clear();
    }
}
#[derive(Clone)]
struct Client {
    spec: SudokuSpec,
    dialer: Arc<dyn Dialer>,
    pool: Arc<HttpPool>,
    mode: String,
    host: String,
    sni: String,
    target: TargetAddr,
}
fn client(
    spec: &SudokuSpec,
    dialer: Arc<dyn Dialer>,
    pool: Arc<HttpPool>,
    mode: &str,
) -> io::Result<Client> {
    let mut target = spec.server.clone();
    let mut sni = match &target {
        TargetAddr::Domain(h, _) => h.clone(),
        TargetAddr::Ip(a) => a.ip().to_string(),
    };
    let mut host = target.to_string();
    if !spec.http_host.is_empty() {
        let override_host = &spec.http_host;
        let (name, port) = if let Ok(address) = override_host.parse::<std::net::SocketAddr>() {
            (address.ip().to_string(), Some(address.port()))
        } else if let Some((name, p)) = override_host.rsplit_once(':') {
            if name.contains(':') {
                (override_host.trim_matches(['[', ']']).to_string(), None)
            } else {
                (
                    name.to_string(),
                    Some(
                        p.parse::<u16>()
                            .map_err(|_| bad("invalid HTTPMask host port"))?,
                    ),
                )
            }
        } else {
            (override_host.clone(), None)
        };
        if let Some(port) = port {
            if port == 0 {
                return Err(bad("invalid HTTPMask host port"));
            }
            target = match target {
                TargetAddr::Ip(mut a) => {
                    a.set_port(port);
                    TargetAddr::Ip(a)
                }
                TargetAddr::Domain(h, _) => TargetAddr::Domain(h, port),
            };
        }
        sni = name;
        host = TargetAddr::from_host(&sni, target.port()).to_string();
    }
    // mihomo 的 multiplex: off 只是不在隧道之间共享 HTTP 传输；每条隧道自己的 http.Transport 仍对
    // 连续的上传 POST 复用 keep-alive 连接。这里同样：off 时给这条隧道一个独立的空闲池，而不是每个
    // 请求新建 TCP（HTTPS 时还要再握手一次 TLS），否则上行被「每 POST 一次建连 + 慢启动」拖住。
    let pool = if spec.multiplex == "off" {
        Arc::new(HttpPool::default())
    } else {
        pool
    };
    Ok(Client {
        spec: spec.clone(),
        dialer,
        pool,
        mode: mode.into(),
        host,
        sni,
        target,
    })
}
impl Client {
    async fn socket(&self) -> io::Result<BoxStream> {
        let stream = self.dialer.dial_tcp(&self.target).await?;
        match &self.spec.tls {
            Some(tls) => Ok(Box::new(
                oryn_tls::connect_proxy(stream, &self.sni, tls).await?,
            )),
            None => Ok(stream),
        }
    }
    fn path(&self, path: &str) -> String {
        if self.spec.path_root.is_empty() {
            path.into()
        } else {
            format!("/{}{path}", self.spec.path_root)
        }
    }
    async fn request(&self, method: &str, path: &str, body: &[u8]) -> io::Result<Response> {
        let cached = {
            let mut idle = self.pool.idle.lock().unwrap();
            idle.retain(|c| c.at.elapsed() < Duration::from_secs(30));
            idle.pop().map(|c| c.io)
        };
        let mut io = match cached {
            Some(io) => io,
            None => BufReader::new(self.socket().await?),
        };
        let mime = if self.mode == "poll" {
            "text/plain"
        } else {
            "application/octet-stream"
        };
        let head=format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nX-Sudoku-Tunnel: {}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\n\r\n",self.host,self.mode,body.len());
        if head.len() > 16 * 1024 || body.len() > 128 * 1024 {
            return Err(bad("HTTPMask request exceeds limit"));
        }
        // 请求头和主体一次写出：分两次写会多一个小报文，并让接收端的延迟 ACK 与 TLS 记录都多出一份开销
        let mut request = Vec::with_capacity(head.len() + body.len());
        request.extend_from_slice(head.as_bytes());
        request.extend_from_slice(body);
        io.get_mut().write_all(&request).await?;
        io.get_mut().flush().await?;
        tokio::time::timeout(Duration::from_secs(20), Response::headers(io))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "HTTPMask response header timeout")
            })?
    }
    fn recycle(&self, response: Response) {
        if response.reusable && response.finished() {
            let mut idle = self.pool.idle.lock().unwrap();
            if idle.len() < 8 {
                idle.push(Idle {
                    io: response.io,
                    at: Instant::now(),
                });
            }
        }
    }
    async fn small(&self, method: &str, path: &str, body: &[u8]) -> io::Result<Vec<u8>> {
        let mut last = bad("HTTPMask request failed");
        for attempt in 0..3 {
            let operation = async {
                let mut response = self.request(method, path, body).await?;
                let status = response.status;
                let mut bytes = Vec::new();
                while let Some(part) = response.piece().await? {
                    if bytes.len() + part.len() > 4096 {
                        return Err(bad("HTTPMask control response too large"));
                    }
                    bytes.extend(part);
                }
                self.recycle(response);
                if status != 200 {
                    return Err(io::Error::new(
                        if matches!(status, 408 | 429 | 502 | 503 | 504) {
                            io::ErrorKind::TimedOut
                        } else {
                            io::ErrorKind::PermissionDenied
                        },
                        format!("HTTPMask status {status}"),
                    ));
                }
                Ok(bytes)
            };
            match tokio::time::timeout(Duration::from_secs(20), operation).await {
                Ok(Ok(v)) => return Ok(v),
                Ok(Err(e)) => {
                    if e.kind() == io::ErrorKind::PermissionDenied
                        || e.kind() == io::ErrorKind::InvalidData
                    {
                        return Err(e);
                    }
                    last = e;
                }
                Err(_) => {
                    last = io::Error::new(io::ErrorKind::TimedOut, "HTTPMask request timed out")
                }
            }
            self.pool.clear();
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(50 << attempt)).await;
            }
        }
        Err(last)
    }
}
struct Response {
    io: BufReader<BoxStream>,
    status: u16,
    remaining: Option<usize>,
    chunked: bool,
    chunk: usize,
    crlf: bool,
    done: bool,
    eof: bool,
    reusable: bool,
}
async fn line(io: &mut BufReader<BoxStream>, limit: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let bytes = io.fill_buf().await?;
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTPMask line truncated",
            ));
        }
        let n = bytes
            .iter()
            .position(|v| *v == b'\n')
            .map_or(bytes.len(), |n| n + 1);
        if out.len() + n > limit {
            return Err(bad("HTTPMask line exceeds limit"));
        }
        out.extend_from_slice(&bytes[..n]);
        io.consume(n);
        if out.last() == Some(&b'\n') {
            return Ok(out);
        }
    }
}
impl Response {
    async fn headers(mut io: BufReader<BoxStream>) -> io::Result<Self> {
        let status_line = line(&mut io, 4096).await?;
        let status = std::str::from_utf8(&status_line)
            .map_err(|_| bad("invalid HTTPMask status"))?
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| bad("invalid HTTPMask status"))?;
        let mut total = status_line.len();
        let mut remaining = None;
        let mut chunked = false;
        let mut reusable = true;
        let mut eof = false;
        loop {
            let l = line(&mut io, 4096).await?;
            total += l.len();
            if total > 16 * 1024 {
                return Err(bad("HTTPMask headers exceed limit"));
            }
            if l == b"\r\n" || l == b"\n" {
                break;
            }
            let text = std::str::from_utf8(&l).map_err(|_| bad("invalid HTTPMask header"))?;
            let (k, v) = text
                .split_once(':')
                .ok_or_else(|| bad("invalid HTTPMask header"))?;
            let v = v.trim();
            match k.to_ascii_lowercase().as_str() {
                "content-length" => {
                    if remaining.is_some() {
                        return Err(bad("duplicate HTTPMask content length"));
                    }
                    remaining = Some(
                        v.parse::<usize>()
                            .map_err(|_| bad("invalid HTTPMask content length"))?,
                    );
                }
                "transfer-encoding" => {
                    if !v.eq_ignore_ascii_case("chunked") {
                        return Err(bad("unsupported HTTPMask transfer encoding"));
                    }
                    chunked = true;
                }
                "content-encoding" if !v.eq_ignore_ascii_case("identity") => {
                    return Err(bad("unexpected HTTPMask content encoding"))
                }
                "connection" if v.eq_ignore_ascii_case("close") => reusable = false,
                "x-sudoku-stream-eof" if v == "1" => eof = true,
                _ => {}
            }
        }
        if chunked && remaining.is_some() {
            return Err(bad("ambiguous HTTPMask response framing"));
        }
        if !chunked && remaining.is_none() {
            reusable = false;
        }
        Ok(Self {
            io,
            status,
            remaining,
            chunked,
            chunk: 0,
            crlf: false,
            done: false,
            eof,
            reusable,
        })
    }
    fn finished(&self) -> bool {
        self.done
    }
    async fn piece(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.done {
            return Ok(None);
        }
        let available = if self.chunked {
            if self.crlf {
                let mut crlf = [0; 2];
                self.io.read_exact(&mut crlf).await?;
                if crlf != *b"\r\n" {
                    return Err(bad("invalid HTTPMask chunk delimiter"));
                }
                self.crlf = false;
            }
            if self.chunk == 0 {
                let size = line(&mut self.io, 128).await?;
                let size = std::str::from_utf8(&size).map_err(|_| bad("invalid HTTPMask chunk"))?;
                let size = size.trim().split(';').next().unwrap_or("");
                self.chunk = usize::from_str_radix(size, 16)
                    .map_err(|_| bad("invalid HTTPMask chunk length"))?;
                if self.chunk > 1024 * 1024 {
                    return Err(bad("HTTPMask chunk exceeds limit"));
                }
                if self.chunk == 0 {
                    let mut size = 0;
                    loop {
                        let trailer = line(&mut self.io, 4096).await?;
                        size += trailer.len();
                        if size > 8192 {
                            return Err(bad("HTTPMask trailers exceed limit"));
                        }
                        if trailer == b"\r\n" || trailer == b"\n" {
                            break;
                        }
                        let text = std::str::from_utf8(&trailer)
                            .map_err(|_| bad("invalid HTTPMask trailer"))?;
                        if let Some((key, value)) = text.split_once(':') {
                            if key.eq_ignore_ascii_case("X-Sudoku-Stream-EOF")
                                && value.trim() == "1"
                            {
                                self.eof = true;
                            }
                        }
                    }
                    self.done = true;
                    return Ok(None);
                }
            }
            self.chunk
        } else if let Some(n) = self.remaining {
            if n == 0 {
                self.done = true;
                return Ok(None);
            }
            n
        } else {
            4096
        };
        let mut bytes = vec![0; available.min(4096)];
        let n = self.io.read(&mut bytes).await?;
        if n == 0 {
            if self.chunked || self.remaining.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "HTTPMask body truncated",
                ));
            }
            self.done = true;
            return Ok(None);
        }
        bytes.truncate(n);
        if self.chunked {
            self.chunk -= n;
            if self.chunk == 0 {
                self.crlf = true;
            }
        } else if let Some(left) = self.remaining.as_mut() {
            *left -= n;
        }
        Ok(Some(bytes))
    }
}
pub(super) async fn dial(
    spec: &SudokuSpec,
    seed: &str,
    dialer: Arc<dyn Dialer>,
    pool: Arc<HttpPool>,
    hello: &[u8],
) -> io::Result<(BoxStream, Vec<u8>)> {
    if spec.http_disabled || spec.http_mode == "legacy" {
        let mut raw = dialer.dial_tcp(&spec.server).await?;
        if !spec.http_disabled {
            let root = if spec.path_root.is_empty() {
                String::new()
            } else {
                format!("/{}", spec.path_root)
            };
            let header=format!("GET {root}/ HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",spec.server);
            raw.write_all(header.as_bytes()).await?;
        }
        raw.write_all(hello).await?;
        raw.flush().await?;
        return Ok((raw, vec![]));
    }
    if spec.http_mode == "ws" {
        let c = client(spec, dialer, pool, "ws")?;
        let raw = c.socket().await?;
        let hash = record::sha(format!("sudoku-httpmask-auth-v1:{seed}").as_bytes());
        let timestamp = now().to_be_bytes();
        let mut signed = b"ws\0GET\0/ws\0".to_vec();
        signed.extend_from_slice(&timestamp);
        let tag = ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hash),
            &signed,
        );
        let mut token = timestamp.to_vec();
        token.extend_from_slice(&tag.as_ref()[..16]);
        let token = URL_SAFE_NO_PAD.encode(token);
        let mut request = format!("ws://{}{}?auth={token}", c.host, c.path("/ws"))
            .into_client_request()
            .map_err(io::Error::other)?;
        for (k, v) in [
            ("X-Sudoku-Tunnel", "ws".to_string()),
            ("X-Sudoku-Version", "1".to_string()),
            ("Authorization", format!("Bearer {token}")),
        ] {
            request.headers_mut().insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().map_err(io::Error::other)?,
            );
        }
        let config = WebSocketConfig::default()
            .read_buffer_size(4096)
            .write_buffer_size(4096)
            .max_write_buffer_size(640 * 1024)
            .max_message_size(Some(640 * 1024))
            .max_frame_size(Some(640 * 1024));
        let (ws, _) = tokio_tungstenite::client_async_with_config(request, raw, Some(config))
            .await
            .map_err(io::Error::other)?;
        let mut stream = oryn_transport::WsStream::from_websocket(ws);
        stream.write_all(hello).await?;
        stream.flush().await?;
        return Ok((Box::new(stream), vec![]));
    }
    if spec.http_mode == "auto" {
        let c = client(spec, dialer.clone(), pool.clone(), "stream")?;
        if let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(4), tunnel(c, hello)).await
        {
            return Ok(stream);
        }
        return tunnel(client(spec, dialer, pool, "poll")?, hello).await;
    }
    tunnel(client(spec, dialer, pool, &spec.http_mode)?, hello).await
}
/// 一个上传 POST 的原文上限，同时是应用到隧道之间桥的容量。
const UPLOAD_BATCH: usize = 64 * 1024;
/// poll 模式下一行 Base64 对应的原文上限。
const POLL_LINE: usize = 16 * 1024;
async fn tunnel(client: Client, hello: &[u8]) -> io::Result<(BoxStream, Vec<u8>)> {
    let path = format!(
        "{}?ed={}",
        client.path("/session"),
        URL_SAFE_NO_PAD.encode(hello)
    );
    let response = client.small("GET", &path, &[]).await?;
    let text =
        std::str::from_utf8(&response).map_err(|_| bad("invalid HTTPMask session response"))?;
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key))
            .unwrap_or("")
            .trim()
    };
    let token = field("token=").to_string();
    if token.is_empty()
        || token.len() > 128
        || !token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        || field("cap=") != "upload-seq"
    {
        return Err(bad("HTTPMask session lacks token or upload sequencing"));
    }
    let prefix = URL_SAFE_NO_PAD
        .decode(field("ed="))
        .map_err(|_| bad("invalid HTTPMask early response"))?;
    if prefix.len() > 4096 {
        return Err(bad("HTTPMask early response exceeds limit"));
    }
    let (app, bridge) = tokio::io::duplex(UPLOAD_BATCH);
    let (mut upload, mut download) = tokio::io::split(bridge);
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let errors = Arc::new(Mutex::new(None));
    let failure = errors.clone();
    let up = client.clone();
    let down = client.clone();
    let close = client.clone();
    let up_token = token.clone();
    let down_token = token.clone();
    tokio::spawn(async move {
        let send = async {
            let mut sequence = 0u64;
            // 上一个 POST 等响应期间，应用写入的数据在桥里累积，下一次一次取走（与 mihomo 一样最多 64 KiB 一批）；
            // 上行吞吐 = 每批字节数 ÷ 一次请求的耗时，批越小越被往返时延拖住。
            let mut buf = vec![0u8; UPLOAD_BATCH];
            loop {
                let n = upload.read(&mut buf).await?;
                if n == 0 {
                    let path = format!("{}?token={up_token}&fin=1", up.path("/api/v1/upload"));
                    up.small("POST", &path, &[]).await?;
                    return Ok::<_, io::Error>(());
                }
                sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| bad("HTTPMask upload sequence exhausted"))?;
                let path = format!(
                    "{}?token={up_token}&seq={sequence}",
                    up.path("/api/v1/upload")
                );
                let body = if up.mode == "poll" {
                    // 每行最多 16 KiB 原文（服务端按行解码）
                    let mut encoded = Vec::with_capacity(n * 4 / 3 + n / POLL_LINE + 8);
                    for line in buf[..n].chunks(POLL_LINE) {
                        encoded.extend_from_slice(STANDARD.encode(line).as_bytes());
                        encoded.push(b'\n');
                    }
                    encoded
                } else {
                    buf[..n].to_vec()
                };
                up.small("POST", &path, &body).await?;
            }
        };
        let recv = async {
            let path = format!("{}?token={down_token}", down.path("/stream"));
            let mut retries = 0;
            loop {
                let mut response = match down.request("GET", &path, &[]).await {
                    Ok(r) => r,
                    Err(e) => {
                        if retries >= 2 {
                            return Err(e);
                        }
                        retries += 1;
                        down.pool.clear();
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                if response.status != 200 {
                    // 服务端 / 中间代理的瞬时状态（502 / 503 等）还没交付任何数据，可以安全重拉；
                    // 与请求建立失败共用重试次数。其余状态码视为拒绝，结束隧道。
                    if matches!(response.status, 408 | 429 | 502 | 503 | 504) && retries < 2 {
                        retries += 1;
                        drop(response);
                        tokio::time::sleep(Duration::from_millis(100 << retries)).await;
                        continue;
                    }
                    return Err(bad("HTTPMask pull rejected"));
                }
                retries = 0;
                let mut line = Vec::new();
                let mut any = false;
                while let Some(part) = response.piece().await? {
                    any = true;
                    if down.mode == "poll" {
                        for b in part {
                            if b == b'\n' {
                                if !line.is_empty() {
                                    let bytes = STANDARD
                                        .decode(&line)
                                        .map_err(|_| bad("invalid HTTPMask base64 line"))?;
                                    download.write_all(&bytes).await?;
                                    line.clear();
                                }
                            } else {
                                if line.len() >= 64 * 1024 {
                                    return Err(bad("HTTPMask line too large"));
                                }
                                line.push(b);
                            }
                        }
                    } else {
                        download.write_all(&part).await?;
                    }
                }
                if !line.is_empty() {
                    let bytes = STANDARD
                        .decode(&line)
                        .map_err(|_| bad("invalid HTTPMask final line"))?;
                    download.write_all(&bytes).await?;
                }
                let eof = response.eof;
                down.recycle(response);
                if eof {
                    download.shutdown().await?;
                    return Ok::<_, io::Error>(());
                }
                if !any {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
        };
        let work = async { tokio::try_join!(send, recv).map(|_| ()) };
        tokio::select! {_=cancel.cancelled()=>{},result=work=>{if let Err(e)=result{*failure.lock().unwrap()=Some(e.to_string());}}}
        cancel.cancel();
        if let Ok(_permit) = close.pool.closing.clone().try_acquire_owned() {
            let path = format!("{}?token={token}&close=1", close.path("/api/v1/upload"));
            let _ =
                tokio::time::timeout(Duration::from_secs(1), close.small("POST", &path, &[])).await;
        }
    });
    let mut stream = Pipe {
        inner: app,
        stop,
        error: errors,
    };
    if prefix.is_empty() {
        stream.write_all(hello).await?;
        stream.flush().await?;
    }
    Ok((Box::new(stream), prefix))
}
struct Pipe {
    inner: DuplexStream,
    stop: CancellationToken,
    error: Arc<Mutex<Option<String>>>,
}
impl Drop for Pipe {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl AsyncRead for Pipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, out);
        if matches!(r, Poll::Ready(Ok(()))) && before == out.filled().len() {
            if let Some(e) = self.error.lock().unwrap().as_ref() {
                return Poll::Ready(Err(io::Error::other(e.clone())));
            }
        }
        r
    }
}
impl AsyncWrite for Pipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stop.is_cancelled() {
            return Poll::Ready(Err(bad("HTTPMask tunnel closed")));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
