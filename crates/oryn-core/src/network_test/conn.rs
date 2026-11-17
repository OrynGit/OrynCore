//! 测速用的 HTTP/1.1 keep-alive 连接：一个 worker（或一次延迟测量）一条，逐个发请求，避免每个请求
//! 重新握手和 TCP 慢启动。见 docs/plan-network-test.md「长连接、大请求与准确延迟」。

use std::io;
use std::time::{Duration, Instant};

use oryn_http::{read_response, write_head, Connector, Response, Url};
use oryn_outbound::BoxStream;
use tokio::io::AsyncWriteExt;

/// 上传正文按这个大小的零块循环写出，内存不随请求大小增长。
const UPLOAD_CHUNK: usize = 64 * 1024;
static ZEROS: [u8; UPLOAD_CHUNK] = [0; UPLOAD_CHUNK];

#[derive(Clone, Copy)]
pub(super) enum Body {
    Empty,
    /// `Content-Length` 为给定字节数的全零正文。
    Zeros(usize),
}

pub(super) struct Reply {
    pub response: Response,
    /// 实际收到的响应体字节数（`discard` 时 `response.body` 为空）。
    pub length: usize,
    /// 请求发完到响应读完的耗时；小响应近似一个往返。
    pub elapsed: Duration,
}

#[derive(Default)]
pub(super) struct SpeedConn {
    stream: Option<BoxStream>,
    /// 当前连接的 host、端口与是否 HTTPS；目标变化时重连。
    target: Option<(String, u16, bool)>,
}

impl SpeedConn {
    /// 在已有连接上发请求，没有可用连接时新建。复用的连接若已被服务端关闭（读写时立即出错），
    /// 换新连接重试一次。超时或出错后连接被丢弃。
    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &mut self,
        connector: &dyn Connector,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Body,
        max_body: usize,
        discard: bool,
        timeout: Duration,
    ) -> io::Result<Reply> {
        let url = Url::parse(url)?;
        let key = (url.host.clone(), url.port, url.https);
        if self.target.as_ref() != Some(&key) {
            self.stream = None;
        }
        let deadline = Instant::now() + timeout;
        let reused = self.stream.is_some();
        let first = self
            .attempt(connector, method, &url, headers, body, max_body, discard, deadline)
            .await;
        let result = match first {
            Err(error) if reused && stale(&error) => {
                self.attempt(connector, method, &url, headers, body, max_body, discard, deadline)
                    .await
            }
            other => other,
        };
        match result {
            Ok((reply, keep)) => {
                if let Some(stream) = keep {
                    self.stream = Some(stream);
                    self.target = Some(key);
                }
                Ok(reply)
            }
            Err(error) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn attempt(
        &mut self,
        connector: &dyn Connector,
        method: &str,
        url: &Url,
        headers: &[(&str, &str)],
        body: Body,
        max_body: usize,
        discard: bool,
        deadline: Instant,
    ) -> io::Result<(Reply, Option<BoxStream>)> {
        let pooled = self.stream.take();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let work = async move {
            let mut stream = match pooled {
                Some(stream) => stream,
                None => connect(connector, url).await?,
            };
            let mut all: Vec<(&str, &str)> = headers.to_vec();
            all.push(("Connection", "keep-alive"));
            let length = match body {
                Body::Empty => (method == "POST" || method == "PUT").then_some(0),
                Body::Zeros(n) => Some(n),
            };
            write_head(&mut stream, method, url, &all, length).await?;
            if let Body::Zeros(mut left) = body {
                while left > 0 {
                    let n = left.min(UPLOAD_CHUNK);
                    stream.write_all(&ZEROS[..n]).await?;
                    left -= n;
                }
            }
            stream.flush().await?;
            let sent = Instant::now();
            let (response, length) =
                read_response(&mut stream, method == "HEAD", max_body, discard).await?;
            let elapsed = sent.elapsed();
            let keep = reusable(&response).then_some(stream);
            Ok::<_, io::Error>((
                Reply {
                    response,
                    length,
                    elapsed,
                },
                keep,
            ))
        };
        match tokio::time::timeout(remaining, work).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP request timed out",
            )),
        }
    }
}

async fn connect(connector: &dyn Connector, url: &Url) -> io::Result<BoxStream> {
    let stream = connector.connect(&url.host, url.port).await?;
    if !url.https {
        return Ok(stream);
    }
    let tls = oryn_tls::connect(stream, &url.host, &[oryn_tls::ALPN_HTTP11], false).await?;
    Ok(Box::new(tls))
}

/// 服务端没有声明关闭、且正文有明确长度（`Content-Length` 或分块）时连接可以继续用。
fn reusable(response: &Response) -> bool {
    let closes = response
        .header("connection")
        .is_some_and(|v| v.to_ascii_lowercase().contains("close"));
    let framed = response.header("content-length").is_some()
        || response
            .header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    !closes && framed
}

/// 复用的空闲连接被对端关闭时的典型错误；超时不算（不重试）。
fn stale(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    ) || error.to_string().contains("connection closed before HTTP response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;

    /// 每次连接一个内存回环服务端：按请求顺序应答，记录建立的连接数与收到的上传字节。
    /// `close_after` 个请求后服务端关闭连接（模拟空闲连接被关闭）。
    #[derive(Clone, Default)]
    struct Loop {
        connects: Arc<AtomicUsize>,
        uploaded: Arc<AtomicUsize>,
        close_after: Option<usize>,
    }

    #[async_trait::async_trait]
    impl Connector for Loop {
        async fn connect(&self, _host: &str, _port: u16) -> io::Result<BoxStream> {
            self.connects.fetch_add(1, SeqCst);
            let (client, mut peer) = tokio::io::duplex(256 * 1024);
            let uploaded = self.uploaded.clone();
            let close_after = self.close_after;
            tokio::spawn(async move {
                let mut served = 0;
                let mut buf = Vec::new();
                loop {
                    if close_after == Some(served) {
                        return;
                    }
                    let end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        let mut chunk = [0u8; 4096];
                        match peer.read(&mut chunk).await {
                            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                            _ => return,
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    buf.drain(..end);
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while buf.len() < length {
                        let mut chunk = [0u8; 65536];
                        match peer.read(&mut chunk).await {
                            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                            _ => return,
                        }
                    }
                    buf.drain(..length);
                    uploaded.fetch_add(length, SeqCst);
                    let size = head
                        .split(['?', '&', ' '])
                        .find_map(|p| p.strip_prefix("size="))
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(4);
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n");
                    if peer.write_all(response.as_bytes()).await.is_err()
                        || peer.write_all(&vec![7u8; size]).await.is_err()
                    {
                        return;
                    }
                    served += 1;
                }
            });
            Ok(Box::new(client))
        }
    }

    async fn get(conn: &mut SpeedConn, c: &Loop, size: usize) -> io::Result<Reply> {
        let url = format!("http://t.invalid/download?size={size}");
        conn.send(c, "GET", &url, &[], Body::Empty, 0, true, Duration::from_secs(2))
            .await
    }

    #[tokio::test]
    async fn requests_share_one_connection_and_bodies_are_counted() {
        let c = Loop::default();
        let mut conn = SpeedConn::default();
        for size in [10, 300_000, 0, 5] {
            let reply = get(&mut conn, &c, size).await.unwrap();
            assert_eq!((reply.length, reply.response.body.len()), (size, 0));
        }
        let reply = conn
            .send(
                &c,
                "POST",
                "http://t.invalid/upload",
                &[],
                Body::Zeros(200_000),
                0,
                false,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(reply.response.status, 200);
        assert_eq!(c.uploaded.load(SeqCst), 200_000);
        assert_eq!(c.connects.load(SeqCst), 1, "全部请求复用一条连接");
    }

    #[tokio::test]
    async fn closed_idle_connection_is_replaced_once() {
        let c = Loop {
            close_after: Some(1),
            ..Loop::default()
        };
        let mut conn = SpeedConn::default();
        get(&mut conn, &c, 4).await.unwrap();
        // 服务端在第一个请求后关闭：第二个请求换新连接成功
        get(&mut conn, &c, 4).await.unwrap();
        assert_eq!(c.connects.load(SeqCst), 2);
    }

    #[test]
    fn reuse_requires_framing_and_no_close() {
        let mut r = Response {
            status: 200,
            headers: vec![("Content-Length".into(), "1".into())],
            body: Vec::new(),
        };
        assert!(reusable(&r));
        r.headers.push(("Connection".into(), "Close".into()));
        assert!(!reusable(&r));
        r.headers = vec![];
        assert!(!reusable(&r));
        r.headers = vec![("Transfer-Encoding".into(), "chunked".into())];
        assert!(reusable(&r));
    }
}
