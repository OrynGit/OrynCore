//! 最小 HTTP/1.1 客户端。
//!
//! 用途：规则集与 GEOIP 数据库下载、策略组健康检查、公网 IP 查询、DoH 的 HTTP/1.1 回退。
//! 默认每个请求一个连接（`Connection: close`），统一延迟探测复用连接；支持 HTTPS、重定向、`Content-Length`、分块传输与大小上限。
//! 连接经由 [`Connector`] 建立，因此可以走任意出站。

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use oryn_config::TargetAddr;
use oryn_outbound::{BoxStream, Outbound};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEADER: usize = 64 * 1024;
const USER_AGENT: &str = concat!("Oryn/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// 路径与查询串，以 `/` 开头。
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> io::Result<Url> {
        let bad = || io::Error::new(io::ErrorKind::InvalidInput, format!("invalid URL `{s}`"));
        let (https, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(bad());
        };
        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let path = path.split('#').next().unwrap_or("/");
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let default_port = if https { 443 } else { 80 };
        let (host, port) = if let Some(r) = authority.strip_prefix('[') {
            let (h, after) = r.split_once(']').ok_or_else(bad)?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| bad())?,
                None => default_port,
            };
            (h.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().map_err(|_| bad())?),
                None => (authority.to_string(), default_port),
            }
        };
        if host.is_empty() {
            return Err(bad());
        }
        Ok(Url {
            https,
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    /// `Host` 头的值：IPv6 加方括号，非默认端口带端口。
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.https { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// 解析相对重定向地址。
    fn join(&self, location: &str) -> io::Result<Url> {
        if location.starts_with("http://") || location.starts_with("https://") {
            return Url::parse(location);
        }
        let scheme = if self.https { "https" } else { "http" };
        let base = format!("{scheme}://{}", self.host_header());
        if location.starts_with("//") {
            return Url::parse(&format!("{scheme}:{location}"));
        }
        if location.starts_with('/') {
            return Url::parse(&format!("{base}{location}"));
        }
        let path = self.path.split(['?', '#']).next().unwrap_or("/");
        let dir = match path.rfind('/') {
            Some(i) => &path[..=i],
            None => "/",
        };
        let joined = format!("{dir}{location}");
        Url::parse(&format!("{base}{}", remove_dot_segments(&joined)))
    }
}

/// RFC 3986 §5.2.4：去掉路径中的 `.` 与 `..` 段（查询串原样保留）。
fn remove_dot_segments(target: &str) -> String {
    let (path, query) = match target.find(['?', '#']) {
        Some(i) => target.split_at(i),
        None => (target, ""),
    };
    let mut out: Vec<&str> = Vec::new();
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len().saturating_sub(1);
    for (i, seg) in segments.iter().enumerate() {
        match *seg {
            "." => {
                if i == last {
                    out.push("");
                }
            }
            ".." => {
                if out.len() > 1 {
                    out.pop();
                }
                if i == last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    let mut joined = out.join("/");
    if !joined.starts_with('/') {
        joined.insert(0, '/');
    }
    joined + query
}

/// 建立 TCP 连接的方式。
#[async_trait]
pub trait Connector: Send + Sync {
    async fn connect(&self, host: &str, port: u16) -> io::Result<BoxStream>;
}

/// 经由某个出站建立连接。
pub struct OutboundConnector(pub Arc<dyn Outbound>);

#[async_trait]
impl Connector for OutboundConnector {
    async fn connect(&self, host: &str, port: u16) -> io::Result<BoxStream> {
        self.0.connect_tcp(&TargetAddr::from_host(host, port)).await
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub timeout: Duration,
    /// 0 表示不限制。
    pub max_body: usize,
    pub max_redirects: u8,
    pub skip_verify: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            timeout: Duration::from_secs(30),
            max_body: 0,
            max_redirects: 5,
            skip_verify: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

fn timeout_err() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out")
}

/// 发送请求并跟随重定向。
pub async fn fetch(
    connector: &dyn Connector,
    req: Request<'_>,
    opts: &Options,
) -> io::Result<Response> {
    match tokio::time::timeout(
        opts.timeout,
        fetch_inner(
            connector,
            req,
            opts,
            &mut BodyTarget::<tokio::io::Sink>::Collect,
        ),
    )
    .await
    {
        Ok(r) => r.map(|(resp, _)| resp),
        Err(_) => Err(timeout_err()),
    }
}

/// 与 [`fetch`] 相同，但响应体只计数、不保留：返回的 `body` 为空，第二项是实际收到的字节数。
/// 用于测速这类大响应体，内存不随响应体大小增长。
pub async fn fetch_discard(
    connector: &dyn Connector,
    req: Request<'_>,
    opts: &Options,
) -> io::Result<(Response, usize)> {
    match tokio::time::timeout(
        opts.timeout,
        fetch_inner(
            connector,
            req,
            opts,
            &mut BodyTarget::<tokio::io::Sink>::Discard,
        ),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(timeout_err()),
    }
}

/// 仅最终 HTTP 200 正文写入 writer，返回空 body 和写入字节数。
/// 重定向及非 200 正文按同一上限消费但不写入，非 200 返回计数 0。
/// Geo 调用方须检查 status == 200 再发布文件；错误/取消可留下部分文件，须自行清理。
/// 超时包含连接、重定向、读取与写入；不 spawn，不 flush/关闭调用方 writer。
pub async fn fetch_to_writer<W: AsyncWrite + Unpin>(
    connector: &dyn Connector,
    req: Request<'_>,
    opts: &Options,
    writer: &mut W,
) -> io::Result<(Response, usize)> {
    match tokio::time::timeout(
        opts.timeout,
        fetch_inner(connector, req, opts, &mut BodyTarget::Writer(writer)),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(timeout_err()),
    }
}

enum BodyTarget<'a, W> {
    Collect,
    Discard,
    Writer(&'a mut W),
}

async fn fetch_inner<W: AsyncWrite + Unpin>(
    connector: &dyn Connector,
    req: Request<'_>,
    opts: &Options,
    target: &mut BodyTarget<'_, W>,
) -> io::Result<(Response, usize)> {
    let mut url = Url::parse(req.url)?;
    let mut method = req.method.to_string();
    let mut body = req.body;
    let origin = (url.https, url.host.clone(), url.port);
    // 跳到其他主机后不再带凭据类请求头（与浏览器 / curl 一致）。
    let stripped: Vec<(&str, &str)> = req
        .headers
        .iter()
        .copied()
        .filter(|(k, _)| {
            !["authorization", "proxy-authorization", "cookie"]
                .iter()
                .any(|s| k.eq_ignore_ascii_case(s))
        })
        .collect();
    for _ in 0..=opts.max_redirects {
        let same_origin =
            (url.https, url.host.as_str(), url.port) == (origin.0, origin.1.as_str(), origin.2);
        let headers = if same_origin {
            req.headers
        } else {
            &stripped[..]
        };
        let (resp, len) = once(connector, &method, &url, headers, body, opts, target).await?;
        if matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
            if let Some(loc) = resp.header("location") {
                let next = url.join(loc)?;
                if url.https && !next.https {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "HTTPS redirect downgrade rejected",
                    ));
                }
                url = next;
                if resp.status == 303
                    || ((resp.status == 301 || resp.status == 302) && method == "POST")
                {
                    method = "GET".into();
                    body = &[];
                }
                continue;
            }
        }
        return Ok((resp, len));
    }
    Err(io::Error::other("too many redirects"))
}

pub async fn get(connector: &dyn Connector, url: &str, opts: &Options) -> io::Result<Response> {
    fetch(
        connector,
        Request {
            method: "GET",
            url,
            headers: &[],
            body: &[],
        },
        opts,
    )
    .await
}

async fn once<W: AsyncWrite + Unpin>(
    connector: &dyn Connector,
    method: &str,
    url: &Url,
    headers: &[(&str, &str)],
    body: &[u8],
    opts: &Options,
    target: &mut BodyTarget<'_, W>,
) -> io::Result<(Response, usize)> {
    let stream = connector.connect(&url.host, url.port).await?;
    if url.https {
        let mut tls = oryn_tls::connect(
            stream,
            &url.host,
            &[oryn_tls::ALPN_HTTP11],
            opts.skip_verify,
        )
        .await?;
        exchange(&mut tls, method, url, headers, body, opts.max_body, target).await
    } else {
        let mut stream = stream;
        exchange(
            &mut stream,
            method,
            url,
            headers,
            body,
            opts.max_body,
            target,
        )
        .await
    }
}

/// 在已建立的连接上发送一个请求并读取完整响应。
pub async fn send_and_read<S>(
    s: &mut S,
    method: &str,
    url: &Url,
    headers: &[(&str, &str)],
    body: &[u8],
    max_body: usize,
) -> io::Result<Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange(
        s,
        method,
        url,
        headers,
        body,
        max_body,
        &mut BodyTarget::<tokio::io::Sink>::Collect,
    )
    .await
    .map(|(resp, _)| resp)
}

async fn exchange<S, W: AsyncWrite + Unpin>(
    s: &mut S,
    method: &str,
    url: &Url,
    headers: &[(&str, &str)],
    body: &[u8],
    max_body: usize,
    target: &mut BodyTarget<'_, W>,
) -> io::Result<(Response, usize)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let length = (!body.is_empty() || method == "POST" || method == "PUT").then_some(body.len());
    write_head(s, method, url, headers, length).await?;
    if !body.is_empty() {
        s.write_all(body).await?;
    }
    s.flush().await?;
    read_response_into(s, method == "HEAD", max_body, target).await
}

/// 只发送请求头；`content_length` 为 `Some` 时写 `Content-Length`，正文由调用方随后写入并 flush。
/// 未给出 `Connection` 头时写 `Connection: close`；需要复用连接时传 `("Connection", "keep-alive")`。
pub async fn write_head<S: AsyncWrite + Unpin>(
    s: &mut S,
    method: &str,
    url: &Url,
    headers: &[(&str, &str)],
    content_length: Option<usize>,
) -> io::Result<()> {
    let mut req = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\n",
        url.path,
        url.host_header()
    );
    let has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    if !has("user-agent") {
        req.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
    }
    if !has("accept") {
        req.push_str("Accept: */*\r\n");
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(length) = content_length {
        req.push_str(&format!("Content-Length: {length}\r\n"));
    }
    if !has("connection") {
        req.push_str("Connection: close\r\n");
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await
}

/// 读取一个响应；`discard` 时正文只计数不保留。第二项是正文字节数。
/// 正文按 `Content-Length` 或分块读完即返回，不多读，连接可以继续发下一个请求；
/// 两者都没有（以关闭分帧）或响应声明 `Connection: close` 时，连接不能复用。
pub async fn read_response<S: AsyncRead + Unpin>(
    s: &mut S,
    head: bool,
    max_body: usize,
    discard: bool,
) -> io::Result<(Response, usize)> {
    let mut target = if discard {
        BodyTarget::<tokio::io::Sink>::Discard
    } else {
        BodyTarget::Collect
    };
    read_response_into(s, head, max_body, &mut target).await
}

async fn read_response_into<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    s: &mut S,
    head: bool,
    max_body: usize,
    target: &mut BodyTarget<'_, W>,
) -> io::Result<(Response, usize)> {
    let mut buf = Vec::with_capacity(4096);
    // 跳过 1xx 中间响应（100 Continue、103 Early Hints）；101 由调用方处理。
    let mut interim = 0;
    let header_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            let code = buf
                .get(9..12)
                .and_then(|c| std::str::from_utf8(c).ok())
                .and_then(|c| c.parse::<u16>().ok());
            if buf.starts_with(b"HTTP/1.")
                && code.is_some_and(|c| (100..200).contains(&c) && c != 101)
                && interim < 8
            {
                interim += 1;
                buf.drain(..i + 4);
                continue;
            }
            break i;
        }
        if buf.len() > MAX_HEADER {
            return Err(io::Error::other("HTTP response header too large"));
        }
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP response",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    if !parts.next().unwrap_or("").starts_with("HTTP/1.") {
        return Err(io::Error::other("malformed HTTP response"));
    }
    let status: u16 = parts
        .next()
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io::Error::other("malformed HTTP status"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    let mut resp = Response {
        status,
        headers,
        body: Vec::new(),
    };
    let rest = buf[header_end + 4..].to_vec();
    if head || (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok((resp, 0));
    }
    let chunked = resp
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let length = resp
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok());
    let mut reader = Prefixed {
        prefix: rest,
        pos: 0,
        inner: s,
    };
    // 所有模式共用分帧与预算检查；writer 模式禁止错误页或重定向污染文件。
    let suppress = status != 200 && matches!(target, BodyTarget::Writer(_));
    let mut ignored = BodyTarget::Discard;
    let consumer = if suppress { &mut ignored } else { target };
    let len = consume_body(
        &mut reader,
        chunked,
        length,
        max_body,
        consumer,
        &mut resp.body,
    )
    .await?;
    Ok((resp, if suppress { 0 } else { len }))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// 先返回已缓冲的数据，再从底层读取。
struct Prefixed<'a, S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: &'a mut S,
}

impl<S: AsyncRead + Unpin> Prefixed<'_, S> {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = out.len().min(self.prefix.len() - self.pos);
            out[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(out).await
    }

    async fn read_line(&mut self) -> io::Result<String> {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            if self.read(&mut b).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if b[0] == b'\n' {
                break;
            }
            line.push(b[0]);
            if line.len() > 1024 {
                return Err(io::Error::other("chunk header too long"));
            }
        }
        Ok(String::from_utf8_lossy(&line).trim().to_string())
    }
}

fn checked_body_size(total: usize, extra: usize, max: usize) -> io::Result<usize> {
    total
        .checked_add(extra)
        .filter(|&n| max == 0 || n <= max)
        .ok_or_else(|| io::Error::other("HTTP response body exceeds the size limit"))
}

/// 统一消费三种正文分帧。每次写入前检查预算，scratch 不随声明长度增长。
async fn consume_body<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut Prefixed<'_, S>,
    chunked: bool,
    length: Option<usize>,
    max: usize,
    target: &mut BodyTarget<'_, W>,
    body: &mut Vec<u8>,
) -> io::Result<usize> {
    let mut scratch = [0u8; 16 * 1024];
    let mut total = 0;
    loop {
        let size = if chunked {
            let line = r.read_line().await?;
            let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| io::Error::other("invalid chunk size"))?;
            if size == 0 {
                while !r.read_line().await?.is_empty() {}
                return Ok(total);
            }
            Some(size)
        } else {
            length
        };
        if let Some(size) = size {
            checked_body_size(total, size, max)?;
            // Content-Length 一次预留；多 chunk 保留摊销增长，避免逐块精确扩容复制。
            // writer/discard 不分配正文。
            if matches!(target, BodyTarget::Collect) {
                if chunked {
                    body.reserve(size);
                } else {
                    body.reserve_exact(size);
                }
            }
        }
        let mut remaining = size;
        loop {
            let want = remaining.unwrap_or(scratch.len()).min(scratch.len());
            if want == 0 {
                break;
            }
            let n = r.read(&mut scratch[..want]).await?;
            if n == 0 {
                if remaining.is_some() {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                return Ok(total);
            }
            total = checked_body_size(total, n, max)?;
            match target {
                BodyTarget::Collect => body.extend_from_slice(&scratch[..n]),
                BodyTarget::Discard => {}
                BodyTarget::Writer(writer) => writer.write_all(&scratch[..n]).await?,
            }
            if let Some(left) = &mut remaining {
                *left -= n;
            }
        }
        if !chunked {
            return Ok(total);
        }
        r.read_line().await?;
    }
}

/// 健康检查：从开始连接到收到响应头的耗时。任何 HTTP 响应都视为成功。
pub async fn probe(
    connector: &dyn Connector,
    url: &str,
    timeout: Duration,
    skip_verify: bool,
) -> io::Result<Duration> {
    let start = Instant::now();
    let opts = Options {
        timeout,
        max_body: 64 * 1024,
        max_redirects: 0,
        skip_verify,
    };
    fetch(
        connector,
        Request {
            method: "HEAD",
            url,
            headers: &[],
            body: &[],
        },
        &opts,
    )
    .await?;
    Ok(start.elapsed())
}

/// 统一延迟：首次 HEAD 预热后，在同一连接上测第二次 HEAD 的响应头耗时。
/// 两轮共用超时预算；第二轮失败回退首轮耗时，不把不支持复用的站点判为不可用。
pub async fn probe_unified(
    connector: &dyn Connector,
    url: &str,
    timeout: Duration,
    skip_verify: bool,
) -> io::Result<Duration> {
    let start = tokio::time::Instant::now();
    let deadline = start + timeout;
    let url = Url::parse(url)?;
    let warmup = async {
        let stream = connector.connect(&url.host, url.port).await?;
        let mut stream: BoxStream = if url.https {
            Box::new(
                oryn_tls::connect(stream, &url.host, &[oryn_tls::ALPN_HTTP11], skip_verify).await?,
            )
        } else {
            stream
        };
        send_and_read(
            &mut stream,
            "HEAD",
            &url,
            &[("Connection", "keep-alive")],
            &[],
            64 * 1024,
        )
        .await?;
        Ok::<_, io::Error>(stream)
    };
    let mut stream = tokio::time::timeout_at(deadline, warmup)
        .await
        .map_err(|_| timeout_err())??;
    let first_delay = start.elapsed();
    let measured = tokio::time::Instant::now();
    match tokio::time::timeout_at(
        deadline,
        send_and_read(&mut stream, "HEAD", &url, &[], &[], 64 * 1024),
    )
    .await
    {
        Ok(Ok(_)) => Ok(measured.elapsed()),
        _ => Ok(first_delay),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    struct ProbeConnector(std::sync::Mutex<Option<tokio::io::DuplexStream>>);

    #[async_trait]
    impl Connector for ProbeConnector {
        async fn connect(&self, _: &str, _: u16) -> io::Result<BoxStream> {
            // 建连只允许一次；虚拟时间使握手与响应耗时断言不受本机负载影响。
            let stream = self.0.lock().unwrap().take().expect("probe reconnected");
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok(Box::new(stream))
        }
    }

    fn probe_server(
        replies: Vec<(Duration, &'static [u8])>,
    ) -> (ProbeConnector, tokio::task::JoinHandle<()>) {
        let (client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            for (i, (delay, response)) in replies.into_iter().enumerate() {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(server.read_u8().await.unwrap());
                    assert!(request.len() < 4096);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("HEAD /probe HTTP/1.1\r\n"));
                assert_eq!(request.matches("Connection:").count(), 1);
                assert!(request.contains(if i == 0 {
                    "Connection: keep-alive\r\n"
                } else {
                    "Connection: close\r\n"
                }));
                tokio::time::sleep(delay).await;
                server.write_all(response).await.unwrap();
            }
        });
        (ProbeConnector(std::sync::Mutex::new(Some(client))), task)
    }

    const PROBE_OK: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";
    const PROBE_URL: &str = "http://probe.example/probe";

    #[tokio::test(start_paused = true)]
    async fn unified_probe_excludes_connect_and_warmup() {
        let (connector, server) = probe_server(vec![
            (Duration::from_secs(3), PROBE_OK),
            (Duration::from_millis(20), PROBE_OK),
        ]);
        let delay = probe_unified(&connector, PROBE_URL, Duration::from_secs(10), false)
            .await
            .unwrap();
        assert_eq!(delay, Duration::from_millis(20));
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn unified_probe_closed_connection_keeps_first_result() {
        let (connector, server) = probe_server(vec![(Duration::from_secs(3), PROBE_OK)]);
        let delay = probe_unified(&connector, PROBE_URL, Duration::from_secs(10), false)
            .await
            .unwrap();
        assert_eq!(delay, Duration::from_secs(5));
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn unified_probe_second_request_uses_remaining_budget() {
        let (connector, server) = probe_server(vec![
            (Duration::from_secs(3), PROBE_OK),
            (Duration::from_secs(3), PROBE_OK),
        ]);
        let start = tokio::time::Instant::now();
        let delay = probe_unified(&connector, PROBE_URL, Duration::from_secs(6), false)
            .await
            .unwrap();
        assert_eq!(delay, Duration::from_secs(5));
        assert_eq!(start.elapsed(), Duration::from_secs(6));
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn unified_probe_warmup_timeout_fails() {
        let (connector, server) = probe_server(vec![(Duration::from_secs(3), PROBE_OK)]);
        let error = probe_unified(&connector, PROBE_URL, Duration::from_secs(4), false)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn unified_probe_invalid_warmup_fails() {
        let (connector, server) = probe_server(vec![(Duration::ZERO, b"invalid\r\n\r\n")]);
        assert!(
            probe_unified(&connector, PROBE_URL, Duration::from_secs(10), false)
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    struct Local;

    #[async_trait]
    impl Connector for Local {
        async fn connect(&self, host: &str, port: u16) -> io::Result<BoxStream> {
            assert_eq!(host, "127.0.0.1");
            Ok(Box::new(TcpStream::connect(("127.0.0.1", port)).await?))
        }
    }

    #[test]
    fn urls() {
        let u = Url::parse("https://Example.com/a/b?x=1#frag").unwrap();
        assert_eq!(
            (u.https, u.host.as_str(), u.port, u.path.as_str()),
            (true, "example.com", 443, "/a/b?x=1")
        );
        let u = Url::parse("http://[2001:db8::1]:8080").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("2001:db8::1", 8080, "/")
        );
        assert_eq!(u.host_header(), "[2001:db8::1]:8080");
        assert!(Url::parse("ftp://a.com").is_err() && Url::parse("http://").is_err());
        let base = Url::parse("https://a.com/dir/file.txt").unwrap();
        assert_eq!(base.join("other.txt").unwrap().path, "/dir/other.txt");
        assert_eq!(base.join("/root").unwrap().path, "/root");
        assert_eq!(base.join("https://b.com/x").unwrap().host, "b.com");
        assert_eq!(base.join("//c.com/y").unwrap().host, "c.com");
        assert_eq!(base.join("../up.txt").unwrap().path, "/up.txt");
        assert_eq!(base.join("./a/../b?x=1").unwrap().path, "/dir/b?x=1");
    }

    #[tokio::test]
    async fn interim_responses_are_skipped() {
        let raw = b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let mut s = std::io::Cursor::new(raw);
        let (r, _) = read_response(&mut s, false, 0, false).await.unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
    }

    /// 本地 HTTP 服务器：按路径返回不同响应。
    async fn server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    // 客户端分两次写请求头和请求体，所以要读到头部结束，再按 Content-Length 读足请求体
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 1024];
                    let head_end = loop {
                        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        let n = s.read(&mut buf).await.unwrap();
                        assert!(n > 0, "客户端在请求头结束前关闭了连接");
                        raw.extend_from_slice(&buf[..n]);
                    };
                    let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
                    let want = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while raw.len() < head_end + want {
                        let n = s.read(&mut buf).await.unwrap();
                        assert!(n > 0, "客户端在请求体结束前关闭了连接");
                        raw.extend_from_slice(&buf[..n]);
                    }
                    let req = String::from_utf8_lossy(&raw).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let resp: Vec<u8> = match path.as_str() {
                        "/len" => b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
                        "/chunked" => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-T: 1\r\n\r\n".to_vec(),
                        "/close" => b"HTTP/1.1 200 OK\r\n\r\nuntil close".to_vec(),
                        "/redirect" => b"HTTP/1.1 302 Found\r\nLocation: /len\r\nContent-Length: 0\r\n\r\n".to_vec(),
                        "/loop" => b"HTTP/1.1 301 Moved\r\nLocation: /loop\r\nContent-Length: 0\r\n\r\n".to_vec(),
                        "/big" => b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec(),
                        "/204" => b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
                        "/post" => {
                            let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
                        }
                        _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
                    };
                    let _ = s.write_all(&resp).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn eof_body_limit_exact_and_one_extra_byte() {
        for (len, ok) in [(8192, true), (8193, false)] {
            let mut wire = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
            wire.extend(vec![b'x'; len]);
            let result = read_response(&mut wire.as_slice(), false, 8192, false).await;
            assert_eq!(result.is_ok(), ok);
            if let Ok((response, size)) = result {
                assert_eq!(size, 8192);
                assert_eq!(response.body, vec![b'x'; 8192]);
            }
        }
    }

    #[tokio::test]
    async fn responses() {
        let port = server().await;
        let url = |p: &str| format!("http://127.0.0.1:{port}{p}");
        let opts = Options::default();
        assert_eq!(
            get(&Local, &url("/len"), &opts).await.unwrap().body,
            b"hello"
        );
        assert_eq!(
            get(&Local, &url("/chunked"), &opts).await.unwrap().body,
            b"hello world"
        );
        assert_eq!(
            get(&Local, &url("/close"), &opts).await.unwrap().body,
            b"until close"
        );
        let r = get(&Local, &url("/redirect"), &opts).await.unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
        assert!(get(&Local, &url("/loop"), &opts).await.is_err());
        assert_eq!(
            get(&Local, &url("/missing"), &opts).await.unwrap().status,
            404
        );
        let small = Options {
            max_body: 10,
            ..Options::default()
        };
        assert!(get(&Local, &url("/big"), &small).await.is_err());
        assert_eq!(get(&Local, &url("/204"), &opts).await.unwrap().status, 204);
        let r = fetch(
            &Local,
            Request {
                method: "POST",
                url: &url("/post"),
                headers: &[("Content-Type", "text/plain")],
                body: b"ping",
            },
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(r.body, b"ping");
        // 只计数不保留：三种分帧都返回正文长度、body 为空，上限仍然生效
        for (path, len) in [("/len", 5), ("/chunked", 11), ("/close", 11)] {
            let request = Request {
                method: "GET",
                url: &url(path),
                headers: &[],
                body: &[],
            };
            let (r, n) = fetch_discard(&Local, request, &opts).await.unwrap();
            assert_eq!((r.status, n, r.body.len()), (200, len, 0), "{path}");
        }
        let request = Request {
            method: "GET",
            url: &url("/big"),
            headers: &[],
            body: &[],
        };
        assert!(fetch_discard(&Local, request, &small).await.is_err());
        assert!(
            probe(&Local, &url("/204"), Duration::from_secs(2), false)
                .await
                .is_ok()
        );
    }
}
