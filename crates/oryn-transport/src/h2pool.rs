//! 同一出站的 Flow 共享有界的 h2 连接池，每个 Flow 一个 h2 流。两种承载：
//! - gRPC（gun）：gRPC 5 字节首部 + protobuf field 1（bytes）。
//! - `network: h2`（V2Ray HTTP/2）：PUT 请求，请求体与响应体都是原始字节。
//! - NaïveProxy：CONNECT 请求（authority 形式），请求体与响应体是原始字节（填充由出站处理）。
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::{Buf, Bytes};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex as StdMutex, OnceLock,
    },
    task::{ready, Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::oneshot;

const MAX_MESSAGE: usize = 64 * 1024;
/// 一次写入 h2 流的字节数（gRPC 里就是一条 gun 消息）。
const WRITE_CHUNK: usize = 64 * 1024;
/// 每条流在 h2 内部排队的待发数据上限。32 KiB 时生产方与连接驱动任务像乒乓一样一块一块交接，
/// 上行比下行慢（gRPC / h2 上行 60–85% 线速）；深一些让两边流水线起来。上限仍是常数，
/// 内存随活跃流数线性增长（32 条流满载 4 MiB）。
const SEND_BUFFER: usize = 128 * 1024;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn frame(data: &[u8]) -> Bytes {
    let mut proto = vec![10];
    let mut len = data.len();
    while len >= 128 {
        proto.push((len as u8 & 127) | 128);
        len >>= 7;
    }
    proto.push(len as u8);
    proto.extend_from_slice(data);
    let mut out = vec![0];
    out.extend_from_slice(&(proto.len() as u32).to_be_bytes());
    out.extend(proto);
    out.into()
}
fn payload(proto: &[u8]) -> io::Result<Bytes> {
    if proto.first() != Some(&10) {
        return Err(invalid("gRPC gun requires protobuf bytes field 1"));
    }
    let mut len = 0usize;
    for i in 0..3 {
        let b = *proto
            .get(i + 1)
            .ok_or_else(|| invalid("truncated protobuf length"))?;
        len |= ((b & 127) as usize) << (i * 7);
        if b & 128 == 0 {
            if len > MAX_MESSAGE || proto.len() != i + 2 + len {
                return Err(invalid("invalid protobuf payload length"));
            }
            return Ok(Bytes::copy_from_slice(&proto[i + 2..]));
        }
    }
    Err(invalid("protobuf length overflow"))
}
/// 每条连接的流数上限（另受服务端 SETTINGS_MAX_CONCURRENT_STREAMS 限制）。
const MAX_STREAMS: usize = 32;
const MAX_CONNECTIONS: usize = 4;
/// 流接收窗口的下限，也是开满 MAX_STREAMS 条流时每条流的窗口。
const MIN_STREAM_WINDOW: u32 = 128 * 1024;
/// 流接收窗口的上限。单流吞吐约等于「窗口的一半 ÷ 往返时延」（h2 在释放过半窗口时才发 WINDOW_UPDATE），
/// 128 KiB 在 50 ms 往返下只有约 10 Mbit/s；Go 的 HTTP/2 客户端默认 4 MiB，这里取 2 MiB。
const MAX_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
/// 每条连接所有流窗口之和，也是连接窗口：流越少单流窗口越大，流越多越接近下限。
/// 最坏情况下一条连接缓存的未读数据不超过它（与此前固定 128 KiB × 32 条流相同），
/// 少量读者停滞也不会占满连接窗口、阻塞同一连接上的其他流。
pub const WINDOW_BUDGET: u32 = MIN_STREAM_WINDOW * MAX_STREAMS as u32;
/// 连接上有 `streams` 条流时每条流的接收窗口（2 的幂，减少 SETTINGS 变动）。
pub fn stream_window(streams: usize) -> u32 {
    let share = WINDOW_BUDGET / streams.clamp(1, MAX_STREAMS) as u32;
    let share = share.clamp(MIN_STREAM_WINDOW, MAX_STREAM_WINDOW);
    1 << (31 - share.leading_zeros())
}
/// RFC 7541 附录 B 的 Base62 Huffman 码长。padding 的长度是压缩后字节数。
fn base62_huffman_bits(c: u8) -> usize {
    match c {
        b'0'..=b'2' | b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
        b'3'..=b'9'
        | b'A'
        | b'b'
        | b'd'
        | b'f'
        | b'g'
        | b'h'
        | b'l'
        | b'm'
        | b'n'
        | b'p'
        | b'r'
        | b'u' => 6,
        b'X' | b'Z' => 8,
        _ => 7,
    }
}

fn xhttp_padding(spec: &oryn_config::XHttpSpec) -> String {
    let min = spec.padding.min.min(spec.padding.max).min(8192);
    let max = spec.padding.max.min(8192);
    let random = crate::random_bytes(4);
    let value = u32::from_be_bytes(random.try_into().unwrap()) as usize;
    let len = min + value % (max - min + 1);
    if spec.padding.obfs_mode && spec.padding.method == "tokenish" {
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut out = String::with_capacity(len * 8 / 5 + 1);
        let mut bits: usize = 0;
        while bits.div_ceil(8) < len {
            // 拒绝抽样避免 256 对 62 取余引入偏差；随机缓冲最多 256 字节。
            for byte in crate::random_bytes(256) {
                if byte >= 248 {
                    continue;
                }
                let c = ALPHABET[byte as usize % ALPHABET.len()];
                bits += base62_huffman_bits(c);
                out.push(c as char);
                if bits.div_ceil(8) >= len {
                    break;
                }
            }
        }
        return out;
    }
    "X".repeat(len)
}

fn query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            out.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
    }
    out
}

fn append_query(uri: &str, key: &str, value: &str) -> String {
    // 对齐 url.Values.Set：同名参数覆盖，不能追加后留下旧 session/seq/padding。
    let (base, query) = uri.split_once('?').unwrap_or((uri, ""));
    let mut out = base.to_owned();
    let decode_key = |text: &str| {
        let mut bytes = Vec::with_capacity(text.len());
        let mut iter = text.bytes();
        while let Some(b) = iter.next() {
            if b == b'%' {
                let hi = iter.next().and_then(|b| (b as char).to_digit(16));
                let lo = iter.next().and_then(|b| (b as char).to_digit(16));
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    bytes.push((hi * 16 + lo) as u8);
                }
            } else {
                bytes.push(if b == b'+' { b' ' } else { b });
            }
        }
        bytes
    };
    for item in query.split('&').filter(|v| !v.is_empty()) {
        let old_key = item.split_once('=').map(|(k, _)| k).unwrap_or(item);
        if decode_key(old_key) == key.as_bytes() {
            continue;
        }
        out.push(if out.contains('?') { '&' } else { '?' });
        out.push_str(item);
    }
    out.push(if out.contains('?') { '&' } else { '?' });
    out.push_str(&query_escape(key));
    out.push('=');
    out.push_str(&query_escape(value));
    out
}

fn apply_xhttp_padding(
    mut request: http::Request<()>,
    spec: &oryn_config::XHttpSpec,
) -> io::Result<http::Request<()>> {
    let value = xhttp_padding(spec);
    if value.is_empty() {
        return Ok(request);
    }
    // mihomo's compatibility padding is always x_padding in Referer unless
    // obfs mode is explicitly enabled.  In particular, custom key/header
    // values must not silently alter the default wire format.
    let (placement, key, header) = if spec.padding.obfs_mode {
        (
            spec.padding.placement.as_str(),
            spec.padding.key.as_str(),
            spec.padding.header.as_str(),
        )
    } else {
        ("queryinheader", "x_padding", "Referer")
    };
    let uri = request.uri().to_string();
    match placement {
        "header" => {
            let header_name: http::header::HeaderName = header
                .parse()
                .map_err(|_| invalid("invalid XHTTP padding header"))?;
            let header_value: http::header::HeaderValue = value
                .parse()
                .map_err(|_| invalid("invalid XHTTP padding value"))?;
            request.headers_mut().insert(header_name, header_value);
        }
        "query" => {
            let uri = append_query(&uri, key, &value);
            *request.uri_mut() = uri.parse().map_err(io::Error::other)?;
        }
        "cookie" => {
            let cookie = format!("{}={}", key, value);
            let existing = request
                .headers()
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            let combined = if existing.is_empty() {
                cookie
            } else {
                format!("{existing}; {cookie}")
            };
            request.headers_mut().insert(
                http::header::COOKIE,
                combined
                    .parse()
                    .map_err(|_| invalid("invalid XHTTP cookie padding"))?,
            );
        }
        // mihomo's default mode hides x_padding in the Referer URL. The
        // Referer contains the original URL and only the padding query; this
        // deliberately does not copy session/seq metadata into that URL.
        "queryinheader" => {
            let base = uri.split('?').next().unwrap_or(&uri);
            let referer = append_query(base, key, &value);
            let header_name: http::header::HeaderName = header
                .parse()
                .map_err(|_| invalid("invalid XHTTP padding header"))?;
            let header_value: http::header::HeaderValue = referer
                .parse()
                .map_err(|_| invalid("invalid XHTTP padding referer"))?;
            request.headers_mut().insert(header_name, header_value);
        }
        _ => return Err(invalid("unsupported XHTTP padding placement")),
    }
    Ok(request)
}

fn append_path_segment(uri: &str, value: &str) -> String {
    if let Some((base, query)) = uri.split_once('?') {
        format!("{}/{}?{query}", base.trim_end_matches('/'), value)
    } else {
        format!("{}/{}", uri.trim_end_matches('/'), value)
    }
}

/// Encode one packet-up POST according to the configured bounded placement.
/// Binary body is retained for `body`; the other placements use URL-safe
/// base64 so the request remains valid HTTP metadata.
fn apply_uplink_data(
    mut request: http::Request<()>,
    spec: &oryn_config::XHttpSpec,
    data: &[u8],
) -> io::Result<(http::Request<()>, Vec<u8>)> {
    if matches!(spec.uplink_data_placement.as_str(), "body" | "auto") {
        return Ok((request, data.to_vec()));
    }
    let encoded = URL_SAFE_NO_PAD.encode(data);
    let chunk = spec.uplink_chunk_size.clamp(64, 64 * 1024);
    match spec.uplink_data_placement.as_str() {
        "header" => {
            for (index, part) in encoded.as_bytes().chunks(chunk).enumerate() {
                let name: http::HeaderName = format!("{}-{index}", spec.uplink_data_key)
                    .parse()
                    .map_err(|_| invalid("invalid XHTTP data header"))?;
                let value = http::HeaderValue::from_bytes(part)
                    .map_err(|_| invalid("invalid XHTTP data header value"))?;
                request.headers_mut().insert(name, value);
            }
        }
        "cookie" => {
            let mut cookie = request
                .headers()
                .get(http::header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            for (index, part) in encoded.as_bytes().chunks(chunk).enumerate() {
                if !cookie.is_empty() {
                    cookie.push_str("; ");
                }
                cookie.push_str(&format!(
                    "{}_{}={}",
                    spec.uplink_data_key,
                    index,
                    std::str::from_utf8(part).map_err(io::Error::other)?
                ));
            }
            if !cookie.is_empty() {
                request.headers_mut().insert(
                    http::header::COOKIE,
                    cookie
                        .parse()
                        .map_err(|_| invalid("invalid XHTTP data cookie"))?,
                );
            }
        }
        _ => return Err(invalid("unsupported XHTTP uplink data placement")),
    }
    Ok((request, Vec::new()))
}

/// Apply Session/Seq placement. Padding is applied by callers before this
/// function, matching mihomo's request construction order (the default
/// Referer padding must not include session/seq metadata).
fn apply_xhttp_meta(
    mut request: http::Request<()>,
    spec: &oryn_config::XHttpSpec,
    session: &str,
    sequence: Option<u64>,
) -> io::Result<http::Request<()>> {
    let mut uri = request.uri().to_string();
    let mut cookie = request
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let mut set_cookie = |key: &str, value: &str| {
        if !cookie.is_empty() {
            cookie.push_str("; ");
        }
        cookie.push_str(key);
        cookie.push('=');
        cookie.push_str(value);
    };
    let mut apply = |placement: &str, key: &str, value: &str| -> io::Result<()> {
        match placement {
            "path" => uri = append_path_segment(&uri, value),
            "query" => uri = append_query(&uri, key, value),
            "header" => {
                let name: http::HeaderName = key
                    .parse()
                    .map_err(|_| invalid("invalid XHTTP metadata header"))?;
                let value: http::HeaderValue = value
                    .parse()
                    .map_err(|_| invalid("invalid XHTTP metadata value"))?;
                request.headers_mut().insert(name, value);
            }
            "cookie" => set_cookie(key, value),
            _ => return Err(invalid("invalid XHTTP metadata placement")),
        }
        Ok(())
    };
    if !session.is_empty() {
        apply(&spec.session_placement, &spec.session_key, session)?;
    }
    if let Some(sequence) = sequence {
        apply(&spec.seq_placement, &spec.seq_key, &sequence.to_string())?;
    }
    if uri != request.uri().to_string() {
        *request.uri_mut() = uri.parse().map_err(io::Error::other)?;
    }
    if !cookie.is_empty() {
        request.headers_mut().insert(
            http::header::COOKIE,
            cookie
                .parse()
                .map_err(|_| invalid("invalid XHTTP cookie"))?,
        );
    }
    Ok(request)
}

fn new_xhttp_session(spec: &oryn_config::XHttpSpec) -> String {
    // mihomo's historical empty-table format is 16 random bytes rendered as
    // lower-case hexadecimal (32 characters). Configured tables use the
    // bounded session length and a named alphabet when requested.
    if spec.session_table.is_empty() {
        return crate::random_bytes(16)
            .into_iter()
            .flat_map(|b| {
                let hi = b"0123456789abcdef"[(b >> 4) as usize] as char;
                let lo = b"0123456789abcdef"[(b & 0x0f) as usize] as char;
                [hi, lo]
            })
            .collect();
    }
    if spec.session_table.eq_ignore_ascii_case("uuid") {
        let mut b = crate::random_bytes(16);
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        return format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        );
    }
    let table = match spec.session_table.as_str() {
        "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX" => "0123456789ABCDEF",
        "alphabet" => "abcdefghijklmnopqrstuvwxyz",
        "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex" => "0123456789abcdef",
        "number" => "0123456789",
        value => value,
    };
    let length = spec.session_length.clamp(1, 128);
    crate::random_bytes(length)
        .into_iter()
        .map(|b| table.as_bytes()[b as usize % table.len()] as char)
        .collect()
}

/// 拨号由 Outbound 提供；XHTTP 可在连接寿命结束后重新拨号。
pub trait XHttpIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> XHttpIo for T {}
pub type XHttpDial = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<Box<dyn XHttpIo>>> + Send>> + Send + Sync,
>;

fn xhttp_request(
    authority: &str,
    spec: &oryn_config::XHttpSpec,
    method: &str,
    session: &str,
    sequence: Option<u64>,
    stream_body: bool,
    packet: Option<&[u8]>,
) -> io::Result<(http::Request<()>, Vec<u8>)> {
    let (scheme, authority) = if let Some(host) = authority.strip_prefix("http://") {
        ("http", host)
    } else {
        (
            "https",
            authority.strip_prefix("https://").unwrap_or(authority),
        )
    };
    let host = spec.hosts.first().map(String::as_str).unwrap_or(authority);
    let path = if spec.session_placement == "path" || spec.seq_placement == "path" {
        // stream-one 也使用归一化尾斜线，和 mihomo 的路由前缀一致。
        if let Some((path, query)) = spec.path.split_once('?') {
            format!("{}/?{query}", path.trim_end_matches('/'))
        } else {
            format!("{}/", spec.path.trim_end_matches('/'))
        }
    } else {
        spec.path.clone()
    };
    let mut request = http::Request::builder()
        .method(method)
        .uri(format!("{scheme}://{host}{path}"));
    for (name, value) in &spec.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let mut request = request.body(()).map_err(io::Error::other)?;
    if stream_body && !spec.no_grpc_header {
        request.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/grpc"),
        );
    }
    let (request, body) = if let Some(data) = packet {
        apply_uplink_data(request, spec, data)?
    } else {
        (request, Vec::new())
    };
    let request = apply_xhttp_padding(request, spec)?;
    Ok((apply_xhttp_meta(request, spec, session, sequence)?, body))
}

#[cfg(not(test))]
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(not(test))]
const IDLE_CHECK: Duration = Duration::from_secs(10);
#[cfg(test)]
const IDLE_TIMEOUT: Duration = Duration::from_millis(300);
#[cfg(test)]
const IDLE_CHECK: Duration = Duration::from_millis(100);

struct Conn {
    send: StdMutex<h2::client::SendRequest<Bytes>>,
    /// 目标流窗口；driver 任务在上一次 SETTINGS 被确认后再下发新值。
    window: tokio::sync::watch::Sender<u32>,
    active: AtomicUsize,
    xhttp_active: AtomicUsize,
    idle_since: StdMutex<Instant>,
    broken: AtomicBool,
    driver: tokio::task::JoinHandle<()>,
    request_count: AtomicUsize,
    reuse_count: AtomicUsize,
    created: Instant,
    max_reuse_times: usize,
    max_request_times: usize,
    max_reusable_secs: u64,
}
impl Drop for Conn {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl Conn {
    /// 流数变化后重新计算单流窗口。
    fn retune(&self) {
        let window = stream_window(self.active.load(Ordering::Acquire));
        self.window.send_if_modified(|current| {
            let changed = *current != window;
            *current = window;
            changed
        });
    }
    fn alive(&self) -> bool {
        !self.driver.is_finished() && !self.broken.load(Ordering::Acquire)
    }
    fn has_room(&self, max_concurrency: usize) -> bool {
        let limit = max_concurrency
            .min(MAX_STREAMS)
            .min(self.send.lock().unwrap().current_max_send_streams());
        self.active.load(Ordering::Acquire) < limit
    }
    fn reusable(&self) -> bool {
        let reused = self.reuse_count.load(Ordering::Acquire);
        let requests = self.request_count.load(Ordering::Acquire);
        (self.max_reuse_times == 0 || reused < self.max_reuse_times)
            && (self.max_request_times == 0 || requests < self.max_request_times)
            && (self.max_reusable_secs == 0
                || self.created.elapsed().as_secs() < self.max_reusable_secs)
    }
    fn idle_expired(&self) -> bool {
        self.active.load(Ordering::Acquire) == 0
            && self.xhttp_active.load(Ordering::Acquire) == 0
            && self.idle_since.lock().unwrap().elapsed() >= IDLE_TIMEOUT
    }
    async fn request(
        &self,
        req: http::Request<()>,
        end_stream: bool,
    ) -> io::Result<(h2::client::ResponseFuture, h2::SendStream<Bytes>)> {
        let send = self.send.lock().unwrap().clone();
        let mut send = send.ready().await.map_err(io::Error::other)?;
        send.send_request(req, end_stream).map_err(io::Error::other)
    }
}

/// 流持有连接的引用；最后一个流结束且连接已移出池时，连接随之关闭。
struct Lease(Arc<Conn>);
impl Drop for Lease {
    fn drop(&mut self) {
        *self.0.idle_since.lock().unwrap() = Instant::now();
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.retune();
    }
}

/// 一个出站的 gRPC 连接池：多条 Flow 共享 h2 连接，每条 Flow 一个 gRPC 流。
#[derive(Clone)]
pub struct GrpcPool {
    /// SETTINGS 的首部表与首部列表上限按 Chrome 取值（NaïveProxy 用）；窗口仍用有界的值。
    chrome: bool,
    conns: Arc<tokio::sync::Mutex<Vec<Arc<Conn>>>>,
    /// 正在池外拨号/握手的连接数；作为容量预留，避免并发 Flow 越过上限。
    opening: Arc<AtomicUsize>,
    opening_changed: Arc<tokio::sync::Notify>,
    cleaner: Arc<StdMutex<Option<tokio::task::JoinHandle<()>>>>,
    xhttp_reuse: Option<oryn_config::XHttpReuseSpec>,
    xhttp_limits: Arc<OnceLock<(usize, usize)>>,
}
impl Default for GrpcPool {
    fn default() -> Self {
        Self {
            chrome: false,
            conns: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            opening: Arc::new(AtomicUsize::new(0)),
            opening_changed: Arc::new(tokio::sync::Notify::new()),
            cleaner: Arc::new(StdMutex::new(None)),
            xhttp_reuse: None,
            xhttp_limits: Arc::new(OnceLock::new()),
        }
    }
}
impl Drop for GrpcPool {
    fn drop(&mut self) {
        if Arc::strong_count(&self.cleaner) == 1 {
            if let Some(cleaner) = self.cleaner.lock().unwrap().take() {
                cleaner.abort();
            }
        }
    }
}
impl GrpcPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn chrome() -> Self {
        let mut pool = Self::default();
        pool.chrome = true;
        pool
    }

    /// 为 XHTTP 建立一份共享连接池视图。连接存储仍与原池共享，
    /// 但此视图把 xmux 的并发、连接数和寿命限制应用到 acquire。
    fn with_xhttp_reuse(&self, reuse: &oryn_config::XHttpReuseSpec) -> Self {
        let mut pool = self.clone();
        pool.xhttp_limits.get_or_init(|| {
            (
                sample_range(reuse.min_max_concurrency, reuse.max_concurrency),
                sample_range(reuse.min_max_connections, reuse.max_connections),
            )
        });
        pool.xhttp_reuse = Some(reuse.clone());
        pool
    }

    /// 打开一个 CONNECT 流（NaïveProxy）：`target` 为 `host:port`，响应须为 200。
    pub async fn open_connect<S, F, Fut>(
        &self,
        target: &str,
        headers: &[(String, String)],
        dial: F,
    ) -> io::Result<GrpcStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<S>>,
    {
        let mut request = http::Request::builder().method("CONNECT").uri(target);
        for (name, value) in headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let request = request.body(()).map_err(io::Error::other)?;
        self.open_request(request, true, &[], false, dial).await
    }

    /// 打开一个 gRPC 流并写出协议首部。`dial` 只在需要新连接时调用，返回已完成 TLS（h2）的字节流。
    pub async fn open<S, F, Fut>(
        &self,
        authority: &str,
        spec: &oryn_config::GrpcSpec,
        initial: &[u8],
        dial: F,
    ) -> io::Result<GrpcStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<S>>,
    {
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("https://{authority}/{}/Tun", spec.service_name))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .map_err(io::Error::other)?;
        self.open_request(request, false, initial, false, dial)
            .await
    }

    /// 打开一个 `network: h2` 流：PUT 请求，请求体与响应体是原始字节。
    pub async fn open_h2<S, F, Fut>(
        &self,
        authority: &str,
        spec: &oryn_config::H2Spec,
        initial: &[u8],
        dial: F,
    ) -> io::Result<GrpcStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<S>>,
    {
        // 与 V2Ray 一致：Host 取配置的候选，没有配置时用连接的服务器地址
        let host = spec.hosts.first().map(String::as_str).unwrap_or(authority);
        let request = http::Request::builder()
            .method("PUT")
            .uri(format!("https://{host}{}", spec.path))
            .body(())
            .map_err(io::Error::other)?;
        self.open_request(request, true, initial, false, dial).await
    }

    /// 单次拨号的兼容入口。需要连接轮换或独立下载地址时使用 with_dialers 入口。
    pub async fn open_xhttp<S, F, Fut>(
        &self,
        authority: &str,
        spec: &oryn_config::XHttpSpec,
        initial: &[u8],
        dial: F,
    ) -> io::Result<XHttpStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<S>> + Send + 'static,
    {
        let dial = Arc::new(StdMutex::new(Some(dial)));
        let dial: XHttpDial = Arc::new(move || {
            let dial = dial.lock().unwrap().take();
            Box::pin(async move {
                let dial =
                    dial.ok_or_else(|| io::Error::other("XHTTP needs a repeatable dialer"))?;
                Ok(Box::new(dial().await?) as Box<dyn XHttpIo>)
            })
        });
        self.open_xhttp_with_dialers(authority, spec, initial, dial, None)
            .await
    }

    /// 每个方向使用独立拨号器和连接池；无下载配置时两方向共享一次 Flow 引用。
    pub async fn open_xhttp_with_dialers(
        &self,
        authority: &str,
        spec: &oryn_config::XHttpSpec,
        initial: &[u8],
        dial: XHttpDial,
        download: Option<(&GrpcPool, &str, XHttpDial)>,
    ) -> io::Result<XHttpStream> {
        let mode = if spec.mode == "auto" {
            "packet-up"
        } else {
            &spec.mode
        };
        let upload_client = XHttpClient::new(self.with_xhttp_reuse(&spec.reuse), dial);
        if mode == "stream-one" {
            let (request, _) = xhttp_request(
                authority,
                spec,
                &spec.uplink_http_method,
                "",
                None,
                true,
                None,
            )?;
            return Ok(XHttpStream::Single(
                upload_client.open(request, initial, false).await?,
            ));
        }
        if !matches!(mode, "stream-up" | "packet-up") {
            return Err(invalid("invalid XHTTP mode"));
        }
        let session = new_xhttp_session(spec);
        let download_spec = spec
            .download
            .as_ref()
            .map(|d| d.transport.as_ref())
            .unwrap_or(spec);
        let (download_client, download_authority) = if let Some((pool, authority, dial)) = download
        {
            (
                XHttpClient::new(pool.with_xhttp_reuse(&download_spec.reuse), dial),
                authority,
            )
        } else {
            (upload_client.clone(), authority)
        };
        let (request, _) = xhttp_request(
            download_authority,
            download_spec,
            "GET",
            &session,
            None,
            false,
            None,
        )?;
        // 先发 GET，但不等待响应首部，避免等上传数据的服务端死锁。
        let download = download_client.open(request, &[], true).await?;
        if mode == "packet-up" {
            let mut stream = PacketUpStream::new(
                download,
                upload_client,
                authority.to_owned(),
                session,
                spec.clone(),
            );
            if !initial.is_empty() {
                stream.write_all(initial).await?;
                // packet-up 的 write 允许有界缓存；返回 Flow 前必须发出协议握手，
                // 并等服务端确认，这样首个 POST 被拒绝时调用方拿到的是连接错误。
                std::future::poll_fn(|cx| stream.poll_drain(cx)).await?;
            }
            return Ok(XHttpStream::Packet(stream));
        }
        let (request, _) = xhttp_request(
            authority,
            spec,
            &spec.uplink_http_method,
            &session,
            None,
            true,
            None,
        )?;
        let upload = upload_client.open(request, initial, false).await?;
        Ok(XHttpStream::Split { upload, download })
    }

    async fn open_request<S, F, Fut>(
        &self,
        request: http::Request<()>,
        raw: bool,
        initial: &[u8],
        end_stream: bool,
        dial: F,
    ) -> io::Result<GrpcStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<S>>,
    {
        self.start_cleaner();
        let mut dial = Some(dial);
        loop {
            let (lease, fresh) = self.acquire(&mut dial).await?;
            match lease.0.request(request.clone(), end_stream).await {
                Ok((response, send)) => {
                    let mut out = GrpcStream {
                        response: Some(response),
                        send,
                        recv: None,
                        read: Vec::new(),
                        payload: Bytes::new(),
                        pending: Bytes::new(),
                        eof: false,
                        closed: false,
                        raw,
                        _lease: lease,
                        _xhttp_flow: None,
                    };
                    // 不先等待响应：服务端通常收到协议首部之后才发送 HTTP 响应。
                    if !initial.is_empty() {
                        out.write_all(initial).await?;
                        out.flush().await?;
                    }
                    return Ok(out);
                }
                Err(err) => {
                    lease.0.broken.store(true, Ordering::Release);
                    // 复用的连接可能已被服务端关闭（GOAWAY 等），换新连接重试一次。
                    if fresh || dial.is_none() {
                        return Err(err);
                    }
                }
            }
        }
    }

    async fn acquire<S, F, Fut>(&self, dial: &mut Option<F>) -> io::Result<(Lease, bool)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<S>>,
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            // 先注册再查看 opening，避免释放池锁与等待之间丢失通知。
            let changed = self.opening_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let mut conns = self.conns.lock().await;
            conns.retain(|c| c.alive() && c.reusable());
            let max_concurrency = self
                .xhttp_reuse
                .as_ref()
                .map(|r| r.max_concurrency)
                .filter(|n| *n > 0)
                .unwrap_or(MAX_STREAMS);
            if let Some(conn) = conns.iter().find(|c| c.has_room(max_concurrency)) {
                conn.reuse_count.fetch_add(1, Ordering::AcqRel);
                conn.active.fetch_add(1, Ordering::AcqRel);
                conn.retune();
                return Ok((Lease(conn.clone()), false));
            }
            let reserved = conns.len() + self.opening.load(Ordering::Acquire);
            let max_connections = self
                .xhttp_reuse
                .as_ref()
                .map(|r| r.max_connections)
                .filter(|n| *n > 0)
                .unwrap_or(MAX_CONNECTIONS)
                .min(MAX_CONNECTIONS);
            if reserved >= max_connections {
                if self.opening.load(Ordering::Acquire) > 0 {
                    drop(conns);
                    tokio::time::timeout_at(deadline, changed)
                        .await
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "HTTP/2 connection pool opening timed out",
                            )
                        })?;
                    continue;
                }
                return Err(io::Error::other("gRPC connection pool capacity reached"));
            }
            // 只在锁内预留名额；耗时的拨号与 h2 握手在锁外执行。
            self.opening.fetch_add(1, Ordering::AcqRel);
            let opening = Opening {
                count: self.opening.clone(),
                changed: self.opening_changed.clone(),
            };
            drop(conns);

            let stream = dial.take().expect("dial is used once")().await?;
            let conn = Arc::new(handshake(stream, self.chrome, self.xhttp_reuse.as_ref()).await?);
            // 先发布完整连接和首条流名额，再归还 opening，不能留下容量计数空档。
            conn.active.store(1, Ordering::Release);
            self.conns.lock().await.push(conn.clone());
            drop(opening);
            return Ok((Lease(conn), true));
        }
    }

    fn start_cleaner(&self) {
        let mut cleaner = self.cleaner.lock().unwrap();
        if cleaner.is_some() {
            return;
        }
        let conns = Arc::downgrade(&self.conns);
        *cleaner = Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(IDLE_CHECK);
            loop {
                tick.tick().await;
                let Some(conns) = conns.upgrade() else { break };
                conns
                    .lock()
                    .await
                    .retain(|c| c.alive() && !c.idle_expired());
            }
        }));
    }

    #[cfg(test)]
    async fn connections(&self) -> usize {
        self.conns.lock().await.len()
    }
}

fn sample_range(min: usize, max: usize) -> usize {
    let min = min.min(max);
    if min == max {
        return min;
    }
    let random = crate::random_bytes(8);
    let random = u64::from_be_bytes(random.try_into().unwrap());
    min + (random % (max - min + 1) as u64) as usize
}

/// 一个 XHTTP Flow 在一个 h2 连接上的占用，和该 Flow 的 HTTP 请求数分开计数。
struct XHttpFlowLease(Arc<Conn>);
impl Drop for XHttpFlowLease {
    fn drop(&mut self) {
        *self.0.idle_since.lock().unwrap() = Instant::now();
        self.0.xhttp_active.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Opening {
    count: Arc<AtomicUsize>,
    changed: Arc<tokio::sync::Notify>,
}
impl Drop for Opening {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
        self.changed.notify_waiters();
    }
}

#[derive(Clone)]
struct XHttpClient {
    pool: GrpcPool,
    dial: XHttpDial,
    current: Arc<tokio::sync::Mutex<Option<Arc<XHttpFlowLease>>>>,
}
impl XHttpClient {
    fn new(pool: GrpcPool, dial: XHttpDial) -> Self {
        Self {
            pool,
            dial,
            current: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
    async fn acquire_flow(&self) -> io::Result<Arc<XHttpFlowLease>> {
        self.pool.start_cleaner();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let changed = self.pool.opening_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let mut conns = self.pool.conns.lock().await;
            // 过期但仍被 Flow 或 HTTP 请求持有的连接仍计容量，防止池外无限积累。
            conns.retain(|c| {
                c.alive()
                    && (c.reusable()
                        || c.active.load(Ordering::Acquire) > 0
                        || c.xhttp_active.load(Ordering::Acquire) > 0)
            });
            let (concurrency, connections) =
                self.pool.xhttp_limits.get().copied().unwrap_or((0, 0));
            let concurrency = if concurrency == 0 {
                MAX_STREAMS
            } else {
                concurrency.min(MAX_STREAMS)
            };
            let connections = if connections == 0 {
                MAX_CONNECTIONS
            } else {
                connections.min(MAX_CONNECTIONS)
            };
            if let Some(conn) = conns
                .iter()
                .filter(|c| {
                    c.reusable()
                        && c.has_room(MAX_STREAMS)
                        && c.xhttp_active.load(Ordering::Acquire) < concurrency
                })
                .min_by_key(|c| c.xhttp_active.load(Ordering::Acquire))
            {
                conn.reuse_count.fetch_add(1, Ordering::AcqRel);
                conn.xhttp_active.fetch_add(1, Ordering::AcqRel);
                return Ok(Arc::new(XHttpFlowLease(conn.clone())));
            }
            if conns.len() + self.pool.opening.load(Ordering::Acquire) >= connections {
                if self.pool.opening.load(Ordering::Acquire) > 0 {
                    drop(conns);
                    tokio::time::timeout_at(deadline, changed)
                        .await
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "XHTTP connection pool opening timed out",
                            )
                        })?;
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "XHTTP connection pool capacity reached",
                ));
            }
            self.pool.opening.fetch_add(1, Ordering::AcqRel);
            let opening = Opening {
                count: self.pool.opening.clone(),
                changed: self.pool.opening_changed.clone(),
            };
            drop(conns);
            let conn = Arc::new(
                handshake(
                    (self.dial)().await?,
                    self.pool.chrome,
                    self.pool.xhttp_reuse.as_ref(),
                )
                .await?,
            );
            conn.xhttp_active.store(1, Ordering::Release);
            self.pool.conns.lock().await.push(conn.clone());
            drop(opening);
            return Ok(Arc::new(XHttpFlowLease(conn)));
        }
    }
    async fn open(
        &self,
        request: http::Request<()>,
        initial: &[u8],
        end_stream: bool,
    ) -> io::Result<GrpcStream> {
        let mut current = self.current.lock().await;
        let flow = loop {
            if let Some(flow) = current.as_ref() {
                let conn = &flow.0;
                let age_ok = conn.max_reusable_secs == 0
                    || conn.created.elapsed().as_secs() < conn.max_reusable_secs;
                if conn.alive()
                    && age_ok
                    && conn.has_room(MAX_STREAMS)
                    && conn
                        .request_count
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            (conn.max_request_times == 0 || count < conn.max_request_times)
                                .then_some(count + 1)
                        })
                        .is_ok()
                {
                    break flow.clone();
                }
            }
            // 旧下载流仍持有旧连接；新 POST 可在另一条有界连接上继续同一 session。
            *current = None;
            *current = Some(self.acquire_flow().await?);
        };
        flow.0.active.fetch_add(1, Ordering::AcqRel);
        flow.0.retune();
        let lease = Lease(flow.0.clone());
        drop(current);
        let (response, send) = match flow.0.request(request, end_stream).await {
            Ok(value) => value,
            Err(error) => {
                flow.0.broken.store(true, Ordering::Release);
                return Err(error);
            }
        };
        let mut out = GrpcStream {
            response: Some(response),
            send,
            recv: None,
            read: Vec::new(),
            payload: Bytes::new(),
            pending: Bytes::new(),
            eof: false,
            closed: end_stream,
            raw: true,
            _lease: lease,
            _xhttp_flow: Some(flow),
        };
        if !initial.is_empty() {
            out.write_all(initial).await?;
            out.flush().await?;
        }
        Ok(out)
    }
}

/// 驱动一条 h2 客户端连接，并让它的单流接收窗口可以随流数调整。
///
/// 返回的 `watch::Sender` 里放目标窗口（用 [`stream_window`] 算）；驱动任务在上一条 SETTINGS 被确认后
/// 再下发新值（h2 同时只允许一条未确认的 SETTINGS，失败就稍后重试）。`first` 是握手时已经通告的窗口。
/// 返回的任务句柄被丢弃或中止时连接随之关闭。
pub fn drive_with_window<T, B>(
    mut connection: h2::client::Connection<T, B>,
    first: u32,
) -> (tokio::sync::watch::Sender<u32>, tokio::task::JoinHandle<()>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Buf + Send + 'static,
{
    let (window, mut wanted) = tokio::sync::watch::channel(first);
    let driver = tokio::spawn(async move {
        let mut applied = first;
        let mut retry = false;
        loop {
            tokio::select! {
                _ = &mut connection => break,
                changed = wanted.changed(), if !retry => {
                    if changed.is_err() {
                        let _ = connection.await;
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(25)), if retry => {}
            }
            let target = *wanted.borrow_and_update();
            if target != applied {
                retry = connection.set_initial_window_size(target).is_err();
                if !retry {
                    applied = target;
                }
            } else {
                retry = false;
            }
        }
    });
    (window, driver)
}

async fn handshake<S>(
    stream: S,
    chrome: bool,
    reuse: Option<&oryn_config::XHttpReuseSpec>,
) -> io::Result<Conn>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::client::Builder::new();
    if chrome {
        builder
            .header_table_size(65536)
            .max_header_list_size(256 * 1024);
    } else {
        builder.max_header_list_size(16 * 1024);
    }
    // 建连时这条连接上只有第一条流，窗口从最大值开始；之后随流数调整（见 Conn::retune）。
    let first = stream_window(1);
    let (send, connection) = builder
        .enable_push(false)
        .initial_window_size(first)
        .initial_connection_window_size(WINDOW_BUDGET)
        .max_frame_size(16 * 1024)
        .max_send_buffer_size(SEND_BUFFER)
        .handshake(stream)
        .await
        .map_err(io::Error::other)?;
    let (window, driver) = drive_with_window(connection, first);
    Ok(Conn {
        send: StdMutex::new(send),
        window,
        active: AtomicUsize::new(0),
        xhttp_active: AtomicUsize::new(0),
        idle_since: StdMutex::new(Instant::now()),
        broken: AtomicBool::new(false),
        driver,
        request_count: AtomicUsize::new(0),
        reuse_count: AtomicUsize::new(0),
        created: Instant::now(),
        max_reuse_times: reuse
            .map(|r| sample_range(r.min_max_reuse_times, r.max_reuse_times))
            .unwrap_or(0),
        max_request_times: reuse
            .map(|r| sample_range(r.min_max_request_times, r.max_request_times))
            .unwrap_or(0),
        max_reusable_secs: reuse
            .map(|r| {
                sample_range(
                    r.min_max_reusable_secs as usize,
                    r.max_reusable_secs as usize,
                ) as u64
            })
            .unwrap_or(0),
    })
}

pub struct GrpcStream {
    response: Option<h2::client::ResponseFuture>,
    send: h2::SendStream<Bytes>,
    recv: Option<h2::RecvStream>,
    read: Vec<u8>,
    payload: Bytes,
    pending: Bytes,
    eof: bool,
    closed: bool,
    /// `network: h2`：不做 gun 分帧。
    raw: bool,
    _lease: Lease,
    _xhttp_flow: Option<Arc<XHttpFlowLease>>,
}
impl GrpcStream {
    async fn check_status(&mut self) -> io::Result<()> {
        let Some(response) = self.response.take() else {
            return Ok(());
        };
        let response = response.await.map_err(io::Error::other)?;
        if !response.status().is_success() {
            return Err(invalid("XHTTP upload got a non-success response"));
        }
        self.recv = Some(response.into_body());
        Ok(())
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            self.send.reserve_capacity(self.pending.len());
            let n = match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(n)) if n > 0 => n.min(self.pending.len()),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "h2 stream closed",
                    )))
                }
            };
            self.send
                .send_data(self.pending.split_to(n), false)
                .map_err(io::Error::other)?;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "gRPC write closed",
            )));
        }
        ready!(self.drain(cx))?;
        let n = data.len().min(WRITE_CHUNK);
        if n > 0 {
            self.pending = if self.raw {
                Bytes::copy_from_slice(&data[..n])
            } else {
                frame(&data[..n])
            };
        }
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
impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(response) = &mut self.response {
            let response = ready!(Pin::new(response).poll(cx)).map_err(io::Error::other)?;
            if self.raw {
                if response.status() != http::StatusCode::OK {
                    return Poll::Ready(Err(invalid("HTTP/2 transport got a non-200 response")));
                }
            } else {
                if response.status() != http::StatusCode::OK
                    || !response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|s| s.starts_with("application/grpc"))
                {
                    return Poll::Ready(Err(invalid("invalid gRPC HTTP response")));
                }
                if response
                    .headers()
                    .get("grpc-status")
                    .is_some_and(|s| s != "0")
                {
                    return Poll::Ready(Err(invalid("gRPC server returned error")));
                }
            }
            self.recv = Some(response.into_body());
            self.response = None;
        }
        if self.raw {
            // 响应体就是字节流：数据块直接交给调用方
            loop {
                if !self.payload.is_empty() {
                    let n = self.payload.len().min(buf.remaining());
                    buf.put_slice(&self.payload[..n]);
                    self.payload.advance(n);
                    return Poll::Ready(Ok(()));
                }
                if self.eof {
                    return Poll::Ready(Ok(()));
                }
                let recv = self.recv.as_mut().unwrap();
                match ready!(recv.poll_data(cx)) {
                    Some(Ok(data)) => {
                        recv.flow_control()
                            .release_capacity(data.len())
                            .map_err(io::Error::other)?;
                        self.payload = data;
                    }
                    Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                    None => self.eof = true,
                }
            }
        }
        loop {
            if !self.payload.is_empty() {
                let n = self.payload.len().min(buf.remaining());
                buf.put_slice(&self.payload[..n]);
                self.payload.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.read.len() >= 5 {
                if self.read[0] != 0 {
                    return Poll::Ready(Err(invalid("compressed gRPC messages unsupported")));
                }
                let n = u32::from_be_bytes(self.read[1..5].try_into().unwrap()) as usize;
                if n > MAX_MESSAGE + 4 {
                    return Poll::Ready(Err(invalid("gRPC message exceeds limit")));
                }
                if self.read.len() >= 5 + n {
                    self.payload = payload(&self.read[5..5 + n])?;
                    self.read.drain(..5 + n);
                    continue;
                }
            }
            if self.eof {
                if !self.read.is_empty() {
                    return Poll::Ready(Err(invalid("truncated gRPC message")));
                }
                let trailers = ready!(self.recv.as_mut().unwrap().poll_trailers(cx))
                    .map_err(io::Error::other)?;
                if trailers
                    .as_ref()
                    .and_then(|h| h.get("grpc-status"))
                    .is_some_and(|s| s != "0")
                {
                    return Poll::Ready(Err(invalid("gRPC server returned error")));
                }
                return Poll::Ready(Ok(()));
            }
            let recv = self.recv.as_mut().unwrap();
            match ready!(recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    let n = data.len();
                    recv.flow_control()
                        .release_capacity(n)
                        .map_err(io::Error::other)?;
                    if self.read.len() + n > MAX_MESSAGE + 4 + 5 + 16 * 1024 {
                        return Poll::Ready(Err(invalid("gRPC receive buffer exceeds limit")));
                    }
                    self.read.extend_from_slice(&data);
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => self.eof = true,
            }
        }
    }
}

enum PacketCommand {
    Data(Vec<u8>, oneshot::Sender<io::Result<usize>>),
    Shutdown(oneshot::Sender<io::Result<()>>),
}

/// 发一条上传 POST：写完 body、等到服务端状态；序号由调用方按顺序分配。
async fn send_packet_post(
    client: &XHttpClient,
    authority: &str,
    spec: &oryn_config::XHttpSpec,
    session: &str,
    sequence: u64,
    data: &[u8],
) -> io::Result<usize> {
    let (request, body) = xhttp_request(
        authority,
        spec,
        &spec.uplink_http_method,
        session,
        Some(sequence),
        false,
        Some(data),
    )?;
    let mut stream = client.open(request, &body, body.is_empty()).await?;
    if !body.is_empty() {
        stream.shutdown().await?;
    }
    stream.check_status().await?;
    Ok(data.len())
}

/// 按序分配 `x-seq` 并发出上传 POST。同时在途的数量由 `PacketUpStream` 限制（`depth`），
/// 服务端按序号重排，最多缓存 `sc-max-buffered-posts` 个乱序请求；
/// 每条 POST 单独一个任务，串行等待响应的话单流上传只有「每个往返一块」。
async fn packet_upload_worker(
    client: XHttpClient,
    authority: String,
    session: String,
    spec: oryn_config::XHttpSpec,
    mut commands: tokio::sync::mpsc::Receiver<PacketCommand>,
    failure: Arc<StdMutex<PacketFailure>>,
) {
    let mut sequence = 0u64;
    let interval = Duration::from_millis(spec.sc_min_posts_interval_ms);
    let mut last_post: Option<Instant> = None;
    let failed = Arc::new(AtomicBool::new(false));
    let authority = Arc::new(authority);
    let session = Arc::new(session);
    let spec = Arc::new(spec);
    // worker 被中止时，JoinSet 随之丢弃并取消所有在途 POST。
    let mut posts = tokio::task::JoinSet::new();
    while let Some(command) = commands.recv().await {
        // 有 POST 失败后序列已不连续，继续发后面的块只会让服务端错位。
        if failed.load(Ordering::Acquire) {
            break;
        }
        match command {
            PacketCommand::Data(data, ack) => {
                if let Some(last) = last_post {
                    let elapsed = last.elapsed();
                    if elapsed < interval {
                        tokio::time::sleep(interval - elapsed).await;
                    }
                }
                last_post = Some(Instant::now());
                let Some(next) = sequence.checked_add(1) else {
                    failed.store(true, Ordering::Release);
                    failure.lock().unwrap().set(&invalid("XHTTP sequence exhausted"));
                    let _ = ack.send(Err(invalid("XHTTP sequence exhausted")));
                    break;
                };
                let this = sequence;
                sequence = next;
                let (client, authority, session, spec, failed) = (
                    client.clone(),
                    authority.clone(),
                    session.clone(),
                    spec.clone(),
                    failed.clone(),
                );
                let failure = failure.clone();
                posts.spawn(async move {
                    let result =
                        send_packet_post(&client, &authority, &spec, &session, this, &data).await;
                    if let Err(error) = &result {
                        failed.store(true, Ordering::Release);
                        failure.lock().unwrap().set(error);
                    }
                    let _ = ack.send(result);
                });
                while posts.try_join_next().is_some() {}
            }
            PacketCommand::Shutdown(ack) => {
                while posts.join_next().await.is_some() {}
                let result = if failed.load(Ordering::Acquire) {
                    Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "XHTTP packet-up upload failed",
                    ))
                } else {
                    Ok(())
                };
                let _ = ack.send(result);
                break;
            }
        }
    }
}

/// 同时在途的上传 POST 数上限（还受 `sc-max-buffered-posts` 限制）。
/// 吞吐 ≈ 在途数 × 每块字节 ÷ 往返时延；在途数 × 块大小也是单个 Flow 在这里缓存的上限。
const PACKET_INFLIGHT: usize = 8;

/// 独立于 POST ack 的读端通知，避免读写任务互相覆盖 oneshot 的 waker。
#[derive(Default)]
struct PacketFailure {
    error: Option<(io::ErrorKind, String)>,
    reader: Option<std::task::Waker>,
}
impl PacketFailure {
    fn set(&mut self, error: &io::Error) {
        if self.error.is_none() {
            self.error = Some((error.kind(), error.to_string()));
        }
        if let Some(reader) = self.reader.take() {
            reader.wake();
        }
    }
    fn check(&self) -> io::Result<()> {
        match &self.error {
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            None => Ok(()),
        }
    }
}

pub struct PacketUpStream {
    download: GrpcStream,
    commands: tokio::sync::mpsc::Sender<PacketCommand>,
    /// 已交给 worker、尚未确认的 POST（按发送顺序）；个数不超过 `depth`。
    inflight: std::collections::VecDeque<oneshot::Receiver<io::Result<usize>>>,
    depth: usize,
    pending_shutdown: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
    closed: bool,
    failed: bool,
    chunk_limit: usize,
    task: tokio::task::JoinHandle<()>,
    failure: Arc<StdMutex<PacketFailure>>,
}
impl PacketUpStream {
    fn new(
        download: GrpcStream,
        client: XHttpClient,
        authority: String,
        session: String,
        spec: oryn_config::XHttpSpec,
    ) -> Self {
        let depth = spec.sc_max_buffered_posts.clamp(1, PACKET_INFLIGHT);
        // 队列容量比在途数多 1，保证 `try_send` 在在途数未满时一定成功（再多一条留给 Shutdown）。
        let (commands, rx) = tokio::sync::mpsc::channel(depth + 1);
        let chunk_limit = if spec.uplink_data_placement == "body" {
            spec.sc_max_each_post_bytes
        } else {
            spec.uplink_chunk_size.min(spec.sc_max_each_post_bytes)
        }
        .clamp(1, 64 * 1024);
        let failure = Arc::new(StdMutex::new(PacketFailure::default()));
        let task = tokio::spawn(packet_upload_worker(
            client, authority, session, spec, rx, failure.clone(),
        ));
        Self {
            download,
            commands,
            inflight: Default::default(),
            depth,
            pending_shutdown: None,
            closed: false,
            chunk_limit,
            failed: false,
            task,
            failure,
        }
    }

    /// 回收已完成的 POST；任何一块失败都使整个上传失败（序列已不连续）。
    /// 未完成的会登记当前任务的唤醒，所以只能由写端调用。
    fn reap(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        self.failure.lock().unwrap().check()?;
        if self.failed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut i = 0;
        while i < self.inflight.len() {
            match Pin::new(&mut self.inflight[i]).poll(cx) {
                Poll::Ready(Ok(Ok(_))) => {
                    self.inflight.remove(i);
                }
                Poll::Ready(Ok(Err(error))) => {
                    self.inflight.remove(i);
                    self.failure.lock().unwrap().set(&error);
                    self.failed = true;
                    return Err(error);
                }
                Poll::Ready(Err(_)) => {
                    self.inflight.remove(i);
                    self.failed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "XHTTP packet-up worker closed",
                    ));
                }
                Poll::Pending => i += 1,
            }
        }
        Ok(())
    }

    /// 读端用：只看有没有已经失败的 POST，不登记唤醒（读写两端可能在不同任务里）。
    fn peek_failure(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut i = 0;
        while i < self.inflight.len() {
            match self.inflight[i].try_recv() {
                Ok(Ok(_)) => {
                    self.inflight.remove(i);
                }
                Ok(Err(error)) => {
                    self.failed = true;
                    return Err(error);
                }
                Err(oneshot::error::TryRecvError::Empty) => i += 1,
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.failed = true;
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
            }
        }
        Ok(())
    }

    /// 等所有已写入的块都被服务端确认。
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.reap(cx)?;
        if self.inflight.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
impl Drop for PacketUpStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AsyncRead for PacketUpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        {
            // 登记与检查使用同一把锁，失败发生在任一侧都不会漏唤醒。
            let mut failure = self.failure.lock().unwrap();
            failure.check()?;
            failure.reader = Some(cx.waker().clone());
        }
        self.peek_failure()?;
        Pin::new(&mut self.download).poll_read(cx, buf)
    }
}
impl AsyncWrite for PacketUpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.closed || self.pending_shutdown.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP packet-up closed",
            )));
        }
        self.reap(cx)?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // 在途满了就等其中一块被确认（reap 已登记唤醒）。
        if self.inflight.len() >= self.depth {
            return Poll::Pending;
        }
        let chunk = data[..data.len().min(self.chunk_limit)].to_vec();
        let len = chunk.len();
        let (tx, rx) = oneshot::channel();
        match self.commands.try_send(PacketCommand::Data(chunk, tx)) {
            Ok(()) => {
                self.inflight.push_back(rx);
                Poll::Ready(Ok(len))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.failed = true;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "XHTTP packet-up worker closed",
                )))
            }
            // 容量按在途数留足，正常不会满；真满了就让出并重试，不会丢数据。
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    /// 与 TCP 一样，flush 不等对端确认：数据已进入有界的在途队列。
    /// 错误会在之后的写、读或 shutdown 里报告，shutdown 会等所有块被确认。
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        self.reap(cx)?;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        ready!(self.poll_drain(cx))?;
        if self.pending_shutdown.is_none() {
            let commands = self.commands.clone();
            self.pending_shutdown = Some(Box::pin(async move {
                let (tx, rx) = oneshot::channel();
                commands
                    .send(PacketCommand::Shutdown(tx))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP packet-up worker closed")
                    })?;
                rx.await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP packet-up worker closed")
                })?
            }));
        }
        let pending = self
            .pending_shutdown
            .as_mut()
            .expect("packet shutdown future");
        match pending.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.pending_shutdown = None;
                self.closed = true;
                self.failed = result.is_err();
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// XHTTP 的 Flow 适配：stream-one 使用一个请求流，stream-up 将上传 POST
/// 与下载 GET 组合成一个字节流。两个子流仍分别受 h2 流窗口和连接池上限约束。
pub enum XHttpStream {
    Single(GrpcStream),
    Split {
        upload: GrpcStream,
        download: GrpcStream,
    },
    Packet(PacketUpStream),
}
/// stream-up 的上传响应含 SSE 填充，必须持续释放窗口并传播状态错误。
fn drain_upload_response(upload: &mut GrpcStream, cx: &mut Context<'_>) -> io::Result<()> {
    let mut storage = [0u8; 1024];
    for _ in 0..8 {
        let mut buf = ReadBuf::new(&mut storage);
        match Pin::new(&mut *upload).poll_read(cx, &mut buf) {
            Poll::Pending => return Ok(()),
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Ready(Ok(())) if buf.filled().is_empty() => return Ok(()),
            Poll::Ready(Ok(())) => {}
        }
    }
    cx.waker().wake_by_ref();
    Ok(())
}

impl AsyncRead for XHttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Single(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Split { upload, download } => {
                drain_upload_response(upload, cx)?;
                Pin::new(download).poll_read(cx, buf)
            }
            Self::Packet(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for XHttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Single(stream) => Pin::new(stream).poll_write(cx, data),
            Self::Split { upload, .. } => {
                drain_upload_response(upload, cx)?;
                Pin::new(upload).poll_write(cx, data)
            }
            Self::Packet(stream) => Pin::new(stream).poll_write(cx, data),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Single(stream) => Pin::new(stream).poll_flush(cx),
            Self::Split { upload, .. } => {
                drain_upload_response(upload, cx)?;
                Pin::new(upload).poll_flush(cx)
            }
            Self::Packet(stream) => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Single(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Split { upload, .. } => {
                drain_upload_response(upload, cx)?;
                Pin::new(upload).poll_shutdown(cx)
            }
            Self::Packet(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt};
    #[test]
    fn gun_framing_and_rejection() {
        for n in [0, 1, 127, 128, 16384, 65536] {
            let data = vec![42; n];
            let wire = frame(&data);
            assert_eq!(
                u32::from_be_bytes(wire[1..5].try_into().unwrap()) as usize,
                wire.len() - 5
            );
            assert_eq!(payload(&wire[5..]).unwrap().as_ref(), data);
        }
        for proto in [&[11, 0][..], &[10, 128], &[10, 255, 255, 255], &[10, 2, 1]] {
            assert!(payload(proto).is_err());
        }
    }

    fn xspec() -> oryn_config::XHttpSpec {
        oryn_config::XHttpSpec {
            hosts: vec!["upload.test".into()],
            path: "/tunnel".into(),
            method: "POST".into(),
            mode: "packet-up".into(),
            headers: Vec::new(),
            no_grpc_header: false,
            uplink_http_method: "POST".into(),
            uplink_data_placement: "body".into(),
            uplink_data_key: "data".into(),
            uplink_chunk_size: 128,
            session_placement: "path".into(),
            session_key: "x_session".into(),
            seq_placement: "path".into(),
            seq_key: "x_seq".into(),
            sc_max_each_post_bytes: 1024,
            sc_min_posts_interval_ms: 0,
            padding: oryn_config::XHttpPaddingSpec {
                min: 12,
                max: 12,
                obfs_mode: false,
                key: "custom_padding".into(),
                header: "X-Padding".into(),
                placement: "header".into(),
                method: "repeat-x".into(),
            },
            download: None,
            reuse: oryn_config::XHttpReuseSpec::default(),
            session_table: String::new(),
            session_length: 16,
            sc_max_buffered_posts: 4,
        }
    }

    #[test]
    fn xhttp_padding_and_metadata_follow_wire_order() {
        let spec = xspec();
        let req = http::Request::builder()
            .uri("https://upload.test/tunnel?existing=1")
            .body(())
            .unwrap();
        let req = apply_xhttp_padding(req, &spec).unwrap();
        // Default mode always uses x_padding in Referer, regardless of the
        // custom obfs key/header stored in the spec.
        let referer = req.headers().get("referer").unwrap().to_str().unwrap();
        assert!(referer.starts_with("https://upload.test/tunnel?x_padding="));
        assert!(!referer.contains("existing=1"));
        assert_eq!(req.uri().query(), Some("existing=1"));
        let req = apply_xhttp_meta(req, &spec, "0123456789abcdef", Some(7)).unwrap();
        assert_eq!(req.uri().path(), "/tunnel/0123456789abcdef/7");
        assert_eq!(req.uri().query(), Some("existing=1"));
    }

    #[test]
    fn xhttp_rejects_query_payload_instead_of_sending_empty_body() {
        let mut spec = xspec();
        for placement in ["query", "path"] {
            spec.uplink_data_placement = placement.into();
            let req = http::Request::builder().uri("https://example.test/x").body(()).unwrap();
            assert!(apply_uplink_data(req, &spec, b"payload").is_err(), "{placement}");
        }
    }

    #[test]
    fn xhttp_padding_placements_and_uplink_encoding_are_bounded() {
        let mut spec = xspec();
        spec.padding.obfs_mode = true;
        spec.padding.placement = "query".into();
        spec.padding.key = "pad key".into();
        let req = http::Request::builder()
            .uri("https://upload.test/tunnel")
            .body(())
            .unwrap();
        let req = apply_xhttp_padding(req, &spec).unwrap();
        assert!(req
            .uri()
            .query()
            .unwrap()
            .starts_with("pad%20key=XXXXXXXXXXXX"));

        spec.uplink_data_placement = "header".into();
        spec.uplink_data_key = "data".into();
        let req = http::Request::builder()
            .uri("https://upload.test/tunnel")
            .body(())
            .unwrap();
        let (req, body) = apply_uplink_data(req, &spec, b"hello").unwrap();
        assert!(body.is_empty());
        assert_eq!(req.headers().get("data-0").unwrap(), "aGVsbG8");

        spec.uplink_data_placement = "auto".into();
        let req = http::Request::builder()
            .uri("https://upload.test/tunnel")
            .body(())
            .unwrap();
        let (_req, body) = apply_uplink_data(req, &spec, b"hello").unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn xhttp_query_values_replace_and_tokenish_uses_compressed_length() {
        assert_eq!(
            append_query("https://test/t?seq=bad&other=ok&s%65q=old", "seq", "7"),
            "https://test/t?other=ok&seq=7"
        );
        let mut spec = xspec();
        spec.padding.obfs_mode = true;
        spec.padding.method = "tokenish".into();
        spec.padding.min = 257;
        spec.padding.max = 271;
        for _ in 0..64 {
            let value = xhttp_padding(&spec);
            let compressed = value
                .bytes()
                .map(base62_huffman_bits)
                .sum::<usize>()
                .div_ceil(8);
            assert!((257..=271).contains(&compressed));
            assert!(
                value.len() > 271,
                "tokenish is sized by HPACK bytes, not characters"
            );
        }
    }

    #[tokio::test]
    async fn xhttp_stream_up_surfaces_upload_failure() {
        let (client, server) = duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server).await.unwrap();
            let mut downloads = Vec::new();
            while let Some(Ok((request, mut respond))) = conn.accept().await {
                if request.method() == "GET" {
                    downloads.push(
                        respond
                            .send_response(http::Response::new(()), false)
                            .unwrap(),
                    );
                } else {
                    respond
                        .send_response(
                            http::Response::builder().status(503).body(()).unwrap(),
                            true,
                        )
                        .unwrap();
                }
            }
        });
        let mut spec = xspec();
        spec.mode = "stream-up".into();
        let pool = GrpcPool::new();
        let mut stream = pool
            .open_xhttp("test", &spec, &[], move || async move { Ok(client) })
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
            .await
            .unwrap();
        assert!(
            result.is_err(),
            "upload status must fail reads even while GET stays open"
        );
        drop(stream);
        drop(pool);
        task.await.unwrap();
    }

    #[test]
    fn xhttp_session_defaults_match_mihomo_shape() {
        let spec = xspec();
        let id = new_xhttp_session(&spec);
        assert_eq!(id.len(), 32);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        let mut uuid = spec.clone();
        uuid.session_table = "uuid".into();
        let id = new_xhttp_session(&uuid);
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(
            id.as_bytes()[19] == b'8'
                || id.as_bytes()[19] == b'9'
                || id.as_bytes()[19] == b'a'
                || id.as_bytes()[19] == b'b'
        );
    }
    #[tokio::test]
    async fn delayed_response_fragmentation_and_backpressure() {
        let (a, b) = duplex(1024);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::Builder::new()
                .initial_window_size(64)
                .handshake::<_, Bytes>(b)
                .await
                .unwrap();
            let (request, mut response) = conn.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/service/Tun");
            let driver = tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let mut read = request.into_body();
            let mut raw = Vec::new();
            // 先读协议首部，之后才响应，覆盖原来的握手死锁。
            while raw.len() < frame(b"initial").len() {
                let data = read.data().await.unwrap().unwrap();
                read.flow_control().release_capacity(data.len()).unwrap();
                raw.extend(data);
            }
            assert_eq!(raw, frame(b"initial"));
            let mut send = response
                .send_response(
                    http::Response::builder()
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let wire = frame(b"reply");
            for chunk in wire.chunks(2) {
                send.send_data(Bytes::copy_from_slice(chunk), false)
                    .unwrap();
            }
            let mut count = 0;
            while let Some(data) = read.data().await {
                let data = data.unwrap();
                count += data.len();
                read.flow_control().release_capacity(data.len()).unwrap();
            }
            assert!(count > 70000);
            send.send_trailers(http::HeaderMap::from_iter([(
                http::HeaderName::from_static("grpc-status"),
                http::HeaderValue::from_static("0"),
            )]))
            .unwrap();
            // 保持驱动直到客户端收到尾部并关闭连接。
            driver.await.unwrap();
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let pool = GrpcPool::new();
            let mut client = pool
                .open("proxy.test", &spec(), b"initial", || async { Ok(a) })
                .await
                .unwrap();
            let mut reply = [0; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
            client.write_all(&vec![7; 70000]).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(client.read(&mut reply).await.unwrap(), 0);
            drop(client);
            drop(pool);
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    fn spec() -> oryn_config::GrpcSpec {
        oryn_config::GrpcSpec {
            service_name: "service".into(),
        }
    }

    fn fake_packet_stream(
        download: GrpcStream,
        depth: usize,
        worker: impl FnOnce(tokio::sync::mpsc::Receiver<PacketCommand>) -> tokio::task::JoinHandle<()>,
    ) -> PacketUpStream {
        let (commands, rx) = tokio::sync::mpsc::channel(depth + 1);
        PacketUpStream {
            download,
            commands,
            inflight: Default::default(),
            depth,
            pending_shutdown: None,
            closed: false,
            failed: false,
            chunk_limit: 128,
            task: worker(rx),
            failure: Arc::new(StdMutex::new(PacketFailure::default())),
        }
    }

    #[tokio::test]
    async fn packet_upload_keeps_write_order_and_closes_once() {
        let pool = GrpcPool::new();
        let dials = Dials::new(32);
        let download = dials.open(&pool, b"").await.unwrap();
        let received = Arc::new(StdMutex::new(Vec::new()));
        let output = received.clone();
        let mut stream = fake_packet_stream(download, 8, |mut rx| {
            tokio::spawn(async move {
                while let Some(command) = rx.recv().await {
                    match command {
                        PacketCommand::Data(data, ack) => {
                            output.lock().unwrap().extend_from_slice(&data);
                            let _ = ack.send(Ok(data.len()));
                        }
                        PacketCommand::Shutdown(ack) => {
                            let _ = ack.send(Ok(()));
                            break;
                        }
                    }
                }
            })
        });
        assert_eq!(stream.write(b"original").await.unwrap(), 8);
        assert_eq!(stream.write(b"x").await.unwrap(), 1);
        stream.shutdown().await.unwrap();
        stream.shutdown().await.unwrap();
        assert!(stream.write(b"closed").await.is_err());
        assert_eq!(*received.lock().unwrap(), b"originalx");
    }

    /// 在途块数有上限：上限内的写立即被接受，超过后等某一块被确认才继续，
    /// flush 不等确认，shutdown 等所有块确认。
    #[tokio::test]
    async fn packet_upload_inflight_is_bounded_and_flush_does_not_wait() {
        let pool = GrpcPool::new();
        let dials = Dials::new(32);
        let download = dials.open(&pool, b"").await.unwrap();
        let held = Arc::new(StdMutex::new(Vec::new()));
        let hold = held.clone();
        let mut stream = fake_packet_stream(download, 3, |mut rx| {
            tokio::spawn(async move {
                while let Some(command) = rx.recv().await {
                    match command {
                        PacketCommand::Data(data, ack) => hold.lock().unwrap().push((data, ack)),
                        PacketCommand::Shutdown(ack) => {
                            let _ = ack.send(Ok(()));
                            break;
                        }
                    }
                }
            })
        });
        for i in 0..3u8 {
            assert_eq!(stream.write(&[i]).await.unwrap(), 1);
            stream.flush().await.unwrap();
        }
        // 第四块：在途已满，必须等待
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.write(&[3]))
                .await
                .is_err()
        );
        // 确认第一块后可以继续
        let (_, ack) = held.lock().unwrap().remove(0);
        let _ = ack.send(Ok(1));
        assert_eq!(stream.write(&[3]).await.unwrap(), 1);
        // shutdown 在还有未确认块时不会完成
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.shutdown())
                .await
                .is_err()
        );
        let rest: Vec<_> = held.lock().unwrap().drain(..).collect();
        assert_eq!(rest.len(), 3);
        for (data, ack) in rest {
            let _ = ack.send(Ok(data.len()));
        }
        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn packet_upload_drop_cancels_worker_and_posts() {
        let (client_io, server_io) = duplex(64 * 1024);
        let (post_seen, seen) = oneshot::channel();
        let (post_reset, reset) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let mut downloads = Vec::new();
            let mut signals = Some((post_seen, post_reset));
            let mut posts = tokio::task::JoinSet::new();
            while let Some(Ok((request, mut respond))) = conn.accept().await {
                if request.method() == "GET" {
                    downloads.push((request, respond));
                } else {
                    let (seen, reset) = signals.take().unwrap();
                    posts.spawn(async move {
                        let _body = request.into_body();
                        seen.send(()).unwrap();
                        let reason = std::future::poll_fn(|cx| respond.poll_reset(cx)).await;
                        let _ = reset.send(reason);
                    });
                }
            }
        });
        let pool = GrpcPool::new();
        let mut stream = pool
            .open_xhttp("test", &xspec(), b"", move || async move { Ok(client_io) })
            .await.unwrap();
        stream.write_all(b"pending").await.unwrap();
        seen.await.unwrap();
        let XHttpStream::Packet(packet) = &stream else { panic!("packet mode") };
        let worker = packet.task.abort_handle();
        let failure = Arc::downgrade(&packet.failure);
        drop(stream);
        // 保留 pool/连接，RST 必须来自 Flow Drop，而非整个连接退出。
        let reason = tokio::time::timeout(Duration::from_secs(2), reset).await.unwrap().unwrap().unwrap();
        assert_eq!(reason, h2::Reason::CANCEL);
        assert!(worker.is_finished());
        assert!(failure.upgrade().is_none(), "POST task retained failure state");
        server.abort();
    }

    #[tokio::test]
    async fn packet_upload_failure_wakes_pending_reader() {
        struct ReadWake(tokio::sync::Notify);
        impl std::task::Wake for ReadWake {
            fn wake(self: Arc<Self>) {
                self.0.notify_one();
            }
        }
        let (client_io, server_io) = duplex(64 * 1024);
        let (reject, rejected) = oneshot::channel();
        let (post_seen, seen) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let mut downloads = Vec::new();
            let mut rejected = Some(rejected);
            let mut post_seen = Some(post_seen);
            let mut posts = tokio::task::JoinSet::new();
            while let Some(Ok((request, mut respond))) = conn.accept().await {
                if request.method() == "GET" {
                    // 不发送首部或正文，也不关闭 GET。
                    downloads.push((request, respond));
                } else {
                    let rejected = rejected.take().unwrap();
                    let _ = post_seen.take().unwrap().send(());
                    posts.spawn(async move {
                        rejected.await.unwrap();
                        let _body = request.into_body();
                        let _ = respond.send_response(
                            http::Response::builder().status(503).body(()).unwrap(),
                            true,
                        );
                    });
                }
            }
        });
        let pool = GrpcPool::new();
        let mut stream = pool
            .open_xhttp("test", &xspec(), b"", move || async move { Ok(client_io) })
            .await
            .unwrap();
        stream.write_all(b"request").await.unwrap();
        seen.await.unwrap();
        let wake = Arc::new(ReadWake(tokio::sync::Notify::new()));
        let waker = std::task::Waker::from(wake.clone());
        let mut cx = Context::from_waker(&waker);
        let mut byte = [0; 1];
        assert!(Pin::new(&mut stream)
            .poll_read(&mut cx, &mut ReadBuf::new(&mut byte))
            .is_pending());
        reject.send(()).unwrap();
        // 只等 waker，不把 read future 放进 timeout（超时重 poll 会掩盖漏唤醒）。
        let notified = tokio::time::timeout(Duration::from_secs(2), wake.0.notified()).await;
        server.abort();
        assert!(notified.is_ok(), "POST failure did not wake the pending reader");
        for _ in 0..2 {
            assert!(matches!(Pin::new(&mut stream).poll_read(&mut cx, &mut ReadBuf::new(&mut byte)), Poll::Ready(Err(_))));
            assert!(stream.write(b"later").await.is_err());
            assert!(stream.flush().await.is_err());
            assert!(stream.shutdown().await.is_err());
        }
    }

    #[tokio::test]
    async fn packet_upload_failure_fails_later_writes_and_reads() {
        let pool = GrpcPool::new();
        let dials = Dials::new(32);
        let download = dials.open(&pool, b"").await.unwrap();
        let mut stream = fake_packet_stream(download, 4, |mut rx| {
            tokio::spawn(async move {
                if let Some(PacketCommand::Data(_, ack)) = rx.recv().await {
                    let _ = ack.send(Err(io::Error::other("503")));
                }
            })
        });
        assert_eq!(stream.write(b"a").await.unwrap(), 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut byte = [0u8; 1];
        assert!(stream.read(&mut byte).await.is_err());
        assert!(stream.write(b"b").await.is_err());
        assert!(stream.shutdown().await.is_err());
    }

    /// 回归：packet-up 每个往返只发一块 16 KiB 时，20 ms 往返下上传只有约 6 Mbit/s；
    /// 在途 POST 流水线加 64 KiB 块之后吞吐不再被往返时延限制，且服务端按序号重排后数据完整。
    #[tokio::test]
    async fn packet_up_upload_is_pipelined_on_a_delayed_link() {
        const TOTAL: usize = 4 * 1024 * 1024;
        let (client_io, server_io) = delayed_link(Duration::from_millis(10));
        let posts: Arc<StdMutex<std::collections::BTreeMap<u64, Vec<u8>>>> = Default::default();
        let store = posts.clone();
        let server = tokio::spawn(async move {
            let mut conn = h2::server::Builder::new()
                .initial_window_size(1024 * 1024)
                .initial_connection_window_size(8 * 1024 * 1024)
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            let mut downloads = Vec::new();
            while let Some(Ok((request, mut respond))) = conn.accept().await {
                if request.method() == "GET" {
                    downloads.push(
                        respond
                            .send_response(http::Response::new(()), false)
                            .unwrap(),
                    );
                    continue;
                }
                let seq: u64 = request
                    .uri()
                    .path()
                    .rsplit('/')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .expect("sequence in the path");
                let store = store.clone();
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    let mut data = Vec::new();
                    while let Some(Ok(chunk)) = body.data().await {
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                        data.extend_from_slice(&chunk);
                    }
                    store.lock().unwrap().insert(seq, data);
                    let _ = respond.send_response(http::Response::new(()), true);
                });
            }
        });
        let mut spec = xspec();
        spec.sc_max_each_post_bytes = 64 * 1024;
        spec.uplink_chunk_size = 64 * 1024;
        spec.sc_max_buffered_posts = 16;
        let pool = GrpcPool::new();
        let mut stream = pool
            .open_xhttp("test", &spec, b"", move || async move { Ok(client_io) })
            .await
            .unwrap();
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i * 31 % 251) as u8).collect();
        let started = Instant::now();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let elapsed = started.elapsed();
        let received: Vec<u8> = posts.lock().unwrap().values().flatten().copied().collect();
        assert_eq!(received.len(), TOTAL);
        assert!(received == payload, "payload reassembled by x-seq differs");
        eprintln!("4 MiB packet-up over a 20 ms link: {elapsed:?}");
        // 每个往返一块 16 KiB 时约需 5 s；8 路流水线 × 64 KiB 约 0.2 s。
        assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
        drop(stream);
        drop(pool);
        server.abort();
    }

    /// 回显 gRPC 服务端：每个流返回 200 并原样回显 gun 帧。返回的句柄结束即断开连接。
    fn echo_server(
        io: tokio::io::DuplexStream,
        max_streams: u32,
        streams: Arc<AtomicUsize>,
        seen: Arc<StdMutex<Vec<String>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut conn = h2::server::Builder::new()
                .max_concurrent_streams(max_streams)
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            while let Some(Ok((request, mut respond))) = conn.accept().await {
                streams.fetch_add(1, Ordering::AcqRel);
                seen.lock().unwrap().push(format!(
                    "{} {}{}",
                    request.method(),
                    request.uri().authority().map(|a| a.as_str()).unwrap_or(""),
                    request.uri().path()
                ));
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    let mut send = respond
                        .send_response(
                            http::Response::builder()
                                .header("content-type", "application/grpc")
                                .body(())
                                .unwrap(),
                            false,
                        )
                        .unwrap();
                    while let Some(Ok(data)) = body.data().await {
                        body.flow_control().release_capacity(data.len()).unwrap();
                        if send.send_data(data, false).is_err() {
                            return;
                        }
                    }
                    let _ = send.send_trailers(http::HeaderMap::from_iter([(
                        http::HeaderName::from_static("grpc-status"),
                        http::HeaderValue::from_static("0"),
                    )]));
                });
            }
        })
    }

    struct Dials {
        count: AtomicUsize,
        max_streams: u32,
        streams: Arc<AtomicUsize>,
        seen: Arc<StdMutex<Vec<String>>>,
        servers: StdMutex<Vec<tokio::task::JoinHandle<()>>>,
    }
    impl Dials {
        fn new(max_streams: u32) -> Arc<Self> {
            Arc::new(Self {
                count: AtomicUsize::new(0),
                max_streams,
                streams: Arc::new(AtomicUsize::new(0)),
                seen: Arc::new(StdMutex::new(Vec::new())),
                servers: StdMutex::new(Vec::new()),
            })
        }
        async fn open(self: &Arc<Self>, pool: &GrpcPool, tag: &[u8]) -> io::Result<GrpcStream> {
            let me = self.clone();
            pool.open("proxy.test", &spec(), tag, || async move {
                me.count.fetch_add(1, Ordering::AcqRel);
                let (a, b) = duplex(64 * 1024);
                let server = echo_server(b, me.max_streams, me.streams.clone(), me.seen.clone());
                me.servers.lock().unwrap().push(server);
                Ok(a)
            })
            .await
        }
        async fn open_raw(
            self: &Arc<Self>,
            pool: &GrpcPool,
            spec: &oryn_config::H2Spec,
            first: &[u8],
        ) -> io::Result<GrpcStream> {
            let me = self.clone();
            pool.open_h2("proxy.test:443", spec, first, || async move {
                me.count.fetch_add(1, Ordering::AcqRel);
                let (a, b) = duplex(64 * 1024);
                let server = echo_server(b, me.max_streams, me.streams.clone(), me.seen.clone());
                me.servers.lock().unwrap().push(server);
                Ok(a)
            })
            .await
        }
        fn dials(&self) -> usize {
            self.count.load(Ordering::Acquire)
        }
        /// 断开所有已建立的连接（模拟服务端重启）。
        fn kill(&self) {
            for server in self.servers.lock().unwrap().drain(..) {
                server.abort();
            }
        }
    }

    async fn roundtrip(stream: &mut GrpcStream, tag: &[u8]) {
        let mut buf = vec![0; tag.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, tag);
        stream.write_all(b"more").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"more");
    }

    #[tokio::test]
    async fn flows_share_one_connection() {
        let dials = Dials::new(100);
        let pool = GrpcPool::new();
        let mut flows = Vec::new();
        for i in 0..MAX_STREAMS {
            let tag = format!("flow-{i}");
            let mut s = dials.open(&pool, tag.as_bytes()).await.unwrap();
            roundtrip(&mut s, tag.as_bytes()).await;
            flows.push(s);
        }
        assert_eq!(dials.dials(), 1);
        assert_eq!(dials.streams.load(Ordering::Acquire), MAX_STREAMS);
        // 第 33 条超出每连接上限，新建第二条连接
        let mut extra = dials.open(&pool, b"extra").await.unwrap();
        roundtrip(&mut extra, b"extra").await;
        assert_eq!(dials.dials(), 2);
        // 关闭的流归还名额，下一条复用第一条连接
        flows.truncate(MAX_STREAMS - 1);
        tokio::task::yield_now().await;
        let mut again = dials.open(&pool, b"again").await.unwrap();
        roundtrip(&mut again, b"again").await;
        assert_eq!(dials.dials(), 2);
    }

    #[tokio::test]
    async fn concurrent_cold_pool_waits_for_opening_connections() {
        for xhttp in [false, true] {
            let pool = GrpcPool::new();
            let dials = Dials::new(100);
            let dial: XHttpDial = {
                let dials = dials.clone();
                Arc::new(move || {
                    let dials = dials.clone();
                    Box::pin(async move {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        dials.count.fetch_add(1, Ordering::AcqRel);
                        let (a, b) = duplex(64 * 1024);
                        let server = echo_server(b, 100, dials.streams.clone(), dials.seen.clone());
                        dials.servers.lock().unwrap().push(server);
                        Ok(Box::new(a) as Box<dyn XHttpIo>)
                    })
                })
            };
            let mut jobs = tokio::task::JoinSet::new();
            for _ in 0..40 {
                let pool = pool.clone();
                let dial = dial.clone();
                jobs.spawn(async move {
                    if xhttp {
                        let flow = XHttpClient::new(pool, dial).acquire_flow().await.unwrap();
                        // 持有所有返回的 lease，避免容量因测试提前释放而失真。
                        (None, Some(flow))
                    } else {
                        let stream = pool
                            .open("proxy.test", &spec(), b"", || dial())
                            .await
                            .unwrap();
                        (Some(stream), None)
                    }
                });
            }
            let mut flows = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), async {
                while let Some(result) = jobs.join_next().await {
                    flows.push(result.unwrap());
                }
            })
            .await
            .unwrap();
            assert_eq!(flows.len(), 40);
            assert!(dials.dials() <= MAX_CONNECTIONS);
            assert_eq!(pool.opening.load(Ordering::Acquire), 0);
            dials.kill();
        }
    }

    #[tokio::test]
    async fn cancelled_dial_returns_reserved_capacity() {
        let pool = GrpcPool::new();
        for _ in 0..MAX_CONNECTIONS {
            let started = Arc::new(tokio::sync::Notify::new());
            let task = {
                let pool = pool.clone();
                let started = started.clone();
                tokio::spawn(async move {
                    pool.open("proxy.test", &spec(), b"", || async move {
                        started.notify_one();
                        std::future::pending::<io::Result<tokio::io::DuplexStream>>().await
                    })
                    .await
                })
            };
            tokio::time::timeout(Duration::from_secs(1), started.notified())
                .await
                .unwrap();
            task.abort();
            assert!(matches!(task.await, Err(error) if error.is_cancelled()));
            assert_eq!(pool.opening.load(Ordering::Acquire), 0);
        }
        let dials = Dials::new(100);
        let mut stream = dials.open(&pool, b"recovered").await.unwrap();
        roundtrip(&mut stream, b"recovered").await;
        dials.kill();
    }

    #[tokio::test]
    async fn raw_h2_carries_bytes_without_framing_and_shares_connections() {
        let dials = Dials::new(100);
        let pool = GrpcPool::new();
        let spec = oryn_config::H2Spec {
            hosts: vec!["cdn.test".into(), "other.test".into()],
            path: "/tun".into(),
        };
        let mut a = dials.open_raw(&pool, &spec, b"first").await.unwrap();

        let mut b = dials
            .open_raw(
                &pool,
                &oryn_config::H2Spec {
                    hosts: vec![],
                    path: "/".into(),
                },
                b"second",
            )
            .await
            .unwrap();
        for (stream, first) in [(&mut a, b"first".as_slice()), (&mut b, b"second")] {
            let mut got = vec![0; first.len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, first);
            // 超过一个 16 KiB 写块：原样回来，没有 gun 首部
            let big: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
            stream.write_all(&big).await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = vec![0; big.len()];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, big);
        }
        assert_eq!(dials.dials(), 1);
        let seen = dials.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                "PUT cdn.test/tun".to_string(),
                "PUT proxy.test:443/".to_string()
            ]
        );
        // 对端结束请求体后读到 EOF
        a.shutdown().await.unwrap();
        let mut rest = Vec::new();
        a.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn server_stream_limit_and_pool_capacity() {
        let dials = Dials::new(2);
        let pool = GrpcPool::new();
        let mut flows = Vec::new();
        for i in 0..2 * MAX_CONNECTIONS {
            let tag = format!("flow-{i}");
            let mut s =
                tokio::time::timeout(Duration::from_secs(5), dials.open(&pool, tag.as_bytes()))
                    .await
                    .unwrap()
                    .unwrap();
            roundtrip(&mut s, tag.as_bytes()).await;
            flows.push(s);
        }
        // 服务端每连接只允许 2 个流：8 条 Flow 用满 4 条连接
        assert_eq!(dials.dials(), MAX_CONNECTIONS);
        let err = dials.open(&pool, b"full").await.err().unwrap();
        assert!(err.to_string().contains("capacity"));
        assert_eq!(dials.dials(), MAX_CONNECTIONS);
    }

    #[tokio::test]
    async fn broken_connection_fails_its_flows_and_redials() {
        let dials = Dials::new(100);
        let pool = GrpcPool::new();
        let mut old = dials.open(&pool, b"old").await.unwrap();
        roundtrip(&mut old, b"old").await;
        dials.kill();
        let mut buf = [0; 1];
        let got = tokio::time::timeout(Duration::from_secs(5), old.read(&mut buf))
            .await
            .unwrap();
        assert!(got.is_err());
        let mut new = tokio::time::timeout(Duration::from_secs(5), dials.open(&pool, b"new"))
            .await
            .unwrap()
            .unwrap();
        roundtrip(&mut new, b"new").await;
        assert_eq!(dials.dials(), 2);
        assert_eq!(pool.connections().await, 1);
    }

    #[tokio::test]
    async fn idle_connections_are_closed() {
        let dials = Dials::new(100);
        let pool = GrpcPool::new();
        let mut s = dials.open(&pool, b"a").await.unwrap();
        roundtrip(&mut s, b"a").await;
        // 有流时不回收
        tokio::time::sleep(IDLE_TIMEOUT * 2).await;
        assert_eq!(pool.connections().await, 1);
        drop(s);
        tokio::time::sleep(IDLE_TIMEOUT + IDLE_CHECK * 3).await;
        assert_eq!(pool.connections().await, 0);
        let mut s = dials.open(&pool, b"b").await.unwrap();
        roundtrip(&mut s, b"b").await;
        assert_eq!(dials.dials(), 2);
    }

    #[test]
    fn stream_window_shrinks_with_open_streams_inside_the_budget() {
        assert_eq!(stream_window(0), MAX_STREAM_WINDOW);
        assert_eq!(stream_window(1), MAX_STREAM_WINDOW);
        assert_eq!(stream_window(2), 2 * 1024 * 1024);
        assert_eq!(stream_window(3), 1024 * 1024);
        assert_eq!(stream_window(8), 512 * 1024);
        assert_eq!(stream_window(32), MIN_STREAM_WINDOW);
        assert_eq!(stream_window(1000), MIN_STREAM_WINDOW);
        for n in 1..=MAX_STREAMS {
            assert!(stream_window(n) as usize * n <= WINDOW_BUDGET as usize);
            assert!(stream_window(n).is_power_of_two());
        }
    }

    /// 在两端之间加单向时延的链路：读到的数据到达时刻 + delay 之后才写给对端，保持顺序且互不叠加。
    fn delayed_link(delay: Duration) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        use tokio::io::AsyncReadExt;
        let (client, client_mid) = duplex(256 * 1024);
        let (server_mid, server) = duplex(256 * 1024);
        fn pump(
            mut from: tokio::io::ReadHalf<tokio::io::DuplexStream>,
            mut to: tokio::io::WriteHalf<tokio::io::DuplexStream>,
            delay: Duration,
        ) {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<(tokio::time::Instant, Vec<u8>)>(4096);
            tokio::spawn(async move {
                let mut buf = vec![0; 16 * 1024];
                loop {
                    match from.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx
                                .send((tokio::time::Instant::now(), buf[..n].to_vec()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            });
            tokio::spawn(async move {
                while let Some((at, data)) = rx.recv().await {
                    tokio::time::sleep_until(at + delay).await;
                    if to.write_all(&data).await.is_err() {
                        break;
                    }
                }
                let _ = to.shutdown().await;
            });
        }
        let (cr, cw) = tokio::io::split(client_mid);
        let (sr, sw) = tokio::io::split(server_mid);
        pump(cr, sw, delay);
        pump(sr, cw, delay);
        (client, server)
    }

    /// 回归：流窗口固定 128 KiB 时，单流下载在 20 ms 往返下只有约 26 Mbit/s；
    /// 窗口随流数放大后，一条流应当能跑满链路。
    #[tokio::test]
    async fn single_stream_download_is_not_window_limited_on_a_delayed_link() {
        const TOTAL: usize = 16 * 1024 * 1024;
        let (client_io, server_io) = delayed_link(Duration::from_millis(10));
        let server = tokio::spawn(async move {
            let mut conn = h2::server::Builder::new()
                .initial_window_size(4 * 1024 * 1024)
                .initial_connection_window_size(8 * 1024 * 1024)
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            let (request, mut response) = conn.accept().await.unwrap().unwrap();
            let driver = tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let mut read = request.into_body();
            let data = read.data().await.unwrap().unwrap();
            read.flow_control().release_capacity(data.len()).unwrap();
            let mut send = response
                .send_response(
                    http::Response::builder()
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let mut sent = 0;
            while sent < TOTAL {
                let chunk = frame(&vec![9; 16 * 1024 - 8]);
                sent += chunk.len();
                let mut chunk = chunk;
                while !chunk.is_empty() {
                    send.reserve_capacity(chunk.len());
                    let n = std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .unwrap()
                        .unwrap();
                    send.send_data(chunk.split_to(n.min(chunk.len())), false)
                        .unwrap();
                }
            }
            send.send_data(Bytes::new(), true).unwrap();
            let _ = driver.await;
        });
        let started = Instant::now();
        let pool = GrpcPool::new();
        let mut client = pool
            .open("proxy.test", &spec(), b"go", || async { Ok(client_io) })
            .await
            .unwrap();
        let mut got = 0;
        let mut buf = vec![0; 64 * 1024];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(20), client.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            if n == 0 {
                break;
            }
            got += n;
        }
        let elapsed = started.elapsed();
        assert!(got >= TOTAL - 20 * 1024, "{got}");
        // 20 ms 往返下，128 KiB 窗口约需 3.3 s；2 MiB 窗口只受链路与调度限制。
        eprintln!("16 MiB over a 20 ms link: {elapsed:?}");
        assert!(elapsed < Duration::from_millis(2000), "{elapsed:?}");
        drop(client);
        drop(pool);
        let _ = server.await;
    }

    /// gRPC 读路径的开销基准（默认忽略）：单线程运行时里经内存 h2 连接收 256 MiB 的 gun 帧，
    /// 服务端与客户端在同一线程，耗时近似总 CPU。用于比较读路径改动前后，不是吞吐验收。
    /// `cargo test --release -p oryn-transport grpc_read_path_bench -- --ignored --nocapture`
    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn grpc_read_path_bench() {
        const TOTAL: usize = 256 * 1024 * 1024;
        let (client_io, server_io) = duplex(1024 * 1024);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::Builder::new()
                .initial_window_size(8 * 1024 * 1024)
                .initial_connection_window_size(16 * 1024 * 1024)
                .max_frame_size(16 * 1024)
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            let (request, mut response) = conn.accept().await.unwrap().unwrap();
            let driver = tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let mut read = request.into_body();
            let data = read.data().await.unwrap().unwrap();
            read.flow_control().release_capacity(data.len()).unwrap();
            let mut send = response
                .send_response(
                    http::Response::builder()
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            // Xray 每条 gun 消息最多约 8 KiB 数据；这里用 8 KiB，消息常跨 DATA 帧边界
            let message = frame(&vec![7u8; 8 * 1024]);
            let mut sent = 0;
            while sent < TOTAL {
                let mut chunk = message.clone();
                sent += chunk.len();
                while !chunk.is_empty() {
                    send.reserve_capacity(chunk.len());
                    let n = std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .unwrap()
                        .unwrap();
                    send.send_data(chunk.split_to(n.min(chunk.len())), false)
                        .unwrap();
                }
            }
            send.send_data(Bytes::new(), true).unwrap();
            let _ = driver.await;
        });
        let pool = GrpcPool::new();
        let mut client = pool
            .open("proxy.test", &spec(), b"go", || async { Ok(client_io) })
            .await
            .unwrap();
        let started = Instant::now();
        let mut got = 0usize;
        let mut buf = vec![0; 64 * 1024];
        while got < TOTAL * 8 / 10 {
            let n = client.read(&mut buf).await.unwrap();
            assert!(n > 0);
            got += n;
        }
        let elapsed = started.elapsed();
        eprintln!(
            "gRPC read path: {} MiB in {:?} = {:.0} MiB/s (server and client on one thread)",
            got >> 20,
            elapsed,
            got as f64 / 1048576.0 / elapsed.as_secs_f64()
        );
        drop(client);
        drop(pool);
        server.abort();
    }
}
