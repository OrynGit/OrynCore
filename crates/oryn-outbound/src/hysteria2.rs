//! Hysteria2 出站。线格式按公开协议独立实现。

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{
    inbox::{self, Inbox},
    reassembly::Reassembly,
    slots::{Counted, HeldStream, Slots},
};
use async_trait::async_trait;
use bytes::Bytes;
use oryn_config::{Hysteria2Spec, TargetAddr};
use oryn_quic::{Congestion, Hop, QuicClient, QuicParams, MAX_BIDI};
use tokio::task::JoinHandle;

use crate::{resolve_target, BoxStream, Outbound, PacketConn, Resolver, SessionControl};

const MAX_SESSIONS: usize = 32;
const REASSEMBLY_BUDGET: usize = 128 * 1024;
const MAX_FRAGMENTS: usize = 16;
/// 协议规定的 UDP 负载上限：服务端会截断更大的包，所以客户端直接拒绝。
const MAX_UDP_PAYLOAD: usize = 4096;
const FRAG_WAIT: Duration = Duration::from_secs(3);
/// 每个会话同时等待重组的包数。
const PENDING_PER_SESSION: usize = 4;

pub struct Hysteria2Outbound {
    name: String,
    spec: Hysteria2Spec,
    resolver: Arc<dyn Resolver>,
    quic: Arc<QuicClient>,
    brutal: Option<Arc<AtomicU64>>,
    auth: Mutex<Option<Arc<AuthCache>>>,
    /// 认证单飞锁，见 `authenticate`。
    auth_flight: tokio::sync::Mutex<()>,
    #[cfg(test)]
    auth_driver: Mutex<Option<tokio::task::AbortHandle>>,
    streams: Slots,
    udp: Mutex<Option<Arc<UdpHub>>>,
}

#[derive(Debug)]
struct AuthCache {
    id: usize,
    udp: bool,
    task: JoinHandle<()>,
    /// h3 的 `SendRequest` 句柄。最后一个句柄释放时 h3 会以 H3_NO_ERROR 关闭整条 QUIC 连接，
    /// 而认证之后的 TCP / UDP 都复用这条连接，所以句柄必须与连接同寿命。
    _send: Mutex<Box<dyn std::any::Any + Send>>,
}

impl Drop for AuthCache {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// 仅单飞拥有者持有：所有认证 await（包括 h3 初始化）失败/取消均回滚。
struct AuthAttempt {
    conn: quinn::Connection,
    driver: Option<tokio::task::AbortHandle>,
    published: bool,
}

impl Drop for AuthAttempt {
    fn drop(&mut self) {
        if !self.published {
            self.conn.close(0u32.into(), b"auth interrupted");
            if let Some(driver) = &self.driver {
                driver.abort();
            }
        }
    }
}

type SessionInbox = Arc<Inbox<(Vec<u8>, String)>>;

struct UdpHub {
    conn: quinn::Connection,
    sessions: Mutex<HashMap<u32, SessionInbox>>,
    reassembly: Mutex<Reassembly<u32, String>>,
}

impl Hysteria2Outbound {
    pub fn new(
        name: String,
        spec: Hysteria2Spec,
        resolver: Arc<dyn Resolver>,
        dialer: Arc<dyn crate::Dialer>,
        datagrams: Arc<dyn oryn_udp::DatagramFactory>,
    ) -> Arc<Self> {
        let rendezvous = spec.realm.clone().map(|realm| {
            Arc::new(crate::realm::Realm::new(
                realm,
                resolver.clone(),
                dialer,
                datagrams.clone(),
            )) as Arc<dyn oryn_quic::Rendezvous>
        });
        let brutal = spec.up_bps.map(|rate| Arc::new(AtomicU64::new(rate)));
        let hop = spec.ports.as_ref().map(|ports| Hop {
            ranges: ports.ranges.clone(),
            count: ports.count,
            min: Duration::from_secs(spec.hop_min_secs),
            max: Duration::from_secs(spec.hop_max_secs),
        });
        let alpn = spec
            .tls
            .alpn
            .iter()
            .map(|item| item.as_bytes().to_vec())
            .collect();
        let quic = QuicClient::new(QuicParams {
            datagrams,
            alpn,
            skip_verify: spec.tls.skip_cert_verify,
            fingerprint: spec.tls.fingerprint,
            disable_sni: false,
            congestion: Congestion::Bbr,
            brutal_rate: brutal.clone(),
            obfs: spec.obfs_password.as_ref().map(|pw| match spec.gecko {
                Some((min, max)) => oryn_quic::Obfs::Gecko {
                    key: pw.as_bytes().to_vec(),
                    min: min as usize,
                    max: max as usize,
                },
                None => oryn_quic::Obfs::Salamander(pw.as_bytes().to_vec()),
            }),
            hop,
            rendezvous,
            zero_rtt: false,
            // 与官方客户端一致：服务端空闲超时（默认 30 s）前保活，长连接上的流不会因空闲被拆
            keep_alive: Some(oryn_quic::KEEP_ALIVE),
        });
        Arc::new(Self {
            name,
            spec,
            resolver,
            quic,
            brutal,
            auth: Mutex::new(None),
            auth_flight: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            auth_driver: Mutex::new(None),
            streams: Slots::default(),
            udp: Mutex::new(None),
        })
    }

    async fn peer(&self) -> io::Result<(IpAddr, u16, String)> {
        if self.spec.realm.is_some() {
            // 实际对端由打洞决定；这里的地址只用来判断是否复用现有连接
            let name = self
                .spec
                .tls
                .sni
                .clone()
                .unwrap_or_else(|| match &self.spec.server {
                    TargetAddr::Domain(host, _) => host.clone(),
                    TargetAddr::Ip(ip) => ip.ip().to_string(),
                });
            return Ok((IpAddr::from([0, 0, 0, 0]), 0, name));
        }
        let addrs = resolve_target(self.resolver.as_ref(), &self.spec.server).await?;
        let addr = *addrs
            .first()
            .ok_or_else(|| io::Error::other("cannot resolve hysteria2 server"))?;
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

    async fn ready(&self) -> io::Result<(quinn::Connection, bool, Arc<AuthCache>)> {
        // 认证改变 BBR / Brutal 模式时重建一次；稳定响应不重复关闭。
        // 服务端连续改变模式时仍最多两次尝试，避免无限重连。
        for _ in 0..2 {
            let (ip, port, name) = self.peer().await?;
            let conn = self.quic.connection(ip, &name, port).await?;
            let (udp, auth) = self.authenticate(&conn).await?;
            if conn.close_reason().is_none() {
                return Ok((conn, udp, auth));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "hysteria2 connection closed after authentication",
        ))
    }

    fn cached_auth(&self, id: usize) -> Option<(bool, Arc<AuthCache>)> {
        self.auth
            .lock()
            .unwrap()
            .as_ref()
            .filter(|cache| cache.id == id)
            .map(|cache| (cache.udp, cache.clone()))
    }

    async fn authenticate(&self, conn: &quinn::Connection) -> io::Result<(bool, Arc<AuthCache>)> {
        let id = conn.stable_id();
        if let Some(cached) = self.cached_auth(id) {
            return Ok(cached);
        }
        // 单飞：同一条连接上只能有一个 h3 客户端（RFC 9114 每端只有一条控制流），
        // 并发首次使用的 Flow 在这里排队，等先到者认证完直接用缓存
        let _single = self.auth_flight.lock().await;
        if let Some(cached) = self.cached_auth(id) {
            return Ok(cached);
        }
        if conn.close_reason().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "hysteria2 connection closed before authentication",
            ));
        }
        let mut attempt = AuthAttempt {
            conn: conn.clone(),
            driver: None,
            published: false,
        };
        let down = self.spec.down_bps.unwrap_or(0);
        let padding = padding();
        let request = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("hysteria-auth", &self.spec.password)
            .header("hysteria-cc-rx", down.to_string())
            .header("hysteria-padding", padding)
            .body(())
            .map_err(io::Error::other)?;
        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(io::Error::other)?;
        let task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        attempt.driver = Some(task.abort_handle());
        #[cfg(test)]
        self.auth_driver
            .lock()
            .unwrap()
            .replace(task.abort_handle());
        let mut stream = send.send_request(request).await.map_err(io::Error::other)?;
        stream.finish().await.map_err(io::Error::other)?;
        let response = stream.recv_response().await.map_err(io::Error::other)?;
        if response.status().as_u16() != 233 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "hysteria2 authentication failed",
            ));
        }
        let udp = auth_udp(response.headers());
        // 缺失/非法数值与官方一样按 0（unlimited）处理，不能沿用上次连接的低速率。
        self.apply_server_rate(
            response
                .headers()
                .get("hysteria-cc-rx")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        );
        let keep = Arc::new(AuthCache {
            id,
            udp,
            task,
            _send: Mutex::new(Box::new(send)),
        });
        *self.auth.lock().unwrap() = Some(keep.clone());
        attempt.published = true;
        self.udp.lock().unwrap().take();
        Ok((udp, keep))
    }

    fn apply_server_rate(&self, value: &str) {
        let Some(rate) = &self.brutal else {
            return;
        };
        if value == "auto" {
            let _ = self.quic.disable_brutal();
            return;
        }
        let configured = self
            .spec
            .up_bps
            .expect("Brutal requires configured upload rate");
        let server = value.parse::<u64>().unwrap_or(0);
        let negotiated = if server == 0 {
            configured
        } else {
            configured.min(server)
        };
        rate.store(negotiated, Ordering::Relaxed);
        let _ = self.quic.enable_brutal();
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn tag(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "hysteria2"
    }
    fn session_control(&self) -> Option<Arc<dyn SessionControl>> {
        Some(Arc::new(crate::QuicControl(self.quic.clone())))
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        // 名额随流一起释放；失败时 slot 在这里被丢弃，同样归还
        let slot = self
            .streams
            .acquire(MAX_BIDI)
            .ok_or_else(|| io::Error::other("hysteria2 stream limit reached"))?;
        let (conn, _, auth) = self.ready().await?;
        Ok(HeldStream::boxed(
            Counted::boxed(open_tcp(&conn, target).await?, slot),
            (self.quic.clone(), auth),
        ))
    }
    async fn bind_udp(&self, _first: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.spec.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hysteria2 udp is disabled",
            ));
        }
        let (conn, udp, auth) = self.ready().await?;
        if !udp {
            return Err(io::Error::other("hysteria2 server disabled udp"));
        }
        let hub = self.hub(conn).await?;
        hub.open_session((self.quic.clone(), auth))
    }
}

async fn open_tcp(conn: &quinn::Connection, target: &TargetAddr) -> io::Result<BoxStream> {
    let (mut send, recv) = conn.open_bi().await.map_err(io::Error::other)?;
    let mut request = Vec::new();
    put_varint(&mut request, 0x401);
    let addr = host_port(target);
    put_varint(&mut request, addr.len() as u64);
    request.extend_from_slice(addr.as_bytes());
    let pad = padding();
    put_varint(&mut request, pad.len() as u64);
    request.extend_from_slice(pad.as_bytes());
    send.write_all(&request).await.map_err(io::Error::other)?;
    // 不在这里等 TCP 响应：官方服务端拨号成功后马上回，但 mihomo / sing-quic 的服务端把它和第一份回程数据
    // 一起发，目标又是「客户端先说话」的协议（HTTP、TLS）时，在这里等就是死锁。
    // 与 sing-quic 的客户端一样，写入立即放行，响应头在第一次读时读取并校验。
    Ok(Box::new(tokio::io::join(
        ResponseHeaderReader {
            recv,
            header: Vec::new(),
            state: HeaderState::Reading,
        },
        send,
    )))
}

/// TCP 响应头：status(1) + 消息（变长整数长度）+ 填充（变长整数长度）。
#[derive(PartialEq)]
enum HeaderState {
    Reading,
    Done,
    Rejected(String),
}
struct ResponseHeaderReader {
    recv: quinn::RecvStream,
    header: Vec<u8>,
    state: HeaderState,
}
/// 已读入的字节是否构成完整响应头：`Ok(None)` 还不完整，`Ok(Some((status, 消息)))` 完整。
fn parse_response_header(buf: &[u8]) -> io::Result<Option<(u8, Vec<u8>)>> {
    let Some((&status, rest)) = buf.split_first() else {
        return Ok(None);
    };
    let Some((message_len, rest)) = take_varint(rest) else {
        return Ok(None);
    };
    if message_len > 4096 {
        return Err(io::Error::other("hysteria2 header too large"));
    }
    if (rest.len() as u64) < message_len {
        return Ok(None);
    }
    let (message, rest) = rest.split_at(message_len as usize);
    let Some((padding_len, rest)) = take_varint(rest) else {
        return Ok(None);
    };
    if padding_len > 4096 {
        return Err(io::Error::other("hysteria2 header too large"));
    }
    if (rest.len() as u64) < padding_len {
        return Ok(None);
    }
    Ok(Some((status, message.to_vec())))
}
impl tokio::io::AsyncRead for ResponseHeaderReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::{ready, Poll};
        while self.state == HeaderState::Reading {
            // 逐字节读：头部很短，且绝不能多读到数据
            let mut byte = [0u8; 1];
            let mut one = tokio::io::ReadBuf::new(&mut byte);
            ready!(std::pin::Pin::new(&mut self.recv).poll_read(cx, &mut one))?;
            if one.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "hysteria2 tcp response truncated",
                )));
            }
            self.header.push(byte[0]);
            if let Some((status, message)) = parse_response_header(&self.header)? {
                self.state = if status == 0 {
                    HeaderState::Done
                } else {
                    HeaderState::Rejected(format!(
                        "hysteria2 tcp rejected: {}",
                        String::from_utf8_lossy(&message)
                    ))
                };
            }
        }
        if let HeaderState::Rejected(text) = &self.state {
            return Poll::Ready(Err(io::Error::other(text.clone())));
        }
        std::pin::Pin::new(&mut self.recv).poll_read(cx, out)
    }
}

fn host_port(target: &TargetAddr) -> String {
    match target {
        TargetAddr::Ip(addr) if addr.is_ipv6() => format!("[{}]:{}", addr.ip(), addr.port()),
        TargetAddr::Ip(addr) => format!("{}:{}", addr.ip(), addr.port()),
        TargetAddr::Domain(host, port) => format!("{host}:{port}"),
    }
}

fn padding() -> String {
    let n = 16
        + (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as usize)
            .unwrap_or(0)
            % 49);
    "a".repeat(n)
}

fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        out.extend_from_slice(&((0x4000 | value) as u16).to_be_bytes());
    } else if value < 1 << 30 {
        out.extend_from_slice(&((0x8000_0000 | value) as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&(0xC000_0000_0000_0000 | value).to_be_bytes());
    }
}

impl Hysteria2Outbound {
    async fn hub(&self, conn: quinn::Connection) -> io::Result<Arc<UdpHub>> {
        let id = conn.stable_id();
        Ok(crate::shared_hub(
            &self.udp,
            |hub| hub.conn.stable_id() == id,
            || {
                let hub = Arc::new(UdpHub {
                    conn: conn.clone(),
                    sessions: Mutex::new(HashMap::new()),
                    reassembly: Mutex::new(Reassembly::new(
                        REASSEMBLY_BUDGET,
                        PENDING_PER_SESSION,
                        MAX_FRAGMENTS as u8,
                        FRAG_WAIT,
                    )),
                });
                let reader = hub.clone();
                tokio::spawn(async move { reader.run().await });
                hub
            },
        ))
    }
}

impl UdpHub {
    async fn run(self: Arc<Self>) {
        loop {
            let datagram = match self.conn.read_datagram().await {
                Ok(bytes) => bytes,
                Err(_) => break,
            };
            self.ingest(&datagram);
        }
        // QUIC 连接已断：让所有会话立刻结束，而不是等上层空闲超时
        for inbox in self.sessions.lock().unwrap().values() {
            inbox.close();
        }
    }

    fn ingest(&self, datagram: &[u8]) {
        let Some((session, packet, frag, total, addr, payload)) = parse_udp(datagram) else {
            return;
        };
        // 未知或已移除关联不能占共享重组预算；持会话锁到入表完成，防止 Drop 穿过检查。
        let sessions = self.sessions.lock().unwrap();
        let Some(tx) = sessions.get(&session).cloned() else {
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
        drop(sessions);
        if let Some((body, addr)) = done {
            let bytes = body.len();
            let _ = tx.try_send_sized((body, addr), bytes);
        }
    }

    fn open_session(
        self: &Arc<Self>,
        keep: (Arc<QuicClient>, Arc<AuthCache>),
    ) -> io::Result<Box<dyn PacketConn>> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= MAX_SESSIONS {
            return Err(io::Error::other("hysteria2 udp session limit reached"));
        }
        let id = next_id(&sessions);
        let inbox = Arc::new(Inbox::with_bytes(
            inbox::SESSION_PACKETS,
            inbox::SESSION_BYTES,
        ));
        sessions.insert(id, inbox.clone());
        drop(sessions);
        Ok(Box::new(HyPacket {
            id,
            packet: AtomicU16::new(1),
            conn: self.conn.clone(),
            hub: self.clone(),
            rx: inbox,
            _keep: keep,
        }))
    }
}

fn next_id(sessions: &HashMap<u32, SessionInbox>) -> u32 {
    let mut id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1);
    while sessions.contains_key(&id) || id == 0 {
        id = id.wrapping_add(1);
    }
    id
}

struct HyPacket {
    id: u32,
    packet: AtomicU16,
    conn: quinn::Connection,
    hub: Arc<UdpHub>,
    rx: SessionInbox,
    _keep: (Arc<QuicClient>, Arc<AuthCache>),
}

#[async_trait]
impl PacketConn for HyPacket {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        if buf.len() > MAX_UDP_PAYLOAD {
            return Err(io::Error::other("hysteria2 udp packet exceeds 4096 bytes"));
        }
        let addr = host_port(target);
        let max = self.conn.max_datagram_size().unwrap_or(1200);
        let header = 8 + varint_len(addr.len() as u64) + addr.len();
        let room = max.saturating_sub(header).max(1);
        let pieces = buf.chunks(room).collect::<Vec<_>>();
        let pieces = if pieces.is_empty() { vec![buf] } else { pieces };
        if pieces.len() > MAX_FRAGMENTS {
            return Err(io::Error::other("hysteria2 udp packet is too large"));
        }
        let total = pieces.len() as u8;
        // 未分片的包 ID 为 0；分片包每次换一个非 0 的 ID，避免丢片后与下一个包的分片拼在一起
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
            let mut frame = Vec::new();
            frame.extend_from_slice(&self.id.to_be_bytes());
            frame.extend_from_slice(&packet.to_be_bytes());
            frame.push(index as u8);
            frame.push(total);
            put_varint(&mut frame, addr.len() as u64);
            frame.extend_from_slice(addr.as_bytes());
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
                "hysteria2 udp closed",
            ));
        };
        let n = crate::copy_datagram(&payload, buf, "Hysteria2");
        Ok((
            n,
            parse_host_port(&addr).unwrap_or(TargetAddr::Domain(addr, 0)),
        ))
    }
}

impl Drop for HyPacket {
    fn drop(&mut self) {
        self.hub.sessions.lock().unwrap().remove(&self.id);
    }
}

fn parse_udp(data: &[u8]) -> Option<(u32, u16, u8, u8, String, Vec<u8>)> {
    if data.len() < 8 {
        return None;
    }
    let session = u32::from_be_bytes(data[0..4].try_into().ok()?);
    let packet = u16::from_be_bytes(data[4..6].try_into().ok()?);
    let frag = data[6];
    let total = data[7];
    let (addr_len, rest) = take_varint(&data[8..])?;
    let addr_len = usize::try_from(addr_len).ok()?;
    if rest.len() < addr_len {
        return None;
    }
    let addr = String::from_utf8(rest[..addr_len].to_vec()).ok()?;
    let payload = rest[addr_len..].to_vec();
    Some((session, packet, frag, total, addr, payload))
}

fn take_varint(data: &[u8]) -> Option<(u64, &[u8])> {
    let first = *data.first()?;
    let extra = match first >> 6 {
        0 => 0,
        1 => 1,
        2 => 3,
        _ => 7,
    };
    if data.len() < 1 + extra {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &data[1..1 + extra] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, &data[1 + extra..]))
}

fn varint_len(value: u64) -> usize {
    if value < 64 {
        1
    } else if value < 16_384 {
        2
    } else if value < 1 << 30 {
        4
    } else {
        8
    }
}

fn auth_udp(headers: &http::HeaderMap) -> bool {
    // Go strconv.ParseBool 只接受这些 true 表示；缺失、非法或任何 false 表示均禁用。
    matches!(
        headers.get("hysteria-udp").and_then(|v| v.to_str().ok()),
        Some("1" | "t" | "T" | "true" | "TRUE" | "True")
    )
}

fn parse_host_port(text: &str) -> Option<TargetAddr> {
    if let Some(rest) = text.strip_prefix('[') {
        let (ip, port) = rest.rsplit_once("]:")?;
        return Some(TargetAddr::from_host(ip, port.parse().ok()?));
    }
    let (host, port) = text.rsplit_once(':')?;
    Some(TargetAddr::from_host(host, port.parse().ok()?))
}

#[cfg(test)]
#[path = "hysteria2_audit_tests.rs"]
mod audit_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_response_header_is_parsed_incrementally_and_exactly() {
        let mut wire = vec![0u8]; // status ok
        put_varint(&mut wire, 2);
        wire.extend_from_slice(b"OK");
        put_varint(&mut wire, 70); // 两字节的变长整数
        wire.extend_from_slice(&[b'p'; 70]);
        // 逐字节喂入：只有最后一个字节到齐时才算完整，不会提前把数据当成头部
        for end in 0..wire.len() {
            assert!(
                parse_response_header(&wire[..end]).unwrap().is_none(),
                "{end}"
            );
        }
        let (status, message) = parse_response_header(&wire).unwrap().unwrap();
        assert_eq!((status, message.as_slice()), (0, &b"OK"[..]));
        // 拒绝：状态非 0，消息带回
        let mut rejected = vec![1u8];
        put_varint(&mut rejected, 4);
        rejected.extend_from_slice(b"nope");
        put_varint(&mut rejected, 0);
        let (status, message) = parse_response_header(&rejected).unwrap().unwrap();
        assert_eq!((status, message.as_slice()), (1, &b"nope"[..]));
        // 头部长度超限
        let mut huge = vec![0u8];
        put_varint(&mut huge, 5000);
        assert!(parse_response_header(&huge).is_err());
    }

    #[test]
    fn quic_varint_round_trips_all_lengths() {
        for value in [
            0,
            63,
            64,
            16_383,
            16_384,
            (1u64 << 30) - 1,
            1u64 << 30,
            (1u64 << 62) - 1,
        ] {
            let mut encoded = Vec::new();
            put_varint(&mut encoded, value);
            let (decoded, rest) = take_varint(&encoded).expect("encoded varint");
            assert_eq!(decoded, value);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn quic_varint_rejects_truncated_four_and_eight_byte_values() {
        assert!(take_varint(&[0x80, 1, 2]).is_none());
        assert!(take_varint(&[0xc0, 1, 2, 3, 4, 5, 6]).is_none());
    }
}
