//! 上游 DNS 传输：UDP、TCP、DoT、DoH（HTTP/2，协商失败回退 HTTP/1.1）、DoH3、DoQ。
//!
//! 每个（服务器，出站）组合一个 [`Client`]，复用连接：DoT 保留空闲连接，DoH 复用 HTTP/2 连接，
//! DoQ / DoH3 复用 QUIC 连接。

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf, Bytes};
use oryn_config::{DnsProto, ServerSpec, TargetAddr};
use oryn_outbound::{BoxStream, Outbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::quic_socket::PacketConnSocket;

/// 单次查询（含建立连接）的超时。
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_IDLE_TLS: usize = 2;
const MAX_MESSAGE: usize = 65535;

/// 查询发往上游时经过的出站。
#[derive(Clone)]
pub enum Via {
    Direct,
    Proxy(Arc<dyn Outbound>),
}

impl Via {
    pub fn key(&self) -> String {
        match self {
            Via::Direct => "DIRECT".into(),
            Via::Proxy(o) => o.tag().to_string(),
        }
    }
}

type TlsConn = oryn_tls::TlsStream<BoxStream>;
type H3Send = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

pub struct Client {
    spec: ServerSpec,
    via: Via,
    addr: SocketAddr,
    skip_verify: bool,
    tls_idle: Mutex<Vec<TlsConn>>,
    h2: Mutex<Option<h2::client::SendRequest<Bytes>>>,
    /// 服务器只协商出 HTTP/1.1。
    http1: AtomicBool,
    quic: Mutex<Option<(quinn::Endpoint, quinn::Connection)>>,
    h3: Mutex<Option<H3Send>>,
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

impl Client {
    pub fn new(spec: ServerSpec, via: Via, addr: SocketAddr, skip_verify: bool) -> Client {
        Client {
            skip_verify: skip_verify || spec.skip_cert_verify,
            spec,
            via,
            addr,
            tls_idle: Mutex::new(Vec::new()),
            h2: Mutex::new(None),
            http1: AtomicBool::new(false),
            quic: Mutex::new(None),
            h3: Mutex::new(None),
        }
    }

    /// 发送查询并返回应答（应答的 ID 与查询一致）。
    pub async fn exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        match tokio::time::timeout(UPSTREAM_TIMEOUT, self.exchange_inner(query)).await {
            Ok(r) => r,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("DNS upstream {} timed out", self.spec.raw),
            )),
        }
    }

    async fn exchange_inner(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        if query.len() < 12 || query.len() > MAX_MESSAGE {
            return Err(io::Error::other("invalid DNS query"));
        }
        let id = [query[0], query[1]];
        // 发往上游的事务 ID 随机化，不沿用客户端的 ID（防止可预测 ID 被伪造应答命中）；
        // 应答还要求问题段与查询一致。
        let wire_id = random_id();
        let query = &with_id(query, wire_id);
        let mut resp = match (self.spec.proto, &self.via) {
            (DnsProto::Tailscale, _) => {
                return Err(io::Error::other(
                    "identity DNS must be queried through its outbound",
                ))
            }
            (DnsProto::Udp, Via::Direct) => self.udp(query).await?,
            // 经代理时 UDP 改用 TCP（HTTP 代理不支持 UDP）
            (DnsProto::Udp | DnsProto::Tcp, _) => {
                let mut s = self.tcp().await?;
                framed(&mut s, query).await?
            }
            (DnsProto::Tls, _) => self.dot(query).await?,
            (DnsProto::Https, _) => self.doh(&with_id(query, [0, 0])).await?,
            (DnsProto::H3, _) => self.doh3(&with_id(query, [0, 0])).await?,
            (DnsProto::Quic, _) => self.doq(&with_id(query, [0, 0])).await?,
        };
        if resp.len() < 12 {
            return Err(io::Error::other("DNS response too short"));
        }
        if matches!(
            self.spec.proto,
            DnsProto::Https | DnsProto::H3 | DnsProto::Quic
        ) {
            resp[0] = id[0];
            resp[1] = id[1];
        } else if resp[..2] != wire_id {
            return Err(io::Error::other("DNS response ID mismatch"));
        }
        if !same_question(query, &resp) {
            return Err(io::Error::other("DNS response question mismatch"));
        }
        resp[0] = id[0];
        resp[1] = id[1];
        Ok(resp)
    }

    async fn udp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let sock = oryn_udp::iface::bind_udp(self.addr.is_ipv6()).await?;
        sock.connect(self.addr).await?;
        sock.send(query).await?;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = sock.recv(&mut buf).await?;
            // 忽略 ID 或问题段不符的迟到 / 伪造应答
            if n >= 2 && buf[..2] == query[..2] && same_question(query, &buf[..n]) {
                buf.truncate(n);
                return Ok(buf);
            }
        }
    }

    async fn tcp(&self) -> io::Result<BoxStream> {
        match &self.via {
            Via::Direct => {
                let s = oryn_udp::iface::connect_tcp(self.addr).await?;
                let _ = s.set_nodelay(true);
                Ok(Box::new(s))
            }
            Via::Proxy(o) => o.connect_tcp(&TargetAddr::Ip(self.addr)).await,
        }
    }

    async fn tls(&self, alpn: &[&[u8]]) -> io::Result<TlsConn> {
        let s = self.tcp().await?;
        oryn_tls::connect(s, &self.spec.host, alpn, self.skip_verify).await
    }

    async fn dot(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let idle = self.tls_idle.lock().unwrap().pop();
        if let Some(mut s) = idle {
            if let Ok(resp) = framed(&mut s, query).await {
                self.return_tls(s);
                return Ok(resp);
            }
        }
        let mut s = self.tls(&[]).await?;
        let resp = framed(&mut s, query).await?;
        self.return_tls(s);
        Ok(resp)
    }

    fn return_tls(&self, s: TlsConn) {
        let mut idle = self.tls_idle.lock().unwrap();
        if idle.len() < MAX_IDLE_TLS {
            idle.push(s);
        }
    }

    fn doh_request(&self) -> io::Result<http::Request<()>> {
        let host = if self.spec.host.contains(':') {
            format!("[{}]", self.spec.host)
        } else {
            self.spec.host.clone()
        };
        let authority = if self.spec.port == 443 {
            host
        } else {
            format!("{host}:{}", self.spec.port)
        };
        http::Request::builder()
            .method("POST")
            .uri(format!("https://{authority}{}", self.spec.path))
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .map_err(io_err)
    }

    async fn doh(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        if self.http1.load(Ordering::Relaxed) {
            return self.doh_http1(query).await;
        }
        let pooled = self.h2.lock().unwrap().clone();
        if let Some(send) = pooled {
            match h2_post(send, self.doh_request()?, query).await {
                Ok(r) => return Ok(r),
                Err(_) => *self.h2.lock().unwrap() = None,
            }
        }
        let tls = self
            .tls(&[oryn_tls::ALPN_H2, oryn_tls::ALPN_HTTP11])
            .await?;
        if oryn_tls::negotiated_alpn(&tls).as_deref() != Some(oryn_tls::ALPN_H2) {
            self.http1.store(true, Ordering::Relaxed);
            return self.doh_http1_on(tls, query).await;
        }
        let (send, conn) = h2::client::handshake(tls).await.map_err(io_err)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        *self.h2.lock().unwrap() = Some(send.clone());
        h2_post(send, self.doh_request()?, query).await
    }

    async fn doh_http1(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let tls = self.tls(&[oryn_tls::ALPN_HTTP11]).await?;
        self.doh_http1_on(tls, query).await
    }

    async fn doh_http1_on(&self, mut tls: TlsConn, query: &[u8]) -> io::Result<Vec<u8>> {
        let url = oryn_http::Url {
            https: true,
            host: self.spec.host.clone(),
            port: self.spec.port,
            path: self.spec.path.clone(),
        };
        let headers = [
            ("Content-Type", "application/dns-message"),
            ("Accept", "application/dns-message"),
        ];
        let resp =
            oryn_http::send_and_read(&mut tls, "POST", &url, &headers, query, MAX_MESSAGE).await?;
        if !resp.is_success() {
            return Err(io::Error::other(format!(
                "DoH server returned HTTP {}",
                resp.status
            )));
        }
        Ok(resp.body)
    }

    async fn quic_conn(&self, alpn: &[u8]) -> io::Result<quinn::Connection> {
        if let Some((_, c)) = self.quic.lock().unwrap().as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let mut config = oryn_tls::quic_client_config(&[alpn], self.skip_verify)?;
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(io_err)?))
            .stream_receive_window(quinn::VarInt::from_u32(64 * 1024))
            .receive_window(quinn::VarInt::from_u32(256 * 1024))
            .send_window(256 * 1024);
        config.transport_config(Arc::new(transport));
        let endpoint = match &self.via {
            Via::Direct => {
                let local: SocketAddr = if self.addr.is_ipv6() {
                    "[::]:0".parse().unwrap()
                } else {
                    "0.0.0.0:0".parse().unwrap()
                };
                quinn::Endpoint::client(local)?
            }
            Via::Proxy(o) => {
                let pc = o.bind_udp(&TargetAddr::Ip(self.addr)).await?;
                let socket = PacketConnSocket::new(pc, self.addr.is_ipv6());
                quinn::Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    None,
                    socket,
                    Arc::new(quinn::TokioRuntime),
                )?
            }
        };
        let conn = endpoint
            .connect_with(
                config,
                self.addr,
                self.spec.host.trim_start_matches('[').trim_end_matches(']'),
            )
            .map_err(io_err)?
            .await
            .map_err(io_err)?;
        *self.quic.lock().unwrap() = Some((endpoint, conn.clone()));
        Ok(conn)
    }

    async fn doq(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let conn = self.quic_conn(oryn_tls::ALPN_DOQ).await?;
        let r = doq_exchange(&conn, query).await;
        if r.is_err() {
            *self.quic.lock().unwrap() = None;
        }
        r
    }

    async fn doh3(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let pooled = self.h3.lock().unwrap().clone();
        let mut send = match pooled {
            Some(s) => s,
            None => {
                let conn = self.quic_conn(oryn_tls::ALPN_H3).await?;
                let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn))
                    .await
                    .map_err(io_err)?;
                tokio::spawn(async move {
                    let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                });
                *self.h3.lock().unwrap() = Some(send.clone());
                send
            }
        };
        let r: io::Result<Vec<u8>> = async {
            let mut stream = send
                .send_request(self.doh_request()?)
                .await
                .map_err(io_err)?;
            stream
                .send_data(Bytes::copy_from_slice(query))
                .await
                .map_err(io_err)?;
            stream.finish().await.map_err(io_err)?;
            let resp = stream.recv_response().await.map_err(io_err)?;
            if !resp.status().is_success() {
                return Err(io::Error::other(format!(
                    "DoH3 server returned HTTP {}",
                    resp.status()
                )));
            }
            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.map_err(io_err)? {
                while chunk.has_remaining() {
                    let c = chunk.chunk();
                    body.extend_from_slice(c);
                    let n = c.len();
                    chunk.advance(n);
                }
                if body.len() > MAX_MESSAGE {
                    return Err(io::Error::other("DoH3 response too large"));
                }
            }
            Ok(body)
        }
        .await;
        if r.is_err() {
            *self.h3.lock().unwrap() = None;
            *self.quic.lock().unwrap() = None;
        }
        r
    }
}

fn random_id() -> [u8; 2] {
    use std::hash::{BuildHasher, Hasher};
    // RandomState 每次新建都换一组随机键；混入计数与时间即可得到不可预测的 16 位 ID。
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    (h.finish() as u16).to_be_bytes()
}

/// 应答的问题段（名称大小写不敏感）与查询一致；没有问题段的应答不接受。
fn same_question(query: &[u8], resp: &[u8]) -> bool {
    match (
        crate::wire::parse_question(query),
        crate::wire::parse_question(resp),
    ) {
        (Some(q), Some(r)) => q.name == r.name && q.qtype == r.qtype && q.qclass == r.qclass,
        (None, _) => true,
        _ => false,
    }
}

fn with_id(query: &[u8], id: [u8; 2]) -> Vec<u8> {
    let mut q = query.to_vec();
    q[0] = id[0];
    q[1] = id[1];
    q
}

/// DNS over TCP / TLS：2 字节长度前缀。
pub async fn framed<S>(s: &mut S, query: &[u8]) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut req = Vec::with_capacity(query.len() + 2);
    req.extend_from_slice(&(query.len() as u16).to_be_bytes());
    req.extend_from_slice(query);
    s.write_all(&req).await?;
    s.flush().await?;
    let len = s.read_u16().await? as usize;
    let mut resp = vec![0u8; len];
    s.read_exact(&mut resp).await?;
    Ok(resp)
}

async fn h2_post(
    send: h2::client::SendRequest<Bytes>,
    req: http::Request<()>,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let mut send = send.ready().await.map_err(io_err)?;
    let (response, mut stream) = send.send_request(req, false).map_err(io_err)?;
    stream
        .send_data(Bytes::copy_from_slice(query), true)
        .map_err(io_err)?;
    let resp = response.await.map_err(io_err)?;
    if !resp.status().is_success() {
        return Err(io::Error::other(format!(
            "DoH server returned HTTP {}",
            resp.status()
        )));
    }
    let mut body = resp.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(io_err)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
        if out.len() > MAX_MESSAGE {
            return Err(io::Error::other("DoH response too large"));
        }
    }
    Ok(out)
}

/// DoQ（RFC 9250）：每个查询一个双向流，2 字节长度前缀，发送后关闭发送方向。
async fn doq_exchange(conn: &quinn::Connection, query: &[u8]) -> io::Result<Vec<u8>> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(io_err)?;
    let mut req = Vec::with_capacity(query.len() + 2);
    req.extend_from_slice(&(query.len() as u16).to_be_bytes());
    req.extend_from_slice(query);
    send.write_all(&req).await.map_err(io_err)?;
    send.finish().map_err(io_err)?;
    let data = recv.read_to_end(MAX_MESSAGE + 2).await.map_err(io_err)?;
    if data.len() < 2 {
        return Err(io::Error::other("DoQ response too short"));
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    data.get(2..2 + len)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| io::Error::other("DoQ response truncated"))
}
