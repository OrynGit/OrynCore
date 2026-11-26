//! TS2021 控制连接。Noise 实现来自固定上游组件，其余网络 I/O 使用 Oryn Dialer。
//! 协议参考 tailscale/tailscale-rs f4781c480e8d1376aed89f737beefe7425e8b866
//! ts_control/src/client/{connect,register,map_stream}.rs（BSD-3-Clause）；本文件为 Oryn 适配实现。
use super::{err, Task};
use crate::{BoxStream, Dialer};
use bytes::Bytes;
use oryn_config::{TailscaleSpec, TargetAddr, TlsSpec};
use serde_json::{json, Value};
use std::{io, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ts_keys::{MachinePublicKey, NodeState};

/// 单个 MapResponse 上限：须容下 256 个对端的完整 netmap（见 snapshot::MAX_PEERS）。
pub const MAX_MAP: usize = 1024 * 1024;
const MAX_HTTP: usize = 64 * 1024;
const CAP: ts_capabilityversion::CapabilityVersion =
    ts_capabilityversion::CapabilityVersion::CURRENT;

/// Hostinfo.OS：与 tailscale `version.OS()` 一致（GOOS，Apple 平台写作 iOS / macOS）。
/// 原先固定上报 iOS，控制面按平台下发的能力与统计失真（OrynCore#43）。
pub fn host_os() -> &'static str {
    match std::env::consts::OS {
        "ios" => "iOS",
        "macos" => "macOS",
        os => os,
    }
}

pub async fn transport(dialer: &dyn Dialer, url: &url::Url) -> io::Result<BoxStream> {
    transport_with(dialer, url, None).await
}

/// `cert` 是 DERP 节点的 `CertName`：`sha256-raw:<hex>` 固定自签叶证书（整张 DER 的 SHA-256，
/// 不验证信任链，与 tailscale tlsdial.SetConfigExpectedCertHash 相同）；其它值是期望的证书名称。
pub async fn transport_with(
    dialer: &dyn Dialer,
    url: &url::Url,
    cert: Option<&str>,
) -> io::Result<BoxStream> {
    transport_derp(dialer, url, cert, false, &[]).await
}

/// 连接 DERP 节点：`insecure` 对应 DERPMap 里的 `InsecureForTests`（非 127.0.0.1 走 HTTPS
/// 时跳过证书链校验，仅校验握手签名）；`fallback_ips` 用于 `HostName` 仅作 SNI/无 DNS 解析时
/// 回退直连 DERPMap 给出的 `IPv4` / `IPv6`（OrynCore#43）。
pub async fn transport_derp(
    dialer: &dyn Dialer,
    url: &url::Url,
    cert: Option<&str>,
    insecure: bool,
    fallback_ips: &[std::net::IpAddr],
) -> io::Result<BoxStream> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(err("Tailscale URL contains credentials or fragment"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| err("missing Tailscale server host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| err("invalid Tailscale server port"))?;
    let host_unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    let target = host_unbracketed
        .parse()
        .map(|ip| TargetAddr::Ip(std::net::SocketAddr::new(ip, port)))
        .unwrap_or_else(|_| TargetAddr::Domain(host_unbracketed.into(), port));
    let stream = match dialer.dial_tcp(&target).await {
        Ok(stream) => stream,
        Err(first_err) => {
            let mut connected = None;
            for ip in fallback_ips {
                if let Ok(stream) = dialer
                    .dial_tcp(&TargetAddr::Ip(std::net::SocketAddr::new(*ip, port)))
                    .await
                {
                    connected = Some(stream);
                    break;
                }
            }
            connected.ok_or(first_err)?
        }
    };
    if url.scheme() == "http" && host_unbracketed == "127.0.0.1" {
        return Ok(stream);
    }
    if url.scheme() != "https" {
        return Err(err("Tailscale requires HTTPS"));
    }
    let pinned = match cert.and_then(|c| c.strip_prefix("sha256-raw:")) {
        Some(hex) => Some(cert_hash(hex)?),
        None => None,
    };
    let name = match cert {
        Some(c) if pinned.is_none() => c,
        _ => host_unbracketed,
    };
    let spec = TlsSpec {
        sni: Some(name.into()),
        skip_cert_verify: insecure || pinned.is_some(),
        alpn: vec!["http/1.1".into()],
        fingerprint: pinned,
        client_fingerprint: None,
        reality: None,
        ech: None,
    };
    Ok(Box::new(
        oryn_tls::connect_proxy(stream, name, &spec).await?,
    ))
}

fn cert_hash(hex: &str) -> io::Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(err("invalid DERP sha256-raw certificate hash"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| err("invalid DERP sha256-raw certificate hash"))?;
    }
    Ok(out)
}

/// 逐字节读取有限 HTTP 首部，不多读升级后的 Noise / DERP 数据。
pub async fn headers(stream: &mut BoxStream) -> io::Result<(u16, Vec<(String, String)>)> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= 16 * 1024 {
            return Err(err("Tailscale HTTP headers exceed limit"));
        }
        bytes.push(stream.read_u8().await?);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| err("invalid HTTP header"))?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|s| s.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| err("invalid HTTP status"))?;
    let mut fields = Vec::new();
    for line in lines.filter(|s| !s.is_empty()) {
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| err("invalid HTTP field"))?;
        fields.push((k.to_ascii_lowercase(), v.trim().into()));
    }
    Ok((status, fields))
}

async fn key(dialer: &dyn Dialer, url: &url::Url) -> io::Result<MachinePublicKey> {
    let mut stream = transport(dialer, url).await?;
    let host = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let request = format!(
        "GET /key?v={} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        u16::from(CAP)
    );
    stream.write_all(request.as_bytes()).await?;
    let (status, fields) = headers(&mut stream).await?;
    if status != 200 {
        return Err(err("Tailscale control key request failed"));
    }
    let len = fields
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok());
    let mut body = Vec::new();
    if fields
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                if line.len() >= 128 {
                    return Err(err("invalid HTTP chunk length"));
                }
                line.push(stream.read_u8().await?);
            }
            let n = usize::from_str_radix(
                std::str::from_utf8(&line)
                    .map_err(io::Error::other)?
                    .trim()
                    .split(';')
                    .next()
                    .unwrap_or(""),
                16,
            )
            .map_err(io::Error::other)?;
            if n == 0 {
                break;
            }
            if n > MAX_HTTP - body.len() {
                return Err(err("control key body exceeds limit"));
            }
            let start = body.len();
            body.resize(start + n, 0);
            stream.read_exact(&mut body[start..]).await?;
            if stream.read_u16().await? != 0x0d0a {
                return Err(err("invalid HTTP chunk terminator"));
            }
        }
    } else if let Some(len) = len {
        if len > MAX_HTTP {
            return Err(err("control key body exceeds limit"));
        }
        body.resize(len, 0);
        stream.read_exact(&mut body).await?;
    } else {
        stream
            .take((MAX_HTTP + 1) as u64)
            .read_to_end(&mut body)
            .await?;
        if body.len() > MAX_HTTP {
            return Err(err("control key body exceeds limit"));
        }
    }
    let value: Value = serde_json::from_slice(&body).map_err(io::Error::other)?;
    value["publicKey"]
        .as_str()
        .ok_or_else(|| err("missing control public key"))?
        .parse()
        .map_err(io::Error::other)
}

pub struct Control {
    sender: h2::client::SendRequest<Bytes>,
    _driver: Task,
    url: url::Url,
}

impl Control {
    pub async fn connect(
        spec: &TailscaleSpec,
        keys: &NodeState,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let url: url::Url = spec.control_url.parse().map_err(io::Error::other)?;
        let control_key = key(dialer.as_ref(), &url).await?;
        let mut stream = transport(dialer.as_ref(), &url).await?;
        let (handshake, init) = ts_control_noise::Handshake::initialize(
            &format!("Tailscale Control Protocol v{}", u16::from(CAP)),
            &keys.machine_keys,
            &control_key,
            CAP,
        );
        let host = &url[url::Position::BeforeHost..url::Position::AfterPort];
        stream.write_all(format!("POST /ts2021 HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: tailscale-control-protocol\r\nX-Tailscale-Handshake: {init}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
        let (status, fields) = headers(&mut stream).await?;
        if status != 101
            || !fields.iter().any(|(k, v)| {
                k == "upgrade" && v.eq_ignore_ascii_case("tailscale-control-protocol")
            })
        {
            return Err(err("TS2021 upgrade rejected"));
        }
        let mut noise = handshake
            .complete(stream, &keys.machine_keys)
            .await
            .map_err(io::Error::other)?;
        let mut prefix = [0; 5];
        noise.read_exact(&mut prefix).await?;
        let conn: BoxStream = if prefix == [255, 255, 255, b'T', b'S'] {
            let n = noise.read_u32().await? as usize;
            if n > 1024 {
                return Err(err("TS2021 challenge exceeds limit"));
            }
            let mut skip = vec![0; n];
            noise.read_exact(&mut skip).await?;
            Box::new(noise)
        } else {
            Box::new(Prefixed {
                prefix: std::io::Cursor::new(prefix.to_vec()),
                inner: Box::new(noise),
            })
        };
        let (sender, driver) = h2::client::Builder::new()
            .initial_window_size(64 * 1024)
            .initial_connection_window_size(128 * 1024)
            .max_frame_size(16 * 1024)
            .max_header_list_size(16 * 1024)
            .max_concurrent_streams(4)
            .handshake(conn)
            .await
            .map_err(io::Error::other)?;
        let driver = Task(tokio::spawn(async move {
            let _ = driver.await;
        }));
        let mut ctl = Self {
            sender,
            _driver: driver,
            url,
        };
        let register = json!({"Version":u16::from(CAP),"NodeKey":keys.node_keys.public.to_string(),
            "Hostinfo":{"Hostname":spec.hostname.as_deref().unwrap_or("oryn"),"OS":host_os(),"IPNVersion":"Oryn/0.0.1"},
            "Auth":spec.auth_key.as_ref().map(|key| json!({"AuthKey":key})),"Ephemeral":spec.ephemeral});
        let mut response = ctl.post("/machine/register", register).await?;
        let result: Value =
            serde_json::from_slice(&response.all(MAX_HTTP).await?).map_err(io::Error::other)?;
        if result["MachineAuthorized"].as_bool() != Some(true)
            || result["NodeKeyExpired"].as_bool() == Some(true)
            || result["Error"].as_str().is_some_and(|s| !s.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Tailscale registration denied; supply a valid auth-key or approve the device",
            ));
        }
        Ok(ctl)
    }
    async fn post(&mut self, path: &str, body: Value) -> io::Result<Body> {
        let bytes = Bytes::from(serde_json::to_vec(&body).map_err(io::Error::other)?);
        let uri = self.url.join(path).map_err(io::Error::other)?.to_string();
        let req = http::Request::post(uri)
            .header("content-type", "application/json")
            .body(())
            .map_err(io::Error::other)?;
        self.sender = self
            .sender
            .clone()
            .ready()
            .await
            .map_err(io::Error::other)?;
        let (response, mut tx) = self
            .sender
            .send_request(req, false)
            .map_err(io::Error::other)?;
        tx.send_data(bytes, true).map_err(io::Error::other)?;
        let response = response.await.map_err(io::Error::other)?;
        if !response.status().is_success() {
            return Err(err("Tailscale control HTTP request failed"));
        }
        Ok(Body {
            stream: response.into_body(),
            pending: Bytes::new(),
        })
    }
    pub async fn map(
        &mut self,
        spec: &TailscaleSpec,
        keys: &NodeState,
        region: Option<u16>,
        stream: bool,
    ) -> io::Result<Body> {
        self.post("/machine/map",json!({"Version":u16::from(CAP), "NodeKey": keys.node_keys.public.to_string(),
            "DiscoKey":keys.disco_keys.public.to_string(),"Stream":stream,"KeepAlive":true,"OmitPeers":!stream,
            "Hostinfo":{"Hostname":spec.hostname.as_deref().unwrap_or("oryn"),"OS":host_os(),"IPNVersion":"Oryn/0.0.1",
                "NetInfo":{"PreferredDERP":region.unwrap_or(0)}},"Endpoints":[]})).await
    }
}

pub struct Body {
    stream: h2::RecvStream,
    pending: Bytes,
}
impl Body {
    async fn exact(&mut self, mut dst: &mut [u8]) -> io::Result<()> {
        while !dst.is_empty() {
            if self.pending.is_empty() {
                self.pending = self
                    .stream
                    .data()
                    .await
                    .ok_or_else(|| err("Tailscale control stream closed"))?
                    .map_err(io::Error::other)?;
                self.stream
                    .flow_control()
                    .release_capacity(self.pending.len())
                    .map_err(io::Error::other)?;
            }
            let n = dst.len().min(self.pending.len());
            dst[..n].copy_from_slice(&self.pending.split_to(n));
            dst = &mut dst[n..];
        }
        Ok(())
    }
    pub async fn frame(&mut self) -> io::Result<Value> {
        let mut len = [0; 4];
        self.exact(&mut len).await?;
        let len = u32::from_le_bytes(len) as usize;
        if len > MAX_MAP {
            return Err(err("Tailscale netmap exceeds 256 KiB limit"));
        }
        let mut body = vec![0; len];
        self.exact(&mut body).await?;
        serde_json::from_slice(&body).map_err(io::Error::other)
    }
    pub async fn all(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.stream.data().await {
            let chunk = chunk.map_err(io::Error::other)?;
            if chunk.len() > limit - out.len() {
                return Err(err("Tailscale HTTP body exceeds limit"));
            }
            out.extend_from_slice(&chunk);
            self.stream
                .flow_control()
                .release_capacity(chunk.len())
                .map_err(io::Error::other)?;
        }
        Ok(out)
    }
}

pub async fn timed<T>(future: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Tailscale operation timed out"))?
}

struct Prefixed {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: BoxStream,
}
impl tokio::io::AsyncRead for Prefixed {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if (self.prefix.position() as usize) < self.prefix.get_ref().len() {
            std::pin::Pin::new(&mut self.prefix).poll_read(cx, buf)
        } else {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}
impl tokio::io::AsyncWrite for Prefixed {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod os_and_cert_tests {
    use super::*;
    #[test]
    fn host_os_follows_platform_not_ios() {
        let os = host_os();
        if cfg!(target_os = "macos") {
            assert_eq!(os, "macOS");
        } else if cfg!(target_os = "linux") {
            assert_eq!(os, "linux");
        }
        assert!(cfg!(target_os = "ios") || os != "iOS");
    }
    #[test]
    fn sha256_raw_hash_is_hex_of_32_bytes() {
        let hex = format!("{}{}", "00ff".repeat(15), "a1b2");
        let hash = cert_hash(&hex).unwrap();
        assert_eq!(hash[0], 0x00);
        assert_eq!(hash[1], 0xff);
        assert_eq!(hash[31], 0xb2);
        assert!(cert_hash("abcd").is_err());
        assert!(cert_hash(&"zz".repeat(32)).is_err());
    }

    #[tokio::test]
    async fn derp_tls_supports_sha256_raw_insecure_for_tests_and_ip_fallback() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::net::TcpListener;

        struct LoopbackDialer(std::net::SocketAddr);
        #[async_trait::async_trait]
        impl Dialer for LoopbackDialer {
            async fn dial_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
                match target {
                    TargetAddr::Ip(addr) if *addr == self.0 => {
                        let s = tokio::net::TcpStream::connect(self.0).await?;
                        Ok(Box::new(s))
                    }
                    TargetAddr::Domain(host, _) if host == "derp-999.invalid" => {
                        Err(io::Error::new(io::ErrorKind::NotFound, "no dns"))
                    }
                    _ => Err(io::Error::new(io::ErrorKind::ConnectionRefused, "unexpected target")),
                }
            }
        }

        let cert = rcgen::generate_simple_self_signed(vec!["wrong.internal".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let digest = ring::digest::digest(&ring::digest::SHA256, cert_der.as_ref());
        let sha256_pin = format!(
            "sha256-raw:{}",
            digest
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );

        let tls_cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(oryn_tls::provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
            while let Ok((stream, _)) = listener.accept().await {
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acc.accept(stream).await {
                        let mut buf = [0u8; 4];
                        if tls.read_exact(&mut buf).await.is_ok() {
                            let _ = tls.write_all(&buf).await;
                        }
                    }
                });
            }
        });

        let dialer = LoopbackDialer(addr);
        let direct_url: url::Url = format!("https://127.0.0.1:{}/derp", addr.port()).parse().unwrap();
        let named_url: url::Url = format!("https://derp-999.invalid:{}/derp", addr.port())
            .parse()
            .unwrap();
        let fallback = [addr.ip()];

        // 默认不跳过校验且无 pin：拒绝自签证书
        assert!(transport_derp(&dialer, &direct_url, None, false, &[]).await.is_err());

        // Err 固定哈希拒绝；正确 sha256-raw:<hex> 与 HostName 不可解析时 IPv4 回退均成功
        let bad_pin = format!("sha256-raw:{}", "00".repeat(32));
        assert!(transport_derp(&dialer, &direct_url, Some(&bad_pin), false, &[]).await.is_err());

        let mut s = transport_derp(&dialer, &named_url, Some(&sha256_pin), false, &fallback)
            .await
            .expect("sha256-raw self-signed DERP with IP fallback must succeed");
        s.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        s.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");

        // 非 127.0.0.1 节点开启 InsecureForTests (insecure = true) 通过自签 TLS
        let mut s2 = transport_derp(&dialer, &named_url, None, true, &fallback)
            .await
            .expect("InsecureForTests HTTPS DERP must succeed");
        s2.write_all(b"pong").await.unwrap();
        s2.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"pong");

        // 同时传错 pin + insecure=true 仍须被 PinnedVerifier 拒绝
        assert!(transport_derp(&dialer, &direct_url, Some(&bad_pin), true, &[]).await.is_err());

        server_task.abort();
    }
}
