//! Trojan / VLESS 共用下层组合；协议只提供首部与 UDP 编解码。
use crate::{unsupported, with_timeout, BoxStream, Dialer, Outbound, PacketConn, Resolver};
use async_trait::async_trait;
use oryn_config::{PacketEncoding, SecuritySpec, StreamProxySpec, TargetAddr, TransportSpec};
use oryn_protocol::{socks5, trojan, vless, vmess};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
    sync::Mutex,
};

/// `oryn-transport` intentionally does not depend on the outbound crate.  This
/// adapter preserves the shared byte-stream boundary when Mekya opens a fresh
/// HTTP request for each upload batch.
struct MekyaStreamAdapter(crate::BoxStream);
impl AsyncRead for MekyaStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for MekyaStreamAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

/// 裸 mKCP 也使用配置后的数据报工厂，确保链式代理与普通直连语义一致。
struct KcpPackets {
    packets: Arc<dyn oryn_udp::Datagrams>,
    peer: std::net::SocketAddr,
}
impl oryn_transport::KcpPacketIo for KcpPackets {
    fn send<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { self.packets.try_send_to(packet, self.peer) })
    }
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            loop {
                let (n, peer) = self.packets.recv_from(buf).await?;
                if peer == self.peer {
                    return Ok(n);
                }
                tokio::task::yield_now().await;
            }
        })
    }
}

pub enum StreamProtocol {
    Trojan(String),
    Vless([u8; 16]),
    Vmess(oryn_config::VmessSpec),
}
/// V2Ray QUIC 传输：同一出站的 Flow 共享一条 QUIC 连接，每个 Flow 一个双向流。
#[cfg(feature = "quic")]
struct QuicTransport {
    client: Arc<oryn_quic::QuicClient>,
    streams: crate::slots::Slots,
}

pub struct StreamProxyOutbound {
    tag: String,
    spec: StreamProxySpec,
    protocol: StreamProtocol,
    dialer: Arc<dyn Dialer>,
    /// 解析 QUIC 传输的服务器地址。
    resolver: Arc<dyn Resolver>,
    datagrams: Arc<dyn oryn_udp::DatagramFactory>,
    /// gRPC / h2 传输时同一出站的 Flow 共享 h2 连接。
    h2: Option<oryn_transport::GrpcPool>,
    xhttp_download: Option<oryn_transport::GrpcPool>,
    encryption: Option<oryn_protocol::vless_encryption::Client>,
    #[cfg(feature = "quic")]
    quic: Option<QuicTransport>,
}
impl StreamProxyOutbound {
    pub fn new(
        tag: String,
        spec: StreamProxySpec,
        protocol: StreamProtocol,
        dialer: Arc<dyn Dialer>,
        datagrams: Arc<dyn oryn_udp::DatagramFactory>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let h2 = matches!(
            spec.transport,
            TransportSpec::Grpc(_) | TransportSpec::H2(_) | TransportSpec::XHttp(_)
        )
        .then(oryn_transport::GrpcPool::new);
        let xhttp_download =
            matches!(&spec.transport, TransportSpec::XHttp(x) if x.download.is_some())
                .then(oryn_transport::GrpcPool::new);
        #[cfg(feature = "quic")]
        let quic = match (&spec.transport, &spec.security) {
            (TransportSpec::Quic, SecuritySpec::Tls(tls)) => {
                let alpn = if tls.alpn.is_empty() {
                    vec![b"h3".to_vec()]
                } else {
                    tls.alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
                };
                Some(QuicTransport {
                    client: oryn_quic::QuicClient::new(oryn_quic::QuicParams {
                        datagrams: datagrams.clone(),
                        alpn,
                        skip_verify: tls.skip_cert_verify,
                        fingerprint: tls.fingerprint,
                        disable_sni: false,
                        congestion: oryn_quic::Congestion::Bbr,
                        brutal_rate: None,
                        obfs: None,
                        hop: None,
                        rendezvous: None,
                        zero_rtt: false,
                        keep_alive: None,
                    }),
                    streams: crate::slots::Slots::default(),
                })
            }
            _ => None,
        };
        let encryption = spec
            .vless_encryption
            .clone()
            .map(oryn_protocol::vless_encryption::Client::new);
        Self {
            encryption,
            tag,
            spec,
            protocol,
            dialer,
            resolver,
            datagrams,
            h2,
            xhttp_download,
            #[cfg(feature = "quic")]
            quic,
        }
    }

    /// V2Ray QUIC：共享连接上开一个双向流，协议首部是流的第一段数据。
    #[cfg(feature = "quic")]
    async fn open_quic(&self, quic: &QuicTransport, initial: &[u8]) -> io::Result<BoxStream> {
        // RuntimeConfig 也可直接构造：不能仅依赖 YAML 校验而把隐私选项静默降级。
        if matches!(&self.spec.security, SecuritySpec::Tls(tls) if tls.ech.is_some()) {
            return Err(unsupported("QUIC transport does not support ECH"));
        }
        let slot = quic
            .streams
            .acquire(oryn_quic::MAX_BIDI)
            .ok_or_else(|| io::Error::other("QUIC transport stream limit reached"))?;
        let addr = *crate::resolve_target(self.resolver.as_ref(), &self.spec.server)
            .await?
            .first()
            .ok_or_else(|| io::Error::other("cannot resolve QUIC transport server"))?;
        let name = match &self.spec.security {
            SecuritySpec::Tls(tls) if tls.sni.is_some() => tls.sni.clone().unwrap(),
            _ => match &self.spec.server {
                TargetAddr::Domain(d, _) => d.clone(),
                TargetAddr::Ip(a) => a.ip().to_string(),
            },
        };
        let conn = quic
            .client
            .connection(addr.ip(), &name, addr.port())
            .await?;
        let (mut send, recv) = conn.open_bi().await.map_err(io::Error::other)?;
        send.write_all(initial).await.map_err(io::Error::other)?;
        Ok(crate::slots::HeldStream::boxed(
            crate::slots::Counted::boxed(Box::new(tokio::io::join(recv, send)), slot),
            quic.client.clone(),
        ))
    }

    async fn open_kcp(&self, spec: &oryn_config::KcpSpec, initial: &[u8]) -> io::Result<BoxStream> {
        if !matches!(self.spec.security, SecuritySpec::None) {
            return Err(unsupported("mKCP does not support an additional TLS layer"));
        }
        let addr = *crate::resolve_target(self.resolver.as_ref(), &self.spec.server)
            .await?
            .first()
            .ok_or_else(|| io::Error::other("cannot resolve mKCP server"))?;
        let packets = self.datagrams.bind(addr).await?;
        let mut stream = oryn_transport::KcpStream::connect_io(
            KcpPackets {
                packets,
                peer: addr,
            },
            spec,
        )
        .await?;
        stream.write_all(initial).await?;
        stream.flush().await?;
        Ok(Box::new(stream))
    }

    /// 上下行均经过同一出站的 Dialer，独立下载端不会绕过 dialer-proxy。
    fn xhttp_dialer(&self, spec: StreamProxySpec) -> oryn_transport::XHttpDial {
        let dialer = self.dialer.clone();
        let spec = Arc::new(spec);
        Arc::new(move || {
            let dialer = dialer.clone();
            let spec = spec.clone();
            Box::pin(async move {
                let raw = dialer.dial_tcp(&spec.server).await?;
                let (stream, _) = apply_security_for_spec(&spec, raw).await?;
                Ok(Box::new(MekyaStreamAdapter(stream)) as Box<dyn oryn_transport::XHttpIo>)
            })
        })
    }

    fn mekya_dialer(&self) -> oryn_transport::MekyaDial {
        let dialer = self.dialer.clone();
        let server = self.spec.server.clone();
        let security = Arc::new(self.spec.security.clone());
        let host = match security.as_ref() {
            SecuritySpec::Tls(tls) => tls.sni.clone().unwrap_or_else(|| match &server {
                TargetAddr::Domain(domain, _) => domain.clone(),
                TargetAddr::Ip(addr) => addr.ip().to_string(),
            }),
            SecuritySpec::ShadowTls(spec) if !spec.host.is_empty() => spec.host.clone(),
            _ => match &server {
                TargetAddr::Domain(domain, _) => domain.clone(),
                TargetAddr::Ip(addr) => addr.ip().to_string(),
            },
        };
        Arc::new(move || {
            let dialer = dialer.clone();
            let server = server.clone();
            let security = security.clone();
            let host = host.clone();
            Box::pin(async move {
                let raw = dialer.dial_tcp(&server).await?;
                match security.as_ref() {
                    SecuritySpec::None => Ok((
                        Box::new(MekyaStreamAdapter(raw)) as oryn_transport::MekyaStream,
                        true, // mihomo 未包装 TLS 的 Mekya 连接默认使用 h2c。
                    )),
                    SecuritySpec::Tls(tls) => {
                        let mut tls = tls.clone();
                        if tls.alpn.is_empty() {
                            tls.alpn = vec!["h2".into(), "http/1.1".into()];
                        }
                        let stream = oryn_tls::connect_proxy(raw, &host, &tls).await?;
                        let alpn = oryn_tls::negotiated_alpn(&stream);
                        let h2 = match alpn.as_deref() {
                            Some(b"h2") => true,
                            None | Some(b"http/1.1") => false,
                            _ => {
                                return Err(unsupported(
                                    "Mekya peer negotiated an unsupported ALPN",
                                ))
                            }
                        };
                        Ok((
                            Box::new(MekyaStreamAdapter(Box::new(stream)))
                                as oryn_transport::MekyaStream,
                            h2,
                        ))
                    }
                    SecuritySpec::ShadowTls(spec) => Ok((
                        Box::new(MekyaStreamAdapter(Box::new(
                            oryn_tls::shadowtls::connect(raw, spec).await?,
                        ))) as oryn_transport::MekyaStream,
                        false,
                    )),
                }
            })
        })
    }
    /// VLESS Vision：TCP + TLS / Reality。外层 TLS 下面垫逐记录读取层，VLESS 首部与响应由 Vision 流处理。
    /// UDP 走 XUDP（Mux 命令，没有地址）。
    async fn open_vision(
        &self,
        uuid: &[u8; 16],
        target: &TargetAddr,
        udp: bool,
    ) -> io::Result<BoxStream> {
        let SecuritySpec::Tls(tls) = &self.spec.security else {
            return Err(unsupported("VLESS Vision requires TLS"));
        };
        let host = match (&tls.sni, &self.spec.server) {
            (Some(sni), _) => sni.clone(),
            (None, TargetAddr::Domain(d, _)) => d.clone(),
            (None, TargetAddr::Ip(a)) => a.ip().to_string(),
        };
        let s = self.dialer.dial_tcp(&self.spec.server).await?;
        let s = oryn_tls::connect_proxy(crate::vision::RecordReader::new(s), &host, tls).await?;
        let request = if udp {
            vless::request_with_flow(uuid, None, vless::COMMAND_MUX, vless::FLOW_VISION)?
        } else {
            vless::request_with_flow(uuid, Some(target), vless::COMMAND_TCP, vless::FLOW_VISION)?
        };
        Ok(Box::new(crate::vision::VisionStream::new(
            s, *uuid, request,
        )))
    }

    async fn open(&self, target: &TargetAddr, udp: bool) -> io::Result<BoxStream> {
        if let (true, StreamProtocol::Vless(uuid)) = (self.spec.vision, &self.protocol) {
            return with_timeout(self.open_vision(uuid, target, udp), "proxy handshake").await;
        }
        with_timeout(
            async {
                let mut vmess_session = None;
                let initial = match &self.protocol {
                    StreamProtocol::Trojan(password) => trojan::request(password, target, udp)?,
                    StreamProtocol::Vless(uuid) => {
                        let mut header = vless::request(uuid, target, udp)?;
                        if udp && matches!(self.spec.packet_encoding, PacketEncoding::Xudp) {
                            header.truncate(19);
                            header[18] = 3;
                        }
                        header
                    }
                    StreamProtocol::Vmess(spec) => {
                        let (header, session) = vmess::Session::request(
                            spec,
                            target,
                            if udp {
                                if matches!(self.spec.packet_encoding, PacketEncoding::Xudp) {
                                    3
                                } else {
                                    2
                                }
                            } else {
                                1
                            },
                        )?;
                        vmess_session = Some(session);
                        header.to_vec()
                    }
                };
                let protocol_header = initial;
                let initial = if self.encryption.is_some() {
                    &[][..]
                } else {
                    protocol_header.as_slice()
                };
                let mut s = match (&self.spec.transport, &self.h2) {
                    (TransportSpec::Grpc(spec), Some(pool)) => {
                        let stream = pool
                            .open(&self.authority(), spec, initial, || async {
                                let s = self.dialer.dial_tcp(&self.spec.server).await?;
                                self.apply_security(s).await
                            })
                            .await?;
                        Box::new(stream) as BoxStream
                    }
                    (TransportSpec::H2(spec), Some(pool)) => {
                        let stream = pool
                            .open_h2(&self.authority(), spec, initial, || async {
                                let s = self.dialer.dial_tcp(&self.spec.server).await?;
                                self.apply_security(s).await
                            })
                            .await?;
                        Box::new(stream) as BoxStream
                    }
                    (TransportSpec::XHttp(spec), Some(pool)) => {
                        let download_authority = spec.download.as_ref().map(|d| {
                            format!(
                                "{}://{}",
                                if matches!(d.security, SecuritySpec::None) {
                                    "http"
                                } else {
                                    "https"
                                },
                                d.server
                            )
                        });
                        let authority = format!(
                            "{}://{}",
                            if matches!(self.spec.security, SecuritySpec::None) {
                                "http"
                            } else {
                                "https"
                            },
                            self.authority()
                        );
                        let download = spec
                            .download
                            .as_ref()
                            .zip(self.xhttp_download.as_ref())
                            .map(|(d, pool)| {
                                let mut endpoint = self.spec.clone();
                                endpoint.server = d.server.clone();
                                endpoint.security = d.security.clone();
                                endpoint.transport = TransportSpec::XHttp(*d.transport.clone());
                                (
                                    pool,
                                    download_authority.as_deref().unwrap(),
                                    self.xhttp_dialer(endpoint),
                                )
                            });
                        let stream = pool
                            .open_xhttp_with_dialers(
                                &authority,
                                spec,
                                initial,
                                self.xhttp_dialer(self.spec.clone()),
                                download,
                            )
                            .await?;
                        Box::new(stream) as BoxStream
                    }
                    (TransportSpec::Kcp(spec), _) => self.open_kcp(spec, initial).await?,
                    (TransportSpec::Mekya(spec), _) => {
                        let host = match &self.spec.server {
                            TargetAddr::Domain(domain, _) => domain.clone(),
                            TargetAddr::Ip(addr) => addr.ip().to_string(),
                        };
                        let mut mekya = spec.clone();
                        if mekya.url.is_empty() {
                            mekya.url = format!("https://{}", self.authority());
                        }
                        let mut kcp = oryn_transport::connect_kcp_dial(
                            &mekya,
                            host.clone(),
                            self.mekya_dialer(),
                        )
                        .await?;
                        kcp.write_all(initial).await?;
                        kcp.flush().await?;
                        Box::new(kcp) as BoxStream
                    }
                    #[cfg(feature = "quic")]
                    (TransportSpec::Quic, _) => match &self.quic {
                        Some(quic) => self.open_quic(quic, initial).await?,
                        None => return Err(unsupported("QUIC transport requires TLS")),
                    },
                    _ => {
                        let s = self.dialer.dial_tcp(&self.spec.server).await?;
                        let s = self.apply_security(s).await?;
                        self.apply_transport(s, initial).await?
                    }
                };
                if let Some(encryption) = &self.encryption {
                    s = Box::new(encryption.connect(s).await?);
                    s.write_all(&protocol_header).await?;
                    s.flush().await?;
                }
                if matches!(self.protocol, StreamProtocol::Vless(_)) {
                    s = Box::new(vless::ResponseStream::new(s));
                }
                if let Some(session) = vmess_session {
                    s = Box::new(session.stream(s));
                }
                Ok(s)
            },
            "proxy handshake",
        )
        .await
    }

    /// Security 层只接收和返回字节流，因此可以独立替换 TLS、ShadowTLS 等实现。
    async fn apply_security(&self, stream: BoxStream) -> io::Result<BoxStream> {
        Ok(self.apply_security_with_alpn(stream).await?.0)
    }

    async fn apply_security_with_alpn(&self, stream: BoxStream) -> io::Result<(BoxStream, bool)> {
        apply_security_for_spec(&self.spec, stream).await
    }
}

async fn apply_security_for_spec(
    spec: &StreamProxySpec,
    stream: BoxStream,
) -> io::Result<(BoxStream, bool)> {
    let security = match &spec.security {
        SecuritySpec::None => return Ok((stream, false)),
        SecuritySpec::Tls(tls) => {
            let mut tls = tls.clone();
            if matches!(
                spec.transport,
                TransportSpec::Ws(_) | TransportSpec::HttpUpgrade(_)
            ) && tls.client_fingerprint.is_some()
                && tls.alpn.is_empty()
            {
                tls.alpn = vec!["http/1.1".into()];
            }
            if matches!(
                spec.transport,
                TransportSpec::Grpc(_) | TransportSpec::H2(_) | TransportSpec::XHttp(_)
            ) && tls.alpn.is_empty()
            {
                tls.alpn = vec!["h2".into()];
            }
            if matches!(spec.transport, TransportSpec::Mekya(_)) && tls.alpn.is_empty() {
                tls.alpn = vec!["h2".into(), "http/1.1".into()];
            }
            if matches!(spec.transport, TransportSpec::Http(_)) && tls.alpn.is_empty() {
                tls.alpn = vec!["http/1.1".into()];
            }
            Some(tls)
        }
        SecuritySpec::ShadowTls(spec) => {
            return Ok((
                Box::new(oryn_tls::shadowtls::connect(stream, spec).await?),
                false,
            ));
        }
    };
    let tls = security.unwrap();
    let host = match (&tls.sni, &spec.server) {
        (Some(sni), _) => sni.clone(),
        (None, TargetAddr::Domain(d, _)) => d.clone(),
        (None, TargetAddr::Ip(a)) => a.ip().to_string(),
    };
    let stream = oryn_tls::connect_proxy(stream, &host, &tls).await?;
    // Reality 服务端（Xray / sing-box）握手时不返回 ALPN，gRPC / h2 / XHTTP 仍直接在其上跑 HTTP/2，
    // 所以 Reality 下不能以「对端协商了 h2」作为前提。
    let reality = tls.reality.is_some();
    let negotiated_h2 = reality || oryn_tls::negotiated_alpn(&stream).as_deref() == Some(b"h2");
    if matches!(
        spec.transport,
        TransportSpec::Grpc(_) | TransportSpec::H2(_) | TransportSpec::XHttp(_)
    ) && !negotiated_h2
    {
        return Err(io::Error::other("HTTP/2 peer did not negotiate h2"));
    }
    Ok((Box::new(stream), negotiated_h2))
}

impl StreamProxyOutbound {
    fn authority(&self) -> String {
        match &self.spec.server {
            TargetAddr::Ip(a) => a.to_string(),
            TargetAddr::Domain(d, p) => format!("{d}:{p}"),
        }
    }

    /// Transport 层把初始协议首部放到 TCP、WebSocket 或 HTTPUpgrade 中；gRPC 经连接池。
    async fn apply_transport(
        &self,
        mut stream: BoxStream,
        initial: &[u8],
    ) -> io::Result<BoxStream> {
        match &self.spec.transport {
            TransportSpec::Tcp => {
                stream.write_all(initial).await?;
                stream.flush().await?;
                Ok(stream)
            }
            TransportSpec::Ws(ws) => {
                let authority = self.authority();
                // Trojan 服务端常以一次 Read 读取整个请求头（56 字节密码 + CRLF + 命令 + 地址 + CRLF，
                // 最长 320 字节）；early data 装不下整个头时禁用，避免把头切到 HTTP 与 WS 两个读取边界。
                let mut ws = ws.clone();
                if matches!(self.protocol, StreamProtocol::Trojan(_)) && ws.max_early_data < 320 {
                    ws.max_early_data = 0;
                }
                Ok(Box::new(
                    oryn_transport::connect(stream, &authority, &ws, initial).await?,
                ))
            }
            TransportSpec::HttpUpgrade(spec) => {
                let authority = self.authority();
                Ok(Box::new(
                    oryn_transport::connect_http_upgrade(stream, &authority, spec, initial).await?,
                ))
            }
            TransportSpec::Http(spec) => {
                let authority = self.authority();
                Ok(Box::new(
                    oryn_transport::connect_http(stream, &authority, spec, initial).await?,
                ))
            }
            TransportSpec::Grpc(_)
            | TransportSpec::H2(_)
            | TransportSpec::XHttp(_)
            | TransportSpec::Kcp(_)
            | TransportSpec::Mekya(_)
            | TransportSpec::Quic => Err(io::Error::other(
                "this transport is opened through its own connection pool",
            )),
        }
    }
}
#[async_trait]
impl Outbound for StreamProxyOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        match self.protocol {
            StreamProtocol::Trojan(_) => "trojan",
            StreamProtocol::Vless(_) => "vless",
            StreamProtocol::Vmess(_) => "vmess",
        }
    }
    #[cfg(feature = "quic")]
    fn session_control(&self) -> Option<Arc<dyn crate::SessionControl>> {
        self.quic.as_ref().map(|q| {
            Arc::new(crate::QuicControl(q.client.clone())) as Arc<dyn crate::SessionControl>
        })
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        self.open(target, false).await
    }
    async fn bind_udp(&self, first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.spec.udp {
            return Err(unsupported("UDP is not enabled for this proxy"));
        }
        let magic = TargetAddr::Domain("sp.packet-addr.v2fly.arpa".into(), 0);
        let target = if matches!(self.spec.packet_encoding, PacketEncoding::PacketAddr) {
            &magic
        } else {
            first_target
        };
        let s = self.open(target, true).await?;
        if matches!(self.spec.packet_encoding, PacketEncoding::Xudp) || self.spec.vision {
            return Ok(Box::new(crate::packet_encoding::XudpConn::new(
                s,
                first_target.clone(),
            )));
        }
        let (read, write) = tokio::io::split(s);
        if matches!(self.protocol, StreamProtocol::Vmess(_)) {
            let conn: Box<dyn PacketConn> = Box::new(VmessPacketConn {
                read: Mutex::new(read),
                write: Mutex::new(write),
                target: target.clone(),
                scratch: crate::RecvScratch::new(),
            });
            return Ok(
                if matches!(self.spec.packet_encoding, PacketEncoding::PacketAddr) {
                    Box::new(crate::packet_encoding::PacketAddrConn {
                        inner: conn,
                        magic,
                        scratch: crate::RecvScratch::new(),
                    })
                } else {
                    conn
                },
            );
        }
        let conn: Box<dyn PacketConn> = Box::new(StreamPacketConn {
            read: Mutex::new(PacketReader {
                stream: read,
                pending: Vec::new(),
                failed: false,
            }),
            write: Mutex::new(crate::FrameWriter::new(write)),
            target: target.clone(),
            trojan: matches!(self.protocol, StreamProtocol::Trojan(_)),
        });
        Ok(
            if matches!(self.spec.packet_encoding, PacketEncoding::PacketAddr) {
                Box::new(crate::packet_encoding::PacketAddrConn {
                    inner: conn,
                    magic,
                    scratch: crate::RecvScratch::new(),
                })
            } else {
                conn
            },
        )
    }
}
struct PacketReader {
    stream: ReadHalf<BoxStream>,
    pending: Vec<u8>,
    failed: bool,
}
struct StreamPacketConn {
    read: Mutex<PacketReader>,
    write: Mutex<crate::FrameWriter<WriteHalf<BoxStream>>>,
    target: TargetAddr,
    trojan: bool,
}
impl PacketReader {
    // select! 可能取消 recv_from，必须把已读取的字节留在连接内，不能用局部 read_exact。
    async fn packet(
        &mut self,
        buf: &mut [u8],
        trojan: bool,
        target: &TargetAddr,
    ) -> io::Result<(usize, TargetAddr)> {
        loop {
            if self.failed {
                return Err(io::Error::other("UDP stream is closed"));
            }
            let header = if trojan {
                socks5::decode_addr(&self.pending).and_then(|(a, n)| {
                    (self.pending.len() >= n + 4).then(|| {
                        (
                            a,
                            n + 4,
                            u16::from_be_bytes([self.pending[n], self.pending[n + 1]]) as usize,
                        )
                    })
                })
            } else if self.pending.len() >= 2 {
                Some((
                    target.clone(),
                    2,
                    u16::from_be_bytes([self.pending[0], self.pending[1]]) as usize,
                ))
            } else {
                None
            };
            if let Some((addr, header, len)) = header {
                if trojan && self.pending[header - 2..header] != *b"\r\n" {
                    self.failed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Trojan UDP invalid delimiter",
                    ));
                }
                if self.pending.len() >= header + len {
                    let n = crate::copy_datagram(
                        &self.pending[header..header + len],
                        buf,
                        "Trojan/VLESS",
                    );
                    self.pending.drain(..header + len);
                    return Ok((n, addr));
                }
            }
            // 合法最大帧：地址 259（1 + 1 + 255 + 2）+ 长度 2 + CRLF 2 + 载荷 65535
            const MAX_FRAME: usize = 65535 + 263;
            if self.pending.len() >= MAX_FRAME {
                self.failed = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP stream frame too large or invalid address",
                ));
            }
            let mut scratch = [0; 4096];
            let limit = scratch.len().min(MAX_FRAME - self.pending.len());
            let n = self.stream.read(&mut scratch[..limit]).await?;
            if n == 0 {
                self.failed = true;
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "UDP stream closed",
                ));
            }
            self.pending.extend_from_slice(&scratch[..n]);
        }
    }
}
#[async_trait]
impl PacketConn for StreamPacketConn {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        if !self.trojan && target != &self.target {
            return Err(unsupported(
                "VLESS UDP connection is bound to its first target",
            ));
        }
        let frame = if self.trojan {
            trojan::encode_udp(target, buf)?
        } else {
            vless::encode_udp(buf)?
        };
        self.write.lock().await.send(frame).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        self.read
            .lock()
            .await
            .packet(buf, self.trojan, &self.target)
            .await
    }
}

struct VmessPacketConn {
    read: Mutex<ReadHalf<BoxStream>>,
    write: Mutex<WriteHalf<BoxStream>>,
    target: TargetAddr,
    scratch: crate::RecvScratch,
}
#[async_trait]
impl PacketConn for VmessPacketConn {
    async fn send_to(&self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        if target != &self.target {
            return Err(unsupported(
                "VMess UDP connection is bound to its first target",
            ));
        }
        if data.len() > 15000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess UDP payload exceeds 15000 bytes",
            ));
        }
        let mut write = self.write.lock().await;
        write.write_all(data).await?;
        write.flush().await
    }
    async fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut data = self.scratch.take();
        let n = self.read.lock().await.read(&mut data).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let n = crate::copy_datagram(&data[..n], out, "VMess");
        Ok((n, self.target.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn vmess_udp_declared_limit_rejects_before_writing_and_keeps_connection() {
        let (stream, mut peer) = tokio::io::duplex(32768);
        let (read, write) = tokio::io::split(Box::new(stream) as BoxStream);
        let target = TargetAddr::Domain("example.test".into(), 53);
        let conn = VmessPacketConn {
            read: Mutex::new(read),
            write: Mutex::new(write),
            target: target.clone(),
            scratch: crate::RecvScratch::new(),
        };
        let err = conn.send_to(&vec![0x11; 15001], &target).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let valid = vec![0x22; 15000];
        conn.send_to(&valid, &target).await.unwrap();
        let mut received = vec![0; valid.len()];
        peer.read_exact(&mut received).await.unwrap();
        // 替身接在协议流边界：被拒包不得触及底层，后续合法包仍然可发送。
        assert_eq!(received, valid);
        conn.send_to(b"next", &target).await.unwrap();
        let mut next = [0; 4];
        peer.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"next");
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn quic_rejects_ech_before_resolving_or_dialing() {
        struct NoDns;
        #[async_trait]
        impl Resolver for NoDns {
            async fn resolve(&self, _: &str) -> io::Result<Vec<std::net::IpAddr>> {
                panic!("unsupported ECH must be rejected before DNS");
            }
        }
        let config = oryn_config::parse_config("proxies:\n  - {name: test, type: vless, server: example.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, network: quic}").unwrap();
        let (mut spec, uuid) = config
            .outbounds
            .iter()
            .find_map(|o| match &o.kind {
                oryn_config::OutboundKind::Vless { stream, uuid } => Some((stream.clone(), *uuid)),
                _ => None,
            })
            .unwrap();
        let SecuritySpec::Tls(tls) = &mut spec.security else {
            panic!()
        };
        // 模拟绕过 YAML 解析、直接构造 RuntimeConfig 的调用方。
        tls.ech = Some(oryn_config::EchSpec {
            config: vec![1, 2, 3, 4],
        });
        let out = StreamProxyOutbound::new(
            "test".into(),
            spec,
            StreamProtocol::Vless(uuid),
            Arc::new(crate::DirectDialer::new(Arc::new(NoDns))),
            Arc::new(oryn_udp::UdpFactory),
            Arc::new(NoDns),
        );
        let result = out.open_quic(out.quic.as_ref().unwrap(), b"initial").await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("ECH ignored"),
        };
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("ECH"));
    }

    #[tokio::test]
    async fn udp_writer_survives_partial_write_cancellation() {
        use std::future::Future;
        use std::time::Duration;

        for trojan in [false, true] {
            let target = TargetAddr::Domain("example.test".into(), 53);
            // 只容纳四字节，保证首帧写出一部分之后遇到背压。
            let (stream, mut server) = tokio::io::duplex(4);
            let (read, write) = tokio::io::split(Box::new(stream) as BoxStream);
            let conn = Arc::new(StreamPacketConn {
                read: Mutex::new(PacketReader {
                    stream: read,
                    pending: Vec::new(),
                    failed: false,
                }),
                write: Mutex::new(crate::FrameWriter::new(write)),
                target: target.clone(),
                trojan,
            });
            let first = [0x61; 32];
            let mut sending = Box::pin(conn.send_to(&first, &target));
            std::future::poll_fn(|cx| {
                assert!(sending.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(sending);

            let encode = |data: &[u8]| {
                if trojan {
                    trojan::encode_udp(&target, data).unwrap()
                } else {
                    vless::encode_udp(data).unwrap()
                }
            };
            let mut expected = encode(&first);
            expected.extend_from_slice(&encode(b"next"));
            let mut received = vec![0; expected.len()];
            server.read_exact(&mut received[..4]).await.unwrap();
            assert_eq!(&received[..4], &expected[..4]);
            let result = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::try_join!(
                    conn.send_to(b"next", &target),
                    server.read_exact(&mut received[4..]),
                )
            })
            .await;
            assert!(
                result.is_ok(),
                "trojan={trojan}: cancelled frame tail was lost"
            );
            result.unwrap().unwrap();
            assert_eq!(
                received, expected,
                "trojan={trojan}: frame boundary corrupted"
            );
        }
    }

    #[tokio::test]
    async fn udp_reader_survives_cancellation_and_small_buffers() {
        let target = TargetAddr::Domain("example.test".into(), 53);
        for trojan in [false, true] {
            let (stream, mut server) = tokio::io::duplex(1024);
            let (stream, _) = tokio::io::split(Box::new(stream) as BoxStream);
            let mut reader = PacketReader {
                stream,
                pending: Vec::new(),
                failed: false,
            };
            let frame = if trojan {
                oryn_protocol::trojan::encode_udp(&target, b"abcdef").unwrap()
            } else {
                vless::encode_udp(b"abcdef").unwrap()
            };
            server.write_all(&frame[..2]).await.unwrap();
            let mut buf = [0; 3];
            assert!(tokio::time::timeout(
                std::time::Duration::from_millis(10),
                reader.packet(&mut buf, trojan, &target)
            )
            .await
            .is_err());
            assert_eq!(reader.pending, &frame[..2]);
            server.write_all(&frame[2..]).await.unwrap();
            server.write_all(&frame).await.unwrap();
            assert_eq!(
                reader.packet(&mut buf, trojan, &target).await.unwrap(),
                (3, target.clone())
            );
            assert_eq!(&buf, b"abc");
            assert_eq!(reader.packet(&mut buf, trojan, &target).await.unwrap().0, 3);
            assert_eq!(&buf, b"abc");
        }
    }
}
