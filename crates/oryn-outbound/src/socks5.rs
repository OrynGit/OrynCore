use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use oryn_config::{ProxyAuth, TargetAddr, TlsSpec};
use oryn_protocol::socks5;
use oryn_udp::{DatagramFactory, Datagrams};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::{
    resolve_target, unsupported, with_timeout, wrap_tls, BoxStream, Dialer, Outbound, PacketConn,
    Resolver,
};

pub struct Socks5Outbound {
    tag: String,
    server: TargetAddr,
    auth: Option<ProxyAuth>,
    udp: bool,
    tls: Option<TlsSpec>,
    dialer: Arc<dyn Dialer>,
    resolver: Arc<dyn Resolver>,
    /// UDP 中继的数据报通道：直连或经由 `dialer-proxy`。
    datagrams: Arc<dyn DatagramFactory>,
}

impl Socks5Outbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: String,
        server: TargetAddr,
        auth: Option<ProxyAuth>,
        udp: bool,
        tls: Option<TlsSpec>,
        dialer: Arc<dyn Dialer>,
        resolver: Arc<dyn Resolver>,
        datagrams: Arc<dyn DatagramFactory>,
    ) -> Self {
        Socks5Outbound {
            tag,
            server,
            auth,
            udp,
            tls,
            dialer,
            resolver,
            datagrams,
        }
    }

    fn auth(&self) -> Option<(&str, &str)> {
        self.auth
            .as_ref()
            .map(|a| (a.username.as_str(), a.password.as_str()))
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "socks5"
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        with_timeout(
            async {
                let stream = self.dialer.dial_tcp(&self.server).await?;
                let mut stream = wrap_tls(stream, &self.tls, &self.server).await?;
                socks5::handshake(&mut stream, self.auth()).await?;
                socks5::connect(&mut stream, target).await?;
                Ok(stream)
            },
            "SOCKS5 handshake",
        )
        .await
    }

    async fn bind_udp(&self, _first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.udp {
            return Err(unsupported("UDP is not enabled for this SOCKS5 proxy"));
        }
        // 先自行解析服务器地址，UDP ASSOCIATE 回复未指定地址时需要用到服务器 IP
        let server = resolve_target(&*self.resolver, &self.server).await?[0];
        let (control, relay) = with_timeout(
            async {
                let control = self.dialer.dial_tcp(&TargetAddr::Ip(server)).await?;
                let mut control = wrap_tls(control, &self.tls, &self.server).await?;
                socks5::handshake(&mut control, self.auth()).await?;
                let relay = socks5::udp_associate(&mut control, server.ip()).await?;
                Ok((control, relay))
            },
            "SOCKS5 UDP handshake",
        )
        .await?;
        let socket = self.datagrams.bind(relay).await?;
        // 控制连接必须保持打开，关联才有效：后台读它，断开（EOF / 错误）即让 recv_from 报错，
        // 否则 UDP 黑洞无法与「没有流量」区分。服务端不会在控制连接上再发数据，读到的字节直接丢弃。
        let closed = CancellationToken::new();
        let watcher = tokio::spawn({
            let closed = closed.clone();
            let mut control = control;
            async move {
                let mut scratch = [0u8; 64];
                while matches!(control.read(&mut scratch).await, Ok(n) if n > 0) {}
                closed.cancel();
            }
        });
        Ok(Box::new(SocksPacketConn {
            socket,
            relay,
            closed,
            watcher,
        }))
    }
}

fn control_closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "SOCKS5 UDP association control connection closed",
    )
}

/// SOCKS5 UDP 关联。
struct SocksPacketConn {
    socket: Arc<dyn Datagrams>,
    relay: SocketAddr,
    /// 控制连接已断开。
    closed: CancellationToken,
    /// 持有控制连接的后台任务；Drop 时 abort，控制连接随之关闭，服务端结束关联。
    watcher: tokio::task::JoinHandle<()>,
}

impl Drop for SocksPacketConn {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}

#[async_trait]
impl PacketConn for SocksPacketConn {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        if self.closed.is_cancelled() {
            return Err(control_closed());
        }
        let pkt = socks5::encode_udp(target, buf)?;
        self.socket.try_send_to(&pkt, self.relay)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut raw = vec![0u8; buf.len() + 262];
        loop {
            let (n, from) = tokio::select! {
                r = self.socket.recv_from(&mut raw) => r?,
                _ = self.closed.cancelled() => return Err(control_closed()),
            };
            // 中继按 RFC 1928 从 BND.ADDR:BND.PORT 回包；同时比对端口，同主机其他服务的包不收
            if from != self.relay {
                continue;
            }
            if let Some((addr, payload)) = socks5::decode_udp(&raw[..n]) {
                let len = crate::copy_datagram(payload, buf, "SOCKS5");
                return Ok((len, addr));
            }
        }
    }
}
