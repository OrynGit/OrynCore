//! ShadowsocksR 出站（`type: ssr`）。
//!
//! 结构与 MetaCubeX/mihomo `adapter/outbound/shadowsocksr.go` 相同（v1.19.32，出处见 Oryn_dev/docs/oryncore/provenance.md）：
//! 写方向 应用数据 → 协议插件 → 流式加密（首包带 IV）→ 混淆 → TCP；读方向相反。UDP 不经过混淆：
//! 地址 + 数据 → 协议插件的包编码 → 流式加密（每包一个 IV）。
//! 第一个写出就是目的地址（协议插件把认证信息和地址一起打包），所以混淆的握手在连接时完成。

mod obfs;
mod protocol;
mod util;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use oryn_config::{SsrSpec, TargetAddr};
use oryn_udp::{DatagramFactory, Datagrams};
use shadowsocks_crypto::v1::Cipher;
use shadowsocks_crypto::CipherKind;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    resolve_target, unsupported, with_timeout, BoxStream, Dialer, Outbound, PacketConn, Resolver,
};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

/// 读写缓冲上限：未解码的密文最多两个协议块（每块小于 8 KiB），解码后的明文按块交出。
const MAX_UNDECODED: usize = 64 * 1024;

pub struct SsrOutbound {
    tag: String,
    server: TargetAddr,
    /// None 表示 `none`（不加密）。
    kind: Option<CipherKind>,
    key: Vec<u8>,
    udp: bool,
    protocol: Arc<protocol::Protocol>,
    obfs: obfs::Obfs,
    dialer: Arc<dyn Dialer>,
    resolver: Arc<dyn Resolver>,
    datagrams: Arc<dyn DatagramFactory>,
}

impl SsrOutbound {
    pub fn new(
        tag: String,
        spec: &SsrSpec,
        dialer: Arc<dyn Dialer>,
        resolver: Arc<dyn Resolver>,
        datagrams: Arc<dyn DatagramFactory>,
    ) -> io::Result<Self> {
        let (kind, key) = if spec.cipher == "none" {
            (None, util::kdf(spec.password.as_bytes(), 16))
        } else {
            let kind: CipherKind = spec.cipher.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported ShadowsocksR cipher",
                )
            })?;
            if !kind.is_stream() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ShadowsocksR needs a stream cipher",
                ));
            }
            (
                Some(kind),
                util::kdf(spec.password.as_bytes(), kind.key_len()),
            )
        };
        let obfs_kind = obfs::Kind::parse(&spec.obfs).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "unsupported ShadowsocksR obfs")
        })?;
        let protocol_kind = protocol::Kind::parse(&spec.protocol).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported ShadowsocksR protocol",
            )
        })?;
        let (host, port) = match &spec.server {
            TargetAddr::Domain(d, p) => (d.clone(), *p),
            TargetAddr::Ip(a) => (a.ip().to_string(), a.port()),
        };
        let mut client_id = [0u8; 32];
        client_id.copy_from_slice(&util::random_bytes(32));
        Ok(Self {
            tag,
            server: spec.server.clone(),
            kind,
            udp: spec.udp,
            protocol: Arc::new(protocol::Protocol::new(
                protocol_kind,
                key.clone(),
                &spec.protocol_param,
                obfs_kind.overhead(),
            )),
            obfs: obfs::Obfs {
                kind: obfs_kind,
                host,
                port,
                key: key.clone(),
                iv_len: kind.map_or(0, |k| k.iv_len()),
                param: spec.obfs_param.clone(),
                client_id,
            },
            key,
            dialer,
            resolver,
            datagrams,
        })
    }

    fn iv_len(&self) -> usize {
        self.kind.map_or(0, |k| k.iv_len())
    }

    fn cipher(&self, iv: &[u8]) -> Option<Cipher> {
        self.kind.map(|k| Cipher::new(k, &self.key, iv))
    }
}

/// SOCKS5 地址（ATYP + 地址 + 端口）。
fn socks_addr(target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32);
    oryn_protocol::socks5::encode_addr(target, &mut out)?;
    Ok(out)
}

fn parse_socks_addr(data: &[u8]) -> io::Result<(TargetAddr, usize)> {
    let bad = || invalid("ShadowsocksR bad address");
    let atyp = *data.first().ok_or_else(bad)?;
    // 服务端回包只用 1 / 3 / 4；高位标志（Python 版的 0x10 等）只出现在客户端请求里。
    // 不做掩码：origin / auth_sha1_v4 的 UDP 没有认证，伪造的首字节必须被拒，而不是被错误解析。
    match atyp {
        1 => {
            let b = data.get(1..7).ok_or_else(bad)?;
            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Ok((
                TargetAddr::Ip(SocketAddr::new(ip.into(), u16::from_be_bytes([b[4], b[5]]))),
                7,
            ))
        }
        4 => {
            let b = data.get(1..19).ok_or_else(bad)?;
            let ip: [u8; 16] = b[..16].try_into().unwrap();
            let ip = std::net::Ipv6Addr::from(ip);
            Ok((
                TargetAddr::Ip(SocketAddr::new(
                    ip.into(),
                    u16::from_be_bytes([b[16], b[17]]),
                )),
                19,
            ))
        }
        3 => {
            let n = *data.get(1).ok_or_else(bad)? as usize;
            let b = data.get(2..2 + n + 2).ok_or_else(bad)?;
            let host = String::from_utf8_lossy(&b[..n]).into_owned();
            Ok((
                TargetAddr::Domain(host, u16::from_be_bytes([b[n], b[n + 1]])),
                2 + n + 2,
            ))
        }
        _ => Err(bad()),
    }
}

#[async_trait]
impl Outbound for SsrOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "ssr"
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let addr = socks_addr(target)?;
        with_timeout(
            async {
                let io = self.dialer.dial_tcp(&self.server).await?;
                let iv = util::random_bytes(self.iv_len());
                let mut enc = self.cipher(&iv);
                let mut codec = self.protocol.stream(&iv);
                let mut first = Vec::new();
                codec.encode(&addr, &mut first);
                if let Some(enc) = &mut enc {
                    enc.encrypt_packet(&mut first);
                }
                let mut wire = iv;
                wire.extend_from_slice(&first);
                let io = self.obfs.connect(io, wire).await?;
                Ok(Box::new(SsrStream {
                    io,
                    enc,
                    dec: None,
                    kind: self.kind,
                    key: self.key.clone(),
                    iv_len: self.iv_len(),
                    read_iv: Vec::new(),
                    codec,
                    undecoded: Vec::new(),
                    decoded: Vec::new(),
                    decoded_pos: 0,
                    out: Vec::new(),
                    out_pos: 0,
                    failed: false,
                }) as BoxStream)
            },
            "ShadowsocksR handshake",
        )
        .await
    }

    async fn bind_udp(&self, first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.udp {
            return Err(unsupported(
                "UDP is not enabled for this ShadowsocksR proxy",
            ));
        }
        let _ = first_target;
        let server = with_timeout(
            resolve_target(&*self.resolver, &self.server),
            "ShadowsocksR UDP resolve",
        )
        .await?[0];
        let socket = self.datagrams.bind(server).await?;
        Ok(Box::new(SsrPacket {
            socket,
            server,
            crypto: SsrPacketCrypto {
                kind: self.kind,
                key: self.key.clone(),
                iv_len: self.iv_len(),
            },
            protocol: self.protocol.clone(),
            scratch: crate::RecvScratch::new(),
        }))
    }
}

struct SsrStream {
    io: BoxStream,
    enc: Option<Cipher>,
    dec: Option<Cipher>,
    kind: Option<CipherKind>,
    key: Vec<u8>,
    iv_len: usize,
    read_iv: Vec<u8>,
    codec: Box<dyn protocol::StreamCodec>,
    undecoded: Vec<u8>,
    decoded: Vec<u8>,
    decoded_pos: usize,
    out: Vec<u8>,
    out_pos: usize,
    failed: bool,
}

impl SsrStream {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(invalid("ShadowsocksR stream failed")));
        }
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl SsrStream {
    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self;
        loop {
            if this.decoded_pos < this.decoded.len() {
                let n = (this.decoded.len() - this.decoded_pos).min(out.remaining());
                out.put_slice(&this.decoded[this.decoded_pos..this.decoded_pos + n]);
                this.decoded_pos += n;
                if this.decoded_pos == this.decoded.len() {
                    this.decoded.clear();
                    this.decoded_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            // 直接读进待解码缓冲的尾部并原地解密，不经栈缓冲中转、不另分配
            let start = this.undecoded.len();
            this.undecoded.resize(start + 8192, 0);
            let mut rb = ReadBuf::new(&mut this.undecoded[start..]);
            let polled = Pin::new(&mut this.io).poll_read(cx, &mut rb);
            let n = rb.filled().len();
            this.undecoded.truncate(start + n);
            ready!(polled)?;
            if n == 0 {
                if !this.undecoded.is_empty()
                    || (!this.read_iv.is_empty() && this.read_iv.len() < this.iv_len)
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated ShadowsocksR stream",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
            // 服务端的 IV 在下行最前面
            if let (None, Some(kind)) = (&this.dec, this.kind) {
                let need = this.iv_len - this.read_iv.len();
                let take = need.min(n);
                this.read_iv
                    .extend_from_slice(&this.undecoded[start..start + take]);
                this.undecoded.drain(start..start + take);
                if this.read_iv.len() < this.iv_len {
                    continue;
                }
                this.dec = Some(Cipher::new(kind, &this.key, &this.read_iv));
            }
            if let Some(dec) = &mut this.dec {
                // 流式加密没有认证，解密总是成功
                let _ = dec.decrypt_packet(&mut this.undecoded[start..]);
            }
            if this.undecoded.len() > MAX_UNDECODED {
                return Poll::Ready(Err(invalid("ShadowsocksR undecoded buffer overflow")));
            }
            this.codec.decode(&mut this.undecoded, &mut this.decoded)?;
        }
    }
}

impl AsyncRead for SsrStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.failed {
            return Poll::Ready(Err(invalid("ShadowsocksR stream failed")));
        }
        // `poll_write` 可能把尚未写完的密文留在 `out`：读之前顺带推进，
        // 「write_all 后不 flush 直接 read 等响应」的调用方才不会永久等待。
        if let Poll::Ready(Err(e)) = self.poll_drain(cx) {
            self.failed = true;
            return Poll::Ready(Err(e));
        }
        let result = self.poll_read_inner(cx, out);
        // 协议 codec 在错误后可能切换 raw 模式；认证失败后绝不能再继续解码。
        if matches!(result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }
}

impl AsyncWrite for SsrStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = data.len().min(16 * 1024);
        this.codec.encode(&data[..take], &mut this.out);
        if let Some(enc) = &mut this.enc {
            enc.encrypt_packet(&mut this.out);
        }
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(take))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

struct SsrPacketCrypto {
    kind: Option<CipherKind>,
    key: Vec<u8>,
    iv_len: usize,
}

struct SsrPacket {
    socket: Arc<dyn Datagrams>,
    server: SocketAddr,
    crypto: SsrPacketCrypto,
    protocol: Arc<protocol::Protocol>,
    scratch: crate::RecvScratch,
}

#[async_trait]
impl PacketConn for SsrPacket {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        if buf.len() > 65507 - 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ShadowsocksR UDP payload too large",
            ));
        }
        let mut packet = socks_addr(target)?;
        packet.extend_from_slice(buf);
        let mut packet = self.protocol.encode_packet(&packet);
        let iv = util::random_bytes(self.crypto.iv_len);
        if let Some(kind) = self.crypto.kind {
            Cipher::new(kind, &self.crypto.key, &iv).encrypt_packet(&mut packet);
        }
        let mut wire = iv;
        wire.extend_from_slice(&packet);
        self.socket.try_send_to(&wire, self.server)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut packet = self.scratch.take();
        loop {
            let (n, from) = self.socket.recv_from(&mut packet).await?;
            if from != self.server || n < self.crypto.iv_len {
                continue;
            }
            let (iv, body) = packet[..n].split_at_mut(self.crypto.iv_len);
            if let Some(kind) = self.crypto.kind {
                let _ = Cipher::new(kind, &self.crypto.key, iv).decrypt_packet(body);
            }
            let Ok(decoded) = self.protocol.decode_packet(body) else {
                continue;
            };
            let Ok((addr, used)) = parse_socks_addr(&decoded) else {
                continue;
            };
            let payload = &decoded[used..];
            let m = crate::copy_datagram(payload, buf, "ShadowsocksR");
            return Ok((m, addr));
        }
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod audit_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_addresses_roundtrip() {
        for target in [
            TargetAddr::Ip("1.2.3.4:53".parse().unwrap()),
            TargetAddr::Ip("[::1]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 80),
        ] {
            let mut wire = socks_addr(&target).unwrap();
            wire.extend_from_slice(b"payload");
            let (addr, used) = parse_socks_addr(&wire).unwrap();
            assert_eq!(addr, target);
            assert_eq!(&wire[used..], b"payload");
        }
        assert!(parse_socks_addr(&[3, 10, b'a']).is_err());
    }
}
