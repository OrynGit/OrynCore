//! ShadowTLS v1 / v2 / v3。v3 的认证线格式改写自 SagerNet/sing-shadowtls v3_client.go / v3_conn.go；
//! v1 / v2 改写自 client.go、v2_client.go、v2_conn.go、v2_hash.go。
//! commit fcd445d33c1170763222c9891904fb352a6bf277（v0.2.1-0.20250503051639-fcd445d33c11）。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncWriteExt, ReadBuf};
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn context(password: &str, seed: &[u8]) -> hmac::Context {
    let mut h = hmac::Context::with_key(&hmac::Key::new(
        hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        password.as_bytes(),
    ));
    h.update(seed);
    h
}
fn tag(h: &hmac::Context) -> [u8; 4] {
    h.clone().sign().as_ref()[..4].try_into().unwrap()
}
fn equal(a: &[u8], b: &[u8; 4]) -> bool {
    a.len() == 4 && a.iter().zip(b).fold(0, |d, (a, b)| d | (*a ^ b)) == 0
}
#[derive(Debug)]
struct Hello {
    password: String,
}
impl rustls::crypto::OrynClientHello for Hello {
    fn customize(
        &self,
        body: &[u8],
        _: Option<&dyn rustls::crypto::ActiveKeyExchange>,
        retry: bool,
    ) -> Result<Vec<u8>, rustls::Error> {
        if retry || body.len() < 67 || body[34] != 32 {
            return Err(rustls::Error::General(
                "ShadowTLS requires TLS 1.3 session ID without retry".into(),
            ));
        }
        let mut body = body.to_vec();
        SystemRandom::new()
            .fill(&mut body[35..63])
            .map_err(|_| rustls::Error::General("random source failed".into()))?;
        body[63..67].fill(0);
        let mut wire = vec![1];
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        wire.extend_from_slice(&body);
        let mut h = context(&self.password, &[]);
        h.update(&wire);
        body[63..67].copy_from_slice(&tag(&h));
        Ok(body)
    }
}
struct Records<S> {
    stream: S,
    wire: Vec<u8>,
    out: Vec<u8>,
    position: usize,
    password: String,
    random: Option<[u8; 32]>,
    hash: Option<hmac::Context>,
    xor: [u8; 32],
    authorized: bool,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Records<S> {
    fn record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            let need = if self.wire.len() < 5 {
                5
            } else {
                let n = u16::from_be_bytes(self.wire[3..5].try_into().unwrap()) as usize;
                if n > 18436 {
                    return Poll::Ready(Err(invalid("ShadowTLS record exceeds limit")));
                }
                5 + n
            };
            if self.wire.len() == need && need >= 5 {
                return Poll::Ready(Ok(true));
            }
            let mut scratch = [0; 4096];
            let n = (need - self.wire.len()).min(scratch.len());
            let mut b = ReadBuf::new(&mut scratch[..n]);
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut b))?;
            if b.filled().is_empty() {
                return if self.wire.is_empty() {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Ready(Err(invalid("truncated ShadowTLS record")))
                };
            }
            self.wire.extend_from_slice(b.filled());
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Records<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if b.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.position == self.out.len() {
            self.out.clear();
            self.position = 0;
            if !ready!(self.record(cx))? {
                return Poll::Ready(Ok(()));
            }
            let mut wire = std::mem::take(&mut self.wire);
            if wire[0] == 22 && wire.len() >= 43 && wire[5] == 2 {
                let random: [u8; 32] = wire[11..43].try_into().unwrap();
                self.hash = Some(context(&self.password, &random));
                self.xor = ring::digest::digest(
                    &ring::digest::SHA256,
                    &[self.password.as_bytes(), &random].concat(),
                )
                .as_ref()
                .try_into()
                .unwrap();
                self.random = Some(random);
            }
            if wire[0] == 23 {
                self.authorized = false;
                if wire.len() > 9 {
                    if let Some(h) = &mut self.hash {
                        h.update(&wire[9..]);
                        let expected = tag(h);
                        if equal(&wire[5..9], &expected) {
                            for (i, b) in wire[9..].iter_mut().enumerate() {
                                *b ^= self.xor[i % 32];
                            }
                            wire.drain(5..9);
                            let len = (wire.len() - 5) as u16;
                            wire[3..5].copy_from_slice(&len.to_be_bytes());
                            self.authorized = true;
                        }
                    }
                }
            }
            self.out = wire;
        }
        let n = b.remaining().min(self.out.len() - self.position);
        b.put_slice(&self.out[self.position..self.position + n]);
        self.position += n;
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Records<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    spec: &oryn_config::ShadowTlsSpec,
) -> io::Result<Verified<S>> {
    let alpn: Vec<&[u8]> = spec.alpn.iter().map(|a| a.as_bytes()).collect();
    let mut config = (*cached(&alpn, spec.skip_cert_verify, Versions::Tls13)?).clone();
    config.resumption = rustls::client::Resumption::disabled();
    config.oryn_client_hello = Some(Arc::new(Hello {
        password: spec.password.clone(),
    }));
    let wire = Records {
        stream,
        wire: Vec::new(),
        out: Vec::new(),
        position: 0,
        password: spec.password.clone(),
        random: None,
        hash: None,
        xor: [0; 32],
        authorized: false,
    };
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name(&spec.host)?, wire)
        .await?;
    tls.flush().await?;
    let (wire, connection) = tls.into_inner();
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || !wire.authorized
        || wire.position != wire.out.len()
    {
        return Err(invalid("ShadowTLS handshake was not authenticated"));
    }
    let random = wire
        .random
        .ok_or_else(|| invalid("ShadowTLS missing server random"))?;
    Ok(Verified {
        stream: wire.stream,
        read: context(&spec.password, &[random.as_slice(), b"S"].concat()),
        write: context(&spec.password, &[random.as_slice(), b"C"].concat()),
        ignore: wire.hash,
        wire: Vec::new(),
        payload: Vec::new(),
        position: 0,
        pending: Vec::new(),
        written: 0,
        failed: false,
    })
}
pub struct Verified<S> {
    stream: S,
    read: hmac::Context,
    write: hmac::Context,
    ignore: Option<hmac::Context>,
    wire: Vec<u8>,
    payload: Vec<u8>,
    position: usize,
    pending: Vec<u8>,
    written: usize,
    failed: bool,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Verified<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.stream).poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                self.failed = true;
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Verified<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failed {
            return Poll::Ready(Err(invalid("ShadowTLS failed")));
        }
        ready!(self.drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(16384);
        self.write.update(&data[..n]);
        let mac = tag(&self.write);
        self.write.update(&mac);
        self.pending = vec![23, 3, 3];
        self.pending.extend(((n + 4) as u16).to_be_bytes());
        self.pending.extend(mac);
        self.pending.extend_from_slice(&data[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Verified<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.failed {
            return Poll::Ready(Err(invalid("ShadowTLS failed")));
        }
        loop {
            if self.position < self.payload.len() {
                let n = out.remaining().min(self.payload.len() - self.position);
                out.put_slice(&self.payload[self.position..self.position + n]);
                self.position += n;
                return Poll::Ready(Ok(()));
            }
            let need = if self.wire.len() < 5 {
                5
            } else {
                let n = u16::from_be_bytes(self.wire[3..5].try_into().unwrap()) as usize;
                if !(4..=18436).contains(&n) || self.wire[..3] != [23, 3, 3] {
                    self.failed = true;
                    return Poll::Ready(Err(invalid("invalid ShadowTLS record")));
                }
                5 + n
            };
            if self.wire.len() == need {
                let wire = std::mem::take(&mut self.wire);
                if let Some(ignore) = &mut self.ignore {
                    ignore.update(&wire[9..]);
                    if equal(&wire[5..9], &tag(ignore)) {
                        continue;
                    }
                    self.ignore = None;
                }
                self.read.update(&wire[9..]);
                let mac = tag(&self.read);
                if !equal(&wire[5..9], &mac) {
                    self.failed = true;
                    return Poll::Ready(Err(invalid("ShadowTLS record authentication failed")));
                }
                self.read.update(&mac);
                self.payload = wire[9..].to_vec();
                self.position = 0;
                continue;
            }
            let mut scratch = [0; 4096];
            let n = (need - self.wire.len()).min(scratch.len());
            let mut buf = ReadBuf::new(&mut scratch[..n]);
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                if self.wire.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                self.failed = true;
                return Poll::Ready(Err(invalid("truncated ShadowTLS record")));
            }
            self.wire.extend_from_slice(buf.filled());
        }
    }
}

// ---------------------------------------------------------------------------
// v1 / v2
// ---------------------------------------------------------------------------

/// v1 / v2 的握手服务端按 TLS 1.2 工作；握手使用真实的证书校验（除非 skip-cert-verify）。
async fn tls12_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    spec: &oryn_config::ShadowTlsSpec,
) -> io::Result<S> {
    let alpn: Vec<&[u8]> = spec.alpn.iter().map(|a| a.as_bytes()).collect();
    let mut config = (*cached(&alpn, spec.skip_cert_verify, Versions::Tls12)?).clone();
    config.resumption = rustls::client::Resumption::disabled();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name(&spec.host)?, stream)
        .await?;
    let (stream, _) = tls.into_inner();
    Ok(stream)
}

/// v1：TLS 握手完成后，底层连接就是裸的代理流（没有任何记录封装）。
pub async fn connect_v1<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    spec: &oryn_config::ShadowTlsSpec,
) -> io::Result<S> {
    tls12_handshake(stream, spec).await
}

/// 对读到的全部字节做 HMAC-SHA1（密钥为密码）。
struct HashRead<S> {
    stream: S,
    hmac: hmac::Context,
}

impl<S: AsyncRead + Unpin> AsyncRead for HashRead<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        ready!(Pin::new(&mut self.stream).poll_read(cx, out))?;
        let this = &mut *self;
        this.hmac.update(&out.filled()[before..]);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HashRead<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// v2：握手期间读到的全部字节的 HMAC 前 8 字节随第一次写出发给服务端作为认证；
/// 之后双向都是 TLS 应用数据记录（类型 23、版本 TLS 1.2）。
pub async fn connect_v2<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    spec: &oryn_config::ShadowTlsSpec,
) -> io::Result<V2Stream<S>> {
    let hashed = HashRead {
        stream,
        hmac: hmac::Context::with_key(&hmac::Key::new(
            hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            spec.password.as_bytes(),
        )),
    };
    let hashed = tls12_handshake(hashed, spec).await?;
    let sum: [u8; 8] = hashed.hmac.sign().as_ref()[..8].try_into().unwrap();
    Ok(V2Stream {
        stream: hashed.stream,
        sum: Some(sum),
        header: [0; 5],
        header_len: 0,
        remaining: 0,
        pending: Vec::new(),
        written: 0,
        accepted: 0,
    })
}

pub struct V2Stream<S> {
    stream: S,
    /// 还没发出的认证摘要，随第一条记录发送。
    sum: Option<[u8; 8]>,
    header: [u8; 5],
    header_len: usize,
    /// 当前记录还剩多少载荷没读。
    remaining: usize,
    pending: Vec<u8>,
    written: usize,
    /// `pending` 里对应的明文字节数，写完才向调用方确认。
    accepted: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for V2Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.remaining > 0 {
                let limit = out.remaining().min(self.remaining);
                let before = out.filled().len();
                let mut window = ReadBuf::new(out.initialize_unfilled_to(limit));
                ready!(Pin::new(&mut self.stream).poll_read(cx, &mut window))?;
                let got = window.filled().len();
                if got == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                out.set_filled(before + got);
                self.remaining -= got;
                return Poll::Ready(Ok(()));
            }
            // 读记录首部（5 字节）
            let have = self.header_len;
            let mut header = self.header;
            let mut window = ReadBuf::new(&mut header[have..]);
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut window))?;
            let got = window.filled().len();
            if got == 0 {
                return if have == 0 {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            self.header = header;
            self.header_len += got;
            if self.header_len == 5 {
                self.header_len = 0;
                if self.header[0] != 23 {
                    return Poll::Ready(Err(invalid("unexpected ShadowTLS v2 record type")));
                }
                self.remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> V2Stream<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.stream).poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.pending.clear();
        self.written = 0;
        self.accepted = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for V2Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // 第一条记录里认证摘要在载荷最前面
        let prefix = self.sum.take();
        let limit = 16384 - prefix.map_or(0, |_| 8);
        let n = data.len().min(limit);
        let payload_len = n + prefix.map_or(0, |_| 8);
        let mut record = vec![23, 3, 3];
        record.extend_from_slice(&(payload_len as u16).to_be_bytes());
        if let Some(sum) = prefix {
            record.extend_from_slice(&sum);
        }
        record.extend_from_slice(&data[..n]);
        self.pending = record;
        self.accepted = n;
        // 尽量写出；没写完的留在 pending，下一次写出或 flush 继续
        match self.drain(cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            _ => Poll::Ready(Ok(n)),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn reader(stream: tokio::io::DuplexStream) -> Verified<tokio::io::DuplexStream> {
        Verified {
            stream,
            read: context("secret", b"seedS"),
            write: context("secret", b"seedC"),
            ignore: None,
            wire: Vec::new(),
            payload: Vec::new(),
            position: 0,
            pending: Vec::new(),
            written: 0,
            failed: false,
        }
    }
    #[tokio::test]
    async fn authenticated_records_reject_tampering_truncation_and_oversize() {
        for mode in ["valid", "tamper", "truncated", "oversize"] {
            let (stream, mut peer) = tokio::io::duplex(1024);
            let mut client = reader(stream);
            let mut h = context("secret", b"seedS");
            h.update(b"data");
            let mut wire = vec![23, 3, 3, 0, 8];
            wire.extend(tag(&h));
            wire.extend(b"data");
            match mode {
                "tamper" => wire[9] ^= 1,
                "truncated" => wire.truncate(10),
                "oversize" => wire = vec![23, 3, 3, 255, 255],
                _ => {}
            }
            peer.write_all(&wire).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut out = Vec::new();
            let result = client.read_to_end(&mut out).await;
            if mode == "valid" {
                result.unwrap();
                assert_eq!(out, b"data");
            } else {
                assert!(result.is_err(), "{mode}");
            }
        }
    }

    fn v2(stream: tokio::io::DuplexStream) -> V2Stream<tokio::io::DuplexStream> {
        V2Stream {
            stream,
            sum: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            header: [0; 5],
            header_len: 0,
            remaining: 0,
            pending: Vec::new(),
            written: 0,
            accepted: 0,
        }
    }

    #[tokio::test]
    async fn v2_first_record_carries_the_digest_and_records_are_bounded() {
        let (a, mut b) = tokio::io::duplex(1 << 20);
        let mut client = v2(a);
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        let mut first = vec![0; 5 + 8 + 5];
        b.read_exact(&mut first).await.unwrap();
        assert_eq!(&first[..5], &[23, 3, 3, 0, 13]);
        assert_eq!(&first[5..13], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&first[13..], b"hello");
        // 之后的记录没有摘要；超过 16 KiB 拆成多条
        let big = vec![7u8; 40_000];
        client.write_all(&big).await.unwrap();
        client.flush().await.unwrap();
        let mut total = 0;
        while total < big.len() {
            let mut header = [0u8; 5];
            b.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[..3], &[23, 3, 3]);
            let n = u16::from_be_bytes([header[3], header[4]]) as usize;
            assert!(n <= 16384);
            let mut payload = vec![0; n];
            b.read_exact(&mut payload).await.unwrap();
            assert!(payload.iter().all(|x| *x == 7));
            total += n;
        }
        assert_eq!(total, big.len());
    }

    #[tokio::test]
    async fn v2_reads_records_across_arbitrary_boundaries_and_rejects_other_types() {
        let (a, mut b) = tokio::io::duplex(1 << 16);
        let mut client = v2(a);
        let mut wire = Vec::new();
        for part in [&b"abc"[..], b"defgh"] {
            wire.extend_from_slice(&[23, 3, 3]);
            wire.extend_from_slice(&(part.len() as u16).to_be_bytes());
            wire.extend_from_slice(part);
        }
        tokio::spawn(async move {
            for byte in wire {
                b.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
            b.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"abcdefgh");
        let (a, mut b) = tokio::io::duplex(1024);
        let mut client = v2(a);
        b.write_all(&[22, 3, 3, 0, 1, 9]).await.unwrap();
        let mut buf = [0u8; 4];
        assert!(client.read(&mut buf).await.is_err());
    }

    #[tokio::test]
    async fn hash_read_signs_exactly_the_bytes_read() {
        let (a, mut b) = tokio::io::duplex(1024);
        let mut hashed = HashRead {
            stream: a,
            hmac: hmac::Context::with_key(&hmac::Key::new(
                hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                b"pw",
            )),
        };
        b.write_all(b"server flight one").await.unwrap();
        b.write_all(b" and two").await.unwrap();
        let mut got = vec![0; 25];
        hashed.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"server flight one and two");
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, b"pw");
        assert_eq!(
            hashed.hmac.sign().as_ref(),
            hmac::sign(&key, b"server flight one and two").as_ref()
        );
    }
}
