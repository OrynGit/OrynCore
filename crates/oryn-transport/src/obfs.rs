//! simple-obfs 客户端：Shadowsocks 的 `obfs-local` 插件，把 TCP 流伪装成 HTTP 或 TLS 握手。
//!
//! 来源 SagerNet/sing-box `transport/simple-obfs/http.go`、`tls.go`，
//! commit 25a600db24f7680ad9806ce5427bd0ab8afe1114（v1.13.14）；该目录本身修改自
//! Dreamacro/clash `transport/simple-obfs`（Clash，GPL-3.0）。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
//! 改写为有界、可取消读取的 Rust 状态机；出处登记在 Oryn_dev/docs/oryncore/provenance.md。
//!
//! - HTTP：第一次写出把 SS 首包作为请求体，伪装成带 `Upgrade: websocket` 的 GET；第一次读取先跳过响应首部。
//! - TLS：第一次写出把 SS 首包放进 ClientHello 的 session ticket 扩展；之后每次写出是一条 TLS 应用数据记录。
//!   读取时先跳过 ServerHello（96 字节）与 ChangeCipherSpec（6 字节）这两条固定大小的记录，之后逐条解记录。

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::random_bytes;

/// 响应首部上限，超过视为不是 simple-obfs 服务端。
const MAX_RESPONSE_HEAD: usize = 16 * 1024;
const TLS_CHUNK: usize = 16 * 1024;
const HTTP_FIRST_CHUNK: usize = 16 * 1024;
const MAX_HTTP_HOST: usize = 16 * 1024;
/// 第一条响应：ServerHello 记录（5 + 91）、ChangeCipherSpec 记录（5 + 1）、下一条记录的类型与版本（3）。
const FIRST_SKIP: usize = 105;
const NEXT_SKIP: usize = 3;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

enum FirstWrite {
    Pending,
    /// 已接纳的请求（首部加有界首包）与写出位置，不再依赖调用者输入。
    Writing {
        request: Vec<u8>,
        pos: usize,
    },
    Done,
    Failed(io::ErrorKind),
}

pub struct HttpObfs<S> {
    stream: S,
    host: String,
    port: u16,
    first: FirstWrite,
    head: Vec<u8>,
    head_done: bool,
    /// 响应首部之后随首部一起读到的数据。
    spill: Vec<u8>,
    spill_pos: usize,
}

impl<S> HttpObfs<S> {
    pub fn new(stream: S, host: &str, port: u16) -> Self {
        Self {
            stream,
            host: host.to_string(),
            port,
            first: FirstWrite::Pending,
            head: Vec::new(),
            head_done: false,
            spill: Vec::new(),
            spill_pos: 0,
        }
    }

    fn request_for(&self, payload: &[u8]) -> Vec<u8> {
        let random = random_bytes(16);
        let key = base64::engine::general_purpose::URL_SAFE.encode(&random);
        let host = if self.port == 80 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let seed = random_bytes(2);
        let mut out = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/7.{}.{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nContent-Length: {}\r\n\r\n",
            seed[0] % 54,
            seed[1] % 2,
            payload.len()
        )
        .into_bytes();
        out.extend_from_slice(payload);
        out
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpObfs<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // 首写已接纳但底层仍背压：读回复前必须推进请求，避免双方互等。
        if !self.head_done {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        loop {
            if self.spill_pos < self.spill.len() {
                let n = buf.remaining().min(self.spill.len() - self.spill_pos);
                let start = self.spill_pos;
                buf.put_slice(&self.spill[start..start + n]);
                self.spill_pos += n;
                return Poll::Ready(Ok(()));
            }
            if self.head_done {
                return Pin::new(&mut self.stream).poll_read(cx, buf);
            }
            let mut chunk = [0u8; 1024];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read))?;
            let n = read.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            let before = self.head.len();
            self.head.extend_from_slice(&chunk[..n]);
            // 从上一次已检查过的位置往前 3 字节开始找，防止结尾标记被读取边界切开
            let from = before.saturating_sub(3);
            if let Some(i) = self.head[from..].windows(4).position(|w| w == b"\r\n\r\n") {
                let end = from + i + 4;
                self.spill = self.head.split_off(end);
                self.head.clear();
                self.spill_pos = 0;
                self.head_done = true;
            } else if self.head.len() > MAX_RESPONSE_HEAD {
                return Poll::Ready(Err(invalid("simple-obfs HTTP response head is too large")));
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> HttpObfs<S> {
    fn fail_write(&mut self, err: io::Error) -> io::Error {
        // 丢弃缓冲并锁存终态，禁止错误后重放部分请求。
        self.first = FirstWrite::Failed(err.kind());
        err
    }

    fn drain_first(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.first {
                FirstWrite::Failed(kind) => return Poll::Ready(Err((*kind).into())),
                FirstWrite::Writing { request, pos } if *pos < request.len() => {
                    match ready!(Pin::new(&mut self.stream).poll_write(cx, &request[*pos..])) {
                        Ok(0) => {
                            return Poll::Ready(Err(
                                self.fail_write(io::ErrorKind::WriteZero.into())
                            ))
                        }
                        Ok(n) => *pos += n,
                        Err(err) => return Poll::Ready(Err(self.fail_write(err))),
                    }
                }
                FirstWrite::Writing { .. } => self.first = FirstWrite::Done,
                _ => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpObfs<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain_first(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if matches!(self.first, FirstWrite::Pending) {
            if self.host.len() > MAX_HTTP_HOST {
                let err = invalid("simple-obfs HTTP host is too large");
                return Poll::Ready(Err(self.fail_write(err)));
            }
            let n = data.len().min(HTTP_FIRST_CHUNK);
            let request = self.request_for(&data[..n]);
            self.first = FirstWrite::Writing { request, pos: 0 };
            // 接纳后即使底层 Pending 也必须确认真实长度，不能让取消重用旧输入。
            return match self.drain_first(cx) {
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                _ => Poll::Ready(Ok(n)),
            };
        }
        match Pin::new(&mut self.stream).poll_write(cx, data) {
            Poll::Ready(Ok(0)) => {
                Poll::Ready(Err(self.fail_write(io::ErrorKind::WriteZero.into())))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(self.fail_write(err))),
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain_first(cx))?;
        match Pin::new(&mut self.stream).poll_flush(cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(self.fail_write(err))),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain_first(cx))?;
        match Pin::new(&mut self.stream).poll_shutdown(cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(self.fail_write(err))),
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

enum ReadState {
    Skip(usize),
    Length([u8; 2], usize),
    Payload(usize),
}

pub struct TlsObfs<S> {
    stream: S,
    server: String,
    first_write: bool,
    first_read: bool,
    state: ReadState,
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> TlsObfs<S> {
    pub fn new(stream: S, server: &str) -> Self {
        Self {
            stream,
            server: server.to_string(),
            first_write: true,
            first_read: true,
            state: ReadState::Skip(FIRST_SKIP),
            out: Vec::new(),
            out_pos: 0,
        }
    }
}

/// 把 `data` 放进 session ticket 扩展的 ClientHello。
pub fn client_hello(data: &[u8], server: &str) -> Vec<u8> {
    let random = random_bytes(28);
    let session_id = random_bytes(32);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mut out = Vec::with_capacity(220 + data.len() + server.len());
    // handshake 记录头：类型 22、TLS 1.0、长度
    out.extend_from_slice(&[22, 0x03, 0x01]);
    out.extend_from_slice(&((212 + data.len() + server.len()) as u16).to_be_bytes());
    // ClientHello：类型 1、24 位长度、TLS 1.2
    out.push(1);
    out.push(0);
    out.extend_from_slice(&((208 + data.len() + server.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&random);
    out.push(32);
    out.extend_from_slice(&session_id);
    // 密码套件
    out.extend_from_slice(&[0x00, 0x38]);
    out.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);
    // 压缩方法
    out.extend_from_slice(&[0x01, 0x00]);
    // 扩展总长
    out.extend_from_slice(&((79 + data.len() + server.len()) as u16).to_be_bytes());
    // session ticket：载荷在这里
    out.extend_from_slice(&[0x00, 0x23]);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    // server name
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&((server.len() + 5) as u16).to_be_bytes());
    out.extend_from_slice(&((server.len() + 3) as u16).to_be_bytes());
    out.push(0);
    out.extend_from_slice(&(server.len() as u16).to_be_bytes());
    out.extend_from_slice(server.as_bytes());
    // ec_point_formats
    out.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);
    // supported_groups
    out.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);
    // signature_algorithms
    out.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);
    // encrypt_then_mac、extended_master_secret
    out.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);
    out.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    out
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsObfs<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.state {
                ReadState::Skip(0) => self.state = ReadState::Length([0; 2], 0),
                ReadState::Skip(n) => {
                    let mut scratch = [0u8; 256];
                    let take = n.min(scratch.len());
                    let mut read = ReadBuf::new(&mut scratch[..take]);
                    ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read))?;
                    let got = read.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    self.state = ReadState::Skip(n - got);
                }
                ReadState::Length(mut len, have) => {
                    let mut read = ReadBuf::new(&mut len[have..]);
                    ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read))?;
                    let got = read.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let have = have + got;
                    self.state = if have == 2 {
                        let length = u16::from_be_bytes(len) as usize;
                        self.first_read = false;
                        if length == 0 {
                            ReadState::Skip(NEXT_SKIP)
                        } else {
                            ReadState::Payload(length)
                        }
                    } else {
                        ReadState::Length(len, have)
                    };
                }
                ReadState::Payload(left) => {
                    let limit = buf.remaining().min(left);
                    let mut read = ReadBuf::new(buf.initialize_unfilled_to(limit));
                    ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read))?;
                    let got = read.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    buf.advance(got);
                    self.state = if got == left {
                        ReadState::Skip(NEXT_SKIP)
                    } else {
                        ReadState::Payload(left - got)
                    };
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> TlsObfs<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.stream).poll_write(cx, &self.out[self.out_pos..]))?;
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

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsObfs<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 上一次排队的数据先发完
        ready!(self.drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(TLS_CHUNK);
        if self.first_write {
            self.first_write = false;
            self.out = client_hello(&data[..n], &self.server);
        } else {
            let mut record = vec![0x17, 0x03, 0x03];
            record.extend_from_slice(&(n as u16).to_be_bytes());
            record.extend_from_slice(&data[..n]);
            self.out = record;
        }
        self.out_pos = 0;
        // 先尽量写出；写不完的留在 `out`，下一次写出或 flush 时继续
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
#[path = "obfs_write_tests.rs"]
mod write_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// 服务端（simple-obfs server 的行为）：HTTP。读到请求首部结束，请求体是第一段数据；
    /// 回 101 之后双向透传。
    async fn http_server(mut s: tokio::io::DuplexStream) -> Vec<u8> {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
        }
        let text = String::from_utf8(head).unwrap();
        assert!(
            text.starts_with("GET / HTTP/1.1\r\nHost: example.com:8443\r\n"),
            "{text}"
        );
        assert!(
            text.contains("Upgrade: websocket\r\n") && text.contains("Connection: Upgrade\r\n")
        );
        assert!(text.contains("Sec-WebSocket-Key: "));
        let length: usize = text
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        let mut first = vec![0; length];
        s.read_exact(&mut first).await.unwrap();
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nreply-one").await.unwrap();
        // 后续数据原样回显
        let mut rest = vec![0; 11];
        s.read_exact(&mut rest).await.unwrap();
        s.write_all(&rest).await.unwrap();
        first
    }

    #[tokio::test]
    async fn http_obfs_round_trip() {
        let (client, server) = duplex(4096);
        let task = tokio::spawn(http_server(server));
        let mut c = HttpObfs::new(client, "example.com", 8443);
        c.write_all(b"first-packet").await.unwrap();
        c.flush().await.unwrap();
        // 响应首部之后紧跟的 reply-one 随首部一起到达
        let mut got = [0; 9];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"reply-one");
        c.write_all(b"hello-world").await.unwrap();
        let mut echo = [0; 11];
        c.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello-world");
        assert_eq!(task.await.unwrap(), b"first-packet");
    }

    #[tokio::test]
    async fn http_obfs_handles_split_response_head() {
        let (client, mut server) = duplex(4096);
        let mut c = HttpObfs::new(client, "h", 80);
        c.write_all(b"x").await.unwrap();
        let mut head = vec![0; 256];
        let _ = server.read(&mut head).await.unwrap();
        for part in [
            &b"HTTP/1.1 101 Switch"[..],
            b"ing\r\nA: b\r",
            b"\n\r",
            b"\npayload",
        ] {
            server.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
        let mut got = [0; 7];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"payload");
        // 没有首部结束标记且过长：拒绝
        let (client, mut server) = duplex(64 * 1024);
        let mut c = HttpObfs::new(client, "h", 80);
        c.write_all(b"x").await.unwrap();
        tokio::spawn(async move {
            let junk = vec![b'a'; 20 * 1024];
            let _ = server.write_all(&junk).await;
        });
        let mut b = [0; 1];
        assert!(c.read_exact(&mut b).await.is_err());
    }

    fn ticket_payload(hello: &[u8]) -> Vec<u8> {
        // 5 记录头 + 4 握手头 + 2 版本 + 32 random + 1 + 32 session id + 2 + 56 套件 + 2 压缩 + 2 扩展总长
        let at = 5 + 4 + 2 + 32 + 1 + 32 + 2 + 56 + 2 + 2;
        assert_eq!(&hello[at..at + 2], &[0x00, 0x23]);
        let len = u16::from_be_bytes([hello[at + 2], hello[at + 3]]) as usize;
        hello[at + 4..at + 4 + len].to_vec()
    }

    #[tokio::test]
    async fn tls_obfs_round_trip() {
        let (client, mut server) = duplex(64 * 1024);
        let mut c = TlsObfs::new(client, "bing.com");
        c.write_all(b"first-packet").await.unwrap();
        c.flush().await.unwrap();
        // 服务端读取 ClientHello：记录长度来自头部
        let mut head = [0u8; 5];
        server.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..3], &[22, 3, 1]);
        let length = u16::from_be_bytes([head[3], head[4]]) as usize;
        let mut body = vec![0; length];
        server.read_exact(&mut body).await.unwrap();
        let mut hello = head.to_vec();
        hello.extend(body);
        assert_eq!(ticket_payload(&hello), b"first-packet");
        // 长度自洽：握手长度字段与记录长度一致
        assert_eq!(
            u16::from_be_bytes([hello[7], hello[8]]) as usize + 4,
            length
        );
        assert!(hello.windows(8).any(|w| w == b"bing.com"));

        // 回复：ServerHello 记录（96 字节）、CCS 记录（6 字节）、应用数据记录
        let mut reply = vec![22, 3, 3, 0, 91];
        reply.extend(vec![0xEE; 91]);
        reply.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        for part in [&b"first-reply"[..], b"-and-more"] {
            reply.extend_from_slice(&[0x17, 3, 3]);
            reply.extend_from_slice(&(part.len() as u16).to_be_bytes());
            reply.extend_from_slice(part);
        }
        server.write_all(&reply).await.unwrap();
        let mut got = vec![0; 20];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"first-reply-and-more");

        // 之后的写出是应用数据记录，超过 16 KiB 拆成多条
        let big = vec![9u8; 40_000];
        c.write_all(&big).await.unwrap();
        c.flush().await.unwrap();
        let mut total = 0;
        while total < big.len() {
            let mut rec = [0u8; 5];
            server.read_exact(&mut rec).await.unwrap();
            assert_eq!(&rec[..3], &[0x17, 3, 3]);
            let n = u16::from_be_bytes([rec[3], rec[4]]) as usize;
            assert!(n <= 16 * 1024);
            let mut payload = vec![0; n];
            server.read_exact(&mut payload).await.unwrap();
            assert!(payload.iter().all(|b| *b == 9));
            total += n;
        }
        assert_eq!(total, big.len());
    }

    #[tokio::test]
    async fn tls_obfs_survives_one_byte_reads() {
        let (client, mut server) = duplex(64 * 1024);
        let mut c = TlsObfs::new(client, "x.test");
        let mut reply = vec![22, 3, 3, 0, 91];
        reply.extend(vec![1; 91]);
        reply.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        reply.extend_from_slice(&[0x17, 3, 3, 0, 5]);
        reply.extend_from_slice(b"abcde");
        reply.extend_from_slice(&[0x17, 3, 3, 0, 3]);
        reply.extend_from_slice(b"xyz");
        tokio::spawn(async move {
            for byte in reply {
                server.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut got = Vec::new();
        let mut b = [0u8; 1];
        while got.len() < 8 {
            c.read_exact(&mut b).await.unwrap();
            got.push(b[0]);
        }
        assert_eq!(got, b"abcdexyz");
    }
}
