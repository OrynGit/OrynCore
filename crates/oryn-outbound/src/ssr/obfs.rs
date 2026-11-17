//! ShadowsocksR 混淆插件：plain、http_simple、http_post、random_head、tls1.2_ticket_auth。
//!
//! 来源 MetaCubeX/mihomo `transport/ssr/obfs`（http_simple.go、http_post.go、random_head.go、
//! tls1.2_ticket_auth.go），v1.19.32，commit 见 Oryn_dev/docs/oryncore/provenance.md。
//! Copyright (C) 2021–2026 MetaCubeX contributors。SPDX-License-Identifier: GPL-3.0-or-later
//! 改写为连接时完成的握手（首个写出就是协议首部，见 mod.rs）加稳态的字节流封装。
//! tls1.2_ticket_auth 的服务端握手响应按记录解析（Go 版假设一次读到整个响应）。

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::util::{crc32, hmac_sha1, random_below, random_bytes, unix_now};
use crate::BoxStream;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Plain,
    HttpSimple,
    HttpPost,
    RandomHead,
    Tls12TicketAuth,
}

impl Kind {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "plain" => Kind::Plain,
            "http_simple" => Kind::HttpSimple,
            "http_post" => Kind::HttpPost,
            "random_head" => Kind::RandomHead,
            "tls1.2_ticket_auth" | "tls1.2_ticket_fastauth" => Kind::Tls12TicketAuth,
            _ => return None,
        })
    }

    pub(crate) fn overhead(self) -> usize {
        match self {
            Kind::Tls12TicketAuth => 5,
            _ => 0,
        }
    }
}

pub(crate) struct Obfs {
    pub(crate) kind: Kind,
    /// 服务器地址（Host 首部 / SNI 的默认值）。
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) key: Vec<u8>,
    pub(crate) iv_len: usize,
    pub(crate) param: String,
    /// tls1.2_ticket_auth 的客户端编号（每个出站一个）。
    pub(crate) client_id: [u8; 32],
}

/// 响应首部与握手响应的上限。
const MAX_HEAD: usize = 16 * 1024;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
];

impl Obfs {
    /// 完成握手并把第一段数据（IV + 加密后的协议首部）发出去，返回稳态的字节流。
    pub(crate) async fn connect(&self, mut io: BoxStream, first: Vec<u8>) -> io::Result<BoxStream> {
        match self.kind {
            Kind::Plain => {
                io.write_all(&first).await?;
                io.flush().await?;
                Ok(io)
            }
            Kind::HttpSimple | Kind::HttpPost => {
                io.write_all(&self.http_request(&first)).await?;
                io.flush().await?;
                Ok(Box::new(HttpResponse {
                    io,
                    head: Vec::new(),
                    done: false,
                    rest: Vec::new(),
                    rest_pos: 0,
                }))
            }
            Kind::RandomHead => {
                // 先发一段带 CRC 的随机数据，读掉服务端回的随机数据，再发真正的数据
                let mut head = random_bytes(random_below(96) + 4);
                let crc = 0xffff_ffffu32.wrapping_sub(crc32(&head));
                head.extend_from_slice(&crc.to_le_bytes());
                io.write_all(&head).await?;
                io.flush().await?;
                // 与 Python shadowsocksr / mihomo 的 `client_decode` 相同：丢弃「第一次收到的那一块」。
                // 协议没有长度字段，服务端随机响应若被 TCP 分段到多次读取会失步，这是协议固有缺陷；
                // 服务端实现都是一次 send 发出 ≤ 100 字节，实际不会分段。
                let mut discard = [0u8; 4096];
                if io.read(&mut discard).await? == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                io.write_all(&first).await?;
                io.flush().await?;
                Ok(io)
            }
            Kind::Tls12TicketAuth => self.tls_handshake(io, first).await,
        }
    }

    fn http_request(&self, data: &[u8]) -> Vec<u8> {
        let head_len = self.iv_len + 30;
        let head_data_len = if data.len() > head_len + 64 {
            head_len + random_below(65)
        } else {
            data.len()
        };
        let (head, rest) = data.split_at(head_data_len);
        let mut host = self.host.clone();
        let mut body = String::new();
        if !self.param.is_empty() {
            match self.param.split_once('#') {
                Some((h, b)) => {
                    host = h.to_string();
                    body = b.replace("\\n", "\r\n").replace('\n', "\r\n");
                }
                None => host = self.param.clone(),
            }
        }
        let hosts: Vec<&str> = host.split(',').collect();
        let host = hosts[random_below(hosts.len())];
        let mut out = String::new();
        out.push_str(if self.kind == Kind::HttpPost {
            "POST /"
        } else {
            "GET /"
        });
        for b in head {
            out.push_str(&format!("%{b:02x}"));
        }
        out.push_str(" HTTP/1.1\r\nHost: ");
        out.push_str(host);
        if self.port != 80 {
            out.push_str(&format!(":{}", self.port));
        }
        out.push_str("\r\n");
        if !body.is_empty() {
            out.push_str(&body);
            out.push_str("\r\n\r\n");
        } else {
            out.push_str("User-Agent: ");
            out.push_str(USER_AGENTS[random_below(USER_AGENTS.len())]);
            out.push_str("\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n");
            if self.kind == Kind::HttpPost {
                const SET: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                out.push_str("Content-Type: multipart/form-data; boundary=");
                for _ in 0..32 {
                    out.push(SET[random_below(SET.len())] as char);
                }
                out.push_str("\r\n");
            }
            out.push_str("DNT: 1\r\nConnection: keep-alive\r\n\r\n");
        }
        let mut wire = out.into_bytes();
        wire.extend_from_slice(rest);
        wire
    }

    fn tls_hmac(&self, data: &[u8]) -> [u8; 10] {
        let mut key = self.key.clone();
        key.extend_from_slice(&self.client_id);
        hmac_sha1(&key, data)[..10].try_into().unwrap()
    }

    fn tls_host(&self) -> String {
        let host = if self.param.is_empty() {
            self.host.clone()
        } else {
            self.param.clone()
        };
        // IP 地址不作 SNI
        if host.ends_with(|c: char| c.is_ascii_digit()) {
            return String::new();
        }
        let hosts: Vec<&str> = host.split(',').collect();
        hosts[random_below(hosts.len())].to_string()
    }

    async fn tls_handshake(&self, mut io: BoxStream, first: Vec<u8>) -> io::Result<BoxStream> {
        // ClientHello：随机数里带时间与认证，session ID 是客户端编号，扩展里有 SNI 与随机 ticket
        let mut data = vec![3, 3];
        let mut auth = unix_now().to_be_bytes().to_vec();
        auth.extend_from_slice(&random_bytes(18));
        let mac = self.tls_hmac(&auth);
        data.extend_from_slice(&auth);
        data.extend_from_slice(&mac);
        data.push(0x20);
        data.extend_from_slice(&self.client_id);
        data.extend_from_slice(&[
            0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13,
            0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f,
            0x00, 0x0a,
        ]);
        data.extend_from_slice(&[1, 0]);
        let host = self.tls_host();
        let mut ext = vec![0xff, 0x01, 0x00, 0x01, 0x00];
        let len = host.len() as u16;
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&(len + 5).to_be_bytes());
        ext.extend_from_slice(&(len + 3).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&len.to_be_bytes());
        ext.extend_from_slice(host.as_bytes());
        ext.extend_from_slice(&[0, 0x17, 0, 0]);
        let ticket_len = 16 * (random_below(17) + 8);
        ext.extend_from_slice(&[0, 0x23]);
        ext.extend_from_slice(&(ticket_len as u16).to_be_bytes());
        ext.extend_from_slice(&random_bytes(ticket_len));
        ext.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03,
            0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03,
        ]);
        ext.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
        ext.extend_from_slice(&[0x00, 0x12, 0x00, 0x00]);
        ext.extend_from_slice(&[0x75, 0x50, 0x00, 0x00]);
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18]);
        data.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        data.extend_from_slice(&ext);
        let mut hello = vec![0x16, 3, 1];
        hello.extend_from_slice(&((data.len() + 4) as u16).to_be_bytes());
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&(data.len() as u16).to_be_bytes());
        hello.extend_from_slice(&data);
        io.write_all(&hello).await?;
        io.flush().await?;

        // 服务端：ServerHello、可选的 NewSessionTicket、ChangeCipherSpec、Finished（末尾 10 字节是之前全部内容的 HMAC）
        let mut response = Vec::new();
        let mut saw_ccs = false;
        loop {
            let mut header = [0u8; 5];
            io.read_exact(&mut header).await?;
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            if response.len() + 5 + len > MAX_HEAD {
                return Err(invalid("tls1.2_ticket_auth handshake too large"));
            }
            response.extend_from_slice(&header);
            let start = response.len();
            response.resize(start + len, 0);
            io.read_exact(&mut response[start..]).await?;
            match header[0] {
                0x14 => saw_ccs = true,
                0x16 if saw_ccs => break,
                0x16 => {}
                _ => return Err(invalid("tls1.2_ticket_auth unexpected handshake record")),
            }
        }
        let n = response.len();
        if n < 11 + 32 + 1 + 32
            || response[33..43] != self.tls_hmac(&response[11..33])
            || response[n - 10..] != self.tls_hmac(&response[..n - 10])
        {
            return Err(invalid("tls1.2_ticket_auth hmac verification failed"));
        }
        let mut finish = vec![0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20];
        finish.extend_from_slice(&random_bytes(22));
        let mac = self.tls_hmac(&finish);
        finish.extend_from_slice(&mac);
        pack_records(&first, &mut finish);
        io.write_all(&finish).await?;
        io.flush().await?;
        Ok(Box::new(TlsTicket {
            io,
            state: Record::Header,
            header: [0; 5],
            header_have: 0,
            body_left: 0,
            pending: Vec::new(),
            pending_pos: 0,
        }))
    }
}

/// 应用数据切成随机大小的 TLS 记录（与参考实现相同：超过 2048 字节时每段 100–4195 字节）。
fn pack_records(mut data: &[u8], out: &mut Vec<u8>) {
    while data.len() > 2048 {
        let size = (random_below(4096) + 100).min(data.len());
        record(&data[..size], out);
        data = &data[size..];
    }
    if !data.is_empty() {
        record(data, out);
    }
}

fn record(data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x17, 3, 3]);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// http_simple / http_post：跳过服务端响应首部，之后原样透传。
struct HttpResponse {
    io: BoxStream,
    head: Vec<u8>,
    done: bool,
    rest: Vec<u8>,
    rest_pos: usize,
}

impl AsyncRead for HttpResponse {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.rest_pos < this.rest.len() {
            let n = (this.rest.len() - this.rest_pos).min(out.remaining());
            out.put_slice(&this.rest[this.rest_pos..this.rest_pos + n]);
            this.rest_pos += n;
            return Poll::Ready(Ok(()));
        }
        if this.done {
            return Pin::new(&mut this.io).poll_read(cx, out);
        }
        loop {
            let mut buf = [0u8; 2048];
            let mut rb = ReadBuf::new(&mut buf);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.head.extend_from_slice(&buf[..n]);
            if let Some(pos) = this.head.windows(4).position(|w| w == b"\r\n\r\n") {
                this.done = true;
                this.rest = this.head.split_off(pos + 4);
                this.rest_pos = 0;
                this.head = Vec::new();
                return Pin::new(&mut *this).poll_read(cx, out);
            }
            if this.head.len() > MAX_HEAD {
                return Poll::Ready(Err(invalid("http_simple response header too large")));
            }
        }
    }
}

impl AsyncWrite for HttpResponse {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// tls1.2_ticket_auth 握手之后：写出切成应用数据记录，读入逐条解记录。
struct TlsTicket {
    io: BoxStream,
    state: Record,
    header: [u8; 5],
    header_have: usize,
    /// 当前记录还剩多少内容没交出去。
    body_left: usize,
    pending: Vec<u8>,
    pending_pos: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Record {
    Header,
    Body,
}

impl AsyncRead for TlsTicket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // 读之前推进尚未写出的记录，避免「写后不 flush 就读」的调用方死等
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        loop {
            match this.state {
                Record::Header => {
                    while this.header_have < 5 {
                        let mut rb = ReadBuf::new(&mut this.header[this.header_have..]);
                        ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
                        let n = rb.filled().len();
                        if n == 0 {
                            return if this.header_have == 0 {
                                Poll::Ready(Ok(()))
                            } else {
                                Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                            };
                        }
                        this.header_have += n;
                    }
                    if this.header[..3] != [0x17, 3, 3] {
                        return Poll::Ready(Err(invalid("tls1.2_ticket_auth bad record")));
                    }
                    this.header_have = 0;
                    this.body_left = u16::from_be_bytes([this.header[3], this.header[4]]) as usize;
                    if this.body_left > 0 {
                        this.state = Record::Body;
                    }
                }
                Record::Body => {
                    let limit = this.body_left.min(out.remaining());
                    let before = out.filled().len();
                    let mut rb = ReadBuf::new(out.initialize_unfilled_to(limit));
                    ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    out.set_filled(before + n);
                    this.body_left -= n;
                    if this.body_left == 0 {
                        this.state = Record::Header;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl TlsTicket {
    /// 把已打包的记录写进底层。
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.io).poll_write(cx, &self.pending[self.pending_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending_pos += n;
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TlsTicket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(16 * 1024);
        pack_records(&buf[..take], &mut this.pending);
        // 尽量当场写出，不把数据只留在私有缓冲里等 flush
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
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
