//! VLESS Vision（`flow: xtls-rprx-vision`）。
//!
//! 来源 SagerNet/sing-vmess `vless/vision.go`、`vless/constant.go`，
//! commit 3aed155119a1（v0.2.8-0.20250909125414-3aed155119a1，sing-box 1.14.0 所用版本）。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
//! 改写为 Rust 的 AsyncRead / AsyncWrite 状态机；出处登记在 Oryn_dev/docs/oryncore/provenance.md。
//!
//! Vision 在外层 TLS 里给内层流量的前几个包加填充，并识别内层 TLS：内层是 TLS 1.3 时，客户端
//! 在第一条内层应用数据前发出「直写」命令，此后上行字节不再经过外层 TLS；服务端同样在下行切换。
//! 切换点之后的字节在 TCP 上紧跟着最后一条外层 TLS 记录。Go 的实现直接取 `tls.Conn` 的内部缓冲；
//! rustls 会一次处理缓冲里的所有完整记录，把切换点之后的内层记录也当作外层记录解密而失败。
//! 所以外层 TLS 下面垫一层 [`RecordReader`]：填充阶段每次只交给 rustls 一条记录的字节，
//! 切换时套接字里剩下的就是原始字节，不需要修改 rustls。

use std::future::Future;
use std::io::{self, Read};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use oryn_tls::TlsStream;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxStream;

const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

const COMMAND_CONTINUE: u8 = 0;
const COMMAND_END: u8 = 1;
const COMMAND_DIRECT: u8 = 2;

/// Xray 的单次读取块大小。
const CHUNK: usize = 8192;
/// 外层 TLS 单次读取的明文上限（一条 TLS 记录最多 16 KiB 明文）。
const READ_CHUNK: usize = 16 * 1024;
/// sing-vmess 在切换直写时为剩余缓冲等待 5 ms（原注释「wtf」）；保持相同行为。
const DIRECT_WRITE_DELAY: Duration = Duration::from_millis(5);

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

/// 内层 TLS 1.3 的密码套件中，除 TLS_AES_128_CCM_8_SHA256 外都允许直写。
fn xtls_cipher(cipher: u16) -> bool {
    matches!(cipher, 0x1301..=0x1304)
}

fn random_below(bound: u32) -> usize {
    let mut b = [0u8; 4];
    SystemRandom::new()
        .fill(&mut b)
        .expect("system random source failed");
    (u32::from_le_bytes(b) % bound) as usize
}

// ---------------------------------------------------------------------------
// RecordReader
// ---------------------------------------------------------------------------

/// 外层 TLS 下面的字节流：受限模式下每次读取不越过当前 TLS 记录的边界，而且直接读到调用方的
/// 缓冲里，自己不预读。切换到直读或填充结束后解除限制，此后原样透传。
pub(crate) struct RecordReader<S> {
    inner: S,
    limited: bool,
    /// 当前记录还没交出去的字节数（含首部）；0 表示下一次要先读首部。
    record_left: usize,
    header: [u8; 5],
    header_have: usize,
    header_given: usize,
}

impl<S> RecordReader<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            limited: true,
            record_left: 0,
            header: [0; 5],
            header_have: 0,
            header_given: 0,
        }
    }

    fn unlimit(&mut self) {
        self.limited = false;
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordReader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // 已读满（或 EOF 时已读到）但还没交出去的首部字节（受限与否都先交出）。
        // 首部没读满时 record_left 仍为 0，不能提前交出。
        if this.record_left > 0 && this.header_given < this.header_have {
            let n = (this.header_have - this.header_given).min(out.remaining());
            out.put_slice(&this.header[this.header_given..this.header_given + n]);
            this.header_given += n;
            this.record_left = this.record_left.saturating_sub(n);
            if this.header_given == this.header_have && this.record_left == 0 {
                this.header_have = 0;
                this.header_given = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if !this.limited {
            return Pin::new(&mut this.inner).poll_read(cx, out);
        }
        if this.record_left == 0 {
            // 先把 5 字节首部读满，再决定这条记录的长度
            while this.header_have < 5 {
                let mut part = ReadBuf::new(&mut this.header[this.header_have..5]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
                let n = part.filled().len();
                if n == 0 {
                    // EOF：交出已有的部分首部（由 TLS 层报错）
                    if this.header_have == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.record_left = this.header_have;
                    this.header_given = 0;
                    return Pin::new(&mut *this).poll_read(cx, out);
                }
                this.header_have += n;
            }
            this.record_left = 5 + u16::from_be_bytes([this.header[3], this.header[4]]) as usize;
            this.header_given = 0;
            return Pin::new(&mut *this).poll_read(cx, out);
        }
        // 记录体：直接读到调用方缓冲，最多读到记录末尾
        let limit = this.record_left.min(out.remaining());
        let before = out.filled().len();
        let mut part = ReadBuf::new(out.initialize_unfilled_to(limit));
        ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
        let n = part.filled().len();
        out.set_filled(before + n);
        this.record_left -= n;
        if this.record_left == 0 {
            this.header_have = 0;
            this.header_given = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordReader<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 内层 TLS 识别与填充（两个方向共用）
// ---------------------------------------------------------------------------

struct Filter {
    uuid: [u8; 16],
    is_tls: bool,
    packets_to_filter: i32,
    is_tls12_or_above: bool,
    remaining_server_hello: i32,
    cipher: u16,
    enable_xtls: bool,
}

impl Filter {
    fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            is_tls: false,
            packets_to_filter: 8,
            is_tls12_or_above: false,
            remaining_server_hello: -1,
            cipher: 0,
            enable_xtls: false,
        }
    }

    fn filter(&mut self, buffer: &[u8]) {
        self.packets_to_filter -= 1;
        if buffer.len() > 6 {
            if buffer[0] == 22 && buffer[1] == 3 && buffer[2] == 3 {
                self.is_tls = true;
                if buffer[5] == 2 {
                    self.is_tls12_or_above = true;
                    self.remaining_server_hello = ((buffer[3] as i32) << 8 | buffer[4] as i32) + 5;
                    if buffer.len() >= 79 && self.remaining_server_hello >= 79 {
                        let session_id_len = buffer[43] as usize;
                        let at = 43 + session_id_len + 1;
                        if let Some(suite) = buffer.get(at..at + 2) {
                            self.cipher = u16::from_be_bytes([suite[0], suite[1]]);
                        }
                    }
                }
            } else if buffer[..2] == TLS_CLIENT_HANDSHAKE_START && buffer[5] == 1 {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(buffer.len());
            self.remaining_server_hello -= end as i32;
            if buffer[..end]
                .windows(TLS13_SUPPORTED_VERSIONS.len())
                .any(|w| w == TLS13_SUPPORTED_VERSIONS)
            {
                if xtls_cipher(self.cipher) {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello == 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

/// 一个填充块：可选的 UUID 前缀、命令、内容长度、填充长度、内容、填充。
fn pad(uuid: Option<[u8; 16]>, content: &[u8], command: u8, is_tls: bool, out: &mut Vec<u8>) {
    let content_len = content.len();
    let padding_len = if content_len < 900 && is_tls {
        random_below(500) + 900 - content_len
    } else {
        random_below(256)
    };
    if let Some(uuid) = uuid {
        out.extend_from_slice(&uuid);
    }
    out.extend_from_slice(&[
        command,
        (content_len >> 8) as u8,
        content_len as u8,
        (padding_len >> 8) as u8,
        padding_len as u8,
    ]);
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
}

/// 解填充状态（与 sing-vmess 的 unPadding 相同；填充首部被读取块边界切开时暂存）。
struct Unpad {
    uuid: [u8; 16],
    prefix_have: usize,
    plain: bool,
    header_seen: bool,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
    header: [u8; 5],
    header_have: usize,
}

impl Unpad {
    fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            prefix_have: 0,
            plain: false,
            header_seen: false,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            header: [0; 5],
            header_have: 0,
        }
    }

    /// 只交出已确认的内容；UUID 前缀至多缓存 16 字节，首部状态另有固定 5 字节。
    fn unpad(&mut self, buffer: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let mut index = 0;
        if self.plain {
            out.extend_from_slice(buffer);
            return Ok(());
        }
        if self.remaining_content == -1 && self.remaining_padding == -1 {
            while self.prefix_have < self.uuid.len() && index < buffer.len() {
                if buffer[index] != self.uuid[self.prefix_have] {
                    // 尚未匹配完整 UUID：恢复此前暂存的候选前缀，再原样交出当前块。
                    self.plain = true;
                    out.extend_from_slice(&self.uuid[..self.prefix_have]);
                    out.extend_from_slice(&buffer[index..]);
                    self.prefix_have = 0;
                    return Ok(());
                }
                self.prefix_have += 1;
                index += 1;
            }
            if self.prefix_have < self.uuid.len() {
                return Ok(());
            }
            self.remaining_content = 0;
            self.remaining_padding = 0;
        }
        while index < buffer.len() {
            if self.remaining_content <= 0 && self.remaining_padding <= 0 {
                if self.finished_command().is_some() {
                    out.extend_from_slice(&buffer[index..]);
                    break;
                }
                let take = (5 - self.header_have).min(buffer.len() - index);
                self.header[self.header_have..self.header_have + take]
                    .copy_from_slice(&buffer[index..index + take]);
                self.header_have += take;
                index += take;
                if self.header_have < 5 {
                    break;
                }
                self.header_have = 0;
                let h = self.header;
                if !matches!(h[0], COMMAND_CONTINUE | COMMAND_END | COMMAND_DIRECT) {
                    return Err(invalid("Vision unknown command"));
                }
                self.header_seen = true;
                self.current_command = h[0];
                self.remaining_content = (h[1] as i32) << 8 | h[2] as i32;
                self.remaining_padding = (h[3] as i32) << 8 | h[4] as i32;
            } else if self.remaining_content > 0 {
                let end = (self.remaining_content as usize).min(buffer.len() - index);
                out.extend_from_slice(&buffer[index..index + end]);
                self.remaining_content -= end as i32;
                index += end;
            } else {
                let end = (self.remaining_padding as usize).min(buffer.len() - index);
                self.remaining_padding -= end as i32;
                index += end;
            }
        }
        Ok(())
    }

    fn finished_command(&self) -> Option<u8> {
        (self.header_seen
            && self.remaining_content == 0
            && self.remaining_padding == 0
            && self.header_have == 0
            && matches!(self.current_command, COMMAND_END | COMMAND_DIRECT))
        .then_some(self.current_command)
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if self.plain {
            return Ok(());
        }
        if self.remaining_content == -1 {
            // EOF 前没有完整 UUID，候选前缀仍属于普通未填充内容。
            out.extend_from_slice(&self.uuid[..self.prefix_have]);
            self.prefix_have = 0;
            self.plain = true;
            return Ok(());
        }
        if !self.header_seen
            || self.header_have != 0
            || self.remaining_content != 0
            || self.remaining_padding != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated Vision padding frame",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VisionStream
// ---------------------------------------------------------------------------

/// 从外层 TLS 读取：只取已解密的明文，缓冲为空时才处理下一条记录。
///
/// 不能用 tokio-rustls 的 `poll_read`：它会继续处理后续记录来填满调用方的缓冲（并把错误留到下一次），
/// 切换点之后的原始字节就会被当成外层记录消耗掉。`poll_fill_buf` 只在明文为空时读一条记录。
fn poll_tls_read(tls: &mut Tls, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
    use tokio::io::AsyncBufRead;
    let data = ready!(Pin::new(&mut *tls).poll_fill_buf(cx))?;
    let n = data.len().min(out.len());
    out[..n].copy_from_slice(&data[..n]);
    Pin::new(&mut *tls).consume(n);
    Poll::Ready(Ok(n))
}

type Tls = TlsStream<RecordReader<BoxStream>>;

pub(crate) struct VisionStream {
    tls: Tls,
    filter: Filter,
    /// 还没发出的 VLESS 请求首部，随第一次写出发送（与 sing-vmess 的 DialEarlyConn 相同）。
    request: Option<Vec<u8>>,
    // 响应首部：版本 + 附加字段长度 + 附加字段
    response: [u8; 257],
    response_have: usize,
    response_need: usize,
    response_done: bool,
    // 写方向
    is_padding: bool,
    direct_write: bool,
    write_uuid: bool,
    /// 待写出：先经外层 TLS 的部分，再直接写到 TCP 的部分。
    out_tls: Vec<u8>,
    out_tls_pos: usize,
    tls_needs_flush: bool,
    out_raw: Vec<u8>,
    out_raw_pos: usize,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
    // 读方向
    within_padding: bool,
    unpad: Unpad,
    direct_read: bool,
    pending: Vec<u8>,
    pending_pos: usize,
    chunk: Vec<u8>,
    read_eof: bool,
    failed: bool,
}

impl VisionStream {
    pub(crate) fn new(tls: Tls, uuid: [u8; 16], request: Vec<u8>) -> Self {
        Self {
            tls,
            filter: Filter::new(uuid),
            request: Some(request),
            response: [0; 257],
            response_have: 0,
            response_need: 2,
            response_done: false,
            is_padding: true,
            direct_write: false,
            write_uuid: true,
            out_tls: Vec::new(),
            out_tls_pos: 0,
            tls_needs_flush: false,
            out_raw: Vec::new(),
            out_raw_pos: 0,
            delay: None,
            within_padding: true,
            unpad: Unpad::new(uuid),
            direct_read: false,
            pending: Vec::new(),
            pending_pos: 0,
            chunk: Vec::new(),
            read_eof: false,
            failed: false,
        }
    }

    fn raw(&mut self) -> &mut RecordReader<BoxStream> {
        self.tls.get_mut().0
    }

    // ----- 写 -----

    fn padding(&mut self, content: &[u8], command: u8, out: &mut Vec<u8>) {
        let uuid = self.write_uuid.then_some(self.filter.uuid);
        self.write_uuid = false;
        pad(uuid, content, command, self.filter.is_tls, out);
    }

    /// 把一次写入编码到待写缓冲（填充阶段）。
    fn encode_padded(&mut self, data: &[u8]) {
        let mut tls_part = self.request.take().unwrap_or_default();
        let mut raw_part = Vec::new();
        // 与 sing-vmess 的 reshapeBuffer 相同：超过 8192 − 21 时在最后一个内层应用数据记录处切开
        let pieces: Vec<&[u8]> = if data.len() < CHUNK - 21 {
            vec![data]
        } else {
            let index = data
                .windows(3)
                .rposition(|w| w == TLS_APPLICATION_DATA_START)
                .filter(|&i| i > 0)
                .unwrap_or(CHUNK / 2);
            vec![&data[..index], &data[index..]]
        };
        let mut finished_at = None;
        for (i, piece) in pieces.iter().enumerate() {
            if self.filter.is_tls && piece.len() > 6 && piece[..3] == TLS_APPLICATION_DATA_START {
                let mut command = COMMAND_END;
                if self.filter.enable_xtls {
                    self.direct_write = true;
                    command = COMMAND_DIRECT;
                }
                self.is_padding = false;
                self.padding(piece, command, &mut tls_part);
                finished_at = Some(i);
                break;
            } else if !self.filter.is_tls12_or_above && self.filter.packets_to_filter <= 1 {
                self.is_padding = false;
                self.padding(piece, COMMAND_END, &mut tls_part);
                finished_at = Some(i);
                break;
            }
            self.padding(piece, COMMAND_CONTINUE, &mut tls_part);
        }
        // 结束填充之后剩下的块不再填充：直写时绕过外层 TLS，否则仍经外层 TLS
        if let Some(i) = finished_at {
            for piece in &pieces[i + 1..] {
                if self.direct_write {
                    raw_part.extend_from_slice(piece);
                } else {
                    tls_part.extend_from_slice(piece);
                }
            }
        }
        self.out_tls = tls_part;
        self.out_tls_pos = 0;
        self.out_raw = raw_part;
        self.out_raw_pos = 0;
        if self.direct_write && !self.out_raw.is_empty() {
            self.delay = Some(Box::pin(tokio::time::sleep(DIRECT_WRITE_DELAY)));
        }
    }

    /// 写完待写缓冲：外层 TLS 部分写完并刷新后，才写直写部分。
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(invalid("Vision stream failed")));
        }
        while self.out_tls_pos < self.out_tls.len() {
            let n =
                ready!(Pin::new(&mut self.tls).poll_write(cx, &self.out_tls[self.out_tls_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_tls_pos += n;
            self.tls_needs_flush = true;
        }
        if self.tls_needs_flush {
            ready!(Pin::new(&mut self.tls).poll_flush(cx))?;
            self.tls_needs_flush = false;
            self.out_tls.clear();
            self.out_tls_pos = 0;
        }
        if let Some(delay) = &mut self.delay {
            ready!(delay.as_mut().poll(cx));
            self.delay = None;
        }
        while self.out_raw_pos < self.out_raw.len() {
            let (start, end) = (self.out_raw_pos, self.out_raw.len());
            let mut chunk = std::mem::take(&mut self.out_raw);
            let result = Pin::new(self.raw()).poll_write(cx, &chunk[start..end]);
            std::mem::swap(&mut self.out_raw, &mut chunk);
            let n = ready!(result)?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_raw_pos += n;
        }
        self.out_raw.clear();
        self.out_raw_pos = 0;
        Poll::Ready(Ok(()))
    }

    // ----- 读 -----

    /// 响应首部在 Vision 解填充之前读掉。
    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.response_done {
            while self.response_have < self.response_need {
                let n = ready!(poll_tls_read(
                    &mut self.tls,
                    cx,
                    &mut self.response[self.response_have..self.response_need]
                ))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VLESS truncated response header",
                    )));
                }
                self.response_have += n;
            }
            if self.response_need == 2 {
                if self.response[0] != 0 {
                    return Poll::Ready(Err(invalid("VLESS invalid response version")));
                }
                self.response_need = 2 + self.response[1] as usize;
                if self.response_need > 2 {
                    continue;
                }
            }
            self.response_done = true;
        }
        Poll::Ready(Ok(()))
    }

    /// 从外层 TLS 读一块并处理填充，结果放进 `pending`。返回 false 表示 EOF。
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        ready!(self.poll_response(cx))?;
        if self.chunk.len() != READ_CHUNK {
            self.chunk = vec![0; READ_CHUNK];
        }
        let mut chunk = std::mem::take(&mut self.chunk);
        let result = poll_tls_read(&mut self.tls, cx, &mut chunk);
        let restore = |this: &mut Self, chunk: Vec<u8>| this.chunk = chunk;
        let n = match result {
            Poll::Pending => {
                restore(self, chunk);
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => {
                restore(self, chunk);
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(n)) => n,
        };
        self.pending.clear();
        self.pending_pos = 0;
        if n == 0 {
            restore(self, chunk);
            self.read_eof = true;
            self.unpad.finish(&mut self.pending)?;
            return Poll::Ready(Ok(!self.pending.is_empty()));
        }
        if self.within_padding || self.filter.packets_to_filter > 0 {
            self.unpad.unpad(&chunk[..n], &mut self.pending)?;
            match self.unpad.finished_command() {
                Some(COMMAND_END) => {
                    self.within_padding = false;
                    self.raw().unlimit();
                }
                Some(COMMAND_DIRECT) => {
                    self.within_padding = false;
                    self.direct_read = true;
                    // 切换前已解密的剩余明文仍属于应用；随后直接读取底层字节。
                    let mut rest = [0u8; 4096];
                    loop {
                        match self.tls.get_mut().1.reader().read(&mut rest) {
                            Ok(0) => break,
                            Ok(m) => self.pending.extend_from_slice(&rest[..m]),
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                restore(self, chunk);
                                return Poll::Ready(Err(e));
                            }
                        }
                    }
                    self.raw().unlimit();
                }
                _ if self.unpad.plain => {
                    self.within_padding = false;
                    self.raw().unlimit();
                }
                _ => {
                    // 候选 UUID 或不完整填充帧都必须维持逐 TLS 记录读取。
                    self.within_padding = true;
                }
            }
            if self.filter.packets_to_filter > 0 && !self.pending.is_empty() {
                self.filter.filter(&self.pending);
            }
        } else {
            self.pending.extend_from_slice(&chunk[..n]);
        }
        restore(self, chunk);
        Poll::Ready(Ok(true))
    }
}

impl VisionStream {
    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // 服务端先说话的协议：还没写过请求时先把请求和一个空填充块发出去，否则服务端不会回应
        if this.request.is_some() && this.out_tls.is_empty() {
            this.write_nil();
        }
        ready!(this.poll_drain(cx))?;
        loop {
            if this.pending_pos < this.pending.len() {
                let n = (this.pending.len() - this.pending_pos).min(out.remaining());
                out.put_slice(&this.pending[this.pending_pos..this.pending_pos + n]);
                this.pending_pos += n;
                if this.pending_pos == this.pending.len() {
                    this.pending.clear();
                    this.pending_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                return Poll::Ready(Ok(()));
            }
            if this.direct_read {
                return Pin::new(this.raw()).poll_read(cx, out);
            }
            if !this.within_padding && this.filter.packets_to_filter <= 0 && this.response_done {
                return Pin::new(&mut this.tls).poll_read(cx, out);
            }
            if !ready!(this.poll_fill(cx))? {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.failed {
            return Poll::Ready(Err(invalid("Vision stream failed")));
        }
        let result = self.poll_read_inner(cx, out);
        if matches!(result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }
}

impl VisionStream {
    /// 等同于 Go 版的 `Write(nil)`：发请求首部与一个空内容的填充块。
    fn write_nil(&mut self) {
        if self.filter.packets_to_filter > 0 {
            self.filter.filter(&[]);
        }
        self.encode_padded(&[]);
    }
}

impl VisionStream {
    // 写侧状态（is_padding / direct_write / write_uuid）在出错前可能已推进、部分字节已上线，
    // 出错后重试会重复发送，所以任何写错误都把整条流置为失败（与 VMess 编码失败的语义一致）。
    fn write_inner(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self;
        ready!(this.poll_drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.filter.packets_to_filter > 0 {
            this.filter.filter(data);
        }
        if this.is_padding {
            // 填充块的内容长度是 u16，Xray 的缓冲是 8 KiB：每次最多接受一个缓冲的数据
            let data = &data[..data.len().min(CHUNK)];
            this.encode_padded(data);
            // 已编码进待写缓冲即视为接受；后续写 / 刷新时写完
            match this.poll_drain(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                _ => return Poll::Ready(Ok(data.len())),
            }
        }
        if this.direct_write {
            Pin::new(this.raw()).poll_write(cx, data)
        } else {
            Pin::new(&mut this.tls).poll_write(cx, data)
        }
    }

    fn flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self;
        ready!(this.poll_drain(cx))?;
        if this.direct_write {
            Pin::new(this.raw()).poll_flush(cx)
        } else {
            Pin::new(&mut this.tls).poll_flush(cx)
        }
    }

    fn shutdown_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self;
        ready!(this.poll_drain(cx))?;
        if this.direct_write {
            Pin::new(this.raw()).poll_shutdown(cx)
        } else {
            Pin::new(&mut this.tls).poll_shutdown(cx)
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = self.write_inner(cx, data);
        if matches!(result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = self.flush_inner(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = self.shutdown_inner(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }
}

#[cfg(test)]
#[path = "vision_stream_tests.rs"]
mod stream_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn record_reader_never_reads_past_a_record() {
        let (mut peer, ours) = tokio::io::duplex(1 << 16);
        // 两条记录，后面跟原始字节
        let mut wire = vec![23, 3, 3, 0, 3, b'a', b'b', b'c', 23, 3, 3, 0, 1, b'd'];
        wire.extend_from_slice(b"RAW");
        peer.write_all(&wire).await.unwrap();
        let mut rr = RecordReader::new(ours);
        let mut buf = [0u8; 64];
        let mut got = Vec::new();
        // 受限模式：读两条记录，每次读取都不越过记录边界
        while got.len() < 14 {
            let n = rr.read(&mut buf).await.unwrap();
            assert!(n > 0);
            let before = got.len();
            got.extend_from_slice(&buf[..n]);
            assert!(
                before < 8 && got.len() <= 8 || before >= 8 && got.len() <= 14,
                "{before} {}",
                got.len()
            );
        }
        assert_eq!(&got[..], &wire[..14]);
        rr.unlimit();
        let n = rr.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"RAW");
    }

    #[tokio::test]
    async fn record_reader_handles_split_headers() {
        let (mut peer, ours) = tokio::io::duplex(1 << 16);
        let task = tokio::spawn(async move {
            for b in [23u8, 3, 3, 0, 2, b'x', b'y'] {
                peer.write_all(&[b]).await.unwrap();
                tokio::task::yield_now().await;
            }
            peer
        });
        let mut rr = RecordReader::new(ours);
        let mut got = vec![0u8; 7];
        rr.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [23, 3, 3, 0, 2, b'x', b'y']);
        drop(task.await.unwrap());
    }

    #[test]
    fn padding_roundtrip_across_chunk_boundaries() {
        let uuid = [9u8; 16];
        let mut wire = Vec::new();
        pad(Some(uuid), b"hello", COMMAND_CONTINUE, true, &mut wire);
        pad(None, b"world", COMMAND_END, false, &mut wire);
        wire.extend_from_slice(b"-plain");
        // 任意切分读取块，内容与命令都不变
        for step in [1usize, 3, 5, 7, 64, 4096] {
            let mut u = Unpad::new(uuid);
            let mut got = Vec::new();
            for chunk in wire.chunks(step) {
                u.unpad(chunk, &mut got).unwrap();
            }
            u.finish(&mut got).unwrap();
            assert_eq!(got, b"helloworld-plain", "step {step}");
            assert_eq!(u.current_command, COMMAND_END);
        }
        // 没有 UUID 前缀的数据原样通过
        let mut u = Unpad::new(uuid);
        let mut got = Vec::new();
        u.unpad(b"not padded data here!!", &mut got).unwrap();
        assert_eq!(got, b"not padded data here!!");
    }

    #[test]
    fn padding_lengths_follow_the_reference() {
        for _ in 0..50 {
            let mut out = Vec::new();
            pad(None, &[1; 100], COMMAND_CONTINUE, true, &mut out);
            let padding = (out[3] as usize) << 8 | out[4] as usize;
            assert!((800..1300).contains(&padding), "{padding}");
            out.clear();
            pad(None, &[1; 2000], COMMAND_CONTINUE, true, &mut out);
            let padding = (out[3] as usize) << 8 | out[4] as usize;
            assert!(padding < 256);
        }
    }

    #[test]
    fn filter_detects_tls13_server_hello() {
        let mut f = Filter::new([7; 16]);
        // ClientHello
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x40, 0x01];
        ch.resize(70, 0);
        f.filter(&ch);
        assert!(f.is_tls);
        // ServerHello：session ID 32 字节，cipher 0x1301，扩展里有 supported_versions = TLS 1.3
        let mut sh = vec![0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0, 0, 0x76, 0x03, 0x03];
        sh.extend_from_slice(&[0; 32]); // random
        sh.push(32); // session id len at index 43
        sh.extend_from_slice(&[0; 32]);
        sh.extend_from_slice(&[0x13, 0x01, 0x00]);
        sh.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        sh.resize(0x7a + 5, 0);
        f.filter(&sh);
        assert!(f.enable_xtls);
        assert_eq!(f.packets_to_filter, 0);
        // CCM_8 不允许直写
        let mut f2 = Filter::new([7; 16]);
        let mut sh2 = sh.clone();
        sh2[43 + 33] = 0x13;
        sh2[43 + 34] = 0x05;
        f2.filter(&sh2);
        assert!(!f2.enable_xtls);
    }
}
