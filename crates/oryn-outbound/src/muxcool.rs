//! Mux.Cool 的单会话封装：v2ray-plugin 开启 `mux` 时，每条 SS 连接都在 WebSocket 里作为一个
//! Mux.Cool 会话（不是多路复用）。帧格式依据 V2Ray Mux.Cool 规范。
//!
//! 来源 SagerNet/sing-vmess `mux_wrapper.go`，commit 3a8da1e3baff96ba453501e0959863fec2c30977（v0.2.7）。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
//! 改写为有界、可取消读取的 Rust 状态机；出处登记在 Oryn_dev/docs/oryncore/provenance.md。
//!
//! 写出：第一帧是 New（会话 0、TCP、目的地 `v1.mux.cool:666`，带数据），之后是 Keep 帧；
//! 读取：解析帧首部，Keep 帧的数据交给调用方，End 为 EOF，Error 选项为连接已关闭。

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_TCP: u8 = 1;
/// 每帧载荷上限。
const CHUNK: usize = 16 * 1024;
/// 元数据（会话编号之后的部分）的合理上限，防止对端用巨大的元数据拖住读取。
const MAX_METADATA: usize = 1024;
const MUX_HOST: &str = "v1.mux.cool";
const MUX_PORT: u16 = 666;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

enum Read {
    /// 读 6 字节：元数据长度（2）+ 会话编号（2）+ 状态 + 选项。
    Header([u8; 6], usize),
    /// 丢弃 Keep 帧里多出的元数据；`true` 表示之后还有数据长度要读。
    Discard(usize, bool),
    /// 读数据长度（2 字节）。
    DataLength([u8; 2], usize),
    Payload(usize),
}

pub(crate) struct MuxCool<S> {
    stream: S,
    read: Read,
    // 外层 poll_read 统一锁存 EOF / 错误，避免部分首部失败后继续解帧。
    read_terminal: Option<Option<io::ErrorKind>>,
    discard_payload: bool,
    wrote_new: bool,
    pending: Vec<u8>,
    written: usize,
}

impl<S> MuxCool<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            read: Read::Header([0; 6], 0),
            read_terminal: None,
            discard_payload: false,
            wrote_new: false,
            pending: Vec::new(),
            written: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MuxCool<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(terminal) = self.read_terminal {
            return Poll::Ready(terminal.map_or(Ok(()), |kind| Err(kind.into())));
        }
        let before = out.filled().len();
        let result = self.poll_receive(cx, out);
        match &result {
            Poll::Ready(Err(error)) => self.read_terminal = Some(Some(error.kind())),
            Poll::Ready(Ok(())) if out.filled().len() == before => {
                self.read_terminal = Some(None);
            }
            _ => {}
        }
        result
    }
}

impl<S: AsyncRead + Unpin> MuxCool<S> {
    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut self.read {
                Read::Header(buf, have) => {
                    let mut header = *buf;
                    let start = *have;
                    let mut window = ReadBuf::new(&mut header[start..]);
                    ready!(Pin::new(&mut self.stream).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return if start == 0 {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                        };
                    }
                    let have = start + got;
                    if have < 6 {
                        self.read = Read::Header(header, have);
                        continue;
                    }
                    let length = u16::from_be_bytes([header[0], header[1]]) as usize;
                    let (status, option) = (header[4], header[5]);
                    if !(4..=MAX_METADATA).contains(&length) {
                        return Poll::Ready(Err(invalid("invalid Mux.Cool frame length")));
                    }
                    let extra = length - 4;
                    let session = u16::from_be_bytes([header[2], header[3]]);
                    // 单会话封装只用会话 0；KeepAlive 不属于任何会话，不检查编号
                    if status != STATUS_KEEP_ALIVE && session != 0 {
                        return Poll::Ready(Err(invalid("unexpected Mux.Cool session id")));
                    }
                    match status {
                        STATUS_NEW => {
                            return Poll::Ready(Err(invalid("unexpected Mux.Cool new frame")))
                        }
                        // End 带 Error 表示会话因错误结束（如服务端连不上目标），不能当干净 EOF
                        STATUS_END if option & OPTION_ERROR != 0 => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "Mux.Cool peer ended the session with an error",
                            )))
                        }
                        STATUS_END => return Poll::Ready(Ok(())),
                        STATUS_KEEP | STATUS_KEEP_ALIVE => {}
                        _ => return Poll::Ready(Err(invalid("unexpected Mux.Cool frame"))),
                    }
                    if option & OPTION_ERROR != 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "Mux.Cool peer closed the session",
                        )));
                    }
                    let has_data = option & OPTION_DATA != 0;
                    self.discard_payload = status == STATUS_KEEP_ALIVE;
                    // Keep 帧里的地址等额外元数据先丢掉
                    self.read = if extra > 0 {
                        Read::Discard(extra, has_data)
                    } else if has_data {
                        Read::DataLength([0; 2], 0)
                    } else {
                        Read::Header([0; 6], 0)
                    };
                }
                Read::Discard(left, has_data) => {
                    let (left, has_data) = (*left, *has_data);
                    let mut scratch = [0u8; 256];
                    let take = left.min(scratch.len());
                    let mut window = ReadBuf::new(&mut scratch[..take]);
                    ready!(Pin::new(&mut self.stream).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let left = left - got;
                    self.read = if left > 0 {
                        Read::Discard(left, has_data)
                    } else if has_data {
                        Read::DataLength([0; 2], 0)
                    } else {
                        Read::Header([0; 6], 0)
                    };
                }
                Read::DataLength(buf, have) => {
                    let mut length = *buf;
                    let start = *have;
                    let mut window = ReadBuf::new(&mut length[start..]);
                    ready!(Pin::new(&mut self.stream).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let have = start + got;
                    self.read = if have == 2 {
                        match u16::from_be_bytes(length) as usize {
                            0 => Read::Header([0; 6], 0),
                            // 复用固定 256 字节 scratch，最大帧也不分配载荷缓冲。
                            n if self.discard_payload => Read::Discard(n, false),
                            n => Read::Payload(n),
                        }
                    } else {
                        Read::DataLength(length, have)
                    };
                }
                Read::Payload(left) => {
                    let left = *left;
                    let limit = out.remaining().min(left);
                    let before = out.filled().len();
                    let mut window = ReadBuf::new(out.initialize_unfilled_to(limit));
                    ready!(Pin::new(&mut self.stream).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    out.set_filled(before + got);
                    self.read = if got == left {
                        Read::Header([0; 6], 0)
                    } else {
                        Read::Payload(left - got)
                    };
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> MuxCool<S> {
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
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MuxCool<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(CHUNK);
        let mut frame = Vec::with_capacity(n + 32);
        if !self.wrote_new {
            self.wrote_new = true;
            let address = {
                let mut a = Vec::new();
                a.extend_from_slice(&MUX_PORT.to_be_bytes());
                a.push(0x02);
                a.push(MUX_HOST.len() as u8);
                a.extend_from_slice(MUX_HOST.as_bytes());
                a
            };
            frame.extend_from_slice(&((5 + address.len()) as u16).to_be_bytes());
            frame.extend_from_slice(&[0, 0, STATUS_NEW, OPTION_DATA, NETWORK_TCP]);
            frame.extend_from_slice(&address);
        } else {
            frame.extend_from_slice(&4u16.to_be_bytes());
            frame.extend_from_slice(&[0, 0, STATUS_KEEP, OPTION_DATA]);
        }
        frame.extend_from_slice(&(n as u16).to_be_bytes());
        frame.extend_from_slice(&data[..n]);
        self.pending = frame;
        match self.drain(cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            _ => Poll::Ready(Ok(n)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    /// 不发 End 帧：Xray / v2ray 收到 End 会关闭会话的两个方向，半关闭后对端的回复会被丢掉。
    /// 底层连接（WebSocket）的关闭就是这个单会话的结束信号。
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util as futures;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn audit_keepalive_fragmented_cancelled_then_business() {
        let (client, mut server) = duplex(1024);
        let mut c = MuxCool::new(client);
        // 非会话 KeepAlive、额外元数据和最大 u16 数据，逐字节取消读取。
        let mut wire = vec![0, 5, 12, 34, 4, 1, 99, 255, 255];
        wire.extend(std::iter::repeat_n(0x5a, 65535));
        wire.extend_from_slice(&[0, 4, 0, 0, 4, 1, 0, 0]);
        wire.extend_from_slice(&[0, 4, 0, 0, 4, 1, 0, 1, 42]);
        let mut out = [0; 8];
        for byte in wire {
            server.write_all(&[byte]).await.unwrap();
            let mut read = Box::pin(c.read(&mut out));
            assert!(matches!(futures::poll!(read.as_mut()), Poll::Pending));
        }
        server
            .write_all(&[0, 4, 0, 0, 2, 1, 0, 2, b'o', b'k'])
            .await
            .unwrap();
        assert_eq!(c.read(&mut out).await.unwrap(), 2);
        assert_eq!(&out[..2], b"ok");
    }

    #[tokio::test]
    async fn audit_end_and_truncation_are_latched() {
        for (wire, kind) in [
            (vec![0, 4, 0, 0, 3, 0, 0, 4, 0, 0, 2, 1, 0, 1, 42], None),
            (vec![0, 4, 0], Some(io::ErrorKind::UnexpectedEof)),
            (
                vec![0, 4, 0, 0, 4, 1, 0],
                Some(io::ErrorKind::UnexpectedEof),
            ),
            (
                vec![0, 4, 0, 0, 4, 1, 0, 2, 42],
                Some(io::ErrorKind::UnexpectedEof),
            ),
        ] {
            let (client, mut server) = duplex(1024);
            let mut c = MuxCool::new(client);
            server.write_all(&wire).await.unwrap();
            server.shutdown().await.unwrap();
            for _ in 0..3 {
                let mut out = [0; 8];
                let result = c.read(&mut out).await;
                match kind {
                    None => assert_eq!(result.unwrap(), 0),
                    Some(kind) => assert_eq!(result.unwrap_err().kind(), kind),
                }
            }
        }
    }

    #[tokio::test]
    async fn audit_terminal_reads_do_not_resume() {
        for (header, expected) in [
            ([0, 4, 0, 0, 3, 0], None),
            ([0, 4, 0, 0, 3, 2], Some(io::ErrorKind::ConnectionAborted)),
            ([0, 3, 0, 0, 2, 1], Some(io::ErrorKind::InvalidData)),
            ([0, 4, 0, 0, 9, 0], Some(io::ErrorKind::InvalidData)),
        ] {
            let (client, mut server) = duplex(1024);
            let mut c = MuxCool::new(client);
            let mut out = [0; 8];
            for byte in &header[..5] {
                server.write_all(&[*byte]).await.unwrap();
                let mut read = Box::pin(c.read(&mut out));
                assert!(matches!(futures::poll!(read.as_mut()), Poll::Pending));
            }
            server.write_all(&header[5..]).await.unwrap();
            server
                .write_all(&[0, 4, 0, 0, 2, 1, 0, 1, 42])
                .await
                .unwrap();
            for _ in 0..3 {
                let result = c.read(&mut out).await;
                match expected {
                    None => assert_eq!(result.unwrap(), 0),
                    Some(kind) => assert_eq!(result.unwrap_err().kind(), kind),
                }
            }
        }
    }

    #[tokio::test]
    async fn frames_match_the_reference_wrapper() {
        let (client, mut server) = duplex(64 * 1024);
        let mut c = MuxCool::new(client);
        c.write_all(b"hello").await.unwrap();
        c.write_all(b"world!").await.unwrap();
        c.flush().await.unwrap();
        // New 帧：长度 20 = 5 + 15（端口 2 + 类型 1 + 域名长度 1 + 11）
        let mut expected = vec![0, 20, 0, 0, 1, 1, 1];
        expected.extend_from_slice(&666u16.to_be_bytes());
        expected.push(2);
        expected.push(11);
        expected.extend_from_slice(b"v1.mux.cool");
        expected.extend_from_slice(&[0, 5]);
        expected.extend_from_slice(b"hello");
        // Keep 帧
        expected.extend_from_slice(&[0, 4, 0, 0, 2, 1, 0, 6]);
        expected.extend_from_slice(b"world!");
        let mut got = vec![0; expected.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn reads_keep_frames_skips_metadata_and_stops_at_end() {
        let (client, mut server) = duplex(64 * 1024);
        let mut c = MuxCool::new(client);
        let mut wire = Vec::new();
        // Keep + 数据
        wire.extend_from_slice(&[0, 4, 0, 0, 2, 1, 0, 3]);
        wire.extend_from_slice(b"abc");
        // 没有数据的 Keep
        wire.extend_from_slice(&[0, 4, 0, 0, 2, 0]);
        // KeepAlive
        wire.extend_from_slice(&[0, 4, 0, 0, 4, 0]);
        // Keep + 6 字节额外元数据 + 数据
        wire.extend_from_slice(&[0, 10, 0, 0, 2, 1, 9, 9, 9, 9, 9, 9, 0, 2]);
        wire.extend_from_slice(b"de");
        // End
        wire.extend_from_slice(&[0, 4, 0, 0, 3, 0]);
        // 一字节一字节送达
        tokio::spawn(async move {
            for b in wire {
                server.write_all(&[b]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut got = Vec::new();
        c.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"abcde");
    }

    #[tokio::test]
    async fn rejects_new_frames_error_option_and_oversized_metadata() {
        for wire in [
            vec![0, 4, 0, 0, 1, 1, 0, 1, 0],
            vec![0, 4, 0, 0, 2, 2],
            vec![0xFF, 0xFF, 0, 0, 2, 1],
            vec![0, 4, 0, 0, 9, 0],
            // End + Error：会话因错误结束
            vec![0, 4, 0, 0, 3, 2],
            // 非 0 会话编号
            vec![0, 4, 0, 1, 2, 0],
        ] {
            let (client, mut server) = duplex(1024);
            let mut c = MuxCool::new(client);
            server.write_all(&wire).await.unwrap();
            let mut b = [0u8; 4];
            assert!(c.read(&mut b).await.is_err(), "{wire:?}");
        }
    }
}
