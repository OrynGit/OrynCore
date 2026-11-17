//! sing-mux 前 16 次读写记录填充；来源 SagerNet/sing-mux padding.go。
//! commit 1c5ed1c7731c23e0308870b3ce05708e38a208f2（v0.3.3）。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use ring::rand::{SecureRandom, SystemRandom};
pub(super) struct Padding {
    stream: BoxStream,
    read: Vec<u8>,
    payload: Bytes,
    pending: Bytes,
    reads: u8,
    writes: u8,
    eof: bool,
}
impl Padding {
    pub(super) fn new(stream: BoxStream) -> Self {
        Self {
            stream,
            read: Vec::new(),
            payload: Bytes::new(),
            pending: Bytes::new(),
            reads: 0,
            writes: 0,
            eof: false,
        }
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.stream).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for Padding {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.payload.is_empty() {
                let n = out.remaining().min(self.payload.len());
                out.put_slice(&self.payload[..n]);
                self.payload.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.reads >= 16 && !self.read.is_empty() {
                self.payload = Bytes::from(std::mem::take(&mut self.read));
                continue;
            }
            if self.reads < 16 && self.read.len() >= 4 {
                let n = u16::from_be_bytes(self.read[..2].try_into().unwrap()) as usize;
                let p = u16::from_be_bytes(self.read[2..4].try_into().unwrap()) as usize;
                if n == 0 || p > 767 {
                    return Poll::Ready(Err(err("invalid mux padding record")));
                }
                if self.read.len() >= 4 + n + p {
                    self.payload = Bytes::copy_from_slice(&self.read[4..4 + n]);
                    self.read.drain(..4 + n + p);
                    self.reads += 1;
                    continue;
                }
            }
            if self.eof {
                if !self.read.is_empty() {
                    return Poll::Ready(Err(err("truncated mux padding record")));
                }
                return Poll::Ready(Ok(()));
            }
            let mut scratch = [0; 4096];
            let mut buf = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                self.eof = true;
                continue;
            }
            if self.read.len() + buf.filled().len() > 65535 + 767 + 4 + 4096 {
                return Poll::Ready(Err(err("mux padding buffer exceeded")));
            }
            self.read.extend_from_slice(buf.filled());
        }
    }
}
impl AsyncWrite for Padding {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(16384);
        if self.writes < 16 {
            let mut random = [0; 2];
            SystemRandom::new()
                .fill(&mut random)
                .map_err(|_| err("random source failed"))?;
            let pad = 256 + (u16::from_be_bytes(random) % 512) as usize;
            let mut record = (n as u16).to_be_bytes().to_vec();
            record.extend((pad as u16).to_be_bytes());
            record.extend_from_slice(&data[..n]);
            record.resize(record.len() + pad, 0);
            self.pending = record.into();
            self.writes += 1;
        } else {
            self.pending = Bytes::copy_from_slice(&data[..n]);
        }
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
