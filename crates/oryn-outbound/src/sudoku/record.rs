// 线格式移植自 MetaCubeX/mihomo transport/sudoku/{session_keys,handshake_kip,kip}.go、crypto/record_conn.go
// @ 88dcbf7f1614a67c3b36b848ee3592dfa92ada36，GPL-3.0；原文件未单列版权声明。
// Oryn：增量读取、有界缓冲、写入取消安全，保留 epoch / seq / rekey 语义。
use super::{
    bad, random,
    table::{Decoder, Table},
};
use crate::BoxStream;
use ring::{aead, digest, hkdf, hmac};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub fn sha(data: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, data)
        .as_ref()
        .try_into()
        .unwrap()
}
struct Size;
impl hkdf::KeyType for Size {
    fn len(&self) -> usize {
        32
    }
}
fn expand(prk: &hkdf::Prk, label: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    prk.expand(&[label], Size).unwrap().fill(&mut out).unwrap();
    out
}
pub fn bases(seed: &str) -> ([u8; 32], [u8; 32]) {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &sha(seed.as_bytes()));
    (
        expand(&prk, b"sudoku-psk-c2s"),
        expand(&prk, b"sudoku-psk-s2c"),
    )
}
pub fn session_keys(seed: &str, shared: &[u8; 32], nonce: &[u8; 16]) -> ([u8; 32], [u8; 32]) {
    let mut ikm = shared.to_vec();
    ikm.extend_from_slice(nonce);
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &sha(seed.as_bytes())).extract(&ikm);
    (
        expand(&prk, b"sudoku-session-c2s"),
        expand(&prk, b"sudoku-session-s2c"),
    )
}
pub fn kip(kind: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    let len = u16::try_from(payload.len()).map_err(|_| bad("Sudoku KIP payload too large"))?;
    let mut out = b"kip".to_vec();
    out.push(kind);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}
fn counters() -> io::Result<(u32, u64)> {
    let epoch = u32::from_be_bytes(random()?);
    let seq = u64::from_be_bytes(random()?);
    Ok((epoch.clamp(1, u32::MAX - 1), seq.clamp(1, u64::MAX - 1)))
}
struct Direction {
    base: [u8; 32],
    epoch: u32,
    seq: u64,
    cipher: Option<(u32, aead::LessSafeKey)>,
    initialized: bool,
    bytes: u64,
}
impl Direction {
    fn new(base: [u8; 32]) -> io::Result<Self> {
        let (epoch, seq) = counters()?;
        Ok(Self {
            base,
            epoch,
            seq,
            cipher: None,
            initialized: false,
            bytes: 0,
        })
    }
    fn cipher(&mut self, method: &str, epoch: u32) -> io::Result<&aead::LessSafeKey> {
        if self.cipher.as_ref().is_none_or(|(e, _)| *e != epoch) {
            let mut material = b"sudoku-record:".to_vec();
            material.extend_from_slice(method.as_bytes());
            material.extend_from_slice(&epoch.to_be_bytes());
            let key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &self.base), &material);
            let algo = if method == "aes-128-gcm" {
                &aead::AES_128_GCM
            } else {
                &aead::CHACHA20_POLY1305
            };
            let key = aead::UnboundKey::new(algo, &key.as_ref()[..algo.key_len()])
                .map_err(|_| bad("Sudoku cipher key failed"))?;
            self.cipher = Some((epoch, aead::LessSafeKey::new(key)));
        }
        Ok(&self.cipher.as_ref().unwrap().1)
    }
}
pub struct Security {
    table: Arc<Table>,
    decoder: Decoder,
    padding: u8,
    method: String,
    tx: Direction,
    rx: Direction,
    wire: Vec<u8>,
    plain: Vec<u8>,
    plain_at: usize,
}
impl Security {
    pub fn new(
        table: Arc<Table>,
        packed: bool,
        min: u8,
        max: u8,
        method: String,
        seed: &str,
    ) -> io::Result<Self> {
        let (tx, rx) = bases(seed);
        // 在 u32 上算区间宽度：max = 255 时 u8 上的 `max - min + 1` 会溢出
        let span = u32::from(max).saturating_sub(u32::from(min)) + 1;
        let padding = min.saturating_add((u32::from_be_bytes(random()?) % span) as u8);
        Ok(Self {
            decoder: Decoder::new(table.clone(), packed),
            table,
            padding,
            method,
            tx: Direction::new(tx)?,
            rx: Direction::new(rx)?,
            wire: Vec::new(),
            plain: Vec::new(),
            plain_at: 0,
        })
    }
    pub fn encode(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        if plaintext.len() > 4096 {
            return Err(bad("Sudoku write chunk exceeds 4096 bytes"));
        }
        if self.method == "none" {
            return self.table.encode(plaintext, self.padding);
        }
        let mut header = [0; 12];
        header[..4].copy_from_slice(&self.tx.epoch.to_be_bytes());
        header[4..].copy_from_slice(&self.tx.seq.to_be_bytes());
        self.tx.seq = self
            .tx
            .seq
            .checked_add(1)
            .ok_or_else(|| bad("Sudoku sequence exhausted"))?;
        let cipher = self.tx.cipher(&self.method, self.tx.epoch)?;
        let mut encrypted = plaintext.to_vec();
        cipher
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(header),
                aead::Aad::from(header),
                &mut encrypted,
            )
            .map_err(|_| bad("Sudoku encryption failed"))?;
        let mut frame = ((encrypted.len() + 12) as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&encrypted);
        self.tx.bytes += plaintext.len() as u64;
        if self.tx.bytes >= 32 * 1024 * 1024 {
            self.tx.epoch = self
                .tx
                .epoch
                .checked_add(1)
                .ok_or_else(|| bad("Sudoku epoch exhausted"))?;
            self.tx.seq = counters()?.1;
            self.tx.bytes = 0;
        }
        self.table.encode(&frame, self.padding)
    }
    pub fn rekey(&mut self, tx: [u8; 32], rx: [u8; 32]) -> io::Result<()> {
        if self.plain_at != self.plain.len() || !self.wire.is_empty() {
            return Err(bad("unexpected Sudoku bytes across rekey"));
        }
        self.tx = Direction::new(tx)?;
        self.rx = Direction::new(rx)?;
        Ok(())
    }
    fn next_plain(&mut self) -> io::Result<bool> {
        if self.plain_at < self.plain.len() {
            return Ok(true);
        }
        self.plain.clear();
        self.plain_at = 0;
        if self.method == "none" {
            if self.wire.is_empty() {
                return Ok(false);
            }
            std::mem::swap(&mut self.plain, &mut self.wire);
            return Ok(true);
        }
        if self.wire.len() < 2 {
            return Ok(false);
        }
        let length = usize::from(u16::from_be_bytes([self.wire[0], self.wire[1]]));
        if length < 28 {
            return Err(bad("Sudoku encrypted record too short"));
        }
        if self.wire.len() < length + 2 {
            return Ok(false);
        }
        let header: [u8; 12] = self.wire[2..14].try_into().unwrap();
        let epoch = u32::from_be_bytes(header[..4].try_into().unwrap());
        let seq = u64::from_be_bytes(header[4..].try_into().unwrap());
        if self.rx.initialized
            && (epoch < self.rx.epoch
                || epoch == self.rx.epoch && seq != self.rx.seq
                || epoch > self.rx.epoch && epoch - self.rx.epoch > 8)
        {
            return Err(bad("Sudoku replay or out-of-order record"));
        }
        let cipher = self.rx.cipher(&self.method, epoch)?;
        let plaintext = cipher
            .open_in_place(
                aead::Nonce::assume_unique_for_key(header),
                aead::Aad::from(header),
                &mut self.wire[14..length + 2],
            )
            .map_err(|_| bad("Sudoku record authentication failed"))?;
        self.plain.extend_from_slice(plaintext);
        self.wire.drain(..length + 2);
        self.rx.epoch = epoch;
        self.rx.seq = seq
            .checked_add(1)
            .ok_or_else(|| bad("Sudoku receive sequence exhausted"))?;
        self.rx.initialized = true;
        Ok(!self.plain.is_empty())
    }
    fn feed(&mut self, raw: &[u8]) -> io::Result<()> {
        self.decoder.feed(raw, &mut self.wire)?;
        if self.wire.len() > 65537 + 4096 {
            return Err(bad("Sudoku receive buffer limit exceeded"));
        }
        Ok(())
    }
}
pub struct SecureStream {
    inner: BoxStream,
    pub security: Security,
    pending: Vec<u8>,
    offset: usize,
    failed: bool,
}
impl SecureStream {
    pub fn new(inner: BoxStream, mut security: Security, prefix: &[u8]) -> io::Result<Self> {
        security.feed(prefix)?;
        Ok(Self {
            inner,
            security,
            pending: vec![],
            offset: 0,
            failed: false,
        })
    }
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.offset < self.pending.len() {
            let n = std::task::ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.offset..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "Sudoku write closed",
                )));
            }
            self.offset += n;
        }
        self.pending.clear();
        self.offset = 0;
        Poll::Ready(Ok(()))
    }
    fn read(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // 读方向不驱动写缓冲：split 后这样做会覆盖写方向的 waker，HTTP 背压下会死锁。
        // 握手与载体写任务负责 flush；公共 Flow 上的后台复制也会刷新写入。
        for _ in 0..32 {
            if self.security.next_plain()? {
                let n = out
                    .remaining()
                    .min(self.security.plain.len() - self.security.plain_at);
                out.put_slice(
                    &self.security.plain[self.security.plain_at..self.security.plain_at + n],
                );
                self.security.plain_at += n;
                return Poll::Ready(Ok(()));
            }
            let mut raw = [0; 4096];
            let mut buf = ReadBuf::new(&mut raw);
            std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return Poll::Ready(
                    if self.security.wire.is_empty() && !self.security.decoder.incomplete() {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated Sudoku record",
                        ))
                    },
                );
            }
            self.security.feed(buf.filled())?;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncRead for SecureStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(bad("Sudoku stream failed")));
        }
        let r = self.read(cx, out);
        if matches!(r, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        r
    }
}
impl AsyncWrite for SecureStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failed {
            return Poll::Ready(Err(bad("Sudoku stream failed")));
        }
        std::task::ready!(self.flush_pending(cx))?;
        let n = buf.len().min(4096);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        self.pending = self.security.encode(&buf[..n])?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.flush_pending(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.flush_pending(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn security() -> Security {
        let map = super::super::table::Mapping::new("test");
        let table = Arc::new(Table::new("test", "prefer_entropy", "", map));
        Security::new(table, false, 0, 0, "chacha20-poly1305".into(), "test").unwrap()
    }
    #[test]
    fn records_reject_replay_tamper_truncation_and_epoch_jumps() {
        let mut tx = security();
        let mut rx = security();
        rx.rx.base = tx.tx.base;
        let data = tx.encode(b"hello").unwrap();
        for byte in &data {
            rx.feed(&[*byte]).unwrap();
        }
        assert!(rx.next_plain().unwrap());
        assert_eq!(rx.plain, b"hello");
        rx.plain_at = 5;
        rx.feed(&data).unwrap();
        assert!(rx.next_plain().is_err());
        let mut rx = security();
        rx.rx.base = tx.tx.base;
        let mut raw = Vec::new();
        Decoder::new(tx.table.clone(), false)
            .feed(&data, &mut raw)
            .unwrap();
        raw[15] ^= 1;
        let tampered = tx.table.encode(&raw, 0).unwrap();
        rx.feed(&tampered).unwrap();
        assert!(rx.next_plain().is_err());
        let mut rx = security();
        rx.rx.base = tx.tx.base;
        rx.feed(&data[..data.len() - 4]).unwrap();
        assert!(!rx.next_plain().unwrap());
        tx.tx.bytes = 32 * 1024 * 1024 - 5;
        let data = tx.encode(b"hello").unwrap();
        let mut rx = security();
        rx.rx.base = tx.tx.base;
        rx.feed(&data).unwrap();
        rx.next_plain().unwrap();
        rx.plain_at = 5;
        let next = tx.encode(b"next").unwrap();
        rx.feed(&next).unwrap();
        assert!(rx.next_plain().unwrap());
        assert_eq!(rx.plain, b"next");
        rx.plain_at = 4;
        tx.tx.epoch += 9;
        let bad = tx.encode(b"bad").unwrap();
        rx.feed(&bad).unwrap();
        assert!(rx.next_plain().is_err());
    }
}
