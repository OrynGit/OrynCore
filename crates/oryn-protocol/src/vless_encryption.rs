// 协议移植：XTLS/Xray-core proxy/vless/encryption/{client,common,xor}.go
// commit d2758a023cd7f4174a5a5fa4ff66e487d4342ba0（v1.260327.0）。
// 原文件未另列作者版权；保留仓库许可声明：
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
// Oryn：只移植协议，使用有界、可取消的 Rust 流，票据每出站一份。

use aes::cipher::{KeyIvInit, StreamCipher};
use ml_kem::{
    kem::{Decapsulate, KeyExport},
    MlKem768,
};
use oryn_config::{EncryptionMode, EncryptionPadding, VlessEncryptionSpec};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

type Ctr = ctr::Ctr128BE<aes::Aes256>;
const MAX_FRAME: usize = 8192;
const MAX_CIPHERTEXT: usize = 16640;
const MAX_NONCE: [u8; 12] = [255; 12];
const DEFAULT_PADDING: [EncryptionPadding; 3] = [
    EncryptionPadding {
        probability: 100,
        min: 111,
        max: 1111,
    },
    EncryptionPadding {
        probability: 75,
        min: 0,
        max: 111,
    },
    EncryptionPadding {
        probability: 50,
        min: 0,
        max: 3333,
    },
];

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("random source failed"))?;
    Ok(bytes)
}
fn derive(context: &[u8], material: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key_bytes(context);
    hasher.update(material);
    Zeroizing::new(*hasher.finalize().as_bytes())
}
fn ctr(material: &[u8], iv: &[u8; 16]) -> Ctr {
    let key = derive(b"VLESS", material);
    Ctr::new((&*key).into(), iv.into())
}
fn x25519(secret: &StaticSecret, public: &[u8]) -> io::Result<Zeroizing<[u8; 32]>> {
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("invalid X25519 key length"))?;
    let shared = secret.diffie_hellman(&PublicKey::from(public));
    if !shared.was_contributory() {
        return Err(invalid("invalid X25519 low-order key"));
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

struct AeadState {
    key: aead::LessSafeKey,
    nonce: [u8; 12],
}
impl AeadState {
    fn new(context: &[u8], material: &[u8]) -> Self {
        let bytes = derive(context, material);
        Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, &*bytes).expect("AES key length"),
            ),
            nonce: [0; 12],
        }
    }
    /// Xray 在使用前递增，首条记录使用 nonce 1。
    fn next_nonce(&mut self) -> aead::Nonce {
        for byte in self.nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        aead::Nonce::assume_unique_for_key(self.nonce)
    }
    fn seal(&mut self, aad: &[u8], plain: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next_nonce();
        let mut bytes = plain.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut bytes)
            .map_err(|_| invalid("VLESS Encryption seal failed"))?;
        Ok(bytes)
    }
    fn open(
        &mut self,
        aad: &[u8],
        ciphertext: &[u8],
        fixed: Option<[u8; 12]>,
    ) -> io::Result<Vec<u8>> {
        let nonce = match fixed {
            Some(n) => aead::Nonce::assume_unique_for_key(n),
            None => self.next_nonce(),
        };
        let mut bytes = Zeroizing::new(ciphertext.to_vec());
        let plain = self
            .key
            .open_in_place(nonce, aead::Aad::from(aad), &mut bytes)
            .map_err(|_| invalid("VLESS Encryption authentication failed"))?;
        Ok(plain.to_vec())
    }
    /// 把 `out[start..]` 原地加密并在末尾追加标签：记录直接在发送缓冲里成形，不另分配。
    fn seal_tail(&mut self, aad: &[u8], out: &mut Vec<u8>, start: usize) -> io::Result<()> {
        let nonce = self.next_nonce();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), &mut out[start..])
            .map_err(|_| invalid("VLESS Encryption seal failed"))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }
    /// 原地解密「密文 + 标签」，`buf` 截断为明文。
    fn open_vec(&mut self, aad: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.next_nonce();
        let n = self
            .key
            .open_in_place(nonce, aead::Aad::from(aad), buf)
            .map_err(|_| invalid("VLESS Encryption authentication failed"))?
            .len();
        buf.truncate(n);
        Ok(())
    }
}

struct Ticket {
    key: Zeroizing<[u8; 64]>,
    value: Zeroizing<[u8; 16]>,
    expires: Instant,
}
type Tickets = Arc<Mutex<Option<Arc<Ticket>>>>;

/// 一个出站的握手配置与有界票据缓存，所有并发 Flow 共用它。
pub struct Client {
    spec: VlessEncryptionSpec,
    tickets: Tickets,
}
impl Client {
    pub fn new(spec: VlessEncryptionSpec) -> Self {
        Self {
            spec,
            tickets: Arc::default(),
        }
    }

    fn relays(&self, iv: &[u8; 16]) -> io::Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        let mut wire = Vec::with_capacity(self.spec.keys.len() * 1120);
        let mut last_ctr: Option<Ctr> = None;
        let mut final_key = Zeroizing::new([0; 32]);
        for (i, public) in self.spec.keys.iter().enumerate() {
            let (mut relay, shared) = if public.len() == 32 {
                let seed = Zeroizing::new(random::<32>()?);
                let secret = StaticSecret::from(*seed);
                (
                    PublicKey::from(&secret).as_bytes().to_vec(),
                    x25519(&secret, public)?,
                )
            } else {
                let bytes = ml_kem::Key::<ml_kem::EncapsulationKey768>::try_from(public.as_slice())
                    .map_err(|_| invalid("invalid ML-KEM key size"))?;
                let key = ml_kem::EncapsulationKey768::new(&bytes)
                    .map_err(|_| invalid("invalid ML-KEM public key"))?;
                let entropy = Zeroizing::new(random::<32>()?);
                let (ciphertext, shared) = key.encapsulate_deterministic(&(*entropy).into());
                (
                    ciphertext.to_vec(),
                    Zeroizing::new(shared.as_slice().try_into().expect("shared key size")),
                )
            };
            if self.spec.mode != EncryptionMode::Native {
                ctr(public, iv).apply_keystream(&mut relay);
            }
            if let Some(last) = last_ctr.as_mut() {
                last.apply_keystream(&mut relay[..32]);
            }
            wire.extend_from_slice(&relay);
            if let Some(next) = self.spec.keys.get(i + 1) {
                let mut c = ctr(shared.as_ref(), iv);
                let mut hash = *blake3::hash(next).as_bytes();
                c.apply_keystream(&mut hash);
                wire.extend_from_slice(&hash);
                last_ctr = Some(c);
            }
            final_key = shared;
        }
        Ok((wire, final_key))
    }

    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut io: S,
    ) -> io::Result<EncryptedStream<S>> {
        let iv = random::<16>()?;
        let (relays, nfs) = self.relays(&iv)?;
        let mut hello = iv.to_vec();
        hello.extend_from_slice(&relays);
        let mut nfs_aead = AeadState::new(&iv, nfs.as_ref());
        let ticket = if self.spec.zero_rtt {
            let mut slot = self.tickets.lock().unwrap();
            if slot.as_ref().is_some_and(|t| Instant::now() >= t.expires) {
                *slot = None;
            }
            slot.clone()
        } else {
            None
        };
        if let Some(ticket) = ticket {
            let mut united = Zeroizing::new([0; 96]);
            united[..64].copy_from_slice(ticket.key.as_ref());
            united[64..].copy_from_slice(nfs.as_ref());
            hello.extend(nfs_aead.seal(&[], &32u16.to_be_bytes())?);
            let encrypted_ticket = nfs_aead.seal(&[], ticket.value.as_ref())?;
            hello.extend_from_slice(&encrypted_ticket);
            let tx = AeadState::new(&encrypted_ticket, united.as_ref());
            io.write_all(&hello).await?;
            io.flush().await?;
            let mut stream = EncryptedStream::new(io, united, tx, None);
            if self.spec.mode == EncryptionMode::Random {
                stream.tx_ctr = Some(ctr(stream.united.as_ref(), &iv));
                stream.random_mode = true;
            }
            stream.resume = Some((self.tickets.clone(), ticket));
            return Ok(stream);
        }

        let seed = Zeroizing::new(random::<64>()?);
        let pfs_dk = ml_kem::DecapsulationKey768::from_seed((*seed).into());
        let xseed = Zeroizing::new(random::<32>()?);
        let pfs_x = StaticSecret::from(*xseed);
        let mut pfs_public = pfs_dk.encapsulation_key().to_bytes().to_vec();
        pfs_public.extend_from_slice(PublicKey::from(&pfs_x).as_bytes());
        hello.extend(nfs_aead.seal(&[], &1232u16.to_be_bytes())?);
        hello.extend(nfs_aead.seal(&[], &pfs_public)?);
        let (lengths, gaps) = padding(&self.spec.padding)?;
        let total = lengths.iter().sum::<usize>();
        let before_padding = hello.len();
        hello.extend(nfs_aead.seal(&[], &((total - 18) as u16).to_be_bytes())?);
        hello.extend(nfs_aead.seal(&[], &vec![0; total - 34])?);
        let mut offset = 0;
        for (i, n) in lengths.into_iter().enumerate() {
            let n = n + if i == 0 { before_padding } else { 0 };
            io.write_all(&hello[offset..offset + n]).await?;
            io.flush().await?;
            offset += n;
            if let Some(ms) = gaps.get(i) {
                tokio::time::sleep(Duration::from_millis(*ms as u64)).await;
            }
        }
        let mut response = [0; 1136];
        io.read_exact(&mut response).await?;
        let server_pfs = Zeroizing::new(nfs_aead.open(&[], &response, Some(MAX_NONCE))?);
        let ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(&server_pfs[..1088])
            .map_err(|_| invalid("invalid ML-KEM ciphertext"))?;
        let shared = pfs_dk.decapsulate(&ciphertext);
        let xshared = x25519(&pfs_x, &server_pfs[1088..])?;
        let mut united = Zeroizing::new([0; 96]);
        united[..32].copy_from_slice(shared.as_slice());
        united[32..64].copy_from_slice(xshared.as_ref());
        united[64..].copy_from_slice(nfs.as_ref());
        let tx = AeadState::new(&pfs_public, united.as_ref());
        let mut rx = AeadState::new(&server_pfs, united.as_ref());
        let mut encrypted_ticket = [0; 32];
        io.read_exact(&mut encrypted_ticket).await?;
        let ticket = Zeroizing::new(rx.open(&[], &encrypted_ticket, None)?);
        let mut encrypted_length = [0; 18];
        io.read_exact(&mut encrypted_length).await?;
        let len = rx.open(&[], &encrypted_length, None)?;
        let pad_len = u16::from_be_bytes([len[0], len[1]]) as usize;
        if pad_len < 16 {
            return Err(invalid("invalid VLESS Encryption padding length"));
        }
        let mut pad = vec![0; pad_len];
        io.read_exact(&mut pad).await?;
        rx.open(&[], &pad, None)?;
        let seconds = u16::from_be_bytes([ticket[0], ticket[1]]);
        if self.spec.zero_rtt && seconds > 0 {
            *self.tickets.lock().unwrap() = Some(Arc::new(Ticket {
                key: Zeroizing::new(united[..64].try_into().expect("PFS key size")),
                value: Zeroizing::new(ticket.as_slice().try_into().expect("ticket size")),
                expires: Instant::now() + Duration::from_secs(seconds as u64),
            }));
        }
        let mut stream = EncryptedStream::new(io, united, tx, Some(rx));
        if self.spec.mode == EncryptionMode::Random {
            stream.tx_ctr = Some(ctr(stream.united.as_ref(), &iv));
            stream.rx_ctr = Some(ctr(
                stream.united.as_ref(),
                ticket.as_slice().try_into().expect("ticket size"),
            ));
        }
        Ok(stream)
    }
}

fn between(a: u16, b: u16) -> io::Result<usize> {
    let (lo, hi) = (a.min(b) as u32, a.max(b) as u32);
    if hi == lo {
        return Ok(lo as usize);
    }
    let span = hi - lo;
    let limit = u32::MAX - (u32::MAX % span);
    loop {
        let n = u32::from_le_bytes(random()?);
        if n < limit {
            return Ok((lo + n % span) as usize);
        }
    }
}
fn padding(spec: &[EncryptionPadding]) -> io::Result<(Vec<usize>, Vec<usize>)> {
    let mut lengths = Vec::new();
    let mut gaps = Vec::new();
    for (i, p) in if spec.is_empty() {
        &DEFAULT_PADDING[..]
    } else {
        spec
    }
    .iter()
    .enumerate()
    {
        // between(0, 100) 落在 [0, 100)：probability = 0 永不填充，100 总是填充
        let n = if between(0, 100)? < p.probability as usize {
            between(p.min, p.max)?
        } else {
            0
        };
        if i % 2 == 0 {
            lengths.push(n);
        } else {
            gaps.push(n);
        }
    }
    Ok((lengths, gaps))
}

/// 双向记录状态；任何时刻每方向只缓存一个有上限的记录，不启动后台任务。
pub struct EncryptedStream<S> {
    io: S,
    united: Zeroizing<[u8; 96]>,
    tx: AeadState,
    rx: Option<AeadState>,
    tx_ctr: Option<Ctr>,
    rx_ctr: Option<Ctr>,
    random_mode: bool,
    random: [u8; 16],
    random_read: usize,
    header: [u8; 5],
    header_read: usize,
    /// 收到的记录密文；原地解密后与 `plain` 交换，两块缓冲轮流复用。
    body: Zeroizing<Vec<u8>>,
    body_read: usize,
    plain: Zeroizing<Vec<u8>>,
    plain_pos: usize,
    pending: Vec<u8>,
    pending_pos: usize,
    read_failed: bool,
    write_failed: bool,
    write_closed: bool,
    was_resumed: bool,
    resume: Option<(Tickets, Arc<Ticket>)>,
}
impl<S> EncryptedStream<S> {
    fn new(io: S, united: Zeroizing<[u8; 96]>, tx: AeadState, rx: Option<AeadState>) -> Self {
        let was_resumed = rx.is_none();
        Self {
            write_closed: false,
            was_resumed,
            io,
            united,
            tx,
            rx,
            tx_ctr: None,
            rx_ctr: None,
            random_mode: false,
            random: [0; 16],
            random_read: 0,
            header: [0; 5],
            header_read: 0,
            body: Zeroizing::new(Vec::new()),
            body_read: 0,
            plain: Zeroizing::new(Vec::new()),
            plain_pos: 0,
            pending: Vec::new(),
            pending_pos: 0,
            read_failed: false,
            write_failed: false,
            resume: None,
        }
    }
    /// 测试和诊断可确认这次连接是否使用了票据，不暴露票据内容。
    pub fn resumed(&self) -> bool {
        self.was_resumed
    }
    fn invalidate_ticket(&mut self) {
        if let Some((slot, ticket)) = self.resume.take() {
            let mut slot = slot.lock().unwrap();
            if slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &ticket))
            {
                *slot = None;
            }
        }
    }
}
impl<S: AsyncRead + Unpin> EncryptedStream<S> {
    fn read_record(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.plain_pos < self.plain.len() {
            let n = out.remaining().min(self.plain.len() - self.plain_pos);
            out.put_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
            self.plain_pos += n;
            return Poll::Ready(Ok(()));
        }
        if self.rx.is_none() {
            ready!(fill(
                &mut self.io,
                cx,
                &mut self.random,
                &mut self.random_read,
                false
            ))?;
            self.rx = Some(AeadState::new(&self.random, self.united.as_ref()));
            if self.random_mode {
                self.rx_ctr = Some(ctr(self.united.as_ref(), &self.random));
            }
        }
        if self.body.is_empty() {
            let complete = ready!(fill(
                &mut self.io,
                cx,
                &mut self.header,
                &mut self.header_read,
                true
            ))?;
            if !complete {
                // 已读到服务端 random 才会走到这里：票据已被接受，记录边界上的干净关闭不失效票据。
                // 拒绝路径（读 random 时断开、记录截断或认证失败）仍在 poll_read 的错误分支里失效。
                self.resume = None;
                return Poll::Ready(Ok(()));
            }
            if let Some(c) = self.rx_ctr.as_mut() {
                c.apply_keystream(&mut self.header);
            }
            let n = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
            if self.header[..3] != [23, 3, 3] || !(17..=MAX_CIPHERTEXT).contains(&n) {
                return Poll::Ready(Err(invalid("invalid VLESS Encryption record header")));
            }
            self.body.resize(n, 0);
        }
        ready!(fill(
            &mut self.io,
            cx,
            &mut self.body,
            &mut self.body_read,
            false
        ))?;
        let rx = self.rx.as_mut().expect("initialized receiver");
        let rekey = rx.nonce == MAX_NONCE;
        // 换钥的上下文要用解密前的密文
        let context = rekey.then(|| {
            let mut context = self.header.to_vec();
            context.extend_from_slice(&self.body);
            context
        });
        rx.open_vec(&self.header, &mut self.body)?;
        std::mem::swap(&mut *self.plain, &mut *self.body);
        if let Some(context) = context {
            self.rx = Some(AeadState::new(&context, self.united.as_ref()));
        }
        self.resume = None;
        self.header_read = 0;
        self.body.clear();
        self.body_read = 0;
        self.plain_pos = out.remaining().min(self.plain.len());
        out.put_slice(&self.plain[..self.plain_pos]);
        Poll::Ready(Ok(()))
    }
}
fn fill<S: AsyncRead + Unpin>(
    io: &mut S,
    cx: &mut Context<'_>,
    data: &mut [u8],
    pos: &mut usize,
    clean_eof: bool,
) -> Poll<io::Result<bool>> {
    while *pos < data.len() {
        let mut buf = ReadBuf::new(&mut data[*pos..]);
        ready!(Pin::new(&mut *io).poll_read(cx, &mut buf))?;
        if buf.filled().is_empty() {
            return if clean_eof && *pos == 0 {
                Poll::Ready(Ok(false))
            } else {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated VLESS Encryption record",
                )))
            };
        }
        *pos += buf.filled().len();
    }
    Poll::Ready(Ok(true))
}
impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.read_failed {
            return Poll::Ready(Err(invalid("VLESS Encryption reader failed")));
        }
        let result = this.read_record(cx, out);
        if let Poll::Ready(Err(_)) = result {
            this.read_failed = true;
            this.invalidate_ticket();
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> EncryptedStream<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "VLESS Encryption writer failed",
            )));
        }
        while self.pending_pos < self.pending.len() {
            match ready!(Pin::new(&mut self.io).poll_write(cx, &self.pending[self.pending_pos..])) {
                Ok(0) => {
                    self.write_failed = true;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Ok(n) => self.pending_pos += n,
                Err(err) => {
                    self.write_failed = true;
                    return Poll::Ready(Err(err));
                }
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(MAX_FRAME);
        let len = (n + 16) as u16;
        let mut header = [23, 3, 3, (len >> 8) as u8, len as u8];
        let rekey = this.tx.nonce == MAX_NONCE;
        // 首部（明文，作 AAD）+ 负载直接写进发送缓冲，负载原地加密
        let at = this.pending.len();
        this.pending.extend_from_slice(&header);
        this.pending.extend_from_slice(&data[..n]);
        this.tx.seal_tail(&header, &mut this.pending, at + header.len())?;
        if rekey {
            this.tx = AeadState::new(&this.pending[at..], this.united.as_ref());
        }
        if let Some(c) = this.tx_ctr.as_mut() {
            c.apply_keystream(&mut header);
            this.pending[at..at + header.len()].copy_from_slice(&header);
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        match Pin::new(&mut this.io).poll_flush(cx) {
            Poll::Ready(Err(err)) => {
                this.write_failed = true;
                Poll::Ready(Err(err))
            }
            result => result,
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        this.write_closed = true;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "vless_encryption_tests.rs"]
mod tests;
