// 移植自 enfein/mieru pkg/cipher/{api,cipher,keygen}.go、pkg/protocol/metadata.go、underlay_{stream,packet}.go
// @ a366b4a2d08a42178704f3126d71f82a27e014a5；Copyright (C) 2021–2026 mieru authors.
// Modified for Oryn: Rust 实现、有界缓冲与严格长度检查。
// SPDX-License-Identifier: GPL-3.0-or-later
use super::pattern::{self, Pattern};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use ring::{digest, pbkdf2};
use std::{
    io,
    num::NonZeroU32,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const CHUNK: usize = 1024;
/// 发送窗口（在途数据报个数）的上限。
pub const WINDOW: usize = 256;
/// 发送窗口的下限：同一节点上会话很多时每个会话仍有的窗口。
pub const MIN_WINDOW: usize = 32;
/// 一个节点所有活跃会话共享的发送窗口总量：1 个会话得到 WINDOW，会话越多每个越小，最低 MIN_WINDOW。
pub const WINDOW_BUDGET: usize = 512;
/// 接收窗口（可缓存的乱序数据报个数）的上限，线上窗口字段通告的就是剩余的接收空位。
/// 官方实现的发送端在途量只受它自己的拥塞窗口限制（最多 4096 段），收到端一出现缺口，
/// 缺口后面的数据就要能先存下；32 段的接收窗口在无丢包时也会丢掉三成数据报（见 docs/protocols/mieru.md）。
pub const RECV_WINDOW: usize = 1024;
/// 接收窗口的下限与节点预算：1–2 个会话各 1024 段，会话越多越小，最低 64 段；载荷不超过 1 KiB，
/// 所以一个节点缓存的乱序数据不超过约 2 MiB。
pub const MIN_RECV_WINDOW: usize = 64;
pub const RECV_BUDGET: usize = 2048;
pub fn bad(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
/// 随机字节（nonce、填充、会话 ID）。每个数据报要取三次，用系统调用的话 getentropy 是热点之一
/// （主机剖析中比 XChaCha20 还重），这里用 rand 的线程本地 CSPRNG（ChaCha12，定期从系统熵重新播种）。
pub fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut b = [0; N];
    rand::Rng::fill(&mut rand::rng(), &mut b[..]);
    Ok(b)
}

pub fn key(username: &str, password: &str, seconds: u64) -> [u8; 32] {
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(password.as_bytes());
    hash.update(&[0]);
    hash.update(username.as_bytes());
    let hashed = hash.finish();
    let rounded = ((seconds + 60) / 120) * 120;
    let salt = digest::digest(&digest::SHA256, &rounded.to_be_bytes());
    let mut out = [0; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(64).unwrap(),
        salt.as_ref(),
        hashed.as_ref(),
        &mut out,
    );
    out
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub kind: u8,
    pub id: u32,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub status: u8,
    pub payload: Vec<u8>,
}
impl Frame {
    pub fn new(kind: u8, id: u32, seq: u32, payload: Vec<u8>) -> Self {
        Self {
            kind,
            id,
            seq,
            ack: 0,
            window: WINDOW as u16,
            status: 0,
            payload,
        }
    }
    fn metadata(&self, suffix: u8) -> io::Result<[u8; 32]> {
        if self.payload.len() > u16::MAX as usize {
            return Err(bad("Mieru payload too large"));
        }
        let mut b = [0; 32];
        b[0] = self.kind;
        b[2..6].copy_from_slice(&((now() / 60) as u32).to_be_bytes());
        b[6..10].copy_from_slice(&self.id.to_be_bytes());
        b[10..14].copy_from_slice(&self.seq.to_be_bytes());
        if self.kind <= 5 {
            b[14] = self.status;
            b[15..17].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
            b[17] = suffix;
        } else {
            b[14..18].copy_from_slice(&self.ack.to_be_bytes());
            b[18..20].copy_from_slice(&self.window.to_be_bytes());
            b[22..24].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
            b[24] = suffix;
        }
        Ok(b)
    }
}

pub struct Codec {
    cipher: XChaCha20Poly1305,
    nonce: Option<[u8; 24]>,
    user: String,
    packet: bool,
    pub pattern: Pattern,
}
impl Codec {
    pub fn new(key: &[u8; 32], user: String, packet: bool, pattern: Pattern) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
            nonce: None,
            user,
            packet,
            pattern,
        }
    }
    fn increment(&mut self) -> io::Result<[u8; 24]> {
        let mut n = self.nonce.ok_or_else(|| bad("Mieru missing nonce"))?;
        for byte in n.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                self.nonce = Some(n);
                return Ok(n);
            }
        }
        Err(bad("Mieru nonce exhausted"))
    }
    fn seal(&self, nonce: &[u8; 24], data: &[u8]) -> io::Result<Vec<u8>> {
        self.cipher
            .encrypt(nonce.into(), data)
            .map_err(|_| bad("Mieru encryption failed"))
    }
    fn open(&self, nonce: &[u8; 24], data: &[u8]) -> io::Result<Vec<u8>> {
        self.cipher
            .decrypt(nonce.into(), data)
            .map_err(|_| bad("Mieru authentication failed"))
    }
    pub fn encode(&mut self, frame: &Frame) -> io::Result<Vec<u8>> {
        let first = self.nonce.is_none();
        let explicit = self.packet || first;
        let nonce = if explicit {
            let mut n = random::<24>()?;
            if first || self.pattern.nonce_all {
                self.pattern.nonce(&mut n)?;
            }
            let mut hash = digest::Context::new(&digest::SHA256);
            hash.update(self.user.as_bytes());
            hash.update(&n[..16]);
            n[20..].copy_from_slice(&hash.finish().as_ref()[..4]);
            self.nonce = Some(n);
            n
        } else {
            self.increment()?
        };
        let low = frame.kind == 6 && self.pattern.mode != 0 && !frame.payload.is_empty();
        let length = if low {
            pattern::encoded_len(frame.payload.len(), self.pattern.mode)?
        } else {
            frame.payload.len()
        };
        let mut padding = random::<255>()?;
        for byte in &mut padding {
            *byte = 32 + *byte % 95;
        }
        let rand = random::<2>()?;
        let budget = if self.packet {
            1400usize.saturating_sub(88 + length)
        } else {
            510
        };
        let prefix = if frame.kind > 5 {
            usize::from(rand[0]) % (usize::from(self.pattern.middle) + 1)
        } else {
            0
        };
        let prefix = prefix.min(budget);
        let suffix =
            (usize::from(rand[1]) % (usize::from(self.pattern.end) + 1)).min(budget - prefix);
        let mut meta = frame.metadata(suffix as u8)?;
        let mut half = 0;
        if frame.kind > 5 {
            meta[21] = prefix as u8;
        }
        if low {
            half = pattern::half_mask(self.pattern.mode)?;
            meta[0] = 10;
            meta[1] = self.pattern.mode;
            meta[22..24].copy_from_slice(&(length as u16).to_be_bytes());
            meta[25..29].copy_from_slice(&half.to_be_bytes());
            meta[29..31].copy_from_slice(&(frame.payload.len() as u16).to_be_bytes());
            meta[31] = self.pattern.rotation;
        }
        let mut out = Vec::with_capacity(length + 600);
        if explicit {
            out.extend_from_slice(&nonce);
        }
        out.extend_from_slice(&self.seal(&nonce, &meta)?);
        out.extend_from_slice(&padding[..prefix]);
        if !frame.payload.is_empty() {
            let n = if self.packet {
                nonce
            } else {
                self.increment()?
            };
            let encrypted = self.seal(&n, &frame.payload)?;
            if low {
                out.extend_from_slice(&pattern::encode(
                    &encrypted,
                    self.pattern.mode,
                    half,
                    self.pattern.rotation,
                )?);
            } else {
                out.extend_from_slice(&encrypted);
            }
        }
        out.extend_from_slice(&padding[..suffix]);
        Ok(out)
    }
    fn parse(meta: &[u8]) -> io::Result<(Frame, usize, usize, usize)> {
        if meta.len() != 32 || !matches!(meta[0], 3..=9 | 11) {
            return Err(bad("Mieru invalid server record"));
        }
        let u32_at = |p| u32::from_be_bytes(meta[p..p + 4].try_into().unwrap());
        if u32_at(2).abs_diff((now() / 60) as u32) > 1 {
            return Err(bad("Mieru stale timestamp"));
        }
        let control = meta[0] <= 5;
        let (len, prefix, suffix) = if control {
            (
                u16::from_be_bytes([meta[15], meta[16]]) as usize,
                0,
                meta[17] as usize,
            )
        } else {
            (
                u16::from_be_bytes([meta[22], meta[23]]) as usize,
                meta[21] as usize,
                meta[24] as usize,
            )
        };
        if (control && len > 1024)
            || (meta[0] != 11 && len > 32 * 1024)
            || u32_at(6) == 0
            || matches!(meta[0], 6 | 8)
        {
            return Err(bad("Mieru invalid record bounds or direction"));
        }
        if meta[0] == 11 {
            let mode = meta[1];
            let half = u32_at(25);
            let rotation = meta[31];
            let plain = usize::from(u16::from_be_bytes([meta[29], meta[30]]));
            if !(1..=4).contains(&mode)
                || plain > 32768
                || half.count_ones() != u32::from(mode + 3) * 4
                || (rotation > 15 && !rotation.is_multiple_of(16))
                || len != pattern::encoded_len(plain, mode)?
            {
                return Err(bad("Mieru invalid low entropy metadata"));
            }
        }
        Ok((
            Frame {
                kind: if meta[0] == 11 { 7 } else { meta[0] },
                id: u32_at(6),
                seq: u32_at(10),
                ack: if control { 0 } else { u32_at(14) },
                window: if control {
                    WINDOW as u16
                } else {
                    u16::from_be_bytes([meta[18], meta[19]])
                },
                status: if control { meta[14] } else { 0 },
                payload: Vec::new(),
            },
            len,
            prefix,
            suffix,
        ))
    }
    pub async fn read<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> io::Result<Frame> {
        let nonce = if self.nonce.is_none() {
            let mut n = [0; 24];
            reader.read_exact(&mut n).await?;
            self.nonce = Some(n);
            n
        } else {
            self.increment()?
        };
        let mut encrypted = [0; 48];
        reader.read_exact(&mut encrypted).await?;
        let meta = self.open(&nonce, &encrypted)?;
        let (mut frame, len, prefix, suffix) = Self::parse(&meta)?;
        let mut padding = [0; 255];
        reader.read_exact(&mut padding[..prefix]).await?;
        if len > 0 {
            let mut data = vec![0; len + 16];
            reader.read_exact(&mut data).await?;
            let n = self.increment()?;
            if meta[0] == 11 {
                data = pattern::decode(&data, &meta)?;
            }
            frame.payload = self.open(&n, &data)?;
        }
        reader.read_exact(&mut padding[..suffix]).await?;
        Ok(frame)
    }
    pub fn decode(&self, packet: &[u8]) -> io::Result<Frame> {
        if packet.len() < 72 || packet.len() > 1500 {
            return Err(bad("Mieru invalid datagram size"));
        }
        let nonce: [u8; 24] = packet[..24].try_into().unwrap();
        let meta = self.open(&nonce, &packet[24..72])?;
        let (mut frame, len, prefix, suffix) = Self::parse(&meta)?;
        let wire_len = if len == 0 { 0 } else { len + 16 };
        if packet.len() != 72 + prefix + wire_len + suffix {
            return Err(bad("Mieru invalid datagram length"));
        }
        if len > 0 {
            let data = &packet[72 + prefix..72 + prefix + wire_len];
            frame.payload = if meta[0] == 11 {
                self.open(&nonce, &pattern::decode(data, &meta)?)?
            } else {
                self.open(&nonce, data)?
            };
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_record_rejects_tampering_and_invalid_bounds() {
        let p = Pattern::new(&oryn_config::MieruTrafficPattern::default());
        let mut tx = Codec::new(&[7; 32], "oryn".into(), true, p.clone());
        let rx = Codec::new(&[7; 32], "oryn".into(), true, p);
        let frame = Frame::new(7, 123, 1, b"test".to_vec());
        let good = tx.encode(&frame).unwrap();
        assert_eq!(rx.decode(&good).unwrap().payload, b"test");
        for at in [0, 24, 40, 60, 72] {
            let mut bad = good.clone();
            bad[at] ^= 128;
            assert!(rx.decode(&bad).is_err());
        }
        for len in 0..good.len() {
            assert!(rx.decode(&good[..len]).is_err());
        }
        let mut wrong = frame.clone();
        wrong.kind = 6;
        assert!(rx.decode(&tx.encode(&wrong).unwrap()).is_err());
        let mut wrong = frame;
        wrong.id = 0;
        assert!(rx.decode(&tx.encode(&wrong).unwrap()).is_err());
    }
    #[test]
    fn key_time_rounding_is_stable_and_credentials_are_distinct() {
        assert_eq!(key("u", "p", 120), key("u", "p", 179));
        assert_ne!(key("u", "p", 179), key("u", "p", 180));
        assert_ne!(key("u", "p", 120), key("u2", "p", 120));
        assert_ne!(key("u", "p", 120), key("u", "p ", 120));
    }
}
