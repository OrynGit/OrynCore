//! Snell v4 记录层（Surge Snell v4 / v5 服务端都接受）。
//!
//! 移植自 sagernet/sing-snell snellv4/record.go，commit 20f2eaec77c328b7eb7e937fa9c894ee9c8a0057。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! 记录：[盐（仅第一条）] + 加密首部（版本 4、保留 2 字节、填充长度、载荷长度）+ 填充 + 载荷密文。
//! 只有第一条记录带初始填充（256–511 字节），填充按载荷密文的 0/1 比例生成，并与密文按偶数下标交换。
//! 每次写入的分块上限从约 1400 字节起，31 秒内连续写入时每次增加 1421，直到 0x3fff。
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, BytesMut};
use ring::rand::{SecureRandom, SystemRandom};

use super::{Aead, Frame, HEADER_CIPHER, HEADER_PLAIN, HEADER_VERSION, SALT, TAG};

pub(super) const MAX_PAYLOAD: usize = 0x3fff;
const FRAME_SIZE: usize = 1460;
const FIRST_RECORD_OVERHEAD: usize = 55;
const RESET_RECORD_OVERHEAD: usize = 39;
const INITIAL_PADDING_MIN: usize = 0x100;
const INITIAL_PADDING_SPAN: usize = 0x100;
const RESET_INTERVAL: u64 = 31;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random(buf: &mut [u8]) -> io::Result<()> {
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| io::Error::other("system random source failed"))
}

pub(super) struct Writer {
    aead: Aead,
    salt: [u8; SALT],
    salt_sent: bool,
    initial_padding: usize,
    payload_limit: usize,
    last_write: u64,
}

impl Writer {
    pub(super) fn new(psk: &[u8]) -> io::Result<Self> {
        let salt = super::random_salt()?;
        let mut r = [0u8; 2];
        random(&mut r)?;
        Ok(Self {
            aead: Aead::new(psk, &salt)?,
            salt,
            salt_sent: false,
            initial_padding: INITIAL_PADDING_MIN
                + (u16::from_le_bytes(r) as usize % INITIAL_PADDING_SPAN),
            payload_limit: 0,
            last_write: 0,
        })
    }

    fn limit_for(&self, now: u64) -> usize {
        if !self.salt_sent {
            return FRAME_SIZE - FIRST_RECORD_OVERHEAD - self.initial_padding;
        }
        if self.last_write != 0
            && now.saturating_sub(self.last_write) < RESET_INTERVAL
            && self.payload_limit > 0
        {
            return self.payload_limit;
        }
        FRAME_SIZE - RESET_RECORD_OVERHEAD
    }

    fn advance(&mut self, limit: usize, now: u64) {
        self.last_write = now;
        self.payload_limit = if limit < MAX_PAYLOAD {
            (limit + FRAME_SIZE - RESET_RECORD_OVERHEAD).min(MAX_PAYLOAD)
        } else {
            MAX_PAYLOAD
        };
    }

    fn padding_for(&self, payload_len: usize) -> usize {
        if self.salt_sent || payload_len == 0 {
            0
        } else {
            self.initial_padding
        }
    }

    pub(super) fn stream(&mut self, mut data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let now = now_unix();
        let limit = self.limit_for(now);
        self.advance(limit, now);
        while !data.is_empty() {
            let take = data.len().min(limit);
            let padding = self.padding_for(take);
            self.record(&data[..take], padding, out)?;
            data = &data[take..];
        }
        Ok(())
    }

    /// UDP：整包一条记录；超过当前分块上限的包按 sing-snell 的行为拒绝。
    pub(super) fn packet(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let now = now_unix();
        let limit = self.limit_for(now);
        if data.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: payload length exceeds maximum",
            ));
        }
        self.advance(limit, now);
        let padding = self.padding_for(data.len());
        self.record(data, padding, out)
    }

    pub(super) fn zero(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        let now = now_unix();
        let limit = self.limit_for(now);
        self.advance(limit, now);
        self.record(&[], 0, out)
    }

    fn record(&mut self, payload: &[u8], padding_len: usize, out: &mut Vec<u8>) -> io::Result<()> {
        if !self.salt_sent {
            out.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        let mut header = [0u8; HEADER_PLAIN];
        header[0] = HEADER_VERSION;
        header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.aead.seal(&header, &[]));
        if payload.is_empty() {
            return Ok(());
        }
        let mut sealed = self.aead.seal(payload, &[]);
        let mut padding = vec![0u8; padding_len];
        if padding_len > 0 {
            fill_padding(&mut padding, &sealed)?;
            let n = padding.len().min(sealed.len());
            for i in (0..n).step_by(2) {
                std::mem::swap(&mut padding[i], &mut sealed[i]);
            }
        }
        out.extend_from_slice(&padding);
        out.extend_from_slice(&sealed);
        Ok(())
    }
}

fn random_int31(source: &[u8], index: usize) -> usize {
    (u32::from_le_bytes(source[index * 4..index * 4 + 4].try_into().unwrap()) & 0x7fff_ffff)
        as usize
}

/// 让「填充 + 密文」整体的 1 比特占比落在 0.4 / 1.6 附近（只在密文自身比例偏中间时这样做）。
fn fill_padding(padding: &mut [u8], cipher: &[u8]) -> io::Result<()> {
    let counted = cipher.len() & !3;
    let ones: usize = cipher[..counted]
        .iter()
        .map(|b| b.count_ones() as usize)
        .sum();
    let zeros = 8 * cipher.len() as isize - ones as isize;
    if zeros <= 0 {
        return random(padding);
    }
    let ratio = ones as f64 / zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        return random(padding);
    }
    let base = if (zeros as usize) < ones { 0.4 } else { 1.6 };
    let mut r = [0u8; 4];
    random(&mut r)?;
    let target_ratio = base + random_int31(&r, 0) as f64 / 2_147_483_647.0 / 10.0;
    let total_bits = 8 * (padding.len() + cipher.len());
    let target_ones =
        (total_bits as f64 * (target_ratio / (target_ratio + 1.0)) - ones as f64) as isize;
    if target_ones < 0 || target_ones as usize > 8 * padding.len() {
        return random(padding);
    }
    fill_with_bit_count(padding, target_ones as usize)
}

fn fill_with_bit_count(padding: &mut [u8], one_bits: usize) -> io::Result<()> {
    let total = 8 * padding.len();
    let mut bitset = vec![0u8; total];
    for bit in bitset.iter_mut().take(one_bits) {
        *bit = 1;
    }
    let mut randomness = vec![0u8; 4 * total];
    random(&mut randomness)?;
    let mut position = 0;
    let mut remaining = total;
    while remaining > 1 {
        let divisor = 0x7fff_ffff / remaining;
        let swap = position + random_int31(&randomness, position) / (divisor + 1);
        bitset.swap(swap, position);
        position += 1;
        remaining -= 1;
    }
    padding.fill(0);
    for (index, bit) in bitset.iter().enumerate() {
        if *bit == 1 {
            padding[index / 8] |= 1 << (index % 8);
        }
    }
    Ok(())
}

pub(super) struct Reader {
    aead: Option<Aead>,
    pending: Option<(usize, usize)>,
}

impl Reader {
    pub(super) fn new() -> Self {
        Self {
            aead: None,
            pending: None,
        }
    }

    pub(super) fn parse(&mut self, psk: &[u8], buf: &mut BytesMut) -> io::Result<Option<Frame>> {
        if self.aead.is_none() {
            if buf.len() < SALT {
                return Ok(None);
            }
            let salt: [u8; SALT] = buf[..SALT].try_into().unwrap();
            buf.advance(SALT);
            self.aead = Some(Aead::new(psk, &salt)?);
        }
        let aead = self.aead.as_mut().unwrap();
        if self.pending.is_none() {
            if buf.len() < HEADER_CIPHER {
                return Ok(None);
            }
            let header = aead
                .open(&buf[..HEADER_CIPHER], &[])
                .map_err(|_| invalid("snell: open record header"))?;
            buf.advance(HEADER_CIPHER);
            if header[0] != HEADER_VERSION {
                return Err(invalid("snell: bad header version"));
            }
            let padding = u16::from_be_bytes([header[3], header[4]]) as usize;
            let payload = u16::from_be_bytes([header[5], header[6]]) as usize;
            if payload == 0 {
                return Ok(Some(Frame::Eof));
            }
            self.pending = Some((padding, payload));
        }
        let (padding_len, payload_len) = self.pending.unwrap();
        let need = padding_len + payload_len + TAG;
        if buf.len() < need {
            return Ok(None);
        }
        let mut padding = buf[..padding_len].to_vec();
        let mut sealed = buf[padding_len..need].to_vec();
        buf.advance(need);
        self.pending = None;
        let n = padding.len().min(sealed.len());
        for i in (0..n).step_by(2) {
            std::mem::swap(&mut padding[i], &mut sealed[i]);
        }
        let plain = aead
            .open(&sealed, &[])
            .map_err(|_| invalid("snell: open record payload"))?;
        Ok(Some(Frame::Data(plain)))
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_roundtrip_with_initial_padding() {
        let mut writer = Writer::new(b"psk").unwrap();
        let mut reader = Reader::new();
        let mut wire = Vec::new();
        let first: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        writer.stream(&first, &mut wire).unwrap();
        writer.stream(&[1, 2, 3], &mut wire).unwrap();
        writer.zero(&mut wire).unwrap();
        let mut buf = BytesMut::from(&wire[..]);
        let mut got = Vec::new();
        loop {
            match reader.parse(b"psk", &mut buf).unwrap() {
                Some(Frame::Data(d)) => got.extend_from_slice(&d),
                Some(Frame::Eof) => break,
                None => panic!("short"),
            }
        }
        assert_eq!(&got[..3000], &first[..]);
        assert_eq!(&got[3000..], &[1, 2, 3]);
    }

    #[test]
    fn padding_bit_count() {
        let mut padding = vec![0u8; 64];
        fill_with_bit_count(&mut padding, 100).unwrap();
        assert_eq!(padding.iter().map(|b| b.count_ones()).sum::<u32>(), 100);
    }

    #[test]
    fn packet_limit() {
        let mut writer = Writer::new(b"psk").unwrap();
        let mut out = Vec::new();
        writer.stream(&[0u8; 10], &mut out).unwrap();
        // 第一次写之后上限至少 1421 + 首条上限
        assert!(writer.packet(&[0u8; 2000], &mut out).is_ok());
        assert!(writer.packet(&[0u8; 20_000], &mut out).is_err());
    }
}
