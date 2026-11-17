// 移植自 enfein/mieru apis/trafficpattern/config.go、pkg/protocol/low_entropy.go
// @ a366b4a2d08a42178704f3126d71f82a27e014a5；Copyright (C) 2026 mieru authors.
// Modified for Oryn: 有界结构、无全局缓存，使用可移植位操作。
// SPDX-License-Identifier: GPL-3.0-or-later
use super::wire::{bad, random};
use oryn_config::MieruTrafficPattern;
use std::io;
#[derive(Clone)]
pub struct Pattern {
    pub fragment: bool,
    pub sleep_ms: u8,
    pub nonce_type: u8,
    pub nonce_all: bool,
    pub nonce_min: u8,
    pub nonce_max: u8,
    pub prefixes: Vec<Vec<u8>>,
    pub middle: u8,
    pub end: u8,
    pub mode: u8,
    pub rotation: u8,
}
impl Pattern {
    pub fn new(p: &MieruTrafficPattern) -> Self {
        // 未指定 seed 时使用 Oryn 固定画像，不读取系统主机名，也不引入宿主隐私标识。
        let seed = p.seed.unwrap_or(20261002);
        let fixed = |n: u32, name: &str| {
            let text = format!("{seed}:{name}");
            let hash = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
            (u32::from_be_bytes(hash.as_ref()[..4].try_into().unwrap()) & 0x7fff_ffff) % n
        };
        let min = p.nonce_min.unwrap_or_else(|| {
            if p.unlock {
                fixed(13, "nonce.minLen") as u8
            } else {
                6 + fixed(7, "nonce.minLen") as u8
            }
        });
        let rotation = fixed(31, "lowEntropy.maskRotation") as u8;
        Self {
            fragment: p
                .fragment
                .unwrap_or(p.unlock && fixed(2, "tcpFragment.enable") == 1),
            sleep_ms: p.sleep_ms.unwrap_or_else(|| {
                if p.unlock {
                    1 + fixed(100, "tcpFragment.maxSleepMs") as u8
                } else {
                    0
                }
            }),
            nonce_type: p.nonce_type.unwrap_or_else(|| {
                if p.unlock {
                    fixed(3, "nonce.type") as u8
                } else {
                    1 + fixed(2, "nonce.type") as u8
                }
            }),
            nonce_all: p
                .nonce_all
                .unwrap_or(fixed(2, "nonce.applyToAllUDPPacket") == 1),
            nonce_min: min,
            nonce_max: p
                .nonce_max
                .unwrap_or_else(|| min + fixed(u32::from(13 - min), "nonce.maxLen") as u8),
            prefixes: p.prefixes.clone(),
            middle: p.padding_middle.unwrap_or_else(|| {
                fixed(256, "padding.maxMiddlePaddingLen").saturating_sub(128) as u8
            }),
            end: p.padding_end.unwrap_or_else(|| {
                if p.unlock {
                    fixed(256, "padding.maxEndPaddingLen") as u8
                } else {
                    255
                }
            }),
            mode: p.low_mode.unwrap_or_else(|| {
                if p.unlock {
                    fixed(5, "lowEntropy.mode") as u8
                } else {
                    0
                }
            }),
            rotation: p.low_rotation.unwrap_or(if rotation <= 15 {
                rotation
            } else {
                (rotation - 15) * 16
            }),
        }
    }
    pub fn nonce(&self, n: &mut [u8; 24]) -> io::Result<()> {
        let min = self.nonce_min.min(self.nonce_max);
        let len = usize::from(min + random::<1>()?[0] % (self.nonce_max - min + 1));
        match self.nonce_type {
            1 => {
                for b in &mut n[..len] {
                    *b = 32 + *b % 95;
                }
            }
            2 => {
                for b in &mut n[..len] {
                    *b = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                        [usize::from(*b % 64)];
                }
            }
            3 if !self.prefixes.is_empty() => {
                let prefix = &self.prefixes[usize::from(random::<1>()?[0]) % self.prefixes.len()];
                n[..prefix.len()].copy_from_slice(prefix);
            }
            _ => {}
        }
        Ok(())
    }
}
fn mask_at(half: u32, rotation: u8, index: usize) -> u64 {
    let full = (u64::from(half) << 32) | u64::from(half);
    if rotation <= 15 {
        full.rotate_right((index * usize::from(rotation)) as u32)
    } else {
        full.rotate_left((index * usize::from(rotation / 16)) as u32)
    }
}
fn deposit(mut bits: u64, mut mask: u64) -> u64 {
    let mut out = 0;
    while mask != 0 {
        let low = mask & mask.wrapping_neg();
        if bits & 1 != 0 {
            out |= low;
        }
        mask &= mask - 1;
        bits >>= 1;
    }
    out
}
fn extract(bits: u64, mut mask: u64) -> u64 {
    let mut out = 0;
    let mut place = 1;
    while mask != 0 {
        let low = mask & mask.wrapping_neg();
        if bits & low != 0 {
            out |= place;
        }
        place <<= 1;
        mask &= mask - 1;
    }
    out
}
pub fn encoded_len(len: usize, mode: u8) -> io::Result<usize> {
    if !(1..=4).contains(&mode) {
        return Err(bad("Mieru invalid low entropy mode"));
    }
    Ok(len.div_ceil(usize::from(mode) + 3) * 8)
}
pub fn half_mask(mode: u8) -> io::Result<u32> {
    let ones = u32::from(mode + 3) * 4;
    let mut mask = 0u32;
    while mask.count_ones() < ones {
        mask |= 1u32 << (random::<1>()?[0] % 32);
    }
    Ok(mask)
}
pub fn encode(ciphertext: &[u8], mode: u8, half: u32, rotation: u8) -> io::Result<Vec<u8>> {
    let body = &ciphertext[..ciphertext.len() - 16];
    let size = usize::from(mode) + 3;
    let mut out = Vec::with_capacity(encoded_len(body.len(), mode)? + 16);
    for (i, chunk) in body.chunks(size).enumerate() {
        let mut b = [0; 8];
        b[8 - chunk.len()..].copy_from_slice(chunk);
        out.extend_from_slice(
            &deposit(u64::from_be_bytes(b), mask_at(half, rotation, i)).to_be_bytes(),
        );
    }
    out.extend_from_slice(&ciphertext[ciphertext.len() - 16..]);
    Ok(out)
}
pub fn decode(ciphertext: &[u8], meta: &[u8]) -> io::Result<Vec<u8>> {
    let mode = meta[1];
    let half = u32::from_be_bytes(meta[25..29].try_into().unwrap());
    let rotation = meta[31];
    let len = usize::from(u16::from_be_bytes([meta[29], meta[30]]));
    if !(1..=4).contains(&mode)
        || len > 32768
        || half.count_ones() != u32::from(mode + 3) * 4
        || (rotation > 15 && !rotation.is_multiple_of(16))
        || ciphertext.len() != encoded_len(len, mode)? + 16
    {
        return Err(bad("Mieru invalid low entropy metadata"));
    }
    let size = usize::from(mode) + 3;
    let mut out = Vec::with_capacity(len + 16);
    let mut polarity = None;
    for (i, bytes) in ciphertext[..ciphertext.len() - 16]
        .chunks_exact(8)
        .enumerate()
    {
        let n = size.min(len - out.len());
        let word = u64::from_be_bytes(bytes.try_into().unwrap());
        let mask = mask_at(half, rotation, i);
        let data_mask = deposit((1u64 << (n * 8)) - 1, mask);
        let padding = word & !data_mask;
        let bit = if padding == 0 {
            false
        } else if padding == !data_mask {
            true
        } else {
            return Err(bad("Mieru invalid low entropy padding"));
        };
        if polarity.is_some_and(|p| p != bit) {
            return Err(bad("Mieru inconsistent low entropy padding"));
        }
        polarity = Some(bit);
        out.extend_from_slice(&extract(word, mask).to_be_bytes()[8 - n..]);
    }
    out.extend_from_slice(&ciphertext[ciphertext.len() - 16..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn low_entropy_padding_is_canonical() {
        for mode in 1..=4 {
            for rotation in [0, 1, 15, 16, 240] {
                for n in [1, 7, 8, 511, 1024] {
                    let mut data = vec![0xab; n];
                    data.extend_from_slice(&[0xcc; 16]);
                    let half = half_mask(mode).unwrap();
                    let encoded = encode(&data, mode, half, rotation).unwrap();
                    let mut meta = [0; 32];
                    meta[1] = mode;
                    meta[25..29].copy_from_slice(&half.to_be_bytes());
                    meta[29..31].copy_from_slice(&(n as u16).to_be_bytes());
                    meta[31] = rotation;
                    assert_eq!(decode(&encoded, &meta).unwrap(), data);
                    let mut invalid = meta;
                    invalid[1] = 255;
                    assert!(decode(&encoded, &invalid).is_err());
                    assert!(decode(&encoded[..encoded.len() - 1], &meta).is_err());
                }
            }
        }
    }
}
