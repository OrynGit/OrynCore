//! ShadowsocksR 用到的小工具：摘要、HMAC、RC4、Adler-32、XorShift128+、EVP_BytesToKey。
//!
//! 来源 MetaCubeX/mihomo `transport/ssr/tools`（random.go、crypto.go）与 `transport/shadowsocks/core`
//! 的 Kdf，commit 见 Oryn_dev/docs/oryncore/provenance.md（v1.19.32）。
//! Copyright (C) 2021–2026 MetaCubeX contributors，SPDX-License-Identifier: GPL-3.0-or-later
//! XorShift 的初始化按 shadowsocksr（Python）实现：不修改调用方的摘要，不足 16 字节补零。

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use ring::rand::{SecureRandom, SystemRandom};
use sha1::Sha1;

pub(crate) fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

pub(crate) fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub(crate) fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub(crate) fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

pub(crate) fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// OpenSSL EVP_BytesToKey（MD5，一次迭代），Shadowsocks 的口令派生。
pub(crate) fn kdf(password: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < len {
        let mut input = prev.clone();
        input.extend_from_slice(password);
        let d = md5(&input);
        out.extend_from_slice(&d);
        prev = d.to_vec();
    }
    out.truncate(len);
    out
}

pub(crate) fn random_bytes(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut b)
        .expect("system random source failed");
    b
}

pub(crate) fn random_u32() -> u32 {
    let b = random_bytes(4);
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// 0..n 的随机数；n 为 0 时返回 0。
pub(crate) fn random_below(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        (random_u32() as usize) % n
    }
}

pub(crate) fn random_f64() -> f64 {
    (random_u32() as f64) / (u32::MAX as f64 + 1.0)
}

pub(crate) fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

pub(crate) struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        for b in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *b ^= k;
        }
    }
}

#[derive(Default)]
pub(crate) struct XorShift128Plus {
    s: [u64; 2],
}

impl XorShift128Plus {
    pub(crate) fn next(&mut self) -> u64 {
        let mut x = self.s[0];
        let y = self.s[1];
        self.s[0] = y;
        x ^= x << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.s[1] = x;
        x.wrapping_add(y)
    }

    fn padded(bin: &[u8]) -> [u8; 16] {
        let mut full = [0u8; 16];
        let n = bin.len().min(16);
        full[..n].copy_from_slice(&bin[..n]);
        full
    }

    pub(crate) fn init_from_bin(&mut self, bin: &[u8]) {
        let full = Self::padded(bin);
        self.s[0] = u64::from_le_bytes(full[..8].try_into().unwrap());
        self.s[1] = u64::from_le_bytes(full[8..].try_into().unwrap());
    }

    pub(crate) fn init_from_bin_and_length(&mut self, bin: &[u8], length: usize) {
        let mut full = Self::padded(bin);
        full[..2].copy_from_slice(&(length as u16).to_le_bytes());
        self.s[0] = u64::from_le_bytes(full[..8].try_into().unwrap());
        self.s[1] = u64::from_le_bytes(full[8..].try_into().unwrap());
        for _ in 0..4 {
            self.next();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        // RFC 6229：key 0x0102030405，前 16 字节密钥流
        let mut rc4 = Rc4::new(&[1, 2, 3, 4, 5]);
        let mut ks = [0u8; 16];
        rc4.apply(&mut ks);
        assert_eq!(
            ks,
            [
                0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11,
                0x18, 0xa8
            ]
        );
        // zlib 的 adler32("Wikipedia") = 0x11E60398
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        // EVP_BytesToKey("password", 16) = md5("password")
        assert_eq!(kdf(b"password", 16), md5(b"password").to_vec());
        assert_eq!(
            kdf(b"password", 32)[16..],
            md5(&[&md5(b"password")[..], b"password"].concat())[..]
        );
    }

    #[test]
    fn xorshift_matches_the_python_reference() {
        // shadowsocksr obfsplugin/auth_chain.py 的 xorshift128plus：v0 = 1, v1 = 2 时第一个输出
        let mut r = XorShift128Plus::default();
        let mut bin = [0u8; 16];
        bin[0] = 1;
        bin[8] = 2;
        r.init_from_bin(&bin);
        let x: u64 = 1;
        let y: u64 = 2;
        let mut e = x ^ (x << 23);
        e ^= y ^ (e >> 17) ^ (y >> 26);
        assert_eq!(r.next(), e.wrapping_add(y));
        // 不足 16 字节补零，不修改输入
        let short = [9u8; 4];
        r.init_from_bin_and_length(&short, 300);
        assert_eq!(short, [9u8; 4]);
    }
}
