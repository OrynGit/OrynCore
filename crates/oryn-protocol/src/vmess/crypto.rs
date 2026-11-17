//! 按 VMess 公开规范实现的密码学原语。MD5 仅用于旧协议密钥。
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use md5::{Digest, Md5};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use sha2::Sha256;
use std::io;
pub fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut b = [0; N];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| bad("random source failed"))?;
    Ok(b)
}
pub fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
pub fn fnv(data: &[u8]) -> u32 {
    data.iter().fold(0x811c9dc5u32, |h, b| {
        (h ^ *b as u32).wrapping_mul(0x1000193)
    })
}
fn nested_hash(keys: &[&[u8]], data: &[u8], md: bool) -> Vec<u8> {
    if keys.is_empty() {
        return if md {
            md5(data).to_vec()
        } else {
            sha256(data).to_vec()
        };
    }
    let (key, rest) = keys.split_last().unwrap();
    let key = if key.len() > 64 {
        nested_hash(rest, key, md)
    } else {
        key.to_vec()
    };
    let mut inner = vec![0x36; 64];
    let mut outer = vec![0x5c; 64];
    for (i, b) in key.iter().enumerate() {
        inner[i] ^= b;
        outer[i] ^= b;
    }
    inner.extend_from_slice(data);
    outer.extend(nested_hash(rest, &inner, md));
    nested_hash(rest, &outer, md)
}
pub fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    let mut keys = vec![b"VMess AEAD KDF".as_slice()];
    keys.extend_from_slice(paths);
    nested_hash(&keys, key, false).try_into().unwrap()
}
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    nested_hash(&[key], data, true)
}
pub fn aes_block(key: &[u8], block: &mut [u8; 16]) {
    Aes128::new_from_slice(key)
        .unwrap()
        .encrypt_block(block.into());
}
pub fn seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &mut Vec<u8>,
    chacha: bool,
) -> io::Result<()> {
    let alg = if chacha {
        &aead::CHACHA20_POLY1305
    } else {
        &aead::AES_128_GCM
    };
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(alg, key).map_err(|_| bad("invalid AEAD key"))?,
    );
    key.seal_in_place_append_tag(
        aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| bad("invalid AEAD nonce"))?,
        aead::Aad::from(aad),
        data,
    )
    .map_err(|_| bad("AEAD encryption failed"))
}
pub fn open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &mut Vec<u8>,
    chacha: bool,
) -> io::Result<()> {
    let alg = if chacha {
        &aead::CHACHA20_POLY1305
    } else {
        &aead::AES_128_GCM
    };
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(alg, key).map_err(|_| bad("invalid AEAD key"))?,
    );
    let n = key
        .open_in_place(
            aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| bad("invalid AEAD nonce"))?,
            aead::Aad::from(aad),
            data,
        )
        .map_err(|_| bad("VMess authentication failed"))?
        .len();
    data.truncate(n);
    Ok(())
}
pub fn chacha_key(key: &[u8]) -> Vec<u8> {
    let a = md5(key);
    [a.as_slice(), md5(&a).as_slice()].concat()
}
pub struct Cfb {
    aes: Aes128,
    feedback: [u8; 16],
    encrypted: [u8; 16],
    position: usize,
}
impl Cfb {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        Self {
            aes: Aes128::new_from_slice(key).unwrap(),
            feedback: iv.try_into().unwrap(),
            encrypted: [0; 16],
            position: 0,
        }
    }
    pub fn apply(&mut self, data: &mut [u8], decrypt: bool) {
        for b in data {
            if self.position == 0 {
                self.encrypted = self.feedback;
                self.aes.encrypt_block((&mut self.encrypted).into());
            }
            let original = *b;
            *b ^= self.encrypted[self.position];
            self.feedback[self.position] = if decrypt { original } else { *b };
            self.position = (self.position + 1) % 16;
        }
    }
}
/// 每帧复用的 AEAD 密钥：`UnboundKey::new` 要做一次密钥扩展，不应每帧重做。
pub fn aead_key(key: &[u8], chacha: bool) -> Option<aead::LessSafeKey> {
    let alg = if chacha {
        &aead::CHACHA20_POLY1305
    } else {
        &aead::AES_128_GCM
    };
    aead::UnboundKey::new(alg, key)
        .ok()
        .map(aead::LessSafeKey::new)
}
/// 原地加密 `data`，返回要追加在其后的认证标签。
pub fn seal_slice(key: &aead::LessSafeKey, nonce: &[u8], data: &mut [u8]) -> io::Result<aead::Tag> {
    key.seal_in_place_separate_tag(
        aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| bad("invalid AEAD nonce"))?,
        aead::Aad::empty(),
        data,
    )
    .map_err(|_| bad("AEAD encryption failed"))
}
/// 原地解密「密文 + 标签」，返回明文长度。
pub fn open_slice(key: &aead::LessSafeKey, nonce: &[u8], data: &mut [u8]) -> io::Result<usize> {
    key.open_in_place(
        aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| bad("invalid AEAD nonce"))?,
        aead::Aad::empty(),
        data,
    )
    .map(|plain| plain.len())
    .map_err(|_| bad("VMess authentication failed"))
}
