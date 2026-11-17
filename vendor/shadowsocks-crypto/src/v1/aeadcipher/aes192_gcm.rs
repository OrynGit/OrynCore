//! Oryn 修补：AEAD_AES_192_GCM。ring 不支持 AES-192，固定用 RustCrypto `aes-gcm`。

use aes::Aes192;
use aes_gcm::{
    aead::{consts::U12, generic_array::typenum::Unsigned, AeadCore, AeadInPlace, KeyInit, KeySizeUser},
    AesGcm,
    Key,
    Nonce,
    Tag,
};

type CryptoAes192Gcm = AesGcm<Aes192, U12>;

pub struct Aes192Gcm(CryptoAes192Gcm);

impl Aes192Gcm {
    pub fn new(key: &[u8]) -> Aes192Gcm {
        let key = Key::<CryptoAes192Gcm>::from_slice(key);
        Aes192Gcm(CryptoAes192Gcm::new(key))
    }

    pub fn key_size() -> usize {
        <CryptoAes192Gcm as KeySizeUser>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <CryptoAes192Gcm as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <CryptoAes192Gcm as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("AES_192_GCM encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = Nonce::from_slice(nonce);
        let (ciphertext, in_tag) =
            ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
        let in_tag = Tag::from_slice(in_tag);
        self.0.decrypt_in_place_detached(nonce, &[], ciphertext, in_tag).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST SP 800-38D 测试向量（Test Case 7 的空明文变体：K = 0^192，IV = 0^96）。
    #[test]
    fn known_answer() {
        let c = Aes192Gcm::new(&[0u8; 24]);
        let mut buf = [0u8; 16];
        c.encrypt(&[0u8; 12], &mut buf);
        assert_eq!(buf, [0xcd, 0x33, 0xb2, 0x8a, 0xc7, 0x73, 0xf7, 0x4b, 0xa0, 0x0e, 0xd1, 0xf3, 0x12, 0x57, 0x24, 0x35]);
        assert!(c.decrypt(&[0u8; 12], &mut buf));
    }
}
