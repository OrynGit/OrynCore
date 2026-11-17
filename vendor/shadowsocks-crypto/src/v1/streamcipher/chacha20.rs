use chacha20::{
    cipher::{IvSizeUser, KeyIvInit, KeySizeUser, StreamCipher, Unsigned},
    ChaCha20,
    Key,
    Nonce,
    XChaCha20,
    XNonce,
};

/// ChaCha20 for IETF Protocols
///
/// https://tools.ietf.org/html/rfc8439
pub struct Chacha20 {
    cipher: ChaCha20,
}

impl Chacha20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let key = Key::from_slice(key);
        let nonce = Nonce::from_slice(nonce);
        let cipher = ChaCha20::new(key, nonce);

        Self { cipher }
    }

    pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher.apply_keystream(plaintext_in_ciphertext_out);
    }

    pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.cipher.apply_keystream(ciphertext_in_plaintext_out);
    }

    pub fn key_size() -> usize {
        <ChaCha20 as KeySizeUser>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <ChaCha20 as IvSizeUser>::IvSize::to_usize()
    }
}

/// Oryn 修补：XChaCha20（24 字节 nonce），对应 mihomo / sing-shadowsocks 的 `xchacha20`。
pub struct XChacha20 {
    cipher: XChaCha20,
}

impl XChacha20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let key = Key::from_slice(key);
        let nonce = XNonce::from_slice(nonce);
        let cipher = XChaCha20::new(key, nonce);

        Self { cipher }
    }

    pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher.apply_keystream(plaintext_in_ciphertext_out);
    }

    pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.cipher.apply_keystream(ciphertext_in_plaintext_out);
    }

    pub fn key_size() -> usize {
        <XChaCha20 as KeySizeUser>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <XChaCha20 as IvSizeUser>::IvSize::to_usize()
    }
}
