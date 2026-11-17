//! 浏览器 / Reality 的真实 X25519 key exchange；Firefox 同时提供真实 P256 share。
use crate::browser::{invalid, random};
use rustls::{
    crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    Error, NamedGroup,
};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
pub(crate) struct BrowserX25519 {
    pub(crate) p256: bool,
}
pub(crate) static X25519: BrowserX25519 = BrowserX25519 { p256: false };
pub(crate) static FIREFOX_X25519: BrowserX25519 = BrowserX25519 { p256: true };
impl SupportedKxGroup for BrowserX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut bytes = [0; 32];
        random(&mut bytes)?;
        let secret = StaticSecret::from(bytes);
        bytes.fill(0);
        let public = PublicKey::from(&secret).to_bytes();
        let p256 = if self.p256 {
            Some(rustls::crypto::ring::kx_group::SECP256R1.start()?)
        } else {
            None
        };
        Ok(Box::new(Exchange {
            secret,
            public,
            p256,
        }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}
struct Exchange {
    secret: StaticSecret,
    public: [u8; 32],
    p256: Option<Box<dyn ActiveKeyExchange>>,
}
impl Exchange {
    fn shared(&self, peer: &[u8; 32]) -> Result<[u8; 32], Error> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer));
        if !shared.was_contributory() {
            return Err(invalid("invalid X25519 peer public key"));
        }
        Ok(shared.to_bytes())
    }
}
impl ActiveKeyExchange for Exchange {
    fn oryn_reality_secret(&self, peer: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.shared(peer)
    }
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer = peer
            .try_into()
            .map_err(|_| invalid("invalid X25519 public key length"))?;
        Ok(SharedSecret::from(&self.shared(&peer)?[..]))
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        self.p256
            .as_ref()
            .map(|p| (NamedGroup::secp256r1, p.pub_key()))
    }
    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        self.p256
            .ok_or_else(|| invalid("missing browser P256 exchange"))?
            .complete(peer)
    }
}
