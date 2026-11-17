// Portions derived from SagerNet/sing-box common/tls/reality_client.go
// @ 573c6179ab4fc1b9ecb8f049299bb1dfe8babc97 (v1.12.8).
// Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
// Modified for Oryn: Rust / ring, no HTTP fallback, no Go or unsafe certificate access.
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{browser::invalid, NoVerify};
use oryn_config::RealitySpec;
use ring::{aead, hkdf, hmac};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ActiveKeyExchange,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error, SignatureScheme,
};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub(crate) type AuthKey = Arc<Mutex<Option<Zeroizing<[u8; 32]>>>>;
struct KeyLength;
impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}

pub(crate) fn authenticate_hello(
    body: &mut [u8],
    key: &dyn ActiveKeyExchange,
    spec: &RealitySpec,
    auth: &AuthKey,
) -> Result<(), Error> {
    if key.group() != rustls::NamedGroup::X25519 || body.len() < 67 || body[34] != 32 {
        return Err(invalid("Reality requires X25519 and 32-byte session ID"));
    }
    let mut shared = Zeroizing::new(key.oryn_reality_secret(&spec.public_key)?);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &body[2..22]);
    let prk = salt.extract(&shared[..]);
    let mut derived = Zeroizing::new([0; 32]);
    prk.expand(&[b"REALITY"], KeyLength)
        .map_err(|_| invalid("Reality HKDF failed"))?
        .fill(&mut derived[..])
        .map_err(|_| invalid("Reality HKDF failed"))?;
    shared.fill(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock before Unix epoch"))?
        .as_secs();
    let timestamp = u32::try_from(now).map_err(|_| invalid("Reality timestamp out of range"))?;
    let mut session = Vec::with_capacity(32);
    session.extend_from_slice(&[1, 8, 1, 0]);
    session.extend_from_slice(&timestamp.to_be_bytes());
    session.extend_from_slice(&spec.short_id);
    body[35..67].fill(0);
    let mut aad = vec![
        1,
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ];
    aad.extend_from_slice(body);
    let nonce = aead::Nonce::try_assume_unique_for_key(&body[22..34])
        .map_err(|_| invalid("Reality invalid nonce"))?;
    let aes = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &derived[..])
            .map_err(|_| invalid("Reality AES key failed"))?,
    );
    aes.seal_in_place_append_tag(nonce, aead::Aad::from(&aad), &mut session)
        .map_err(|_| invalid("Reality authentication encryption failed"))?;
    body[35..67].copy_from_slice(&session);
    *auth
        .lock()
        .map_err(|_| invalid("Reality auth lock failed"))? = Some(derived);
    Ok(())
}

pub(crate) struct RealityVerifier {
    pub(crate) auth: AuthKey,
    pub(crate) signatures: NoVerify,
}
impl std::fmt::Debug for RealityVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RealityVerifier")
    }
}
impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let (public, signature) = certificate_identity(cert.as_ref())?;
        let auth = self
            .auth
            .lock()
            .map_err(|_| invalid("Reality auth lock failed"))?;
        let auth = auth
            .as_ref()
            .ok_or_else(|| invalid("Reality authentication key unavailable"))?;
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA512, &auth[..]),
            public,
            signature,
        )
        .map_err(|_| invalid("Reality server authentication failed"))?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(invalid("Reality requires TLS 1.3"))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.signatures.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signatures.supported_verify_schemes()
    }
}

// 仅借用有界 DER 字节，解析 Ed25519 SPKI / 外层 signature；不实现通用 X509 或信任链。
fn tlv<'a>(input: &mut &'a [u8]) -> Result<(u8, &'a [u8]), Error> {
    let tag = *input
        .first()
        .ok_or_else(|| invalid("Reality truncated certificate"))?;
    let mut p = 1;
    let first = *input
        .get(p)
        .ok_or_else(|| invalid("Reality truncated DER length"))?;
    p += 1;
    let len = if first < 128 {
        first as usize
    } else {
        let count = (first & 127) as usize;
        if count == 0 || count > 4 {
            return Err(invalid("Reality invalid DER length"));
        }
        let bytes = input
            .get(p..p + count)
            .ok_or_else(|| invalid("Reality truncated DER length"))?;
        p += count;
        if bytes[0] == 0 {
            return Err(invalid("Reality noncanonical DER length"));
        }
        let mut len = 0usize;
        for b in bytes {
            len = len
                .checked_mul(256)
                .and_then(|n| n.checked_add(*b as usize))
                .ok_or_else(|| invalid("Reality DER length overflow"))?;
        }
        if len < 128 {
            return Err(invalid("Reality noncanonical DER length"));
        }
        len
    };
    let data = input
        .get(p..p + len)
        .ok_or_else(|| invalid("Reality truncated DER value"))?;
    *input = &input[p + len..];
    Ok((tag, data))
}
fn expect<'a>(input: &mut &'a [u8], expected: u8) -> Result<&'a [u8], Error> {
    let (tag, data) = tlv(input)?;
    if tag != expected {
        return Err(invalid("Reality certificate structure mismatch"));
    }
    Ok(data)
}
fn ed25519_algorithm(input: &[u8]) -> Result<(), Error> {
    if input != [6, 3, 0x2b, 0x65, 0x70] {
        return Err(invalid("Reality certificate must use Ed25519"));
    }
    Ok(())
}
pub(crate) fn certificate_identity(cert: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if cert.len() > 128 * 1024 {
        return Err(invalid("Reality certificate too large"));
    }
    let mut outer = cert;
    let mut cert = expect(&mut outer, 0x30)?;
    if !outer.is_empty() {
        return Err(invalid("Reality trailing certificate data"));
    }
    let mut tbs = expect(&mut cert, 0x30)?;
    ed25519_algorithm(expect(&mut cert, 0x30)?)?;
    let signature = expect(&mut cert, 3)?;
    if signature.len() != 65 || signature[0] != 0 || !cert.is_empty() {
        return Err(invalid("Reality invalid certificate signature"));
    }
    if tbs.first() == Some(&0xa0) {
        tlv(&mut tbs)?;
    }
    for tag in [2, 0x30, 0x30, 0x30, 0x30] {
        expect(&mut tbs, tag)?;
    }
    let mut spki = expect(&mut tbs, 0x30)?;
    ed25519_algorithm(expect(&mut spki, 0x30)?)?;
    let public = expect(&mut spki, 3)?;
    if public.len() != 33 || public[0] != 0 || !spki.is_empty() {
        return Err(invalid("Reality invalid Ed25519 public key"));
    }
    Ok((&public[1..], &signature[1..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::{BrowserHello, Hello};
    use rustls::crypto::{OrynClientHello, SupportedKxGroup};
    #[test]
    fn reality_key_bound_session_authentication() {
        let server = x25519_dalek::StaticSecret::from([7; 32]);
        let public = x25519_dalek::PublicKey::from(&server).to_bytes();
        let spec = RealitySpec {
            public_key: public,
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let exchange = crate::kx::X25519.start().unwrap();
        // 有真实 X25519 share 的标准 ClientHello，由测试客户端 TLS 引擎生成。
        let config = rustls::ClientConfig::builder_with_provider(crate::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::NoVerify(crate::provider())))
            .with_no_client_auth();
        let mut connection = rustls::ClientConnection::new(
            Arc::new(config),
            crate::server_name("proxy.test").unwrap(),
        )
        .unwrap();
        let mut wire = Vec::new();
        connection.write_tls(&mut wire).unwrap();
        let mut body = wire[9..].to_vec();
        // 仅供此单元测试：用实际测试 exchange 的公钥替换 rustls 初始 X25519 share。
        let pos = body.windows(4).position(|w| w == [0, 29, 0, 32]).unwrap();
        body[pos + 4..pos + 36].copy_from_slice(exchange.pub_key());
        let auth: AuthKey = Default::default();
        let hook = BrowserHello::new("chrome", Some(spec.clone()), auth.clone());
        let encrypted = hook.customize(&body, Some(&*exchange), false).unwrap();
        let hello = Hello::parse(&encrypted).unwrap();
        assert!(hello
            .ext(51)
            .unwrap()
            .windows(32)
            .any(|w| w == exchange.pub_key()));
        let shared = server.diffie_hellman(&x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(exchange.pub_key()).unwrap(),
        ));
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &encrypted[2..22]);
        let prk = salt.extract(shared.as_bytes());
        let mut key = [0; 32];
        prk.expand(&[b"REALITY"], KeyLength)
            .unwrap()
            .fill(&mut key)
            .unwrap();
        let mut aad = vec![1, 0, (encrypted.len() >> 8) as u8, encrypted.len() as u8];
        aad.extend_from_slice(&encrypted);
        aad[39..71].fill(0);
        let aes = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
        let mut sid = encrypted[35..67].to_vec();
        let plain = aes
            .open_in_place(
                aead::Nonce::try_assume_unique_for_key(&encrypted[22..34]).unwrap(),
                aead::Aad::from(&aad),
                &mut sid,
            )
            .unwrap();
        assert_eq!(&plain[..4], &[1, 8, 1, 0]);
        assert_eq!(&plain[8..], &spec.short_id);
        let timestamp = u32::from_be_bytes(plain[4..8].try_into().unwrap()) as u64;
        assert!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .abs_diff(timestamp)
                <= 1
        );
        let mut corrupt = encrypted[35..67].to_vec();
        corrupt[0] ^= 1;
        assert!(aes
            .open_in_place(
                aead::Nonce::try_assume_unique_for_key(&encrypted[22..34]).unwrap(),
                aead::Aad::from(&aad),
                &mut corrupt
            )
            .is_err());
        assert!(hook.customize(&body, Some(&*exchange), true).is_err());
    }
    #[test]
    fn strict_certificate_authentication_and_der() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["proxy.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut der = cert.der().to_vec();
        let public = certificate_identity(&der).unwrap().0.to_vec();
        let auth: AuthKey = Arc::new(Mutex::new(Some(Zeroizing::new([9; 32]))));
        let verifier = RealityVerifier {
            auth,
            signatures: NoVerify(crate::provider()),
        };
        let signature = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, &[9; 32]), &public);
        let tail = der.len() - 64;
        der[tail..].copy_from_slice(signature.as_ref());
        let name = crate::server_name("proxy.test").unwrap();
        assert!(verifier
            .verify_server_cert(
                &CertificateDer::from(der.as_slice()),
                &[],
                &name,
                &[],
                UnixTime::now()
            )
            .is_ok());
        der[tail] ^= 1;
        assert!(verifier
            .verify_server_cert(
                &CertificateDer::from(der.as_slice()),
                &[],
                &name,
                &[],
                UnixTime::now()
            )
            .is_err());
        assert!(
            verifier
                .verify_server_cert(cert.der(), &[], &name, &[], UnixTime::now())
                .is_err(),
            "普通合法证书不能替代 Reality 身份认证"
        );
        for n in 0..cert.der().len() {
            assert!(
                certificate_identity(&cert.der()[..n]).is_err(),
                "truncated DER {n}"
            );
        }
        for data in [
            vec![],
            vec![0x30, 0x80],
            vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
            vec![0x30, 0x81, 1, 0],
        ] {
            assert!(certificate_identity(&data).is_err());
        }
    }
}
