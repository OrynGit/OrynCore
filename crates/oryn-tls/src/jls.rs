// 线格式移植自 metacubex/jls-tls jls.go @ 67adc0e2f79630fcf80f0b65278d4d1a094b812b。
// Copyright 2009 The Go Authors. BSD-3-Clause（JLS 衍生实现沿用仓库 LICENSE）。
// Modified for Oryn: Rust 原生客户端，认证回调与 TLS transcript 集成。
use aes_gcm::{
    aead::{consts::U32, Aead, KeyInit},
    aes::Aes256,
    AesGcm,
};
use ring::digest::{Context, SHA256};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::OrynJlsAuth,
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use std::{fmt, io, sync::Arc};

type JlsGcm = AesGcm<Aes256, U32>;
struct Auth {
    username: String,
    password: String,
}
impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JlsAuth")
    }
}
fn failure() -> rustls::Error {
    rustls::Error::General("JLS authentication failed".into())
}
fn auth_data(hello: &[u8], client: bool) -> Result<Vec<u8>, rustls::Error> {
    if hello.len() < 38 || hello.len() > 16 * 1024 || hello[0] != if client { 1 } else { 2 } {
        return Err(failure());
    }
    let declared =
        (usize::from(hello[1]) << 16) | (usize::from(hello[2]) << 8) | usize::from(hello[3]);
    if declared + 4 != hello.len() {
        return Err(failure());
    }
    let mut data = hello.to_vec();
    data[6..38].fill(0);
    if client {
        let mut at = 38;
        let session = *data.get(at).ok_or_else(failure)? as usize;
        at += 1 + session;
        let length = read_len(&data, at)?;
        at += 2 + length;
        let compression = *data.get(at).ok_or_else(failure)? as usize;
        at += 1 + compression;
        let extensions = read_len(&data, at)?;
        at += 2;
        if at + extensions != data.len() {
            return Err(failure());
        }
        while at < data.len() {
            let typ = read_len(&data, at)?;
            let len = read_len(&data, at + 2)?;
            at += 4;
            let end = at
                .checked_add(len)
                .filter(|n| *n <= data.len())
                .ok_or_else(failure)?;
            if typ == 41 {
                let identities = read_len(&data, at)?;
                let mut pos = at + 2 + identities;
                let binders = read_len(&data, pos)?;
                pos += 2;
                if pos + binders != end {
                    return Err(failure());
                }
                while pos < end {
                    let n = usize::from(data[pos]);
                    pos += 1;
                    if pos + n > end {
                        return Err(failure());
                    }
                    data[pos..pos + n].fill(0);
                    pos += n;
                }
            }
            at = end;
        }
    }
    Ok(data)
}
fn read_len(data: &[u8], at: usize) -> Result<usize, rustls::Error> {
    let s = data.get(at..at + 2).ok_or_else(failure)?;
    Ok(usize::from(u16::from_be_bytes([s[0], s[1]])))
}
fn hash(prefix: &str, data: &[u8]) -> [u8; 32] {
    let mut h = Context::new(&SHA256);
    h.update(prefix.as_bytes());
    h.update(data);
    h.finish().as_ref().try_into().unwrap()
}
impl OrynJlsAuth for Auth {
    fn client_random(&self, hello: &[u8]) -> Result<[u8; 32], rustls::Error> {
        let data = auth_data(hello, true)?;
        let key = hash(&self.password, &data);
        let nonce = hash(&self.username, &data);
        let aead = JlsGcm::new((&key).into());
        let mut seed: [u8; 16] = hello[6..22].try_into().unwrap();
        loop {
            let encrypted = aead
                .encrypt((&nonce).into(), seed.as_slice())
                .map_err(|_| failure())?;
            let result: [u8; 32] = encrypted.try_into().map_err(|_| failure())?;
            let tail = &result[24..];
            if tail != b"DOWNGRD\x01"
                && tail != b"DOWNGRD\x00"
                && tail != [0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c]
            {
                return Ok(result);
            }
            use ring::rand::SecureRandom;
            ring::rand::SystemRandom::new()
                .fill(&mut seed)
                .map_err(|_| failure())?;
        }
    }
    fn verify_server_hello(&self, hello: &[u8]) -> Result<(), rustls::Error> {
        let data = auth_data(hello, false)?;
        let key = hash(&self.password, &data);
        let nonce = hash(&self.username, &data);
        let plain = JlsGcm::new((&key).into())
            .decrypt((&nonce).into(), &hello[6..38])
            .map_err(|_| failure())?;
        if plain.len() != 16 {
            return Err(failure());
        }
        Ok(())
    }
}
/// 只由本模块与强制 ServerHello 认证钩子一起安装，普通 TLS 不可获得此验证器。
#[derive(Debug)]
struct JlsCertificate;
impl ServerCertVerifier for JlsCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(failure())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        super::provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
/// 每个出站独立持有此配置及票据缓存，不能跨凭据/节点复用。
pub fn client_config(
    username: &str,
    password: &str,
    alpn: &[String],
    early: bool,
) -> io::Result<quinn::ClientConfig> {
    let mut tls = ClientConfig::builder_with_provider(super::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(JlsCertificate))
        .with_no_client_auth();
    tls.oryn_jls = Some(Arc::new(Auth {
        username: username.into(),
        password: password.into(),
    }));
    tls.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    tls.enable_early_data = early;
    tls.resumption = rustls::client::Resumption::store(Arc::new(Tickets::default()));
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

/// 单节点单票据缓存。rustls 的通用缓存以服务器数取整并预留一格；容量 1 会立即逐出。
/// 本地缓存不持久化、不开跨节点共享，票据原有的 verifier/credential 绑定继续生效。
#[derive(Debug, Default)]
struct Tickets(std::sync::Mutex<TicketState>);
#[derive(Debug, Default)]
struct TicketState {
    hint: Option<(ServerName<'static>, rustls::NamedGroup)>,
    ticket: Option<(ServerName<'static>, rustls::client::Tls13ClientSessionValue)>,
}
impl rustls::client::ClientSessionStore for Tickets {
    fn set_kx_hint(&self, name: ServerName<'static>, group: rustls::NamedGroup) {
        self.0.lock().unwrap().hint = Some((name, group));
    }
    fn kx_hint(&self, name: &ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.0
            .lock()
            .unwrap()
            .hint
            .as_ref()
            .filter(|(n, _)| n == name)
            .map(|(_, g)| *g)
    }
    fn set_tls12_session(
        &self,
        _: ServerName<'static>,
        _: rustls::client::Tls12ClientSessionValue,
    ) {
    }
    fn tls12_session(&self, _: &ServerName<'_>) -> Option<rustls::client::Tls12ClientSessionValue> {
        None
    }
    fn remove_tls12_session(&self, _: &ServerName<'static>) {}
    fn insert_tls13_ticket(
        &self,
        name: ServerName<'static>,
        ticket: rustls::client::Tls13ClientSessionValue,
    ) {
        self.0.lock().unwrap().ticket = Some((name, ticket));
    }
    fn take_tls13_ticket(
        &self,
        name: &ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        let mut state = self.0.lock().unwrap();
        if state.ticket.as_ref().is_some_and(|(n, _)| n == name) {
            state.ticket.take().map(|(_, t)| t)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jls_authentication_binds_complete_hello_and_credentials() {
        let auth = Auth {
            username: "u".into(),
            password: "p".into(),
        };
        let mut hello = vec![2, 0, 0, 35, 3, 3];
        hello.extend([0; 32]);
        hello.push(0);
        let data = auth_data(&hello, false).unwrap();
        let key = hash("p", &data);
        let nonce = hash("u", &data);
        let encrypted = JlsGcm::new((&key).into())
            .encrypt((&nonce).into(), [4; 16].as_slice())
            .unwrap();
        hello[6..38].copy_from_slice(&encrypted);
        auth.verify_server_hello(&hello).unwrap();
        for at in [0, 2, 5, 6, 20, 37, 38] {
            let mut bad = hello.clone();
            bad[at] ^= 1;
            assert!(auth.verify_server_hello(&bad).is_err());
        }
        let wrong = Auth {
            username: "x".into(),
            password: "p".into(),
        };
        assert!(wrong.verify_server_hello(&hello).is_err());
    }
}
