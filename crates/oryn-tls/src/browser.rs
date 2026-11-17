// ClientHello 模板来自 github.com/metacubex/utls u_parrots.go
// @ 8b5753f5737a9e173f6ebc85edb6cdd144301c71（v1.8.0）。
// Copyright 2017 Google Inc. All rights reserved.
// Copyright (c) 2009 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Oryn：模板数据适配 rustls 的真实密钥交换，不使用 Go 运行后端；完整许可见 profiles/LICENSE。

use crate::reality::{self, AuthKey};
use oryn_config::RealitySpec;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{
    crypto::{ActiveKeyExchange, OrynClientHello},
    Error,
};
use std::sync::Mutex;

pub(crate) fn invalid(msg: &str) -> Error {
    Error::General(msg.to_string())
}
pub(crate) fn random(buf: &mut [u8]) -> Result<(), Error> {
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| invalid("TLS random source failed"))
}

#[derive(Clone)]
pub(crate) struct Hello {
    prefix: Vec<u8>,
    pub(crate) ciphers: Vec<u8>,
    compression: Vec<u8>,
    pub(crate) extensions: Vec<(u16, Vec<u8>)>,
}
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let part = self
            .data
            .get(self.pos..self.pos + n)
            .ok_or_else(|| invalid("invalid ClientHello encoding"))?;
        self.pos += n;
        Ok(part)
    }
    fn u16(&mut self) -> Result<usize, Error> {
        let v = self.take(2)?;
        Ok(u16::from_be_bytes([v[0], v[1]]) as usize)
    }
    fn v16(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()?;
        self.take(n)
    }
    fn v8(&mut self) -> Result<&'a [u8], Error> {
        let n = self.take(1)?[0] as usize;
        self.take(n)
    }
}
impl Hello {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() > 16 * 1024 {
            return Err(invalid("ClientHello exceeds 16 KiB"));
        }
        let mut c = Cursor { data, pos: 0 };
        c.take(34)?;
        c.v8()?;
        let prefix = data[..c.pos].to_vec();
        let ciphers = c.v16()?.to_vec();
        let compression = c.v8()?.to_vec();
        let ext_data = c.v16()?;
        if c.pos != data.len() {
            return Err(invalid("trailing ClientHello data"));
        }
        let mut c = Cursor {
            data: ext_data,
            pos: 0,
        };
        let mut extensions = Vec::new();
        while c.pos < ext_data.len() {
            let ty = c.u16()? as u16;
            let data = c.v16()?.to_vec();
            if extensions.len() >= 64 || extensions.iter().any(|(t, _)| *t == ty) {
                return Err(invalid("invalid ClientHello extension list"));
            }
            extensions.push((ty, data));
        }
        Ok(Self {
            prefix,
            ciphers,
            compression,
            extensions,
        })
    }
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = self.prefix.clone();
        v16(&self.ciphers, &mut out)?;
        out.push(self.compression.len() as u8);
        out.extend_from_slice(&self.compression);
        let mut exts = Vec::new();
        for (ty, data) in &self.extensions {
            exts.extend_from_slice(&ty.to_be_bytes());
            v16(data, &mut exts)?;
        }
        v16(&exts, &mut out)?;
        Ok(out)
    }
    pub(crate) fn ext(&self, ty: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(t, _)| *t == ty)
            .map(|(_, d)| d.as_slice())
    }
    fn replace(&mut self, ty: u16, value: Option<Vec<u8>>) {
        if let Some(i) = self.extensions.iter().position(|(t, _)| *t == ty) {
            if let Some(value) = value {
                self.extensions[i].1 = value;
            } else {
                self.extensions.remove(i);
            }
        } else if let Some(value) = value {
            self.extensions.push((ty, value));
        }
    }
}
fn v16(data: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let len = u16::try_from(data.len()).map_err(|_| invalid("TLS vector too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}
fn template(profile: &str) -> Result<&'static [u8], Error> {
    Ok(match profile {
        "chrome" => include_bytes!("profiles/chrome.bin"),
        "firefox" => include_bytes!("profiles/firefox.bin"),
        "safari" => include_bytes!("profiles/safari.bin"),
        "ios" => include_bytes!("profiles/ios.bin"),
        "edge" => include_bytes!("profiles/edge.bin"),
        "android" => include_bytes!("profiles/android.bin"),
        "360" => include_bytes!("profiles/360.bin"),
        "qq" => include_bytes!("profiles/qq.bin"),
        _ => return Err(invalid("unsupported browser fingerprint")),
    })
}
pub(crate) fn choose(profile: &str) -> Result<&str, Error> {
    if profile != "random" {
        return Ok(profile);
    }
    let mut byte = [0];
    random(&mut byte)?;
    Ok(["chrome", "firefox", "safari"][byte[0] as usize % 3])
}
pub(crate) fn default_alpn(profile: &str) -> Vec<Vec<u8>> {
    if profile == "android" {
        Vec::new()
    } else {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    }
}
fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}
fn grease_words(data: &mut [u8]) -> Result<(), Error> {
    for word in data.chunks_exact_mut(2) {
        if is_grease(u16::from_be_bytes([word[0], word[1]])) {
            let mut b = [0];
            random(&mut b)?;
            let value = (b[0] & 0xf0) | 0x0a;
            word.copy_from_slice(&[value, value]);
        }
    }
    Ok(())
}

/// 每连接一个定制器，重试保留初始 GREASE / 顺序；没有全局模板状态缓存。
pub(crate) struct BrowserHello {
    profile: String,
    previous: Mutex<Option<Hello>>,
    reality: Option<RealitySpec>,
    pub(crate) auth: AuthKey,
}
impl std::fmt::Debug for BrowserHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserHello")
            .field("profile", &self.profile)
            .field("reality", &self.reality.is_some())
            .finish()
    }
}
impl BrowserHello {
    pub(crate) fn new(profile: &str, reality: Option<RealitySpec>, auth: AuthKey) -> Self {
        Self {
            profile: profile.into(),
            previous: Mutex::new(None),
            reality,
            auth,
        }
    }
    fn first(&self, current: &Hello) -> Result<Hello, Error> {
        let mut hello = Hello::parse(template(&self.profile)?)?;
        hello.prefix = current.prefix.clone();
        hello.compression = current.compression.clone();
        grease_words(&mut hello.ciphers)?;
        let mut first_grease = None;
        for (ty, data) in &mut hello.extensions {
            if is_grease(*ty) {
                let mut b = [0];
                random(&mut b)?;
                let mut value = ((b[0] & 0xf0) | 0x0a) as u16 * 0x0101;
                if first_grease == Some(value) {
                    value ^= 0x1010;
                } else {
                    first_grease = Some(value);
                }
                *ty = value;
            }
            if *ty == 10 {
                grease_words(&mut data[2..])?;
            }
            if *ty == 43 {
                grease_words(&mut data[1..])?;
            }
            if *ty == 65037 {
                // ECH GREASE 格式：outer type、KDF、AEAD、config ID、enc 向量、payload 向量。
                if data.len() < 10 {
                    return Err(invalid("invalid ECH GREASE template"));
                }
                random(&mut data[5..6])?;
                let enc_len = u16::from_be_bytes([data[6], data[7]]) as usize;
                if 8 + enc_len + 2 > data.len() {
                    return Err(invalid("invalid ECH GREASE template"));
                }
                if enc_len == 32 {
                    let mut seed = [0; 32];
                    random(&mut seed)?;
                    let secret = x25519_dalek::StaticSecret::from(seed);
                    seed.fill(0);
                    data[8..8 + enc_len]
                        .copy_from_slice(x25519_dalek::PublicKey::from(&secret).as_bytes());
                } else {
                    random(&mut data[8..8 + enc_len])?;
                }
                random(&mut data[10 + enc_len..])?;
            }
        }
        if self.profile == "chrome" {
            // Chrome 106+ 随机扩展顺序，GREASE 仍保持首 / 尾。
            let len = hello.extensions.len();
            for i in (2..len - 1).rev() {
                let mut r = [0; 2];
                random(&mut r)?;
                let j = 1 + u16::from_be_bytes(r) as usize % i;
                hello.extensions.swap(i, j);
            }
        }
        Ok(hello)
    }
}
impl OrynClientHello for BrowserHello {
    fn customize(
        &self,
        body: &[u8],
        key: Option<&dyn ActiveKeyExchange>,
        retry: bool,
    ) -> Result<Vec<u8>, Error> {
        let current = Hello::parse(body)?;
        let mut previous = self
            .previous
            .lock()
            .map_err(|_| invalid("TLS customizer lock failed"))?;
        if retry && self.reality.is_some() {
            return Err(invalid("Reality does not support HelloRetryRequest"));
        }
        let mut hello = if retry {
            previous
                .clone()
                .ok_or_else(|| invalid("missing ClientHello retry state"))?
        } else {
            self.first(&current)?
        };
        hello.prefix = current.prefix.clone();
        hello.replace(0, current.ext(0).map(<[u8]>::to_vec));
        hello.replace(16, current.ext(16).map(<[u8]>::to_vec));
        if !current
            .ext(16)
            .is_some_and(|a| a.windows(2).any(|v| v == b"h2"))
        {
            hello.replace(17513, None);
        }
        if let Some(shares) = current.ext(51) {
            if self.profile != "android" {
                let mut adapted = Vec::new();
                let grease_group = hello.ext(10).and_then(|groups| {
                    groups[2..]
                        .chunks_exact(2)
                        .map(|g| u16::from_be_bytes([g[0], g[1]]))
                        .find(|g| is_grease(*g))
                });
                if let Some(old) = hello.ext(51) {
                    let mut c = Cursor { data: old, pos: 2 };
                    while c.pos < old.len() {
                        let group = c.u16()? as u16;
                        let data = c.v16()?;
                        if is_grease(group) {
                            let g = grease_group.ok_or_else(|| {
                                invalid("GREASE key share group is missing from supported groups")
                            })?;
                            adapted.extend_from_slice(&g.to_be_bytes());
                            v16(data, &mut adapted)?;
                        }
                    }
                }
                adapted.extend_from_slice(&shares[2..]);
                let mut encoded = Vec::new();
                v16(&adapted, &mut encoded)?;
                hello.replace(51, Some(encoded));
            }
        } else {
            hello.replace(51, None);
        }
        // HRR 的 cookie 来自 TLS 引擎，不复用首次发送的数据。
        hello.replace(44, current.ext(44).map(<[u8]>::to_vec));
        // 禁用真实 ECH / PSK，GREASE 不代表实际密钥或会话复用。
        hello.replace(41, None);
        hello.replace(42, None);
        if let Some(i) = hello.extensions.iter().position(|(t, _)| *t == 21) {
            hello.extensions[i].1.clear();
            let size = hello.encode()?.len() + 4;
            if (256..512).contains(&size) {
                hello.extensions[i].1.resize(512 - size, 0);
            } else {
                hello.extensions.remove(i);
            }
        }
        let mut encoded = hello.encode()?;
        if let Some(spec) = &self.reality {
            let key = key.ok_or_else(|| invalid("Reality requires X25519 key share"))?;
            reality::authenticate_hello(&mut encoded, key, spec, &self.auth)?;
        }
        // 重试需要带相同 session ID / random；已发认证后的编码只在当前连接存在。
        hello.prefix = encoded[..hello.prefix.len()].to_vec();
        *previous = Some(hello);
        Ok(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryn_config::TlsSpec;
    use std::{
        io,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    struct Prefix<S> {
        inner: S,
        head: Vec<u8>,
        pos: usize,
    }
    impl<S: AsyncRead + Unpin> AsyncRead for Prefix<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.pos < this.head.len() {
                let n = buf.remaining().min(this.head.len() - this.pos);
                buf.put_slice(&this.head[this.pos..this.pos + n]);
                this.pos += n;
                Poll::Ready(Ok(()))
            } else {
                Pin::new(&mut this.inner).poll_read(cx, buf)
            }
        }
    }
    impl<S: AsyncWrite + Unpin> AsyncWrite for Prefix<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }
    fn spec(profile: &str) -> TlsSpec {
        TlsSpec {
            sni: Some("proxy.test".into()),
            skip_cert_verify: true,
            alpn: vec![],
            fingerprint: None,
            client_fingerprint: Some(profile.into()),
            reality: None,
            ech: None,
        }
    }
    async fn capture(profile: &str, p384: bool) -> Hello {
        capture_version(profile, p384, false).await
    }
    async fn capture_version(profile: &str, p384: bool, tls12: bool) -> Hello {
        let (client, mut server) = tokio::io::duplex(32 * 1024);
        let cert = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let mut provider = rustls::crypto::ring::default_provider();
        if p384 {
            provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1];
        }
        let versions = if profile == "android" || tls12 {
            &[&rustls::version::TLS12][..]
        } else {
            &[&rustls::version::TLS13][..]
        };
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
            )
            .unwrap();
        config.alpn_protocols = if profile == "android" {
            vec![]
        } else {
            vec![b"h2".to_vec()]
        };
        let task = tokio::spawn(async move {
            let mut head = vec![0; 5];
            server.read_exact(&mut head).await.unwrap();
            let len = u16::from_be_bytes([head[3], head[4]]) as usize;
            assert!(len <= 16 * 1024);
            head.resize(5 + len, 0);
            server.read_exact(&mut head[5..]).await.unwrap();
            let hello = Hello::parse(&head[9..]).unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(Prefix {
                    inner: server,
                    head,
                    pos: 0,
                })
                .await
                .unwrap();
            let mut data = [0; 4];
            tls.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
            hello
        });
        let mut tls = crate::connect_proxy(client, "proxy.test", &spec(profile))
            .await
            .unwrap();
        tls.write_all(b"ping").await.unwrap();
        tls.flush().await.unwrap();
        let mut data = [0; 4];
        tls.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"pong");
        task.await.unwrap()
    }
    fn normalize(data: &[u8]) -> Vec<u8> {
        let mut data = data.to_vec();
        for word in data.chunks_exact_mut(2) {
            if is_grease(u16::from_be_bytes([word[0], word[1]])) {
                word.copy_from_slice(&[0x0a, 0x0a]);
            }
        }
        data
    }
    #[tokio::test]
    async fn actual_client_hello_profiles_and_tls() {
        for profile in [
            "chrome", "firefox", "safari", "ios", "edge", "android", "360", "qq",
        ] {
            eprintln!("browser {profile}");
            let actual =
                tokio::time::timeout(std::time::Duration::from_secs(5), capture(profile, false))
                    .await
                    .unwrap();
            let expected = Hello::parse(template(profile).unwrap()).unwrap();
            assert_eq!(
                normalize(&actual.ciphers),
                normalize(&expected.ciphers),
                "{profile}"
            );
            assert_eq!(
                actual.ext(13),
                expected.ext(13),
                "signature algorithms {profile}"
            );
            assert_eq!(
                normalize(actual.ext(10).unwrap()),
                normalize(expected.ext(10).unwrap()),
                "groups {profile}"
            );
            assert!(actual
                .ext(0)
                .unwrap()
                .windows(10)
                .any(|v| v == b"proxy.test"));
            let mut a: Vec<_> = actual
                .extensions
                .iter()
                .map(|(t, _)| if is_grease(*t) { 0x0a0a } else { *t })
                .collect();
            let mut b: Vec<_> = expected
                .extensions
                .iter()
                .map(|(t, _)| if is_grease(*t) { 0x0a0a } else { *t })
                .collect();
            a.retain(|t| *t != 21);
            b.retain(|t| *t != 21);
            if profile == "chrome" {
                a.sort();
                b.sort();
            }
            assert_eq!(a, b, "extensions {profile}");
            if let (Some(a), Some(b)) = (actual.ext(51), expected.ext(51)) {
                assert_ne!(a, b, "snapshot key share must be replaced");
                let groups = actual.ext(10).unwrap();
                let mut c = Cursor { data: a, pos: 2 };
                while c.pos < a.len() {
                    let group = c.u16().unwrap() as u16;
                    c.v16().unwrap();
                    assert!(
                        groups[2..]
                            .chunks_exact(2)
                            .any(|g| g == group.to_be_bytes()),
                        "key share must be a supported group"
                    );
                }
            }
        }
        let a = capture("chrome", false).await;
        let b = capture("chrome", false).await;
        assert_ne!(&a.prefix[2..34], &b.prefix[2..34]);
        assert_ne!(a.ext(51), b.ext(51));
    }
    #[tokio::test]
    async fn browser_tls12_fallback() {
        for profile in [
            "chrome", "firefox", "safari", "ios", "edge", "android", "360", "qq",
        ] {
            capture_version(profile, false, true).await;
        }
    }
    #[tokio::test]
    async fn browser_hello_retry() {
        for profile in ["chrome", "firefox", "safari"] {
            capture(profile, true).await;
        }
    }
}
