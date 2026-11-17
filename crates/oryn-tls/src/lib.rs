//! TLS / QUIC 客户端配置。
//!
//! - 加密实现使用 ring（rustls 的 `ring` provider）。
//! - 证书使用系统校验（Apple 平台为 Security.framework），尊重用户安装并信任的证书。
//! - `skip_verify` 时接受任意证书，只用于用户明确开启「跳过 TLS 验证」的场景。

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};

pub use tokio_rustls::client::TlsStream;

mod browser;
pub mod jls;
mod kx;
mod reality;
pub mod shadowtls;

pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_HTTP11: &[u8] = b"http/1.1";
pub const ALPN_H3: &[u8] = b"h3";
pub const ALPN_DOQ: &[u8] = b"doq";

pub fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

/// 不校验证书（仍校验握手签名，防止被动篡改之外的明显错误）。
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// 固定叶证书，仍由原校验器验证信任链（除非显式跳过）及握手签名。
#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    fingerprint: [u8; 32],
}
impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = ring::digest::digest(&ring::digest::SHA256, cert.as_ref());
        if digest.as_ref() != self.fingerprint {
            return Err(rustls::Error::General(
                "TLS certificate SHA-256 fingerprint mismatch".into(),
            ));
        }
        self.inner
            .verify_server_cert(cert, intermediates, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// 客户端允许的 TLS 版本。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Versions {
    Default,
    Tls13,
    /// ShadowTLS v1 / v2 的握手服务端按 TLS 1.2 工作。
    Tls12,
}

fn build_config(
    alpn: &[&[u8]],
    skip_verify: bool,
    versions: Versions,
    fingerprint: Option<[u8; 32]>,
    ech: Option<&[u8]>,
) -> Result<ClientConfig, rustls::Error> {
    // aws-lc-rs provider 同时提供 ECH HPKE 与 X25519MLKEM768；普通 TLS 也默认
    // 优先发送混合 key share。浏览器指纹路径在 connect_proxy 中使用独立 ring provider。
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = match versions {
        Versions::Tls13 => &[&rustls::version::TLS13],
        Versions::Tls12 => &[&rustls::version::TLS12],
        Versions::Default => rustls::DEFAULT_VERSIONS,
    };
    let builder = if let Some(config) = ech {
        let ech = rustls::client::EchConfig::new(
            EchConfigListBytes::from(config),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        )?;
        ClientConfig::builder_with_provider(provider.clone()).with_ech(ech.into())?
    } else {
        ClientConfig::builder_with_provider(provider.clone()).with_protocol_versions(versions)?
    };
    let inner: Arc<dyn ServerCertVerifier> = if skip_verify {
        Arc::new(NoVerify(provider))
    } else {
        system_verifier(provider.clone())?
    };
    let verifier: Arc<dyn ServerCertVerifier> = match fingerprint {
        Some(fingerprint) => Arc::new(PinnedVerifier { inner, fingerprint }),
        None => inner,
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    // 普通 TLS / DNS 保持原 wire 行为，证书压缩仅由浏览器模板启用。
    config.cert_decompressors.clear();
    config.cert_compressors.clear();
    Ok(config)
}

/// 非 Android 使用系统证书库。Android 上 `rustls-platform-verifier` 未接入 JVM 时会在校验中 panic，
/// 所以改用内置的 Mozilla 根证书，校验失败只断开这一条 TLS，不结束进程。
fn system_verifier(
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, rustls::Error> {
    #[cfg(target_os = "android")]
    {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map(|verifier| verifier as Arc<dyn ServerCertVerifier>)
            .map_err(|error| rustls::Error::General(error.to_string()))
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(Arc::new(rustls_platform_verifier::Verifier::new(provider)?))
    }
}

type Key = (Vec<Vec<u8>>, bool, Versions);

fn cached(alpn: &[&[u8]], skip_verify: bool, versions: Versions) -> io::Result<Arc<ClientConfig>> {
    static CACHE: OnceLock<Mutex<HashMap<Key, Arc<ClientConfig>>>> = OnceLock::new();
    let key: Key = (
        alpn.iter().map(|p| p.to_vec()).collect(),
        skip_verify,
        versions,
    );
    let cache = CACHE.get_or_init(Default::default);
    if let Some(c) = cache.lock().unwrap().get(&key) {
        return Ok(c.clone());
    }
    let config =
        Arc::new(build_config(alpn, skip_verify, versions, None, None).map_err(io::Error::other)?);
    let mut cache = cache.lock().unwrap();
    if cache.len() < 32 {
        cache.insert(key, config.clone());
    }
    Ok(config)
}

/// TCP 上使用的 TLS 客户端配置（带缓存）。
pub fn client_config(alpn: &[&[u8]], skip_verify: bool) -> io::Result<Arc<ClientConfig>> {
    cached(alpn, skip_verify, Versions::Default)
}

pub fn server_name(host: &str) -> io::Result<ServerName<'static>> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(host.to_string()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TLS server name `{host}`"),
        )
    })
}

/// 在已建立的流上进行 TLS 握手。
pub async fn connect<S>(
    stream: S,
    host: &str,
    alpn: &[&[u8]],
    skip_verify: bool,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = client_config(alpn, skip_verify)?;
    tokio_rustls::TlsConnector::from(config)
        .connect(server_name(host)?, stream)
        .await
}

/// 代理 TLS：带证书固定值的配置不进入全局缓存，避免配置重载积累。
pub async fn connect_pinned<S>(
    stream: S,
    host: &str,
    alpn: &[&[u8]],
    skip_verify: bool,
    fingerprint: Option<[u8; 32]>,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = match fingerprint {
        None => client_config(alpn, skip_verify)?,
        Some(pin) => Arc::new(
            build_config(alpn, skip_verify, Versions::Default, Some(pin), None)
                .map_err(io::Error::other)?,
        ),
    };
    tokio_rustls::TlsConnector::from(config)
        .connect(server_name(host)?, stream)
        .await
}

/// 使用配置文件中提供的 ECHConfigList 建立 TLS 1.3 连接。
pub async fn connect_ech<S>(
    stream: S,
    host: &str,
    alpn: &[&[u8]],
    skip_verify: bool,
    ech: &oryn_config::EchSpec,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = Arc::new(
        build_config(alpn, skip_verify, Versions::Tls13, None, Some(&ech.config))
            .map_err(io::Error::other)?,
    );
    tokio_rustls::TlsConnector::from(config)
        .connect(server_name(host)?, stream)
        .await
}

/// 节点 TLS 安全层：普通 TLS 与指纹 / Reality 返回相同类型，不向上层泄漏 TLS 决策。
pub async fn connect_proxy<S>(
    stream: S,
    host: &str,
    spec: &oryn_config::TlsSpec,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(ech) = &spec.ech {
        if spec.fingerprint.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ECH cannot be combined with a certificate fingerprint",
            ));
        }
        if spec.client_fingerprint.is_some() || spec.reality.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ECH cannot be combined with browser fingerprint or Reality",
            ));
        }
        let alpn: Vec<&[u8]> = spec.alpn.iter().map(|a| a.as_bytes()).collect();
        return connect_ech(stream, host, &alpn, spec.skip_cert_verify, ech).await;
    }
    let Some(profile) = spec.client_fingerprint.as_deref() else {
        if spec.reality.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Reality requires a browser fingerprint",
            ));
        }
        let alpn: Vec<&[u8]> = spec.alpn.iter().map(|a| a.as_bytes()).collect();
        return connect_pinned(stream, host, &alpn, spec.skip_cert_verify, spec.fingerprint).await;
    };
    let profile = browser::choose(profile).map_err(io::Error::other)?;
    let reality = spec.reality.is_some();
    if reality && (profile == "android" || spec.fingerprint.is_some()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Reality TLS settings",
        ));
    }
    let mut provider = rustls::crypto::ring::default_provider();
    if profile != "android" {
        provider.kx_groups = vec![
            if profile == "firefox" {
                &kx::FIREFOX_X25519
            } else {
                &kx::X25519
            },
            rustls::crypto::ring::kx_group::SECP256R1,
            rustls::crypto::ring::kx_group::SECP384R1,
        ];
    }
    let provider = Arc::new(provider);
    let versions: &[&rustls::SupportedProtocolVersion] = if reality {
        &[&rustls::version::TLS13]
    } else if profile == "android" {
        &[&rustls::version::TLS12]
    } else {
        rustls::DEFAULT_VERSIONS
    };
    let auth: reality::AuthKey = Default::default();
    let inner: Arc<dyn ServerCertVerifier> = if reality {
        Arc::new(reality::RealityVerifier {
            auth: auth.clone(),
            signatures: NoVerify(provider.clone()),
        })
    } else if spec.skip_cert_verify {
        Arc::new(NoVerify(provider.clone()))
    } else {
        system_verifier(provider.clone()).map_err(io::Error::other)?
    };
    let verifier: Arc<dyn ServerCertVerifier> = match spec.fingerprint {
        Some(fingerprint) => Arc::new(PinnedVerifier { inner, fingerprint }),
        None => inner,
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = if spec.alpn.is_empty() {
        browser::default_alpn(profile)
    } else {
        spec.alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
    };
    config.oryn_client_hello = Some(Arc::new(browser::BrowserHello::new(
        profile,
        spec.reality.clone(),
        auth,
    )));
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name(host)?, stream)
        .await
}

/// 协商出的 ALPN。
pub fn negotiated_alpn<S>(stream: &TlsStream<S>) -> Option<Vec<u8>> {
    stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
}

/// QUIC 客户端配置（TLS 1.3）。
pub fn quic_client_config(alpn: &[&[u8]], skip_verify: bool) -> io::Result<quinn::ClientConfig> {
    quic_client_config_ex(alpn, skip_verify, None, true, false)
}

/// `enable_sni` 为 false 时不发送 SNI。证书固定与系统校验仍然生效。
pub fn quic_client_config_ex(
    alpn: &[&[u8]],
    skip_verify: bool,
    fingerprint: Option<[u8; 32]>,
    enable_sni: bool,
    early_data: bool,
) -> io::Result<quinn::ClientConfig> {
    let mut tls = build_config(alpn, skip_verify, Versions::Tls13, fingerprint, None)
        .map_err(io::Error::other)?;
    tls.enable_sni = enable_sni;
    // 每个 QUIC 出站只连一个服务器，少量会话票据就够；调用方需复用返回的配置，票据才能跨连接保留。
    // rustls 按每服务器 8 张票据折算服务器数，折算成 1 时新条目会被立刻淘汰，所以至少给到 2 个服务器
    tls.resumption = rustls::client::Resumption::in_memory_sessions(32);
    tls.enable_early_data = early_data;
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ech_with_certificate_pin_is_rejected_before_handshake() {
        for skip in [false, true] {
            let spec = oryn_config::TlsSpec {
                sni: None,
                skip_cert_verify: skip,
                alpn: vec![],
                fingerprint: Some([0x11; 32]),
                client_fingerprint: None,
                reality: None,
                // 故意不是合法 ECHConfigList：组合检查必须先于配置解析与任何 I/O。
                ech: Some(oryn_config::EchSpec { config: vec![1, 2, 3, 4] }),
            };
            let (client, _server) = tokio::io::duplex(16);
            let err = connect_proxy(client, "example.test", &spec).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("certificate fingerprint"));
        }
    }

    #[test]
    fn configs_are_cached_and_valid() {
        let a = client_config(&[ALPN_H2], true).unwrap();
        let b = client_config(&[ALPN_H2], true).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(client_config(&[], false).is_ok(), "系统证书校验器可用");
        assert!(quic_client_config(&[ALPN_DOQ], false).is_ok());
        assert!(
            server_name("1.1.1.1").is_ok()
                && server_name("[2001:db8::1]").is_ok()
                && server_name("dns.google").is_ok()
        );
        assert!(server_name("bad name").is_err());
    }
}
