//! MITM CA 与有界叶证书缓存。私钥不进入日志，导出配置描述文件只含公钥证书。
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use std::{collections::VecDeque, io, sync::Arc};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroize;
/// 叶证书缓存上限：每条约数 KB（证书 + 私钥 + rustls 配置），超出后每个新主机都要生成密钥并签名。
pub const MAX_LEAF_CACHE: usize = 128;
#[derive(Clone, PartialEq, Eq)]
pub struct CaMaterial {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
}
impl Drop for CaMaterial {
    fn drop(&mut self) {
        self.private_key_der.zeroize();
    }
}
impl std::fmt::Debug for CaMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CaMaterial { private_key: REDACTED }")
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct LeafMaterial {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
}
impl Drop for LeafMaterial {
    fn drop(&mut self) {
        self.private_key_der.zeroize();
    }
}
impl std::fmt::Debug for LeafMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LeafMaterial { private_key: REDACTED }")
    }
}
pub struct CertificateAuthority {
    material: CaMaterial,
    issuer: Issuer<'static, KeyPair>,
    expires: OffsetDateTime,
    leaves: VecDeque<Leaf>,
}
struct Leaf {
    host: String,
    material: LeafMaterial,
    expires: OffsetDateTime,
    /// 按是否允许 h2 缓存的 rustls 配置，避免每条连接重建。
    configs: [Option<Arc<ServerConfig>>; 2],
}
fn error(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
impl CertificateAuthority {
    pub fn generate(common_name: &str) -> io::Result<Self> {
        let key = KeyPair::generate().map_err(error)?;
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, common_name);
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        p.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
        let c = p.self_signed(&key).map_err(error)?;
        Self::from_material(CaMaterial {
            certificate_der: c.der().to_vec(),
            private_key_der: key.serialize_der(),
        })
    }
    pub fn from_material(material: CaMaterial) -> io::Result<Self> {
        if material.certificate_der.len() > 32768 || material.private_key_der.len() > 32768 {
            return Err(error("CA material exceeds limit"));
        }
        let key = KeyPair::try_from(material.private_key_der.as_slice()).map_err(error)?;
        let (rest, cert) =
            x509_parser::parse_x509_certificate(&material.certificate_der).map_err(error)?;
        if !rest.is_empty() || !cert.is_ca() || !cert.validity().is_valid() {
            return Err(error("MITM CA is invalid, expired or not a CA"));
        }
        if cert
            .key_usage()
            .map_err(error)?
            .is_some_and(|k| !k.value.key_cert_sign())
        {
            return Err(error("CA cannot sign certificates"));
        }
        if cert.public_key().raw != key.subject_public_key_info() {
            return Err(error("CA private key does not match certificate"));
        }
        let expires = OffsetDateTime::from_unix_timestamp(cert.validity().not_after.timestamp())
            .map_err(error)?;
        let issuer = Issuer::from_ca_cert_der(
            &CertificateDer::from(material.certificate_der.as_slice()),
            key,
        )
        .map_err(error)?;
        Ok(Self {
            material,
            issuer,
            expires,
            leaves: VecDeque::new(),
        })
    }
    pub fn material(&self) -> &CaMaterial {
        &self.material
    }
    pub fn leaf(&mut self, host: &str) -> io::Result<LeafMaterial> {
        let i = self.leaf_index(host)?;
        Ok(self.leaves[i].material.clone())
    }
    /// 取得（或生成）主机的叶证书，移到最近使用的位置并返回其下标。
    fn leaf_index(&mut self, host: &str) -> io::Result<usize> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        // IP 主机（无 SNI 时回退为目的地址）由 rcgen 写成 iPAddress SAN，不是 dNSName。
        rustls::pki_types::ServerName::try_from(h.clone()).map_err(error)?;
        if h.is_empty() || h.contains('*') {
            return Err(error("invalid MITM hostname"));
        }
        if let Some(i) = self
            .leaves
            .iter()
            .position(|l| l.host == h && l.expires > OffsetDateTime::now_utc())
        {
            let v = self.leaves.remove(i).unwrap();
            self.leaves.push_back(v);
            return Ok(self.leaves.len() - 1);
        }
        if self.expires <= OffsetDateTime::now_utc() {
            return Err(error("MITM CA expired"));
        }
        let key = KeyPair::generate().map_err(error)?;
        let mut p = CertificateParams::new(vec![h.clone()]).map_err(error)?;
        p.distinguished_name.push(DnType::CommonName, &h);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        p.not_after = self
            .expires
            .min(OffsetDateTime::now_utc() + Duration::days(90));
        let cert = p.signed_by(&key, &self.issuer).map_err(error)?;
        let material = LeafMaterial {
            certificate_der: cert.der().to_vec(),
            private_key_der: key.serialize_der(),
        };
        // 同名但已过期的旧条目一并去掉。
        self.leaves.retain(|l| l.host != h);
        if self.leaves.len() >= MAX_LEAF_CACHE {
            self.leaves.pop_front();
        }
        self.leaves.push_back(Leaf {
            host: h,
            material,
            expires: p.not_after,
            configs: [None, None],
        });
        Ok(self.leaves.len() - 1)
    }
    pub fn server_config(&mut self, host: &str, http2: bool) -> io::Result<Arc<ServerConfig>> {
        let i = self.leaf_index(host)?;
        if let Some(config) = &self.leaves[i].configs[usize::from(http2)] {
            return Ok(config.clone());
        }
        let leaf = &self.leaves[i].material;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.private_key_der.clone()));
        let mut config = ServerConfig::builder_with_provider(oryn_tls::provider())
            .with_safe_default_protocol_versions()
            .map_err(error)?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.certificate_der.clone())],
                key,
            )
            .map_err(error)?;
        config.alpn_protocols = if http2 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        config.send_tls13_tickets = 0;
        let config = Arc::new(config);
        self.leaves[i].configs[usize::from(http2)] = Some(config.clone());
        Ok(config)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reload_and_sign() {
        let ca = CertificateAuthority::generate("Oryn MITM CA").unwrap();
        let mut ca = CertificateAuthority::from_material(ca.material().clone()).unwrap();
        let a = ca.leaf("api.example.com").unwrap();
        assert_eq!(a, ca.leaf("api.example.com").unwrap());
        assert!(ca
            .server_config("api.example.com", true)
            .unwrap()
            .alpn_protocols
            .contains(&b"h2".to_vec()));
    }
    #[test]
    fn ip_hosts_get_ip_address_san_and_configs_are_cached() {
        let mut ca = CertificateAuthority::generate("IP fixture").unwrap();
        for host in ["1.2.3.4", "2001:db8::1"] {
            let leaf = ca.leaf(host).unwrap();
            let (_, cert) = x509_parser::parse_x509_certificate(&leaf.certificate_der).unwrap();
            let san = cert.subject_alternative_name().unwrap().unwrap();
            assert!(san
                .value
                .general_names
                .iter()
                .all(|n| matches!(n, x509_parser::extensions::GeneralName::IPAddress(_))));
        }
        let a = ca.server_config("a.test", true).unwrap();
        let b = ca.server_config("a.test", true).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, &ca.server_config("a.test", false).unwrap()));
    }
    #[test]
    fn mismatched_private_key_rejected() {
        let a = CertificateAuthority::generate("A").unwrap();
        let b = CertificateAuthority::generate("B").unwrap();
        let mut m = a.material().clone();
        m.private_key_der = b.material().private_key_der.clone();
        assert!(CertificateAuthority::from_material(m).is_err());
    }
    #[test]
    fn leaf_cache_expiry_and_capacity() {
        let mut ca = CertificateAuthority::generate("Cache fixture").unwrap();
        let old = ca.leaf("fixture.test").unwrap();
        ca.leaves.front_mut().unwrap().expires = OffsetDateTime::now_utc() - Duration::seconds(1);
        assert_ne!(old, ca.leaf("fixture.test").unwrap());
        for n in 0..MAX_LEAF_CACHE + 3 {
            ca.leaf(&format!("host{n}.test")).unwrap();
        }
        assert_eq!(ca.leaves.len(), MAX_LEAF_CACHE);
        ca.leaves.clear();
        ca.expires = OffsetDateTime::now_utc() - Duration::seconds(1);
        assert!(ca.leaf("fixture.test").is_err());
    }
}
