//! VLESS Encryption 配置编译。公钥与 padding 在加载时校验，不记录凭据原文。
use crate::ConfigError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    Native,
    XorPub,
    Random,
}

#[derive(Debug, Clone, Copy)]
pub struct EncryptionPadding {
    pub probability: u8,
    pub min: u16,
    pub max: u16,
}

#[derive(Clone)]
pub struct VlessEncryptionSpec {
    pub mode: EncryptionMode,
    pub zero_rtt: bool,
    pub keys: Vec<Vec<u8>>,
    /// 偶数项为分片长度，奇数项为分片间隔（毫秒）。
    pub padding: Vec<EncryptionPadding>,
}
impl std::fmt::Debug for VlessEncryptionSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessEncryptionSpec")
            .field("mode", &self.mode)
            .field("zero_rtt", &self.zero_rtt)
            .field("key_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl VlessEncryptionSpec {
    pub fn parse(value: &str) -> Result<Option<Self>, ConfigError> {
        let bad = || ConfigError("invalid VLESS encryption configuration".into());
        if value.is_empty() || value == "none" {
            return Ok(None);
        }
        if value.len() > 16 * 1024 {
            return Err(bad());
        }
        let parts: Vec<_> = value.split('.').collect();
        if parts.len() < 4 || parts.len() > 27 || parts[0] != "mlkem768x25519plus" {
            return Err(bad());
        }
        let mode = match parts[1] {
            "native" => EncryptionMode::Native,
            "xorpub" => EncryptionMode::XorPub,
            "random" => EncryptionMode::Random,
            _ => return Err(bad()),
        };
        let zero_rtt = match parts[2] {
            "0rtt" => true,
            "1rtt" => false,
            _ => return Err(bad()),
        };
        let mut keys = Vec::new();
        let mut padding = Vec::new();
        let mut max_length = 0usize;
        let mut max_gap = 0usize;
        for p in &parts[3..] {
            if p.len() < 20 {
                if padding.len() >= 16 {
                    return Err(bad());
                }
                let fields: Vec<_> = p.split('-').collect();
                if fields.len() != 3
                    || fields
                        .iter()
                        .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()))
                {
                    return Err(bad());
                }
                let probability = fields[0].parse::<u8>().map_err(|_| bad())?;
                let min = fields[1].parse::<u16>().map_err(|_| bad())?;
                let max = fields[2].parse::<u16>().map_err(|_| bad())?;
                if probability > 100
                    || (padding.is_empty() && (probability != 100 || min < 35 || max < 35))
                {
                    return Err(bad());
                }
                if padding.len() % 2 == 0 {
                    max_length += min.max(max) as usize;
                } else {
                    max_gap += min.max(max) as usize;
                }
                padding.push(EncryptionPadding {
                    probability,
                    min,
                    max,
                });
            } else {
                if keys.len() >= 8 {
                    return Err(bad());
                }
                let key = URL_SAFE_NO_PAD.decode(p).map_err(|_| bad())?;
                if !valid_key(&key) {
                    return Err(bad());
                }
                keys.push(key);
            }
        }
        if keys.is_empty() || max_length > 65553 || max_gap > 3000 {
            return Err(bad());
        }
        Ok(Some(Self {
            mode,
            zero_rtt,
            keys,
            padding,
        }))
    }
}

fn valid_key(k: &[u8]) -> bool {
    match k.len() {
        32 => k.iter().any(|b| *b != 0),
        // FIPS 203 的公钥模数校验；最后 32 字节为 rho。
        1184 => k[..1152].chunks_exact(3).all(|b| {
            (u16::from(b[0]) | u16::from(b[1] & 15) << 8) < 3329
                && (u16::from(b[1] >> 4) | u16::from(b[2]) << 4) < 3329
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    #[test]
    fn modes_padding_and_key_limits() {
        for mode in ["native", "xorpub", "random"] {
            for rtt in ["1rtt", "0rtt"] {
                let s = VlessEncryptionSpec::parse(&format!(
                    "mlkem768x25519plus.{mode}.{rtt}.100-35-35.{KEY}"
                ))
                .unwrap()
                .unwrap();
                assert_eq!(s.zero_rtt, rtt == "0rtt");
                assert_eq!(s.keys.len(), 1);
            }
        }
        for extra in [
            "",
            "100-34-34",
            "101-35-35",
            "100-65535-65535.100-0-0.100-35-35",
            "100-35-35.100-3001-3001",
            "50-35-35",
            "100--35",
            "100-35-35-1",
        ] {
            assert!(
                VlessEncryptionSpec::parse(&format!(
                    "mlkem768x25519plus.native.0rtt.{extra}.{KEY}"
                ))
                .is_err(),
                "{extra}"
            );
        }
        assert!(VlessEncryptionSpec::parse(&format!(
            "mlkem768x25519plus.native.0rtt.{}",
            [KEY; 9].join(".")
        ))
        .is_err());
        assert!(VlessEncryptionSpec::parse(
            "mlkem768x25519plus.native.0rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(VlessEncryptionSpec::parse(&format!(
            "mlkem768x25519plus.native.0rtt.{}",
            URL_SAFE_NO_PAD.encode([255; 1184])
        ))
        .is_err());
        for wrong in [
            "mlkem",
            "mlkem768x25519plus.unknown.0rtt",
            "mlkem768x25519plus.native.2rtt",
        ] {
            assert!(VlessEncryptionSpec::parse(wrong).is_err());
        }
    }
}
