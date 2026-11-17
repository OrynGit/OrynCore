//! GEOIP：MaxMind DB（MMDB）国家库，内存映射加载，不计入进程的脏内存。

use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use maxminddb::PathElement;
use oryn_config::IpCidr;

pub trait GeoLookup: Send + Sync {
    /// 大写的国家代码。
    fn country(&self, ip: IpAddr) -> Option<String>;

    /// 自治系统号；国家库返回 `None`。
    fn asn(&self, _ip: IpAddr) -> Option<u32> {
        None
    }
}

/// 基于 MMDB 文件的查询。
pub struct Mmdb<S: AsRef<[u8]> + Send + Sync> {
    reader: maxminddb::Reader<S>,
}

impl Mmdb<maxminddb::Mmap> {
    pub fn open(path: &Path) -> Result<Self, String> {
        // SAFETY：数据库文件由 Oryn 下载并原子替换（先写临时文件再改名），映射期间不会被原地修改。
        let reader = unsafe { maxminddb::Reader::open_mmap(path) }.map_err(|e| e.to_string())?;
        Ok(Mmdb { reader })
    }
}

impl Mmdb<Vec<u8>> {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        maxminddb::Reader::from_source(bytes)
            .map(|reader| Mmdb { reader })
            .map_err(|e| e.to_string())
    }
}

impl<S: AsRef<[u8]> + Send + Sync> Mmdb<S> {
    pub fn validate_kind(&self, asn: bool) -> Result<(), String> {
        let kind = self.reader.metadata().database_type.to_ascii_lowercase();
        let valid = if asn {
            kind.contains("asn")
        } else {
            kind.contains("country") || kind.contains("city")
        };
        if valid {
            Ok(())
        } else {
            Err(format!("unexpected MMDB database type: {kind}"))
        }
    }
}

impl<S: AsRef<[u8]> + Send + Sync> GeoLookup for Mmdb<S> {
    fn country(&self, ip: IpAddr) -> Option<String> {
        let result = self.reader.lookup(ip).ok()?;
        for key in ["country", "registered_country"] {
            if let Ok(Some(code)) =
                result.decode_path::<String>(&[PathElement::Key(key), PathElement::Key("iso_code")])
            {
                return Some(code.to_ascii_uppercase());
            }
        }
        None
    }

    fn asn(&self, ip: IpAddr) -> Option<u32> {
        let result = self.reader.lookup(ip).ok()?;
        result
            .decode_path::<u32>(&[PathElement::Key("autonomous_system_number")])
            .ok()
            .flatten()
    }
}

/// 可热替换的 GEOIP / ASN 数据库。
#[derive(Default)]
pub struct GeoIp {
    db: RwLock<Option<Arc<dyn GeoLookup>>>,
}

impl GeoIp {
    pub fn set(&self, db: Option<Arc<dyn GeoLookup>>) {
        *self.db.write().unwrap() = db;
    }

    pub fn is_loaded(&self) -> bool {
        self.db.read().unwrap().is_some()
    }

    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let db = self.db.read().unwrap().clone()?;
        db.country(unmap(ip))
    }

    /// `IP-ASN,<asn>` 使用的查询。
    pub fn asn(&self, ip: IpAddr) -> Option<u32> {
        let db = self.db.read().unwrap().clone()?;
        db.asn(unmap(ip))
    }

    /// 一组 `GEOIP,<code>` 中是否有匹配的。国家最多查一次：每次查询都是一次完整的 MMDB 树遍历
    /// 加一次字符串分配，含多个 GEOIP 的规则集原来每个 code 各查一遍。
    pub fn matches_any<'a>(&self, codes: impl IntoIterator<Item = &'a str>, ip: IpAddr) -> bool {
        let mut country: Option<Option<String>> = None;
        codes.into_iter().any(|code| {
            if code == "LAN" {
                is_lan(ip)
            } else {
                country.get_or_insert_with(|| self.country(ip)).as_deref() == Some(code)
            }
        })
    }

    /// `GEOIP,<code>` 是否匹配；`LAN` 匹配局域网与保留地址。
    pub fn matches(&self, code: &str, ip: IpAddr) -> bool {
        if code == "LAN" {
            return is_lan(ip);
        }
        self.country(ip).is_some_and(|c| c == code)
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

const LAN: [&str; 14] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

/// 局域网、回环、链路本地、组播等保留地址。
pub fn is_lan(ip: IpAddr) -> bool {
    use std::sync::OnceLock;
    static SET: OnceLock<crate::sets::IpSet> = OnceLock::new();
    SET.get_or_init(|| {
        let cidrs: Vec<IpCidr> = LAN.iter().filter_map(|c| IpCidr::parse(c)).collect();
        crate::sets::IpSet::build(&cidrs)
    })
    .contains(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake;
    impl GeoLookup for Fake {
        fn country(&self, ip: IpAddr) -> Option<String> {
            (ip == "1.2.3.4".parse::<IpAddr>().unwrap()).then(|| "CN".to_string())
        }
    }

    /// 与 oryn-core 端到端测试中的生成器相同：只含 IPv4 网段的最小国家库。
    fn build_mmdb(networks: &[([u8; 4], u8, &str)]) -> Vec<u8> {
        #[derive(Clone, Copy)]
        enum Rec {
            Empty,
            Node(usize),
            Data(usize),
        }
        let mut data = Vec::new();
        let mut offsets: std::collections::HashMap<String, usize> = Default::default();
        let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty, Rec::Empty]];
        for (ip, prefix, code) in networks {
            let off = *offsets.entry(code.to_string()).or_insert_with(|| {
                let off = data.len();
                data.push(0xE1);
                data.push(0x40 | 7);
                data.extend_from_slice(b"country");
                data.push(0xE1);
                data.push(0x40 | 8);
                data.extend_from_slice(b"iso_code");
                data.push(0x40 | code.len() as u8);
                data.extend_from_slice(code.as_bytes());
                off
            });
            let bits = u32::from_be_bytes(*ip);
            let mut node = 0usize;
            for depth in 0..*prefix {
                let bit = ((bits >> (31 - depth)) & 1) as usize;
                if depth + 1 == *prefix {
                    nodes[node][bit] = Rec::Data(off);
                } else {
                    node = match nodes[node][bit] {
                        Rec::Node(n) => n,
                        _ => {
                            nodes.push([Rec::Empty, Rec::Empty]);
                            let n = nodes.len() - 1;
                            nodes[node][bit] = Rec::Node(n);
                            n
                        }
                    };
                }
            }
        }
        let count = nodes.len();
        let mut out = Vec::new();
        for n in &nodes {
            for r in n {
                let v = match *r {
                    Rec::Empty => count,
                    Rec::Node(i) => i,
                    Rec::Data(off) => count + 16 + off,
                } as u32;
                out.extend_from_slice(&v.to_be_bytes()[1..]);
            }
        }
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&data);
        out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
        let key = |out: &mut Vec<u8>, k: &str| {
            out.push(0x40 | k.len() as u8);
            out.extend_from_slice(k.as_bytes());
        };
        out.push(0xE0 | 9);
        key(&mut out, "binary_format_major_version");
        out.extend_from_slice(&[0xA1, 2]);
        key(&mut out, "binary_format_minor_version");
        out.push(0xA0);
        key(&mut out, "build_epoch");
        out.extend_from_slice(&[0x08, 0x02, 0, 0, 0, 0, 0x65, 0, 0, 0]);
        key(&mut out, "database_type");
        key(&mut out, "Test-Country");
        key(&mut out, "description");
        out.push(0xE0);
        key(&mut out, "ip_version");
        out.extend_from_slice(&[0xA1, 4]);
        key(&mut out, "languages");
        out.extend_from_slice(&[0x00, 0x04]);
        key(&mut out, "node_count");
        out.push(0xC4);
        out.extend_from_slice(&(count as u32).to_be_bytes());
        key(&mut out, "record_size");
        out.extend_from_slice(&[0xA1, 24]);
        out
    }

    #[test]
    fn mmdb_lookup() {
        let db = Mmdb::from_bytes(build_mmdb(&[
            ([114, 0, 0, 0], 8, "CN"),
            ([8, 8, 8, 0], 24, "US"),
        ]))
        .unwrap();
        assert_eq!(
            db.country("114.114.114.114".parse().unwrap()).as_deref(),
            Some("CN")
        );
        assert_eq!(
            db.country("8.8.8.8".parse().unwrap()).as_deref(),
            Some("US")
        );
        assert_eq!(db.country("1.1.1.1".parse().unwrap()), None);
        assert!(Mmdb::from_bytes(b"not a database".to_vec()).is_err());
    }

    #[test]
    fn lan_and_lookup() {
        assert!(is_lan("192.168.1.1".parse().unwrap()) && is_lan("fe80::1".parse().unwrap()));
        assert!(!is_lan("8.8.8.8".parse().unwrap()));
        let g = GeoIp::default();
        assert!(
            !g.matches("CN", "1.2.3.4".parse().unwrap()),
            "未加载时不命中"
        );
        g.set(Some(Arc::new(Fake)));
        assert!(g.matches("CN", "1.2.3.4".parse().unwrap()));
        assert!(g.matches("CN", "::ffff:1.2.3.4".parse().unwrap()));
        assert!(!g.matches("US", "1.2.3.4".parse().unwrap()));
        assert!(g.matches("LAN", "10.0.0.1".parse().unwrap()));
    }
}
