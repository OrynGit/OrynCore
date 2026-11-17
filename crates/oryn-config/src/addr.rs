use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// 连接目标：IP 地址或域名，均带端口。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    /// 由主机字符串和端口构造；能解析为 IP 时优先使用 IP。
    pub fn from_host(host: &str, port: u16) -> Self {
        let trimmed = host.trim_start_matches('[').trim_end_matches(']');
        match trimmed.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
            Err(_) => TargetAddr::Domain(host.to_ascii_lowercase(), port),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(a) => a.port(),
            TargetAddr::Domain(_, p) => *p,
        }
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(a: SocketAddr) -> Self {
        TargetAddr::Ip(a)
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(a) => write!(f, "{a}"),
            TargetAddr::Domain(d, p) => write!(f, "{d}:{p}"),
        }
    }
}
