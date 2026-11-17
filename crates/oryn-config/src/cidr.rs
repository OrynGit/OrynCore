use std::fmt;
use std::net::IpAddr;

/// IPv4 / IPv6 网段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn parse(s: &str) -> Option<IpCidr> {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip.parse::<IpAddr>().ok()?, Some(p.parse::<u8>().ok()?)),
            None => (s.parse::<IpAddr>().ok()?, None),
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        Some(IpCidr { addr: ip, prefix })
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// 去掉主机位后的网段，如 `203.0.113.9/24` → `203.0.113.0/24`。
    pub fn network(&self) -> IpCidr {
        let addr = match self.addr {
            IpAddr::V4(a) => IpAddr::V4((u32::from(a) & mask_u32(self.prefix)).into()),
            IpAddr::V6(a) => IpAddr::V6((u128::from(a) & mask_u128(self.prefix)).into()),
        };
        IpCidr {
            addr,
            prefix: self.prefix,
        }
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// IPv4 网段的闭区间 `[起始, 结束]`。
    pub fn range_v4(&self) -> Option<(u32, u32)> {
        match self.addr {
            IpAddr::V4(a) => {
                let mask = mask_u32(self.prefix);
                let start = u32::from(a) & mask;
                Some((start, start | !mask))
            }
            IpAddr::V6(_) => None,
        }
    }

    /// IPv6 网段的闭区间 `[起始, 结束]`。
    pub fn range_v6(&self) -> Option<(u128, u128)> {
        match self.addr {
            IpAddr::V6(a) => {
                let mask = mask_u128(self.prefix);
                let start = u128::from(a) & mask;
                Some((start, start | !mask))
            }
            IpAddr::V4(_) => None,
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = mask_u32(self.prefix);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = mask_u128(self.prefix);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            // IPv4 映射的 IPv6 地址按 IPv4 匹配
            (IpAddr::V4(_), IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => self.contains(IpAddr::V4(v4)),
                None => false,
            },
            _ => false,
        }
    }
}

fn mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

fn mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4() {
        let c = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(c.contains("::ffff:10.0.0.1".parse().unwrap()));
        assert!(IpCidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        assert!(IpCidr::parse("1.2.3.4")
            .unwrap()
            .contains("1.2.3.4".parse().unwrap()));
        assert!(IpCidr::parse("1.2.3.4/33").is_none());
    }

    #[test]
    fn v6() {
        let c = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap()));
        assert!(!c.contains("10.0.0.1".parse().unwrap()));
    }
}
