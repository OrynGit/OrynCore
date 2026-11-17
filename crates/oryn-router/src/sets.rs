//! 紧凑的集合结构，用于可能很大的规则集（十万条量级）。
//!
//! - [`StrSet`]：所有字符串排序后拼接在一块内存中，只额外保存偏移，二分查找。
//! - [`DomainSet`]：完整、后缀（含本身）、仅子域名、通配四类。
//! - [`IpSet`]：合并后的地址区间，二分查找。

use std::net::IpAddr;

use oryn_config::{DomainPattern, IpCidr};

/// 只读字符串集合。每项额外开销 4 字节。
#[derive(Debug, Default, Clone)]
pub struct StrSet {
    data: String,
    /// 第 i 项为 `data[offsets[i]..offsets[i + 1]]`，末尾多存一个结束偏移。
    offsets: Vec<u32>,
}

impl StrSet {
    pub fn build(mut items: Vec<String>) -> StrSet {
        items.sort_unstable();
        items.dedup();
        let total: usize = items.iter().map(String::len).sum();
        let mut data = String::with_capacity(total);
        let mut offsets = Vec::with_capacity(items.len() + 1);
        for s in &items {
            offsets.push(data.len() as u32);
            data.push_str(s);
        }
        offsets.push(data.len() as u32);
        StrSet { data, offsets }
    }

    pub fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get(&self, i: usize) -> &str {
        &self.data[self.offsets[i] as usize..self.offsets[i + 1] as usize]
    }

    pub fn contains(&self, s: &str) -> bool {
        let (mut lo, mut hi) = (0usize, self.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.get(mid).cmp(s) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        false
    }
}

#[derive(Debug, Default)]
pub struct DomainSetBuilder {
    exact: Vec<String>,
    suffix: Vec<String>,
    subdomains: Vec<String>,
    wildcards: Vec<Vec<String>>,
}

impl DomainSetBuilder {
    pub fn add(&mut self, p: DomainPattern) {
        match p {
            DomainPattern::Exact(d) => self.exact.push(d),
            DomainPattern::Suffix(d) => self.suffix.push(d),
            DomainPattern::Subdomains(d) => self.subdomains.push(d),
            DomainPattern::Wildcard(l) => self.wildcards.push(l),
        }
    }

    pub fn build(self) -> DomainSet {
        DomainSet {
            exact: StrSet::build(self.exact),
            suffix: StrSet::build(self.suffix),
            subdomains: StrSet::build(self.subdomains),
            wildcards: self.wildcards,
        }
    }
}

#[derive(Debug, Default)]
pub struct DomainSet {
    exact: StrSet,
    suffix: StrSet,
    subdomains: StrSet,
    wildcards: Vec<Vec<String>>,
}

impl DomainSet {
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffix.len() + self.subdomains.len() + self.wildcards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `domain` 须已规范化（小写、无末尾点）。
    pub fn contains(&self, domain: &str) -> bool {
        if self.exact.contains(domain) || self.suffix.contains(domain) {
            return true;
        }
        let mut rest = domain;
        while let Some(i) = rest.find('.') {
            rest = &rest[i + 1..];
            if self.suffix.contains(rest) || self.subdomains.contains(rest) {
                return true;
            }
        }
        if !self.wildcards.is_empty() {
            // 不收集标签：先按标签数筛掉，再逐段比较（每连接每规则集原来都要分配一个 Vec）
            let count = domain.split('.').count();
            return self.wildcards.iter().any(|w| {
                w.len() == count
                    && w.iter()
                        .zip(domain.split('.'))
                        .all(|(p, l)| p == "*" || p == l)
            });
        }
        false
    }
}

#[derive(Debug, Default, Clone)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merge<T: Ord + Copy + num_like::Step>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        match out.last_mut() {
            Some(last) if s <= last.1.next_or_max() => {
                if e > last.1 {
                    last.1 = e;
                }
            }
            _ => out.push((s, e)),
        }
    }
    out
}

mod num_like {
    pub trait Step {
        fn next_or_max(self) -> Self;
    }
    impl Step for u32 {
        fn next_or_max(self) -> Self {
            self.saturating_add(1)
        }
    }
    impl Step for u128 {
        fn next_or_max(self) -> Self {
            self.saturating_add(1)
        }
    }
}

fn find<T: Ord + Copy>(ranges: &[(T, T)], x: T) -> bool {
    let i = ranges.partition_point(|r| r.0 <= x);
    i > 0 && ranges[i - 1].1 >= x
}

impl IpSet {
    pub fn build(cidrs: &[IpCidr]) -> IpSet {
        IpSet {
            v4: merge(cidrs.iter().filter_map(IpCidr::range_v4).collect()),
            v6: merge(cidrs.iter().filter_map(IpCidr::range_v6).collect()),
        }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => find(&self.v4, u32::from(v4)),
                None => find(&self.v6, u128::from(a)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_set() {
        let s = StrSet::build(vec![
            "b.com".into(),
            "a.com".into(),
            "c.com".into(),
            "a.com".into(),
        ]);
        assert_eq!(s.len(), 3);
        assert!(
            s.contains("a.com") && s.contains("c.com") && !s.contains("d.com") && !s.contains("")
        );
        assert!(!StrSet::build(vec![]).contains("a"));
    }

    #[test]
    fn domain_set() {
        let mut b = DomainSetBuilder::default();
        for p in ["exact.com", "+.suffix.com", ".sub.com", "*.one.com"] {
            b.add(DomainPattern::parse(p).unwrap());
        }
        let d = b.build();
        assert!(d.contains("exact.com") && !d.contains("a.exact.com"));
        assert!(
            d.contains("suffix.com") && d.contains("a.b.suffix.com") && !d.contains("xsuffix.com")
        );
        assert!(!d.contains("sub.com") && d.contains("a.sub.com"));
        assert!(d.contains("x.one.com") && !d.contains("x.y.one.com"));
        assert_eq!(d.len(), 4);
    }

    #[test]
    fn ip_set() {
        let cidrs: Vec<IpCidr> = [
            "10.0.0.0/8",
            "10.1.0.0/16",
            "11.0.0.0/8",
            "192.168.1.1",
            "2001:db8::/32",
            "0.0.0.0/32",
        ]
        .iter()
        .map(|c| IpCidr::parse(c).unwrap())
        .collect();
        let s = IpSet::build(&cidrs);
        assert_eq!(s.v4.len(), 3, "10/8 与 11/8 相邻合并");
        for ip in [
            "10.2.3.4",
            "11.255.255.255",
            "192.168.1.1",
            "::ffff:10.0.0.1",
            "2001:db8::5",
            "0.0.0.0",
        ] {
            assert!(s.contains(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["12.0.0.0", "192.168.1.2", "2001:db9::1", "9.255.255.255"] {
            assert!(!s.contains(ip.parse().unwrap()), "{ip}");
        }
        let all = IpSet::build(&[
            IpCidr::parse("0.0.0.0/0").unwrap(),
            IpCidr::parse("::/0").unwrap(),
        ]);
        assert!(
            all.contains("255.255.255.255".parse().unwrap())
                && all.contains("ffff::1".parse().unwrap())
        );
    }
}
