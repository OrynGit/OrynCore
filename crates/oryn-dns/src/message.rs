//! 完整的 DNS 报文模型（RFC 1035 / 6891 / 7871）。
//!
//! 只有需要改写报文时才使用（主机映射应答、IP 屏蔽、禁用 A / AAAA、ECS）；
//! 其余情况直接透传上游的原始报文。解析时展开压缩指针，序列化时重新压缩。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use oryn_config::IpCidr;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_DNAME: u16 = 39;
pub const TYPE_OPT: u16 = 41;
pub const OPTION_ECS: u16 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// CNAME / NS / PTR / DNAME。
    Name(String),
    Mx(u16, String),
    Soa {
        mname: String,
        rname: String,
        fixed: [u8; 20],
    },
    Srv {
        fixed: [u8; 6],
        target: String,
    },
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

fn u16_at(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]))
}

fn read_name(b: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    let mut total = 0;
    loop {
        let len = *b.get(pos)? as usize;
        if len & 0xC0 == 0xC0 {
            end.get_or_insert(pos + 2);
            jumps += 1;
            let ptr = (u16_at(b, pos)? & 0x3FFF) as usize;
            if jumps > 64 || ptr >= b.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        let label = b.get(pos + 1..pos + 1 + len)?;
        total += len + 1;
        if total > 255 {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

impl Message {
    pub fn parse(b: &[u8]) -> Option<Message> {
        if b.len() < 12 {
            return None;
        }
        let counts = [u16_at(b, 4)?, u16_at(b, 6)?, u16_at(b, 8)?, u16_at(b, 10)?];
        let mut pos = 12;
        let mut questions = Vec::new();
        for _ in 0..counts[0] {
            let (name, p) = read_name(b, pos)?;
            questions.push(Question {
                name,
                qtype: u16_at(b, p)?,
                qclass: u16_at(b, p + 2)?,
            });
            pos = p + 4;
        }
        let mut sections: [Vec<Record>; 3] = Default::default();
        for (i, section) in sections.iter_mut().enumerate() {
            for _ in 0..counts[i + 1] {
                let (r, p) = read_record(b, pos)?;
                section.push(r);
                pos = p;
            }
        }
        let [answers, authority, additional] = sections;
        Some(Message {
            id: u16_at(b, 0)?,
            flags: u16_at(b, 2)?,
            questions,
            answers,
            authority,
            additional,
        })
    }

    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer {
            out: Vec::with_capacity(512),
            names: HashMap::new(),
        };
        w.out.extend_from_slice(&self.id.to_be_bytes());
        w.out.extend_from_slice(&self.flags.to_be_bytes());
        for n in [
            self.questions.len(),
            self.answers.len(),
            self.authority.len(),
            self.additional.len(),
        ] {
            w.out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        for q in &self.questions {
            w.name(&q.name, true);
            w.out.extend_from_slice(&q.qtype.to_be_bytes());
            w.out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for r in self
            .answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            w.record(r);
        }
        w.out
    }

    /// 所有 A / AAAA 应答中的地址。
    pub fn answer_ips(&self) -> Vec<IpAddr> {
        self.answers
            .iter()
            .filter_map(|r| match r.data {
                RData::A(a) => Some(IpAddr::V4(a)),
                RData::Aaaa(a) => Some(IpAddr::V6(a)),
                _ => None,
            })
            .collect()
    }

    /// 移除满足条件的 A / AAAA 应答，返回是否有改动。
    pub fn retain_answers(&mut self, mut keep: impl FnMut(&Record) -> bool) -> bool {
        let before = self.answers.len();
        self.answers
            .retain(|r| !matches!(r.data, RData::A(_) | RData::Aaaa(_)) || keep(r));
        self.answers.len() != before
    }

    /// 查询中的 ECS 选项（地址与源前缀长度）。
    pub fn ecs(&self) -> Option<IpCidr> {
        let opt = self.additional.iter().find(|r| r.rtype == TYPE_OPT)?;
        let RData::Raw(data) = &opt.data else {
            return None;
        };
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let code = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let v = data.get(pos + 4..pos + 4 + len)?;
            if code == OPTION_ECS && v.len() >= 4 {
                let family = u16::from_be_bytes([v[0], v[1]]);
                let prefix = v[2];
                let addr = &v[4..];
                let ip = match family {
                    1 => {
                        let mut b = [0u8; 4];
                        b[..addr.len().min(4)].copy_from_slice(&addr[..addr.len().min(4)]);
                        IpAddr::V4(Ipv4Addr::from(b))
                    }
                    2 => {
                        let mut b = [0u8; 16];
                        b[..addr.len().min(16)].copy_from_slice(&addr[..addr.len().min(16)]);
                        IpAddr::V6(Ipv6Addr::from(b))
                    }
                    _ => return None,
                };
                return IpCidr::parse(&format!("{ip}/{prefix}"));
            }
            pos += 4 + len;
        }
        None
    }

    /// 设置 ECS 选项：没有 OPT 记录时添加一条；已有 ECS 时按 `replace` 决定是否覆盖。
    pub fn set_ecs(&mut self, subnet: IpCidr, replace: bool) {
        let option = ecs_option(subnet);
        match self.additional.iter_mut().find(|r| r.rtype == TYPE_OPT) {
            Some(opt) => {
                let RData::Raw(data) = &mut opt.data else {
                    return;
                };
                let mut out = Vec::new();
                let mut pos = 0;
                let mut had = false;
                while pos + 4 <= data.len() {
                    let code = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                    let end = (pos + 4 + len).min(data.len());
                    if code == OPTION_ECS {
                        had = true;
                        if !replace {
                            out.extend_from_slice(&data[pos..end]);
                        }
                    } else {
                        out.extend_from_slice(&data[pos..end]);
                    }
                    pos = end;
                }
                if !had || replace {
                    out.extend_from_slice(&option);
                }
                *data = out;
            }
            None => self.additional.push(Record {
                name: String::new(),
                rtype: TYPE_OPT,
                class: 1232,
                ttl: 0,
                data: RData::Raw(option),
            }),
        }
    }
}

fn ecs_option(subnet: IpCidr) -> Vec<u8> {
    let prefix = subnet.prefix();
    let (family, addr): (u16, Vec<u8>) = match subnet.addr() {
        IpAddr::V4(a) => (1, a.octets().to_vec()),
        IpAddr::V6(a) => (2, a.octets().to_vec()),
    };
    // 地址只保留前缀覆盖的字节，且末尾多余的位清零（RFC 7871 §6）
    let bytes = (prefix as usize).div_ceil(8);
    let mut addr = addr[..bytes].to_vec();
    if !prefix.is_multiple_of(8) {
        if let Some(last) = addr.last_mut() {
            *last &= 0xFFu8 << (8 - prefix % 8);
        }
    }
    let mut v = Vec::with_capacity(8 + addr.len());
    v.extend_from_slice(&OPTION_ECS.to_be_bytes());
    v.extend_from_slice(&((4 + addr.len()) as u16).to_be_bytes());
    v.extend_from_slice(&family.to_be_bytes());
    v.push(prefix);
    v.push(0);
    v.extend_from_slice(&addr);
    v
}

fn read_record(b: &[u8], pos: usize) -> Option<(Record, usize)> {
    let (name, p) = read_name(b, pos)?;
    let rtype = u16_at(b, p)?;
    let class = u16_at(b, p + 2)?;
    let ttl = u32::from_be_bytes(b.get(p + 4..p + 8)?.try_into().ok()?);
    let len = u16_at(b, p + 8)? as usize;
    let start = p + 10;
    let raw = b.get(start..start + len)?;
    let data = match rtype {
        TYPE_A if len == 4 => RData::A(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
        TYPE_AAAA if len == 16 => RData::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(raw).ok()?)),
        TYPE_CNAME | TYPE_NS | TYPE_PTR | TYPE_DNAME => RData::Name(read_name(b, start)?.0),
        TYPE_MX if len >= 3 => RData::Mx(u16_at(b, start)?, read_name(b, start + 2)?.0),
        TYPE_SOA => {
            let (mname, p1) = read_name(b, start)?;
            let (rname, p2) = read_name(b, p1)?;
            RData::Soa {
                mname,
                rname,
                fixed: b.get(p2..p2 + 20)?.try_into().ok()?,
            }
        }
        TYPE_SRV if len >= 7 => RData::Srv {
            fixed: raw[..6].try_into().ok()?,
            target: read_name(b, start + 6)?.0,
        },
        _ => RData::Raw(raw.to_vec()),
    };
    Some((
        Record {
            name,
            rtype,
            class,
            ttl,
            data,
        },
        start + len,
    ))
}

struct Writer {
    out: Vec<u8>,
    /// 已写入的域名后缀 → 偏移，用于压缩。
    names: HashMap<String, u16>,
}

impl Writer {
    fn name(&mut self, name: &str, compress: bool) {
        let name = name.trim_end_matches('.');
        if name.is_empty() {
            self.out.push(0);
            return;
        }
        let labels: Vec<&str> = name.split('.').collect();
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".").to_ascii_lowercase();
            if compress {
                if let Some(&off) = self.names.get(&suffix) {
                    self.out.extend_from_slice(&(0xC000 | off).to_be_bytes());
                    return;
                }
                if self.out.len() < 0x3FFF {
                    self.names.insert(suffix, self.out.len() as u16);
                }
            }
            let l = labels[i].as_bytes();
            self.out.push(l.len().min(63) as u8);
            self.out.extend_from_slice(&l[..l.len().min(63)]);
        }
        self.out.push(0);
    }

    fn record(&mut self, r: &Record) {
        self.name(&r.name, true);
        self.out.extend_from_slice(&r.rtype.to_be_bytes());
        self.out.extend_from_slice(&r.class.to_be_bytes());
        self.out.extend_from_slice(&r.ttl.to_be_bytes());
        let len_pos = self.out.len();
        self.out.extend_from_slice(&[0, 0]);
        match &r.data {
            RData::A(a) => self.out.extend_from_slice(&a.octets()),
            RData::Aaaa(a) => self.out.extend_from_slice(&a.octets()),
            RData::Name(n) => self.name(n, true),
            RData::Mx(pref, n) => {
                self.out.extend_from_slice(&pref.to_be_bytes());
                self.name(n, true);
            }
            RData::Soa {
                mname,
                rname,
                fixed,
            } => {
                self.name(mname, true);
                self.name(rname, true);
                self.out.extend_from_slice(fixed);
            }
            RData::Srv { fixed, target } => {
                self.out.extend_from_slice(fixed);
                self.name(target, false);
            }
            RData::Raw(d) => self.out.extend_from_slice(d),
        }
        let len = (self.out.len() - len_pos - 2) as u16;
        self.out[len_pos..len_pos + 2].copy_from_slice(&len.to_be_bytes());
    }
}

/// 以查询为模板构造应答：`QR=1`、`RA=1`，保留 ID、RD 与问题段。
pub fn response_for(query: &Message, rcode: u8, answers: Vec<Record>) -> Message {
    Message {
        id: query.id,
        flags: 0x8000 | (query.flags & 0x0100) | 0x0080 | (rcode as u16 & 0x0F),
        questions: query.questions.clone(),
        answers,
        authority: Vec::new(),
        additional: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire;

    fn sample() -> Vec<u8> {
        // www.example.com CNAME cdn.example.net；cdn.example.net A 1.2.3.4 / A 10.0.0.1；AAAA；MX；SOA
        let q = Message {
            id: 0x1234,
            flags: 0x0100,
            questions: vec![Question {
                name: "www.example.com".into(),
                qtype: TYPE_A,
                qclass: 1,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
        let rec = |name: &str, rtype, data| Record {
            name: name.into(),
            rtype,
            class: 1,
            ttl: 300,
            data,
        };
        let mut m = response_for(
            &q,
            0,
            vec![
                rec(
                    "www.example.com",
                    TYPE_CNAME,
                    RData::Name("cdn.example.net".into()),
                ),
                rec(
                    "cdn.example.net",
                    TYPE_A,
                    RData::A(Ipv4Addr::new(1, 2, 3, 4)),
                ),
                rec(
                    "cdn.example.net",
                    TYPE_A,
                    RData::A(Ipv4Addr::new(10, 0, 0, 1)),
                ),
                rec(
                    "cdn.example.net",
                    TYPE_AAAA,
                    RData::Aaaa("2001:db8::1".parse().unwrap()),
                ),
                rec(
                    "example.com",
                    TYPE_MX,
                    RData::Mx(10, "mail.example.com".into()),
                ),
            ],
        );
        m.authority.push(rec(
            "example.com",
            TYPE_SOA,
            RData::Soa {
                mname: "ns1.example.com".into(),
                rname: "hostmaster.example.com".into(),
                fixed: [7; 20],
            },
        ));
        m.serialize()
    }

    #[test]
    fn roundtrip_with_compression() {
        let bytes = sample();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.id, 0x1234);
        assert_eq!(m.answers.len(), 5);
        assert_eq!(m.answer_ips().len(), 3);
        assert_eq!(
            Message::parse(&m.serialize()).unwrap(),
            m,
            "序列化再解析保持一致"
        );
        // 压缩生效：比不压缩短
        assert!(bytes.len() < 200, "{}", bytes.len());
        // 与最小解析器一致
        let a = wire::parse_answer(&bytes).unwrap();
        assert_eq!(a.ips.len(), 3);
    }

    #[test]
    fn filtering_answers() {
        let mut m = Message::parse(&sample()).unwrap();
        let blocked = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(
            m.retain_answers(|r| !matches!(r.data, RData::A(a) if blocked.contains(IpAddr::V4(a))))
        );
        assert_eq!(m.answer_ips().len(), 2);
        assert!(
            m.answers.iter().any(|r| r.rtype == TYPE_CNAME),
            "非地址记录保留"
        );
        assert!(!m.retain_answers(|_| true));
    }

    #[test]
    fn ecs_option() {
        let mut q = Message::parse(&wire::build_query(1, "a.example", TYPE_A)).unwrap();
        assert_eq!(q.ecs(), None);
        q.set_ecs(IpCidr::parse("1.2.3.4/24").unwrap(), false);
        let q2 = Message::parse(&q.serialize()).unwrap();
        assert_eq!(q2.ecs(), IpCidr::parse("1.2.3.0/24"));
        // 已有 ECS 且不覆盖
        let mut q3 = q2.clone();
        q3.set_ecs(IpCidr::parse("5.6.7.0/24").unwrap(), false);
        assert_eq!(q3.ecs(), IpCidr::parse("1.2.3.0/24"));
        q3.set_ecs(IpCidr::parse("2001:db8:abcd::/56").unwrap(), true);
        assert_eq!(
            Message::parse(&q3.serialize()).unwrap().ecs(),
            IpCidr::parse("2001:db8:abcd::/56")
        );
        assert_eq!(
            super::ecs_option(IpCidr::parse("1.2.3.255/20").unwrap())[8..],
            [1, 2, 0]
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(Message::parse(&[0; 11]).is_none());
        let mut bad = sample();
        bad.truncate(bad.len() - 3);
        assert!(Message::parse(&bad).is_none());
    }
}
