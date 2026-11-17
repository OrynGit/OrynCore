//! 最小化的 DNS 报文编解码（RFC 1035），只处理 Oryn 需要的部分。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

const HEADER_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    /// 小写、无末尾点。
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// 问题段结束的位置（用于构造错误响应）。
    pub end: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answer {
    pub rcode: u8,
    pub ips: Vec<IpAddr>,
    /// 所有应答记录中的最小 TTL；没有应答记录时为 None。
    pub min_ttl: Option<u32>,
    /// 否定应答（RFC 2308）：权威段 SOA 的 TTL 与 MINIMUM 中较小者。
    pub negative_ttl: Option<u32>,
}

fn u16_at(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]))
}

fn u32_at(buf: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_be_bytes(buf.get(pos..pos + 4)?.try_into().ok()?))
}

/// 读取域名，支持压缩指针。返回（域名，名字之后的位置）。
fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos)? as usize;
        if len & 0xC0 == 0xC0 {
            let ptr = (u16_at(buf, pos)? & 0x3FFF) as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 64 || ptr >= buf.len() {
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
        let label = buf.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        if name.len() > 255 {
            return None;
        }
        pos += 1 + len;
    }
    Some((name, end.unwrap_or(pos)))
}

/// 解析查询中的第一个问题。
pub fn parse_question(buf: &[u8]) -> Option<Question> {
    if buf.len() < HEADER_LEN || u16_at(buf, 4)? == 0 {
        return None;
    }
    let id = u16_at(buf, 0)?;
    let (name, pos) = read_name(buf, HEADER_LEN)?;
    let qtype = u16_at(buf, pos)?;
    let qclass = u16_at(buf, pos + 2)?;
    Some(Question {
        id,
        name,
        qtype,
        qclass,
        end: pos + 4,
    })
}

/// 解析响应中的 A / AAAA 记录与最小 TTL。
const TYPE_SOA: u16 = 6;

pub fn parse_answer(buf: &[u8]) -> Option<Answer> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let rcode = buf[3] & 0x0F;
    let qd = u16_at(buf, 4)? as usize;
    let an = u16_at(buf, 6)? as usize;
    let mut pos = HEADER_LEN;
    for _ in 0..qd {
        let (_, p) = read_name(buf, pos)?;
        pos = p + 4;
    }
    let mut out = Answer {
        rcode,
        ..Default::default()
    };
    for _ in 0..an {
        let (_, p) = read_name(buf, pos)?;
        let rtype = u16_at(buf, p)?;
        let ttl = u32_at(buf, p + 4)?;
        let rdlen = u16_at(buf, p + 8)? as usize;
        let rdata = buf.get(p + 10..p + 10 + rdlen)?;
        match (rtype, rdlen) {
            (TYPE_A, 4) => out.ips.push(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (TYPE_AAAA, 16) => {
                let b: [u8; 16] = rdata.try_into().ok()?;
                out.ips.push(IpAddr::V6(Ipv6Addr::from(b)));
            }
            _ => {}
        }
        out.min_ttl = Some(out.min_ttl.map_or(ttl, |m| m.min(ttl)));
        pos = p + 10 + rdlen;
    }
    if out.min_ttl.is_none() {
        let ns = u16_at(buf, 8).unwrap_or(0) as usize;
        for _ in 0..ns {
            let Some((_, p)) = read_name(buf, pos) else { break };
            let (Some(rtype), Some(ttl), Some(rdlen)) =
                (u16_at(buf, p), u32_at(buf, p + 4), u16_at(buf, p + 8))
            else {
                break;
            };
            let rdlen = rdlen as usize;
            if rtype == TYPE_SOA {
                // MNAME、RNAME 之后依次是 SERIAL、REFRESH、RETRY、EXPIRE、MINIMUM。
                let minimum = read_name(buf, p + 10)
                    .and_then(|(_, m)| read_name(buf, m))
                    .and_then(|(_, r)| u32_at(buf, r + 16));
                if let Some(minimum) = minimum {
                    out.negative_ttl = Some(ttl.min(minimum));
                }
                break;
            }
            pos = p + 10 + rdlen;
        }
    }
    Some(out)
}

/// 构造一个只含单个问题的查询（RD=1）。
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let label = &label.as_bytes()[..label.len().min(63)];
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

/// 按查询构造错误响应：保留头部与问题段，去掉其余部分。
pub fn build_error(query: &[u8], question_end: Option<usize>, rcode: u8) -> Vec<u8> {
    let end = question_end.unwrap_or(HEADER_LEN).min(query.len());
    let mut out = query[..end.max(HEADER_LEN.min(query.len()))].to_vec();
    if out.len() < HEADER_LEN {
        out.resize(HEADER_LEN, 0);
    }
    out[2] = 0x80 | (out[2] & 0x01); // QR=1，保留 RD
    out[3] = 0x80 | (rcode & 0x0F); // RA=1
    let qd: u16 = if question_end.is_some() { 1 } else { 0 };
    out[4..6].copy_from_slice(&qd.to_be_bytes());
    out[6..12].fill(0);
    out
}

pub fn set_id(buf: &mut [u8], id: u16) {
    if buf.len() >= 2 {
        buf[..2].copy_from_slice(&id.to_be_bytes());
    }
}

pub fn id_of(buf: &[u8]) -> Option<u16> {
    u16_at(buf, 0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// 构造一个带 CNAME + A 的响应，第二条记录使用压缩指针。
    pub fn sample_response(id: u16, name: &str, ips: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
        let mut out = build_query(id, name, TYPE_A);
        out[2] = 0x81;
        out[3] = 0x80;
        out[6..8].copy_from_slice(&(ips.len() as u16).to_be_bytes());
        for ip in ips {
            out.extend_from_slice(&[0xC0, 12]);
            out.extend_from_slice(&TYPE_A.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&ip.octets());
        }
        out
    }

    #[test]
    fn question_roundtrip() {
        let q = build_query(0x1234, "WWW.Example.COM.", TYPE_AAAA);
        let p = parse_question(&q).unwrap();
        assert_eq!(p.id, 0x1234);
        assert_eq!(p.name, "www.example.com");
        assert_eq!(p.qtype, TYPE_AAAA);
        assert_eq!(p.end, q.len());
    }

    #[test]
    fn answer_with_compression() {
        let r = sample_response(
            7,
            "a.example",
            &[Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)],
            300,
        );
        let a = parse_answer(&r).unwrap();
        assert_eq!(a.rcode, 0);
        assert_eq!(a.ips.len(), 2);
        assert_eq!(a.min_ttl, Some(300));
    }

    #[test]
    fn error_response() {
        let mut q = build_query(9, "x.test", TYPE_A);
        q.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]); // EDNS OPT
        q[10..12].copy_from_slice(&1u16.to_be_bytes());
        let p = parse_question(&q).unwrap();
        let e = build_error(&q, Some(p.end), RCODE_REFUSED);
        assert_eq!(e.len(), p.end);
        assert_eq!(e[3] & 0x0F, RCODE_REFUSED);
        assert_eq!(&e[10..12], &[0, 0]);
        assert_eq!(parse_question(&e).unwrap().name, "x.test");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_question(&[0; 5]).is_none());
        let mut loop_ptr = build_query(1, "a", TYPE_A);
        loop_ptr[12] = 0xC0;
        loop_ptr[13] = 12;
        assert!(parse_question(&loop_ptr).is_none());
    }
}
