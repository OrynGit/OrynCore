//! 隧道内 DNS 的最小报文编解码：只发单问题的 A / AAAA 查询，只读 A / AAAA 应答。
//!
//! 不复用 `oryn-dns::wire`：`oryn-dns` 依赖 `oryn-outbound`，而本 crate 被 `oryn-outbound`
//! 依赖，复用会形成依赖环。

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const HEADER: usize = 12;

/// 不引入随机数依赖：标准库每次新建 `RandomState` 都带随机密钥。
pub fn random_u64() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(0);
    hasher.finish()
}

pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + name.len() + 6);
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

pub fn id_of(buf: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.first()?, *buf.get(1)?]))
}

/// 跳过一个（可能压缩的）域名，返回其后的位置。
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *buf.get(pos)?;
        if len & 0xC0 == 0xC0 {
            buf.get(pos + 1)?;
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + usize::from(len);
    }
    None
}

/// 响应中的 A / AAAA 地址；不是响应或解析失败返回 None。
pub fn parse_ips(buf: &[u8]) -> Option<Vec<IpAddr>> {
    if buf.len() < HEADER || buf[2] & 0x80 == 0 {
        return None;
    }
    let qd = usize::from(u16::from_be_bytes([buf[4], buf[5]]));
    let an = usize::from(u16::from_be_bytes([buf[6], buf[7]]));
    let mut pos = HEADER;
    for _ in 0..qd {
        pos = skip_name(buf, pos)? + 4;
    }
    let mut ips = Vec::new();
    for _ in 0..an {
        let p = skip_name(buf, pos)?;
        let rtype = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]);
        let len = usize::from(u16::from_be_bytes([*buf.get(p + 8)?, *buf.get(p + 9)?]));
        let data = buf.get(p + 10..p + 10 + len)?;
        match (rtype, len) {
            (TYPE_A, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            (TYPE_AAAA, 16) => {
                let octets: [u8; 16] = data.try_into().ok()?;
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos = p + 10 + len;
    }
    Some(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_compression() {
        let mut resp = build_query(7, "a.example", TYPE_A);
        resp[2] |= 0x80;
        resp[7] = 2;
        // 第一条用压缩指针指向问题段的名字，第二条是 CNAME 之外的 AAAA
        resp.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 1]);
        resp.extend_from_slice(&[0xC0, 12, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16]);
        resp.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(id_of(&resp), Some(7));
        assert_eq!(
            parse_ips(&resp).unwrap(),
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                "fd00::1".parse::<IpAddr>().unwrap()
            ]
        );
        // 查询本身不是响应
        assert!(parse_ips(&build_query(1, "x", TYPE_A)).is_none());
        // 截断的报文
        assert!(parse_ips(&resp[..resp.len() - 3]).is_none());
    }
}
