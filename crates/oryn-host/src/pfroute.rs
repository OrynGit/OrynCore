//! macOS `PF_ROUTE` 路由消息的编码与解析（纯数据，不做系统调用，可在任何平台上测试）。
//!
//! 布局见 XNU `net/route.h`：`rt_msghdr` 之后按 `RTA_*` 位的顺序排列 sockaddr，
//! 每个按 4 字节对齐（`ROUNDUP`）；长度为 0 的 sockaddr 占 4 字节。字段为主机字节序。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use oryn_config::IpCidr;

pub const RTM_VERSION: u8 = 5;
pub const RTM_ADD: u8 = 0x1;
pub const RTM_DELETE: u8 = 0x2;
pub const RTM_CHANGE: u8 = 0x3;
pub const RTM_GET: u8 = 0x4;
pub const RTM_IFINFO: u8 = 0xe;

pub const RTF_UP: i32 = 0x1;
pub const RTF_GATEWAY: i32 = 0x2;
pub const RTF_HOST: i32 = 0x4;
pub const RTF_STATIC: i32 = 0x800;

pub const RTA_DST: i32 = 0x1;
pub const RTA_GATEWAY: i32 = 0x2;
pub const RTA_NETMASK: i32 = 0x4;
pub const RTA_IFP: i32 = 0x10;
/// RTA_DST .. RTA_BRD 共 8 种地址。
const RTAX_MAX: u32 = 8;

pub const AF_INET: u8 = 2;
pub const AF_LINK: u8 = 18;
pub const AF_INET6: u8 = 30;

/// `sizeof(struct rt_msghdr)`（macOS）。
pub const RT_MSGHDR_LEN: usize = 92;
const SOCKADDR_IN_LEN: usize = 16;
const SOCKADDR_IN6_LEN: usize = 28;
const SOCKADDR_DL_LEN: usize = 20;

fn roundup(n: usize) -> usize {
    if n == 0 {
        4
    } else {
        1 + ((n - 1) | 3)
    }
}

/// 路由的下一跳。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gateway {
    /// 经网关地址（`RTF_GATEWAY`）。
    Ip(IpAddr),
    /// 直接经接口（`route add -interface`），值为接口序号。
    Link(u32),
}

fn sockaddr_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(a) => {
            let mut sa = [0u8; SOCKADDR_IN_LEN];
            sa[0] = SOCKADDR_IN_LEN as u8;
            sa[1] = AF_INET;
            sa[4..8].copy_from_slice(&a.octets());
            out.extend_from_slice(&sa);
        }
        IpAddr::V6(a) => {
            let mut sa = [0u8; SOCKADDR_IN6_LEN];
            sa[0] = SOCKADDR_IN6_LEN as u8;
            sa[1] = AF_INET6;
            sa[8..24].copy_from_slice(&a.octets());
            out.extend_from_slice(&sa);
        }
    }
}

fn sockaddr_dl(out: &mut Vec<u8>, index: u32) {
    let mut sa = [0u8; SOCKADDR_DL_LEN];
    sa[0] = SOCKADDR_DL_LEN as u8;
    sa[1] = AF_LINK;
    sa[2..4].copy_from_slice(&(index as u16).to_ne_bytes());
    out.extend_from_slice(&sa);
}

fn mask_of(cidr: &IpCidr) -> IpAddr {
    let p = cidr.prefix() as u32;
    if cidr.is_ipv4() {
        let m = if p == 0 { 0 } else { u32::MAX << (32 - p) };
        IpAddr::V4(Ipv4Addr::from(m))
    } else {
        let m = if p == 0 { 0 } else { u128::MAX << (128 - p) };
        IpAddr::V6(Ipv6Addr::from(m))
    }
}

/// 编码一条 `RTM_ADD` / `RTM_DELETE` / `RTM_GET`。`want_ifp` 时请求内核在回复中带出接口（`RTA_IFP`）。
pub fn encode(rtm_type: u8, seq: i32, dst: &IpCidr, gateway: Option<Gateway>, want_ifp: bool) -> Vec<u8> {
    let dst = dst.network();
    let host = dst.prefix() == if dst.is_ipv4() { 32 } else { 128 };
    let mut flags = RTF_UP | RTF_STATIC;
    let mut addrs = RTA_DST;
    let mut body = Vec::new();
    sockaddr_ip(&mut body, dst.addr());
    match gateway {
        Some(Gateway::Ip(ip)) => {
            flags |= RTF_GATEWAY;
            addrs |= RTA_GATEWAY;
            sockaddr_ip(&mut body, ip);
        }
        Some(Gateway::Link(index)) => {
            addrs |= RTA_GATEWAY;
            sockaddr_dl(&mut body, index);
        }
        None => {}
    }
    if host {
        flags |= RTF_HOST;
    } else {
        addrs |= RTA_NETMASK;
        sockaddr_ip(&mut body, mask_of(&dst));
    }
    if want_ifp {
        addrs |= RTA_IFP;
        sockaddr_dl(&mut body, 0);
    }
    let len = RT_MSGHDR_LEN + body.len();
    let mut msg = vec![0u8; RT_MSGHDR_LEN];
    msg[0..2].copy_from_slice(&(len as u16).to_ne_bytes());
    msg[2] = RTM_VERSION;
    msg[3] = rtm_type;
    msg[8..12].copy_from_slice(&flags.to_ne_bytes());
    msg[12..16].copy_from_slice(&addrs.to_ne_bytes());
    msg[20..24].copy_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&body);
    msg
}

/// 解析后的路由消息（只取用到的字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteMsg {
    pub rtm_type: u8,
    pub index: u16,
    pub flags: i32,
    pub pid: i32,
    pub seq: i32,
    pub errno: i32,
    pub gateway: Option<Gateway>,
    /// `RTA_IFP` 给出的接口序号。
    pub ifp: Option<u32>,
}

fn read_sockaddr(sa: &[u8]) -> Option<Gateway> {
    match sa.get(1).copied()? {
        AF_INET if sa.len() >= 8 => Some(Gateway::Ip(IpAddr::V4(Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7])))),
        AF_INET6 if sa.len() >= 24 => {
            let octets: [u8; 16] = sa[8..24].try_into().ok()?;
            Some(Gateway::Ip(IpAddr::V6(Ipv6Addr::from(octets))))
        }
        AF_LINK if sa.len() >= 4 => Some(Gateway::Link(u16::from_ne_bytes([sa[2], sa[3]]) as u32)),
        _ => None,
    }
}

/// 解析一条路由消息；非路由类型（如 `RTM_IFINFO`）只填头部字段。
pub fn parse(msg: &[u8]) -> Option<RouteMsg> {
    if msg.len() < RT_MSGHDR_LEN || msg[2] != RTM_VERSION {
        return None;
    }
    let len = (u16::from_ne_bytes([msg[0], msg[1]]) as usize).min(msg.len());
    let i32_at = |o: usize| i32::from_ne_bytes(msg[o..o + 4].try_into().unwrap());
    let mut out = RouteMsg {
        rtm_type: msg[3],
        index: u16::from_ne_bytes([msg[4], msg[5]]),
        flags: i32_at(8),
        pid: i32_at(16),
        seq: i32_at(20),
        errno: i32_at(24),
        gateway: None,
        ifp: None,
    };
    if !matches!(out.rtm_type, RTM_ADD | RTM_DELETE | RTM_CHANGE | RTM_GET) {
        return Some(out);
    }
    let addrs = i32_at(12);
    let mut rest = &msg[RT_MSGHDR_LEN..len];
    for bit in 0..RTAX_MAX {
        if addrs & (1 << bit) == 0 {
            continue;
        }
        let sa_len = *rest.first()? as usize;
        let step = roundup(sa_len);
        let sa = rest.get(..sa_len.max(1))?;
        match 1 << bit {
            RTA_GATEWAY => out.gateway = read_sockaddr(sa),
            RTA_IFP => {
                out.ifp = match read_sockaddr(sa) {
                    Some(Gateway::Link(i)) if i != 0 => Some(i),
                    _ => None,
                }
            }
            _ => {}
        }
        rest = rest.get(step.min(rest.len())..)?;
    }
    Some(out)
}

/// `/etc/resolv.conf` 中可路由的 DNS 服务器：跳过回环、链路本地与带作用域（`%en0`）的地址。
pub fn resolv_conf_servers(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(ip) = words.next().filter(|w| !w.contains('%')).and_then(|w| w.parse::<IpAddr>().ok()) else {
            continue;
        };
        let skip = match ip {
            IpAddr::V4(a) => a.is_loopback() || a.is_link_local() || a.is_unspecified(),
            IpAddr::V6(a) => a.is_loopback() || a.is_unspecified() || (a.segments()[0] & 0xffc0) == 0xfe80,
        };
        if !skip && !out.contains(&ip) && out.len() < 16 {
            out.push(ip);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_vendor = "apple")]
    #[test]
    fn header_length_matches_libc() {
        assert_eq!(std::mem::size_of::<libc::rt_msghdr>(), RT_MSGHDR_LEN);
        assert_eq!(std::mem::size_of::<libc::sockaddr_dl>(), SOCKADDR_DL_LEN);
        assert_eq!(std::mem::size_of::<libc::sockaddr_in6>(), SOCKADDR_IN6_LEN);
    }

    #[test]
    fn encodes_interface_route_with_netmask() {
        let msg = encode(RTM_ADD, 3, &IpCidr::parse("128.0.0.0/1").unwrap(), Some(Gateway::Link(17)), false);
        assert_eq!(msg.len(), RT_MSGHDR_LEN + 16 + 20 + 16);
        assert_eq!(u16::from_ne_bytes([msg[0], msg[1]]) as usize, msg.len());
        let flags = i32::from_ne_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(flags, RTF_UP | RTF_STATIC);
        let addrs = i32::from_ne_bytes(msg[12..16].try_into().unwrap());
        assert_eq!(addrs, RTA_DST | RTA_GATEWAY | RTA_NETMASK);
        let parsed = parse(&msg).unwrap();
        assert_eq!((parsed.rtm_type, parsed.seq, parsed.gateway), (RTM_ADD, 3, Some(Gateway::Link(17))));
        // 掩码 128.0.0.0
        assert_eq!(&msg[RT_MSGHDR_LEN + 36 + 4..RT_MSGHDR_LEN + 36 + 8], &[128, 0, 0, 0]);
    }

    #[test]
    fn host_route_has_no_netmask_and_gateway_flag() {
        let msg = encode(RTM_ADD, 1, &IpCidr::parse("2001:db8::53").unwrap(), Some(Gateway::Ip("fe80::1".parse().unwrap())), false);
        let flags = i32::from_ne_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(flags, RTF_UP | RTF_STATIC | RTF_GATEWAY | RTF_HOST);
        assert_eq!(msg.len(), RT_MSGHDR_LEN + 28 + 28);
        assert_eq!(parse(&msg).unwrap().gateway, Some(Gateway::Ip("fe80::1".parse().unwrap())));
    }

    #[test]
    fn parses_get_reply_with_ifp_and_zero_length_netmask() {
        // 模拟内核回复：DST、GATEWAY、NETMASK（长度 0）、IFP
        let mut msg = vec![0u8; RT_MSGHDR_LEN];
        msg[2] = RTM_VERSION;
        msg[3] = RTM_GET;
        msg[12..16].copy_from_slice(&(RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFP).to_ne_bytes());
        sockaddr_ip(&mut msg, "0.0.0.0".parse().unwrap());
        sockaddr_ip(&mut msg, "192.168.1.1".parse().unwrap());
        msg.extend_from_slice(&[0, 0, 0, 0]);
        sockaddr_dl(&mut msg, 6);
        let len = msg.len() as u16;
        msg[0..2].copy_from_slice(&len.to_ne_bytes());
        let parsed = parse(&msg).unwrap();
        assert_eq!(parsed.gateway, Some(Gateway::Ip("192.168.1.1".parse().unwrap())));
        assert_eq!(parsed.ifp, Some(6));
        assert!(parse(&msg[..50]).is_none());
    }

    #[test]
    fn resolv_conf_keeps_routable_servers() {
        let text = "# generated\nnameserver 192.168.1.1\nnameserver 127.0.0.1\nnameserver fe80::1%en0\n\
                    nameserver 2001:db8::1\nnameserver 192.168.1.1\nsearch lan\nnameserver bogus\n";
        let v: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        assert_eq!(resolv_conf_servers(text), v);
    }
}
