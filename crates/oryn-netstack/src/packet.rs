//! IP 包的最小解析与 UDP 包构造。UDP 不经过 lwIP，直接在这里处理。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// 代理数据面只处理普通单播；广播、组播和未指定地址由平台入口丢弃。
pub fn is_non_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => value.is_broadcast() || value.is_multicast() || value.is_unspecified(),
        IpAddr::V6(value) => value.is_multicast() || value.is_unspecified(),
    }
}

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed<'a> {
    /// TCP 段。`syn` 表示连接请求（SYN 且非 ACK）。
    Tcp { dst_port: u16, syn: bool },
    /// 未分片的 UDP 数据报。
    Udp {
        src: SocketAddr,
        dst: SocketAddr,
        payload: &'a [u8],
    },
    /// 其它（ICMP、分片、扩展头等），交给 lwIP。
    Other,
    /// 格式错误，丢弃。
    Invalid,
}

pub fn parse(pkt: &[u8]) -> Parsed<'_> {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => parse_v4(pkt),
        Some(6) => parse_v6(pkt),
        _ => Parsed::Invalid,
    }
}

fn parse_v4(pkt: &[u8]) -> Parsed<'_> {
    if pkt.len() < 20 {
        return Parsed::Invalid;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if ihl < 20 || total < ihl || total > pkt.len() {
        return Parsed::Invalid;
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x3FFF != 0 {
        // MF 置位或偏移非零：分片，交给 lwIP 重组
        return Parsed::Other;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    transport(pkt[9], &pkt[ihl..total], IpAddr::V4(src), IpAddr::V4(dst))
}

fn parse_v6(pkt: &[u8]) -> Parsed<'_> {
    if pkt.len() < 40 {
        return Parsed::Invalid;
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if 40 + payload_len > pkt.len() {
        return Parsed::Invalid;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    transport(
        pkt[6],
        &pkt[40..40 + payload_len],
        IpAddr::V6(Ipv6Addr::from(src)),
        IpAddr::V6(Ipv6Addr::from(dst)),
    )
}

fn transport(proto: u8, seg: &[u8], src: IpAddr, dst: IpAddr) -> Parsed<'_> {
    match proto {
        PROTO_TCP => {
            if seg.len() < 20 {
                return Parsed::Invalid;
            }
            let dst_port = u16::from_be_bytes([seg[2], seg[3]]);
            let flags = seg[13];
            Parsed::Tcp {
                dst_port,
                syn: flags & TCP_SYN != 0 && flags & TCP_ACK == 0,
            }
        }
        PROTO_UDP => {
            if seg.len() < 8 {
                return Parsed::Invalid;
            }
            let sport = u16::from_be_bytes([seg[0], seg[1]]);
            let dport = u16::from_be_bytes([seg[2], seg[3]]);
            let len = u16::from_be_bytes([seg[4], seg[5]]) as usize;
            if len < 8 || len > seg.len() {
                return Parsed::Invalid;
            }
            Parsed::Udp {
                src: SocketAddr::new(src, sport),
                dst: SocketAddr::new(dst, dport),
                payload: &seg[8..len],
            }
        }
        _ => Parsed::Other,
    }
}

static IP_ID: AtomicU16 = AtomicU16::new(1);

fn to_v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// 构造一个 UDP 包（用于把出站收到的数据报写回隧道）。地址族不一致时返回 None。
pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = 8 + payload.len();
    match (src.ip(), dst.ip()) {
        (IpAddr::V6(s), IpAddr::V6(d))
            if s.to_ipv4_mapped().is_none() || d.to_ipv4_mapped().is_none() =>
        {
            if udp_len > u16::MAX as usize {
                return None;
            }
            let mut out = Vec::with_capacity(40 + udp_len);
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&(udp_len as u16).to_be_bytes());
            out.push(PROTO_UDP);
            out.push(64);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            push_udp(&mut out, src.port(), dst.port(), payload);
            let mut sum = sum_bytes(0, &s.octets());
            sum = sum_bytes(sum, &d.octets());
            sum += udp_len as u32 + PROTO_UDP as u32;
            finish_udp_checksum(&mut out[40..], sum);
            Some(out)
        }
        (s, d) => {
            let (s, d) = (to_v4(s)?, to_v4(d)?);
            let total = 20 + udp_len;
            if total > u16::MAX as usize {
                return None;
            }
            let mut out = Vec::with_capacity(total);
            out.push(0x45);
            out.push(0);
            out.extend_from_slice(&(total as u16).to_be_bytes());
            out.extend_from_slice(&IP_ID.fetch_add(1, Ordering::Relaxed).to_be_bytes());
            out.extend_from_slice(&[0, 0, 64, PROTO_UDP, 0, 0]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            let hsum = checksum(sum_bytes(0, &out[..20]));
            out[10..12].copy_from_slice(&hsum.to_be_bytes());
            push_udp(&mut out, src.port(), dst.port(), payload);
            let mut sum = sum_bytes(0, &s.octets());
            sum = sum_bytes(sum, &d.octets());
            sum += udp_len as u32 + PROTO_UDP as u32;
            finish_udp_checksum(&mut out[20..], sum);
            Some(out)
        }
    }
}

fn push_udp(out: &mut Vec<u8>, sport: u16, dport: u16, payload: &[u8]) {
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
}

fn finish_udp_checksum(udp: &mut [u8], pseudo: u32) {
    let mut c = checksum(sum_bytes(pseudo, udp));
    if c == 0 {
        c = 0xFFFF;
    }
    udp[6..8].copy_from_slice(&c.to_be_bytes());
}

fn sum_bytes(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    sum
}

fn checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 解析出的 TCP 段（测试与诊断用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: Vec<u8>,
}

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;

/// 解析 IPv4 / IPv6 中的 TCP 段（不支持 IPv6 扩展头）。
pub fn parse_tcp(pkt: &[u8]) -> Option<TcpSegment> {
    let (src_ip, dst_ip, seg): (IpAddr, IpAddr, &[u8]) = match pkt.first()? >> 4 {
        4 => {
            let ihl = ((pkt[0] & 0x0F) as usize) * 4;
            let total = u16::from_be_bytes([*pkt.get(2)?, *pkt.get(3)?]) as usize;
            if *pkt.get(9)? != PROTO_TCP || total > pkt.len() || ihl > total {
                return None;
            }
            let s = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let d = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            (IpAddr::V4(s), IpAddr::V4(d), &pkt[ihl..total])
        }
        6 => {
            if pkt.len() < 40 || pkt[6] != PROTO_TCP {
                return None;
            }
            let len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            let s: [u8; 16] = pkt[8..24].try_into().ok()?;
            let d: [u8; 16] = pkt[24..40].try_into().ok()?;
            (
                IpAddr::V6(Ipv6Addr::from(s)),
                IpAddr::V6(Ipv6Addr::from(d)),
                pkt.get(40..40 + len)?,
            )
        }
        _ => return None,
    };
    if seg.len() < 20 {
        return None;
    }
    let off = ((seg[12] >> 4) as usize) * 4;
    if off < 20 || off > seg.len() {
        return None;
    }
    Some(TcpSegment {
        src: SocketAddr::new(src_ip, u16::from_be_bytes([seg[0], seg[1]])),
        dst: SocketAddr::new(dst_ip, u16::from_be_bytes([seg[2], seg[3]])),
        seq: u32::from_be_bytes(seg[4..8].try_into().ok()?),
        ack: u32::from_be_bytes(seg[8..12].try_into().ok()?),
        flags: seg[13],
        window: u16::from_be_bytes([seg[14], seg[15]]),
        payload: seg[off..].to_vec(),
    })
}

/// 构造一个无选项的 TCP 段（测试与诊断用）。
pub fn build_tcp(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src.port().to_be_bytes());
    tcp.extend_from_slice(&dst.port().to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&window.to_be_bytes());
    tcp.extend_from_slice(&[0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    let seg_len = tcp.len();
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + seg_len;
            let mut out = Vec::with_capacity(total);
            out.push(0x45);
            out.push(0);
            out.extend_from_slice(&(total as u16).to_be_bytes());
            out.extend_from_slice(&IP_ID.fetch_add(1, Ordering::Relaxed).to_be_bytes());
            out.extend_from_slice(&[0x40, 0, 64, PROTO_TCP, 0, 0]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            let hsum = checksum(sum_bytes(0, &out[..20]));
            out[10..12].copy_from_slice(&hsum.to_be_bytes());
            let mut sum = sum_bytes(sum_bytes(0, &s.octets()), &d.octets());
            sum += seg_len as u32 + PROTO_TCP as u32;
            let c = checksum(sum_bytes(sum, &tcp));
            tcp[16..18].copy_from_slice(&c.to_be_bytes());
            out.extend_from_slice(&tcp);
            Some(out)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut out = Vec::with_capacity(40 + seg_len);
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&(seg_len as u16).to_be_bytes());
            out.push(PROTO_TCP);
            out.push(64);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            let mut sum = sum_bytes(sum_bytes(0, &s.octets()), &d.octets());
            sum += seg_len as u32 + PROTO_TCP as u32;
            let c = checksum(sum_bytes(sum, &tcp));
            tcp[16..18].copy_from_slice(&c.to_be_bytes());
            out.extend_from_slice(&tcp);
            Some(out)
        }
        _ => None,
    }
}

/// 本机没有 IPv6 时对发往全局单播 `2000::/3` 的包的处理结果。
#[derive(Debug, PartialEq, Eq)]
pub enum Ipv6Gate {
    /// 不是全局 IPv6 新连接 / 数据报，照常交给 Netstack。
    Pass,
    /// 回给应用的拒绝包（TCP RST 或 ICMPv6 目的不可达），原包丢弃。
    Reply(Vec<u8>),
}

const PROTO_ICMPV6: u8 = 58;
/// ICMPv6 差错报文连同 IPv6 头不超过最小 MTU。
const ICMPV6_ERROR_MAX: usize = 1280;

/// 在握手之前拒绝全局 IPv6：TCP SYN 回 RST|ACK，UDP 回 ICMPv6 目的不可达（无路由），
/// 应用因此立即得到连接失败并回退 IPv4。非 SYN 的 TCP 段、ICMPv6、扩展头与非全局地址放行。
pub fn gate_global_ipv6(pkt: &[u8]) -> Ipv6Gate {
    if pkt.len() < 40 || pkt[0] >> 4 != 6 || pkt[24] & 0xE0 != 0x20 {
        return Ipv6Gate::Pass;
    }
    match pkt[6] {
        PROTO_TCP => {
            let Some(seg) = parse_tcp(pkt) else {
                return Ipv6Gate::Pass;
            };
            if seg.flags & (TCP_SYN | TCP_ACK) != TCP_SYN {
                return Ipv6Gate::Pass;
            }
            build_tcp(
                seg.dst,
                seg.src,
                0,
                seg.seq.wrapping_add(1),
                TCP_FLAG_RST | TCP_FLAG_ACK,
                0,
                &[],
            )
            .map_or(Ipv6Gate::Pass, Ipv6Gate::Reply)
        }
        PROTO_UDP => Ipv6Gate::Reply(icmpv6_no_route(pkt)),
        _ => Ipv6Gate::Pass,
    }
}

/// ICMPv6 目的不可达（type 1，code 0 无路由），携带原包前部。
fn icmpv6_no_route(pkt: &[u8]) -> Vec<u8> {
    let quoted = &pkt[..pkt.len().min(ICMPV6_ERROR_MAX - 48)];
    let len = 8 + quoted.len();
    let mut out = Vec::with_capacity(40 + len);
    out.extend_from_slice(&[0x60, 0, 0, 0]);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.push(PROTO_ICMPV6);
    out.push(64);
    // 源为原目的地址，目的为原源地址。
    out.extend_from_slice(&pkt[24..40]);
    out.extend_from_slice(&pkt[8..24]);
    out.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(quoted);
    let mut sum = sum_bytes(0, &out[8..40]);
    sum += len as u32 + PROTO_ICMPV6 as u32;
    let c = checksum(sum_bytes(sum, &out[40..]));
    out[42..44].copy_from_slice(&c.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_non_unicast_addresses() {
        assert!(is_non_unicast("255.255.255.255".parse().unwrap()));
        assert!(is_non_unicast("224.0.0.251".parse().unwrap()));
        assert!(is_non_unicast("ff02::fb".parse().unwrap()));
        assert!(!is_non_unicast("1.1.1.1".parse().unwrap()));
    }

    fn verify(pkt: &[u8]) {
        match parse(pkt) {
            Parsed::Udp { .. } => {}
            p => panic!("{p:?}"),
        }
        if pkt[0] >> 4 == 4 {
            assert_eq!(checksum(sum_bytes(0, &pkt[..20])), 0);
            let mut pseudo = sum_bytes(0, &pkt[12..20]);
            pseudo += (pkt.len() - 20) as u32 + 17;
            assert_eq!(checksum(sum_bytes(pseudo, &pkt[20..])), 0);
        } else {
            let mut pseudo = sum_bytes(0, &pkt[8..40]);
            pseudo += (pkt.len() - 40) as u32 + 17;
            assert_eq!(checksum(sum_bytes(pseudo, &pkt[40..])), 0);
        }
    }

    #[test]
    fn udp_roundtrip_v4() {
        let src: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let dst: SocketAddr = "198.18.0.1:5353".parse().unwrap();
        let pkt = build_udp(src, dst, b"hello!!").unwrap();
        verify(&pkt);
        assert_eq!(
            parse(&pkt),
            Parsed::Udp {
                src,
                dst,
                payload: b"hello!!"
            }
        );
        // IPv4 映射地址按 IPv4 构造
        let mapped: SocketAddr = "[::ffff:8.8.8.8]:53".parse().unwrap();
        assert_eq!(build_udp(mapped, dst, b"x").unwrap()[0] >> 4, 4);
    }

    #[test]
    fn udp_roundtrip_v6() {
        let src: SocketAddr = "[2001:4860:4860::8888]:443".parse().unwrap();
        let dst: SocketAddr = "[fd00::1]:50000".parse().unwrap();
        let pkt = build_udp(src, dst, b"odd").unwrap();
        verify(&pkt);
        assert_eq!(
            parse(&pkt),
            Parsed::Udp {
                src,
                dst,
                payload: b"odd"
            }
        );
        assert!(build_udp(src, "1.1.1.1:1".parse().unwrap(), b"x").is_none());
    }

    #[test]
    fn global_ipv6_gate_rejects_syn_and_udp_only() {
        let app: SocketAddr = "[fd00:6f72:796e::1]:50000".parse().unwrap();
        let global: SocketAddr = "[2409:8c54::1]:443".parse().unwrap();
        // TCP SYN：回 RST|ACK，确认号为 SYN 序号 + 1
        let syn = build_tcp(app, global, 1000, 0, TCP_FLAG_SYN, 65535, &[]).unwrap();
        let Ipv6Gate::Reply(rst) = gate_global_ipv6(&syn) else {
            panic!()
        };
        let seg = parse_tcp(&rst).unwrap();
        assert_eq!((seg.src, seg.dst, seg.ack), (global, app, 1001));
        assert_eq!(seg.flags, TCP_FLAG_RST | TCP_FLAG_ACK);
        let pseudo = sum_bytes(0, &rst[8..40]) + (rst.len() - 40) as u32 + 6;
        assert_eq!(checksum(sum_bytes(pseudo, &rst[40..])), 0);
        // 已有连接的段、ULA 与 IPv4 放行
        let ack = build_tcp(app, global, 1001, 1, TCP_FLAG_ACK, 65535, &[]).unwrap();
        assert_eq!(gate_global_ipv6(&ack), Ipv6Gate::Pass);
        let ula: SocketAddr = "[fd7a:115c:a1e0::1]:443".parse().unwrap();
        let syn_ula = build_tcp(app, ula, 1, 0, TCP_FLAG_SYN, 65535, &[]).unwrap();
        assert_eq!(gate_global_ipv6(&syn_ula), Ipv6Gate::Pass);
        let v4 = build_tcp(
            "10.0.0.2:1".parse().unwrap(),
            "1.1.1.1:443".parse().unwrap(),
            1,
            0,
            TCP_FLAG_SYN,
            65535,
            &[],
        )
        .unwrap();
        assert_eq!(gate_global_ipv6(&v4), Ipv6Gate::Pass);
        // UDP：ICMPv6 目的不可达，携带原包，校验和正确，总长不超过 1280
        let big = vec![7u8; 1400];
        let udp = build_udp(app, global, &big).unwrap();
        let Ipv6Gate::Reply(icmp) = gate_global_ipv6(&udp) else {
            panic!()
        };
        assert!(icmp.len() <= 1280);
        assert_eq!((icmp[6], icmp[40], icmp[41]), (58, 1, 0));
        assert_eq!(&icmp[8..24], &udp[24..40]);
        assert_eq!(&icmp[24..40], &udp[8..24]);
        assert_eq!(&icmp[48..88], &udp[..40]);
        let len = icmp.len() - 40;
        let sum = sum_bytes(0, &icmp[8..40]) + len as u32 + 58;
        assert_eq!(checksum(sum_bytes(sum, &icmp[40..])), 0);
    }

    #[test]
    fn tcp_syn_and_fragments() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[9] = PROTO_TCP;
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[33] = TCP_SYN;
        assert_eq!(
            parse(&pkt),
            Parsed::Tcp {
                dst_port: 443,
                syn: true
            }
        );
        pkt[33] = TCP_SYN | TCP_ACK;
        assert_eq!(
            parse(&pkt),
            Parsed::Tcp {
                dst_port: 443,
                syn: false
            }
        );
        pkt[6] = 0x20; // MF
        assert_eq!(parse(&pkt), Parsed::Other);
        assert_eq!(parse(&pkt[..10]), Parsed::Invalid);
        assert_eq!(parse(&[0x70]), Parsed::Invalid);
    }
}
