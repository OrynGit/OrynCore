//! 隧道内的 IP 分片与重组，IPv4 与 IPv6 同一套。
//!
//! smoltcp 0.11 不重组也不切分普通 IPv6 分片（它的 `proto-ipv6-fragmentation` 只服务 6LoWPAN）；
//! IPv4 切片时第一片载荷为 `MTU − 20`，默认 MTU 1280 下偏移不是 8 的倍数。所以不打开 smoltcp 的分片：
//! 收到的分片在交给 smoltcp 之前在这里重组；超过 MTU 的 UDP 数据报在这里生成首部并切片。
//! 包只在本 crate 内流动。

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// 重组后 / 切片前的 IP 包上限。
pub const MAX_PACKET: usize = 8192;
/// 同时重组的数据报（两族、所有对端合计）；满时淘汰最旧的。
/// 多对端并发分片时 4 个槽位会互相淘汰丢整组；8 个槽位最坏 64 KiB。
const SLOTS: usize = 8;
const MAX_FRAGMENTS: usize = 64;
/// RFC 791 建议的重组计时器初值。
const TIMEOUT: Duration = Duration::from_secs(15);
const TTL: u8 = 64;
const UDP: u8 = 17;
const IPV6_FRAGMENT: u8 = 44;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Key {
    V4([u8; 4], [u8; 4], u8, u16),
    V6([u8; 16], [u8; 16], u32),
}

/// 一个分片的解析结果。
struct Fragment<'a> {
    key: Key,
    offset: usize,
    more: bool,
    data: &'a [u8],
    /// 不分片部分（IPv4 首部；IPv6 固定首部与分片首部之前的扩展首部）。
    head: &'a [u8],
    /// IPv6：不分片部分中最后一个 Next Header 字段的位置，以及分片首部给出的上层协议。
    next_header: Option<(usize, u8)>,
}

enum Parsed<'a> {
    Whole,
    Fragment(Fragment<'a>),
    Invalid,
}

fn parse(packet: &[u8]) -> Parsed<'_> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => parse_v4(packet),
        Some(6) => parse_v6(packet),
        _ => Parsed::Invalid,
    }
}

fn parse_v4(packet: &[u8]) -> Parsed<'_> {
    if packet.len() < 20 {
        return Parsed::Invalid;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if ihl < 20 || total < ihl || total > packet.len() {
        return Parsed::Invalid;
    }
    let flags = u16::from_be_bytes([packet[6], packet[7]]);
    let more = flags & 0x2000 != 0;
    let offset = usize::from(flags & 0x1fff) * 8;
    if !more && offset == 0 {
        return Parsed::Whole;
    }
    let key = Key::V4(
        packet[12..16].try_into().unwrap(),
        packet[16..20].try_into().unwrap(),
        packet[9],
        u16::from_be_bytes([packet[4], packet[5]]),
    );
    Parsed::Fragment(Fragment {
        key,
        offset,
        more,
        data: &packet[ihl..total],
        head: &packet[..ihl],
        next_header: None,
    })
}

fn parse_v6(packet: &[u8]) -> Parsed<'_> {
    if packet.len() < 40 {
        return Parsed::Invalid;
    }
    let end = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if end > packet.len() {
        return Parsed::Invalid;
    }
    let mut next = packet[6];
    let mut field = 6;
    let mut pos = 40;
    // 分片首部之前只允许逐跳、路由、目的选项首部（RFC 8200 §4.1）
    for _ in 0..8 {
        if !matches!(next, 0 | 43 | 60) {
            break;
        }
        if pos + 2 > end {
            return Parsed::Invalid;
        }
        let len = (usize::from(packet[pos + 1]) + 1) * 8;
        if pos + len > end {
            return Parsed::Invalid;
        }
        next = packet[pos];
        field = pos;
        pos += len;
    }
    if next != IPV6_FRAGMENT {
        return Parsed::Whole;
    }
    if pos + 8 > end {
        return Parsed::Invalid;
    }
    let word = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    let key = Key::V6(
        packet[8..24].try_into().unwrap(),
        packet[24..40].try_into().unwrap(),
        u32::from_be_bytes(packet[pos + 4..pos + 8].try_into().unwrap()),
    );
    Parsed::Fragment(Fragment {
        key,
        offset: usize::from(word & 0xfff8),
        more: word & 1 != 0,
        data: &packet[pos + 8..end],
        head: &packet[..pos],
        next_header: Some((field, packet[pos])),
    })
}

/// 第一片的不分片部分，以及 IPv6 时要改写的 Next Header 位置与值。
type Head = (Vec<u8>, Option<(usize, u8)>);

struct Slot {
    key: Key,
    started: Instant,
    head: Option<Head>,
    data: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    total: Option<usize>,
}

impl Slot {
    /// 加入一个分片；返回 false 表示这组分片不合法，应整组丢弃。
    fn add(&mut self, f: &Fragment<'_>) -> bool {
        let end = f.offset + f.data.len();
        if f.more && (f.data.is_empty() || !f.data.len().is_multiple_of(8)) {
            return false;
        }
        if f.head.len() + end > MAX_PACKET {
            return false;
        }
        if !f.more {
            if self.total.is_some_and(|t| t != end) {
                return false;
            }
            self.total = Some(end);
        }
        if self.total.is_some_and(|t| end > t)
            || self
                .ranges
                .iter()
                .any(|&(_, e)| self.total.is_some_and(|t| e > t))
        {
            return false;
        }
        if f.offset == 0 {
            let head = (f.head.to_vec(), f.next_header);
            if self.head.as_ref().is_some_and(|h| *h != head) {
                return false;
            }
            self.head = Some(head);
        }
        // 完全相同的重复分片忽略；其余重叠按 RFC 5722 整组丢弃
        if self.ranges.contains(&(f.offset, end)) {
            return self.data[f.offset..end] == *f.data;
        }
        if self.ranges.iter().any(|&(s, e)| f.offset < e && s < end) {
            return false;
        }
        if self.ranges.len() >= MAX_FRAGMENTS {
            return false;
        }
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        self.data[f.offset..end].copy_from_slice(f.data);
        self.ranges.push((f.offset, end));
        true
    }

    fn complete(&mut self) -> bool {
        let (Some(total), Some(_)) = (self.total, &self.head) else {
            return false;
        };
        self.ranges.sort_unstable();
        let mut covered = 0;
        for &(s, e) in &self.ranges {
            if s != covered {
                return false;
            }
            covered = e;
        }
        covered == total
    }

    fn assemble(self) -> Vec<u8> {
        let (mut packet, next_header) = self.head.unwrap();
        packet.extend_from_slice(&self.data);
        match next_header {
            None => {
                let ihl = usize::from(packet[0] & 0x0f) * 4;
                let total = packet.len() as u16;
                packet[2..4].copy_from_slice(&total.to_be_bytes());
                packet[6..8].fill(0);
                packet[10..12].fill(0);
                let sum = checksum(&packet[..ihl], 0);
                packet[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            Some((field, next)) => {
                packet[field] = next;
                let len = (packet.len() - 40) as u16;
                packet[4..6].copy_from_slice(&len.to_be_bytes());
            }
        }
        packet
    }
}

/// 有上限的重组器。
#[derive(Default)]
pub struct Reassembler {
    slots: Vec<Slot>,
}

impl Reassembler {
    /// 不是分片的包原样返回；分片在凑齐前返回 None，凑齐后返回完整的包。不合法的包丢弃。
    pub fn push(&mut self, packet: Vec<u8>, now: Instant) -> Option<Vec<u8>> {
        self.expire(now);
        let f = match parse(&packet) {
            Parsed::Whole => return Some(packet),
            Parsed::Invalid => return None,
            Parsed::Fragment(f) => f,
        };
        let i = match self.slots.iter().position(|s| s.key == f.key) {
            Some(i) => i,
            None => {
                if self.slots.len() >= SLOTS {
                    let oldest = (0..self.slots.len())
                        .min_by_key(|&i| self.slots[i].started)
                        .unwrap();
                    self.slots.swap_remove(oldest);
                }
                self.slots.push(Slot {
                    key: f.key,
                    started: now,
                    head: None,
                    data: Vec::new(),
                    ranges: Vec::new(),
                    total: None,
                });
                self.slots.len() - 1
            }
        };
        if !self.slots[i].add(&f) {
            self.slots.swap_remove(i);
            return None;
        }
        if !self.slots[i].complete() {
            return None;
        }
        Some(self.slots.swap_remove(i).assemble())
    }

    pub fn expire(&mut self, now: Instant) {
        self.slots
            .retain(|s| now.duration_since(s.started) < TIMEOUT);
    }

    #[cfg(test)]
    fn pending(&self) -> usize {
        self.slots.len()
    }
}

fn checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [b] = chunks.remainder() {
        sum += u32::from(*b) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_sum(src: IpAddr, dst: IpAddr, len: usize) -> u32 {
    let mut pseudo = Vec::with_capacity(40);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&[0, UDP]);
            pseudo.extend_from_slice(&(len as u16).to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&(len as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, UDP]);
        }
        _ => unreachable!("address families checked by the caller"),
    }
    let mut sum = 0u32;
    for c in pseudo.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    sum
}

/// 生成一个 UDP 数据报并按 MTU 切成 IP 分片，偏移按 8 字节对齐。
/// 两端地址族必须相同；调用方保证 `payload` 不超过 [`MAX_PACKET`] 对应的载荷上限。
pub fn fragment_udp(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    mtu: usize,
    ident: u32,
) -> Vec<Vec<u8>> {
    let len = 8 + payload.len();
    let mut udp = Vec::with_capacity(len);
    udp.extend_from_slice(&src.port().to_be_bytes());
    udp.extend_from_slice(&dst.port().to_be_bytes());
    udp.extend_from_slice(&(len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let mut sum = checksum(&udp, pseudo_sum(src.ip(), dst.ip(), len));
    if sum == 0 {
        sum = 0xffff;
    }
    udp[6..8].copy_from_slice(&sum.to_be_bytes());

    let v4 = src.is_ipv4();
    let header = if v4 { 20 } else { 48 };
    let step = (mtu - header) & !7;
    let mut out = Vec::with_capacity(udp.len().div_ceil(step));
    for (i, chunk) in udp.chunks(step).enumerate() {
        let offset = i * step;
        let more = offset + chunk.len() < udp.len();
        let mut p = Vec::with_capacity(header + chunk.len());
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                p.extend_from_slice(&[0x45, 0]);
                p.extend_from_slice(&((20 + chunk.len()) as u16).to_be_bytes());
                p.extend_from_slice(&(ident as u16).to_be_bytes());
                let word = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
                p.extend_from_slice(&word.to_be_bytes());
                p.extend_from_slice(&[TTL, UDP, 0, 0]);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                let sum = checksum(&p, 0);
                p[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                p.extend_from_slice(&[0x60, 0, 0, 0]);
                p.extend_from_slice(&((8 + chunk.len()) as u16).to_be_bytes());
                p.extend_from_slice(&[IPV6_FRAGMENT, TTL]);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                p.extend_from_slice(&[UDP, 0]);
                let word = offset as u16 | u16::from(more);
                p.extend_from_slice(&word.to_be_bytes());
                p.extend_from_slice(&ident.to_be_bytes());
            }
            _ => unreachable!("address families checked by the caller"),
        }
        p.extend_from_slice(chunk);
        out.push(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr,
    };

    const V4: (&str, &str) = ("10.0.0.2:5000", "10.0.0.1:7");
    const V6: (&str, &str) = ("[fd00::2]:5000", "[fd00::1]:7");

    fn addrs((a, b): (&str, &str)) -> (SocketAddr, SocketAddr) {
        (a.parse().unwrap(), b.parse().unwrap())
    }

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    /// 用 smoltcp 的 wire 解析校验首部与 UDP 校验和，返回 UDP 载荷。
    fn check_udp(packet: &[u8], src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        let caps = ChecksumCapabilities::default();
        let (s, d, body) = if src.is_ipv4() {
            let ip = Ipv4Packet::new_checked(packet).unwrap();
            let repr = Ipv4Repr::parse(&ip, &caps).unwrap();
            assert_eq!(repr.next_header, IpProtocol::Udp);
            assert!(!ip.more_frags() && ip.frag_offset() == 0);
            (
                IpAddress::Ipv4(repr.src_addr),
                IpAddress::Ipv4(repr.dst_addr),
                ip.payload().to_vec(),
            )
        } else {
            let ip = Ipv6Packet::new_checked(packet).unwrap();
            let repr = Ipv6Repr::parse(&ip).unwrap();
            assert_eq!(repr.next_header, IpProtocol::Udp);
            (
                IpAddress::Ipv6(repr.src_addr),
                IpAddress::Ipv6(repr.dst_addr),
                ip.payload().to_vec(),
            )
        };
        let udp = UdpPacket::new_checked(&body[..]).unwrap();
        let repr = UdpRepr::parse(&udp, &s, &d, &caps).unwrap();
        assert_eq!((repr.src_port, repr.dst_port), (src.port(), dst.port()));
        udp.payload().to_vec()
    }

    #[test]
    fn roundtrip_both_families_aligned_offsets() {
        let now = Instant::now();
        for (pair, header) in [(V4, 28), (V6, 48)] {
            let (src, dst) = addrs(pair);
            for mtu in [1280, 1281, 1420] {
                for size in [1, 1253, 1500, 4096, MAX_PACKET - header] {
                    let data = payload(size);
                    let frags = fragment_udp(src, dst, &data, mtu, 0x1234_5678);
                    for f in &frags {
                        assert!(f.len() <= mtu);
                    }
                    if frags.len() > 1 {
                        // 非最后一片的数据长度是 8 的倍数，并能被 smoltcp 解析
                        if src.is_ipv4() {
                            let ip = Ipv4Packet::new_checked(&frags[0][..]).unwrap();
                            assert!(ip.verify_checksum());
                            assert!(ip.more_frags());
                            assert_eq!(ip.payload().len() % 8, 0);
                        } else {
                            assert_eq!((frags[0].len() - 48) % 8, 0);
                        }
                    }
                    let mut r = Reassembler::default();
                    // 倒序送入
                    let mut whole = None;
                    for f in frags.into_iter().rev() {
                        assert!(whole.is_none());
                        whole = r.push(f, now);
                    }
                    let whole = whole.unwrap();
                    assert_eq!(check_udp(&whole, src, dst), data, "mtu {mtu} size {size}");
                    assert_eq!(r.pending(), 0);
                }
            }
        }
    }

    #[test]
    fn whole_packets_pass_through_and_garbage_is_dropped() {
        let now = Instant::now();
        let mut r = Reassembler::default();
        let (src, dst) = addrs(V4);
        let single = fragment_udp(src, dst, b"tiny", 1280, 1);
        assert_eq!(single.len(), 1);
        assert_eq!(r.push(single[0].clone(), now), Some(single[0].clone()));
        assert_eq!(r.push(vec![0x45; 10], now), None);
        assert_eq!(r.push(vec![], now), None);
        assert_eq!(r.push(vec![0x20; 40], now), None);
    }

    #[test]
    fn duplicates_overlaps_and_inconsistent_lengths() {
        let now = Instant::now();
        for pair in [V4, V6] {
            let (src, dst) = addrs(pair);
            let data = payload(3000);
            let frags = fragment_udp(src, dst, &data, 1280, 9);
            assert_eq!(frags.len(), 3);
            // 完全相同的重复分片被忽略
            let mut r = Reassembler::default();
            assert!(r.push(frags[0].clone(), now).is_none());
            assert!(r.push(frags[0].clone(), now).is_none());
            assert!(r.push(frags[1].clone(), now).is_none());
            assert!(r.push(frags[2].clone(), now).is_some());
            // 内容不同的重复分片：整组丢弃
            let mut r = Reassembler::default();
            assert!(r.push(frags[0].clone(), now).is_none());
            let mut changed = frags[0].clone();
            *changed.last_mut().unwrap() ^= 1;
            assert!(r.push(changed, now).is_none());
            assert_eq!(r.pending(), 0);
            // 重叠：把第二片的偏移往前移 8 字节
            let mut r = Reassembler::default();
            assert!(r.push(frags[0].clone(), now).is_none());
            let mut shifted = frags[1].clone();
            if src.is_ipv4() {
                let word = u16::from_be_bytes([shifted[6], shifted[7]]);
                shifted[6..8].copy_from_slice(&(word - 1).to_be_bytes());
                shifted[10..12].fill(0);
                let sum = checksum(&shifted[..20], 0);
                shifted[10..12].copy_from_slice(&sum.to_be_bytes());
            } else {
                let word = u16::from_be_bytes([shifted[42], shifted[43]]);
                shifted[42..44].copy_from_slice(&(word - 8).to_be_bytes());
            }
            assert!(r.push(shifted, now).is_none());
            assert_eq!(r.pending(), 0);
            // 两个不同的「最后一片」长度：整组丢弃
            let mut r = Reassembler::default();
            assert!(r.push(frags[2].clone(), now).is_none());
            let other = fragment_udp(src, dst, &payload(2000), 1280, 9);
            assert!(r.push(other[1].clone(), now).is_none());
            assert_eq!(r.pending(), 0);
        }
    }

    #[test]
    fn limits_eviction_and_timeout() {
        let now = Instant::now();
        let (src, dst) = addrs(V4);
        let mut r = Reassembler::default();
        for id in 0..SLOTS as u32 + 2 {
            let frags = fragment_udp(src, dst, &payload(2000), 1280, id);
            assert!(r
                .push(frags[0].clone(), now + Duration::from_millis(id as u64))
                .is_none());
        }
        assert_eq!(r.pending(), SLOTS);
        // 最旧的两组已被淘汰，补齐它们不会产出
        let first = fragment_udp(src, dst, &payload(2000), 1280, 0);
        assert!(r.push(first[1].clone(), now).is_none());
        // 最新的一组仍可补齐
        let last = fragment_udp(src, dst, &payload(2000), 1280, SLOTS as u32 + 1);
        assert!(r.push(last[1].clone(), now).is_some());
        // 超时整组丢弃
        let mut r = Reassembler::default();
        let frags = fragment_udp(src, dst, &payload(2000), 1280, 77);
        assert!(r.push(frags[0].clone(), now).is_none());
        assert!(r.push(frags[1].clone(), now + TIMEOUT).is_none());
        assert_eq!(r.pending(), 1);
        // 超过 MAX_PACKET 的数据报：整组丢弃
        let mut r = Reassembler::default();
        let big = fragment_udp(src, dst, &payload(MAX_PACKET), 1280, 5);
        let mut got = None;
        for f in big {
            got = got.or(r.push(f, now));
        }
        assert!(got.is_none());
        // 分片数超过上限：每片 8 字节的 IPv4 分片
        let mut r = Reassembler::default();
        let tiny = fragment_udp(src, dst, &payload(MAX_FRAGMENTS * 8 + 8), 28, 6);
        assert!(tiny.len() > MAX_FRAGMENTS);
        let mut got = None;
        for f in tiny {
            got = got.or(r.push(f, now));
        }
        assert!(got.is_none());
    }

    #[test]
    fn ipv6_extension_headers_before_fragment_header() {
        let now = Instant::now();
        let (src, dst) = addrs(V6);
        let data = payload(2500);
        let frags = fragment_udp(src, dst, &data, 1280, 3);
        let mut r = Reassembler::default();
        let mut whole = None;
        for f in frags {
            // 在固定首部后插入 8 字节的目的选项首部（PadN）
            let mut p = f[..40].to_vec();
            p[6] = 60;
            let plen = u16::from_be_bytes([p[4], p[5]]) + 8;
            p[4..6].copy_from_slice(&plen.to_be_bytes());
            p.extend_from_slice(&[IPV6_FRAGMENT, 0, 1, 4, 0, 0, 0, 0]);
            p.extend_from_slice(&f[40..]);
            whole = whole.or(r.push(p, now));
        }
        let whole = whole.unwrap();
        // 目的选项首部保留，其 Next Header 改为 UDP
        assert_eq!(whole[6], 60);
        assert_eq!(whole[40], UDP);
        let mut plain = whole[..40].to_vec();
        plain[6] = UDP;
        let plen = u16::from_be_bytes([plain[4], plain[5]]) - 8;
        plain[4..6].copy_from_slice(&plen.to_be_bytes());
        plain.extend_from_slice(&whole[48..]);
        assert_eq!(check_udp(&plain, src, dst), data);
    }
}
