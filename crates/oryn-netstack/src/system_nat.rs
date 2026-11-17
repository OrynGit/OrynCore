//! 系统 TCP 回注所需的有界 tuple NAT 原型。
//!
//! 这里只处理包级 tuple 改写和 checksum，不创建 listener、不修改系统路由，
//! 也不把 NAT 映射暴露到 Router。真实后端接入前仍需补齐 SYN/FIN/RST、
//! 回程路由、端口复用和网络扩展头策略。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use std::time::{Duration, Instant};

const TCP: u8 = 6;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const PORT_QUARANTINE: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl Tuple {
    fn reversed(self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatError {
    Malformed,
    Fragmented,
    Unsupported,
    FamilyMismatch,
    Capacity,
    Collision,
    NotFound,
}

impl std::fmt::Display for NatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed IP/TCP packet",
            Self::Fragmented => "fragmented packet is not handled by the NAT prototype",
            Self::Unsupported => "unsupported IP or transport header",
            Self::FamilyMismatch => "tuple family does not match packet",
            Self::Capacity => "NAT table is full",
            Self::Collision => "translated tuple is already in use",
            Self::NotFound => "NAT mapping was not found",
        })
    }
}

impl std::error::Error for NatError {}

#[derive(Debug, Clone, Copy)]
struct Entry {
    original: Tuple,
    translated: Tuple,
    created: Instant,
    accepted: bool,
}

/// 有显式容量上限的双向 NAT 表。满载时拒绝新映射，不淘汰活动连接。
pub struct NatTable {
    max_entries: usize,
    forward: HashMap<Tuple, Entry>,
    reverse: HashMap<Tuple, Entry>,
    retired: HashMap<Tuple, Instant>,
}

impl NatTable {
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            max_entries,
            forward: HashMap::with_capacity(max_entries.min(1024)),
            reverse: HashMap::with_capacity(max_entries.min(1024)),
            retired: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    pub fn insert(&mut self, original: Tuple, translated: Tuple) -> Result<(), NatError> {
        self.reap();
        if original.src.is_ipv4() != original.dst.is_ipv4()
            || translated.src.is_ipv4() != translated.dst.is_ipv4()
            || original.src.is_ipv4() != translated.src.is_ipv4()
            || original.dst.is_ipv4() != translated.dst.is_ipv4()
        {
            return Err(NatError::FamilyMismatch);
        }
        if self.forward.contains_key(&original)
            || self.reverse.contains_key(&translated)
            || self.retired.contains_key(&translated)
        {
            return Err(NatError::Collision);
        }
        if self.forward.len() + self.retired.len() >= self.max_entries {
            return Err(NatError::Capacity);
        }
        let entry = Entry {
            original,
            translated,
            created: Instant::now(),
            accepted: false,
        };
        self.forward.insert(original, entry);
        self.reverse.insert(translated, entry);
        Ok(())
    }

    pub fn remove(&mut self, original: Tuple) -> bool {
        let Some(entry) = self.forward.remove(&original) else {
            return false;
        };
        self.reverse.remove(&entry.translated);
        self.retired
            .insert(entry.translated, Instant::now() + PORT_QUARANTINE);
        true
    }

    /// 只由验证过 peer 的 listener 调用；活跃流不受握手超时影响。
    pub fn accept(&mut self, translated: Tuple) -> Result<Tuple, NatError> {
        let entry = self
            .reverse
            .get_mut(&translated)
            .ok_or(NatError::NotFound)?;
        if entry.accepted || entry.created.elapsed() >= HANDSHAKE_TIMEOUT {
            return Err(NatError::NotFound);
        }
        entry.accepted = true;
        let original = entry.original;
        self.forward.get_mut(&original).unwrap().accepted = true;
        Ok(original)
    }

    /// 只清理未完成握手和过期隔离记录；单向 FIN 不触发映射回收。
    pub fn reap(&mut self) {
        let now = Instant::now();
        self.retired.retain(|_, until| *until > now);
        let expired: Vec<_> = self
            .forward
            .iter()
            .filter(|(_, e)| !e.accepted && now.duration_since(e.created) >= HANDSHAKE_TIMEOUT)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.remove(key);
        }
    }

    /// 把应用发往原始目标的包改成“虚拟源 → 内部 listener”。
    pub fn forward_packet(&self, packet: &mut [u8], original: Tuple) -> Result<(), NatError> {
        let entry = self.forward.get(&original).ok_or(NatError::NotFound)?;
        rewrite_packet(packet, entry.original, entry.translated)
    }

    /// 把内部 listener 返回的包还原成“原始目标 → 应用源”。
    pub fn reverse_packet(&self, packet: &mut [u8], translated: Tuple) -> Result<(), NatError> {
        let entry = self.reverse.get(&translated).ok_or(NatError::NotFound)?;
        rewrite_packet(
            packet,
            entry.translated.reversed(),
            entry.original.reversed(),
        )
    }
}

fn rewrite_packet(packet: &mut [u8], from: Tuple, to: Tuple) -> Result<(), NatError> {
    let parsed = parse_packet(packet)?;
    if parsed.tuple != from {
        return Err(NatError::NotFound);
    }
    if from.src.is_ipv4() != to.src.is_ipv4() || from.dst.is_ipv4() != to.dst.is_ipv4() {
        return Err(NatError::FamilyMismatch);
    }
    set_ip(packet, parsed.ip_offset, to.src.ip(), to.dst.ip())?;
    if parsed.version == 4 {
        packet[10..12].fill(0);
        let sum = checksum(sum_with(0, &packet[..parsed.ip_header_len]));
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
    }
    let pseudo = pseudo_sum(packet, parsed.version, parsed.tcp_offset, parsed.end);
    let tcp = &mut packet[parsed.tcp_offset..parsed.end];
    tcp[..2].copy_from_slice(&to.src.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&to.dst.port().to_be_bytes());
    tcp[16..18].fill(0);
    let sum = checksum(sum_with(pseudo, tcp));
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Parsed {
    tuple: Tuple,
    version: u8,
    ip_offset: usize,
    ip_header_len: usize,
    tcp_offset: usize,
    end: usize,
}

fn parse_packet(packet: &[u8]) -> Result<Parsed, NatError> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => parse_v4(packet),
        Some(6) => parse_v6(packet),
        _ => Err(NatError::Unsupported),
    }
}

fn parse_v4(packet: &[u8]) -> Result<Parsed, NatError> {
    if packet.len() < 20 || packet[9] != TCP {
        return Err(NatError::Malformed);
    }
    let ihl = (packet[0] as usize & 0x0f) * 4;
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let flags = u16::from_be_bytes([packet[6], packet[7]]);
    if ihl < 20 || total < ihl || total > packet.len() {
        return Err(NatError::Malformed);
    }
    if flags & 0x3fff != 0 {
        return Err(NatError::Fragmented);
    }
    let src = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    parse_tcp(packet, 4, ihl, total, src, dst)
}

fn parse_v6(packet: &[u8]) -> Result<Parsed, NatError> {
    if packet.len() < 40 || packet[6] != TCP {
        return Err(NatError::Unsupported);
    }
    let payload = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let end = 40usize.checked_add(payload).ok_or(NatError::Malformed)?;
    if end > packet.len() {
        return Err(NatError::Malformed);
    }
    let src = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24]).unwrap(),
    ));
    let dst = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40]).unwrap(),
    ));
    parse_tcp(packet, 6, 40, end, src, dst)
}

fn parse_tcp(
    packet: &[u8],
    version: u8,
    ip_header_len: usize,
    end: usize,
    src: IpAddr,
    dst: IpAddr,
) -> Result<Parsed, NatError> {
    let off = ip_header_len;
    if end < off + 20 {
        return Err(NatError::Malformed);
    }
    let data_offset = (packet[off + 12] as usize >> 4) * 4;
    if data_offset < 20 || off + data_offset > end {
        return Err(NatError::Malformed);
    }
    Ok(Parsed {
        tuple: Tuple {
            src: SocketAddr::new(src, u16::from_be_bytes([packet[off], packet[off + 1]])),
            dst: SocketAddr::new(dst, u16::from_be_bytes([packet[off + 2], packet[off + 3]])),
        },
        version,
        ip_offset: 0,
        ip_header_len,
        tcp_offset: off,
        end,
    })
}

fn set_ip(packet: &mut [u8], _offset: usize, src: IpAddr, dst: IpAddr) -> Result<(), NatError> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            Ok(())
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
            Ok(())
        }
        _ => Err(NatError::FamilyMismatch),
    }
}

fn pseudo_sum(packet: &[u8], version: u8, tcp_offset: usize, end: usize) -> u32 {
    let mut sum = 0;
    if version == 4 {
        sum = sum_with(sum, &packet[12..20]);
    } else {
        sum = sum_with(sum, &packet[8..40]);
    }
    sum + (end - tcp_offset) as u32 + TCP as u32
}

fn sum_with(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += (byte as u32) << 8;
    }
    sum
}

fn checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{build_tcp, parse_tcp, TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_SYN};

    fn validate(packet: &[u8]) {
        let version = packet[0] >> 4;
        let (ip_len, end) = if version == 4 {
            (20, u16::from_be_bytes([packet[2], packet[3]]) as usize)
        } else {
            (40, 40 + u16::from_be_bytes([packet[4], packet[5]]) as usize)
        };
        if version == 4 {
            assert_eq!(checksum(sum_with(0, &packet[..ip_len])), 0);
        }
        let tcp_offset = ip_len;
        let mut tcp = packet[tcp_offset..end].to_vec();
        let expected = u16::from_be_bytes([tcp[16], tcp[17]]);
        tcp[16..18].fill(0);
        assert_eq!(
            checksum(sum_with(pseudo_sum(packet, version, tcp_offset, end), &tcp)),
            expected
        );
    }

    #[test]
    fn bounded_v4_forward_and_reverse_restore_tuple_and_checksum() {
        let original = Tuple {
            src: "198.18.0.10:40123".parse().unwrap(),
            dst: "203.0.113.7:443".parse().unwrap(),
        };
        let translated = Tuple {
            src: "198.18.0.254:50123".parse().unwrap(),
            dst: "198.18.0.1:40000".parse().unwrap(),
        };
        let mut nat = NatTable::with_capacity(1);
        nat.insert(original, translated).unwrap();
        let mut packet = build_tcp(
            original.src,
            original.dst,
            1,
            0,
            TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_PSH,
            4096,
            b"x",
        )
        .unwrap();
        nat.forward_packet(&mut packet, original).unwrap();
        let fwd = parse_tcp(&packet).unwrap();
        assert_eq!(fwd.src, translated.src);
        assert_eq!(fwd.dst, translated.dst);
        validate(&packet);
        packet = build_tcp(
            translated.dst,
            translated.src,
            8,
            2,
            TCP_FLAG_ACK,
            4096,
            b"reply",
        )
        .unwrap();
        nat.reverse_packet(&mut packet, translated).unwrap();
        let back = parse_tcp(&packet).unwrap();
        assert_eq!(back.src, original.dst);
        assert_eq!(back.dst, original.src);
        validate(&packet);
    }

    #[test]
    fn bounded_v6_and_capacity() {
        let a: Tuple = Tuple {
            src: "[fd00::10]:1".parse().unwrap(),
            dst: "[2001:db8::7]:443".parse().unwrap(),
        };
        let b: Tuple = Tuple {
            src: "[fd00::fe]:2".parse().unwrap(),
            dst: "[fd00::2]:40000".parse().unwrap(),
        };
        let mut nat = NatTable::with_capacity(1);
        nat.insert(a, b).unwrap();
        let mut p = build_tcp(
            a.src,
            a.dst,
            2,
            1,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            4096,
            b"payload",
        )
        .unwrap();
        nat.forward_packet(&mut p, a).unwrap();
        assert_eq!(parse_tcp(&p).unwrap().src, b.src);
        validate(&p);
        p = build_tcp(b.dst, b.src, 9, 3, TCP_FLAG_ACK, 4096, b"return").unwrap();
        nat.reverse_packet(&mut p, b).unwrap();
        assert_eq!(parse_tcp(&p).unwrap().dst, a.src);
        validate(&p);
        let c: Tuple = Tuple {
            src: "[fd00::11]:3".parse().unwrap(),
            dst: a.dst,
        };
        assert_eq!(nat.insert(c, b), Err(NatError::Collision));
        assert!(nat.remove(a));
        assert!(nat.is_empty());
        assert_eq!(nat.insert(c, b), Err(NatError::Collision));
    }

    #[test]
    fn handshake_expiry_and_active_half_close_keep_budget() {
        let a = Tuple { src: "198.18.0.10:4".parse().unwrap(), dst: "203.0.113.7:443".parse().unwrap() };
        let b = Tuple { src: "198.18.0.254:5".parse().unwrap(), dst: "198.18.0.1:40000".parse().unwrap() };
        let mut nat = NatTable::with_capacity(1);
        nat.insert(a, b).unwrap();
        assert_eq!(nat.accept(b).unwrap(), a);
        nat.forward.get_mut(&a).unwrap().created = Instant::now() - HANDSHAKE_TIMEOUT * 2;
        nat.reap();
        assert_eq!(nat.len(), 1);
        assert!(nat.remove(a));
        assert_eq!(nat.insert(a, b), Err(NatError::Collision));
        *nat.retired.get_mut(&b).unwrap() = Instant::now();
        nat.insert(a, b).unwrap();
        nat.forward.get_mut(&a).unwrap().created = Instant::now() - HANDSHAKE_TIMEOUT * 2;
        nat.reap();
        assert!(nat.is_empty());
        assert_eq!(nat.insert(a, b), Err(NatError::Collision));
    }

    #[test]
    fn rejects_fragments_and_mismatched_packet() {
        let original: Tuple = Tuple {
            src: "198.18.0.10:1".parse().unwrap(),
            dst: "203.0.113.7:443".parse().unwrap(),
        };
        let translated: Tuple = Tuple {
            src: "198.18.0.254:2".parse().unwrap(),
            dst: "198.18.0.1:40000".parse().unwrap(),
        };
        let mut nat = NatTable::with_capacity(1);
        nat.insert(original, translated).unwrap();
        let mut p = build_tcp(original.src, original.dst, 1, 0, TCP_FLAG_SYN, 4096, &[]).unwrap();
        p[6] = 0x20;
        assert_eq!(
            nat.forward_packet(&mut p, original),
            Err(NatError::Fragmented)
        );
    }
}
