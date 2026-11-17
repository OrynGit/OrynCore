//! 仅对显式别名执行本机 IPv4 TCP 反射。包始终留在 Netstack 以下。
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq)]
pub enum Reflection {
    Pass,
    Drop,
    Packet(Vec<u8>),
}

pub struct Loopback {
    source: Ipv4Addr,
    aliases: Vec<Ipv4Addr>,
}

impl Default for Loopback {
    fn default() -> Self {
        Self {
            source: Ipv4Addr::UNSPECIFIED,
            aliases: Vec::new(),
        }
    }
}

impl Loopback {
    pub fn new(source: Ipv4Addr, aliases: Vec<Ipv4Addr>) -> Result<Self, &'static str> {
        if aliases.len() > 16 {
            return Err("too many loopback addresses");
        }
        Ok(Self { source, aliases })
    }

    pub fn reflect(&self, packet: &[u8]) -> Reflection {
        if self.aliases.is_empty() || packet.len() < 20 || packet[0] >> 4 != 4 {
            return Reflection::Pass;
        }
        let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        if !self.aliases.contains(&destination) {
            return Reflection::Pass;
        }
        // 一旦命中别名，非法包不得回退普通 Netstack/DIRECT。
        if packet[0] != 0x45
            || packet.len() < 40
            || packet[9] != 6
            || packet[12..16] != self.source.octets()
            || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
            || u16::from_be_bytes([packet[6], packet[7]]) & 0xbfff != 0
            || checksum(&packet[..20], 0) != 0
        {
            return Reflection::Drop;
        }
        let tcp_header = usize::from(packet[32] >> 4) * 4;
        if tcp_header < 20
            || tcp_header > packet.len() - 20
            || packet[20..22] == [0, 0]
            || packet[22..24] == [0, 0]
        {
            return Reflection::Drop;
        }
        let pseudo = sum(&packet[12..20]) + 6 + (packet.len() - 20) as u32;
        if checksum(&packet[20..], pseudo) != 0 {
            return Reflection::Drop;
        }
        let mut output = packet.to_vec();
        output[12..16].copy_from_slice(&destination.octets());
        output[16..20].copy_from_slice(&self.source.octets());
        // 地址交换保留两种校验和，端口、序号、负载及 TTL 均不变。
        Reflection::Packet(output)
    }
}

fn sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|b| u32::from(b[0]) * 256 + u32::from(*b.get(1).unwrap_or(&0)))
        .sum()
}
fn checksum(bytes: &[u8], initial: u32) -> u16 {
    let mut value = initial + sum(bytes);
    while value >> 16 != 0 {
        value = (value & 0xffff) + (value >> 16);
    }
    !(value as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{build_tcp, build_udp, parse_tcp};
    fn reflector() -> Loopback {
        Loopback::new(
            "198.18.0.1".parse().unwrap(),
            vec!["10.7.0.1".parse().unwrap(), "10.7.0.2".parse().unwrap()],
        )
        .unwrap()
    }
    fn tcp(flags: u8) -> Vec<u8> {
        build_tcp(
            "198.18.0.1:50000".parse().unwrap(),
            "10.7.0.1:8080".parse().unwrap(),
            42,
            50,
            flags,
            65535,
            b"odd payload",
        )
        .unwrap()
    }
    // 独立按字节验证，不复用实现中的 sum/checksum。
    fn verify(bytes: &[u8], pseudo: &[u8]) {
        let mut all = pseudo.to_vec();
        all.extend_from_slice(bytes);
        if all.len() % 2 != 0 {
            all.push(0);
        }
        let mut value: u64 = all
            .chunks_exact(2)
            .map(|p| u64::from(u16::from_be_bytes([p[0], p[1]])))
            .sum();
        while value > 65535 {
            value = (value & 65535) + (value >> 16);
        }
        assert_eq!(value, 65535);
    }
    #[test]
    fn loopback_bidirectional_tcp_and_checksums() {
        for alias in ["10.7.0.1", "10.7.0.2"] {
            for (src_port, dst_port) in [(50000, 8080), (8080, 50000)] {
                for flags in [2, 18, 16, 24, 17, 4] {
                    let input = build_tcp(
                        format!("198.18.0.1:{src_port}").parse().unwrap(),
                        format!("{alias}:{dst_port}").parse().unwrap(),
                        42,
                        50,
                        flags,
                        65535,
                        b"odd payload",
                    )
                    .unwrap();
                    let Reflection::Packet(out) = reflector().reflect(&input) else {
                        panic!("not reflected")
                    };
                    let seg = parse_tcp(&out).unwrap();
                    assert_eq!(seg.src.to_string(), format!("{alias}:{src_port}"));
                    assert_eq!(seg.dst.to_string(), format!("198.18.0.1:{dst_port}"));
                    assert_eq!((seg.seq, seg.ack, seg.flags), (42, 50, flags));
                    assert_eq!(seg.payload, b"odd payload");
                    verify(&out[..20], &[]);
                    let mut pseudo = out[12..20].to_vec();
                    pseudo.extend_from_slice(&[0, 6]);
                    pseudo.extend_from_slice(&((out.len() - 20) as u16).to_be_bytes());
                    verify(&out[20..], &pseudo);
                }
            }
        }
    }
    #[test]
    fn loopback_output_is_bounded_and_never_creates_flows() {
        use crate::NetStack;
        let mut stack = crate::LwipStack::new(1500).unwrap();
        stack
            .set_loopback(
                "198.18.0.1".parse().unwrap(),
                vec!["10.7.0.1".parse().unwrap()],
            )
            .unwrap();
        for _ in 0..5000 {
            stack.input_packet(&tcp(2));
        }
        assert_eq!(stack.take_output().len(), 4096);
        assert_eq!(stack.output_dropped(), 904);
        assert_eq!(stack.listener_count(), 0);
        assert!(stack.poll_tcp().is_none());
        assert!(stack.poll_udp().is_none());
        stack.input_packet(&tcp(4));
        assert_eq!(stack.take_output().len(), 1);
    }

    #[test]
    fn loopback_drops_invalid_alias_traffic_only() {
        let good = tcp(2);
        for index in [0, 2, 6, 9, 10, 12, 32, 36, 40] {
            let mut bad = good.clone();
            bad[index] ^= 1;
            assert_eq!(reflector().reflect(&bad), Reflection::Drop, "{index}");
        }
        for len in 20..40 {
            assert_eq!(reflector().reflect(&good[..len]), Reflection::Drop);
        }
        let udp = build_udp(
            "198.18.0.1:50000".parse().unwrap(),
            "10.7.0.1:8080".parse().unwrap(),
            b"x",
        )
        .unwrap();
        assert_eq!(reflector().reflect(&udp), Reflection::Drop);
        let mut other = good.clone();
        other[19] = 3;
        assert_eq!(reflector().reflect(&other), Reflection::Pass);
        let v6 = build_tcp(
            "[fd00::1]:1".parse().unwrap(),
            "[2001:db8::1]:80".parse().unwrap(),
            0,
            0,
            2,
            100,
            b"",
        )
        .unwrap();
        assert_eq!(reflector().reflect(&v6), Reflection::Pass);
        assert_eq!(Loopback::default().reflect(&good), Reflection::Pass);
    }
}
