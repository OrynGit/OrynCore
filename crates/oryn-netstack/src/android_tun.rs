//! Android `VpnService` 的普通 TUN packet I/O。
//!
//! Android TUN fd 的每次读写都是一个纯 IPv4/IPv6 packet，不带 Apple utun 的
//! 4 字节 address-family 头。本模块不负责 VPN 授权、socket protect 或 JNI。

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use crate::packet_io::PacketIo;
use crate::utun::IpVersion;

const MAX_IP_PACKET: usize = 65_535 + 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketError {
    Empty,
    InvalidLength,
    UnsupportedVersion,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "TUN packet is empty",
            Self::InvalidLength => "invalid IP packet length",
            Self::UnsupportedVersion => "unsupported IP version",
        })
    }
}

impl std::error::Error for PacketError {}

fn validate(packet: &[u8]) -> Result<IpVersion, PacketError> {
    let version = match packet.first().map(|byte| byte >> 4) {
        Some(4) => IpVersion::V4,
        Some(6) => IpVersion::V6,
        Some(_) => return Err(PacketError::UnsupportedVersion),
        None => return Err(PacketError::Empty),
    };
    match version {
        IpVersion::V4 if packet.len() >= 20 => {
            let header = (packet[0] as usize & 0x0f) * 4;
            let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if header >= 20 && header <= total && total == packet.len() {
                Ok(version)
            } else {
                Err(PacketError::InvalidLength)
            }
        }
        IpVersion::V6 if packet.len() >= 40 => {
            let payload = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if 40 + payload == packet.len() {
                Ok(version)
            } else {
                Err(PacketError::InvalidLength)
            }
        }
        _ => Err(PacketError::InvalidLength),
    }
}

pub struct AndroidTunPacketIo {
    fd: RawFd,
    owns_fd: bool,
    packet: Vec<u8>,
}

impl AndroidTunPacketIo {
    /// 借用平台层持有的 fd；为事件循环设置非阻塞读写，不在 Drop 时关闭它。
    ///
    /// # Safety
    /// `fd` 必须在对象生命周期内有效，且不能被其他读写者并发消费。
    pub unsafe fn from_borrowed_fd(fd: RawFd) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN fd",
            ));
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            owns_fd: false,
            packet: vec![0; MAX_IP_PACKET],
        })
    }

    fn from_owned_fd(fd: RawFd) -> io::Result<Self> {
        // SAFETY: fd is a valid descriptor returned by dup and is owned here.
        let mut io = unsafe { Self::from_borrowed_fd(fd) }?;
        io.owns_fd = true;
        Ok(io)
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        let fd = unsafe { libc::dup(self.fd) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::from_owned_fd(fd)
    }

    pub fn recv_packet(&mut self, packet: &mut Vec<u8>) -> io::Result<IpVersion> {
        let n = unsafe { libc::read(self.fd, self.packet.as_mut_ptr().cast(), self.packet.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let source = &self.packet[..n as usize];
        let version =
            validate(source).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        packet.clear();
        packet.extend_from_slice(source);
        Ok(version)
    }

    pub fn send_packet(&self, version: IpVersion, packet: &[u8]) -> io::Result<()> {
        if validate(packet).ok() != Some(version) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid IP packet",
            ));
        }
        let n = unsafe { libc::write(self.fd, packet.as_ptr().cast(), packet.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short TUN packet write",
            ));
        }
        Ok(())
    }
}

impl PacketIo for AndroidTunPacketIo {
    fn from_borrowed_fd(fd: RawFd) -> io::Result<Self> {
        // SAFETY: same contract as the public constructor.
        unsafe { Self::from_borrowed_fd(fd) }
    }

    fn try_clone(&self) -> io::Result<Self> {
        Self::try_clone(self)
    }

    fn recv_packet(&mut self, packet: &mut Vec<u8>) -> io::Result<IpVersion> {
        Self::recv_packet(self, packet)
    }

    fn send_packet(&self, version: IpVersion, packet: &[u8]) -> io::Result<()> {
        Self::send_packet(self, version, packet)
    }
}

impl AsRawFd for AndroidTunPacketIo {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for AndroidTunPacketIo {
    fn drop(&mut self) {
        if self.owns_fd {
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4() -> [u8; 20] {
        let mut packet = [0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet
    }

    fn ipv6() -> [u8; 40] {
        let mut packet = [0; 40];
        packet[0] = 0x60;
        packet
    }

    #[test]
    fn validates_plain_ipv4_and_ipv6_packets() {
        assert_eq!(validate(&ipv4()), Ok(IpVersion::V4));
        assert_eq!(validate(&ipv6()), Ok(IpVersion::V6));
        assert_eq!(validate(&ipv4()[..19]), Err(PacketError::InvalidLength));
        assert_eq!(validate(&[0x45, 0, 0, 20]), Err(PacketError::InvalidLength));
        assert_eq!(validate(&[]), Err(PacketError::Empty));
        assert_eq!(validate(&[0x25; 20]), Err(PacketError::UnsupportedVersion));
    }

    #[cfg(unix)]
    #[test]
    fn socketpair_round_trip_uses_plain_packets() {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let mut io = unsafe { AndroidTunPacketIo::from_borrowed_fd(fds[0]) }.unwrap();
        let packet = ipv4();
        assert_eq!(
            unsafe { libc::write(fds[1], packet.as_ptr().cast(), packet.len()) },
            packet.len() as isize
        );
        let mut received = Vec::new();
        assert_eq!(io.recv_packet(&mut received).unwrap(), IpVersion::V4);
        assert_eq!(received, packet);
        io.send_packet(IpVersion::V4, &packet).unwrap();
        let mut raw = [0; 20];
        assert_eq!(
            unsafe { libc::read(fds[1], raw.as_mut_ptr().cast(), raw.len()) },
            packet.len() as isize
        );
        assert_eq!(raw, packet);
        unsafe { libc::close(fds[1]) };
    }
}
