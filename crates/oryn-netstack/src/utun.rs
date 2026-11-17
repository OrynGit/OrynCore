//! utun 包 I/O 适配层原型。
//!
//! 这个模块只处理当前描述符上的帧收发，不读取 VPN 配置、不做路由决策，
//! 也不负责从 `NEPacketTunnelFlow` 获取描述符。调用方必须在启动前完成
//! provider 归属验证，并保证同一描述符只有一个 reader。

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, RawFd};

use crate::packet_io::PacketIo;

const AF_HEADER_LEN: usize = 4;
const MAX_IP_PACKET: usize = 65_535 + 40;
const MAX_FRAME: usize = AF_HEADER_LEN + MAX_IP_PACKET;

/// utun 帧中的网络层版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    fn af_number(self) -> u32 {
        match self {
            Self::V4 => libc::AF_INET as u32,
            Self::V6 => libc::AF_INET6 as u32,
        }
    }

    fn from_af_number(af: u32) -> Option<Self> {
        match af as libc::c_int {
            libc::AF_INET => Some(Self::V4),
            libc::AF_INET6 => Some(Self::V6),
            _ => None,
        }
    }
}

/// 帧头或 IP 负载不符合 utun 约定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    UnsupportedAddressFamily,
    AddressFamilyMismatch,
    EmptyPacket,
    InvalidLength,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooShort => "utun frame is shorter than its address-family header",
            Self::UnsupportedAddressFamily => "utun frame has an unsupported address family",
            Self::AddressFamilyMismatch => "utun address family does not match the IP packet",
            Self::EmptyPacket => "utun frame has an empty IP packet",
            Self::InvalidLength => "invalid IP packet length",
        })
    }
}

impl std::error::Error for FrameError {}

fn validate_packet(version: IpVersion, packet: &[u8]) -> Result<(), FrameError> {
    let actual = match packet.first().map(|b| b >> 4) {
        Some(4) => IpVersion::V4,
        Some(6) => IpVersion::V6,
        _ => return Err(FrameError::EmptyPacket),
    };
    if actual != version {
        return Err(FrameError::AddressFamilyMismatch);
    }
    match version {
        IpVersion::V4 if packet.len() >= 20 => {
            let header = (packet[0] as usize & 15) * 4;
            let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if header >= 20 && header <= total && total == packet.len() {
                return Ok(());
            }
        }
        IpVersion::V6 if packet.len() >= 40 => {
            let payload = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if 40 + payload == packet.len() {
                return Ok(());
            }
        }
        _ => {}
    }
    Err(FrameError::InvalidLength)
}

/// 解析 4 字节网络序 address-family 头，不复制负载。
pub fn decode_frame(frame: &[u8]) -> Result<(IpVersion, &[u8]), FrameError> {
    if frame.len() < AF_HEADER_LEN {
        return Err(FrameError::TooShort);
    }
    let af = u32::from_be_bytes(frame[..AF_HEADER_LEN].try_into().unwrap());
    let version = IpVersion::from_af_number(af).ok_or(FrameError::UnsupportedAddressFamily)?;
    let packet = &frame[AF_HEADER_LEN..];
    let packet_version = match packet.first().map(|b| b >> 4) {
        Some(4) => IpVersion::V4,
        Some(6) => IpVersion::V6,
        _ => return Err(FrameError::EmptyPacket),
    };
    if packet_version != version {
        return Err(FrameError::AddressFamilyMismatch);
    }
    validate_packet(version, packet)?;
    Ok((version, packet))
}

/// 在调用方提供的缓冲中构造一帧；用于测试和不支持 `sendmsg` 的回退路径。
pub fn encode_frame(
    version: IpVersion,
    packet: &[u8],
    frame: &mut Vec<u8>,
) -> Result<(), FrameError> {
    if packet.is_empty() {
        return Err(FrameError::EmptyPacket);
    }
    let packet_version = match packet[0] >> 4 {
        4 => IpVersion::V4,
        6 => IpVersion::V6,
        _ => return Err(FrameError::EmptyPacket),
    };
    if packet_version != version {
        return Err(FrameError::AddressFamilyMismatch);
    }
    validate_packet(version, packet)?;
    frame.clear();
    frame.reserve(AF_HEADER_LEN + packet.len());
    frame.extend_from_slice(&version.af_number().to_be_bytes());
    frame.extend_from_slice(packet);
    Ok(())
}

/// 因内核 utun 发送缓冲已满（`ENOBUFS`）而丢弃的包累计数，随 `stats` 输出（诊断连接风暴下的握手停滞）。
pub static BUFFER_FULL_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 内核 utun 发送缓冲已满（`ENOBUFS`）。调用方应丢弃该包而不是终止数据面。
pub fn is_buffer_full(error: &io::Error) -> bool {
    let full = error.raw_os_error() == Some(libc::ENOBUFS);
    if full {
        BUFFER_FULL_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    full
}

/// 已取得的 utun 描述符。
///
/// `from_owned_fd` 接管描述符；`try_clone` 使用 `dup` 创建由返回值独占的
/// 副本。dup 仍共享底层 file-status flags，所以本模块不修改 `O_NONBLOCK`，
/// 每次 syscall 都使用 `MSG_DONTWAIT`。
pub struct UtunPacketIo {
    fd: RawFd,
    owns_fd: bool,
    frame: Vec<u8>,
}

impl UtunPacketIo {
    /// 接管一个已由调用方验证归属的描述符。
    ///
    /// # Safety
    /// `fd` 必须是仍然有效的 utun datagram 描述符，且调用方不能再并发读取或关闭它。
    pub unsafe fn from_owned_fd(fd: RawFd) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid utun fd",
            ));
        }
        Ok(Self {
            fd,
            owns_fd: true,
            frame: vec![0; MAX_FRAME],
        })
    }

    /// 只借用描述符，不在 Drop 时关闭；适合 provider 仍拥有原始句柄的过渡验证。
    ///
    /// # Safety
    /// `fd` 必须在此对象整个生命周期内有效，且调用方保证不并发消费同一 fd。
    pub unsafe fn from_borrowed_fd(fd: RawFd) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid utun fd",
            ));
        }
        Ok(Self {
            fd,
            owns_fd: false,
            frame: vec![0; MAX_FRAME],
        })
    }

    /// 为本对象创建一个独占的 fd 副本；原 fd 的 flags 不会被本模块修改。
    pub fn try_clone(&self) -> io::Result<Self> {
        let fd = unsafe { libc::dup(self.fd) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: dup 返回当前进程拥有的有效描述符。
        unsafe { Self::from_owned_fd(fd) }
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// 非阻塞读取一个完整 utun 帧。EAGAIN 返回 `WouldBlock`，不消费调用方缓冲。
    pub fn recv_packet(&mut self, packet: &mut Vec<u8>) -> io::Result<IpVersion> {
        let mut iov = libc::iovec {
            iov_base: self.frame.as_mut_ptr().cast(),
            iov_len: self.frame.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let n = unsafe { libc::recvmsg(self.fd, &mut msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated utun frame",
            ));
        }
        let (version, payload) = decode_frame(&self.frame[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        packet.clear();
        packet.extend_from_slice(payload);
        Ok(version)
    }

    /// 用 `sendmsg` 分两段发送 header 与 IP payload，避免先拼接一个新 Vec。
    pub fn send_packet(&self, version: IpVersion, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                FrameError::EmptyPacket,
            ));
        }
        let packet_version = match packet[0] >> 4 {
            4 => IpVersion::V4,
            6 => IpVersion::V6,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    FrameError::EmptyPacket,
                ))
            }
        };
        if packet_version != version {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                FrameError::AddressFamilyMismatch,
            ));
        }
        validate_packet(version, packet)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let header = version.af_number().to_be_bytes();
        let mut iov = [
            libc::iovec {
                iov_base: header.as_ptr().cast_mut().cast(),
                iov_len: header.len(),
            },
            libc::iovec {
                iov_base: packet.as_ptr().cast_mut().cast(),
                iov_len: packet.len(),
            },
        ];
        let mut msg: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len() as _;
        let expected = header.len() + packet.len();
        let n = unsafe { libc::sendmsg(self.fd, &msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != expected {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short utun frame write",
            ));
        }
        Ok(())
    }
}

impl PacketIo for UtunPacketIo {
    fn from_borrowed_fd(fd: RawFd) -> io::Result<Self> {
        // SAFETY: forwarded constructor contract is identical.
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

impl AsRawFd for UtunPacketIo {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for UtunPacketIo {
    fn drop(&mut self) {
        if self.owns_fd {
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn frame_round_trip() {
        let mut packet = [0; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        let mut frame = Vec::new();
        encode_frame(IpVersion::V4, &packet, &mut frame).unwrap();
        let (version, payload) = decode_frame(&frame).unwrap();
        assert_eq!(version, IpVersion::V4);
        assert_eq!(payload, packet);
        assert_eq!(decode_frame(&[0, 0, 0]), Err(FrameError::TooShort));
        assert_eq!(
            decode_frame(&[0, 0, 0, 2, 0x60]),
            Err(FrameError::AddressFamilyMismatch)
        );
    }

    #[cfg(unix)]
    #[test]
    fn socketpair_uses_nonblocking_calls_and_owned_duplicate() {
        let mut fds = [0; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // 适配器接管一个端点；对端在测试结尾关闭。
        let mut io = unsafe { UtunPacketIo::from_owned_fd(fds[0]) }.unwrap();
        let mut packet = [0; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        let mut frame = Vec::new();
        encode_frame(IpVersion::V4, &packet, &mut frame).unwrap();
        let sent = unsafe { libc::send(fds[1], frame.as_ptr().cast(), frame.len(), 0) };
        assert_eq!(sent as usize, frame.len());
        let flags = unsafe { libc::fcntl(io.raw_fd(), libc::F_GETFL) };
        let cloned = io.try_clone().unwrap();
        drop(cloned);
        assert_eq!(flags, unsafe { libc::fcntl(io.raw_fd(), libc::F_GETFL) });
        let mut received = Vec::new();
        assert_eq!(io.recv_packet(&mut received).unwrap(), IpVersion::V4);
        assert_eq!(received, packet);
        assert_eq!(
            io.recv_packet(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        io.send_packet(IpVersion::V4, &packet).unwrap();
        let mut raw = [MaybeUninit::<u8>::uninit(); MAX_FRAME];
        let n = unsafe { libc::recv(fds[1], raw.as_mut_ptr().cast(), raw.len(), 0) };
        assert_eq!(n as usize, frame.len());
        let raw = unsafe { std::slice::from_raw_parts(raw.as_ptr().cast::<u8>(), n as usize) };
        assert_eq!(decode_frame(raw).unwrap().1, packet);
        unsafe { libc::close(fds[1]) };
    }
}
