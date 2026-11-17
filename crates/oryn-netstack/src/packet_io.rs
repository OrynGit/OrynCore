use std::io;
use std::os::fd::{AsRawFd, RawFd};

use crate::IpVersion;

/// 平台包 I/O 的最小接口。
///
/// Apple utun 帧包含 address-family 头；Android `VpnService` TUN 只包含纯 IP 包。
/// 事件循环只依赖这个接口，不在 Kotlin 层逐包转发。
pub trait PacketIo: AsRawFd + Sized {
    fn from_borrowed_fd(fd: RawFd) -> io::Result<Self>;
    fn try_clone(&self) -> io::Result<Self>;
    fn recv_packet(&mut self, packet: &mut Vec<u8>) -> io::Result<IpVersion>;
    fn send_packet(&self, version: IpVersion, packet: &[u8]) -> io::Result<()>;
}
