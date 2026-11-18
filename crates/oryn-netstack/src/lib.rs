//! Oryn Netstack：IP 包 ↔ TCP 流 / UDP 数据报。
//!
//! Packet 只存在于本层以下；本层以上只看到 [`NetStack::TcpStream`] 与 [`UdpDatagram`]。
//! V1 的实现是 lwIP（[`LwipStack`]），以后可以替换为其它后端而不影响上层。

pub mod android_tun;
pub mod loopback;
mod lwip;
pub mod packet;
mod packet_io;
mod stack;
pub mod system_nat;
mod tcp;
pub mod utun;

pub use android_tun::AndroidTunPacketIo;
/// Linux `/dev/net/tun`（`IFF_TUN | IFF_NO_PI`）每次读写也是一个纯 IP 包，与 Android 共用实现。
pub type LinuxTunPacketIo = AndroidTunPacketIo;
pub use packet_io::PacketIo;
pub use utun::{IpVersion, UtunPacketIo};

use std::net::SocketAddr;
use std::time::Duration;

pub use stack::LwipStack;
pub use tcp::LwipTcpStream;

/// 来自隧道的 UDP 数据报。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// 用户态协议栈接口。只能在创建它的线程上使用。
pub trait NetStack {
    type TcpStream;

    /// 输入一个来自隧道的 IP 包。
    fn input_packet(&self, packet: &[u8]);
    /// 取出一个新建立的 TCP 连接。
    fn poll_tcp(&self) -> Option<Self::TcpStream>;
    /// 取出一个 UDP 数据报。
    fn poll_udp(&self) -> Option<UdpDatagram>;
    /// 构造 UDP 包写回隧道（`src` 为远端，`dst` 为应用）。
    fn send_udp(&self, src: SocketAddr, dst: SocketAddr, payload: &[u8]);
    /// 取出待写回隧道的 IP 包。
    fn take_output(&self) -> Vec<Vec<u8>>;
    /// 驱动内部定时器，返回距离下次需要调用的时间。
    fn poll_timers(&self) -> Duration;
}
