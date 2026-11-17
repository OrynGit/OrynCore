//! 数据报通道抽象。
//!
//! QUIC（Hysteria2 / TUIC / V2Ray QUIC）与 WireGuard 不直接创建 UDP 套接字，而是向
//! [`DatagramFactory`] 要一个到指定对端的通道：直连时是普通 UDP 套接字；配置了 `dialer-proxy`
//! 时是另一个出站的 UDP（由 `oryn-outbound` 提供实现）。协议层因此不需要知道链路是否经过代理。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

pub mod iface;
mod protect;

pub use protect::{protect_fd, set_socket_protect_callback, SocketProtectFn};

/// 一个到固定对端的数据报通道。
#[async_trait]
pub trait Datagrams: Send + Sync {
    /// 非阻塞发送。缓冲或队列满时丢弃，由上层协议重传。
    fn try_send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<()>;
    /// 等待下一个数据报。取消安全：被取消不丢数据报。
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    /// 不等待地取下一个已到达的数据报（没有就返回 `None`）。接收任务在 `recv_from` 返回后
    /// 用它把积压的包一次取完，省掉每个包一次的任务唤醒。默认不支持。
    fn try_recv_from(&self, _buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        Ok(None)
    }
    /// 让发出的数据报带「不分片」标志，返回是否设置成功。QUIC 的路径 MTU 探测靠它：
    /// 超过路径 MTU 的探测包被丢弃或在本机报错，而不是被悄悄分片。默认不支持。
    fn set_dont_fragment(&self) -> bool {
        false
    }
}

#[async_trait]
pub trait DatagramFactory: Send + Sync {
    /// 创建到 `peer` 的通道。`peer` 的地址族决定本端套接字的地址族。
    async fn bind(&self, peer: SocketAddr) -> io::Result<Arc<dyn Datagrams>>;
}

/// 直连：普通 UDP 套接字。
#[derive(Default, Clone, Copy)]
pub struct UdpFactory;

/// UDP 接收缓冲：系统缺省（macOS 约 256 KiB 接收）装不下对端一个 tick 的突发（mKCP 服务端每 50 ms 可以发出
/// 窗口的 20 倍），内核直接丢包，上层只看到「少了很多包」。这是内核缓冲，不计入进程内存预算；设置失败就保持缺省。
const SOCKET_BUFFER: libc::c_int = 2 * 1024 * 1024;
fn set_buffers(socket: &std::net::UdpSocket) {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    // 只放大接收缓冲：发送缓冲保持缺省，突发发送由内核截断（UDP 语义，上层重传 / 拥塞控制），
    // 放大后 mKCP 这类没有拥塞控制的发送端会一口气发满窗口，把对端的接收缓冲冲掉（上传反而变慢）。
    for name in [libc::SO_RCVBUF] {
        // SAFETY: fd 是有效的套接字，值是 c_int，长度匹配。
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                name,
                &SOCKET_BUFFER as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

/// 同一个套接字的两个句柄：tokio 句柄只用来等可读；发送用非阻塞的 std 句柄。
/// tokio 的 `try_send_to` 在反应器第一次报告可写之前总是 WouldBlock，会吞掉新套接字上的首个包。
struct UdpDatagrams {
    recv: tokio::net::UdpSocket,
    send: std::net::UdpSocket,
}

#[async_trait]
impl DatagramFactory for UdpFactory {
    async fn bind(&self, peer: SocketAddr) -> io::Result<Arc<dyn Datagrams>> {
        let socket = iface::bind_std_udp(peer.is_ipv6())?;
        socket.set_nonblocking(true)?;
        set_buffers(&socket);
        let send = socket.try_clone()?;
        Ok(Arc::new(UdpDatagrams {
            recv: tokio::net::UdpSocket::from_std(socket)?,
            send,
        }))
    }
}

#[async_trait]
impl Datagrams for UdpDatagrams {
    fn try_send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<()> {
        match self.send.send_to(buf, peer) {
            Ok(_) => Ok(()),
            // 发送缓冲满（EWOULDBLOCK），或接口队列满（ENOBUFS：Darwin 55、Linux 105）：UDP 语义，丢弃。
            // 突发时 macOS 的小 UDP 发送缓冲会返回 ENOBUFS，不能把它当成通道失效。
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(err) if matches!(err.raw_os_error(), Some(55) | Some(105)) => Ok(()),
            Err(err) => Err(err),
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv.recv_from(buf).await
    }

    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        match self.recv.try_recv_from(buf) {
            Ok(received) => Ok(Some(received)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn set_dont_fragment(&self) -> bool {
        use std::os::fd::AsRawFd;
        let fd = self.send.as_raw_fd();
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let on: libc::c_int = 1;
        let ipv6 = matches!(self.send.local_addr(), Ok(addr) if addr.is_ipv6());
        let set = |level: libc::c_int, name: libc::c_int, value: libc::c_int| unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) == 0
        };
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            // IP_DONTFRAG = 28、IPV6_DONTFRAG = 62（Darwin）
            if ipv6 {
                set(libc::IPPROTO_IPV6, 62, on)
            } else {
                set(libc::IPPROTO_IP, 28, on)
            }
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // IP_MTU_DISCOVER / IPV6_MTU_DISCOVER = PMTUDISC_DO
            if ipv6 {
                set(
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    libc::IPV6_PMTUDISC_DO,
                )
            } else {
                set(
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    libc::IP_PMTUDISC_DO,
                )
            }
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "android"
        )))]
        {
            let _ = (set, on, ipv6);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_factory_roundtrip_both_families() {
        for loopback in ["127.0.0.1:0", "[::1]:0"] {
            let server = tokio::net::UdpSocket::bind(loopback).await.unwrap();
            let addr = server.local_addr().unwrap();
            let channel = UdpFactory.bind(addr).await.unwrap();
            channel.try_send_to(b"ping", addr).unwrap();
            let mut buf = [0; 16];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            server.send_to(b"pong", from).await.unwrap();
            let (n, from) = channel.recv_from(&mut buf).await.unwrap();
            assert_eq!((&buf[..n], from), (b"pong".as_slice(), addr));
        }
    }
}
