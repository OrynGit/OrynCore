//! 出站套接字绑定的物理接口（macOS TUN 模式，见 docs/plan-macos.md）。
//!
//! TUN 模式把默认路由指向 utun，Core 自己的出站连接若按路由表走就会回到 utun 形成回环。
//! 平台层把物理接口告诉 Core 后，所有直连套接字都用 `IP_BOUND_IF` / `IPV6_BOUND_IF` 绑到该接口。
//! 未设置（iOS 与 macOS 系统代理模式）时这里的函数与普通的 bind / connect 相同。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::protect;

static BOUND_INTERFACE: AtomicU32 = AtomicU32::new(0);

/// 设置出站绑定的接口；`None`、空名或找不到的接口表示不绑定。返回实际生效的接口序号（0 为不绑定）。
pub fn set_bound_interface(name: Option<&str>) -> u32 {
    let index = name
        .filter(|n| !n.is_empty())
        .and_then(|n| std::ffi::CString::new(n).ok())
        // SAFETY: 参数是以 NUL 结尾的有效 C 字符串。
        .map(|n| unsafe { libc::if_nametoindex(n.as_ptr()) })
        .unwrap_or(0);
    BOUND_INTERFACE.store(index, Ordering::Relaxed);
    index
}

pub fn bound_interface() -> u32 {
    BOUND_INTERFACE.load(Ordering::Relaxed)
}

/// 把套接字绑定到当前设置的接口；未设置时什么也不做。
pub fn bind_to_interface(fd: RawFd, ipv6: bool) -> io::Result<()> {
    let index = bound_interface();
    if index == 0 {
        return Ok(());
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let (level, name) = if ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
        } else {
            (libc::IPPROTO_IP, libc::IP_BOUND_IF)
        };
        let value = index as libc::c_int;
        // SAFETY: fd 是调用方持有的有效套接字，值是 c_int，长度匹配。
        let status = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let _ = (fd, ipv6);
    Ok(())
}

fn unspecified(v6: bool) -> SocketAddr {
    if v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }
}

/// 绑定到任意本地地址的 std UDP 套接字（阻塞模式，与 `std::net::UdpSocket::bind` 相同），并绑定接口。
pub fn bind_std_udp(v6: bool) -> io::Result<std::net::UdpSocket> {
    use std::os::fd::AsRawFd;
    let socket = std::net::UdpSocket::bind(unspecified(v6))?;
    protect::protect_fd(socket.as_raw_fd())?;
    bind_to_interface(socket.as_raw_fd(), v6)?;
    Ok(socket)
}

/// 绑定到任意本地地址的 tokio UDP 套接字，并绑定接口。
pub async fn bind_udp(v6: bool) -> io::Result<tokio::net::UdpSocket> {
    use std::os::fd::AsRawFd;
    let socket = tokio::net::UdpSocket::bind(unspecified(v6)).await?;
    protect::protect_fd(socket.as_raw_fd())?;
    bind_to_interface(socket.as_raw_fd(), v6)?;
    Ok(socket)
}

/// 连接 TCP，连接前绑定接口。
pub async fn connect_tcp(addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    use std::os::fd::AsRawFd;
    let socket = if addr.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    protect::protect_fd(socket.as_raw_fd())?;
    bind_to_interface(socket.as_raw_fd(), addr.is_ipv6())?;
    socket.connect(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_to_loopback_and_resets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert_ne!(set_bound_interface(Some("lo0")), 0);
        let stream = connect_tcp(addr).await.unwrap();
        assert!(stream.peer_addr().is_ok());
        let udp = bind_udp(false).await.unwrap();
        udp.connect(addr).await.unwrap();
        assert_eq!(set_bound_interface(Some("no-such-interface0")), 0);
        assert_eq!(set_bound_interface(None), 0);
        assert_eq!(bound_interface(), 0);
    }
}
