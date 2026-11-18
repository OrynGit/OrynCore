//! 出站套接字的防回环设置：绑定物理接口与路由标记。
//!
//! TUN 模式把默认路由指向隧道，Core 自己的出站连接若按路由表走就会回到隧道形成回环。
//! 宿主把物理接口告诉 Core 后，所有直连套接字都绑到该接口：macOS 用 `IP_BOUND_IF` /
//! `IPV6_BOUND_IF`（见 Oryn_dev/docs/apple/plans/plan-macos.md），Linux 用 `SO_BINDTOIFINDEX`
//! （旧内核退回 `SO_BINDTODEVICE`）。Linux 桌面核心另可设置 `SO_MARK`，配合 `ip rule`
//! 让出站绕过隧道（见 Oryn_dev/docs/oryncore/plans/plan-desktop-tun-bare-core.md）。
//! 都未设置（iOS、Android 与系统代理模式）时这里的函数与普通的 bind / connect 相同。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::protect;

static BOUND_INTERFACE: AtomicU32 = AtomicU32::new(0);
/// 出站套接字的 `SO_MARK`（仅 Linux），0 表示不设置。
static ROUTING_MARK: AtomicU32 = AtomicU32::new(0);

/// 设置出站套接字的路由标记（Linux `SO_MARK`，需要 `CAP_NET_ADMIN`）；0 表示不设置。
/// 其他平台忽略。
pub fn set_routing_mark(mark: u32) {
    ROUTING_MARK.store(mark, Ordering::Relaxed);
}

pub fn routing_mark() -> u32 {
    ROUTING_MARK.load(Ordering::Relaxed)
}

/// 直接设置出站绑定的接口序号（0 为不绑定）；供宿主在默认接口变化时更新。
pub fn set_bound_interface_index(index: u32) {
    BOUND_INTERFACE.store(index, Ordering::Relaxed);
}

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

fn setsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
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
    Ok(())
}

/// 为出站套接字设置路由标记并绑定接口；都未设置时什么也不做。
pub fn bind_to_interface(fd: RawFd, ipv6: bool) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mark = routing_mark();
        if mark != 0 {
            setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_MARK, mark as libc::c_int)?;
        }
    }
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
        setsockopt_int(fd, level, name, index as libc::c_int)?;
    }
    #[cfg(target_os = "linux")]
    {
        let _ = ipv6;
        bind_linux(fd, index)?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
    let _ = (fd, ipv6, setsockopt_int);
    Ok(())
}

/// Linux 5.7+ 的 `SO_BINDTOIFINDEX` 直接取接口序号；旧内核不认识时按名字 `SO_BINDTODEVICE`。
#[cfg(target_os = "linux")]
fn bind_linux(fd: RawFd, index: u32) -> io::Result<()> {
    const SO_BINDTOIFINDEX: libc::c_int = 62;
    match setsockopt_int(fd, libc::SOL_SOCKET, SO_BINDTOIFINDEX, index as libc::c_int) {
        Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => {}
        other => return other,
    }
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: 缓冲区长度为 IF_NAMESIZE，满足 if_indextoname 的要求。
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: if_indextoname 成功时写入了以 NUL 结尾的名字。
    let len = unsafe { libc::strlen(name.as_ptr()) };
    // SAFETY: 名字缓冲有效，长度不含结尾 NUL。
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const libc::c_void,
            len as libc::socklen_t,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
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
        let lo = if cfg!(target_os = "linux") { "lo" } else { "lo0" };
        assert_ne!(set_bound_interface(Some(lo)), 0);
        let stream = connect_tcp(addr).await.unwrap();
        assert!(stream.peer_addr().is_ok());
        let udp = bind_udp(false).await.unwrap();
        udp.connect(addr).await.unwrap();
        assert_eq!(set_bound_interface(Some("no-such-interface0")), 0);
        assert_eq!(set_bound_interface(None), 0);
        assert_eq!(bound_interface(), 0);
    }
}
