//! 桌面独立核心 `oryn` 的平台宿主层。
//!
//! 负责 TUN 创建、地址 / 路由设置与还原、默认接口监测；只被 `oryn-cli` 依赖，数据面 crate
//! 不依赖它。Packet 的读写仍在 `oryn-netstack` / `oryn-core` 的包 I/O 后端里。
//! 方案见 Oryn_dev/docs/oryncore/plans/plan-desktop-tun-bare-core.md。
//!
//! 已实现 Linux（第 2 期）与 macOS（第 3 期）；其他平台返回「不支持」。

use std::io;

use oryn_config::desktop::DesktopSettings;

pub mod nlmsg;
pub mod pfroute;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::{default_interface, InterfaceMonitor, Tunnel};
#[cfg(target_os = "macos")]
pub use macos::{default_interface, InterfaceMonitor, Tunnel};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported {
    use super::*;
    use oryn_config::desktop::TunSettings;

    /// 非 Linux 平台尚无 TUN 实现。
    pub struct Tunnel(());

    impl Tunnel {
        pub fn open(_: &TunSettings, _: Option<u32>, _: &std::path::Path) -> io::Result<Tunnel> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN mode is not supported on this platform yet (Linux and macOS only)",
            ))
        }
        pub fn raw_fd(&self) -> std::os::fd::RawFd {
            -1
        }
        pub fn name(&self) -> &str {
            ""
        }
        pub fn index(&self) -> u32 {
            0
        }
    }

    pub struct InterfaceMonitor(());

    impl InterfaceMonitor {
        pub fn start(_: Option<u32>) -> io::Result<InterfaceMonitor> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "auto-detect-interface is not supported on this platform yet (Linux and macOS only)",
            ))
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use unsupported::{InterfaceMonitor, Tunnel};

/// 出站防回环的宿主侧状态：路由标记与接口绑定。Drop 时停止接口监测。
pub struct OutboundGuard {
    _monitor: Option<InterfaceMonitor>,
}

/// 按宿主设置配置直连套接字：`routing-mark` → `SO_MARK`，`interface-name` 固定绑定，
/// 否则 `tun.auto-detect-interface` 时监测默认接口。`tun_index` 为隧道自身的接口序号。
pub fn protect_outbound(settings: &DesktopSettings, tun_index: Option<u32>) -> io::Result<OutboundGuard> {
    if let Some(mark) = settings.effective_routing_mark() {
        if cfg!(target_os = "linux") {
            oryn_udp::iface::set_routing_mark(mark);
            log::info!("outbound sockets use routing mark {mark}");
        } else if settings.routing_mark.is_some() {
            log::warn!("routing-mark is only supported on Linux and was ignored");
        }
    }
    if let Some(name) = &settings.interface_name {
        let index = oryn_udp::iface::set_bound_interface(Some(name));
        if index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface-name: interface {name} not found"),
            ));
        }
        log::info!("outbound sockets bound to {name} (index {index})");
        return Ok(OutboundGuard { _monitor: None });
    }
    // macOS 没有策略路由，auto-route 时直连套接字必须绑物理接口才不会回到 utun
    let auto_detect = settings
        .tun
        .as_ref()
        .is_some_and(|t| t.auto_detect_interface || (cfg!(target_os = "macos") && t.auto_route));
    let monitor = if auto_detect { Some(InterfaceMonitor::start(tun_index)?) } else { None };
    Ok(OutboundGuard { _monitor: monitor })
}
