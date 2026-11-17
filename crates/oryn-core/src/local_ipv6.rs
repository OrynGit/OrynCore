//! 本机（物理网络）IPv6 可用性判定。不可用时：本机拨号用的解析不查 AAAA，Netstack 在握手前拒绝
//! 发往全局 IPv6 的新连接，应用立即失败并回退 IPv4（见 docs/plan-ipv6-settings.md 末节）。

use std::cell::Cell;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use log::info;

use crate::context::EngineCtx;

/// 连续多少次「本机无路由」式的全局 IPv6 连接失败后判为不可用。
const FAILURE_THRESHOLD: u8 = 3;
/// 本机无路由在发出任何包之前就失败；远端返回的不可达至少要一个往返。
const LOCAL_FAILURE_WITHIN: Duration = Duration::from_millis(20);

pub struct LocalIpv6 {
    /// `None` 表示尚未判定。
    available: Cell<Option<bool>>,
    failures: Cell<u8>,
}

impl Default for LocalIpv6 {
    fn default() -> Self {
        Self {
            available: Cell::new(None),
            failures: Cell::new(0),
        }
    }
}

pub fn is_global_ipv6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.octets()[0] & 0xE0 == 0x20)
}

impl LocalIpv6 {
    /// 网络变化：清零失败计数后重新判定。
    pub fn network_changed(&self, ctx: &EngineCtx) {
        self.failures.set(0);
        self.refresh(ctx);
    }

    /// 重新判定，结果变化时同步到 DNS 与 Netstack 并记录原因。
    pub fn refresh(&self, ctx: &EngineCtx) {
        let reason = if ctx.dns.network().ipv6 == Some(false) {
            Some("the system reports no IPv6 on the physical network")
        } else if !probe_route() {
            Some("no local IPv6 route")
        } else if self.failures.get() >= FAILURE_THRESHOLD {
            Some("IPv6 connections fail with no route to host")
        } else {
            None
        };
        let available = reason.is_none();
        ctx.dns.set_local_ipv6(available);
        ctx.stack.set_reject_global_ipv6(!available);
        if self.available.replace(Some(available)) != Some(available) {
            match reason {
                Some(reason) => info!(
                    "local IPv6 unavailable ({reason}): rejecting global IPv6 connections before handshake"
                ),
                None => info!("local IPv6 available"),
            }
        }
    }

    pub fn connect_failed(
        &self,
        ctx: &EngineCtx,
        destination: IpAddr,
        error: &io::Error,
        elapsed: Duration,
    ) {
        let no_route = matches!(
            error.raw_os_error(),
            Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH)
        );
        if !is_global_ipv6(destination) || !no_route || elapsed > LOCAL_FAILURE_WITHIN {
            return;
        }
        let failures = self.failures.get().saturating_add(1);
        self.failures.set(failures);
        if failures == FAILURE_THRESHOLD {
            self.refresh(ctx);
        }
    }

    pub fn connected(&self, destination: IpAddr) {
        if is_global_ipv6(destination) {
            self.failures.set(0);
        }
    }
}

/// 只查本机路由表、不发包：IPv6 UDP 套接字 `connect` 一个全局地址。
/// PacketTunnel 自身的套接字不走自己的隧道，因此反映物理网络。只在 iOS 上探测，
/// 其他平台（开发机测试）视为可用，由 `network.ipv6` 显式控制。
#[cfg(target_os = "ios")]
fn probe_route() -> bool {
    std::net::UdpSocket::bind("[::]:0")
        .and_then(|s| s.connect("[2001:4860:4860::8888]:53"))
        .is_ok()
}

#[cfg(not(target_os = "ios"))]
fn probe_route() -> bool {
    true
}
