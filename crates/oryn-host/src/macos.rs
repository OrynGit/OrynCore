//! macOS：utun 创建、地址 / MTU、`PF_ROUTE` 路由、DNS 路由与默认接口监测。
//!
//! 细节见 Oryn_dev/docs/oryncore/plans/plan-desktop-tun-bare-core.md「第 3 期实施细节」：
//! `auto-route` 用比默认路由更具体的接口路由（`0.0.0.0/1`、`128.0.0.0/1`），Core 的直连套接字
//! 用 `IP_BOUND_IF` 绑物理接口防回环；经网关的排除路由记录在状态文件中，退出与下次启动时删除。

use std::ffi::CString;
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use log::{info, warn};
use oryn_config::desktop::TunSettings;
use oryn_config::IpCidr;

use crate::pfroute::{self, Gateway, RTM_ADD, RTM_DELETE, RTM_GET};

const UTUN_CONTROL: &str = "com.apple.net.utun_control";
const UTUN_OPT_IFNAME: libc::c_int = 2;
const SIOCSIFMTU: libc::c_ulong = 0x8020_6934;
const SIOCAIFADDR: libc::c_ulong = 0x8040_691a;
const SIOCAIFADDR_IN6: libc::c_ulong = 0x8080_691a;
const IN6_IFF_NODAD: libc::c_int = 0x0020;
const ND6_INFINITE_LIFETIME: u32 = 0xffff_ffff;
/// 排除路由的状态文件（数据目录内）。
const STATE_FILE: &str = "oryn-routes.state";
const MAX_STATE_ROUTES: usize = 1024;

fn permission_hint(e: io::Error, what: &str) -> io::Error {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{what}: permission denied (TUN mode requires root on macOS)"),
        ),
        _ => io::Error::new(e.kind(), format!("{what}: {e}")),
    }
}

fn check(status: libc::c_int) -> io::Result<()> {
    if status < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// 建 utun：`device` 为 `utunN` 时取编号 N，否则由内核分配。返回描述符与实际名字。
fn create_utun(device: Option<&str>) -> io::Result<(OwnedFd, String)> {
    let unit = match device {
        None => 0,
        Some(name) => {
            let n = name
                .strip_prefix("utun")
                .and_then(|n| n.parse::<u32>().ok())
                .filter(|n| *n < 0xffff)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("tun.device on macOS must be utunN, got `{name}`")))?;
            n + 1
        }
    };
    // SAFETY: 普通 socket 调用，返回值检查后接管。
    let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    check(fd).map_err(|e| permission_hint(e, "open utun control socket"))?;
    // SAFETY: fd 刚由 socket 返回且有效。
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: ctl_info 全零是合法初值。
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL.bytes()) {
        *dst = src as libc::c_char;
    }
    // SAFETY: info 是有效的 ctl_info。
    check(unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) })
        .map_err(|e| permission_hint(e, "look up utun control"))?;
    // SAFETY: sockaddr_ctl 全零是合法初值。
    let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
    addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
    addr.sc_family = libc::AF_SYSTEM as u8;
    addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = unit;
    // SAFETY: addr 有效，长度匹配。
    let status = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if status < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EBUSY) {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("{} is in use", device.unwrap_or("utun"))));
        }
        return Err(permission_hint(e, "create utun"));
    }
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut len = name.len() as libc::socklen_t;
    // SAFETY: name 缓冲与 len 匹配。
    check(unsafe {
        libc::getsockopt(fd.as_raw_fd(), libc::SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name.as_mut_ptr().cast(), &mut len)
    })?;
    let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
    Ok((fd, String::from_utf8_lossy(&name[..end]).into_owned()))
}

fn ifname_bytes(name: &str) -> [libc::c_char; libc::IFNAMSIZ] {
    let mut out = [0 as libc::c_char; libc::IFNAMSIZ];
    for (dst, src) in out.iter_mut().zip(name.bytes().take(libc::IFNAMSIZ - 1)) {
        *dst = src as libc::c_char;
    }
    out
}

fn dgram(family: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: 普通 socket 调用。
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
    check(fd)?;
    // SAFETY: fd 有效。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn set_mtu(name: &str, mtu: u16) -> io::Result<()> {
    #[repr(C)]
    struct IfreqMtu {
        name: [libc::c_char; libc::IFNAMSIZ],
        mtu: libc::c_int,
        _pad: [u8; 12],
    }
    let sock = dgram(libc::AF_INET)?;
    let mut req = IfreqMtu { name: ifname_bytes(name), mtu: mtu as libc::c_int, _pad: [0; 12] };
    // SAFETY: req 与 struct ifreq（32 字节）布局一致。
    check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFMTU, &mut req) })
}

fn sockaddr_in(ip: std::net::Ipv4Addr) -> libc::sockaddr_in {
    // SAFETY: 全零合法。
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    sa.sin_family = libc::AF_INET as u8;
    sa.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    sa
}

fn sockaddr_in6(ip: std::net::Ipv6Addr) -> libc::sockaddr_in6 {
    // SAFETY: 全零合法。
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    sa.sin6_family = libc::AF_INET6 as u8;
    sa.sin6_addr.s6_addr = ip.octets();
    sa
}

fn add_address(name: &str, cidr: &IpCidr) -> io::Result<()> {
    match cidr.addr() {
        IpAddr::V4(ip) => {
            #[repr(C)]
            struct Ifaliasreq {
                name: [libc::c_char; libc::IFNAMSIZ],
                addr: libc::sockaddr_in,
                dst: libc::sockaddr_in,
                mask: libc::sockaddr_in,
            }
            let p = cidr.prefix() as u32;
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            // 点对点接口：对端地址取本机地址
            let mut req = Ifaliasreq {
                name: ifname_bytes(name),
                addr: sockaddr_in(ip),
                dst: sockaddr_in(ip),
                mask: sockaddr_in(mask.into()),
            };
            let sock = dgram(libc::AF_INET)?;
            // SAFETY: req 与 struct ifaliasreq（64 字节）布局一致。
            check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCAIFADDR, &mut req) })
        }
        IpAddr::V6(ip) => {
            #[repr(C)]
            struct Lifetime {
                expire: libc::time_t,
                preferred: libc::time_t,
                vltime: u32,
                pltime: u32,
            }
            #[repr(C)]
            struct In6Aliasreq {
                name: [libc::c_char; libc::IFNAMSIZ],
                addr: libc::sockaddr_in6,
                dst: libc::sockaddr_in6,
                mask: libc::sockaddr_in6,
                flags: libc::c_int,
                lifetime: Lifetime,
            }
            let p = cidr.prefix() as u32;
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            // SAFETY: 全零合法。
            let mut req: In6Aliasreq = unsafe { std::mem::zeroed() };
            req.name = ifname_bytes(name);
            req.addr = sockaddr_in6(ip);
            req.mask = sockaddr_in6(mask.into());
            req.flags = IN6_IFF_NODAD;
            req.lifetime.vltime = ND6_INFINITE_LIFETIME;
            req.lifetime.pltime = ND6_INFINITE_LIFETIME;
            debug_assert_eq!(std::mem::size_of::<In6Aliasreq>(), 128);
            let sock = dgram(libc::AF_INET6)?;
            // SAFETY: req 与 struct in6_aliasreq（128 字节）布局一致。
            check(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCAIFADDR_IN6, &mut req) })
        }
    }
}

fn if_index(name: &str) -> io::Result<u32> {
    let c = CString::new(name).map_err(|_| io::Error::other("invalid interface name"))?;
    // SAFETY: c 是有效 C 字符串。
    match unsafe { libc::if_nametoindex(c.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        i => Ok(i),
    }
}

fn if_name(index: u32) -> String {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: 缓冲区长度为 IF_NAMESIZE。
    if unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) }.is_null() {
        return format!("#{index}");
    }
    // SAFETY: 成功时写入以 NUL 结尾的名字。
    unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
}

/// 一个 `PF_ROUTE` 套接字。
struct RouteSocket {
    fd: OwnedFd,
    seq: i32,
    buf: Vec<u8>,
}

impl RouteSocket {
    fn open() -> io::Result<RouteSocket> {
        // SAFETY: 普通 socket 调用。
        let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        check(fd)?;
        // SAFETY: fd 有效。
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let timeout = libc::timeval { tv_sec: 5, tv_usec: 0 };
        // SAFETY: timeval 有效，长度匹配。
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        Ok(RouteSocket { fd, seq: 0, buf: vec![0; 2048] })
    }

    fn write(&mut self, rtm_type: u8, dst: &IpCidr, gateway: Option<Gateway>, want_ifp: bool) -> io::Result<i32> {
        self.seq = self.seq.wrapping_add(1);
        let msg = pfroute::encode(rtm_type, self.seq, dst, gateway, want_ifp);
        // SAFETY: msg 在调用期间有效。
        let n = unsafe { libc::write(self.fd.as_raw_fd(), msg.as_ptr().cast(), msg.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(self.seq)
    }

    /// 添加或删除路由；内核拒绝时返回 errno（如 `EEXIST`、`ESRCH`）。
    fn change(&mut self, rtm_type: u8, dst: &IpCidr, gateway: Option<Gateway>) -> io::Result<()> {
        self.write(rtm_type, dst, gateway, false).map(|_| ())
    }

    /// 查询 `dst` 网段的路由（精确匹配网段），返回（下一跳，出接口序号）。
    fn get(&mut self, dst: &IpCidr) -> io::Result<(Option<Gateway>, Option<u32>)> {
        let seq = self.write(RTM_GET, dst, None, true)?;
        // SAFETY: getpid 总是成功。
        let pid = unsafe { libc::getpid() };
        for _ in 0..64 {
            // SAFETY: buf 长度有效。
            let n = unsafe { libc::read(self.fd.as_raw_fd(), self.buf.as_mut_ptr().cast(), self.buf.len()) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(m) = pfroute::parse(&self.buf[..n as usize]) {
                if m.rtm_type == RTM_GET && m.pid == pid && m.seq == seq {
                    if m.errno != 0 {
                        return Err(io::Error::from_raw_os_error(m.errno));
                    }
                    return Ok((m.gateway, m.ifp.or(Some(m.index as u32).filter(|i| *i != 0))));
                }
            }
        }
        Err(io::Error::other("no reply to RTM_GET"))
    }
}

fn default_cidr(v6: bool) -> IpCidr {
    IpCidr::parse(if v6 { "::/0" } else { "0.0.0.0/0" }).unwrap()
}

/// 默认路由（先 IPv4 后 IPv6）的（下一跳，出接口），跳过 `exclude`（隧道自身）。不需要 root。
pub fn default_route(exclude: Option<u32>) -> io::Result<Option<(Option<Gateway>, u32)>> {
    let mut rs = RouteSocket::open()?;
    for v6 in [false, true] {
        match rs.get(&default_cidr(v6)) {
            Ok((gw, Some(index))) if Some(index) != exclude => return Ok(Some((gw, index))),
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
            Err(e) if !v6 => return Err(e),
            Err(_) => {}
        }
    }
    Ok(None)
}

/// 默认路由的出接口序号。
pub fn default_interface(exclude: Option<u32>) -> io::Result<Option<u32>> {
    Ok(default_route(exclude)?.map(|(_, i)| i))
}

fn gateway_text(g: &Gateway) -> String {
    match g {
        Gateway::Ip(ip) => ip.to_string(),
        Gateway::Link(i) => format!("link#{i}"),
    }
}

fn parse_gateway(s: &str) -> Option<Gateway> {
    match s.strip_prefix("link#") {
        Some(i) => i.parse().ok().map(Gateway::Link),
        None => s.parse().ok().map(Gateway::Ip),
    }
}

/// 读取状态文件中的（网段，下一跳）。
fn read_state(path: &Path) -> Vec<(IpCidr, Gateway)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let (dst, gw) = l.split_once(' ')?;
            Some((IpCidr::parse(dst)?, parse_gateway(gw.trim())?))
        })
        .take(MAX_STATE_ROUTES)
        .collect()
}

fn write_state(path: &Path, routes: &[(IpCidr, Gateway)]) -> io::Result<()> {
    let tmp = path.with_extension("state.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    for (dst, gw) in routes {
        writeln!(f, "{dst} {}", gateway_text(gw))?;
    }
    f.sync_all()?;
    std::fs::rename(tmp, path)
}

fn delete_routes(rs: &mut RouteSocket, routes: &[(IpCidr, Gateway)]) -> usize {
    let mut deleted = 0;
    for (dst, gw) in routes {
        match rs.change(RTM_DELETE, dst, Some(*gw)) {
            Ok(()) => deleted += 1,
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
            Err(e) => warn!("failed to delete route {dst} via {}: {e}", gateway_text(gw)),
        }
    }
    deleted
}

/// 已创建并配置好的 utun。Drop 时删除经网关的排除路由，再关闭 utun（内核删除接口路由）。
pub struct Tunnel {
    fd: OwnedFd,
    name: String,
    index: u32,
    state: PathBuf,
    gateway_routes: Vec<(IpCidr, Gateway)>,
}

impl Tunnel {
    /// macOS 没有 `SO_MARK`，`_routing_mark` 不用；防回环靠 `IP_BOUND_IF`（见 `protect_outbound`）。
    pub fn open(settings: &TunSettings, _routing_mark: Option<u32>, state_dir: &Path) -> io::Result<Tunnel> {
        let state = state_dir.join(STATE_FILE);
        let (fd, name) = create_utun(settings.device.as_deref())?;
        let index = if_index(&name)?;
        let mut rs = RouteSocket::open().map_err(|e| permission_hint(e, "open routing socket"))?;
        // 上次异常退出残留的排除路由
        let stale = read_state(&state);
        if !stale.is_empty() {
            let n = delete_routes(&mut rs, &stale);
            warn!("removed {n} stale routes from a previous run ({})", state.display());
            let _ = std::fs::remove_file(&state);
        }
        let mut tunnel = Tunnel { fd, name, index, state, gateway_routes: Vec::new() };
        tunnel.configure(&mut rs, settings)?;
        Ok(tunnel)
    }

    fn configure(&mut self, rs: &mut RouteSocket, s: &TunSettings) -> io::Result<()> {
        let (name, index) = (self.name.clone(), self.index);
        let link = Some(Gateway::Link(index));
        set_mtu(&name, s.mtu).map_err(|e| permission_hint(e, &format!("set {name} mtu {}", s.mtu)))?;
        for cidr in s.inet4_address.iter().chain(&s.inet6_address) {
            add_address(&name, cidr).map_err(|e| permission_hint(e, &format!("add address {cidr} to {name}")))?;
            // 点对点接口不会自动生成网段路由
            if cidr.prefix() < if cidr.is_ipv4() { 32 } else { 128 } {
                add_route(rs, &cidr.network(), link)?;
            }
        }
        info!("TUN {name} (index {index}) up: mtu {}, addresses {}", s.mtu, list(s.inet4_address.iter().chain(&s.inet6_address)));
        if !s.auto_route {
            return Ok(());
        }
        let has_v6 = !s.inet6_address.is_empty();
        let mut routes: Vec<IpCidr> = s.route_address.iter().map(IpCidr::network).collect();
        if routes.is_empty() {
            routes.extend(["0.0.0.0/1", "128.0.0.0/1"].map(|c| IpCidr::parse(c).unwrap()));
            if has_v6 {
                routes.extend(["::/1", "8000::/1"].map(|c| IpCidr::parse(c).unwrap()));
            }
        } else {
            // 显式写了默认路由时拆成两条 /1，不替换系统默认路由
            routes = routes
                .into_iter()
                .flat_map(|r| match (r.prefix(), r.is_ipv4()) {
                    (0, true) => vec![IpCidr::parse("0.0.0.0/1").unwrap(), IpCidr::parse("128.0.0.0/1").unwrap()],
                    (0, false) => vec![IpCidr::parse("::/1").unwrap(), IpCidr::parse("8000::/1").unwrap()],
                    _ => vec![r],
                })
                .collect();
        }
        if !has_v6 && routes.iter().any(|r| !r.is_ipv4()) {
            warn!("tun.route-address has IPv6 entries but tun.inet6-address is not set; IPv6 routes are skipped");
            routes.retain(IpCidr::is_ipv4);
        }
        // 先取原默认路由，再加 /1 路由
        let default = default_route(Some(index))?;
        if !s.route_exclude_address.is_empty() {
            match default {
                Some((gw, ifindex)) => {
                    let gw = gw.filter(|g| matches!(g, Gateway::Ip(_))).unwrap_or(Gateway::Link(ifindex));
                    let excludes: Vec<(IpCidr, Gateway)> = s
                        .route_exclude_address
                        .iter()
                        .filter(|c| c.is_ipv4() == matches!(gw, Gateway::Ip(IpAddr::V4(_))) || matches!(gw, Gateway::Link(_)))
                        .map(|c| (c.network(), gw))
                        .collect();
                    // 先落盘再添加：异常退出后下次启动能删掉
                    write_state(&self.state, &excludes)?;
                    for (dst, gw) in &excludes {
                        match rs.change(RTM_ADD, dst, Some(*gw)) {
                            Ok(()) => self.gateway_routes.push((*dst, *gw)),
                            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                                warn!("route {dst} already exists; left unchanged")
                            }
                            Err(e) => return Err(permission_hint(e, &format!("add route {dst} via {}", gateway_text(gw)))),
                        }
                    }
                }
                None => warn!("no default route found; tun.route-exclude-address is skipped"),
            }
        }
        for route in &routes {
            add_route(rs, route, link)?;
        }
        // 系统 DNS 服务器常在局域网内，比 /1 更具体的直连路由会让查询绕过隧道
        let mut dns_routes = 0;
        if !s.dns_hijack.is_empty() {
            let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
            for ip in pfroute::resolv_conf_servers(&text) {
                if ip.is_ipv6() && !has_v6 {
                    continue;
                }
                let host = IpCidr::parse(&ip.to_string()).expect("valid IP");
                match rs.change(RTM_ADD, &host, link) {
                    Ok(()) => dns_routes += 1,
                    Err(e) => warn!("failed to route DNS server {ip} into {name}: {e}"),
                }
            }
        }
        info!(
            "auto-route: {} via {name}, {} excluded via the original gateway, {dns_routes} DNS server routes",
            list(routes.iter()),
            self.gateway_routes.len()
        );
        Ok(())
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

fn add_route(rs: &mut RouteSocket, dst: &IpCidr, gateway: Option<Gateway>) -> io::Result<()> {
    match rs.change(RTM_ADD, dst, gateway) {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            // 已有同网段路由（如上次残留）：先删再加
            let _ = rs.change(RTM_DELETE, dst, None);
            rs.change(RTM_ADD, dst, gateway)
        }
        other => other,
    }
    .map_err(|e| permission_hint(e, &format!("add route {dst}")))
}

fn list<'a>(items: impl Iterator<Item = &'a IpCidr>) -> String {
    items.map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if !self.gateway_routes.is_empty() {
            match RouteSocket::open() {
                Ok(mut rs) => {
                    let n = delete_routes(&mut rs, &self.gateway_routes);
                    info!("removed {n} excluded routes");
                }
                Err(e) => warn!("failed to remove excluded routes: {e}"),
            }
        }
        let _ = std::fs::remove_file(&self.state);
        info!("TUN {} closed", self.name);
    }
}

/// 监测默认路由接口并把直连套接字绑到它（`IP_BOUND_IF`）。Drop 时停止。
pub struct InterfaceMonitor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl InterfaceMonitor {
    pub fn start(exclude: Option<u32>) -> io::Result<InterfaceMonitor> {
        let events = RouteSocket::open()?;
        let mut current = apply_default(exclude, 0);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("oryn-ifmon".into())
            .spawn(move || {
                let mut buf = vec![0u8; 2048];
                while !flag.load(Ordering::Relaxed) {
                    let mut pfd = libc::pollfd { fd: events.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                    // SAFETY: pfd 有效。
                    if unsafe { libc::poll(&mut pfd, 1, 500) } <= 0 {
                        continue;
                    }
                    let mut relevant = false;
                    loop {
                        // SAFETY: buf 长度有效。
                        let n = unsafe {
                            libc::recv(events.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT)
                        };
                        if n <= 0 {
                            break;
                        }
                        relevant |= pfroute::parse(&buf[..n as usize])
                            .is_some_and(|m| matches!(m.rtm_type, RTM_ADD | RTM_DELETE | pfroute::RTM_CHANGE | pfroute::RTM_IFINFO));
                    }
                    if relevant {
                        std::thread::sleep(Duration::from_millis(200));
                        current = apply_default(exclude, current);
                    }
                }
            })?;
        Ok(InterfaceMonitor { stop, thread: Some(thread) })
    }
}

fn apply_default(exclude: Option<u32>, current: u32) -> u32 {
    match default_interface(exclude) {
        Ok(Some(index)) if index != current => {
            oryn_udp::iface::set_bound_interface_index(index);
            info!("default interface: {} (index {index}); direct sockets are bound to it", if_name(index));
            index
        }
        Ok(Some(_)) => current,
        Ok(None) => {
            warn!("no default route found; keeping the current outbound binding");
            current
        }
        Err(e) => {
            warn!("failed to read the routing table: {e}");
            current
        }
    }
}

impl Drop for InterfaceMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_default_route_without_root() {
        // 开发机一般有默认路由；没有时也不应报错
        let route = default_route(None).unwrap();
        if let Some((_, index)) = route {
            assert!(index > 0);
            assert!(!if_name(index).starts_with('#'));
        }
    }

    #[test]
    fn rejects_bad_device_name_and_reports_permission() {
        let e = create_utun(Some("en0")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        // SAFETY: geteuid 总是成功。
        if unsafe { libc::geteuid() } != 0 {
            let e = create_utun(None).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        }
    }

    #[test]
    fn state_file_round_trip() {
        let dir = std::env::temp_dir().join(format!("oryn-host-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(STATE_FILE);
        let routes = vec![
            (IpCidr::parse("10.0.0.0/8").unwrap(), Gateway::Ip("192.168.1.1".parse().unwrap())),
            (IpCidr::parse("2001:db8::/32").unwrap(), Gateway::Link(7)),
        ];
        write_state(&path, &routes).unwrap();
        assert_eq!(read_state(&path), routes);
        std::fs::write(&path, "garbage\n10.0.0.0/8\n").unwrap();
        assert!(read_state(&path).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
