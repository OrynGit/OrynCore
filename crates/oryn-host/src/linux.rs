//! Linux：`/dev/net/tun`、rtnetlink 地址 / 路由 / 策略规则、默认接口监测。
//!
//! 规则布局（表 `T`、优先级 `P`、标记 `M`）见
//! Oryn_dev/docs/oryncore/plans/plan-desktop-tun-bare-core.md「Linux 策略路由布局」：
//! `P` 排除网段查 main，`P+1` main 的非默认路由优先，`P+2` 未带 `M` 的流量查表 `T`。

use std::ffi::CString;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use log::{info, warn};
use oryn_config::desktop::TunSettings;
use oryn_config::IpCidr;

use crate::nlmsg::*;

const DEFAULT_DEVICE: &str = "oryn0";
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
/// 每个优先级最多删多少条同号规则（防止异常状态下无限循环）。
const MAX_RULE_DELETES: usize = 256;
/// 一次 dump 最多接收的消息数。
const MAX_DUMP_MESSAGES: usize = 65_536;
const RECV_BUF: usize = 64 * 1024;

fn permission_hint(e: io::Error, what: &str) -> io::Error {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{what}: permission denied (TUN mode requires CAP_NET_ADMIN; run as root or grant the capability)"),
        ),
        _ => io::Error::new(e.kind(), format!("{what}: {e}")),
    }
}

/// 一个 NETLINK_ROUTE 套接字。
struct Netlink {
    fd: OwnedFd,
    seq: u32,
    buf: Vec<u8>,
}

impl Netlink {
    fn open(groups: u32) -> io::Result<Netlink> {
        // SAFETY: 普通 socket 调用，返回值检查后接管。
        let fd = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd 刚由 socket 返回且有效。
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: sockaddr_nl 全零是合法初值。
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = groups;
        // SAFETY: addr 是有效的 sockaddr_nl，长度匹配。
        let status = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        // 请求套接字设接收超时，内核异常时不至于永久阻塞
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
        Ok(Netlink { fd, seq: 1, buf: vec![0; RECV_BUF] })
    }

    fn send(&mut self, msg: Msg) -> io::Result<u32> {
        self.seq = self.seq.wrapping_add(1);
        let bytes = msg.finish(self.seq);
        // SAFETY: bytes 在调用期间有效。
        let n = unsafe { libc::send(self.fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(self.seq)
    }

    fn recv(&mut self) -> io::Result<usize> {
        loop {
            // SAFETY: buf 长度为 RECV_BUF。
            let n = unsafe { libc::recv(self.fd.as_raw_fd(), self.buf.as_mut_ptr().cast(), self.buf.len(), 0) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    /// 发送请求并等待内核确认；内核拒绝时返回对应的 errno。
    fn request(&mut self, msg: Msg) -> io::Result<()> {
        let seq = self.send(msg)?;
        loop {
            let n = self.recv()?;
            for m in messages(&self.buf[..n]) {
                if m.seq == seq && m.msg_type == NLMSG_ERROR {
                    return match error_code(m.payload) {
                        Some(0) => Ok(()),
                        Some(code) => Err(io::Error::from_raw_os_error(-code)),
                        None => Err(io::Error::other("truncated netlink error")),
                    };
                }
            }
        }
    }

    /// dump 请求，返回每条回复的内容（不含 `nlmsghdr`）。
    fn dump(&mut self, msg: Msg) -> io::Result<Vec<Vec<u8>>> {
        let seq = self.send(msg)?;
        let mut out = Vec::new();
        loop {
            let n = self.recv()?;
            for m in messages(&self.buf[..n]) {
                if m.seq != seq {
                    continue;
                }
                match m.msg_type {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_ERROR => match error_code(m.payload) {
                        Some(0) => return Ok(out),
                        Some(code) => return Err(io::Error::from_raw_os_error(-code)),
                        None => return Err(io::Error::other("truncated netlink error")),
                    },
                    _ if out.len() < MAX_DUMP_MESSAGES => out.push(m.payload.to_vec()),
                    _ => {}
                }
            }
        }
    }

    fn routes(&mut self, family: u8) -> io::Result<Vec<(RouteInfo, Vec<u8>)>> {
        let mut h = [0u8; 12];
        h[0] = family;
        let replies = self.dump(Msg::new(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, &h))?;
        Ok(replies
            .into_iter()
            .filter_map(|p| parse_route(&p).map(|r| (r, p)))
            .collect())
    }
}

fn family_of(c: &IpCidr) -> u8 {
    if c.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    }
}

fn addr_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// 创建 TUN 设备（`IFF_TUN | IFF_NO_PI`），返回描述符与内核分配的实际名字。
fn create_tun(name: &str) -> io::Result<(OwnedFd, String)> {
    let path = CString::new("/dev/net/tun").unwrap();
    // SAFETY: path 是有效 C 字符串。
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(permission_hint(io::Error::last_os_error(), "open /dev/net/tun"));
    }
    // SAFETY: fd 刚打开且有效。
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // struct ifreq：16 字节名字 + 24 字节联合体，flags 在偏移 16
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name.as_bytes());
    ifr[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    // SAFETY: ifr 至少与 struct ifreq 一样大。
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, ifr.as_mut_ptr()) } < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EBUSY) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("TUN device {name} is in use (is another instance running?)"),
            ));
        }
        return Err(permission_hint(e, &format!("create TUN device {name}")));
    }
    let end = ifr[..16].iter().position(|b| *b == 0).unwrap_or(16);
    Ok((fd, String::from_utf8_lossy(&ifr[..end]).into_owned()))
}

fn if_index(name: &str) -> io::Result<u32> {
    let c = CString::new(name).map_err(|_| io::Error::other("invalid interface name"))?;
    // SAFETY: c 是有效 C 字符串。
    match unsafe { libc::if_nametoindex(c.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        i => Ok(i),
    }
}

/// 删除 `P..=P+2` 的规则（两个地址族）。返回删除条数。
fn delete_rules(nl: &mut Netlink, base: u32) -> usize {
    let mut deleted = 0;
    for family in [AF_INET, AF_INET6] {
        for priority in base..=base + 2 {
            for _ in 0..MAX_RULE_DELETES {
                let msg = Msg::new(RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, &fib_rule_hdr(family, 0, FR_ACT_UNSPEC, 0))
                    .attr_u32(FRA_PRIORITY, priority);
                match nl.request(msg) {
                    Ok(()) => deleted += 1,
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => break,
                    // 内核不支持 IPv6 策略路由等：这一族没有可删的
                    Err(e) if e.raw_os_error() == Some(libc::EAFNOSUPPORT) => break,
                    Err(e) => {
                        warn!("failed to delete ip rule priority {priority}: {e}");
                        break;
                    }
                }
            }
        }
    }
    deleted
}

/// 清空路由表 `table`（两个地址族）。返回删除条数。
fn flush_table(nl: &mut Netlink, table: u32) -> usize {
    let mut deleted = 0;
    for family in [AF_INET, AF_INET6] {
        let routes = match nl.routes(family) {
            Ok(r) => r,
            Err(e) => {
                if e.raw_os_error() != Some(libc::EAFNOSUPPORT) {
                    warn!("failed to list routes: {e}");
                }
                continue;
            }
        };
        for (info, payload) in routes {
            if info.table != table {
                continue;
            }
            let mut msg = Msg::new(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, &payload[..12]);
            for (ty, data) in attrs(&payload[12..]) {
                msg = msg.attr(ty, data);
            }
            match nl.request(msg) {
                Ok(()) => deleted += 1,
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => warn!("failed to delete a route in table {table}: {e}"),
            }
        }
    }
    deleted
}

/// 已创建并配置好的 TUN。Drop 时删除规则与表中的路由，再关闭设备。
pub struct Tunnel {
    fd: OwnedFd,
    name: String,
    index: u32,
    /// `auto-route` 时的（表号，规则基准优先级）。
    routing: Option<(u32, u32)>,
}

impl Tunnel {
    pub fn open(settings: &TunSettings, routing_mark: Option<u32>) -> io::Result<Tunnel> {
        let requested = settings.device.as_deref().unwrap_or(DEFAULT_DEVICE);
        // 先建设备：同名设备被另一个实例占用时在这里失败，不会误删它的规则
        let (fd, name) = create_tun(requested)?;
        let index = if_index(&name)?;
        let mut nl = Netlink::open(0).map_err(|e| permission_hint(e, "open netlink socket"))?;
        let mut tunnel = Tunnel { fd, name, index, routing: None };
        if settings.auto_route {
            let (table, base) = (settings.table_index, settings.rule_index);
            let rules = delete_rules(&mut nl, base);
            let routes = flush_table(&mut nl, table);
            if rules + routes > 0 {
                warn!("removed stale routing state from a previous run: {rules} ip rules (priority {base}-{}), {routes} routes in table {table}", base + 2);
            }
            // 从这里起 Drop 负责清理
            tunnel.routing = Some((table, base));
        }
        tunnel.configure(&mut nl, settings, routing_mark)?;
        Ok(tunnel)
    }

    fn configure(&mut self, nl: &mut Netlink, s: &TunSettings, mark: Option<u32>) -> io::Result<()> {
        let index = self.index;
        let name = self.name.clone();
        let ctx = |what: String| move |e: io::Error| permission_hint(e, &what);
        nl.request(
            Msg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, &ifinfomsg(index as i32, IFF_UP, IFF_UP))
                .attr_u32(IFLA_MTU, s.mtu as u32),
        )
        .map_err(ctx(format!("set {name} up with mtu {}", s.mtu)))?;
        for cidr in s.inet4_address.iter().chain(&s.inet6_address) {
            let family = family_of(cidr);
            let ip = addr_bytes(cidr.addr());
            let mut msg = Msg::new(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, &ifaddrmsg(family, cidr.prefix(), index))
                .attr(IFA_LOCAL, &ip)
                .attr(IFA_ADDRESS, &ip);
            if family == AF_INET6 {
                msg = msg.attr_u32(IFA_FLAGS, IFA_F_NODAD);
            }
            nl.request(msg).map_err(ctx(format!("add address {cidr} to {name}")))?;
        }
        info!("TUN {name} (index {index}) up: mtu {}, addresses {}", s.mtu, list(s.inet4_address.iter().chain(&s.inet6_address)));
        let Some((table, base)) = self.routing else {
            return Ok(());
        };
        let mark = mark.ok_or_else(|| io::Error::other("auto-route requires a routing mark"))?;
        let has_v6 = !s.inet6_address.is_empty();
        let mut routes: Vec<IpCidr> = s.route_address.iter().map(IpCidr::network).collect();
        if routes.is_empty() {
            routes.push(IpCidr::parse("0.0.0.0/0").unwrap());
            if has_v6 {
                routes.push(IpCidr::parse("::/0").unwrap());
            }
        }
        // IPv6 没有隧道地址时 IPv6 路由无法回包，跳过并提示
        if !has_v6 && routes.iter().any(|r| !r.is_ipv4()) {
            warn!("tun.route-address has IPv6 entries but tun.inet6-address is not set; IPv6 routes are skipped");
            routes.retain(IpCidr::is_ipv4);
        }
        for route in &routes {
            let mut msg = Msg::new(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, &rtmsg(family_of(route), route.prefix(), table))
                .attr_u32(RTA_TABLE, table)
                .attr_u32(RTA_OIF, index);
            if route.prefix() > 0 {
                msg = msg.attr(RTA_DST, &addr_bytes(route.addr()));
            }
            nl.request(msg).map_err(ctx(format!("add route {route} to table {table}")))?;
        }
        let families: &[u8] = if has_v6 { &[AF_INET, AF_INET6] } else { &[AF_INET] };
        for exclude in &s.route_exclude_address {
            let family = family_of(exclude);
            if !families.contains(&family) {
                continue;
            }
            let net = exclude.network();
            nl.request(
                Msg::new(RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, &fib_rule_hdr(family, net.prefix(), FR_ACT_TO_TBL, 0))
                    .attr_u32(FRA_PRIORITY, base)
                    .attr_u32(FRA_TABLE, RT_TABLE_MAIN)
                    .attr(FRA_DST, &addr_bytes(net.addr())),
            )
            .map_err(ctx(format!("add ip rule to {net} lookup main")))?;
        }
        for &family in families {
            nl.request(
                Msg::new(RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, &fib_rule_hdr(family, 0, FR_ACT_TO_TBL, 0))
                    .attr_u32(FRA_PRIORITY, base + 1)
                    .attr_u32(FRA_TABLE, RT_TABLE_MAIN)
                    .attr_u32(FRA_SUPPRESS_PREFIXLEN, 0),
            )
            .map_err(ctx("add ip rule lookup main suppress_prefixlength 0".into()))?;
            nl.request(
                Msg::new(RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, &fib_rule_hdr(family, 0, FR_ACT_TO_TBL, FIB_RULE_INVERT))
                    .attr_u32(FRA_PRIORITY, base + 2)
                    .attr_u32(FRA_TABLE, table)
                    .attr_u32(FRA_FWMARK, mark)
                    .attr_u32(FRA_FWMASK, u32::MAX),
            )
            .map_err(ctx(format!("add ip rule not fwmark {mark} lookup {table}")))?;
        }
        info!(
            "auto-route: table {table} ({}), ip rules priority {base}-{} (exclude {}), fwmark {mark}",
            list(routes.iter()),
            base + 2,
            s.route_exclude_address.len()
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

fn list<'a>(items: impl Iterator<Item = &'a IpCidr>) -> String {
    items.map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if let Some((table, base)) = self.routing {
            match Netlink::open(0) {
                Ok(mut nl) => {
                    let rules = delete_rules(&mut nl, base);
                    let routes = flush_table(&mut nl, table);
                    info!("auto-route removed: {rules} ip rules, {routes} routes in table {table}");
                }
                Err(e) => warn!("failed to clean up auto-route state: {e}"),
            }
        }
        info!("TUN {} closed", self.name);
    }
}

/// 当前默认路由的出接口（先 IPv4 后 IPv6），跳过 `exclude`。
pub fn default_interface(exclude: Option<u32>) -> io::Result<Option<u32>> {
    let mut nl = Netlink::open(0)?;
    for family in [AF_INET, AF_INET6] {
        let routes: Vec<RouteInfo> = match nl.routes(family) {
            Ok(r) => r.into_iter().map(|(i, _)| i).collect(),
            Err(_) if family == AF_INET6 => continue,
            Err(e) => return Err(e),
        };
        if let Some(index) = pick_default_interface(&routes, exclude) {
            return Ok(Some(index));
        }
    }
    Ok(None)
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

/// 监测默认路由接口并把直连套接字绑到它（`auto-detect-interface`）。Drop 时停止。
pub struct InterfaceMonitor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl InterfaceMonitor {
    pub fn start(exclude: Option<u32>) -> io::Result<InterfaceMonitor> {
        let mut events = Netlink::open(RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE)?;
        let mut current = apply_default(exclude, 0);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("oryn-ifmon".into())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    let mut pfd = libc::pollfd { fd: events.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                    // SAFETY: pfd 有效。
                    let ready = unsafe { libc::poll(&mut pfd, 1, 500) };
                    if ready <= 0 {
                        continue;
                    }
                    // 读空积压的通知（ENOBUFS 表示有通知丢失，同样重新检测）
                    loop {
                        // SAFETY: buf 长度为 RECV_BUF。
                        let n = unsafe {
                            libc::recv(events.fd.as_raw_fd(), events.buf.as_mut_ptr().cast(), events.buf.len(), libc::MSG_DONTWAIT)
                        };
                        if n <= 0 {
                            break;
                        }
                    }
                    // 路由变化常成批出现，稍等再检测
                    std::thread::sleep(Duration::from_millis(200));
                    current = apply_default(exclude, current);
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
            if current != 0 {
                warn!("no default route found; keeping outbound sockets bound to {}", if_name(current));
            } else {
                warn!("no default route found; outbound sockets are not bound");
            }
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
