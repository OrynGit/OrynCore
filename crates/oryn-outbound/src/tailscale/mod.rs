//! Tailscale 基础出站：单身份、懒启动、DERP 承载和身份 MagicDNS。
//! 不监听入站；普通代理、身份 DNS 和 peer 流量分别沿现有接口运行。
mod control;
mod derp;
mod snapshot;

use crate::{BoxStream, Dialer, Outbound, PacketConn, Resolver, SessionControl, TailnetDnsAnswer};
use async_trait::async_trait;
use oryn_config::{TailscaleSpec, TargetAddr, WireGuardSpec};
use oryn_wireguard::Tunnel;
use serde::{Deserialize, Serialize};
use snapshot::Snapshot;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock, Weak},
    time::Duration,
};
use tokio::sync::Notify;
use ts_keys::{NodeState, PersistState};

fn err(message: &str) -> io::Error {
    io::Error::other(message)
}
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Ready {
    scope: String,
    snapshot: Snapshot,
    tunnel: Arc<Tunnel>,
    endpoints: Vec<Option<SocketAddr>>,
    accept_routes: bool,
    exit_peer: Option<usize>,
    exit_allow_lan: bool,
}
struct State {
    ready: Option<Arc<Ready>>,
    error: Option<String>,
    asleep: bool,
    task: Option<Task>,
}
struct Session {
    spec: TailscaleSpec,
    dialer: Arc<dyn Dialer>,
    resolver: Arc<dyn Resolver>,
    datagrams: Arc<dyn oryn_udp::DatagramFactory>,
    data_dir: Option<PathBuf>,
    state: RwLock<State>,
    notify: Notify,
}
pub struct TailscaleOutbound {
    tag: String,
    session: Arc<Session>,
}
impl TailscaleOutbound {
    pub fn new(
        tag: String,
        spec: TailscaleSpec,
        dialer: Arc<dyn Dialer>,
        resolver: Arc<dyn Resolver>,
        datagrams: Arc<dyn oryn_udp::DatagramFactory>,
        data_dir: Option<&Path>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tag,
            session: Arc::new(Session {
                spec,
                dialer,
                resolver,
                datagrams,
                data_dir: data_dir.map(Path::to_path_buf),
                state: RwLock::new(State {
                    ready: None,
                    error: None,
                    asleep: false,
                    task: None,
                }),
                notify: Notify::new(),
            }),
        })
    }
}
impl Session {
    fn stop(&self, asleep: bool) {
        let mut state = self.state.write().unwrap();
        if let Some(ready) = state.ready.take() {
            ready.tunnel.close();
        }
        state.task = None;
        state.asleep = asleep;
        state.error = None;
        self.notify.notify_waiters();
    }
    fn revoke(&self, message: Option<String>) {
        let mut state = self.state.write().unwrap();
        if let Some(ready) = state.ready.take() {
            ready.tunnel.close();
        }
        state.error = message;
        self.notify.notify_waiters();
    }
    async fn ready(self: &Arc<Self>) -> io::Result<Arc<Ready>> {
        if !self.spec.enabled {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Tailscale is disabled; set oryn-tailscale-enabled: true",
            ));
        }
        {
            let mut state = self.state.write().unwrap();
            if state.asleep {
                return Err(err("Tailscale is suspended"));
            }
            if state.task.as_ref().is_none_or(|t| t.0.is_finished()) {
                state.error = None;
                let weak = Arc::downgrade(self);
                let spec = self.spec.clone();
                let dialer = self.dialer.clone();
                let dir = self.data_dir.clone();
                let datagrams = self.datagrams.clone();
                state.task = Some(Task(tokio::spawn(async move {
                    let result = run(weak.clone(), spec, dialer, datagrams, dir).await;
                    if let Some(s) = weak.upgrade() {
                        s.revoke(Some(match result {
                            Err(e) => e.to_string(),
                            Ok(()) => "Tailscale control stream stopped".into(),
                        }));
                    }
                })));
            }
        }
        control::timed(async {
            loop {
                let notified = self.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let state = self.state.read().unwrap();
                    if state.asleep {
                        return Err(err("Tailscale is suspended"));
                    }
                    if let Some(error) = &state.error {
                        if state.task.as_ref().is_none_or(|task| task.0.is_finished()) {
                            return Err(err(error));
                        }
                    }
                    if let Some(ready) = &state.ready {
                        if !ready.snapshot.valid() {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "Tailscale identity expired or unauthorized",
                            ));
                        }
                        return Ok(ready.clone());
                    }
                }
                notified.await;
            }
        })
        .await
    }
    async fn resolve_target(
        &self,
        ready: &Ready,
        target: &TargetAddr,
    ) -> io::Result<SocketAddr> {
        let socket = match resolve(ready, target) {
            Ok(socket) => socket,
            Err(error) if ready.exit_peer.is_some() && error.kind() == io::ErrorKind::NotFound => {
                let TargetAddr::Domain(name, port) = target else {
                    return Err(error);
                };
                // 尾网名字解析失败不得转给外部 resolver。
                if ready
                    .snapshot
                    .magic_domain(&name.trim_end_matches('.').to_ascii_lowercase())
                {
                    return Err(error);
                }
                // 经 exit node 出去的流量，名字也应经隧道解析，不能把目标主机名泄露给本地网络 / 本地 DNS：
                // 优先用 tailnet 下发的解析器（经隧道、由 exit node 路由），都不可用时才退回本地解析器
                let mut tunneled = Vec::new();
                let resolvers: Vec<SocketAddr> = ready
                    .snapshot
                    .dns_resolvers
                    .iter()
                    .chain(&ready.snapshot.dns_fallback)
                    .copied()
                    .collect();
                for qtype in [1u16, 28] {
                    if let Ok(Some((_, ips))) = tunnel_dns(ready, &resolvers, name, qtype).await {
                        tunneled.extend(ips);
                    }
                    if !tunneled.is_empty() {
                        break;
                    }
                }
                let ips = if tunneled.is_empty() {
                    log::debug!("tailscale: no tunnel DNS answer for exit-node target, using local resolver");
                    self.resolver.resolve(name).await?
                } else {
                    tunneled
                };
                ips.into_iter()
                    .map(|ip| SocketAddr::new(ip, *port))
                    .find(|socket| {
                        resolve(ready, &TargetAddr::Ip(*socket)).is_ok()
                    })
                    .ok_or(error)?
            }
            Err(error) => return Err(error),
        };
        // PacketFilter 是入站规则（tailscale filter.RunIn），出站恒放行（RunOut），这里不据此拦截；
        // 对端是否接受由对端自己的过滤器决定（OrynCore#39）
        Ok(socket)
    }
    fn current(&self, ready: &Ready) -> bool {
        self.state.read().unwrap().ready.as_ref().is_some_and(|r| {
            r.snapshot.generation == ready.snapshot.generation
                && Arc::ptr_eq(&r.tunnel, &ready.tunnel)
                && r.snapshot.valid()
        })
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.stop(true);
    }
}
impl SessionControl for Session {
    fn on_config_replaced(&self) {
        self.stop(true);
    }
    fn on_network_changed(&self) {
        self.stop(false);
    }
    fn on_sleep(&self) {
        self.stop(true);
    }
    fn on_wake(&self) {
        self.stop(false);
    }
}

fn resolve(ready: &Ready, target: &TargetAddr) -> io::Result<SocketAddr> {
    let target = match target {
        TargetAddr::Ip(addr) => *addr,
        TargetAddr::Domain(name, port) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            let ip = ready
                .snapshot
                .records
                .get(&name)
                .and_then(|ips| {
                    ips.iter().copied().find(|ip| {
                        ready.snapshot.peer(*ip)
                            || (ready.accept_routes && ready.snapshot.subnet(*ip))
                            || ready.exit_peer.is_some()
                    })
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "Tailscale MagicDNS has no reachable peer for this name",
                    )
                })?;
            SocketAddr::new(ip, *port)
        }
    };
    if ready.exit_peer.is_some()
        && ready.exit_allow_lan
        && is_local_lan(target.ip())
        && !ready.snapshot.peer(target.ip())
        && !(ready.accept_routes && ready.snapshot.subnet(target.ip()))
    {
        return Err(io::Error::new(
            io::ErrorKind::NetworkUnreachable,
            "Tailscale exit node is configured to allow local LAN access",
        ));
    }
    if !ready.snapshot.peer(target.ip())
        && !(ready.accept_routes && ready.snapshot.subnet(target.ip()))
        && ready.exit_peer.is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::NetworkUnreachable,
            "destination has no authorized Tailscale peer route",
        ));
    }
    Ok(target)
}
fn is_local_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast()
        }
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

#[async_trait]
impl Outbound for TailscaleOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "tailscale"
    }
    fn session_control(&self) -> Option<Arc<dyn SessionControl>> {
        Some(self.session.clone())
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let ready = self.session.ready().await?;
        let target = self.session.resolve_target(&ready, target).await?;
        let stream = ready.tunnel.connect_tcp(&ready.endpoints, target).await?;
        if !self.session.current(&ready) {
            return Err(err("Tailscale routes changed during connection"));
        }
        Ok(Box::new(stream))
    }
    async fn bind_udp(&self, target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.session.spec.udp {
            return Err(crate::unsupported("Tailscale application UDP is disabled"));
        }
        let ready = self.session.ready().await?;
        self.session.resolve_target(&ready, target).await?;
        let udp = ready.tunnel.bind_udp(&ready.endpoints).await?;
        Ok(Box::new(Packets {
            session: self.session.clone(),
            ready,
            udp,
            destinations: Mutex::new(Vec::new()),
        }))
    }
    fn dns_scope(&self) -> Option<String> {
        self.session
            .state
            .read()
            .unwrap()
            .ready
            .as_ref()
            .filter(|r| r.snapshot.valid())
            .map(|r| r.scope.clone())
    }
    async fn query_dns(&self, name: &str, qtype: u16) -> io::Result<TailnetDnsAnswer> {
        let ready = self.session.ready().await?;
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if qtype == 12 {
            let ptr = ready.snapshot.records.iter().find_map(|(name_key, ips)| {
                if !name_key.contains('.') {
                    return None;
                }
                ips.iter()
                    .any(|ip| reverse_name(*ip) == name)
                    .then(|| name_key.clone())
            });
            return Ok(TailnetDnsAnswer {
                exists: ptr.is_some(),
                ptr,
                ips: Vec::new(),
            });
        }
        if let Some(ips) = ready.snapshot.records.get(&name) {
            return Ok(TailnetDnsAnswer {
                exists: true,
                ips: ips.clone(),
                ptr: None,
            });
        }
        let mut route = None;
        for (suffix, resolvers) in &ready.snapshot.dns_routes {
            if (name == *suffix || name.ends_with(&format!(".{suffix}")))
                && route.as_ref().is_none_or(|(old, _)| suffix.len() > *old)
            {
                route = Some((suffix.len(), resolvers));
            }
        }
        if route
            .as_ref()
            .is_some_and(|(_, servers)| servers.is_empty())
        {
            return Ok(TailnetDnsAnswer {
                exists: false,
                ips: Vec::new(),
                ptr: None,
            });
        }
        let resolvers = route
            .map(|(_, servers)| servers.as_slice())
            .filter(|servers| !servers.is_empty())
            .or_else(|| {
                (!ready.snapshot.dns_resolvers.is_empty())
                    .then_some(ready.snapshot.dns_resolvers.as_slice())
            })
            .or_else(|| {
                (!ready.snapshot.dns_fallback.is_empty())
                    .then_some(ready.snapshot.dns_fallback.as_slice())
            })
            .or_else(|| ready.snapshot.magic_domain(&name).then_some([].as_slice()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Tailscale MagicDNS has no record and no scoped resolver",
                )
            })?;
        if resolvers.is_empty() {
            return Ok(TailnetDnsAnswer {
                exists: false,
                ips: Vec::new(),
                ptr: None,
            });
        }
        if qtype == 12 {
            return Ok(TailnetDnsAnswer {
                exists: false,
                ips: Vec::new(),
                ptr: None,
            });
        }
        let (rcode, ips) = tunnel_dns(&ready, resolvers, &name, qtype)
            .await?
            .ok_or_else(|| err("Tailscale DNS resolvers returned no valid answer"))?;
        Ok(TailnetDnsAnswer {
            exists: rcode != 3,
            ips,
            ptr: None,
        })
    }
}
/// 每次查询最多尝试的解析器数：每个 3 秒超时，最坏约 12 秒。
const MAX_DNS_ATTEMPTS: usize = 4;
/// 经隧道向 `resolvers` 依次查询；返回 `(rcode, 地址)`，没有可用解析器或都无有效回答时为 None。
/// 隧道内 UDP 套接字只建一个，查询 ID 随机（可预测的 ID 便于伪造回答）。
async fn tunnel_dns(
    ready: &Ready,
    resolvers: &[SocketAddr],
    name: &str,
    qtype: u16,
) -> io::Result<Option<(u8, Vec<IpAddr>)>> {
    let usable: Vec<SocketAddr> = resolvers
        .iter()
        .copied()
        .filter(|r| {
            resolve(ready, &TargetAddr::Ip(*r)).is_ok()
        })
        .take(MAX_DNS_ATTEMPTS)
        .collect();
    if usable.is_empty() {
        return Ok(None);
    }
    let udp = ready.tunnel.bind_udp(&ready.endpoints).await?;
    let mut buf = vec![0; 4096];
    for resolver in usable {
        let query = build_dns_query(rand::random(), name, qtype)?;
        udp.send_to(&query, resolver)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        // 同一套接字上可能先收到上一个解析器迟到的回答：在期限内跳过不匹配的包
        while let Ok(Ok((n, from))) =
            tokio::time::timeout_at(deadline, udp.recv_from(&mut buf)).await
        {
            if from != resolver || n < 2 || buf[..2] != query[..2] {
                continue;
            }
            if let Some(answer) = parse_dns_answer(&buf[..n]) {
                return Ok(Some(answer));
            }
            break;
        }
    }
    Ok(None)
}
fn build_dns_query(id: u16, name: &str, qtype: u16) -> io::Result<Vec<u8>> {
    if name.len() > 253
        || name.is_empty()
        || name
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63 || !label.is_ascii())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Tailscale DNS query name",
        ));
    }
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        let len = bytes.len();
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.extend_from_slice(&[0, (qtype >> 8) as u8, qtype as u8, 0, 1]);
    Ok(out)
}
fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    for _ in 0..64 {
        let len = *buf.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        if len & 0xc0 != 0 {
            return None;
        }
        pos = pos.checked_add(len + 1)?;
        if len == 0 {
            return Some(pos);
        }
    }
    None
}
fn parse_dns_answer(buf: &[u8]) -> Option<(u8, Vec<IpAddr>)> {
    if buf.len() < 12 || buf[2] & 0x80 == 0 || buf[2] & 0x02 != 0 {
        return None;
    }
    let read16 = |pos: usize| Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]));
    let qd = read16(4)? as usize;
    let an = read16(6)? as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_dns_name(buf, pos)? + 4;
    }
    let mut ips = Vec::new();
    for _ in 0..an {
        pos = skip_dns_name(buf, pos)?;
        let typ = read16(pos)?;
        let len = read16(pos + 8)? as usize;
        let start = pos + 10;
        let data = buf.get(start..start + len)?;
        if typ == 1 && len == 4 {
            ips.push(std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]).into());
        } else if typ == 28 && len == 16 {
            ips.push(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?).into());
        }
        pos = start + len;
    }
    Some((buf[3] & 0x0f, ips))
}
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => {
            let a = ip.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", a[3], a[2], a[1], a[0])
        }
        IpAddr::V6(ip) => {
            let mut out = String::new();
            for byte in ip.octets().iter().rev() {
                out.push_str(&format!("{:x}.{:x}.", byte & 15, byte >> 4));
            }
            out.push_str("ip6.arpa");
            out
        }
    }
}
/// 宣告了默认路由（0.0.0.0/0 或 ::/0）的对端可作 exit node。
fn has_exit_routes(peer: &snapshot::Peer) -> bool {
    peer.routes.iter().any(|r| r.prefix() == 0)
}
fn select_exit(snapshot: &Snapshot, value: Option<&str>) -> io::Result<Option<usize>> {
    let Some(value) = value.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let auto = matches!(
        value.to_ascii_lowercase().as_str(),
        "auto:any" | "auto:*" | "auto"
    );
    let found = if auto {
        snapshot
            .peers
            .iter()
            .enumerate()
            .find(|(_, peer)| peer.online && has_exit_routes(peer))
            .map(|(i, _)| i)
    } else if let Ok(ip) = value.parse::<IpAddr>() {
        snapshot
            .peers
            .iter()
            .enumerate()
            .find(|(_, peer)| peer.ips.contains(&ip) && has_exit_routes(peer))
            .map(|(i, _)| i)
    } else {
        let name = value.trim_end_matches('.').to_ascii_lowercase();
        snapshot
            .peers
            .iter()
            .enumerate()
            .find(|(_, peer)| peer.name.trim_end_matches('.') == name && has_exit_routes(peer))
            .map(|(i, _)| i)
    };
    found.map(Some).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "requested Tailscale exit node is unavailable or does not advertise default routes",
        )
    })
}
struct Packets {
    session: Arc<Session>,
    ready: Arc<Ready>,
    udp: oryn_wireguard::UdpSession,
    destinations: Mutex<Vec<SocketAddr>>,
}
#[async_trait]
impl PacketConn for Packets {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        if !self.session.current(&self.ready) {
            return Err(err("Tailscale UDP identity or routes changed"));
        }
        let target = self.session.resolve_target(&self.ready, target).await?;
        if !self.session.current(&self.ready) {
            return Err(err(
                "Tailscale UDP identity or routes changed during resolution",
            ));
        }
        {
            let mut destinations = self.destinations.lock().unwrap();
            if !destinations.contains(&target) {
                if destinations.len() >= 16 {
                    return Err(err("too many Tailscale UDP destinations"));
                }
                destinations.push(target);
            }
        }
        self.udp.send_to(buf, target)
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        loop {
            if !self.session.current(&self.ready) {
                return Err(err("Tailscale UDP identity or routes changed"));
            }
            let (n, from) = self.udp.recv_from(buf).await?;
            if self.destinations.lock().unwrap().contains(&from) {
                return Ok((n, TargetAddr::Ip(from)));
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Identity {
    version: u8,
    control_url: String,
    keys: PersistState,
}
fn identity(spec: &TailscaleSpec, dir: Option<&Path>) -> io::Result<NodeState> {
    use std::io::{Read, Write};
    let root = dir.ok_or_else(|| err("Tailscale requires a persistent data directory"))?;
    std::fs::create_dir_all(root)?;
    let mut namespace = root.to_path_buf();
    for component in std::iter::once("tailscale-state").chain(spec.state_dir.split('/')) {
        // 只允许普通目录名：`..` 会逃出数据目录，`.` 与空段没有意义
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.contains('\\') {
            return Err(err("unsafe Tailscale state directory"));
        }
        namespace.push(component);
        match std::fs::symlink_metadata(&namespace) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                return Err(err("unsafe Tailscale state directory"))
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(&namespace)?;
            }
            Err(e) => return Err(e),
        }
    }
    let path = namespace.join("identity.json");
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > 16 * 1024 {
            return Err(err("unsafe Tailscale identity file"));
        }
    }
    match std::fs::File::open(&path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 {
                return Err(err("Tailscale identity exceeds limit"));
            }
            let identity: Identity = serde_json::from_slice(&bytes)
                .map_err(|_| err("invalid Tailscale identity; refusing automatic reset"))?;
            if identity.version != 1 || identity.control_url != spec.control_url {
                return Err(err("Tailscale state belongs to a different control server"));
            }
            Ok(NodeState::from(identity.keys))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let keys = PersistState::default();
            let identity = Identity {
                version: 1,
                control_url: spec.control_url.clone(),
                keys: keys.clone(),
            };
            // 先写临时文件再原子改名：中途崩溃只会留下临时文件，不会留下截断的 identity.json
            // （截断文件会被当成损坏而永久拒绝启动）
            let temp = namespace.join("identity.json.tmp");
            let _ = std::fs::remove_file(&temp);
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp)?;
            file.write_all(&serde_json::to_vec(&identity).map_err(io::Error::other)?)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp, &path)?;
            Ok(NodeState::from(keys))
        }
        Err(e) => Err(e),
    }
}

/// 跨控制会话保留的状态：控制连接断开重连时，DERP 仍连着就沿用现有隧道，
/// 新会话的首个 netmap 与之相同（或只有软变化）时不重建、不杀既有 Flow。
struct Carry {
    snapshot: Snapshot,
    relay: Arc<derp::Relay>,
    home: u16,
}

#[cfg(test)]
mod expiry_tests;

async fn expiry_guard<F: std::future::Future<Output = io::Result<()>>>(
    weak: Weak<Session>,
    control: F,
) -> io::Result<()> {
    // 一个会话一个 timer，覆盖 map 静默、KeepAlive、重连退避及握手。
    // 每秒重读墙钟而非把 expiry 永久转换成单调时钟 deadline：时钟前跳
    // 最迟下一次 tick 撤销；回拨不会误用旧 deadline 撤销尚未到期的身份。
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(control);
    loop {
        tokio::select! {
            biased;
            _ = tick.tick() => {
                let Some(session) = weak.upgrade() else { return Ok(()); };
                let expired = {
                    let state = session.state.read().unwrap();
                    let now = snapshot::now();
                    state.ready.as_ref().is_some_and(|ready| {
                        ready.snapshot.expiry.into_iter()
                            .chain(ready.snapshot.peers.iter().filter_map(|peer| peer.expiry))
                            .any(|expiry| expiry <= now)
                    })
                };
                if expired {
                    // 当前 WireGuard 仅支持整代撤销，保守关闭所有既有 Flow。
                    // 返回会丢弃整个控制 future（含连接与 carry），绝不在取消
                    // frame/read_exact 后继续使用同一个流。下一代重编译会滤掉
                    // 已到期 peer，故不会让最早到期者遮住后续 expiry。
                    session.revoke(Some("Tailscale node key expired".into()));
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "Tailscale node key expired"));
                }
            }
            result = &mut control => return result,
        }
    }
}

async fn run(
    weak: Weak<Session>,
    spec: TailscaleSpec,
    dialer: Arc<dyn Dialer>,
    datagrams: Arc<dyn oryn_udp::DatagramFactory>,
    dir: Option<PathBuf>,
) -> io::Result<()> {
    loop {
        let result = expiry_guard(
            weak.clone(),
            run_control(
                weak.clone(),
                spec.clone(),
                dialer.clone(),
                datagrams.clone(),
                dir.clone(),
            ),
        )
        .await;
        if !matches!(&result, Err(error) if error.kind() == io::ErrorKind::Interrupted) {
            return result;
        }
        // 到期不是控制同步错误；丢弃旧 carry 后重新取状态，不携带过期路由。
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn run_control(
    weak: Weak<Session>,
    spec: TailscaleSpec,
    dialer: Arc<dyn Dialer>,
    datagrams: Arc<dyn oryn_udp::DatagramFactory>,
    dir: Option<PathBuf>,
) -> io::Result<()> {
    let mut delay = Duration::from_secs(1);
    let mut carry: Option<Carry> = None;
    loop {
        if weak
            .upgrade()
            .is_some_and(|session| session.state.read().unwrap().asleep)
        {
            return Ok(());
        }
        match run_once(
            weak.clone(),
            spec.clone(),
            dialer.clone(),
            datagrams.clone(),
            dir.clone(),
            &mut carry,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::InvalidInput
                ) =>
            {
                return Err(error)
            }
            Err(error) => {
                log::warn!("tailscale: control/DERP session failed; reconnecting: {error}");
                let Some(session) = weak.upgrade() else {
                    return Ok(());
                };
                // 只有 DERP 承载也断了才撤销隧道；控制面同步超时等瞬时错误期间沿用现有快照与隧道
                // （与官方客户端控制面不可达时继续使用旧 netmap 一致），重连后再比对
                if carry.as_ref().is_none_or(|c| c.relay.is_closed()) {
                    carry = None;
                    session.revoke(Some(error.to_string()));
                }
                drop(session);
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
    }
}

async fn run_once(
    weak: Weak<Session>,
    spec: TailscaleSpec,
    dialer: Arc<dyn Dialer>,
    datagrams: Arc<dyn oryn_udp::DatagramFactory>,
    dir: Option<PathBuf>,
    carry: &mut Option<Carry>,
) -> io::Result<()> {
    log::debug!("tailscale: opening identity");
    let keys = identity(&spec, dir.as_deref())?;
    let scope = ring::digest::digest(
        &ring::digest::SHA256,
        format!("{}|{}", spec.control_url, keys.node_keys.public).as_bytes(),
    )
    .as_ref()
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect::<String>();
    let mut ctl = control::timed(control::Control::connect(&spec, &keys, dialer.clone())).await?;
    log::debug!("tailscale: registered");
    let mut map = control::timed(ctl.map(&spec, &keys, None, true)).await?;
    let mut snapshot = carry
        .as_ref()
        .map(|c| c.snapshot.clone())
        .unwrap_or_default();
    let mut home = carry.as_ref().map(|c| c.home);
    // 每个控制会话都要向控制面报一次 home DERP
    let mut announced = false;
    loop {
        // 到期由外层 expiry_guard 独立处理，不伪装成控制同步超时。
        // 普通 timer tick 不取消此 frame future，read_exact 可安全跨 tick 继续。
        let read = tokio::time::timeout(Duration::from_secs(90), map.frame());
        let relay = carry.as_ref().map(|c| c.relay.clone());
        let value = if let Some(relay) = relay {
            tokio::select! {
                value = read => value.map_err(|_| err("Tailscale control synchronization timed out"))??,
                _ = relay.disconnected() => return Err(err("Tailscale DERP connection closed")),
            }
        } else {
            read.await
                .map_err(|_| err("Tailscale control synchronization timed out"))??
        };
        // 先在独立快照验证，再撤销旧隧道、发布新一代；无半张路由表。
        log::debug!("tailscale: received map");
        let full = value["Peers"].is_array();
        let mut next = snapshot.clone();
        // 全量 netmap 不合法（如对端超过上限）是配置问题，终止；增量不合法时重连拿一份全量重新同步
        let change = next.apply(value).map_err(|error| {
            if full {
                io::Error::new(io::ErrorKind::InvalidData, error.to_string())
            } else {
                err(&format!(
                    "Tailscale netmap delta rejected, resynchronizing: {error}"
                ))
            }
        })?;
        // 还没收到任何实际状态（如先到的 KeepAlive）时不报 home、不建隧道
        if next.generation == 0 {
            snapshot = next;
            continue;
        }
        if !announced {
            if !next.valid() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Tailscale identity is unauthorized or expired",
                ));
            }
            let region = home
                .or_else(|| next.regions.keys().next().copied())
                .ok_or_else(|| err("Tailscale control returned no DERP region"))?;
            let mut ack = control::timed(ctl.map(&spec, &keys, Some(region), false)).await?;
            // 非流式更新无响应内容亦合法；有界消费。
            let _ = control::timed(ack.all(control::MAX_MAP)).await?;
            home = Some(region);
            announced = true;
        }
        let Some(session) = weak.upgrade() else {
            return Ok(());
        };
        let published = session.state.read().unwrap().ready.clone();
        // 软变化（上下线、DNS 记录 / 解析器）且 exit node 选择不变：只换快照，隧道与 Flow 保留
        if change != snapshot::Change::Hard && carry.is_some() {
            if let Some(current) = published {
                let exit_peer = select_exit(&next, spec.exit_node.as_deref())?;
                if exit_peer == current.exit_peer {
                    snapshot = next;
                    if change == snapshot::Change::Soft {
                        session.state.write().unwrap().ready = Some(Arc::new(Ready {
                            scope: current.scope.clone(),
                            snapshot: snapshot.clone(),
                            tunnel: current.tunnel.clone(),
                            endpoints: current.endpoints.clone(),
                            accept_routes: current.accept_routes,
                            exit_peer,
                            exit_allow_lan: current.exit_allow_lan,
                        }));
                        session.notify.notify_waiters();
                    }
                    if let Some(c) = carry.as_mut() {
                        c.snapshot = snapshot.clone();
                        c.home = home.expect("announced");
                    }
                    continue;
                }
            }
        }
        session.revoke(None);
        drop(session);
        *carry = None;
        snapshot = next;
        if !snapshot.valid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Tailscale identity is unauthorized or expired",
            ));
        }
        let region = home.ok_or_else(|| err("Tailscale control returned no DERP region"))?;
        let relay =
            derp::Relay::start(&snapshot, &keys, dialer.clone(), datagrams.clone(), region).await?;
        let exit_peer = select_exit(&snapshot, spec.exit_node.as_deref())?;
        let wire = WireGuardSpec {
            peers: snapshot
                .peers
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    derp::wire_peer(p, i, spec.accept_routes == Some(true), exit_peer == Some(i))
                })
                .collect(),
            private_key: keys.node_keys.private.to_crypto_box().to_bytes(),
            address_v4: snapshot.own_ips.iter().find_map(|ip| {
                if let IpAddr::V4(ip) = ip {
                    Some((*ip, 32))
                } else {
                    None
                }
            }),
            address_v6: snapshot.own_ips.iter().find_map(|ip| {
                if let IpAddr::V6(ip) = ip {
                    Some((*ip, 128))
                } else {
                    None
                }
            }),
            mtu: 1280,
            keepalive_secs: 0,
            // The internal DNS resolver needs a tunnel UDP socket even when
            // mihomo's application `udp` option is false. The public
            // bind_udp method still enforces that option below.
            udp: true,
            remote_dns: false,
            dns: Vec::new(),
            amnezia: None,
            refresh_secs: None,
            tcp_buffers: Default::default(),
        };
        let tunnel = Tunnel::with_factory(wire, Arc::new(derp::Factory(relay.clone())));
        let endpoints = (0..snapshot.peers.len())
            .map(|i| Some(derp::endpoint(i)))
            .collect();
        let Some(session) = weak.upgrade() else {
            tunnel.close();
            return Ok(());
        };
        *carry = Some(Carry {
            snapshot: snapshot.clone(),
            relay,
            home: region,
        });
        session.state.write().unwrap().error = None;
        session.state.write().unwrap().ready = Some(Arc::new(Ready {
            scope: scope.clone(),
            snapshot: snapshot.clone(),
            tunnel,
            endpoints,
            accept_routes: spec.accept_routes == Some(true),
            exit_peer,
            exit_allow_lan: spec.exit_node_allow_lan_access == Some(true),
        }));
        log::debug!("tailscale: ready");
        session.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestResolver;
    #[async_trait]
    impl Resolver for TestResolver {
        async fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
            if name == "lan.example" {
                Ok(vec!["192.168.1.5".parse().unwrap()])
            } else {
                Ok(vec!["8.8.8.8".parse().unwrap()])
            }
        }
    }
    #[tokio::test]
    async fn exit_resolution_preserves_lan_and_udp_acl_boundaries() {
        let key = ts_keys::NodeKeyPair::random().public.to_string();
        let mut snapshot = Snapshot::default();
        snapshot.apply(serde_json::json!({
            "Node": {"Addresses":["100.64.0.1/32"], "MachineAuthorized":true},
            "Peers": [{"ID":2,"Key":key,"Addresses":["100.64.0.2/32"],"MachineAuthorized":true,"HomeDERP":1,"AllowedIPs":["100.64.0.2/32","0.0.0.0/0"]}],
            "DNSConfig":{"Domains":["example.ts.net"]},
            "PacketFilter":[{"SrcIPs":["*"],"IPProto":[17],"DstPorts":[{"IP":"8.8.8.8/32","Ports":{"First":53,"Last":53}},{"IP":"192.168.1.5/32","Ports":{"First":53,"Last":53}}]}]
        })).unwrap();
        let wire = WireGuardSpec {
            peers: vec![derp::wire_peer(&snapshot.peers[0], 0, false, true)],
            private_key: [1; 32],
            address_v4: Some(("100.64.0.1".parse().unwrap(), 32)),
            address_v6: None,
            mtu: 1280,
            keepalive_secs: 0,
            udp: true,
            remote_dns: false,
            dns: vec![],
            amnezia: None,
            refresh_secs: None,
            tcp_buffers: Default::default(),
        };
        let datagrams = Arc::new(oryn_udp::UdpFactory);
        let tunnel = Tunnel::with_factory(wire, datagrams.clone());
        let ready = Ready {
            scope: "test".into(),
            snapshot,
            tunnel: tunnel.clone(),
            endpoints: vec![Some(derp::endpoint(0))],
            accept_routes: false,
            exit_peer: Some(0),
            exit_allow_lan: true,
        };
        let config = oryn_config::parse_config("proxies: [{name: T,type: tailscale}]").unwrap();
        let oryn_config::OutboundKind::Tailscale(spec) = config.outbounds[0].kind.clone() else {
            panic!()
        };
        let resolver = Arc::new(TestResolver);
        let ts = TailscaleOutbound::new(
            "T".into(),
            spec,
            Arc::new(crate::DirectDialer::new(resolver.clone())),
            resolver,
            datagrams,
            None,
        );
        let public = TargetAddr::Domain("public.example".into(), 53);
        assert_eq!(
            ts.session.resolve_target(&ready, &public).await.unwrap(),
            "8.8.8.8:53".parse().unwrap()
        );
        // PacketFilter 只管入站：过滤器只放行 8.8.8.8:53/udp，出站到其它端口仍允许（OrynCore#39）
        assert_eq!(
            ts.session
                .resolve_target(&ready, &TargetAddr::Ip("8.8.8.8:54".parse().unwrap()))
                .await
                .unwrap(),
            "8.8.8.8:54".parse().unwrap()
        );
        // exit node 允许本地 LAN 时，LAN 地址不经隧道；尾网里不存在的名字不外泄
        assert!(ts
            .session
            .resolve_target(&ready, &TargetAddr::Domain("lan.example".into(), 53))
            .await
            .is_err());
        assert!(ts
            .session
            .resolve_target(&ready, &TargetAddr::Domain("missing.example.ts.net".into(), 53))
            .await
            .is_err());
        tunnel.close();
    }
    #[test]
    fn persistent_identity_and_control_binding() {
        let dir = std::env::temp_dir().join(format!(
            "oryn-ts-identity-{}-{}",
            std::process::id(),
            snapshot::now()
        ));
        let config = oryn_config::parse_config("proxies: [{name: T,type: tailscale}]").unwrap();
        let oryn_config::OutboundKind::Tailscale(mut spec) = config
            .outbounds
            .iter()
            .find(|o| o.name == "T")
            .unwrap()
            .kind
            .clone()
        else {
            panic!()
        };
        let a = identity(&spec, Some(&dir)).unwrap();
        let b = identity(&spec, Some(&dir)).unwrap();
        assert_eq!(a.node_keys.public, b.node_keys.public);
        spec.control_url = "https://other.invalid".into();
        assert!(identity(&spec, Some(&dir)).is_err());
        spec.control_url = "https://controlplane.tailscale.com".into();
        std::fs::write(
            dir.join("tailscale-state/tailscale/identity.json"),
            b"broken",
        )
        .unwrap();
        assert!(identity(&spec, Some(&dir)).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
