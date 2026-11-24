//! 出站。
//!
//! 分层：`Protocol → Transport → Security → Dialer`。0.3.0 支持 raw / WebSocket、TLS 与 SOCKS5 / HTTP / SS / Trojan / VLESS；
//! DIRECT 本身就是最底层的 Dialer，也是一个 Outbound。
//!
//! 所有接口都是 `Send + Sync`，返回的 Future 也是 `Send`：出站可以在任意线程上使用，
//! 为以后把加解密放到小线程池留余地。只有 Netstack（lwIP）固定在事件循环线程上。

mod anytls;
mod chain;
mod direct;
mod group;
mod http;
#[cfg(feature = "hysteria2")]
mod hysteria;
#[cfg(feature = "hysteria2")]
mod hysteria2;
#[cfg(any(feature = "hysteria2", feature = "tuic"))]
mod inbox;
mod mieru;
mod smart;
/// Mieru UDP 会话的诊断统计增量，供设备自测使用。
pub use mieru::counters as mieru_counters;
/// WG / Tailscale 出站的进程级资源（工作线程、全局缓冲预算、内存压力），由 Core 按资源档位设置。
pub use oryn_wireguard::resources as wireguard_resources;
mod mux;
mod muxcool;
mod naive;
mod packet_encoding;
#[cfg(feature = "hysteria2")]
mod realm;
#[cfg(any(feature = "hysteria2", feature = "tuic"))]
mod reassembly;
mod reject;
#[cfg(feature = "quic")]
mod shadowquic;
mod shadowsocks;
mod slots;
mod snell;
mod socks5;
mod ss_plugin;
mod ssh;
mod ssr;
mod stream_proxy;
mod sudoku;
pub mod tailscale;
#[cfg(feature = "tuic")]
mod tuic;
mod uot;
mod vision;
#[cfg(feature = "wireguard")]
mod wireguard;

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use oryn_config::{OutboundKind, RuntimeConfig, TargetAddr, TlsSpec};
use tokio::io::{AsyncRead, AsyncWrite};

pub use direct::{DirectDialer, DirectOutbound};
pub use group::{
    resolve, GroupOutbound, GroupStatus, Health, HealthStore, MemberStatus, PickMeta, Resolved,
};
pub use http::HttpOutbound;
pub use reject::RejectOutbound;
pub use shadowsocks::ShadowsocksOutbound;
pub use socks5::Socks5Outbound;
pub use stream_proxy::{StreamProtocol, StreamProxyOutbound};

/// 建立连接（含代理握手）的超时。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// 出站返回的字节流，不绑定具体 socket 类型。
pub type BoxStream = Box<dyn AsyncStream>;

/// 域名解析。由 DNS Engine 实现，出站只用它解析代理服务器地址。
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

/// 最底层的拨号器。上层协议只依赖它提供的流，不直接创建 socket。
#[async_trait]
pub trait Dialer: Send + Sync {
    async fn dial_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream>;
}

/// 逐包寻址的数据报连接：每个数据报都带目的地址。
#[async_trait]
pub trait PacketConn: Send + Sync {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)>;
}

#[async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    /// 协议类型名称，策略组为其类型名（如 select）。
    fn kind(&self) -> &'static str;
    /// Smart 回退后实际建立连接的节点，供连接列表更新。
    fn actual_tag(&self) -> Option<String> {
        None
    }
    fn is_reject(&self) -> bool {
        false
    }
    fn as_group(&self) -> Option<&GroupOutbound> {
        None
    }
    /// Tailscale 出站（登录状态与登录 / 登出命令）。
    fn as_tailscale(&self) -> Option<&tailscale::TailscaleOutbound> {
        None
    }
    fn session_control(&self) -> Option<Arc<dyn SessionControl>> {
        None
    }
    fn dns_scope(&self) -> Option<String> {
        None
    }
    /// 出站内的身份 DNS；普通出站不提供。
    async fn query_dns(&self, _name: &str, _qtype: u16) -> io::Result<TailnetDnsAnswer> {
        Err(unsupported("outbound does not provide identity DNS"))
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream>;
    /// `first_target` 用于选择地址族等初始化工作；之后每个数据报仍各自带目的地址。
    async fn bind_udp(&self, first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>>;
}

/// 身份 DNS 的结构化结果；由 DNS Engine 生成有界 DNS 应答。
#[derive(Debug, Default)]
pub struct TailnetDnsAnswer {
    pub exists: bool,
    pub ips: Vec<IpAddr>,
    pub ptr: Option<String>,
}

/// QUIC / WireGuard 出站对网络切换和睡眠唤醒的响应。
pub trait SessionControl: Send + Sync {
    fn on_config_replaced(&self) {}
    fn on_network_changed(&self);
    fn on_sleep(&self);
    fn on_wake(&self);
}

#[cfg(feature = "quic")]
pub struct QuicControl(pub Arc<oryn_quic::QuicClient>);

#[cfg(feature = "quic")]
impl SessionControl for QuicControl {
    fn on_network_changed(&self) {
        self.0.on_network_changed();
    }
    fn on_sleep(&self) {
        self.0.on_sleep();
    }
    fn on_wake(&self) {
        self.0.on_wake();
    }
}

/// 创建出站所需的外部依赖。
pub struct BuildContext {
    /// 解析代理服务器域名（代理域名服务器 / 转发规则 / 引导 DNS）。
    pub proxy_resolver: Arc<dyn Resolver>,
    /// 解析 DIRECT 连接的目标域名（完整的 DNS 流程）。
    pub direct_resolver: Arc<dyn Resolver>,
    pub health: Arc<HealthStore>,
    /// select 策略组的已保存选择：策略组名称 → 成员名称。
    pub selections: HashMap<String, String>,
    /// 单个 Mieru 节点的活跃会话上限（资源档位化，见 issue #5）。
    pub mieru_sessions: usize,
}

/// 创建叶子出站所需的依赖。Smart 为每个服务器地址族传入受限的拨号器与解析器，
/// 因此各地址族变体拥有独立的连接池 / 会话，不共享任何状态。
pub(crate) struct LeafDeps<'a> {
    pub proxy_resolver: Arc<dyn Resolver>,
    pub direct_resolver: Arc<dyn Resolver>,
    pub direct_dialer: Arc<DirectDialer>,
    pub data_dir: Option<&'a std::path::Path>,
    pub mieru_sessions: usize,
}

/// 创建一个非策略组出站（含 SS / Trojan / VLESS / VMess 的多路复用包装）；策略组返回 `None`。
pub(crate) fn build_leaf(
    spec: &oryn_config::OutboundSpec,
    deps: &LeafDeps<'_>,
    dialer: Arc<dyn Dialer>,
    datagrams: Arc<dyn oryn_udp::DatagramFactory>,
) -> Option<Arc<dyn Outbound>> {
    let name = spec.name.clone();
    let data_dir = deps.data_dir;
    // 有 dialer-proxy 时 Tailscale 不做直连 UDP，只走 DERP（Oryn_dev/docs/oryncore/plans/plan-tailscale-disco.md）
    let direct_udp = spec.dialer.is_none();
    let o: Arc<dyn Outbound> = match &spec.kind {
        OutboundKind::Group(_) => return None,
        OutboundKind::Tailscale(spec) => tailscale::TailscaleOutbound::new(
            name,
            spec.clone(),
            dialer.clone(),
            deps.proxy_resolver.clone(),
            datagrams.clone(),
            data_dir,
            direct_udp,
        ),
        OutboundKind::Direct => Arc::new(DirectOutbound::new(name, deps.direct_dialer.clone())),
        OutboundKind::Reject => Arc::new(RejectOutbound::new(name)),
        OutboundKind::Socks5 {
            server,
            auth,
            udp,
            tls,
        } => Arc::new(Socks5Outbound::new(
            name,
            server.clone(),
            auth.clone(),
            *udp,
            tls.clone(),
            dialer.clone(),
            deps.proxy_resolver.clone(),
            datagrams.clone(),
        )),
        OutboundKind::Http { server, auth, tls } => Arc::new(HttpOutbound::new(
            name,
            server.clone(),
            auth.clone(),
            tls.clone(),
            dialer.clone(),
        )),
        OutboundKind::Shadowsocks {
            server,
            cipher,
            password,
            udp,
            plugin,
            uot,
            mux: _,
        } => Arc::new(ShadowsocksOutbound::new(
            name,
            server.clone(),
            cipher,
            password,
            *udp,
            *uot,
            if matches!(plugin, oryn_config::SsPlugin::None) {
                dialer.clone()
            } else {
                Arc::new(ss_plugin::PluginDialer {
                    inner: dialer.clone(),
                    plugin: plugin.clone(),
                    server: server.clone(),
                })
            },
            deps.proxy_resolver.clone(),
            datagrams.clone(),
        )),
        OutboundKind::Trojan { stream, password } => Arc::new(StreamProxyOutbound::new(
            name,
            stream.clone(),
            StreamProtocol::Trojan(password.clone()),
            dialer.clone(),
            datagrams.clone(),
            deps.proxy_resolver.clone(),
        )),
        OutboundKind::Vless { stream, uuid } => Arc::new(StreamProxyOutbound::new(
            name,
            stream.clone(),
            StreamProtocol::Vless(*uuid),
            dialer.clone(),
            datagrams.clone(),
            deps.proxy_resolver.clone(),
        )),
        OutboundKind::Vmess { stream, protocol } => Arc::new(StreamProxyOutbound::new(
            name,
            stream.clone(),
            StreamProtocol::Vmess(protocol.clone()),
            dialer.clone(),
            datagrams.clone(),
            deps.proxy_resolver.clone(),
        )),
        OutboundKind::Ssr(spec) => match ssr::SsrOutbound::new(
            name.clone(),
            spec,
            dialer.clone(),
            deps.proxy_resolver.clone(),
            datagrams.clone(),
        ) {
            Ok(o) => Arc::new(o),
            // 配置阶段已校验；这里失败只可能是实现不支持的组合，按拒绝处理
            Err(_) => Arc::new(RejectOutbound::new(name)),
        },
        OutboundKind::Sudoku(spec) => sudoku::SudokuOutbound::new(
            name,
            spec.clone(),
            dialer.clone(),
            deps.direct_resolver.clone(),
        ),
        #[cfg(feature = "quic")]
        OutboundKind::ShadowQuic(spec) => match shadowquic::ShadowQuicOutbound::new(
            name.clone(),
            spec.clone(),
            deps.proxy_resolver.clone(),
            deps.direct_resolver.clone(),
            datagrams.clone(),
        ) {
            Ok(outbound) => outbound,
            Err(_) => Arc::new(RejectOutbound::new(name)),
        },
        #[cfg(not(feature = "quic"))]
        OutboundKind::ShadowQuic(_) => Arc::new(RejectOutbound::new(name)),
        OutboundKind::Mieru(spec) => mieru::MieruOutbound::new(
            name,
            spec.clone(),
            dialer.clone(),
            deps.proxy_resolver.clone(),
            deps.direct_resolver.clone(),
            datagrams.clone(),
            deps.mieru_sessions,
        ),
        OutboundKind::Snell(spec) => snell::SnellOutbound::new(
            name,
            spec.clone(),
            dialer.clone(),
            deps.direct_resolver.clone(),
        ),
        OutboundKind::Naive(spec) => naive::NaiveOutbound::new(
            name,
            spec.clone(),
            dialer.clone(),
            deps.proxy_resolver.clone(),
            datagrams.clone(),
        ),
        OutboundKind::Ssh(spec) => match ssh::SshOutbound::new(
            name.clone(),
            spec.clone(),
            dialer.clone(),
            deps.direct_resolver.clone(),
            deps.data_dir,
        ) {
            Ok(o) => o,
            // 私钥 / 主机公钥无法解析：节点不可用，按拒绝处理
            Err(_) => Arc::new(RejectOutbound::new(name)),
        },
        OutboundKind::AnyTls(spec) => {
            let carrier = Arc::new(anytls::AnyCarrier::new(name, spec.clone(), dialer.clone()));
            Arc::new(mux::MuxOutbound::any(carrier, spec.clone()))
        }
        #[cfg(feature = "hysteria2")]
        OutboundKind::Hysteria2(spec) => hysteria2::Hysteria2Outbound::new(
            name,
            spec.clone(),
            deps.proxy_resolver.clone(),
            dialer.clone(),
            datagrams.clone(),
        ),
        #[cfg(not(feature = "hysteria2"))]
        OutboundKind::Hysteria2(_) => Arc::new(RejectOutbound::new(name)),
        #[cfg(feature = "hysteria2")]
        OutboundKind::Hysteria(spec) => hysteria::HysteriaOutbound::new(
            name,
            spec.clone(),
            deps.proxy_resolver.clone(),
            datagrams.clone(),
        ),
        #[cfg(not(feature = "hysteria2"))]
        OutboundKind::Hysteria(_) => Arc::new(RejectOutbound::new(name)),
        #[cfg(feature = "tuic")]
        OutboundKind::Tuic(spec) => tuic::TuicOutbound::new(
            name,
            spec.clone(),
            deps.proxy_resolver.clone(),
            datagrams.clone(),
        ),
        #[cfg(not(feature = "tuic"))]
        OutboundKind::Tuic(_) => Arc::new(RejectOutbound::new(name)),
        #[cfg(feature = "wireguard")]
        OutboundKind::WireGuard(spec) => wireguard::WireGuardOutbound::new(
            name,
            spec.clone(),
            deps.proxy_resolver.clone(),
            datagrams.clone(),
        ),
        #[cfg(not(feature = "wireguard"))]
        OutboundKind::WireGuard(_) => Arc::new(RejectOutbound::new(name)),
    };
    let mux_spec = match &spec.kind {
        OutboundKind::Trojan { stream, .. }
        | OutboundKind::Vless { stream, .. }
        | OutboundKind::Vmess { stream, .. } => stream.mux.as_ref(),
        OutboundKind::Shadowsocks { mux, .. } => mux.as_ref(),
        _ => None,
    };
    let o: Arc<dyn Outbound> = if let Some(mux) = mux_spec {
        let mut outbound = mux::MuxOutbound::new(o, mux.clone());
        let udp = match &spec.kind {
            OutboundKind::Shadowsocks { udp, .. } => *udp,
            OutboundKind::Trojan { stream, .. }
            | OutboundKind::Vless { stream, .. }
            | OutboundKind::Vmess { stream, .. } => stream.udp,
            _ => false,
        };
        outbound.set_udp(udp);
        Arc::new(outbound)
    } else {
        o
    };
    Some(o)
}

/// 按配置创建全部出站，下标与 `RuntimeConfig::outbounds` 一一对应。
///
/// 策略组按依赖顺序创建（成员先于策略组）；配置解析阶段已排除循环引用。
pub fn build_outbounds(config: &RuntimeConfig, ctx: &BuildContext) -> Vec<Arc<dyn Outbound>> {
    build_outbounds_with_data_dir(config, ctx, None)
}

pub fn build_outbounds_with_data_dir(
    config: &RuntimeConfig,
    ctx: &BuildContext,
    data_dir: Option<&std::path::Path>,
) -> Vec<Arc<dyn Outbound>> {
    let proxy_dialer = Arc::new(DirectDialer::new(ctx.proxy_resolver.clone()));
    let direct_dialer = Arc::new(DirectDialer::new(ctx.direct_resolver.clone()));
    let n = config.outbounds.len();
    let mut built: Vec<Option<Arc<dyn Outbound>>> = vec![None; n];

    #[allow(clippy::too_many_arguments)]
    fn build_one(
        i: usize,
        config: &RuntimeConfig,
        ctx: &BuildContext,
        proxy_dialer: &Arc<DirectDialer>,
        direct_dialer: &Arc<DirectDialer>,
        built: &mut Vec<Option<Arc<dyn Outbound>>>,
        visiting: &mut Vec<bool>,
        data_dir: Option<&std::path::Path>,
    ) -> Arc<dyn Outbound> {
        if let Some(o) = &built[i] {
            return o.clone();
        }
        let spec = &config.outbounds[i];
        let name = spec.name.clone();
        // 纵深防御：配置层已排除循环引用，但绕过它直接构造的 RuntimeConfig 不能让这里无限递归。
        // 正在构建中的出站再次被引用即为环，该引用退化为 REJECT。
        if visiting[i] {
            log::warn!("outbound {name} references itself through a cycle; using REJECT");
            return Arc::new(reject::RejectOutbound::new(name));
        }
        visiting[i] = true;
        // dialer-proxy：TCP 经另一个出站的 connect_tcp，UDP 经它的 bind_udp
        let chain: Option<Arc<dyn Outbound>> = spec.dialer.map(|d| {
            build_one(
                d,
                config,
                ctx,
                proxy_dialer,
                direct_dialer,
                built,
                visiting,
                data_dir,
            )
        });
        let dialer: Arc<dyn Dialer> = match &chain {
            Some(outbound) => Arc::new(chain::ChainDialer(outbound.clone())),
            None => proxy_dialer.clone(),
        };
        let datagrams: Arc<dyn oryn_udp::DatagramFactory> = match &chain {
            Some(outbound) => Arc::new(chain::ChainDatagrams(outbound.clone())),
            None => Arc::new(oryn_udp::UdpFactory),
        };
        let deps = LeafDeps {
            proxy_resolver: ctx.proxy_resolver.clone(),
            direct_resolver: ctx.direct_resolver.clone(),
            direct_dialer: direct_dialer.clone(),
            data_dir,
            mieru_sessions: ctx.mieru_sessions,
        };
        let o: Arc<dyn Outbound> = match &spec.kind {
            OutboundKind::Group(g) => {
                let members: Vec<Arc<dyn Outbound>> = g
                    .members
                    .iter()
                    .map(|&m| {
                        build_one(
                            m,
                            config,
                            ctx,
                            proxy_dialer,
                            direct_dialer,
                            built,
                            visiting,
                            data_dir,
                        )
                    })
                    .collect();
                let smart = if g.kind == oryn_config::GroupKind::Smart {
                    Some(smart::build(config, g, &members, ctx, &name, data_dir))
                } else {
                    None
                };
                let mut group = GroupOutbound::new(
                    name.clone(),
                    g.kind,
                    members,
                    g.health.clone(),
                    g.disable_udp,
                    ctx.health.clone(),
                    ctx.selections.get(&name).map(String::as_str),
                );
                group.smart = smart;
                Arc::new(group)
            }
            _ => build_leaf(spec, &deps, dialer, datagrams)
                .expect("non-group outbound kinds are always buildable"),
        };
        visiting[i] = false;
        built[i] = Some(o.clone());
        o
    }

    let mut visiting = vec![false; n];
    (0..n)
        .map(|i| {
            build_one(
                i,
                config,
                ctx,
                &proxy_dialer,
                &direct_dialer,
                &mut built,
                &mut visiting,
                data_dir,
            )
        })
        .collect()
}

/// 代理自身的 TLS（HTTPS 代理、SOCKS5 over TLS）。
pub(crate) async fn wrap_tls(
    stream: BoxStream,
    tls: &Option<TlsSpec>,
    server: &TargetAddr,
) -> io::Result<BoxStream> {
    let Some(tls) = tls else { return Ok(stream) };
    let host = match (&tls.sni, server) {
        (Some(sni), _) => sni.clone(),
        (None, TargetAddr::Domain(d, _)) => d.clone(),
        (None, TargetAddr::Ip(a)) => a.ip().to_string(),
    };
    let s = oryn_tls::connect_proxy(stream, &host, tls).await?;
    Ok(Box::new(s))
}

/// 取出（或创建）一条 QUIC 连接上共享的 UDP 分发器。
///
/// 检查与创建必须在同一把锁内完成：并发到来的第一批 UDP 会话如果各自「先查没有、再各建一个」，
/// 就会在同一条连接上出现多个分发器，它们抢着读数据报，回包被投递到没有该会话的分发器而丢失，
/// 会话 ID 也会重复（TUIC 的关联 ID 都从 1 开始），服务端把它们并成同一个关联，造成回包串会话。
/// `create` 在持锁期间调用，只能做同步工作（构造并 `tokio::spawn` 读取任务）。
pub(crate) fn shared_hub<T>(
    slot: &std::sync::Mutex<Option<Arc<T>>>,
    is_current: impl FnOnce(&T) -> bool,
    create: impl FnOnce() -> Arc<T>,
) -> Arc<T> {
    let mut slot = slot.lock().unwrap();
    if let Some(hub) = slot.as_ref() {
        if is_current(hub) {
            return hub.clone();
        }
    }
    let hub = create();
    *slot = Some(hub.clone());
    hub
}

#[cfg(test)]
mod frame_writer_tests;

/// 流上数据报帧的取消安全写出：整帧先放进 `pending`，已写进度保存在结构里。
/// `send_to` 中途被取消（上层 select! / 超时）时，下一次发送先补完这一帧，TCP 流内的帧边界不会错位。
pub(crate) struct FrameWriter<W> {
    io: W,
    pending: Vec<u8>,
    sent: usize,
    active: bool,
}

impl<W: tokio::io::AsyncWrite + Unpin> FrameWriter<W> {
    pub(crate) fn new(io: W) -> Self {
        Self {
            io,
            pending: Vec::new(),
            sent: 0,
            active: false,
        }
    }

    async fn drain(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        // 无旧帧时不能在保存新帧前 await flush：UoT / XUDP 已更新首次请求状态。
        if !self.active {
            return Ok(());
        }
        while self.sent < self.pending.len() {
            let n = self.io.write(&self.pending[self.sent..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.sent += n;
        }
        // flush 取消后仍保留屏障，下一帧不能越过上一帧的 flush。
        self.io.flush().await?;
        self.pending.clear();
        self.sent = 0;
        self.active = false;
        Ok(())
    }

    /// 写完上一帧的残留，再写出 `frame`。
    pub(crate) async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.drain().await?;
        self.pending = frame;
        self.active = true;
        self.drain().await
    }
}

/// 把收到的 UDP 载荷拷进调用方缓冲，返回拷贝长度。
///
/// 与 `recvfrom` 一样，缓冲不够时截断尾部；但截断会静默损坏 QUIC Initial、大 DNS 响应等，
/// 所以至少记一条 debug 日志，便于排查（各协议的 `recv_from` 统一走这里）。
/// 收 UDP 包用的 64 KiB 临时缓冲，按连接复用：每次 `recv_from` 不再重新分配并清零 64 KiB。
/// 内存与原来相同（读循环几乎总在等包，原来那块缓冲也一直活着），只是不再反复分配。
/// 并发调用时第二个调用方临时分配一块；守卫在取消时也会归还缓冲。
pub(crate) struct RecvScratch(std::sync::Mutex<Vec<u8>>);

impl RecvScratch {
    pub(crate) const SIZE: usize = 65535;

    pub(crate) fn new() -> Self {
        Self(std::sync::Mutex::new(Vec::new()))
    }

    pub(crate) fn take(&self) -> RecvScratchGuard<'_> {
        let mut buf = std::mem::take(&mut *self.0.lock().unwrap());
        if buf.len() != Self::SIZE {
            buf = vec![0; Self::SIZE];
        }
        RecvScratchGuard { slot: self, buf }
    }
}

pub(crate) struct RecvScratchGuard<'a> {
    slot: &'a RecvScratch,
    buf: Vec<u8>,
}

impl std::ops::Deref for RecvScratchGuard<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl std::ops::DerefMut for RecvScratchGuard<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Drop for RecvScratchGuard<'_> {
    fn drop(&mut self) {
        let mut slot = self.slot.0.lock().unwrap();
        if slot.is_empty() {
            *slot = std::mem::take(&mut self.buf);
        }
    }
}

pub(crate) fn copy_datagram(payload: &[u8], buf: &mut [u8], proto: &str) -> usize {
    let n = payload.len().min(buf.len());
    if n < payload.len() {
        log::debug!(
            "{proto}: UDP payload of {} bytes truncated to {n} bytes by receive buffer",
            payload.len()
        );
    }
    buf[..n].copy_from_slice(&payload[..n]);
    n
}

/// UDP 发送的瞬时错误：发送缓冲满（EAGAIN / ENOBUFS，蜂窝高负载常见）、路由暂时不可达等。
/// 丢掉这一个数据报符合 UDP 语义；不能据此拆掉共享载体上的全部会话。
pub(crate) fn is_transient_udp_send_error(err: &io::Error) -> bool {
    if matches!(
        err.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::NetworkDown
    ) {
        return true;
    }
    matches!(
        err.raw_os_error(),
        Some(libc::ENOBUFS | libc::EHOSTUNREACH | libc::ENETUNREACH | libc::ENETDOWN)
    )
}

pub(crate) fn unsupported(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg.to_string())
}

pub(crate) async fn with_timeout<T>(
    fut: impl std::future::Future<Output = io::Result<T>> + Send,
    what: &str,
) -> io::Result<T> {
    match tokio::time::timeout(CONNECT_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{what} timed out"),
        )),
    }
}

/// 把目标解析为 IP 列表。
pub(crate) async fn resolve_target(
    resolver: &dyn Resolver,
    target: &TargetAddr,
) -> io::Result<Vec<std::net::SocketAddr>> {
    match target {
        TargetAddr::Ip(a) => Ok(vec![*a]),
        TargetAddr::Domain(host, port) => {
            let ips = resolver.resolve(host).await?;
            if ips.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("cannot resolve {host}"),
                ));
            }
            Ok(ips
                .into_iter()
                .map(|ip| std::net::SocketAddr::new(ip, *port))
                .collect())
        }
    }
}

#[cfg(test)]
mod shared_hub_tests {
    use super::shared_hub;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};

    struct Hub {
        generation: usize,
    }

    /// 回归：并发的第一批会话只能创建一个分发器。
    /// 创建里故意睡一会儿放大「先查没有、再各建一个」的窗口。
    #[test]
    fn concurrent_first_sessions_create_one_hub() {
        let slot: Arc<Mutex<Option<Arc<Hub>>>> = Arc::new(Mutex::new(None));
        let created = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (slot, created, barrier) = (slot.clone(), created.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    shared_hub(
                        &slot,
                        |hub: &Hub| hub.generation == 1,
                        || {
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            created.fetch_add(1, Ordering::SeqCst);
                            Arc::new(Hub { generation: 1 })
                        },
                    )
                })
            })
            .collect();
        let hubs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(created.load(Ordering::SeqCst), 1);
        assert!(hubs.iter().all(|h| Arc::ptr_eq(h, &hubs[0])));
    }

    #[test]
    fn replaced_when_the_connection_changed() {
        let slot = Mutex::new(None);
        let first = shared_hub(
            &slot,
            |h: &Hub| h.generation == 1,
            || Arc::new(Hub { generation: 1 }),
        );
        let again = shared_hub(
            &slot,
            |h: &Hub| h.generation == 1,
            || Arc::new(Hub { generation: 9 }),
        );
        assert!(Arc::ptr_eq(&first, &again));
        // 连接换了（is_current 不再成立）：创建新的并替换
        let next = shared_hub(
            &slot,
            |h: &Hub| h.generation == 2,
            || Arc::new(Hub { generation: 2 }),
        );
        assert_eq!(next.generation, 2);
        assert!(!Arc::ptr_eq(&first, &next));
    }
}
