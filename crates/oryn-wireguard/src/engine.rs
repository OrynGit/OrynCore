//! boringtun 与 smoltcp 的单任务事件循环。
//!
//! IP 包只在本文件与 `device.rs` 之间流动；对外只有字节流（[`IoStream`]）与数据报（[`UdpSession`]）。
//! 循环睡到下一个计时器、外层套接字可读、用户读写或命令到达为止，不做固定间隔轮询。
//!
//! 一个隧道可以有多个对端：每个对端有自己的 Noise 会话、握手状态与端点；发往隧道的 IP 包按目的地址
//! 在各对端的 `allowed-ips` 里取最长前缀选择对端，收到的包的源地址也必须按同一规则归属发送对端。

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use oryn_config::{IpCidr as Cidr, WireGuardPeerSpec, WireGuardSpec, WireGuardTcpBuffers};
use oryn_udp::{DatagramFactory, Datagrams, UdpFactory};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;

use crate::amnezia::Amnezia;
use crate::device::VirtDevice;
use crate::dns;
use crate::frag::{self, Reassembler};
use crate::resources::{self, Lease, Pressure};

const TCP_CAP: usize = 64;
const UDP_CAP: usize = 16;
// smoltcp 每个 TCP 套接字的缓冲是动态的（方案见 Oryn_dev/docs/oryncore/plans/plan-wg-dynamic-tcp-buffer.md）：
// 从 `RX_INITIAL` / `TX_INITIAL` 开始，按吞吐翻倍到配置上限（见 `Tune`），空闲后收回（时长随内存压力，见
// `resources::Pressure`）；合计受本出站 `tcp-buffer-budget` 与进程级预算（`resources`）双重限制。单条连接的吞吐上限是 窗口 / RTT。
/// 外层通道一次唤醒最多取的数据报数（低于设备接收队列 64）。
const RECV_BATCH: usize = 32;
/// 接收一轮（一个缓冲容量的数据）在这个时间内完成且本端读得快时扩接收缓冲。
const GROW_ROUND: Duration = Duration::from_millis(250);
const UDP_PACKETS: usize = 8;
/// 交给用户 / 从用户取的单块上限与块数：每方向在 smoltcp 之外最多再缓冲 8 KiB。
const CHUNK: usize = 4 * 1024;
const USER_QUEUE: usize = 2;
/// 对端还没有会话时，发往它的包最多暂存的个数；再多的丢弃，由隧道内 TCP 重传。
const PEER_QUEUE: usize = 16;
/// boringtun 每 5 秒重发一次握手；15 秒内（3 次）没有会话就放弃并休眠。
const HANDSHAKE_GIVE_UP: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// 用户丢弃流后，等待 FIN 交换完成的时间，超时发 RST。
const LINGER: Duration = Duration::from_secs(10);
/// 有活动时 boringtun 计时器的检查间隔；无活动时不唤醒。
const TICK: Duration = Duration::from_secs(1);
const TIMER_MIN: Duration = Duration::from_millis(250);
/// boringtun 的 REKEY_AFTER_TIME：唤醒时会话比这更旧就做一次握手探测。
const REKEY_AFTER: Duration = Duration::from_secs(120);
/// boringtun 的 REJECT_AFTER_TIME：会话密钥最多用到这么久。探测失败时比这新的旧会话仍然有效，不能丢。
const REJECT_AFTER: Duration = Duration::from_secs(180);
/// 建外层通道（可能经 dialer-proxy）的期限：引擎是单任务事件循环，等待期间命令、收包、计时器全停。
const BIND_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_CACHE: usize = 32;
const DNS_TTL: Duration = Duration::from_secs(30);
const WIRE_BUF: usize = 4096;
const PORT_FIRST: u16 = 49152;
/// 外层通道创建失败后的最短重试间隔。
const BIND_RETRY: Duration = Duration::from_secs(1);

pub struct Tunnel {
    commands: mpsc::Sender<Command>,
    control: Arc<ControlState>,
    task: JoinHandle<()>,
    dns: Vec<SocketAddr>,
    v4: bool,
    v6: bool,
    cache: Mutex<VecDeque<(String, Instant, Vec<IpAddr>)>>,
}

/// 各对端的端点，按配置里的顺序；解析失败的对端为 None。
pub type Endpoints = Vec<Option<SocketAddr>>;

// 固定两个标志和每个配置 peer 一个地址；不随事件数增长。
#[derive(Default)]
struct PendingControl {
    network: bool,
    asleep: Option<bool>,
    endpoints: Endpoints,
}

struct ControlState {
    pending: Mutex<PendingControl>,
    notify: Notify,
}

impl ControlState {
    fn apply(&self, engine: &mut Engine) {
        let mut pending = self.pending.lock().unwrap();
        if std::mem::take(&mut pending.network) {
            engine.command(Command::NetworkChanged);
        }
        engine.use_endpoints(&pending.endpoints);
        pending.endpoints.fill(None);
        if let Some(asleep) = pending.asleep.take() {
            engine.command(if asleep {
                Command::Sleep
            } else {
                Command::Wake
            });
        }
    }
}

enum Command {
    Tcp {
        endpoints: Endpoints,
        dest: SocketAddr,
        reply: oneshot::Sender<io::Result<IoStream>>,
    },
    Udp {
        endpoints: Endpoints,
        reply: oneshot::Sender<io::Result<UdpSession>>,
    },
    NetworkChanged,
    Sleep,
    Wake,
}

/// 流两端共享的状态。
struct Shared {
    /// 连接被重置或握手失败；读到结尾时返回错误而不是 EOF。
    reset: AtomicBool,
    write_waker: Mutex<Option<Waker>>,
    notify: Arc<Notify>,
}

impl Shared {
    fn wake_writer(&self) {
        if let Some(waker) = self.write_waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

pub struct IoStream {
    incoming: mpsc::Receiver<Vec<u8>>,
    /// `poll_shutdown` 后置空：事件循环看到通道关闭即发送 FIN。
    outgoing: Option<mpsc::Sender<Vec<u8>>>,
    pending: Vec<u8>,
    pos: usize,
    shared: Arc<Shared>,
}

impl AsyncRead for IoStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos >= self.pending.len() {
            match self.incoming.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(if self.shared.reset.load(Ordering::Acquire) {
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "wireguard tcp connection reset",
                        ))
                    } else {
                        Ok(())
                    })
                }
                Poll::Ready(Some(bytes)) => {
                    self.pending = bytes;
                    self.pos = 0;
                    // 通道腾出空位，事件循环可以继续从 smoltcp 取数据
                    self.shared.notify.notify_one();
                }
            }
        }
        let start = self.pos;
        let n = (self.pending.len() - start).min(buf.remaining());
        buf.put_slice(&self.pending[start..start + n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for IoStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let closed = || {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wireguard stream closed",
            )))
        };
        if self.shared.reset.load(Ordering::Acquire) {
            return closed();
        }
        let Some(tx) = self.outgoing.as_ref() else {
            return closed();
        };
        let n = buf.len().min(CHUNK);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let chunk = match tx.try_send(buf[..n].to_vec()) {
            Ok(()) => {
                self.shared.notify.notify_one();
                return Poll::Ready(Ok(n));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return closed(),
            Err(mpsc::error::TrySendError::Full(chunk)) => chunk,
        };
        // 先登记唤醒再重试，避免事件循环在两步之间腾出空位而错过唤醒
        *self.shared.write_waker.lock().unwrap() = Some(cx.waker().clone());
        match tx.try_send(chunk) {
            Ok(()) => {
                self.shared.notify.notify_one();
                Poll::Ready(Ok(n))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => closed(),
            Err(mpsc::error::TrySendError::Full(_)) => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.outgoing = None;
        self.shared.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for IoStream {
    fn drop(&mut self) {
        self.shared.notify.notify_one();
    }
}

/// 隧道内的一个 UDP 套接字。满载时丢包，不阻塞。
pub struct UdpSession {
    outgoing: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    notify: Arc<Notify>,
    max_v4: Option<usize>,
    max_v6: Option<usize>,
}

impl UdpSession {
    pub fn send_to(&self, data: &[u8], dest: SocketAddr) -> io::Result<()> {
        let max = if dest.is_ipv4() {
            self.max_v4
        } else {
            self.max_v6
        };
        let Some(max) = max else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "wireguard has no address of this family",
            ));
        };
        if data.len() > max {
            return Err(io::Error::other(
                "wireguard udp packet exceeds 8192-byte ip packet limit",
            ));
        }
        match self.outgoing.try_send((data.to_vec(), dest)) {
            Ok(()) => {
                self.notify.notify_one();
                Ok(())
            }
            // 队列满：按设计丢弃
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wireguard stopped",
            )),
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.incoming.lock().await;
        let Some((data, from)) = rx.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wireguard stopped",
            ));
        };
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        self.notify.notify_one();
        Ok((n, from))
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.notify.notify_one();
    }
}

impl Tunnel {
    /// 外层数据报走普通 UDP 套接字。
    pub fn new(spec: WireGuardSpec) -> Arc<Self> {
        Self::with_factory(spec, Arc::new(UdpFactory))
    }

    /// 外层数据报经 `factory`：`dialer-proxy` 时经由另一个出站的 UDP。
    pub fn with_factory(spec: WireGuardSpec, factory: Arc<dyn DatagramFactory>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(32);
        let dns = spec.dns.clone();
        let v4 = spec.address_v4.is_some();
        let v6 = spec.address_v6.is_some();
        let control = Arc::new(ControlState {
            pending: Mutex::new(PendingControl {
                endpoints: vec![None; spec.peers.len()],
                ..Default::default()
            }),
            notify: Notify::new(),
        });
        // 引擎跑在 WG 工作线程上，不占用 Core 事件循环线程（resources.rs）
        let task = resources::spawn(run(Engine::new(spec, factory), rx, control.clone()));
        Arc::new(Self {
            commands: tx,
            control,
            task,
            dns,
            v4,
            v6,
            cache: Mutex::new(VecDeque::new()),
        })
    }

    /// 立即撤销隧道（身份或授权变化），关闭所有既有 Flow。
    pub fn close(&self) {
        self.task.abort();
    }

    pub fn on_network_changed(&self) {
        self.control.pending.lock().unwrap().network = true;
        self.control.notify.notify_one();
    }

    /// 更新各对端端点：网络变化后既有流也要改发到新地址，而不是等下一个新 Flow 带来。
    pub fn update_endpoints(&self, endpoints: &[Option<SocketAddr>]) {
        let mut pending = self.control.pending.lock().unwrap();
        for (slot, endpoint) in pending.endpoints.iter_mut().zip(endpoints) {
            if endpoint.is_some() {
                *slot = *endpoint;
            }
        }
        drop(pending);
        self.control.notify.notify_one();
    }

    pub fn on_sleep(&self) {
        self.control.pending.lock().unwrap().asleep = Some(true);
        self.control.notify.notify_one();
    }

    pub fn on_wake(&self) {
        self.control.pending.lock().unwrap().asleep = Some(false);
        self.control.notify.notify_one();
    }

    /// 在隧道内建立 TCP 连接，三次握手完成后返回。
    /// `endpoints` 仅初始化尚无地址的对端；地址刷新须调用 `update_endpoints`，
    /// 防止旧 Flow 或排队命令的快照回滚共享端点。
    pub async fn connect_tcp(
        &self,
        endpoints: &[Option<SocketAddr>],
        dest: SocketAddr,
    ) -> io::Result<IoStream> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Tcp {
            endpoints: endpoints.to_vec(),
            dest,
            reply,
        })
        .await?;
        rx.await
            .map_err(|_| io::Error::other("wireguard stopped"))?
    }

    /// 建立 UDP Flow。`endpoints` 仅用于初始化，刷新须调用 `update_endpoints`。
    pub async fn bind_udp(&self, endpoints: &[Option<SocketAddr>]) -> io::Result<UdpSession> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Udp {
            endpoints: endpoints.to_vec(),
            reply,
        })
        .await?;
        rx.await
            .map_err(|_| io::Error::other("wireguard stopped"))?
    }

    async fn send(&self, command: Command) -> io::Result<()> {
        self.commands
            .send(command)
            .await
            .map_err(|_| io::Error::other("wireguard stopped"))
    }

    /// 经隧道向配置的 `dns` 服务器查询（`remote-dns-resolve`）。答案只在本出站内缓存。
    /// `endpoints` 与 `bind_udp` 一样仅用于初始化，不刷新共享端点。
    pub async fn resolve(
        &self,
        endpoints: &[Option<SocketAddr>],
        host: &str,
    ) -> io::Result<Vec<IpAddr>> {
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(ips) = self.cached(&name) {
            return Ok(ips);
        }
        if self.dns.is_empty() {
            return Err(io::Error::other("wireguard dns servers are not configured"));
        }
        let session = self.bind_udp(endpoints).await?;
        let mut qtypes = Vec::new();
        if self.v4 {
            qtypes.push(dns::TYPE_A);
        }
        if self.v6 {
            qtypes.push(dns::TYPE_AAAA);
        }
        let mut buf = vec![0u8; 2048];
        for server in &self.dns {
            let base = dns::random_u64() as u16;
            let ids: Vec<u16> = (0..qtypes.len() as u16)
                .map(|i| base.wrapping_add(i))
                .collect();
            for (id, qtype) in ids.iter().zip(&qtypes) {
                session.send_to(&dns::build_query(*id, &name, *qtype), *server)?;
            }
            let deadline = tokio::time::Instant::now() + DNS_TIMEOUT;
            let mut answered = Vec::new();
            // 按查询顺序（A 在前）排列，不受应答到达先后影响
            let mut found: Vec<Vec<IpAddr>> = vec![Vec::new(); ids.len()];
            while answered.len() < ids.len() {
                let Ok(Ok((n, from))) =
                    tokio::time::timeout_at(deadline, session.recv_from(&mut buf)).await
                else {
                    break;
                };
                let reply = &buf[..n];
                let Some(id) = dns::id_of(reply) else {
                    continue;
                };
                if from != *server || !ids.contains(&id) || answered.contains(&id) {
                    continue;
                }
                if let Some(ips) = dns::parse_ips(reply) {
                    answered.push(id);
                    found[usize::from(id.wrapping_sub(base))] = ips;
                }
            }
            let ips: Vec<IpAddr> = found.into_iter().flatten().collect();
            if !ips.is_empty() {
                self.remember(name, ips.clone());
                return Ok(ips);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot resolve {host} through wireguard dns"),
        ))
    }

    fn cached(&self, name: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock().unwrap();
        cache.retain(|(_, at, _)| at.elapsed() < DNS_TTL);
        cache
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, _, ips)| ips.clone())
    }

    fn remember(&self, name: String, ips: Vec<IpAddr>) {
        let mut cache = self.cache.lock().unwrap();
        cache.retain(|(n, _, _)| *n != name);
        cache.push_back((name, Instant::now(), ips));
        while cache.len() > DNS_CACHE {
            cache.pop_front();
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Connect {
    reply: oneshot::Sender<io::Result<IoStream>>,
    stream: IoStream,
    deadline: Instant,
}

struct TcpFlow {
    handle: SocketHandle,
    port: u16,
    /// 当前 smoltcp 接收 / 发送缓冲容量，计入预算。
    rx_cap: usize,
    tx_cap: usize,
    tune: Tune,
    /// 全局缓冲预算里的份额，始终等于 `rx_cap + tx_cap`；连接释放时归还。
    lease: Lease,
    /// 这条连接经由哪个对端（按目的地址选定，之后不变）。
    peer: usize,
    connect: Option<Connect>,
    to_user: Option<mpsc::Sender<Vec<u8>>>,
    from_user: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    pos: usize,
    /// 用户关闭了写方向（shutdown 或丢弃）。
    write_done: bool,
    fin_sent: bool,
    peer_fin: bool,
    linger: Option<Instant>,
    /// 已发 RST，下一轮 poll 之后移除。
    dead: bool,
    shared: Arc<Shared>,
}

struct UdpFlow {
    handle: SocketHandle,
    port: u16,
    to_user: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    from_user: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
}

/// 外层数据报通道：每个地址族一个，由各对端按端点的地址族共用。
struct Wires {
    factory: Arc<dyn DatagramFactory>,
    v4: Option<Arc<dyn Datagrams>>,
    v6: Option<Arc<dyn Datagrams>>,
    failed_at: Option<Instant>,
}

impl Wires {
    fn channel(&self, endpoint: SocketAddr) -> Option<&Arc<dyn Datagrams>> {
        if endpoint.is_ipv6() {
            self.v6.as_ref()
        } else {
            self.v4.as_ref()
        }
    }

    /// 发出一条 WireGuard 消息。AmneziaWG 时先变形（含握手前的垃圾包）；否则写入保留字段。
    fn send(
        &self,
        amnezia: Option<&Amnezia>,
        endpoint: Option<SocketAddr>,
        reserved: [u8; 3],
        packet: &mut [u8],
    ) {
        let Some(endpoint) = endpoint else { return };
        let Some(channel) = self.channel(endpoint) else {
            return;
        };
        // 外层是 UDP：发送缓冲满时丢弃，由隧道内 TCP 重传
        match amnezia {
            Some(amnezia) => {
                for datagram in amnezia.outgoing(packet) {
                    let _ = channel.try_send_to(&datagram, endpoint);
                }
            }
            None => {
                if packet.len() >= 4 && reserved != [0, 0, 0] {
                    packet[1..4].copy_from_slice(&reserved);
                }
                let _ = channel.try_send_to(packet, endpoint);
            }
        }
    }
}

/// 一个对端：自己的 Noise 会话与握手状态。
struct Peer {
    public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    allowed: Vec<Cidr>,
    reserved: [u8; 3],
    tunn: Tunn,
    /// 交给 boringtun 的本地索引（24 位），收包时据此区分同一端点的多个对端。
    index: u32,
    endpoint: Option<SocketAddr>,
    /// 正在等待的握手从何时开始。
    handshake: Option<Instant>,
    /// 握手放弃后休眠：不发握手、不跑计时器，直到下一次使用、`wake` 或 `network_changed`。
    dormant: bool,
    /// 还没有会话时暂存发往本对端的包。
    queued: VecDeque<Vec<u8>>,
    /// 本对端的 persistent keepalive，覆盖接口级设置。
    keepalive: Option<u16>,
}

impl Peer {
    fn new(spec: &WireGuardPeerSpec, private_key: [u8; 32], keepalive_secs: u16) -> Self {
        let index = (dns::random_u64() as u32) >> 8;
        let keepalive_secs = spec.keepalive_secs.unwrap_or(keepalive_secs);
        Self {
            public_key: spec.public_key,
            preshared_key: spec.preshared_key,
            allowed: spec.allowed_ips.clone(),
            reserved: spec.reserved,
            tunn: new_tunn(
                private_key,
                spec.public_key,
                spec.preshared_key,
                keepalive_secs,
                index,
            ),
            index,
            endpoint: None,
            handshake: None,
            dormant: false,
            queued: VecDeque::new(),
            keepalive: spec.keepalive_secs,
        }
    }

    /// 丢掉会话与进行中的握手，下次发送时重新握手。
    fn reset(&mut self, private_key: [u8; 32], keepalive_secs: u16) {
        let keepalive_secs = self.keepalive.unwrap_or(keepalive_secs);
        self.tunn = new_tunn(
            private_key,
            self.public_key,
            self.preshared_key,
            keepalive_secs,
            self.index,
        );
        self.handshake = None;
        self.queued.clear();
    }

    fn has_session(&self) -> bool {
        self.tunn.time_since_last_handshake().is_some()
    }
}

struct Engine {
    spec: WireGuardSpec,
    peers: Vec<Peer>,
    wires: Wires,
    amnezia: Option<Amnezia>,
    device: VirtDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: Vec<TcpFlow>,
    udp: Vec<UdpFlow>,
    scratch: Vec<u8>,
    notify: Arc<Notify>,
    asleep: bool,
    last_timer: Option<Instant>,
    next_port: u16,
    /// 收到的分片在交给 smoltcp 之前重组。
    reassembly: Reassembler,
    /// 自行切片的 UDP 数据报使用的标识（IPv4 取低 16 位）。
    next_ident: u32,
}

fn new_tunn(
    private_key: [u8; 32],
    public_key: [u8; 32],
    preshared: Option<[u8; 32]>,
    keepalive_secs: u16,
    index: u32,
) -> Tunn {
    let keepalive = (keepalive_secs > 0).then_some(keepalive_secs);
    Tunn::new(
        StaticSecret::from(private_key),
        PublicKey::from(public_key),
        preshared,
        keepalive,
        index,
        None,
    )
}

/// 动态缓冲的观测状态（每条 TCP 一份，固定大小）。
///
/// 接收方向参照 Linux 的接收端自动调优：收满一个缓冲容量的数据算一「轮」。一轮在 `GROW_ROUND` 内完成、
/// 并且本端读得快（这一轮里缓冲至少有一次降到 1/4 以下）时扩容。读得慢的连接缓冲一直排不空，不扩；
/// 慢流量一轮要很久，也不扩。接收缓冲最终大约是「吞吐 × GROW_ROUND」，再受上限与预算约束。
struct Tune {
    /// 本轮结束时的累计接收字节（交给用户的 + 缓冲中的）；0 表示还没开始。
    rx_round_end: u64,
    rx_round_start: Instant,
    /// 本轮里缓冲降到过 1/4 以下（本端读得上）。
    rx_round_drained: bool,
    /// 已交给用户的累计字节。
    rx_delivered: u64,
    /// 下一轮 `tune` 扩接收缓冲。
    rx_grow: bool,
    /// 有待发数据而发送缓冲已满。
    tx_blocked: bool,
    /// 写进 smoltcp 的累计字节；减去 `send_queue` 即累计已确认。
    tx_enqueued: u64,
    /// 上次扩发送缓冲时的累计已确认字节。
    tx_acked_mark: u64,
    last_active: Instant,
}

impl Tune {
    fn new(now: Instant) -> Self {
        Self {
            rx_round_end: 0,
            rx_round_start: now,
            rx_round_drained: false,
            rx_delivered: 0,
            rx_grow: false,
            tx_blocked: false,
            tx_enqueued: 0,
            tx_acked_mark: 0,
            last_active: now,
        }
    }

    /// 本端取走数据之后看接收方向：`cap` 当前接收缓冲容量，`queued` 取完后仍在缓冲里的字节。
    fn after_read(&mut self, now: Instant, cap: usize, queued: usize) {
        let received = self.rx_delivered + queued as u64;
        let drained = queued <= cap / 4;
        if self.rx_round_end == 0 {
            self.rx_round_end = received + cap as u64;
            self.rx_round_start = now;
            self.rx_round_drained = drained;
            return;
        }
        self.rx_round_drained |= drained;
        if received < self.rx_round_end {
            return;
        }
        if self.rx_round_drained && now.saturating_duration_since(self.rx_round_start) <= GROW_ROUND
        {
            self.rx_grow = true;
        }
        self.rx_round_end = received + cap as u64;
        self.rx_round_start = now;
        self.rx_round_drained = drained;
    }

    /// 发送缓冲已满时是否应该扩：对端窗口放得下更多，且上次扩容后已确认至少半个缓冲（连接在前进）。
    fn tx_should_grow(&self, cap: usize, remote_window: usize, acked: u64) -> bool {
        self.tx_blocked
            && remote_window >= cap
            && acked.saturating_sub(self.tx_acked_mark) >= (cap / 2) as u64
    }
}

/// 新连接的初始缓冲（不超过配置上限）。
fn initial_buffers(cfg: &WireGuardTcpBuffers) -> (usize, usize) {
    (
        cfg.rx.min(WireGuardTcpBuffers::RX_INITIAL),
        cfg.tx.min(WireGuardTcpBuffers::TX_INITIAL),
    )
}

/// 扩容后的容量：翻倍且不超过上限，合计 `used` 加上增量不超预算；不能扩时返回 None。
fn grown(cap: usize, max: usize, used: usize, budget: usize) -> Option<usize> {
    if cap >= max {
        return None;
    }
    let new = cap.saturating_mul(2).min(max);
    (used.saturating_add(new - cap) <= budget).then_some(new)
}

fn now_smol() -> smoltcp::time::Instant {
    smoltcp::time::Instant::now()
}

fn to_ip(addr: IpAddr) -> IpAddress {
    match addr {
        IpAddr::V4(ip) => IpAddress::Ipv4(Ipv4Address::from(ip)),
        IpAddr::V6(ip) => IpAddress::Ipv6(Ipv6Address::from(ip)),
    }
}

fn from_endpoint(endpoint: IpEndpoint) -> SocketAddr {
    let ip = match endpoint.addr {
        IpAddress::Ipv4(ip) => IpAddr::V4(Ipv4Addr::from(ip.0)),
        IpAddress::Ipv6(ip) => IpAddr::V6(Ipv6Addr::from(ip.0)),
    };
    SocketAddr::new(ip, endpoint.port)
}

fn next_port(next: &mut u16, used: impl Fn(u16) -> bool) -> Option<u16> {
    for _ in 0..=(u16::MAX - PORT_FIRST) {
        let port = *next;
        *next = if port == u16::MAX {
            PORT_FIRST
        } else {
            port + 1
        };
        if !used(port) {
            return Some(port);
        }
    }
    None
}

/// IP 包的目的地址。
fn packet_dest(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// 全局最长前缀归属；相同前缀保持原发送侧语义：配置顺序中首个对端优先。
/// 只借用 peers，避免收包时借用整个 Engine（解密结果仍借用 scratch），无需复制或分配。
fn peer_for_ip(peers: &[Peer], ip: IpAddr) -> Option<usize> {
    let mut best: Option<(u8, usize)> = None;
    for (i, peer) in peers.iter().enumerate() {
        for cidr in &peer.allowed {
            if cidr.contains(ip) && best.is_none_or(|(prefix, _)| cidr.prefix() > prefix) {
                best = Some((cidr.prefix(), i));
            }
        }
    }
    best.map(|(_, i)| i)
}

impl Engine {
    fn new(spec: WireGuardSpec, factory: Arc<dyn DatagramFactory>) -> Self {
        let mut device = VirtDevice::new(usize::from(spec.mtu));
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = dns::random_u64();
        let mut iface = Interface::new(config, &mut device, now_smol());
        iface.update_ip_addrs(|addrs| {
            if let Some((ip, prefix)) = spec.address_v4 {
                addrs
                    .push(IpCidr::new(IpAddress::Ipv4(ip.into()), prefix))
                    .ok();
            }
            if let Some((ip, prefix)) = spec.address_v6 {
                addrs
                    .push(IpCidr::new(IpAddress::Ipv6(ip.into()), prefix))
                    .ok();
            }
        });
        // medium-ip 没有邻居发现，网关只用于让 smoltcp 认为目标可达
        if let Some((ip, _)) = spec.address_v4 {
            let _ = iface.routes_mut().add_default_ipv4_route(ip.into());
        }
        if let Some((ip, _)) = spec.address_v6 {
            let _ = iface.routes_mut().add_default_ipv6_route(ip.into());
        }
        let span = u32::from(u16::MAX - PORT_FIRST) + 1;
        let next_port = PORT_FIRST + (dns::random_u64() % u64::from(span)) as u16;
        let peers = spec
            .peers
            .iter()
            .map(|peer| Peer::new(peer, spec.private_key, spec.keepalive_secs))
            .collect();
        Self {
            peers,
            wires: Wires {
                factory,
                v4: None,
                v6: None,
                failed_at: None,
            },
            amnezia: spec.amnezia.map(Amnezia::new),
            spec,
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            tcp: Vec::new(),
            udp: Vec::new(),
            scratch: vec![0; WIRE_BUF],
            notify: Arc::new(Notify::new()),
            asleep: false,
            last_timer: None,
            next_port,
            reassembly: Reassembler::default(),
            next_ident: dns::random_u64() as u32,
        }
    }

    /// 为已知端点的地址族补建缺失的外层通道。创建失败时最多每秒重试一次。
    async fn ensure_wires(&mut self) {
        for v6 in [false, true] {
            let present = if v6 {
                self.wires.v6.is_some()
            } else {
                self.wires.v4.is_some()
            };
            if present {
                continue;
            }
            let Some(endpoint) = self
                .peers
                .iter()
                .filter_map(|p| p.endpoint)
                .find(|e| e.is_ipv6() == v6)
            else {
                continue;
            };
            if self
                .wires
                .failed_at
                .is_some_and(|at| at.elapsed() < BIND_RETRY)
            {
                return;
            }
            let bound =
                match tokio::time::timeout(BIND_TIMEOUT, self.wires.factory.bind(endpoint)).await {
                    Ok(result) => result,
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "wireguard outer channel bind timed out",
                    )),
                };
            match bound {
                Ok(channel) => {
                    self.wires.failed_at = None;
                    if v6 {
                        self.wires.v6 = Some(channel);
                    } else {
                        self.wires.v4 = Some(channel);
                    }
                }
                Err(err) => {
                    log::debug!("wireguard: bind failed: {err}");
                    self.wires.failed_at = Some(Instant::now());
                }
            }
        }
    }

    /// 发送目的地址与接收源地址共用全局归属规则。
    fn peer_for(&self, ip: IpAddr) -> Option<usize> {
        peer_for_ip(&self.peers, ip)
    }

    fn command(&mut self, command: Command) {
        match command {
            Command::Tcp {
                endpoints,
                dest,
                reply,
            } => {
                self.initialize_endpoints(&endpoints);
                let Some(peer) = self.peer_for(dest.ip()) else {
                    let _ = reply.send(Err(io::Error::other("destination is outside allowed-ips")));
                    return;
                };
                if self.peers[peer].endpoint.is_none() {
                    let _ = reply.send(Err(io::Error::other("cannot resolve wireguard endpoint")));
                    return;
                }
                self.peers[peer].dormant = false;
                match self.open_tcp(dest, peer) {
                    Ok((mut flow, stream)) => {
                        flow.connect = Some(Connect {
                            reply,
                            stream,
                            deadline: Instant::now() + CONNECT_TIMEOUT,
                        });
                        self.tcp.push(flow);
                    }
                    Err(err) => {
                        let _ = reply.send(Err(err));
                    }
                }
            }
            Command::Udp { endpoints, reply } => {
                self.initialize_endpoints(&endpoints);
                for peer in &mut self.peers {
                    peer.dormant = false;
                }
                let _ = reply.send(self.open_udp());
            }
            Command::NetworkChanged => {
                // 丢掉外层通道与会话，下次发送时重新握手；隧道内的 TCP 状态保留
                self.wires.v4 = None;
                self.wires.v6 = None;
                self.wires.failed_at = None;
                for peer in &mut self.peers {
                    peer.reset(self.spec.private_key, self.spec.keepalive_secs);
                    peer.dormant = false;
                }
            }
            Command::Sleep => self.asleep = true,
            Command::Wake => {
                self.asleep = false;
                self.last_timer = None;
                for i in 0..self.peers.len() {
                    self.peers[i].dormant = false;
                    let has_flows = self.tcp.iter().any(|f| f.peer == i) || !self.udp.is_empty();
                    // 会话已过期（睡眠超过 REKEY_AFTER）且有流时先做握手探测；只发 keepalive 会用
                    // 可能已失效的密钥，要等计时器兜底才恢复。没有流的对端不探测，下次使用时再握手。
                    match self.peers[i].tunn.time_since_last_handshake() {
                        Some(age) if age >= REKEY_AFTER && has_flows => self.probe(i),
                        Some(age) if age < REKEY_AFTER && self.spec.keepalive_secs > 0 => {
                            if let TunnResult::WriteToNetwork(out) =
                                self.peers[i].tunn.encapsulate(&[], &mut self.scratch)
                            {
                                self.wires.send(
                                    self.amnezia.as_ref(),
                                    self.peers[i].endpoint,
                                    self.peers[i].reserved,
                                    out,
                                );
                            }
                        }
                        None if has_flows => self.probe(i),
                        _ => {}
                    }
                }
            }
        }
    }

    // Flow 的快照只可初始化，刷新必须经独立控制面；排队的旧 Flow 不得回滚新地址。
    fn initialize_endpoints(&mut self, endpoints: &[Option<SocketAddr>]) {
        for (peer, endpoint) in self.peers.iter_mut().zip(endpoints) {
            if peer.endpoint.is_none() {
                peer.endpoint = *endpoint;
            }
        }
    }

    /// 记下各对端当前解析到的端点。对端换了地址：旧会话对新地址无效，丢掉重新握手。
    fn use_endpoints(&mut self, endpoints: &[Option<SocketAddr>]) {
        for (i, endpoint) in endpoints.iter().enumerate().take(self.peers.len()) {
            let Some(endpoint) = *endpoint else { continue };
            let peer = &mut self.peers[i];
            if peer.endpoint != Some(endpoint) {
                if peer.endpoint.is_some() {
                    peer.reset(self.spec.private_key, self.spec.keepalive_secs);
                }
                peer.endpoint = Some(endpoint);
            }
        }
    }

    fn family_ok(&self, ip: IpAddr) -> io::Result<()> {
        let ok = match ip {
            IpAddr::V4(_) => self.spec.address_v4.is_some(),
            IpAddr::V6(_) => self.spec.address_v6.is_some(),
        };
        if ok {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "wireguard has no address of this family",
            ))
        }
    }

    fn open_tcp(&mut self, dest: SocketAddr, peer: usize) -> io::Result<(TcpFlow, IoStream)> {
        if self.tcp.len() >= TCP_CAP {
            return Err(io::Error::other("wireguard tcp socket limit reached"));
        }
        self.family_ok(dest.ip())?;
        let cfg = self.spec.tcp_buffers;
        let (rx, tx) = initial_buffers(&cfg);
        if self.buffer_used() + rx + tx > cfg.budget {
            return Err(io::Error::other("wireguard tcp buffer budget exhausted"));
        }
        // 全部 WG / Tailscale 出站共享的进程级预算（按资源档位区分平台）
        let lease = Lease::acquire(rx + tx)
            .ok_or_else(|| io::Error::other("wireguard tcp buffer budget exhausted"))?;
        let tcp = &self.tcp;
        let port = next_port(&mut self.next_port, |p| tcp.iter().any(|f| f.port == p))
            .ok_or_else(|| io::Error::other("wireguard tcp ports exhausted"))?;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; rx]),
            tcp::SocketBuffer::new(vec![0; tx]),
        );
        // 窗口缩放按上限协商，之后接收缓冲才能扩到上限
        socket.set_rx_capacity_max(cfg.rx);
        socket.set_nagle_enabled(false);
        // smoltcp 默认延迟 ACK 10 ms：接收缓冲填满后，窗口更新也要等这 10 ms，下行吞吐因此降到原来的约 1/18
        //（Oryn_dev/docs/oryncore/measurements/wireguard-cpu-2026-11-18.md）。每个数据段立即 ACK。
        socket.set_ack_delay(None);
        socket
            .connect(
                self.iface.context(),
                IpEndpoint::new(to_ip(dest.ip()), dest.port()),
                port,
            )
            .map_err(|err| io::Error::other(format!("wireguard tcp connect: {err:?}")))?;
        let handle = self.sockets.add(socket);
        let (to_user, incoming) = mpsc::channel(USER_QUEUE);
        let (outgoing, from_user) = mpsc::channel(USER_QUEUE);
        let shared = Arc::new(Shared {
            reset: AtomicBool::new(false),
            write_waker: Mutex::new(None),
            notify: self.notify.clone(),
        });
        let flow = TcpFlow {
            handle,
            port,
            rx_cap: rx,
            tx_cap: tx,
            tune: Tune::new(Instant::now()),
            lease,
            peer,
            connect: None,
            to_user: Some(to_user),
            from_user,
            pending: Vec::new(),
            pos: 0,
            write_done: false,
            fin_sent: false,
            peer_fin: false,
            linger: None,
            dead: false,
            shared: shared.clone(),
        };
        let stream = IoStream {
            incoming,
            outgoing: Some(outgoing),
            pending: Vec::new(),
            pos: 0,
            shared,
        };
        Ok((flow, stream))
    }

    fn open_udp(&mut self) -> io::Result<UdpSession> {
        if !self.spec.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "wireguard udp is disabled",
            ));
        }
        if self.udp.len() >= UDP_CAP {
            return Err(io::Error::other("wireguard udp socket limit reached"));
        }
        let udp = &self.udp;
        let port = next_port(&mut self.next_port, |p| udp.iter().any(|f| f.port == p))
            .ok_or_else(|| io::Error::other("wireguard udp ports exhausted"))?;
        let mtu = usize::from(self.spec.mtu);
        // 至少放得下一个重组后的最大数据报
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; (UDP_PACKETS * mtu).max(frag::MAX_PACKET)],
            )
        };
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket
            .bind(port)
            .map_err(|err| io::Error::other(format!("wireguard udp bind: {err:?}")))?;
        let handle = self.sockets.add(socket);
        let (to_user, incoming) = mpsc::channel(UDP_PACKETS);
        let (outgoing, from_user) = mpsc::channel(UDP_PACKETS);
        self.udp.push(UdpFlow {
            handle,
            port,
            to_user,
            from_user,
        });
        Ok(UdpSession {
            outgoing,
            incoming: tokio::sync::Mutex::new(incoming),
            notify: self.notify.clone(),
            max_v4: self.spec.address_v4.map(|_| frag::MAX_PACKET - 28),
            max_v6: self.spec.address_v6.map(|_| frag::MAX_PACKET - 48),
        })
    }

    /// 处理一个外层数据报。
    fn incoming(&mut self, data: &mut [u8], from: SocketAddr) {
        if !self.peers.iter().any(|p| p.endpoint == Some(from)) {
            return;
        }
        // AmneziaWG：先还原成标准 WireGuard 消息；垃圾包与无法识别的数据报丢弃
        let mut restored;
        let data: &mut [u8] = match &self.amnezia {
            Some(amnezia) => match amnezia.incoming(data) {
                Some(message) => {
                    restored = message;
                    &mut restored
                }
                None => return,
            },
            None => {
                // 合法消息的第 2–4 字节为 0；对端（如带保留字段的服务）可能写入，交给 boringtun 前清零
                if data.len() > 3 {
                    data[1..4].fill(0);
                }
                data
            }
        };
        // 同一端点可能配了多个对端（同一服务器、不同公钥）：按消息里的接收方索引选对端。
        // boringtun 的本地会话索引是 `对端索引 << 8 | 会话号`；握手发起（类型 1）没有接收方索引，取第一个。
        let receiver = match data.first() {
            Some(2) if data.len() >= 12 => {
                Some(u32::from_le_bytes(data[8..12].try_into().unwrap()))
            }
            Some(3 | 4) if data.len() >= 8 => {
                Some(u32::from_le_bytes(data[4..8].try_into().unwrap()))
            }
            _ => None,
        };
        let by_index = receiver.and_then(|r| {
            self.peers
                .iter()
                .position(|p| p.endpoint == Some(from) && p.index == r >> 8)
        });
        let Some(i) = by_index.or_else(|| self.peers.iter().position(|p| p.endpoint == Some(from)))
        else {
            return;
        };
        // 握手响应（类型 2）被 boringtun 接受就是握手完成。不能用 `time_since_last_handshake` 与开始时间比较：
        // boringtun 的「当前时间」只在 `update_timers` 时更新，会话建立时刻可能早于开始时刻，
        // 比较永远不成立，15 秒后会误判为握手超时并重置所有连接。
        let is_response = data.first() == Some(&2);
        let mut rejected = false;
        let amnezia = self.amnezia.as_ref();
        let endpoint = self.peers[i].endpoint;
        let reserved = self.peers[i].reserved;
        match self.peers[i]
            .tunn
            .decapsulate(Some(from.ip()), data, &mut self.scratch)
        {
            TunnResult::WriteToNetwork(out) => {
                self.wires.send(amnezia, endpoint, reserved, out);
                // boringtun 要求重复调用，直到把它内部排队的包发完
                while let TunnResult::WriteToNetwork(out) =
                    self.peers[i].tunn.decapsulate(None, &[], &mut self.scratch)
                {
                    self.wires.send(amnezia, endpoint, reserved, out);
                }
            }
            TunnResult::WriteToTunnelV4(packet, src) => {
                if peer_for_ip(&self.peers, IpAddr::V4(src)) == Some(i) {
                    if let Some(packet) = self.reassembly.push(packet.to_vec(), Instant::now()) {
                        self.device.push_rx(packet);
                    }
                }
            }
            TunnResult::WriteToTunnelV6(packet, src) => {
                if peer_for_ip(&self.peers, IpAddr::V6(src)) == Some(i) {
                    if let Some(packet) = self.reassembly.push(packet.to_vec(), Instant::now()) {
                        self.device.push_rx(packet);
                    }
                }
            }
            TunnResult::Err(err) => {
                rejected = true;
                log::debug!("wireguard: dropped packet: {err:?}");
            }
            TunnResult::Done => {}
        }
        if is_response && !rejected {
            self.peers[i].handshake = None;
            // 会话建立：发出握手期间暂存的包
            while let Some(packet) = self.peers[i].queued.pop_front() {
                self.encapsulate(i, &packet);
            }
        }
    }

    /// 推进一轮：用户数据进 smoltcp、smoltcp 处理、加密发出、结果交给用户。
    fn pump(&mut self) {
        let now = Instant::now();
        self.timers(now);
        self.reassembly.expire(now);
        for _ in 0..4 {
            self.feed();
            let changed = self
                .iface
                .poll(now_smol(), &mut self.device, &mut self.sockets);
            self.flush();
            let delivered = self.service(now);
            let resized = self.tune(now);
            if !changed && !delivered && !resized {
                break;
            }
        }
        self.check_handshakes(now);
    }

    fn timers(&mut self, now: Instant) {
        if self.asleep {
            return;
        }
        if self.last_timer.is_some_and(|last| now - last < TIMER_MIN) {
            return;
        }
        self.last_timer = Some(now);
        for i in 0..self.peers.len() {
            if self.peers[i].dormant {
                continue;
            }
            if let TunnResult::WriteToNetwork(out) =
                self.peers[i].tunn.update_timers(&mut self.scratch)
            {
                self.wires.send(
                    self.amnezia.as_ref(),
                    self.peers[i].endpoint,
                    self.peers[i].reserved,
                    out,
                );
            }
        }
    }

    fn handshake_done(&self, i: usize, started: Instant) -> bool {
        self.peers[i]
            .tunn
            .time_since_last_handshake()
            .is_some_and(|age| age <= started.elapsed())
    }

    fn check_handshakes(&mut self, now: Instant) {
        for i in 0..self.peers.len() {
            let Some(started) = self.peers[i].handshake else {
                continue;
            };
            if self.handshake_done(i, started) {
                self.peers[i].handshake = None;
            } else if now - started >= HANDSHAKE_GIVE_UP {
                // 唤醒探测（或 rekey）没有回应，但旧会话还没到 REJECT_AFTER：保留它与经由它的流，
                // 交给 boringtun 计时器继续 rekey（网络稍后恢复时旧会话可以直接继续用）。
                // 只有确实没有可用会话时才放弃、重置并休眠。
                let session_valid = self.peers[i]
                    .tunn
                    .time_since_last_handshake()
                    .is_some_and(|age| age < REJECT_AFTER);
                if session_valid {
                    log::debug!("wireguard: handshake probe unanswered, keeping current session");
                    self.peers[i].handshake = None;
                } else {
                    self.give_up(i);
                }
            }
        }
    }

    /// 没有会话时开始握手；进行中则不重复（boringtun 自己按 5 秒重发）。
    fn start_handshake(&mut self, i: usize) {
        if self.peers[i].handshake.is_some() {
            return;
        }
        self.peers[i].handshake = Some(Instant::now());
        if let TunnResult::WriteToNetwork(out) = self.peers[i]
            .tunn
            .format_handshake_initiation(&mut self.scratch, false)
        {
            self.wires.send(
                self.amnezia.as_ref(),
                self.peers[i].endpoint,
                self.peers[i].reserved,
                out,
            );
        }
    }

    /// 唤醒后的握手探测：无论是否已有会话都重新握手，失败的处理与普通握手相同。
    fn probe(&mut self, i: usize) {
        self.peers[i].handshake = Some(Instant::now());
        if let TunnResult::WriteToNetwork(out) = self.peers[i]
            .tunn
            .format_handshake_initiation(&mut self.scratch, true)
        {
            self.wires.send(
                self.amnezia.as_ref(),
                self.peers[i].endpoint,
                self.peers[i].reserved,
                out,
            );
        }
    }

    /// 放弃握手：重置本对端、让经由它的 TCP 连接失败，并休眠到下一次使用。
    fn give_up(&mut self, i: usize) {
        log::debug!("wireguard: handshake timed out, sleeping until next use");
        self.peers[i].reset(self.spec.private_key, self.spec.keepalive_secs);
        self.peers[i].dormant = true;
        let flows = std::mem::take(&mut self.tcp);
        for flow in flows {
            if flow.peer != i {
                self.tcp.push(flow);
                continue;
            }
            flow.shared.reset.store(true, Ordering::Release);
            flow.shared.wake_writer();
            if let Some(connect) = flow.connect {
                let _ = connect.reply.send(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "wireguard handshake timed out",
                )));
            }
            self.sockets.remove(flow.handle);
        }
    }

    /// 加密一个 IP 包并发出；对端没有会话时由调用方先处理。
    fn encapsulate(&mut self, i: usize, packet: &[u8]) {
        if self.scratch.len() < packet.len() + 148 {
            self.scratch.resize(packet.len() + 148, 0);
        }
        if let TunnResult::WriteToNetwork(out) =
            self.peers[i].tunn.encapsulate(packet, &mut self.scratch)
        {
            self.wires.send(
                self.amnezia.as_ref(),
                self.peers[i].endpoint,
                self.peers[i].reserved,
                out,
            );
        }
    }

    /// 取出 smoltcp 产出的包，按目的地址交给对端。没有对应对端的包丢弃；
    /// 对端还没有会话时暂存一小部分并开始握手，多出的丢弃由 TCP 重传。
    fn flush(&mut self) {
        while let Some(packet) = self.device.pop_tx() {
            let Some(dest) = packet_dest(&packet) else {
                continue;
            };
            let Some(i) = self.peer_for(dest) else {
                continue;
            };
            if self.peers[i].dormant {
                continue;
            }
            if !self.peers[i].has_session() {
                if self.peers[i].queued.len() < PEER_QUEUE {
                    self.peers[i].queued.push_back(packet);
                }
                self.start_handshake(i);
                continue;
            }
            self.encapsulate(i, &packet);
        }
    }

    fn feed(&mut self) {
        let now = Instant::now();
        for flow in &mut self.tcp {
            if flow.connect.is_some() || flow.dead {
                continue;
            }
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
            while !flow.write_done {
                if flow.pos >= flow.pending.len() {
                    match flow.from_user.try_recv() {
                        Ok(chunk) => {
                            flow.pending = chunk;
                            flow.pos = 0;
                            flow.shared.wake_writer();
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => flow.write_done = true,
                    }
                    continue;
                }
                if !socket.may_send() {
                    break;
                }
                match socket.send_slice(&flow.pending[flow.pos..]) {
                    Ok(n) if n > 0 => {
                        flow.pos += n;
                        flow.tune.tx_enqueued += n as u64;
                        flow.tune.last_active = now;
                    }
                    _ => {
                        // 发送缓冲满，用户数据还在等
                        flow.tune.tx_blocked = true;
                        break;
                    }
                }
            }
            if flow.write_done && flow.pos >= flow.pending.len() && !flow.fin_sent {
                socket.close();
                flow.fin_sent = true;
            }
        }
        let sockets = &mut self.sockets;
        let device = &mut self.device;
        let spec = &self.spec;
        let next_ident = &mut self.next_ident;
        let mtu = usize::from(spec.mtu);
        self.udp.retain_mut(|flow| {
            let socket = sockets.get_mut::<udp::Socket>(flow.handle);
            loop {
                match flow.from_user.try_recv() {
                    Ok((data, dest)) => {
                        let local = match dest.ip() {
                            IpAddr::V4(_) => spec.address_v4.map(|(ip, _)| (IpAddr::V4(ip), 28)),
                            IpAddr::V6(_) => spec.address_v6.map(|(ip, _)| (IpAddr::V6(ip), 48)),
                        };
                        match local {
                            // 超过 MTU：自行切片，整组进入设备队列，放不下则整组丢弃
                            Some((ip, header)) if data.len() + header > mtu => {
                                let src = SocketAddr::new(ip, flow.port);
                                let frags = frag::fragment_udp(src, dest, &data, mtu, *next_ident);
                                *next_ident = next_ident.wrapping_add(1);
                                device.push_tx_all(frags);
                            }
                            // 套接字缓冲满时 send_slice 失败，数据报按设计丢弃
                            _ => {
                                let _ = socket.send_slice(
                                    &data,
                                    IpEndpoint::new(to_ip(dest.ip()), dest.port()),
                                );
                            }
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => return true,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        sockets.remove(flow.handle);
                        return false;
                    }
                }
            }
        });
    }

    /// 返回是否把数据交给了用户（用户侧可能因此腾出空间，值得再推进一轮）。
    fn service(&mut self, now: Instant) -> bool {
        let mut delivered = false;
        let sockets = &mut self.sockets;
        let mut discard = [0u8; 2048];
        self.tcp.retain_mut(|flow| {
            if flow.dead {
                sockets.remove(flow.handle);
                return false;
            }
            let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
            let state = socket.state();
            if let Some(connect) = flow.connect.take() {
                if connect.reply.is_closed() {
                    // 调用方已放弃
                    socket.abort();
                    flow.dead = true;
                    return true;
                }
                match state {
                    tcp::State::Established | tcp::State::CloseWait => {
                        if connect.reply.send(Ok(connect.stream)).is_err() {
                            socket.abort();
                            flow.dead = true;
                            return true;
                        }
                    }
                    tcp::State::Closed => {
                        let _ = connect.reply.send(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "wireguard tcp connection refused",
                        )));
                        sockets.remove(flow.handle);
                        return false;
                    }
                    _ if now >= connect.deadline => {
                        socket.abort();
                        let _ = connect.reply.send(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "wireguard tcp connect timed out",
                        )));
                        flow.dead = true;
                        return true;
                    }
                    _ => {
                        flow.connect = Some(connect);
                        return true;
                    }
                }
            }
            if matches!(
                state,
                tcp::State::CloseWait
                    | tcp::State::Closing
                    | tcp::State::TimeWait
                    | tcp::State::LastAck
            ) {
                flow.peer_fin = true;
            }
            if flow.to_user.as_ref().is_some_and(|tx| tx.is_closed()) {
                // 用户丢弃了流：不再交付，继续收以便处理对端 FIN
                flow.to_user = None;
                flow.write_done = true;
                flow.linger.get_or_insert(now + LINGER);
            }
            match flow.to_user.as_ref() {
                Some(tx) => {
                    let cap = socket.recv_capacity();
                    while socket.can_recv() {
                        let Ok(permit) = tx.try_reserve() else { break };
                        let mut chunk = vec![0; socket.recv_queue().min(CHUNK)];
                        let n = socket.recv_slice(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        chunk.truncate(n);
                        permit.send(chunk);
                        delivered = true;
                        flow.tune.rx_delivered += n as u64;
                        flow.tune.last_active = now;
                    }
                    flow.tune.after_read(now, cap, socket.recv_queue());
                    if socket.recv_queue() == 0 && (flow.peer_fin || state == tcp::State::Closed) {
                        if !flow.peer_fin {
                            flow.shared.reset.store(true, Ordering::Release);
                            flow.shared.wake_writer();
                        }
                        // 丢掉发送端即是 EOF（或重置）
                        flow.to_user = None;
                    }
                }
                None => {
                    while socket.can_recv() {
                        if socket.recv_slice(&mut discard).unwrap_or(0) == 0 {
                            break;
                        }
                    }
                }
            }
            if state == tcp::State::Closed && !flow.peer_fin {
                flow.shared.reset.store(true, Ordering::Release);
                flow.shared.wake_writer();
            }
            let finished = matches!(state, tcp::State::Closed | tcp::State::TimeWait);
            if finished && flow.to_user.is_none() {
                sockets.remove(flow.handle);
                return false;
            }
            if flow.linger.is_some_and(|deadline| now >= deadline) {
                socket.abort();
                flow.dead = true;
            }
            true
        });
        for flow in &mut self.udp {
            let socket = sockets.get_mut::<udp::Socket>(flow.handle);
            while socket.can_recv() {
                // 用户没有及时读取时留在套接字缓冲里，缓冲满后新数据报由 smoltcp 丢弃
                let Ok(permit) = flow.to_user.try_reserve() else {
                    break;
                };
                match socket.recv() {
                    Ok((data, meta)) => {
                        permit.send((data.to_vec(), from_endpoint(meta.endpoint)));
                        delivered = true;
                    }
                    Err(_) => break,
                }
            }
        }
        delivered
    }

    /// 本出站全部 TCP 当前占用的缓冲容量。
    fn buffer_used(&self) -> usize {
        self.tcp.iter().map(|f| f.rx_cap + f.tx_cap).sum()
    }

    /// 按观测扩容或收回缓冲；返回是否有缓冲变化（接收扩容后需要再推进一轮以发出窗口更新）。
    ///
    /// 扩容同时受本出站的 `tcp-buffer-budget` 与进程级预算（[`resources`]）约束；内存压力不为
    /// normal 时不扩容，并按压力等级提前收回空闲的缓冲。
    fn tune(&mut self, now: Instant) -> bool {
        let cfg = self.spec.tcp_buffers;
        let (rx0, tx0) = initial_buffers(&cfg);
        let pressure = resources::pressure();
        let may_grow = pressure == Pressure::Normal;
        let idle_after = pressure.idle_shrink();
        let mut used = self.buffer_used();
        let mut changed = false;
        for flow in &mut self.tcp {
            if flow.connect.is_some() || flow.dead {
                continue;
            }
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
            if std::mem::take(&mut flow.tune.rx_grow) && may_grow {
                if let Some(new) = grown(flow.rx_cap, cfg.rx, used, cfg.budget) {
                    if flow.lease.resize(new + flow.tx_cap) {
                        if socket
                            .replace_rx_buffer(tcp::SocketBuffer::new(vec![0; new]))
                            .is_ok()
                        {
                            used += new - flow.rx_cap;
                            flow.rx_cap = new;
                            changed = true;
                        } else {
                            flow.lease.resize(flow.rx_cap + flow.tx_cap);
                        }
                    }
                }
            }
            let acked = flow.tune.tx_enqueued - socket.send_queue() as u64;
            if may_grow
                && flow
                    .tune
                    .tx_should_grow(flow.tx_cap, socket.remote_window(), acked)
            {
                if let Some(new) = grown(flow.tx_cap, cfg.tx, used, cfg.budget) {
                    if flow.lease.resize(flow.rx_cap + new) {
                        if socket
                            .replace_tx_buffer(tcp::SocketBuffer::new(vec![0; new]))
                            .is_ok()
                        {
                            used += new - flow.tx_cap;
                            flow.tx_cap = new;
                            flow.tune.tx_acked_mark = acked;
                            changed = true;
                        } else {
                            flow.lease.resize(flow.rx_cap + flow.tx_cap);
                        }
                    }
                }
            }
            flow.tune.tx_blocked = false;
            let idle = (flow.rx_cap > rx0 || flow.tx_cap > tx0)
                && now.saturating_duration_since(flow.tune.last_active) >= idle_after
                && socket.recv_queue() == 0
                && socket.send_queue() == 0
                && flow.pos >= flow.pending.len();
            if idle {
                if flow.rx_cap > rx0
                    && socket
                        .replace_rx_buffer(tcp::SocketBuffer::new(vec![0; rx0]))
                        .is_ok()
                {
                    used -= flow.rx_cap - rx0;
                    flow.rx_cap = rx0;
                }
                if flow.tx_cap > tx0
                    && socket
                        .replace_tx_buffer(tcp::SocketBuffer::new(vec![0; tx0]))
                        .is_ok()
                {
                    used -= flow.tx_cap - tx0;
                    flow.tx_cap = tx0;
                }
                // 缩小必定成功
                flow.lease.resize(flow.rx_cap + flow.tx_cap);
                flow.tune.rx_round_end = 0;
            }
        }
        changed
    }

    fn next_wait(&mut self) -> Option<Duration> {
        let mut wait = self
            .iface
            .poll_delay(now_smol(), &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()));
        let keepalive = self.spec.keepalive_secs > 0
            && !self.asleep
            && self.peers.iter().any(|p| !p.dormant && p.has_session());
        let handshaking = self.peers.iter().any(|p| p.handshake.is_some());
        if !self.tcp.is_empty() || handshaking || keepalive {
            wait = Some(wait.map_or(TICK, |w| w.min(TICK)));
        }
        wait
    }
}

/// 一次唤醒里把通道上已到达的数据报再取最多 `RECV_BATCH - 1` 个，省掉每个包一次的循环与唤醒。
/// 不支持 `try_recv_from` 的通道（默认实现返回 None）照旧逐个处理。
fn drain(engine: &mut Engine, channel: Option<&dyn Datagrams>, buf: &mut [u8]) {
    let Some(channel) = channel else { return };
    for _ in 1..RECV_BATCH {
        match channel.try_recv_from(buf) {
            Ok(Some((n, from))) => engine.incoming(&mut buf[..n], from),
            Ok(None) => break,
            Err(err) => {
                // 错误留给下一次 recv_from 处理（会丢弃通道）
                log::debug!("wireguard: channel try_recv error: {err}");
                break;
            }
        }
    }
}

async fn recv(channel: Option<&dyn Datagrams>, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    match channel {
        Some(channel) => channel.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

async fn sleep(wait: Option<Duration>) {
    match wait {
        Some(wait) => tokio::time::sleep(wait).await,
        None => std::future::pending().await,
    }
}

async fn run(
    mut engine: Engine,
    mut commands: mpsc::Receiver<Command>,
    control: Arc<ControlState>,
) {
    let mut buf4 = vec![0u8; WIRE_BUF];
    let mut buf6 = vec![0u8; WIRE_BUF];
    loop {
        control.apply(&mut engine);
        engine.ensure_wires().await;
        control.apply(&mut engine);
        engine.pump();
        let wait = engine.next_wait();
        let v4 = engine.wires.v4.clone();
        let v6 = engine.wires.v6.clone();
        let notify = engine.notify.clone();
        tokio::select! {
            command = commands.recv() => match command {
                Some(command) => {
                    control.apply(&mut engine);
                    engine.command(command);
                },
                None => return,
            },
            got = recv(v4.as_deref(), &mut buf4) => match got {
                Ok((n, from)) => {
                    engine.incoming(&mut buf4[..n], from);
                    drain(&mut engine, v4.as_deref(), &mut buf4);
                }
                Err(err) => {
                    log::debug!("wireguard: channel error: {err}");
                    engine.wires.v4 = None;
                }
            },
            got = recv(v6.as_deref(), &mut buf6) => match got {
                Ok((n, from)) => {
                    engine.incoming(&mut buf6[..n], from);
                    drain(&mut engine, v6.as_deref(), &mut buf6);
                }
                Err(err) => {
                    log::debug!("wireguard: channel error: {err}");
                    engine.wires.v6 = None;
                }
            },
            _ = control.notify.notified() => {}
            _ = notify.notified() => {}
            _ = sleep(wait) => {}
        }
    }
}
