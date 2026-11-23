//! DERP v2：有界帧、有界 WireGuard 包队列和固定数量的区域连接。
//! 协议参考 tailscale/tailscale-rs f4781c480e8d1376aed89f737beefe7425e8b866
//! ts_derp/src/{client.rs,frame/}（BSD-3-Clause）；本文件为 Oryn 适配实现。
use super::magic::{self, Magic, Out, Route, Via};
use super::snapshot::{Peer, Snapshot};
use super::{control, err, Task};
use crate::{BoxStream, Dialer, Resolver};
use async_trait::async_trait;
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    SalsaBox,
};
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    sync::{mpsc, watch, Mutex},
};
use ts_keys::NodeState;

const MAX_FRAME: usize = 65536;
const MAX_WIRE: usize = 4096;
const QUEUE: usize = 32;
/// 直连路径的 WireGuard persistent keepalive（秒），与 WireGuard 常用值一致。
const DIRECT_KEEPALIVE_SECS: u16 = 25;
/// 同时保持的 DERP region 连接上限。
const MAX_REGIONS: usize = 32;
/// 客户端 Ping 间隔：空闲连接也有流量，不被服务端 / 中间代理按空闲掐断。
const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
/// 这么久没收到任何帧（服务端约每 60 秒发 KeepAlive，且会回 Pong）就判定连接已死：
/// 没有 FIN 的静默黑洞也能检出。
const READ_IDLE: std::time::Duration = std::time::Duration::from_secs(120);
type WirePacket = (Vec<u8>, SocketAddr);
/// 发给 disco 状态机的包：disco（经 UDP 或 DERP）与 STUN 响应。
enum Inbound {
    Disco(Vec<u8>, Via),
    Stun(Vec<u8>),
}
/// 本机端点（地址、tailcfg.EndpointType），变化时由控制会话上报。
pub type Endpoints = Vec<(SocketAddr, u8)>;

async fn frame(r: &mut (impl AsyncRead + Unpin)) -> io::Result<(u8, Vec<u8>)> {
    let kind = r.read_u8().await?;
    let n = r.read_u32().await? as usize;
    if n > MAX_FRAME {
        return Err(err("DERP frame exceeds 64 KiB limit"));
    }
    let mut bytes = vec![0; n];
    r.read_exact(&mut bytes).await?;
    Ok((kind, bytes))
}
async fn send(w: &mut (impl AsyncWrite + Unpin), kind: u8, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(err("DERP frame too large"));
    }
    w.write_u8(kind).await?;
    w.write_u32(body.len() as u32).await?;
    w.write_all(body).await?;
    w.flush().await
}

async fn connect(
    url: &url::Url,
    cert: Option<&str>,
    keys: &NodeState,
    dialer: &dyn Dialer,
) -> io::Result<BoxStream> {
    let mut stream = control::transport_with(dialer, url, cert).await?;
    let host = &url[url::Position::BeforeHost..url::Position::AfterPort];
    stream.write_all(format!("GET /derp HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n").as_bytes()).await?;
    let (status, fields) = control::headers(&mut stream).await?;
    if status != 101
        || !fields
            .iter()
            .any(|(k, v)| k == "upgrade" && v.eq_ignore_ascii_case("derp"))
    {
        return Err(err("DERP upgrade rejected"));
    }
    let (kind, server) = frame(&mut stream).await?;
    if kind != 1
        || server.len() != 40
        || server[..8] != [0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91]
    {
        return Err(err("invalid DERP server key"));
    }
    let public =
        crypto_box::PublicKey::from(<[u8; 32]>::try_from(&server[8..]).map_err(io::Error::other)?);
    let secret = keys.node_keys.private.to_crypto_box();
    let cipher = SalsaBox::new(&public, &secret);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let encrypted = cipher
        .encrypt(&nonce, b"{\"version\":2}".as_slice())
        .map_err(|_| err("DERP authentication encryption failed"))?;
    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(keys.node_keys.public.to_crypto_box().as_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&encrypted);
    send(&mut stream, 2, &body).await?;
    let (kind, body) = frame(&mut stream).await?;
    if kind != 3 || body.len() < 40 {
        return Err(err("invalid DERP server info"));
    }
    let plain = cipher
        .decrypt((&body[..24]).into(), &body[24..])
        .map_err(|_| err("DERP authentication failed"))?;
    let info: serde_json::Value = serde_json::from_slice(&plain).map_err(io::Error::other)?;
    if info["version"].as_u64().unwrap_or(2) != 2 {
        return Err(err("unsupported DERP version"));
    }
    send(&mut stream, 7, &[1]).await?;
    Ok(stream)
}

pub fn endpoint(index: usize) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, (index + 1) as u16))
}

pub struct Relay {
    routes: BTreeMap<SocketAddr, (u16, [u8; 32])>,
    senders: BTreeMap<u16, mpsc::Sender<WirePacket>>,
    incoming: Mutex<mpsc::Receiver<WirePacket>>,
    /// 直连状态机（OrynCore#41）；有 dialer-proxy 或套接字不可用时为 None，只走 DERP。
    magic: Option<Arc<std::sync::Mutex<Magic>>>,
    /// IPv4 / IPv6 共享 UDP 套接字：WireGuard、disco、STUN 共用，NAT 映射一致。
    sockets: [Option<Arc<UdpSocket>>; 2],
    endpoints: watch::Receiver<Endpoints>,
    _tasks: Vec<Task>,
}
/// 执行状态机产出的发送：UDP 走共享套接字，DERP 走对端所在 region 的写队列。
#[derive(Clone)]
struct Exec {
    routes: BTreeMap<SocketAddr, (u16, [u8; 32])>,
    senders: BTreeMap<u16, mpsc::Sender<WirePacket>>,
    sockets: [Option<Arc<UdpSocket>>; 2],
}
fn send_udp(sockets: &[Option<Arc<UdpSocket>>; 2], addr: SocketAddr, buf: &[u8]) {
    if let Some(socket) = &sockets[usize::from(addr.is_ipv6())] {
        // 缓冲满或网络错误按丢包处理，由 WireGuard / disco 重传
        let _ = socket.try_send_to(buf, addr);
    }
}
impl Exec {
    fn derp(&self, artificial: SocketAddr, buf: Vec<u8>) -> io::Result<()> {
        let (region, _) = self
            .routes
            .get(&artificial)
            .ok_or_else(|| err("unknown Tailscale peer endpoint"))?;
        let tx = self
            .senders
            .get(region)
            .ok_or_else(|| err("DERP region disconnected"))?;
        match tx.try_send((buf, artificial)) {
            Ok(()) => Ok(()),
            // 突发时丢掉这个包（WireGuard / 隧道内 TCP 会重传），留一条诊断日志
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::debug!("tailscale: DERP send queue full, dropped a packet");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(err("DERP connection closed")),
        }
    }
    fn run(&self, outs: Vec<Out>) {
        for out in outs {
            match out {
                Out::Udp(addr, buf) => send_udp(&self.sockets, addr, &buf),
                Out::Derp(peer, buf) => {
                    let _ = self.derp(endpoint(peer), buf);
                }
            }
        }
    }
}
impl Relay {
    /// 任一区域连接已断开。
    pub fn is_closed(&self) -> bool {
        self.senders.values().any(mpsc::Sender::is_closed)
    }
    pub async fn disconnected(&self) {
        loop {
            if self.senders.values().any(mpsc::Sender::is_closed) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    /// 本机端点变化（STUN 结果、网卡地址），由控制会话经 MapRequest 上报。
    pub fn endpoints(&self) -> watch::Receiver<Endpoints> {
        self.endpoints.clone()
    }
    fn exec(&self) -> Exec {
        Exec {
            routes: self.routes.clone(),
            senders: self.senders.clone(),
            sockets: self.sockets.clone(),
        }
    }
    /// `direct` 为假（配置了 dialer-proxy）时不建直连套接字，只走 DERP：UDP 经前置代理后 NAT
    /// 映射属于代理出口，打洞基本不可行，直连还会绕过用户的代理意图。
    pub async fn start(
        snapshot: &Snapshot,
        keys: &NodeState,
        dialer: Arc<dyn Dialer>,
        resolver: Arc<dyn Resolver>,
        direct: bool,
        home: u16,
    ) -> io::Result<Arc<Self>> {
        let mut regions = std::collections::BTreeSet::from([home]);
        let mut routes = BTreeMap::new();
        let mut sources = BTreeMap::new();
        for (i, peer) in snapshot.peers.iter().enumerate() {
            // 单个对端的 home region 不在 DERPMap 里只影响它自己（经 DERP 不可达，若有直连端点仍可用），
            // 不能让整个 Relay 建立失败
            if snapshot.regions.contains_key(&peer.derp) {
                regions.insert(peer.derp);
            } else if peer.endpoints.is_empty() {
                log::debug!("tailscale: peer {} has no reachable DERP region", peer.name);
            }
            routes.insert(endpoint(i), (peer.derp, peer.key));
            sources.insert(peer.key, endpoint(i));
        }
        // 每个 region 一条 DERP 连接；对端分布在更多 region 时只是连接数增加（原上限 8，OrynCore#43）
        if regions.len() > MAX_REGIONS {
            return Err(err("Tailscale peers span too many DERP regions"));
        }
        let (incoming_tx, incoming) = mpsc::channel(QUEUE);
        let (disco_tx, mut disco_rx) = mpsc::channel::<Inbound>(QUEUE);
        let mut senders = BTreeMap::new();
        let mut tasks = Vec::new();
        for region in regions {
            let urls = snapshot
                .region_nodes
                .get(&region)
                .cloned()
                .or_else(|| snapshot.regions.get(&region).cloned().map(|url| vec![url]))
                .ok_or_else(|| err("peer DERP region is unavailable"))?;
            let mut last = None;
            let mut stream = None;
            for url in urls.iter().take(8) {
                let cert = snapshot.derp_certs.get(url).map(String::as_str);
                match control::timed(connect(url, cert, keys, dialer.as_ref())).await {
                    Ok(value) => {
                        stream = Some(value);
                        break;
                    }
                    Err(error) => last = Some(error),
                }
            }
            let stream = stream
                .ok_or_else(|| last.unwrap_or_else(|| err("all Tailscale DERP nodes failed")))?;
            let (tx, region_tasks) = start_region(
                stream,
                incoming_tx.clone(),
                sources.clone(),
                routes.clone(),
                direct.then(|| (disco_tx.clone(), region)),
            );
            senders.insert(region, tx);
            tasks.extend(region_tasks);
        }
        let mut sockets: [Option<Arc<UdpSocket>>; 2] = [None, None];
        if direct {
            for v6 in [false, true] {
                match oryn_udp::iface::bind_udp(v6).await {
                    Ok(socket) => sockets[usize::from(v6)] = Some(Arc::new(socket)),
                    Err(e) => log::debug!("tailscale: direct UDP socket (ipv6={v6}) unavailable: {e}"),
                }
            }
        }
        let (endpoints_tx, endpoints) = watch::channel(Vec::new());
        let mut magic = None;
        if sockets.iter().any(Option::is_some) {
            let mut state = Magic::new(
                keys.disco_keys.private.to_crypto_box(),
                *keys.node_keys.public.to_crypto_box().as_bytes(),
                snapshot
                    .peers
                    .iter()
                    .map(|p| (p.disco, p.endpoints.clone()))
                    .collect(),
                [sockets[0].is_some(), sockets[1].is_some()],
            );
            let mut local = Vec::new();
            for ip in magic::local_addresses() {
                let socket = &sockets[usize::from(ip.is_ipv6())];
                if let Some(port) = socket.as_ref().and_then(|s| s.local_addr().ok()).map(|a| a.port()) {
                    local.push(SocketAddr::new(ip, port));
                }
            }
            state.set_local(local);
            state.set_stun_servers(stun_servers(snapshot, home, resolver.as_ref()).await);
            let _ = endpoints_tx.send(state.endpoints());
            magic = Some(Arc::new(std::sync::Mutex::new(state)));
        }
        let relay = Self {
            routes,
            senders,
            incoming: Mutex::new(incoming),
            magic: magic.clone(),
            sockets: sockets.clone(),
            endpoints,
            _tasks: Vec::new(),
        };
        if let Some(magic) = magic {
            let exec = relay.exec();
            // 每个套接字一个接收任务：STUN 响应与 disco 交给状态机，其余是 WireGuard
            for socket in sockets.into_iter().flatten() {
                let (magic, incoming, disco) = (magic.clone(), incoming_tx.clone(), disco_tx.clone());
                tasks.push(Task(tokio::spawn(async move {
                    let mut buf = vec![0; MAX_WIRE];
                    while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                        let packet = &buf[..n];
                        if magic::stun_response(packet).is_some() {
                            let _ = disco.try_send(Inbound::Stun(packet.to_vec()));
                        } else if magic::is_disco(packet) {
                            let _ = disco.try_send(Inbound::Disco(packet.to_vec(), Via::Udp(from)));
                        } else if let Some(peer) = magic.lock().unwrap().peer_for(from) {
                            let _ = incoming.try_send((packet.to_vec(), endpoint(peer)));
                        }
                    }
                })));
            }
            tasks.push(Task(tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    let outs = tokio::select! {
                        _ = tick.tick() => magic.lock().unwrap().tick(Instant::now()),
                        inbound = disco_rx.recv() => match inbound {
                            None => break,
                            Some(Inbound::Disco(packet, via)) => {
                                magic.lock().unwrap().on_disco(&packet, via, Instant::now())
                            }
                            Some(Inbound::Stun(packet)) => {
                                let mut state = magic.lock().unwrap();
                                if state.on_stun(&packet) {
                                    let _ = endpoints_tx.send(state.endpoints());
                                }
                                Vec::new()
                            }
                        },
                    };
                    exec.run(outs);
                }
            })));
        }
        Ok(Arc::new(Self {
            _tasks: tasks,
            ..relay
        }))
    }
}

/// home region 的 STUN 服务地址：优先 DERPMap 给出的 IP，否则经代理解析器解析主机名。
async fn stun_servers(snapshot: &Snapshot, home: u16, resolver: &dyn Resolver) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for server in snapshot.stun.get(&home).into_iter().flatten().take(2) {
        let mut ips = server.ips.clone();
        if ips.is_empty() && !server.host.is_empty() {
            if let Ok(Ok(resolved)) =
                tokio::time::timeout(std::time::Duration::from_secs(3), resolver.resolve(&server.host)).await
            {
                ips = resolved;
            }
        }
        for ip in ips.into_iter().take(2) {
            out.push(SocketAddr::new(ip, server.port));
        }
    }
    out
}

// 认证后的真实区域 pipeline；测试也经过同一组读写任务和有界队列。
fn start_region(
    stream: BoxStream,
    incoming: mpsc::Sender<WirePacket>,
    sources: BTreeMap<[u8; 32], SocketAddr>,
    routes: BTreeMap<SocketAddr, (u16, [u8; 32])>,
    disco: Option<(mpsc::Sender<Inbound>, u16)>,
) -> (mpsc::Sender<WirePacket>, Vec<Task>) {
    let mut tasks = Vec::new();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<WirePacket>(QUEUE);
    // 分开读写，避免 select 取消 read_exact 后破坏分帧。
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Vec<u8>>(4);
    let stopped = tokio_util::sync::CancellationToken::new();
    // guard 在 spawn 前创建，未被 poll 就 abort 也会通知另一端。
    let read_guard = stopped.clone().drop_guard();
    let write_guard = stopped.clone().drop_guard();
    let read_stopped = stopped.clone();
    tasks.push(Task(tokio::spawn(async move {
        let _guard = read_guard;
        tokio::select! {
            biased;
            _ = read_stopped.cancelled() => {}
            _ = async {
        loop {
            let Ok(Ok((kind, body))) = tokio::time::timeout(READ_IDLE, frame(&mut reader)).await
            else {
                break;
            };
            match kind {
                5 if body.len() >= 32 && body.len() <= 32 + MAX_WIRE => {
                    let key: [u8; 32] = body[..32].try_into().expect("checked length");
                    if let Some(&from) = sources.get(&key) {
                        let payload = &body[32..];
                        match &disco {
                            // 经 DERP 的 disco：交给状态机（来源身份 = DERP 帧里的 node key）
                            Some((tx, region)) if magic::is_disco(payload) => {
                                let peer = usize::from(from.port()) - 1;
                                let _ = tx.try_send(Inbound::Disco(payload.to_vec(), Via::Derp(peer, *region)));
                            }
                            _ => {
                                let _ = incoming.try_send((payload.to_vec(), from));
                            }
                        }
                    }
                }
                // Ping：排队回 Pong；控制队列满说明写端卡住，断开重连
                0x12 if body.len() == 8 => match ctrl_tx.try_send(body) {
                    Ok(()) => {}
                    Err(_) => break,
                },
                // KeepAlive / PeerGone / Pong / Health 等与未知帧一律忽略（与官方客户端相同），
                // 新版服务端的扩展帧不能导致断连
                _ => {}
            }
        }
            } => {}
        }
    })));
    tasks.push(Task(tokio::spawn(async move {
                let _guard = write_guard;
                // 覆盖整个写循环（包括已选中的 send/flush），而非仅覆盖取队列。
                // 撤销后两端均退出并丢弃流，绝不重用可能只写了一部分的帧。
                tokio::select! {
                    biased;
                    _ = stopped.cancelled() => {}
                    _ = async {
                let mut ping = tokio::time::interval(PING_INTERVAL);
                ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ping.tick().await;
                loop {
                    let result=tokio::select! {
                        biased;
                        ctrl=ctrl_rx.recv()=> match ctrl {Some(body)=>send(&mut writer,0x13,&body).await,None=>break},
                        _=ping.tick()=> {
                            let body: [u8; 8] = rand::random();
                            send(&mut writer,0x12,&body).await
                        }
                        packet=rx.recv()=> {
                            let Some((packet,to))=packet else {break};
                            let Some((_,key))=routes.get(&to) else {continue};
                            let mut body=Vec::with_capacity(32+packet.len());body.extend_from_slice(key);body.extend_from_slice(&packet);
                            send(&mut writer,4,&body).await
                        }
                    };
                    if result.is_err(){break;}
                }
                    } => {}
                }
            })));
    (tx, tasks)
}
#[async_trait]
impl oryn_udp::Datagrams for Relay {
    fn try_send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<()> {
        if buf.len() > MAX_WIRE {
            return Err(err("Tailscale WireGuard packet exceeds limit"));
        }
        // 可信直连只走 UDP；直连未确认时 UDP 与 DERP 都发（WireGuard 重放保护丢弃重复密文）；
        // 没有直连时只走 DERP（OrynCore#41，与 magicsock addrForSendLocked 一致）
        let route = match &self.magic {
            Some(magic) => magic
                .lock()
                .unwrap()
                .route(usize::from(peer.port()).wrapping_sub(1), Instant::now()),
            None => Route::Derp,
        };
        match route {
            Route::Udp(addr) => {
                send_udp(&self.sockets, addr, buf);
                return Ok(());
            }
            Route::Both(addr) => send_udp(&self.sockets, addr, buf),
            Route::Derp => {}
        }
        let (region, _) = self
            .routes
            .get(&peer)
            .ok_or_else(|| err("unknown Tailscale peer endpoint"))?;
        let tx = self
            .senders
            .get(region)
            .ok_or_else(|| err("DERP region disconnected"))?;
        match tx.try_send((buf.to_vec(), peer)) {
            Ok(()) => Ok(()),
            // 突发时丢掉这个密文包（WireGuard / 隧道内 TCP 会重传），留一条诊断日志
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::debug!("tailscale: DERP send queue full, dropped a packet");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(err("DERP connection closed")),
        }
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.incoming.lock().await;
        let (data, from) = rx
            .recv()
            .await
            .ok_or_else(|| err("DERP connections closed"))?;
        if data.len() > buf.len() {
            return Err(err("DERP receive buffer too small"));
        }
        buf[..data.len()].copy_from_slice(&data);
        Ok((data.len(), from))
    }
}
pub struct Factory(pub Arc<Relay>);
#[async_trait]
impl oryn_udp::DatagramFactory for Factory {
    async fn bind(&self, _: SocketAddr) -> io::Result<Arc<dyn oryn_udp::Datagrams>> {
        Ok(self.0.clone())
    }
}

pub fn wire_peer(
    peer: &Peer,
    index: usize,
    accept_routes: bool,
    exit: bool,
) -> oryn_config::WireGuardPeerSpec {
    let mut allowed_ips: Vec<_> = peer
        .ips
        .iter()
        .map(|ip| {
            oryn_config::IpCidr::parse(&format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))
                .expect("valid address")
        })
        .collect();
    if accept_routes {
        allowed_ips.extend(
            peer.routes
                .iter()
                .filter(|route| route.prefix() != 0)
                .cloned(),
        );
    }
    if exit {
        // 只安装此节点实际获批的默认路由，不凭空补另一地址族。
        allowed_ips.extend(
            peer.routes
                .iter()
                .filter(|route| route.prefix() == 0)
                .cloned(),
        );
    }
    oryn_config::WireGuardPeerSpec {
        endpoint: oryn_config::TargetAddr::Ip(endpoint(index)),
        public_key: peer.key,
        preshared_key: None,
        allowed_ips,
        reserved: [0; 3],
        // 有直连端点的对端每 25 s 保活，防止 NAT 映射老化断流（OrynCore#43）；
        // 只走 DERP 的对端不需要，保持安静以省电
        keepalive_secs: (!peer.endpoints.is_empty()).then_some(DIRECT_KEEPALIVE_SECS),
    }
}

#[cfg(test)]
#[path = "derp_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_frame_length_before_reading_or_allocating_body() {
        let mut input = std::io::Cursor::new(vec![5, 0, 1, 0, 1]);
        assert!(frame(&mut input)
            .await
            .unwrap_err()
            .to_string()
            .contains("limit"));
    }
}
