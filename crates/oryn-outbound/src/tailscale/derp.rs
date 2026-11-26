//! DERP v2：有界帧、有界 WireGuard 包队列和固定数量的区域连接。
//! 协议参考 tailscale/tailscale-rs f4781c480e8d1376aed89f737beefe7425e8b866
//! ts_derp/src/{client.rs,frame/}（BSD-3-Clause）；本文件为 Oryn 适配实现。
use super::snapshot::{Peer, Snapshot};
use super::{control, err, Task};
use crate::{BoxStream, Dialer};
use async_trait::async_trait;
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    SalsaBox,
};
use oryn_udp::DatagramFactory;
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, Mutex},
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
    insecure: bool,
    fallback_ips: &[IpAddr],
    keys: &NodeState,
    dialer: &dyn Dialer,
) -> io::Result<BoxStream> {
    let mut stream = control::transport_derp(dialer, url, cert, insecure, fallback_ips).await?;
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
    direct: BTreeMap<SocketAddr, (Arc<dyn oryn_udp::Datagrams>, SocketAddr)>,
    incoming: Mutex<mpsc::Receiver<WirePacket>>,
    _tasks: Vec<Task>,
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
    pub async fn start(
        snapshot: &Snapshot,
        keys: &NodeState,
        dialer: Arc<dyn Dialer>,
        datagrams: Arc<dyn DatagramFactory>,
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
        let mut senders = BTreeMap::new();
        let mut tasks = Vec::new();
        let mut direct = BTreeMap::new();
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
                let insecure = snapshot.derp_insecure.contains(url);
                let fallback_ips = snapshot
                    .derp_ips
                    .get(url)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                match control::timed(connect(
                    url,
                    cert,
                    insecure,
                    fallback_ips,
                    keys,
                    dialer.as_ref(),
                ))
                .await
                {
                    Ok(value) => {
                        stream = Some(value);
                        break;
                    }
                    Err(error) => last = Some(error),
                }
            }
            let stream = stream
                .ok_or_else(|| last.unwrap_or_else(|| err("all Tailscale DERP nodes failed")))?;
            let (tx, region_tasks) =
                start_region(stream, incoming_tx.clone(), sources.clone(), routes.clone());
            senders.insert(region, tx);
            tasks.extend(region_tasks);
        }
        // 使用 peer 上报的 endpoint；本地尚未实现 STUN/disco。
        // 数据报沿配置的 dialer-proxy 运行，不私自绕过前置代理。
        for (i, peer) in snapshot.peers.iter().enumerate() {
            let Some(remote) = peer.endpoints.first().copied() else {
                continue;
            };
            let Ok(channel) = datagrams.bind(remote).await else {
                continue; // 前置代理不支持 UDP 时沿 DERP 承载。
            };
            let artificial = endpoint(i);
            let incoming = incoming_tx.clone();
            let reader = channel.clone();
            tasks.push(Task(tokio::spawn(async move {
                let mut buf = vec![0; MAX_WIRE];
                loop {
                    let Ok((n, from)) = reader.recv_from(&mut buf).await else {
                        break;
                    };
                    if from == remote {
                        let _ = incoming.try_send((buf[..n].to_vec(), artificial));
                    }
                }
            })));
            direct.insert(artificial, (channel, remote));
        }
        Ok(Arc::new(Self {
            routes,
            senders,
            direct,
            incoming: Mutex::new(incoming),
            _tasks: tasks,
        }))
    }
}

// 认证后的真实区域 pipeline；测试也经过同一组读写任务和有界队列。
fn start_region(
    stream: BoxStream,
    incoming: mpsc::Sender<WirePacket>,
    sources: BTreeMap<[u8; 32], SocketAddr>,
    routes: BTreeMap<SocketAddr, (u16, [u8; 32])>,
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
                        let _ = incoming.try_send((body[32..].to_vec(), from));
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
        if let Some((channel, remote)) = self.direct.get(&peer) {
            // UDP 发送成功不证明可达；继续经 DERP 发送，避免 NAT 黑洞。
            // WireGuard 重放保护丢弃重复密文。完整路径探测仍需 disco。
            let _ = channel.try_send_to(buf, *remote);
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
