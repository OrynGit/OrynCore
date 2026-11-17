use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use oryn_config::TargetAddr;
use std::task::Poll;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::Notify;

use crate::{resolve_target, with_timeout, BoxStream, Dialer, Outbound, PacketConn, Resolver};

/// 系统 TCP socket 拨号器。
pub struct DirectDialer {
    resolver: Arc<dyn Resolver>,
}

impl DirectDialer {
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        DirectDialer { resolver }
    }

    pub fn resolver(&self) -> &Arc<dyn Resolver> {
        &self.resolver
    }
}

#[async_trait]
impl Dialer for DirectDialer {
    async fn dial_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let addrs = resolve_target(&*self.resolver, target).await?;
        let mut last = None;
        for a in addrs {
            match with_timeout(oryn_udp::iface::connect_tcp(a), "connect").await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(Box::new(s));
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no usable address")))
    }
}

pub struct DirectOutbound {
    tag: String,
    dialer: Arc<DirectDialer>,
}

impl DirectOutbound {
    pub fn new(tag: String, dialer: Arc<DirectDialer>) -> Self {
        DirectOutbound { tag, dialer }
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "direct"
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        self.dialer.dial_tcp(target).await
    }

    async fn bind_udp(&self, first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        let first = resolve_target(&**self.dialer.resolver(), first_target).await?[0];
        let socket = bind_udp_socket(first.is_ipv6()).await?;
        socket.connect(first).await?;
        let mut resolved = HashMap::new();
        if let TargetAddr::Domain(d, _) = first_target {
            resolved.insert(d.clone(), (first.ip(), Instant::now()));
        }
        Ok(Box::new(DirectPacketConn {
            sockets: Mutex::new(HashMap::from([(first, UdpPeer::new(Arc::new(socket)))])),
            peers_changed: Notify::new(),
            resolver: self.dialer.resolver().clone(),
            resolved: Mutex::new(resolved),
        }))
    }
}

pub(crate) async fn bind_udp_socket(v6: bool) -> io::Result<UdpSocket> {
    oryn_udp::iface::bind_udp(v6).await
}

struct DirectPacketConn {
    // Apple PacketTunnel 出站先关联远端，避免未连接 send_to 的路由策略差异。
    sockets: Mutex<HashMap<SocketAddr, UdpPeer>>,
    peers_changed: Notify,
    resolver: Arc<dyn Resolver>,
    /// 域名目标的解析结果与解析时刻（嗅探改写目标后，UDP 会话每个包都带同一个域名）。
    resolved: Mutex<HashMap<String, (IpAddr, Instant)>>,
}

/// 一个已关联的远端及其最近一次收发时刻。
struct UdpPeer {
    socket: Arc<UdpSocket>,
    used: Instant,
}

impl UdpPeer {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            used: Instant::now(),
        }
    }
}

const MAX_RESOLVED: usize = 16;
const MAX_UDP_PEERS: usize = 16;
/// 对端表满时，空闲超过这么久的对端可被淘汰（长会话里 DNS / NTP / STUN 等一次性对端）。
const UDP_PEER_IDLE: Duration = Duration::from_secs(60);
/// 域名解析结果在会话内的复用时长；过期后重新解析（解析器自己按 TTL 缓存），地址变化能跟上。
const RESOLVED_TTL: Duration = Duration::from_secs(120);

/// 表满时腾出一个位置：淘汰最久未用且已空闲足够久的对端；都还活跃时返回 false。
fn evict_idle(sockets: &mut HashMap<SocketAddr, UdpPeer>) -> bool {
    let victim = sockets
        .iter()
        .filter(|(_, p)| p.used.elapsed() >= UDP_PEER_IDLE)
        .min_by_key(|(_, p)| p.used)
        .map(|(addr, _)| *addr);
    victim.is_some_and(|addr| sockets.remove(&addr).is_some())
}

impl DirectPacketConn {
    async fn socket_for(&self, addr: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        {
            let mut sockets = self.sockets.lock().unwrap();
            if let Some(peer) = sockets.get_mut(&addr) {
                peer.used = Instant::now();
                return Ok(peer.socket.clone());
            }
            if sockets.len() >= MAX_UDP_PEERS && !evict_idle(&mut sockets) {
                return Err(io::Error::other("direct UDP peer limit reached"));
            }
        }
        let socket = bind_udp_socket(addr.is_ipv6()).await?;
        socket.connect(addr).await?;
        let socket = Arc::new(socket);
        let mut sockets = self.sockets.lock().unwrap();
        // 并发 send_to 可能已创建同一目标，或刚好填满容量。
        if let Some(existing) = sockets.get(&addr) {
            return Ok(existing.socket.clone());
        }
        if sockets.len() >= MAX_UDP_PEERS && !evict_idle(&mut sockets) {
            return Err(io::Error::other("direct UDP peer limit reached"));
        }
        sockets.insert(addr, UdpPeer::new(socket.clone()));
        self.peers_changed.notify_one();
        Ok(socket)
    }
}

#[async_trait]
impl PacketConn for DirectPacketConn {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        let addr = match target {
            TargetAddr::Ip(a) => *a,
            TargetAddr::Domain(d, port) => {
                let cached = self
                    .resolved
                    .lock()
                    .unwrap()
                    .get(d)
                    .filter(|(_, at)| at.elapsed() < RESOLVED_TTL)
                    .map(|(ip, _)| *ip);
                match cached {
                    Some(ip) => SocketAddr::new(ip, *port),
                    None => {
                        let a = resolve_target(&*self.resolver, target).await?[0];
                        let mut map = self.resolved.lock().unwrap();
                        if map.len() >= MAX_RESOLVED && !map.contains_key(d) {
                            map.retain(|_, (_, at)| at.elapsed() < RESOLVED_TTL);
                            if map.len() >= MAX_RESOLVED {
                                map.clear();
                            }
                        }
                        map.insert(d.clone(), (a.ip(), Instant::now()));
                        a
                    }
                }
            }
        };
        self.socket_for(addr).await?.send(buf).await.map(|_| ())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        loop {
            // 新目标插入时唤醒接收；取消 recv_from 不移除 socket 或丢弃已到达数据。
            let changed = self.peers_changed.notified();
            tokio::select! {
                result = std::future::poll_fn(|cx| {
                    let mut sockets = self.sockets.lock().unwrap();
                    for (peer, entry) in sockets.iter_mut() {
                        let mut read = ReadBuf::new(buf);
                        match entry.socket.poll_recv(cx, &mut read) {
                            Poll::Ready(Ok(())) => {
                                entry.used = Instant::now();
                                return Poll::Ready(Ok((read.filled().len(), TargetAddr::Ip(*peer))));
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {}
                        }
                    }
                    Poll::Pending
                }) => return result,
                _ = changed => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct NoDns;
    #[async_trait]
    impl Resolver for NoDns {
        async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
            panic!("IP targets must not trigger DNS");
        }
    }

    fn connection() -> DirectPacketConn {
        DirectPacketConn {
            sockets: Mutex::new(HashMap::new()),
            peers_changed: Notify::new(),
            resolver: Arc::new(NoDns),
            resolved: Mutex::new(HashMap::new()),
        }
    }

    #[tokio::test]
    async fn direct_udp_connected_peers_and_limit() {
        let conn = connection();
        let mut servers = Vec::new();
        for _ in 0..MAX_UDP_PEERS {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = server.local_addr().unwrap();
            let (a, b) = tokio::join!(conn.socket_for(addr), conn.socket_for(addr));
            let (a, b) = (a.unwrap(), b.unwrap());
            assert!(Arc::ptr_eq(&a, &b));
            assert_eq!(a.peer_addr().unwrap(), addr);
            servers.push(server);
        }
        let extra = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(conn.socket_for(extra.local_addr().unwrap()).await.is_err());
        assert_eq!(conn.sockets.lock().unwrap().len(), MAX_UDP_PEERS);
        assert!(conn
            .socket_for(servers[0].local_addr().unwrap())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn direct_udp_new_peer_wakes_receive_and_cancel_preserves_reply() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let conn = connection();
            let mut buf = [0; 64];
            // recv 先开始等待；新增目标必须重新登记该 socket 的读唤醒。
            let receive = conn.recv_from(&mut buf);
            tokio::pin!(receive);
            assert!(futures_util::poll!(&mut receive).is_pending());
            let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = TargetAddr::Ip(v4.local_addr().unwrap());
            conn.send_to(b"first", &target).await.unwrap();
            let mut peer_buf = [0; 64];
            let (n, source) = v4.recv_from(&mut peer_buf).await.unwrap();
            assert_eq!(&peer_buf[..n], b"first");
            v4.send_to(b"reply", source).await.unwrap();
            assert_eq!(receive.await.unwrap(), (5, target.clone()));

            let mut buf = [0; 64];
            {
                let receive = conn.recv_from(&mut buf);
                tokio::pin!(receive);
                assert!(futures_util::poll!(&mut receive).is_pending());
            }
            // 同一 PacketConn 添加 IPv6 目标，不影响原 IPv4 目标的回包。
            let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
            let target6 = TargetAddr::Ip(v6.local_addr().unwrap());
            conn.send_to(b"second", &target6).await.unwrap();
            let (_, source6) = v6.recv_from(&mut peer_buf).await.unwrap();
            v6.send_to(b"six", source6).await.unwrap();
            assert_eq!(conn.recv_from(&mut buf).await.unwrap(), (3, target6));
            assert_eq!(&buf[..3], b"six");
            v4.send_to(b"four", source).await.unwrap();
            assert_eq!(conn.recv_from(&mut buf).await.unwrap(), (4, target));
            assert_eq!(&buf[..4], b"four");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn direct_udp_outbound_roundtrip() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = TargetAddr::Ip(server.local_addr().unwrap());
            let outbound = DirectOutbound::new(
                "DIRECT".into(),
                Arc::new(DirectDialer::new(Arc::new(NoDns))),
            );
            let conn = outbound.bind_udp(&target).await.unwrap();
            conn.send_to(b"query", &target).await.unwrap();
            let mut buf = [0; 64];
            let (n, source) = server.recv_from(&mut buf).await.unwrap();
            server.send_to(&buf[..n], source).await.unwrap();
            assert_eq!(conn.recv_from(&mut buf).await.unwrap(), (5, target.clone()));
            assert_eq!(&buf[..5], b"query");
        })
        .await
        .unwrap();
    }
}
