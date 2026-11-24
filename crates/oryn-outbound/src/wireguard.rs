//! WireGuard 出站。对 Router 只暴露 Flow。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use oryn_config::{TargetAddr, WireGuardSpec};
use oryn_udp::DatagramFactory;
use oryn_wireguard::{Endpoints, Tunnel, UdpSession};

use crate::{resolve_target, BoxStream, Outbound, PacketConn, Resolver, SessionControl};

pub struct WireGuardOutbound {
    name: String,
    inner: Arc<Inner>,
}

struct Inner {
    spec: WireGuardSpec,
    resolver: Arc<dyn Resolver>,
    tunnel: Arc<Tunnel>,
    /// `refresh-server-ip-interval`：解析结果的缓存（解析时刻，各对端端点）。
    resolved: Mutex<Option<(Instant, Endpoints)>>,
    resolve_generation: std::sync::atomic::AtomicU64,
}

impl WireGuardOutbound {
    /// `datagrams` 是外层 UDP 的来源：直连是普通套接字，`dialer-proxy` 时经由另一个出站。
    pub fn new(
        name: String,
        spec: WireGuardSpec,
        resolver: Arc<dyn Resolver>,
        datagrams: Arc<dyn DatagramFactory>,
    ) -> Arc<Self> {
        let tunnel = Tunnel::with_factory(spec.clone(), datagrams);
        Arc::new(Self {
            name,
            inner: Arc::new(Inner {
                spec,
                resolver,
                tunnel,
                resolved: Mutex::new(None),
                resolve_generation: std::sync::atomic::AtomicU64::new(0),
            }),
        })
    }
}

impl Inner {
    /// 各对端的端点，用现有解析路径，不能走隧道内 DNS（隧道还没建立）。
    /// 没有配置刷新间隔时每次都解析（解析器自己有缓存）；配置了就按间隔复用结果。
    /// 个别对端解析失败时沿用它上一次的地址；全部失败才算失败。
    async fn endpoints(&self) -> io::Result<Endpoints> {
        let (previous, generation) = {
            let resolved = self.resolved.lock().unwrap();
            let generation = self
                .resolve_generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            (resolved.clone(), generation)
        };
        if let (Some(secs), Some((at, endpoints))) = (self.spec.refresh_secs, &previous) {
            if at.elapsed() < Duration::from_secs(secs) {
                return Ok(endpoints.clone());
            }
        }
        let mut endpoints: Endpoints = Vec::with_capacity(self.spec.peers.len());
        for (i, peer) in self.spec.peers.iter().enumerate() {
            let fallback = previous
                .as_ref()
                .and_then(|(_, old)| old.get(i).copied().flatten());
            // 粘滞：上次用的地址仍在解析结果里就继续用它。多条 A 记录轮换时每次取第一个会让
            // 引擎认为端点变了而反复拆会话重新握手（握手风暴）
            let found = resolve_target(self.resolver.as_ref(), &peer.endpoint)
                .await
                .ok()
                .and_then(|addrs| match fallback {
                    Some(old) if addrs.contains(&old) => Some(old),
                    _ => addrs.into_iter().next(),
                });
            endpoints.push(found.or(fallback));
        }
        if endpoints.iter().all(Option::is_none) {
            return Err(io::Error::other("cannot resolve wireguard endpoint"));
        }
        let mut resolved = self.resolved.lock().unwrap();
        // 旧解析完成不得覆盖换网或更新一次解析的结果；旧 Flow 仍可使用其初始化快照。
        if self
            .resolve_generation
            .load(std::sync::atomic::Ordering::Relaxed)
            == generation
        {
            self.tunnel.update_endpoints(&endpoints);
            *resolved = Some((Instant::now(), endpoints.clone()));
        }
        Ok(endpoints)
    }

    fn usable(&self, ip: IpAddr) -> bool {
        let family = match ip {
            IpAddr::V4(_) => self.spec.address_v4.is_some(),
            IpAddr::V6(_) => self.spec.address_v6.is_some(),
        };
        family
            && self
                .spec
                .peers
                .iter()
                .any(|peer| peer.allowed_ips.iter().any(|cidr| cidr.contains(ip)))
    }

    /// Flow 目标 → 隧道内地址。配置了 `remote-dns-resolve` 时域名只经隧道内 DNS 解析，
    /// 否则沿用现有 Resolver；答案只用于这一次连接，不写回 Flow。
    async fn destination(
        &self,
        endpoints: &Endpoints,
        target: &TargetAddr,
    ) -> io::Result<SocketAddr> {
        let candidates: Vec<SocketAddr> = match target {
            TargetAddr::Ip(addr) => vec![*addr],
            TargetAddr::Domain(host, port) if self.spec.remote_dns => self
                .tunnel
                .resolve(endpoints, host)
                .await?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, *port))
                .collect(),
            TargetAddr::Domain(..) => resolve_target(self.resolver.as_ref(), target).await?,
        };
        candidates
            .into_iter()
            .find(|addr| self.usable(addr.ip()))
            .ok_or_else(|| io::Error::other("destination is outside allowed-ips"))
    }
}

struct Control(Arc<Inner>);
impl SessionControl for Control {
    fn on_network_changed(&self) {
        self.0.tunnel.on_network_changed();
        // 换网后端点可能解析到别的地址：作废缓存、重新解析并推给引擎，既有流也改发到新地址，
        // 而不是继续向旧地址重握手、15 秒后全部失败
        {
            let mut resolved = self.0.resolved.lock().unwrap();
            self.0
                .resolve_generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            resolved.take();
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let inner = self.0.clone();
            runtime.spawn(async move {
                let _ = inner.endpoints().await;
            });
        }
    }
    fn on_sleep(&self) {
        self.0.tunnel.on_sleep();
    }
    fn on_wake(&self) {
        self.0.tunnel.on_wake();
    }
}

#[async_trait]
impl Outbound for WireGuardOutbound {
    fn tag(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "wireguard"
    }
    fn session_control(&self) -> Option<Arc<dyn SessionControl>> {
        Some(Arc::new(Control(self.inner.clone())))
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let endpoints = self.inner.endpoints().await?;
        let dest = self.inner.destination(&endpoints, target).await?;
        let stream = self.inner.tunnel.connect_tcp(&endpoints, dest).await?;
        Ok(Box::new(stream))
    }
    async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.inner.spec.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "wireguard udp is disabled",
            ));
        }
        let endpoints = self.inner.endpoints().await?;
        let session = self.inner.tunnel.bind_udp(&endpoints).await?;
        Ok(Box::new(WireGuardPacket {
            inner: self.inner.clone(),
            endpoints,
            session,
        }))
    }
}

struct WireGuardPacket {
    inner: Arc<Inner>,
    endpoints: Endpoints,
    session: UdpSession,
}

#[async_trait]
impl PacketConn for WireGuardPacket {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        let dest = self.inner.destination(&self.endpoints, target).await?;
        self.session.send_to(buf, dest)
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let (n, from) = self.session.recv_from(buf).await?;
        Ok((n, TargetAddr::Ip(from)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryn_config::{IpCidr, WireGuardPeerSpec};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 每次解析返回不同的地址；`fail` 里的域名解析失败。
    struct Counting {
        calls: AtomicUsize,
        fail: Vec<&'static str>,
    }
    #[async_trait]
    impl Resolver for Counting {
        async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) as u8;
            if self.fail.contains(&host) {
                return Err(io::Error::other("resolve failed"));
            }
            Ok(vec![IpAddr::from([127, 0, 0, 10 + n])])
        }
    }

    fn spec(refresh_secs: Option<u64>, hosts: &[&str]) -> WireGuardSpec {
        WireGuardSpec {
            peers: hosts
                .iter()
                .map(|host| WireGuardPeerSpec {
                    endpoint: TargetAddr::Domain((*host).into(), 51820),
                    public_key: [1; 32],
                    preshared_key: None,
                    allowed_ips: vec![IpCidr::parse("10.0.0.0/24").unwrap()],
                    reserved: [0; 3],
                    keepalive_secs: None,
                })
                .collect(),
            private_key: [2; 32],
            address_v4: Some(("10.0.0.2".parse().unwrap(), 32)),
            address_v6: None,
            mtu: 1280,
            keepalive_secs: 0,
            udp: false,
            remote_dns: false,
            dns: vec![],
            amnezia: None,
            refresh_secs,
            tcp_buffers: Default::default(),
        }
    }

    fn inner(
        refresh_secs: Option<u64>,
        hosts: &[&str],
        fail: Vec<&'static str>,
    ) -> (Arc<Inner>, Arc<Counting>) {
        let resolver = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            fail,
        });
        let out = WireGuardOutbound::new(
            "wg".into(),
            spec(refresh_secs, hosts),
            resolver.clone(),
            Arc::new(oryn_udp::UdpFactory),
        );
        (out.inner.clone(), resolver)
    }

    #[tokio::test]
    async fn without_a_refresh_interval_every_call_resolves() {
        let (inner, resolver) = inner(None, &["a.example"], vec![]);
        let first = inner.endpoints().await.unwrap();
        let second = inner.endpoints().await.unwrap();
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn refresh_interval_reuses_the_result_until_it_expires() {
        let (inner, resolver) = inner(Some(1), &["a.example", "b.example"], vec![]);
        let first = inner.endpoints().await.unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(inner.endpoints().await.unwrap(), first);
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            2,
            "缓存期内不重新解析"
        );
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let refreshed = inner.endpoints().await.unwrap();
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 4);
        assert_ne!(refreshed, first, "到期后重新解析并使用新地址");
    }

    #[tokio::test]
    async fn a_peer_that_fails_to_resolve_keeps_its_previous_address() {
        let (inner, _) = inner(None, &["a.example", "b.example"], vec![]);
        let first = inner.endpoints().await.unwrap();
        // 之后 b 解析失败：沿用上一次的地址
        let resolver = Arc::new(Counting {
            calls: AtomicUsize::new(100),
            fail: vec!["b.example"],
        });
        let flaky = Inner {
            spec: spec(None, &["a.example", "b.example"]),
            resolver,
            tunnel: inner.tunnel.clone(),
            resolved: Mutex::new(inner.resolved.lock().unwrap().clone()),
            resolve_generation: std::sync::atomic::AtomicU64::new(0),
        };
        let second = flaky.endpoints().await.unwrap();
        assert_ne!(second[0], first[0]);
        assert_eq!(second[1], first[1]);
        // 全部失败且没有历史：报错
        let (none, _) = inner_failing();
        assert!(none.endpoints().await.is_err());
    }

    fn inner_failing() -> (Arc<Inner>, ()) {
        let resolver = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            fail: vec!["a.example"],
        });
        let out = WireGuardOutbound::new(
            "wg".into(),
            spec(None, &["a.example"]),
            resolver,
            Arc::new(oryn_udp::UdpFactory),
        );
        (out.inner.clone(), ())
    }
}
