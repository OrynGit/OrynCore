//! 每个出站一条 QUIC 连接。失败重试有上限，没有后台空转。

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use oryn_udp::{DatagramFactory, Datagrams};
use quinn::congestion::{BbrConfig, CubicConfig, NewRenoConfig};
use tokio::sync::{watch, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

use crate::brutal::BrutalFactory;
use crate::socket::{HopPort, Obfs, QuicSocket};
use crate::{
    DATAGRAM_RECEIVE, DATAGRAM_SEND, MAX_BIDI, MAX_UDP_PAYLOAD, MAX_UNI, RECEIVE_WINDOW,
    BRUTAL_SEND_WINDOW, SEND_WINDOW, STREAM_RECEIVE_WINDOW,
};

#[derive(Clone, Copy)]
pub enum Congestion {
    Bbr,
    Cubic,
    NewReno,
}

pub struct Hop {
    pub ranges: Vec<(u16, u16)>,
    pub count: u32,
    pub min: Duration,
    pub max: Duration,
}

pub struct QuicParams {
    /// 创建到对端的数据报通道：直连是 UDP 套接字，`dialer-proxy` 时经由另一个出站。
    pub datagrams: Arc<dyn DatagramFactory>,
    pub alpn: Vec<Vec<u8>>,
    pub skip_verify: bool,
    pub fingerprint: Option<[u8; 32]>,
    pub disable_sni: bool,
    pub congestion: Congestion,
    /// 配置了上传带宽时存在。认证之后可以改小。
    pub brutal_rate: Option<Arc<AtomicU64>>,
    pub obfs: Option<Obfs>,
    pub hop: Option<Hop>,
    /// 对端在 NAT 之后时（Hysteria2 Realm），由它打洞并给出数据报通道与对端地址；
    /// 此时 `connection` 的地址参数只用来判断是否复用现有连接。
    pub rendezvous: Option<Arc<dyn Rendezvous>>,
    /// 有会话票据时以 0-RTT 发起连接（TUIC `reduce-rtt`）。服务器拒绝时，0-RTT 期间打开的流会失败。
    pub zero_rtt: bool,
    /// QUIC 层保活（PING）间隔。`None` 时连接空闲 30 s 即关闭，其上仍打开的流随之失效；
    /// 协议自带心跳（TUIC）或不需要长连接的出站保持 `None`。
    pub keep_alive: Option<Duration>,
}

#[async_trait::async_trait]
pub trait Rendezvous: Send + Sync {
    /// 打通到对端的路径，返回已打洞的数据报通道与对端的实际地址。
    async fn establish(&self) -> std::io::Result<(Arc<dyn Datagrams>, SocketAddr)>;
}

/// 被服务器接受的 0-RTT 连接数，仅供测试与诊断。
static ZERO_RTT_ACCEPTED: AtomicU64 = AtomicU64::new(0);

pub fn zero_rtt_accepted() -> u64 {
    ZERO_RTT_ACCEPTED.load(Ordering::Relaxed)
}

/// 0-RTT 连接的握手结果：`None` 为仍在握手，`Some(true)` 为 0-RTT 被接受，`Some(false)` 为被拒绝或握手失败。
pub type Handshake = watch::Receiver<Option<bool>>;

struct Live {
    conn: quinn::Connection,
    // 端点拥有套接字。丢掉它会拆掉连接。
    _endpoint: quinn::Endpoint,
    epoch: u64,
    handshake: Option<Handshake>,
}

pub struct QuicClient {
    params: QuicParams,
    dial: AsyncMutex<()>,
    live: Mutex<Option<Live>>,
    epoch: AtomicU64,
    asleep: AtomicBool,
    use_brutal: AtomicBool,
    hop_port: Arc<HopPort>,
    hop_task: Mutex<Option<JoinHandle<()>>>,
    /// TLS 配置跨连接复用，会话票据才能留到下一次拨号。
    tls: OnceLock<quinn::ClientConfig>,
    transport_override: Option<Arc<quinn::TransportConfig>>,
}

impl QuicClient {
    pub fn new(params: QuicParams) -> Arc<Self> {
        Self::configured(params, None, None)
    }

    /// 专用协议（JLS）提供独立 TLS 配置与有界传输参数，不改变普通 QUIC 路径。
    pub fn with_config(
        params: QuicParams,
        tls: quinn::ClientConfig,
        transport: Arc<quinn::TransportConfig>,
    ) -> Arc<Self> {
        Self::configured(params, Some(tls), Some(transport))
    }
    fn configured(
        params: QuicParams,
        tls_config: Option<quinn::ClientConfig>,
        transport_override: Option<Arc<quinn::TransportConfig>>,
    ) -> Arc<Self> {
        let initial = params
            .hop
            .as_ref()
            .and_then(|hop| hop.ranges.first().map(|range| range.0))
            .unwrap_or(0);
        let use_brutal = params.brutal_rate.is_some();
        let client = Arc::new(Self {
            params,
            dial: AsyncMutex::new(()),
            live: Mutex::new(None),
            epoch: AtomicU64::new(0),
            asleep: AtomicBool::new(false),
            use_brutal: AtomicBool::new(use_brutal),
            hop_port: Arc::new(HopPort(std::sync::atomic::AtomicU16::new(initial))),
            hop_task: Mutex::new(None),
            tls: OnceLock::new(),
            transport_override,
        });
        if let Some(tls) = tls_config {
            let _ = client.tls.set(tls);
        }
        if let Some(hop) = client.params.hop.as_ref() {
            if hop.count > 1 {
                let port = client.hop_port.clone();
                let ranges = hop.ranges.clone();
                let count = hop.count;
                let min = hop.min;
                let max = hop.max;
                // 间隔与端口都随机取（与参考实现一致），确定性序列会成为可识别的流量特征
                let task = tokio::spawn(async move {
                    loop {
                        let wait = hop_delay(min, max, rand::random());
                        tokio::time::sleep(wait).await;
                        let current = port.0.load(Ordering::Relaxed);
                        let mut next = pick(&ranges, count, rand::random());
                        if next == current {
                            next = pick(&ranges, count, rand::random());
                        }
                        port.0.store(next, Ordering::Relaxed);
                    }
                });
                *client.hop_task.lock().unwrap() = Some(task);
            }
        }
        client
    }

    pub fn on_network_changed(&self) {
        self.bump_and_close(b"network changed");
    }

    pub fn on_sleep(&self) {
        self.asleep.store(true, Ordering::Relaxed);
    }

    pub fn on_wake(&self) {
        self.asleep.store(false, Ordering::Relaxed);
        self.bump_and_close(b"wake");
    }

    /// 改用 BBR。拥塞控制器在建连时确定，所以要关掉当前连接；只在真正从 Brutal 切换时关一次，
    /// 之后每条新连接认证时再收到 `auto` 不再关闭（否则每条连接都会被立刻拆掉）。
    /// 返回是否关闭了当前连接，调用方据此在新连接上重试。
    pub fn disable_brutal(&self) -> bool {
        if self.use_brutal.swap(false, Ordering::Relaxed) {
            self.bump_and_close(b"bbr");
            true
        } else {
            false
        }
    }

    /// 恢复配置的 Brutal；与 disable_brutal 对称，仅模式变化时重建连接。
    /// 调用方须先更新协商速率；没有配置上传带宽时不能启用。
    pub fn enable_brutal(&self) -> bool {
        if self.params.brutal_rate.is_some() && !self.use_brutal.swap(true, Ordering::Relaxed) {
            self.bump_and_close(b"brutal");
            true
        } else {
            false
        }
    }

    /// `conn` 若是仍可能在握手中的 0-RTT 连接，返回其握手结果。
    pub fn handshake(&self, conn: &quinn::Connection) -> Option<Handshake> {
        let live = self.live.lock().unwrap();
        let live = live.as_ref()?;
        if live.conn.stable_id() != conn.stable_id() {
            return None;
        }
        live.handshake.clone()
    }

    pub fn is_asleep(&self) -> bool {
        self.asleep.load(Ordering::Relaxed)
    }

    fn bump_and_close(&self, reason: &[u8]) {
        self.epoch.fetch_add(1, Ordering::Relaxed);
        if let Some(live) = self.live.lock().unwrap().take() {
            live.conn.close(0u32.into(), reason);
        }
    }

    /// 复用现有连接；连接已关闭或经历了网络变化 / 唤醒（epoch 变化）才重新拨号。
    ///
    /// 不因 `peer_ip` 与现有连接不同而重拨：服务器域名多条 A 记录轮换（CDN 常见）时，
    /// 每次解析得到的地址都可能不同，按地址重拨会让新 Flow 反复关闭仍健康的连接与其上全部活动流。
    pub async fn connection(
        &self,
        peer_ip: IpAddr,
        server_name: &str,
        stable_port: u16,
    ) -> std::io::Result<quinn::Connection> {
        let _guard = self.dial.lock().await;
        let peer = SocketAddr::new(peer_ip, stable_port);
        let epoch = self.epoch.load(Ordering::Relaxed);
        if let Some(live) = self.live.lock().unwrap().as_ref() {
            if live.epoch == epoch && live.conn.close_reason().is_none() {
                return Ok(live.conn.clone());
            }
        }
        let mut delay = Duration::from_secs(1);
        let mut last = std::io::Error::other("quic connect failed");
        for attempt in 0..3 {
            if self.epoch.load(Ordering::Relaxed) != epoch {
                return Err(std::io::Error::other("quic connect cancelled"));
            }
            match self.dial_once(peer, server_name, epoch).await {
                Ok(conn) => return Ok(conn),
                Err(err) => {
                    last = err;
                    if attempt == 2 {
                        break;
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(4));
                }
            }
        }
        Err(last)
    }

    async fn dial_once(
        &self,
        peer: SocketAddr,
        server_name: &str,
        epoch: u64,
    ) -> std::io::Result<quinn::Connection> {
        if self.hop_port.0.load(Ordering::Relaxed) == 0 {
            self.hop_port.0.store(peer.port(), Ordering::Relaxed);
        }
        let (udp, remote) = match &self.params.rendezvous {
            Some(rendezvous) => rendezvous.establish().await?,
            None => (self.params.datagrams.bind(peer).await?, peer),
        };
        // 打洞得到的对端端口不能被跳跃端口改写
        let hop = match &self.params.rendezvous {
            Some(_) => Arc::new(HopPort(std::sync::atomic::AtomicU16::new(0))),
            None => self.hop_port.clone(),
        };
        let socket = QuicSocket::bind(udp, remote, hop, self.params.obfs.clone())?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let alpn = self
            .params
            .alpn
            .iter()
            .map(|item| item.as_slice())
            .collect::<Vec<_>>();
        let mut config = match self.tls.get() {
            Some(config) => config.clone(),
            None => {
                let config = oryn_tls::quic_client_config_ex(
                    &alpn,
                    self.params.skip_verify,
                    self.params.fingerprint,
                    !self.params.disable_sni,
                    self.params.zero_rtt,
                )?;
                self.tls.get_or_init(|| config).clone()
            }
        };
        config.transport_config(match &self.transport_override {
            Some(t) => t.clone(),
            None => Arc::new(self.transport()?),
        });
        let connecting = endpoint
            .connect_with(config, remote, server_name)
            .map_err(std::io::Error::other)?;
        let (conn, handshake) = match self.zero_rtt(connecting) {
            Ok((conn, handshake)) => (conn, Some(handshake)),
            Err(connecting) => {
                match tokio::time::timeout(Duration::from_secs(10), connecting).await {
                    Ok(result) => (result.map_err(std::io::Error::other)?, None),
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "quic handshake timed out",
                        ))
                    }
                }
            }
        };
        if self.epoch.load(Ordering::Relaxed) != epoch {
            conn.close(0u32.into(), b"cancelled");
            return Err(std::io::Error::other("quic connect cancelled"));
        }
        let previous = self.live.lock().unwrap().replace(Live {
            conn: conn.clone(),
            _endpoint: endpoint,
            epoch,
            handshake,
        });
        if let Some(previous) = previous {
            previous.conn.close(0u32.into(), b"replaced");
        }
        Ok(conn)
    }

    /// 有票据且启用了 0-RTT 时立即返回连接；握手在后台完成，超时则关闭连接。
    fn zero_rtt(
        &self,
        connecting: quinn::Connecting,
    ) -> Result<(quinn::Connection, Handshake), quinn::Connecting> {
        if !self.params.zero_rtt {
            return Err(connecting);
        }
        let (conn, accepted) = connecting.into_0rtt()?;
        let (tx, rx) = watch::channel(None);
        let watched = conn.clone();
        tokio::spawn(async move {
            let accepted = match tokio::time::timeout(Duration::from_secs(10), accepted).await {
                Ok(accepted) => accepted,
                Err(_) => {
                    watched.close(0u32.into(), b"handshake timeout");
                    false
                }
            };
            if accepted {
                ZERO_RTT_ACCEPTED.fetch_add(1, Ordering::Relaxed);
            }
            let _ = tx.send(Some(accepted));
        });
        Ok((conn, rx))
    }

    fn transport(&self) -> std::io::Result<quinn::TransportConfig> {
        let mut transport = quinn::TransportConfig::default();
        let brutal = self.use_brutal.load(Ordering::Relaxed) && self.params.brutal_rate.is_some();
        let idle = Duration::from_secs(30)
            .try_into()
            .map_err(std::io::Error::other)?;
        transport
            .max_idle_timeout(Some(idle))
            .keep_alive_interval(self.params.keep_alive)
            .stream_receive_window(quinn::VarInt::from_u32(STREAM_RECEIVE_WINDOW))
            .receive_window(quinn::VarInt::from_u32(RECEIVE_WINDOW))
            .send_window(if brutal {
                BRUTAL_SEND_WINDOW
            } else {
                SEND_WINDOW
            })
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_BIDI as u32))
            .max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_UNI as u32))
            .datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE))
            .datagram_send_buffer_size(DATAGRAM_SEND)
            .initial_mtu(MAX_UDP_PAYLOAD);
        let factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
            if self.use_brutal.load(Ordering::Relaxed) {
                if let Some(rate) = &self.params.brutal_rate {
                    Arc::new(BrutalFactory { rate: rate.clone() })
                } else {
                    Arc::new(BbrConfig::default())
                }
            } else {
                match self.params.congestion {
                    Congestion::Bbr => Arc::new(BbrConfig::default()),
                    Congestion::Cubic => Arc::new(CubicConfig::default()),
                    Congestion::NewReno => Arc::new(NewRenoConfig::default()),
                }
            };
        transport.congestion_controller_factory(factory);
        Ok(transport)
    }
}

impl Drop for QuicClient {
    fn drop(&mut self) {
        if let Some(task) = self.hop_task.lock().unwrap().take() {
            task.abort();
        }
        if let Some(live) = self.live.lock().unwrap().take() {
            live.conn.close(0u32.into(), b"drop");
        }
    }
}

fn hop_delay(min: Duration, max: Duration, n: u32) -> Duration {
    if max <= min {
        return min;
    }
    let span = (max - min).as_millis() as u64;
    min + Duration::from_millis(u64::from(n) % (span + 1))
}

fn pick(ranges: &[(u16, u16)], count: u32, n: u32) -> u16 {
    let mut left = n % count.max(1);
    for &(start, end) in ranges {
        let width = u32::from(end - start) + 1;
        if left < width {
            return start + left as u16;
        }
        left -= width;
    }
    ranges.first().map(|range| range.0).unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 本机 QUIC 服务端，空闲超时 `idle`。
    fn server(idle: Duration) -> quinn::Endpoint {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(oryn_tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
            )
            .unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(idle.try_into().unwrap()));
        config.transport_config(Arc::new(transport));
        quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap()
    }

    fn client(keep_alive: Option<Duration>) -> Arc<QuicClient> {
        QuicClient::new(QuicParams {
            datagrams: Arc::new(oryn_udp::UdpFactory),
            alpn: Vec::new(),
            skip_verify: true,
            fingerprint: None,
            disable_sni: false,
            congestion: Congestion::Bbr,
            brutal_rate: None,
            obfs: None,
            hop: None,
            rendezvous: None,
            zero_rtt: false,
            keep_alive,
        })
    }

    /// 流上写一段、空闲超过服务端空闲超时、再写一段，返回服务端是否完整收到。
    async fn survives_idle(keep_alive: Option<Duration>) -> bool {
        let endpoint = server(Duration::from_secs(1));
        let addr = endpoint.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let mut stream = conn.accept_uni().await.ok()?;
            stream.read_to_end(64).await.ok()
        });
        let client = client(keep_alive);
        let conn = client
            .connection(addr.ip(), "localhost", addr.port())
            .await
            .unwrap();
        let mut stream = conn.open_uni().await.unwrap();
        stream.write_all(b"before").await.unwrap();
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let sent = stream.write_all(b"after").await.is_ok() && stream.finish().is_ok();
        let received = receiver.await.unwrap();
        sent && received.as_deref() == Some(b"beforeafter".as_slice())
    }

    /// 空闲超过服务端超时后，长连接上的流仍可用（OrynCore#14）。
    #[tokio::test]
    async fn keep_alive_keeps_idle_stream_usable() {
        assert!(
            !survives_idle(None).await,
            "without keep-alive the idle connection should time out"
        );
        assert!(
            survives_idle(Some(Duration::from_millis(300))).await,
            "keep-alive should keep the idle connection alive"
        );
    }
}
