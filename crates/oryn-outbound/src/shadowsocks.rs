use crate::uot::UotConn;
use crate::{
    resolve_target, unsupported, with_timeout, BoxStream, Dialer, Outbound, PacketConn, Resolver,
};
use async_trait::async_trait;
use bytes::BytesMut;
use oryn_config::TargetAddr;
use oryn_protocol::shadowsocks::{
    self as ss, Context, ServerConfig, ServerType, UdpSocketControlData,
};
use oryn_udp::{DatagramFactory, Datagrams};
use ring::rand::{SecureRandom, SystemRandom};
use std::net::SocketAddr;
use std::{
    io,
    sync::{Arc, Mutex},
    time::SystemTime,
};
use tokio::io::AsyncWriteExt;

pub struct ShadowsocksOutbound {
    tag: String,
    server: TargetAddr,
    config: io::Result<Arc<ServerConfig>>,
    udp: bool,
    /// UDP over TCP 的版本：配置后 UDP 不走原生 UDP，而是在 SS 的 TCP 连接里承载。
    uot: Option<u8>,
    dialer: Arc<dyn Dialer>,
    resolver: Arc<dyn Resolver>,
    datagrams: Arc<dyn DatagramFactory>,
}
impl ShadowsocksOutbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: String,
        server: TargetAddr,
        cipher: &str,
        password: &str,
        udp: bool,
        uot: Option<u8>,
        dialer: Arc<dyn Dialer>,
        resolver: Arc<dyn Resolver>,
        datagrams: Arc<dyn DatagramFactory>,
    ) -> Self {
        let config = ss::config(&server, cipher, password).map(Arc::new);
        Self {
            tag,
            server,
            config,
            udp,
            uot,
            dialer,
            resolver,
            datagrams,
        }
    }
    fn config(&self) -> io::Result<Arc<ServerConfig>> {
        self.config.as_ref().cloned().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Shadowsocks configuration",
            )
        })
    }
}
#[async_trait]
impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "ss"
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let addr = ss::address(target)?;
        let config = self.config()?;
        with_timeout(
            async {
                let s = self.dialer.dial_tcp(&self.server).await?;
                // 提前发空首包，既支持 server-first 应用，也避免库首包拼接大 payload。
                // 2022 库会为无 payload 的握手填充随机长度 padding。
                let mut s = ss::ProxyClientStream::from_stream(
                    Context::new_shared(ServerType::Local),
                    s,
                    &config,
                    addr,
                );
                let _ = s.write(&[]).await?;
                s.flush().await?;
                Ok(Box::new(s) as BoxStream)
            },
            "Shadowsocks handshake",
        )
        .await
    }
    async fn bind_udp(&self, first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        if !self.udp {
            return Err(unsupported("UDP is not enabled for this Shadowsocks proxy"));
        }
        if let Some(version) = self.uot {
            let magic = TargetAddr::Domain(crate::uot::magic(version).into(), 0);
            let stream = self.connect_tcp(&magic).await?;
            return Ok(Box::new(UotConn::new(stream, version, first_target)?));
        }
        let server = with_timeout(
            resolve_target(&*self.resolver, &self.server),
            "Shadowsocks UDP resolve",
        )
        .await?[0];
        let socket = self.datagrams.bind(server).await?;
        let mut random = [0; 8];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| io::Error::other("system random source failed"))?;
        Ok(Box::new(SsPacketConn {
            socket,
            server,
            config: self.config()?,
            context: Context::new(ServerType::Local),
            state: Mutex::new(UdpState {
                session: u64::from_be_bytes(random),
                next: 0,
                windows: Vec::new(),
                wall_high: None,
                clock_failed: false,
            }),
            scratch: crate::RecvScratch::new(),
        }))
    }
}
struct UdpState {
    session: u64,
    next: u64,
    windows: Vec<(u64, Window, u64)>,
    wall_high: Option<SystemTime>,
    clock_failed: bool,
}
impl UdpState {
    // vendor 的时间戳检查使用墙钟；回拨后不能再信任已回收的滑窗。
    // 错误永久保留，调用方必须重建关联（生成新的 client session ID）。
    fn observe_clock(&mut self, now: SystemTime) -> io::Result<u64> {
        if self.wall_high.is_some_and(|high| now < high) {
            self.clock_failed = true;
        }
        let epoch = now.duration_since(SystemTime::UNIX_EPOCH);
        if self.clock_failed || epoch.is_err() {
            self.clock_failed = true;
            return Err(io::Error::other(
                "Shadowsocks UDP clock moved backwards; recreate association",
            ));
        }
        self.wall_high = Some(now);
        Ok(epoch.unwrap().as_secs())
    }

    fn accept_reply(&mut self, control: &UdpSocketControlData, now: u64) -> bool {
        if control.client_session_id != self.session {
            return false;
        }
        let i =
            match self
                .windows
                .iter()
                .position(|(id, _, _)| *id == control.server_session_id)
            {
                Some(i) => i,
                None if self.windows.len() < 4 => {
                    self.windows
                        .push((control.server_session_id, Window::default(), now));
                    self.windows.len() - 1
                }
                None => {
                    // ±30 秒且端点有效：首次接收可比认证时间戳早 30 秒，
                    // 同一密文在 +60 整秒仍可能有效，必须严格大于 60。
                    // 只替换过期槽，不忘记任何仍受保护的滑窗；不是 LRU。
                    let Some(i) = self.windows.iter().position(|(_, _, seen)| {
                        now.checked_sub(*seen).is_some_and(|age| age > 60)
                    }) else {
                        return false;
                    };
                    self.windows[i] = (control.server_session_id, Window::default(), now);
                    i
                }
            };
        if !self.windows[i].1.accept(control.packet_id) {
            return false;
        }
        self.windows[i].2 = now;
        true
    }
}
#[derive(Default)]
struct Window {
    highest: u64,
    bits: u64,
}
impl Window {
    fn accept(&mut self, id: u64) -> bool {
        if self.bits == 0 {
            self.highest = id;
            self.bits = 1;
            return true;
        }
        if id > self.highest {
            let shift = id - self.highest;
            self.bits = if shift >= 64 {
                1
            } else {
                (self.bits << shift) | 1
            };
            self.highest = id;
            return true;
        }
        let offset = self.highest - id;
        if offset >= 64 || self.bits & (1 << offset) != 0 {
            return false;
        }
        self.bits |= 1 << offset;
        true
    }
}
struct SsPacketConn {
    socket: Arc<dyn Datagrams>,
    server: SocketAddr,
    config: Arc<ServerConfig>,
    context: Context,
    state: Mutex<UdpState>,
    scratch: crate::RecvScratch,
}
#[async_trait]
impl PacketConn for SsPacketConn {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        if buf.len() > 65507 - 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks UDP payload too large",
            ));
        }
        let address = ss::address(target)?;
        let control = {
            let mut state = self.state.lock().unwrap();
            if self.config.method().is_aead_2022() {
                state.observe_clock(SystemTime::now())?;
            }
            let mut c = UdpSocketControlData::default();
            c.client_session_id = state.session;
            c.packet_id = state.next;
            state.next = state
                .next
                .checked_add(1)
                .ok_or_else(|| io::Error::other("Shadowsocks UDP packet counter exhausted"))?;
            c
        };
        let mut packet = BytesMut::with_capacity(buf.len() + 1024);
        ss::crypto_io::encrypt_client_payload(
            &self.context,
            self.config.method(),
            self.config.key(),
            &address,
            &control,
            self.config.identity_keys(),
            buf,
            &mut packet,
        );
        self.socket.try_send_to(&packet, self.server)
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut packet = self.scratch.take();
        loop {
            let (n, from) = self.socket.recv_from(&mut packet).await?;
            if from != self.server {
                continue;
            }
            // 在 vendor 时间戳检查两侧采样，并持锁串行化 send/recv 的时钟观察。
            let mut state = self.state.lock().unwrap();
            if self.config.method().is_aead_2022() {
                state.observe_clock(SystemTime::now())?;
            }
            let decoded = ss::crypto_io::decrypt_server_payload(
                &self.context,
                self.config.method(),
                self.config.key(),
                &mut packet[..n],
            );
            let now = if self.config.method().is_aead_2022() {
                state.observe_clock(SystemTime::now())?
            } else {
                0
            };
            let Ok((len, addr, control)) = decoded else {
                continue;
            };
            if let Some(control) = control {
                if !state.accept_reply(&control, now) {
                    continue;
                }
            }
            let n = crate::copy_datagram(&packet[..len], buf, "Shadowsocks");
            return Ok((n, ss::target(addr)));
        }
    }
}

#[cfg(test)]
#[path = "shadowsocks_reclaim_tests.rs"]
mod reclaim_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_replay_window() {
        let mut w = Window::default();
        assert!(w.accept(100));
        assert!(!w.accept(100));
        assert!(w.accept(99));
        assert!(!w.accept(99));
        assert!(!w.accept(1));
        assert!(w.accept(200));
        assert!(!w.accept(100));
        assert!(w.accept(199));
        assert!(w.accept(u64::MAX));
        assert!(!w.accept(u64::MAX));
    }
}
