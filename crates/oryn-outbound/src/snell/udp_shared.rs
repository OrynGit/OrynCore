//! Snell UDP 共用连接：多个 UDP 会话共用少数几条 Snell UDP 连接，按回包来源 `IP:端口` 分发。
//!
//! Snell 的 UDP 包本身带目标地址，一条连接可以承载多个目标。会话的目标在登记前已解析成 IP
//! （与 mihomo 先在本地解析 UDP 目标的做法一致），所以回包归属没有歧义；同一条连接上同一个
//! `IP:端口` 只登记一个会话，冲突时换连接。设计与取舍见 Oryn_dev/docs/oryncore/plans/plan-snell-udp-shared.md。
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use oryn_config::TargetAddr;
use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::sync::mpsc;

use super::{
    decode_udp_response, encode_udp_target, Config, Frame, PacketWriter, Rx, Tx, READ_CHUNK,
    UDP_FORWARD,
};
use crate::{BoxStream, PacketConn};

/// 每个 Snell 出站最多的共用 UDP 连接数。
pub(super) const MAX_SHARED_CONNECTIONS: usize = 4;
/// 每条共用连接最多承载的会话数。
pub(super) const MAX_ROUTES: usize = 128;
/// 每个会话待取回包的上限（个），满则丢弃。
const ROUTE_QUEUE: usize = 64;
/// 最后一个会话结束后，连接保留多久再关闭。
const SHARED_IDLE: Duration = Duration::from_secs(30);
const IDLE_CHECK: Duration = Duration::from_secs(5);

type Delivery = mpsc::Sender<(Vec<u8>, SocketAddr)>;

static NEXT_ROUTE: AtomicU64 = AtomicU64::new(1);

/// 一个 Snell 出站的共用 UDP 连接池。
#[derive(Default)]
pub(super) struct UdpHub {
    conns: Mutex<Vec<Arc<SharedConn>>>,
    /// 新建共用连接时串行：并发到来的会话等第一条连接建好后直接登记，不各自建连。
    creating: tokio::sync::Mutex<()>,
}

impl UdpHub {
    /// 在已有共用连接上登记会话；都放不下（已满或该地址已被占用）时返回 None。
    pub(super) fn try_bind(&self, addr: SocketAddr) -> Option<SharedPacket> {
        let mut conns = self.conns.lock().unwrap();
        conns.retain(|c| !c.is_closed());
        conns.iter().find_map(|c| SharedConn::register(c, addr))
    }

    pub(super) fn can_grow(&self) -> bool {
        let mut conns = self.conns.lock().unwrap();
        conns.retain(|c| !c.is_closed());
        conns.len() < MAX_SHARED_CONNECTIONS
    }

    pub(super) async fn creation_lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.creating.lock().await
    }

    /// 新建的共用连接加入池并登记会话。
    pub(super) fn add(&self, conn: Arc<SharedConn>, addr: SocketAddr) -> Option<SharedPacket> {
        let session = SharedConn::register(&conn, addr);
        let mut conns = self.conns.lock().unwrap();
        conns.retain(|c| !c.is_closed());
        if conns.len() < MAX_SHARED_CONNECTIONS {
            conns.push(conn);
        }
        session
    }

    /// 网络变化 / 唤醒：关闭所有共用连接，其上的会话随之结束。
    pub(super) fn clear(&self) {
        for conn in self.conns.lock().unwrap().drain(..) {
            conn.shutdown();
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        let mut conns = self.conns.lock().unwrap();
        conns.retain(|c| !c.is_closed());
        conns.len()
    }
}

/// 一条已完成 UDP 握手的 Snell 连接；后台读任务按来源地址把回包分给会话。
pub(super) struct SharedConn {
    write: tokio::sync::Mutex<PacketWriter>,
    routes: Mutex<Routes>,
    closed: AtomicBool,
}

#[derive(Default)]
struct Routes {
    map: HashMap<SocketAddr, (u64, Delivery)>,
    idle_since: Option<Instant>,
}

impl SharedConn {
    /// `queue` 是握手回复之后已经读到的记录。
    pub(super) fn start(
        cfg: Arc<Config>,
        io: BoxStream,
        tx: Tx,
        rx: Rx,
        inbuf: BytesMut,
        queue: VecDeque<Vec<u8>>,
    ) -> Arc<Self> {
        let (read, write) = tokio::io::split(io);
        let conn = Arc::new(Self {
            write: tokio::sync::Mutex::new(PacketWriter::new(write, tx)),
            routes: Mutex::new(Routes::default()),
            closed: AtomicBool::new(false),
        });
        tokio::spawn(read_loop(
            Arc::downgrade(&conn),
            cfg,
            read,
            rx,
            inbuf,
            queue,
        ));
        conn
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn register(conn: &Arc<Self>, addr: SocketAddr) -> Option<SharedPacket> {
        let mut routes = conn.routes.lock().unwrap();
        if conn.is_closed() {
            return None;
        }
        if routes.map.len() >= MAX_ROUTES || routes.map.contains_key(&addr) {
            return None;
        }
        let (tx, rx) = mpsc::channel(ROUTE_QUEUE);
        let id = NEXT_ROUTE.fetch_add(1, Ordering::Relaxed);
        routes.map.insert(addr, (id, tx));
        routes.idle_since = None;
        Some(SharedPacket {
            conn: conn.clone(),
            id,
            addr,
            rx: tokio::sync::Mutex::new(rx),
        })
    }

    fn unregister(&self, addr: SocketAddr, id: u64) {
        let mut routes = self.routes.lock().unwrap();
        if routes.map.get(&addr).is_some_and(|(owner, _)| *owner == id) {
            routes.map.remove(&addr);
        }
        if routes.map.is_empty() {
            routes.idle_since = Some(Instant::now());
        }
    }

    fn deliver(&self, from: SocketAddr, payload: &[u8]) {
        let routes = self.routes.lock().unwrap();
        if let Some((_, tx)) = routes.map.get(&from) {
            // 会话来不及取时丢弃（UDP 语义），不阻塞读任务
            let _ = tx.try_send((payload.to_vec(), from));
        } else {
            log::debug!(
                "snell: dropping a UDP reply from {from}, no session is registered for it ({} routes)",
                routes.map.len()
            );
        }
    }

    fn idle_expired(&self) -> bool {
        let routes = self.routes.lock().unwrap();
        routes.map.is_empty()
            && routes
                .idle_since
                .is_some_and(|since| since.elapsed() >= SHARED_IDLE)
    }

    /// 标记关闭并丢弃所有路由：会话的接收端随即返回错误。
    fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.routes.lock().unwrap().map.clear();
    }
}

async fn read_loop(
    conn: Weak<SharedConn>,
    cfg: Arc<Config>,
    mut read: ReadHalf<BoxStream>,
    mut rx: Rx,
    mut inbuf: BytesMut,
    mut queue: VecDeque<Vec<u8>>,
) {
    let v4 = matches!(cfg.spec.version, 4 | 5);
    let mut tick = tokio::time::interval(IDLE_CHECK);
    tick.tick().await;
    let mut tmp = vec![0u8; READ_CHUNK];
    'outer: loop {
        while let Some(record) = queue.pop_front() {
            let Some(c) = conn.upgrade() else { return };
            match decode_udp_response(&record, v4) {
                Ok(Some((TargetAddr::Ip(from), payload))) => c.deliver(from, payload),
                Ok(_) => {}
                Err(_) => break 'outer,
            }
        }
        match rx.parse(cfg.psk(), &mut inbuf) {
            Ok(Some(Frame::Data(record))) => {
                queue.push_back(record);
                continue;
            }
            Ok(Some(Frame::Eof)) | Err(_) => break,
            Ok(None) => {}
        }
        tokio::select! {
            // read 可安全取消：未完成时不消费数据
            n = read.read(&mut tmp) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => inbuf.extend_from_slice(&tmp[..n]),
            },
            _ = tick.tick() => {
                let Some(c) = conn.upgrade() else { return };
                if c.is_closed() {
                    break;
                }
                if c.idle_expired() {
                    log::debug!("snell: closing idle shared UDP connection");
                    break;
                }
            }
        }
    }
    if let Some(c) = conn.upgrade() {
        c.shutdown();
    }
}

/// 挂在共用连接上的一个 UDP 会话。只发往登记时解析出的 `addr`。
pub(super) struct SharedPacket {
    conn: Arc<SharedConn>,
    id: u64,
    addr: SocketAddr,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

#[async_trait]
impl PacketConn for SharedPacket {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        if self.conn.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "snell udp closed",
            ));
        }
        // 会话目标在登记时已解析成 `addr`；域名目标一律按这个 IP 发出，回包才能路由回来
        let dest = match target {
            TargetAddr::Domain(..) => TargetAddr::Ip(self.addr),
            ip => ip.clone(),
        };
        let mut packet = Vec::with_capacity(buf.len() + 24);
        packet.push(UDP_FORWARD);
        encode_udp_target(&dest, &mut packet)?;
        packet.extend_from_slice(buf);
        let mut guard = self.conn.write.lock().await;
        // 等待写锁期间连接可能已被其它会话或网络变化关闭。
        if self.conn.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "snell udp closed",
            ));
        }
        let result = guard.send(&packet).await;
        if result.is_err() {
            self.conn.shutdown();
        }
        result
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some((payload, from)) => {
                let n = crate::copy_datagram(&payload, buf, "Snell");
                Ok((n, TargetAddr::Ip(from)))
            }
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "snell udp closed",
            )),
        }
    }
}

impl Drop for SharedPacket {
    fn drop(&mut self) {
        self.conn.unregister(self.addr, self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Config, Frame, SnellOutbound};
    use super::*;
    use crate::{Dialer, Outbound, Resolver};
    use oryn_config::{SnellMode, SnellSpec};
    use std::future::Future;
    use std::net::IpAddr;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn spec() -> SnellSpec {
        SnellSpec {
            server: TargetAddr::Domain("snell.test".into(), 443),
            psk: "test-psk-0123456789".into(),
            version: 4,
            obfs: None,
            mode: SnellMode::Default,
            reuse: false,
            udp: true,
        }
    }

    /// 最小的 Snell v4 UDP 服务端：回复 UDP 请求，之后把每个包原样回给发送方，来源 = 包的目标 IP。
    async fn fake_udp_server(
        cfg: Arc<Config>,
        mut io: DuplexStream,
        close_after_handshake: bool,
        mapped_replies: bool,
    ) {
        let mut rx = cfg.new_rx();
        let mut tx = cfg.new_tx().unwrap();
        let mut inbuf = BytesMut::new();
        let mut handshake = true;
        loop {
            match rx.parse(cfg.psk(), &mut inbuf).unwrap() {
                Some(Frame::Data(record)) => {
                    let mut out = Vec::new();
                    if handshake {
                        handshake = false;
                        tx.stream(&[0], &mut out).unwrap();
                        if io.write_all(&out).await.is_err() || close_after_handshake {
                            return;
                        }
                        continue;
                    }
                    // 命令 1 + 0 + 族 + IP + 端口 + 载荷
                    assert_eq!(record[0], UDP_FORWARD);
                    assert_eq!(record[1], 0, "shared sessions must send IP targets");
                    let (ip_len, family) = if record[2] == 4 { (4, 4u8) } else { (16, 6u8) };
                    let addr_end = 3 + ip_len + 2;
                    let mut reply = vec![family];
                    if mapped_replies && ip_len == 4 {
                        // 官方 snell-server：IPv4 目标的回包来源是 ::ffff:a.b.c.d
                        reply[0] = 6;
                        reply.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
                    }
                    reply.extend_from_slice(&record[3..addr_end]);
                    reply.extend_from_slice(&record[addr_end..]);
                    tx.packet(&reply, &mut out).unwrap();
                    if io.write_all(&out).await.is_err() {
                        return;
                    }
                }
                Some(Frame::Eof) => return,
                None => {
                    let mut tmp = [0u8; 4096];
                    match io.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => inbuf.extend_from_slice(&tmp[..n]),
                    }
                }
            }
        }
    }

    struct FakeDialer {
        cfg: Arc<Config>,
        dials: AtomicUsize,
        close_after_handshake: AtomicBool,
        mapped_replies: AtomicBool,
    }

    #[async_trait]
    impl Dialer for FakeDialer {
        async fn dial_tcp(&self, _: &TargetAddr) -> io::Result<BoxStream> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            let (client, server) = tokio::io::duplex(256 * 1024);
            let close = self.close_after_handshake.load(Ordering::SeqCst);
            let mapped = self.mapped_replies.load(Ordering::SeqCst);
            tokio::spawn(fake_udp_server(self.cfg.clone(), server, close, mapped));
            Ok(Box::new(client))
        }
    }

    struct FakeResolver;

    #[async_trait]
    impl Resolver for FakeResolver {
        async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
            match host {
                // 先给 IPv6 再给 IPv4：应优先选 IPv4
                "dns.test" => Ok(vec![
                    "2001:db8::53".parse().unwrap(),
                    "9.9.9.9".parse().unwrap(),
                ]),
                _ => Err(io::Error::other("nxdomain")),
            }
        }
    }

    fn outbound() -> (Arc<SnellOutbound>, Arc<FakeDialer>) {
        let cfg = Arc::new(Config {
            spec: spec(),
            profile: None,
        });
        let dialer = Arc::new(FakeDialer {
            cfg,
            dials: AtomicUsize::new(0),
            close_after_handshake: AtomicBool::new(false),
            mapped_replies: AtomicBool::new(false),
        });
        let out = SnellOutbound::new("S".into(), spec(), dialer.clone(), Arc::new(FakeResolver));
        (out, dialer)
    }

    fn ip(s: &str) -> TargetAddr {
        TargetAddr::Ip(s.parse().unwrap())
    }

    async fn roundtrip(
        pc: &dyn PacketConn,
        target: &TargetAddr,
        payload: &[u8],
    ) -> (Vec<u8>, TargetAddr) {
        pc.send_to(payload, target).await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), pc.recv_from(&mut buf))
            .await
            .expect("reply")
            .unwrap();
        (buf[..n].to_vec(), from)
    }

    /// 一条会话在 TCP 背压期间取消发送，不得丢弃密文尾部并破坏其它会话。
    #[tokio::test]
    async fn cancelled_shared_udp_write_preserves_record_for_next_session() {
        let cfg = Arc::new(Config {
            spec: spec(),
            profile: None,
        });
        let (client, mut server) = tokio::io::duplex(32);
        let conn = SharedConn::start(
            cfg.clone(),
            Box::new(client),
            cfg.new_tx().unwrap(),
            cfg.new_rx(),
            BytesMut::new(),
            VecDeque::new(),
        );
        let a_addr = "192.0.2.1:53".parse().unwrap();
        let b_addr = "192.0.2.2:53".parse().unwrap();
        let a = SharedConn::register(&conn, a_addr).unwrap();
        let b = SharedConn::register(&conn, b_addr).unwrap();
        let target = TargetAddr::Ip(a_addr);
        let mut send = Box::pin(a.send_to(b"first", &target));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(send.as_mut().poll(&mut cx).is_pending());
        drop(send);
        drop(a);
        let peer = tokio::spawn(async move {
            let mut rx = cfg.new_rx();
            let mut input = BytesMut::new();
            let mut records = Vec::new();
            while records.len() < 2 {
                match rx.parse(cfg.psk(), &mut input)? {
                    Some(Frame::Data(data)) => records.push(data),
                    Some(Frame::Eof) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    None => {
                        let mut buf = [0u8; 4096];
                        let n = server.read(&mut buf).await?;
                        if n == 0 {
                            return Err(io::ErrorKind::UnexpectedEof.into());
                        }
                        input.extend_from_slice(&buf[..n]);
                    }
                }
            }
            // A 已取消且 Drop；B 的回包也必须仍通过同一共享连接正确投递。
            let mut reply = vec![4];
            reply.extend_from_slice(&[192, 0, 2, 2]);
            reply.extend_from_slice(&53u16.to_be_bytes());
            reply.extend_from_slice(b"reply-b");
            let mut encoded = Vec::new();
            cfg.new_tx()?.packet(&reply, &mut encoded)?;
            server.write_all(&encoded).await?;
            Ok::<_, io::Error>(records)
        });
        b.send_to(b"second", &TargetAddr::Ip(b_addr)).await.unwrap();
        let mut response = [0; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..n], b"reply-b");
        assert_eq!(from, TargetAddr::Ip(b_addr));
        let records = tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap()
            .expect("both records must authenticate");
        for (record, addr, payload) in [
            (&records[0], a_addr, b"first".as_slice()),
            (&records[1], b_addr, b"second".as_slice()),
        ] {
            let mut expected = vec![UDP_FORWARD];
            encode_udp_target(&TargetAddr::Ip(addr), &mut expected).unwrap();
            expected.extend_from_slice(payload);
            assert_eq!(record, &expected);
        }
        conn.shutdown();
    }

    #[tokio::test]
    async fn sessions_to_different_addresses_share_one_connection() {
        let (out, dialer) = outbound();
        let targets = [ip("1.1.1.1:53"), ip("8.8.8.8:53"), ip("8.8.4.4:443")];
        let mut sessions = Vec::new();
        for t in &targets {
            sessions.push(out.bind_udp(t).await.unwrap());
        }
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
        assert_eq!(out.udp_hub.len(), 1);
        // 各自只收到自己的回包
        for (i, (pc, t)) in sessions.iter().zip(&targets).enumerate() {
            let (data, from) = roundtrip(pc.as_ref(), t, format!("hello-{i}").as_bytes()).await;
            assert_eq!(data, format!("hello-{i}").into_bytes());
            assert_eq!(&from, t);
        }
    }

    #[tokio::test]
    async fn concurrent_first_sessions_do_not_each_dial() {
        let (out, dialer) = outbound();
        let tasks: Vec<_> = (0..20u8)
            .map(|i| {
                let out = out.clone();
                tokio::spawn(
                    async move { out.bind_udp(&ip(&format!("10.0.0.{i}:443"))).await.unwrap() },
                )
            })
            .collect();
        let mut sessions = Vec::new();
        for t in tasks {
            sessions.push(t.await.unwrap());
        }
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn same_address_goes_to_another_connection_then_dedicated() {
        let (out, dialer) = outbound();
        let target = ip("142.250.1.1:443");
        let mut sessions = Vec::new();
        for i in 0..(MAX_SHARED_CONNECTIONS + 1) {
            let pc = out.bind_udp(&target).await.unwrap();
            let (data, _) = roundtrip(pc.as_ref(), &target, &[i as u8]).await;
            assert_eq!(data, [i as u8]);
            sessions.push(pc);
        }
        // 4 条共用连接 + 1 条独占
        assert_eq!(
            dialer.dials.load(Ordering::SeqCst),
            MAX_SHARED_CONNECTIONS + 1
        );
        assert_eq!(out.udp_hub.len(), MAX_SHARED_CONNECTIONS);
    }

    #[tokio::test]
    async fn domain_target_is_resolved_and_shared() {
        let (out, dialer) = outbound();
        let a = out.bind_udp(&ip("1.1.1.1:53")).await.unwrap();
        let domain = TargetAddr::Domain("dns.test".into(), 53);
        let b = out.bind_udp(&domain).await.unwrap();
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
        let (data, from) = roundtrip(b.as_ref(), &domain, b"q").await;
        assert_eq!(data, b"q");
        assert_eq!(from, ip("9.9.9.9:53"), "IPv4 preferred");
        drop(a);
        // 解析失败：回退独占连接，把域名交给服务端（假服务端要求 IP，所以只验证建连）
        let _c = out
            .bind_udp(&TargetAddr::Domain("unknown.test".into(), 53))
            .await
            .unwrap();
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 2);
    }

    /// 官方 snell-server 把 IPv4 目标的回包来源写成 `::ffff:a.b.c.d`；
    /// 共用连接按目标 IP 路由，必须把它当作同一个 IPv4 地址，否则所有回包都被丢弃。
    #[tokio::test]
    async fn ipv4_mapped_reply_sources_are_routed_to_the_ipv4_session() {
        let (out, dialer) = outbound();
        dialer.mapped_replies.store(true, Ordering::SeqCst);
        let target = ip("127.0.0.1:19000");
        let session = out.bind_udp(&target).await.unwrap();
        let (data, from) = roundtrip(session.as_ref(), &target, b"echo").await;
        assert_eq!(data, b"echo");
        assert_eq!(from, target, "the source must be reported in IPv4 form");
        // 独占连接路径同样要统一来源地址
        let other = out.bind_udp(&ip("127.0.0.1:19000")).await.unwrap();
        let (data, from) = roundtrip(other.as_ref(), &target, b"again").await;
        assert_eq!(data, b"again");
        assert_eq!(from, target);
    }

    #[tokio::test]
    async fn dropped_session_frees_its_route() {
        let (out, dialer) = outbound();
        let target = ip("1.1.1.1:53");
        let a = out.bind_udp(&target).await.unwrap();
        drop(a);
        let b = out.bind_udp(&target).await.unwrap();
        let (data, _) = roundtrip(b.as_ref(), &target, b"x").await;
        assert_eq!(data, b"x");
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn network_change_closes_shared_connections() {
        let (out, dialer) = outbound();
        let target = ip("1.1.1.1:53");
        let a = out.bind_udp(&target).await.unwrap();
        out.session_control().unwrap().on_network_changed();
        let mut buf = [0u8; 16];
        assert!(a.recv_from(&mut buf).await.is_err());
        assert!(a.send_to(b"x", &target).await.is_err());
        let b = out.bind_udp(&target).await.unwrap();
        let (data, _) = roundtrip(b.as_ref(), &target, b"y").await;
        assert_eq!(data, b"y");
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn server_close_ends_sessions_and_leaves_the_pool() {
        let (out, dialer) = outbound();
        dialer.close_after_handshake.store(true, Ordering::SeqCst);
        let a = out.bind_udp(&ip("1.1.1.1:53")).await.unwrap();
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_secs(2), a.recv_from(&mut buf))
            .await
            .expect("session must end");
        assert!(r.is_err());
        assert_eq!(out.udp_hub.len(), 0);
        dialer.close_after_handshake.store(false, Ordering::SeqCst);
        let b = out.bind_udp(&ip("1.1.1.1:53")).await.unwrap();
        let (data, _) = roundtrip(b.as_ref(), &ip("1.1.1.1:53"), b"z").await;
        assert_eq!(data, b"z");
    }
}
