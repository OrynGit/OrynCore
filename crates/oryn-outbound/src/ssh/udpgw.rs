//! SSH 的 Oryn UDP 网关扩展；按公开协议独立实现，不引入本地监听或 Netstack。
//! 线格式对照：ambrop72/badvpn protocol/udpgw_proto.h @07268f02706e78e282e19641b5d1d41e8e89bf31
//! （BSD-3-Clause）；tun2proxy/tun2proxy src/udpgw.rs @62109025df9b331ae9e5fca8e49f812eb6ce0747（MIT）。
//! 未复制上游实现。每 Flow 一个 SSH 通道，读写各只有一条有界帧。
use super::*;
use oryn_config::SshUdpMode;
use oryn_protocol::socks5;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex as StdMutex,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::{Mutex, Notify, OwnedSemaphorePermit},
    task::JoinHandle,
};

const MAX_FRAME: usize = u16::MAX as usize;
const MAX_PAYLOAD: usize = 65507;
const MAX_TARGETS: usize = 64;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE: Duration = Duration::from_secs(5);

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn input_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "SSH UDP gateway channel closed",
    )
}
fn number(mode: SshUdpMode, bytes: [u8; 2]) -> u16 {
    match mode {
        SshUdpMode::BadVpn => u16::from_le_bytes(bytes),
        SshUdpMode::Tun2Proxy => u16::from_be_bytes(bytes),
    }
}
fn put_number(mode: SshUdpMode, value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&match mode {
        SshUdpMode::BadVpn => value.to_le_bytes(),
        SshUdpMode::Tun2Proxy => value.to_be_bytes(),
    });
}
fn encode(
    mode: SshUdpMode,
    id: u16,
    target: &TargetAddr,
    data: &[u8],
    fresh: bool,
) -> io::Result<Vec<u8>> {
    if data.len() > MAX_PAYLOAD {
        return Err(input_error("SSH UDP payload exceeds 65507 bytes"));
    }
    let mut frame = Vec::with_capacity(data.len() + 265);
    frame.extend_from_slice(&[0, 0]);
    let flags = match mode {
        SshUdpMode::BadVpn => {
            (u8::from(fresh) * 2)
                | if matches!(target, TargetAddr::Ip(a) if a.is_ipv6()) {
                    8
                } else {
                    0
                }
        }
        SshUdpMode::Tun2Proxy => 2,
    };
    frame.push(flags);
    put_number(mode, id, &mut frame);
    match mode {
        SshUdpMode::BadVpn => {
            let TargetAddr::Ip(addr) = target else {
                return Err(input_error("BadVPN requires an IP destination"));
            };
            match addr.ip() {
                IpAddr::V4(ip) => frame.extend_from_slice(&ip.octets()),
                IpAddr::V6(ip) => frame.extend_from_slice(&ip.octets()),
            }
            frame.extend_from_slice(&addr.port().to_be_bytes());
        }
        SshUdpMode::Tun2Proxy => socks5::encode_addr(target, &mut frame)?,
    }
    frame.extend_from_slice(data);
    let len = u16::try_from(frame.len() - 2)
        .map_err(|_| input_error("SSH UDP gateway frame exceeds 65535 bytes"))?;
    frame[..2].copy_from_slice(&match mode {
        SshUdpMode::BadVpn => len.to_le_bytes(),
        SshUdpMode::Tun2Proxy => len.to_be_bytes(),
    });
    Ok(frame)
}
fn keepalive(mode: SshUdpMode) -> Vec<u8> {
    let mut f = Vec::with_capacity(5);
    put_number(mode, 3, &mut f);
    f.extend_from_slice(&[1, 0, 0]);
    f
}

enum Frame<'a> {
    Keepalive,
    Error(u16),
    Data(u16, TargetAddr, &'a [u8]),
}
fn decode(mode: SshUdpMode, body: &[u8]) -> io::Result<Frame<'_>> {
    if body.len() < 3 {
        return Err(bad("SSH UDP gateway frame is too short"));
    }
    let id = number(mode, [body[1], body[2]]);
    match body[0] {
        1 if body.len() == 3 && id == 0 => return Ok(Frame::Keepalive),
        32 if mode == SshUdpMode::Tun2Proxy && body.len() == 3 => return Ok(Frame::Error(id)),
        _ => {}
    }
    let (target, used) = match mode {
        SshUdpMode::BadVpn => match body[0] {
            0 if body.len() >= 9 => (
                TargetAddr::Ip(SocketAddr::new(
                    Ipv4Addr::new(body[3], body[4], body[5], body[6]).into(),
                    u16::from_be_bytes([body[7], body[8]]),
                )),
                6,
            ),
            8 if body.len() >= 21 => (
                TargetAddr::Ip(SocketAddr::new(
                    Ipv6Addr::from(<[u8; 16]>::try_from(&body[3..19]).expect("IPv6 size")).into(),
                    u16::from_be_bytes([body[19], body[20]]),
                )),
                18,
            ),
            _ => return Err(bad("invalid BadVPN UDP gateway response")),
        },
        SshUdpMode::Tun2Proxy => {
            if body[0] != 2 {
                return Err(bad("invalid tun2proxy UDP gateway flags"));
            }
            socks5::decode_addr(&body[3..])
                .ok_or_else(|| bad("invalid tun2proxy UDP gateway address"))?
        }
    };
    if id == 0 || target.port() == 0 || body.len() - 3 - used > MAX_PAYLOAD {
        return Err(bad("invalid SSH UDP gateway data"));
    }
    Ok(Frame::Data(id, target, &body[3 + used..]))
}

struct Destination {
    original: TargetAddr,
    wire: TargetAddr,
    /// 最近一次发送；目标表满时淘汰最久未用的那一个。
    used: std::time::Instant,
}
#[derive(Default)]
struct Shared {
    failed: AtomicBool,
    failure: Notify,
    peers: StdMutex<Vec<Destination>>,
}
impl Shared {
    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.failure.notify_one();
    }
    fn check(&self) -> io::Result<()> {
        if self.failed.load(Ordering::Acquire) {
            Err(closed())
        } else {
            Ok(())
        }
    }
}
struct Reader {
    io: ReadHalf<BoxStream>,
    header: [u8; 2],
    header_read: usize,
    body: Vec<u8>,
    body_read: usize,
    done: bool,
}
impl Reader {
    async fn frame(&mut self, mode: SshUdpMode) -> io::Result<&[u8]> {
        if self.done {
            self.header_read = 0;
            self.body.clear();
            self.body_read = 0;
            self.done = false;
        }
        while self.header_read < 2 {
            let n = self.io.read(&mut self.header[self.header_read..]).await?;
            if n == 0 {
                return Err(closed());
            }
            self.header_read += n;
        }
        if self.body.is_empty() {
            let len = number(mode, self.header) as usize;
            if !(3..=MAX_FRAME).contains(&len) {
                return Err(bad("invalid SSH UDP gateway frame length"));
            }
            self.body.resize(len, 0);
        }
        while self.body_read < self.body.len() {
            let n = self.io.read(&mut self.body[self.body_read..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated SSH UDP gateway frame",
                ));
            }
            self.body_read += n;
        }
        self.done = true;
        Ok(&self.body)
    }
}
struct Writer {
    io: WriteHalf<BoxStream>,
    pending: Vec<u8>,
    sent: usize,
}
impl Writer {
    /// 保留已发送进度，取消 send_to 不会使下一帧插入上一帧中间。
    async fn drain(&mut self) -> io::Result<()> {
        while self.sent < self.pending.len() {
            let n = self.io.write(&self.pending[self.sent..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.sent += n;
        }
        self.io.flush().await?;
        self.pending.clear();
        self.sent = 0;
        Ok(())
    }
}

pub(super) struct Gateway {
    mode: SshUdpMode,
    resolver: Arc<dyn crate::Resolver>,
    shared: Arc<Shared>,
    reader: Mutex<Reader>,
    writer: Arc<Mutex<Writer>>,
    keeper: JoinHandle<()>,
    _slot: OwnedSemaphorePermit,
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.keeper.abort();
    }
}
impl Gateway {
    pub(super) fn new(
        stream: BoxStream,
        mode: SshUdpMode,
        resolver: Arc<dyn crate::Resolver>,
        slot: OwnedSemaphorePermit,
    ) -> Self {
        let (r, w) = tokio::io::split(stream);
        let shared = Arc::new(Shared::default());
        let writer = Arc::new(Mutex::new(Writer {
            io: w,
            pending: Vec::new(),
            sent: 0,
        }));
        let task_writer = writer.clone();
        let task_shared = shared.clone();
        let keeper = tokio::spawn(async move {
            loop {
                tokio::time::sleep(KEEPALIVE).await;
                if task_shared.check().is_err() {
                    return;
                }
                let result = tokio::time::timeout(WRITE_TIMEOUT, async {
                    let mut w = task_writer.lock().await;
                    w.drain().await?;
                    w.pending = keepalive(mode);
                    w.drain().await
                })
                .await;
                if !matches!(result, Ok(Ok(()))) {
                    task_shared.fail();
                    return;
                }
            }
        });
        Self {
            mode,
            resolver,
            shared,
            reader: Mutex::new(Reader {
                io: r,
                header: [0; 2],
                header_read: 0,
                body: Vec::new(),
                body_read: 0,
                done: false,
            }),
            writer,
            keeper,
            _slot: slot,
        }
    }
    async fn receive(&self, out: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut reader = self.reader.lock().await;
        loop {
            let body = reader.frame(self.mode).await?;
            match decode(self.mode, body)? {
                Frame::Keepalive => tokio::task::yield_now().await,
                Frame::Error(id) => {
                    if id == 0 || id as usize > self.shared.peers.lock().unwrap().len() {
                        return Err(bad("unknown SSH UDP gateway connection id"));
                    }
                    // 只是这个目标的数据报转发失败（如目标不可达），按 UDP 语义丢弃，
                    // 不能把整个网关通道（最多 64 个目标）一起报废
                    log::debug!(
                        "ssh udpgw: gateway could not forward a datagram for connection {id}"
                    );
                }
                Frame::Data(id, target, payload) => {
                    let peers = self.shared.peers.lock().unwrap();
                    let peer = peers
                        .get(id as usize - 1)
                        .ok_or_else(|| bad("unknown SSH UDP gateway connection id"))?;
                    // 编号被淘汰重用后，旧目标迟到的回包对不上：丢掉这一个包
                    if peer.wire != target {
                        log::debug!("ssh udpgw: dropped late response for a reused connection id");
                        continue;
                    }
                    let n = crate::copy_datagram(payload, out, "SSH udpgw");
                    return Ok((n, peer.original.clone()));
                }
            }
        }
    }
}
#[async_trait]
impl PacketConn for Gateway {
    async fn send_to(&self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        self.shared.check()?;
        if data.len() > MAX_PAYLOAD || target.port() == 0 {
            return Err(input_error("invalid SSH UDP destination or payload size"));
        }
        let known = self
            .shared
            .peers
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.original == *target)
            .map(|p| p.wire.clone());
        let wire = match known {
            Some(addr) => addr,
            None if self.mode == SshUdpMode::BadVpn && matches!(target, TargetAddr::Domain(..)) => {
                let addrs = crate::resolve_target(self.resolver.as_ref(), target).await?;
                TargetAddr::Ip(*addrs.first().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "SSH UDP destination did not resolve",
                    )
                })?)
            }
            None => target.clone(),
        };
        // 预先校验，不让无效参数消耗目标 ID。
        encode(self.mode, 1, &wire, data, false)?;
        let result = tokio::time::timeout(WRITE_TIMEOUT, async {
            let mut w = self.writer.lock().await;
            self.shared.check()?;
            w.drain().await?;
            let (id, fresh, wire) = {
                let mut peers = self.shared.peers.lock().unwrap();
                let now = std::time::Instant::now();
                if let Some(i) = peers.iter().position(|p| p.original == *target) {
                    peers[i].used = now;
                    ((i + 1) as u16, false, peers[i].wire.clone())
                } else if peers.len() >= MAX_TARGETS {
                    // 目标表满：重用最久未用的编号，带「新连接 / 重绑定」标志让网关改绑新目标
                    let i = peers
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, p)| p.used)
                        .map(|(i, _)| i)
                        .expect("table is full");
                    peers[i] = Destination {
                        original: target.clone(),
                        wire: wire.clone(),
                        used: now,
                    };
                    ((i + 1) as u16, true, wire)
                } else {
                    peers.push(Destination {
                        original: target.clone(),
                        wire: wire.clone(),
                        used: now,
                    });
                    (peers.len() as u16, true, wire)
                }
            };
            w.pending = encode(self.mode, id, &wire, data, fresh)?;
            w.drain().await
        })
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SSH UDP gateway write timed out",
            ))
        });
        // 写超时不致命：Writer 保留了已发送进度，下一次发送先补完这一帧，帧边界不会错位；
        // 真正卡死的通道由保活任务的超时判定。参数错误同样只影响这一个数据报。
        if result.as_ref().is_err_and(|e| {
            !matches!(
                e.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::TimedOut
            )
        }) {
            self.shared.fail();
        }
        result
    }
    async fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        self.shared.check()?;
        let result = tokio::select! { value=self.receive(out)=>value, _=self.shared.failure.notified()=>Err(closed()) };
        if result.is_err() {
            self.shared.fail();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Resolver;
    #[async_trait]
    impl crate::Resolver for Resolver {
        async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
            Ok(vec![Ipv4Addr::LOCALHOST.into()])
        }
    }
    fn gateway(mode: SshUdpMode, capacity: usize) -> (Gateway, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(capacity);
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        (
            Gateway::new(
                Box::new(a),
                mode,
                Arc::new(Resolver),
                sem.try_acquire_owned().unwrap(),
            ),
            b,
        )
    }
    async fn raw_frame(s: &mut tokio::io::DuplexStream, mode: SshUdpMode) -> Vec<u8> {
        let mut len = [0; 2];
        s.read_exact(&mut len).await.unwrap();
        let mut body = vec![0; number(mode, len) as usize];
        s.read_exact(&mut body).await.unwrap();
        body
    }
    #[test]
    fn independent_wire_vectors_and_invalid_frames() {
        let ip = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        assert_eq!(
            encode(SshUdpMode::BadVpn, 0x1234, &ip, b"hi", true).unwrap(),
            vec![11, 0, 2, 0x34, 0x12, 1, 2, 3, 4, 0, 53, b'h', b'i']
        );
        assert_eq!(
            encode(SshUdpMode::Tun2Proxy, 0x1234, &ip, b"hi", false).unwrap(),
            vec![0, 12, 2, 0x12, 0x34, 1, 1, 2, 3, 4, 0, 53, b'h', b'i']
        );
        assert_eq!(keepalive(SshUdpMode::BadVpn), vec![3, 0, 1, 0, 0]);
        assert_eq!(keepalive(SshUdpMode::Tun2Proxy), vec![0, 3, 1, 0, 0]);
        let domain = TargetAddr::Domain("x".repeat(255), 53);
        assert!(encode(SshUdpMode::BadVpn, 1, &domain, b"", false).is_err());
        assert!(encode(SshUdpMode::Tun2Proxy, 1, &domain, &vec![0; 65507], false).is_err());
        for mode in [SshUdpMode::BadVpn, SshUdpMode::Tun2Proxy] {
            for target in [ip.clone(), TargetAddr::Ip("[::1]:7300".parse().unwrap())] {
                let f = encode(mode, 1, &target, b"", false).unwrap();
                assert!(
                    matches!(decode(mode,&f[2..]).unwrap(),Frame::Data(1,addr,data) if addr==target && data.is_empty())
                );
            }
            for invalid in [
                vec![],
                vec![0, 0],
                vec![1, 0, 0, 1],
                vec![255, 1, 0],
                vec![0, 0, 0, 1, 2, 3, 4, 0, 53],
            ] {
                assert!(decode(mode, &invalid).is_err());
            }
        }
    }
    #[tokio::test]
    async fn cancellation_preserves_reads_and_truncation_consumes_whole_datagram() {
        for mode in [SshUdpMode::BadVpn, SshUdpMode::Tun2Proxy] {
            let (g, mut peer) = gateway(mode, 1024);
            let target = TargetAddr::Ip("1.2.3.4:80".parse().unwrap());
            g.send_to(b"request", &target).await.unwrap();
            let _ = raw_frame(&mut peer, mode).await;
            let reply = encode(mode, 1, &target, b"response", false).unwrap();
            peer.write_all(&reply[..3]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(2), g.recv_from(&mut [0; 32]))
                    .await
                    .is_err()
            );
            peer.write_all(&reply[3..]).await.unwrap();
            peer.write_all(&encode(mode, 1, &target, b"next", false).unwrap())
                .await
                .unwrap();
            let mut small = [0; 2];
            assert_eq!(g.recv_from(&mut small).await.unwrap().0, 2);
            assert_eq!(&small, b"re");
            let mut buf = [0; 10];
            let (n, from) = g.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"next");
            assert_eq!(from, target);
            drop(peer);
            assert!(g.recv_from(&mut buf).await.is_err());
            assert!(g.send_to(b"closed", &target).await.is_err());
        }
    }
    #[tokio::test]
    async fn cancelled_write_is_finished_before_the_next_frame() {
        let mode = SshUdpMode::Tun2Proxy;
        let (g, mut peer) = gateway(mode, 8);
        let target = TargetAddr::Ip("127.0.0.1:53".parse().unwrap());
        assert!(
            tokio::time::timeout(Duration::from_millis(2), g.send_to(&[7; 512], &target))
                .await
                .is_err()
        );
        let send = async {
            g.send_to(b"next", &target).await.unwrap();
        };
        let recv = async {
            let first = raw_frame(&mut peer, mode).await;
            assert!(matches!(decode(mode,&first).unwrap(),Frame::Data(_,_,data) if data==[7;512]));
            let second = raw_frame(&mut peer, mode).await;
            assert!(matches!(
                decode(mode, &second).unwrap(),
                Frame::Data(_, _, b"next")
            ));
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(send, recv);
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn keepalive_unknown_id_error_and_target_limits() {
        let mode = SshUdpMode::Tun2Proxy;
        let (g, mut peer) = gateway(mode, 65536);
        for port in 1..=64 {
            g.send_to(
                b"",
                &TargetAddr::Ip(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)),
            )
            .await
            .unwrap();
            let _ = raw_frame(&mut peer, mode).await;
        }
        // 目标表满：第 65 个目标重用最久未用的编号（1），并带新连接标志
        let reused = TargetAddr::Ip("127.0.0.1:65".parse().unwrap());
        g.send_to(b"", &reused).await.unwrap();
        let frame = raw_frame(&mut peer, mode).await;
        assert!(matches!(decode(mode, &frame).unwrap(), Frame::Data(1, ref t, _) if *t == reused));
        // 服务端 keepalive 回复不会被当作空 UDP 数据包；单个目标的 Error 帧只丢弃该数据报，
        // 网关继续工作，之后的回包照常收到
        peer.write_all(&keepalive(mode)).await.unwrap();
        peer.write_all(&[0, 3, 32, 0, 1]).await.unwrap();
        peer.write_all(&encode(mode, 1, &reused, b"ok", false).unwrap())
            .await
            .unwrap();
        let mut buf = [0; 4];
        let (n, from) = g.recv_from(&mut buf).await.unwrap();
        assert_eq!((&buf[..n], from), (&b"ok"[..], reused));
        let (g, mut peer) = gateway(mode, 100);
        peer.write_all(
            &encode(
                mode,
                99,
                &TargetAddr::Ip("127.0.0.1:53".parse().unwrap()),
                b"bad",
                false,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            g.recv_from(&mut [0; 9]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
