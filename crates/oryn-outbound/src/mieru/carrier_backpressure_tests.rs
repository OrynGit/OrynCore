//! M4：刻画保留的共享 TCP 背压；观察窗不是吞吐或慢流隔离验收。
use super::*;
use tokio::io::{AsyncReadExt, DuplexStream};
use tokio::time::{timeout, Instant};

struct DuplexDialer(Mutex<Option<DuplexStream>>);

#[async_trait::async_trait]
impl Dialer for DuplexDialer {
    async fn dial_tcp(&self, _: &TargetAddr) -> io::Result<BoxStream> {
        Ok(Box::new(self.0.lock().unwrap().take().unwrap()))
    }
}

struct UnusedResolver;

#[async_trait::async_trait]
impl Resolver for UnusedResolver {
    async fn resolve(&self, _: &str) -> io::Result<Vec<std::net::IpAddr>> {
        panic!("TCP duplex test must not resolve DNS")
    }
}

#[tokio::test]
async fn tcp_slow_session_blocks_peer_until_drop() {
    // 外层期限只防挂死；所有帧经过 connect 启动的真实 reader 和 Codec。
    timeout(Duration::from_secs(5), async {
        let spec = MieruSpec {
            server: TargetAddr::Ip("127.0.0.1:12345".parse().unwrap()),
            port_end: 12345,
            transport_udp: false,
            username: "test-user".into(),
            password: "test-password".into(),
            udp: false,
            multiplexing: 2,
            no_wait: false,
            traffic_pattern: Default::default(),
        };
        let (client, mut peer) = tokio::io::duplex(256 * 1024);
        let (carrier, key_time) = Carrier::connect(
            &spec,
            &DuplexDialer(Mutex::new(Some(client))),
            &UnusedResolver,
            &oryn_udp::UdpFactory,
        )
        .await
        .unwrap();
        let mut codec = Codec::new(
            &wire::key(&spec.username, &spec.password, key_time),
            spec.username.clone(),
            false,
            super::super::pattern::Pattern::new(&spec.traffic_pattern),
        );
        let slots = Arc::new(Semaphore::new(2));
        let a = super::super::session::open(
            carrier.clone(),
            1,
            vec![],
            slots.clone().acquire_owned().await.unwrap(),
            slots.clone(),
        );
        let mut b = super::super::session::open(
            carrier.clone(),
            2,
            vec![],
            slots.clone().acquire_owned().await.unwrap(),
            slots.clone(),
        );
        // 先确认 B 的完整解码/交付路径可用，排除启动未调度造成的假阻塞。
        peer.write_all(&codec.encode(&Frame::new(7, 2, 0, vec![0x42])).unwrap())
            .await
            .unwrap();
        let mut byte = [0];
        b.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [0x42]);

        // A 不读：16 KiB 应用桥 + 会话 output 高水位 + 2 项接收队列，
        // 16 个 8 KiB 帧足以使真实分发停在 A 的 send().await。
        for seq in 0..16 {
            let frame = Frame::new(7, 1, seq, vec![0x41; TCP_CHUNK]);
            peer.write_all(&codec.encode(&frame).unwrap())
                .await
                .unwrap();
        }
        peer.write_all(&codec.encode(&Frame::new(7, 2, 1, vec![0x43])).unwrap())
            .await
            .unwrap();
        let a_tx = carrier.sessions.lock().unwrap().get(&1).unwrap().clone();
        while a_tx.capacity() != 0 {
            tokio::task::yield_now().await;
        }
        let begin = Instant::now();
        assert!(timeout(Duration::from_millis(30), b.read_exact(&mut byte))
            .await
            .is_err());
        assert_eq!(a_tx.capacity(), 0, "A receive queue must stay full");
        assert!(!carrier.stop.is_cancelled());
        assert_eq!(slots.available_permits(), 0);
        let blocked = begin.elapsed();

        let begin = Instant::now();
        drop(a);
        b.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [0x43]);
        assert!(a_tx.is_closed());
        assert!(!carrier.sessions.lock().unwrap().contains_key(&1));
        assert_eq!(slots.available_permits(), 1);
        assert!(
            !carrier.stop.is_cancelled(),
            "B resumes on the same carrier"
        );
        eprintln!(
            "M4 observation only: B blocked {blocked:?}; resumed after Drop A in {:?}",
            begin.elapsed()
        );
        drop(b);
        carrier.stop.cancel();
    })
    .await
    .expect("Mieru shared backpressure test timed out");
}
