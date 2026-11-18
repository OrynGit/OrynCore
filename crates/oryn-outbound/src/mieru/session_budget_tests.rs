//! 会话并发预算（issue #5）：应用关流后名额及时归还、满载排队而非立即拒绝。
//! 档位数值（64/256/512）在 oryn-core 的 resource_profile_tests 里断言。
use super::session::open;
use super::wire::Frame;
use super::*;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn fixture(sessions: usize) -> (Arc<Carrier>, mpsc::Receiver<Frame>, Arc<Semaphore>) {
    let (send, recv) = mpsc::channel(16);
    let carrier = Arc::new(Carrier {
        send,
        close_waiters: Arc::new(Semaphore::new(32)),
        sessions: Mutex::new(HashMap::new()),
        stop: CancellationToken::new(),
        packet: false,
        reusable: true,
        chunk: 8192,
    });
    (carrier, recv, Arc::new(Semaphore::new(sessions)))
}

/// 轮询等待名额归还，避免对任务调度时序的脆弱依赖。
async fn wait_for_slots(slots: &Semaphore, expected: usize) {
    for _ in 0..200 {
        if slots.available_permits() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "slots did not reach {expected} within 1s (now {})",
        slots.available_permits()
    );
}

#[tokio::test]
async fn app_half_close_returns_slot_without_waiting_for_peer() {
    let (carrier, mut recv, slots) = fixture(1);
    let permit = slots.clone().try_acquire_owned().unwrap();
    let mut stream = open(carrier.clone(), 1, vec![], permit, slots.clone(), 1);
    assert_eq!(slots.available_permits(), 0);
    // 服务端不发关闭帧：会话任务继续等对端；应用关写端必须立刻归还名额，
    // 而不是等服务端会话超时（修前 30–60 s）。
    stream.shutdown().await.unwrap();
    wait_for_slots(&slots, 1).await;
    // 名额归还后会话仍然活着：服务端数据照常交付。
    let tx = carrier.sessions.lock().unwrap().get(&1).cloned().unwrap();
    tx.send(Frame::new(6, 1, 0, b"hi".to_vec())).await.unwrap();
    let mut buf = [0; 2];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hi");
    // 整流丢弃：任务退出，关闭帧发出（先排掉会话启动时的 open 帧）。
    drop(stream);
    let close = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let frame = recv.recv().await.unwrap();
            if frame.kind == 4 {
                break frame;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!((close.kind, close.id), (4, 1));
}

#[tokio::test]
async fn full_slots_queue_instead_of_failing_immediately() {
    let spec = MieruSpec {
        server: TargetAddr::Ip("127.0.0.1:12345".parse().unwrap()),
        port_end: 12345,
        transport_udp: false,
        username: "u".into(),
        password: "p".into(),
        udp: false,
        multiplexing: 2,
        no_wait: true,
        traffic_pattern: Default::default(),
    };
    struct FailingDialer;
    #[async_trait::async_trait]
    impl Dialer for FailingDialer {
        async fn dial_tcp(&self, _: &TargetAddr) -> io::Result<BoxStream> {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "dial refused",
            ))
        }
    }
    struct UnusedResolver;
    #[async_trait::async_trait]
    impl Resolver for UnusedResolver {
        async fn resolve(&self, _: &str) -> io::Result<Vec<std::net::IpAddr>> {
            panic!("queued connect must not resolve before a slot frees")
        }
    }
    let outbound = MieruOutbound::new(
        "m".into(),
        spec,
        Arc::new(FailingDialer),
        Arc::new(UnusedResolver),
        Arc::new(UnusedResolver),
        Arc::new(oryn_udp::UdpFactory),
        1,
    );
    let guard = outbound.slots.clone().try_acquire_owned().unwrap();
    let task = tokio::spawn({
        let outbound = outbound.clone();
        async move {
            outbound
                .connect_tcp(&TargetAddr::Ip("10.0.0.1:80".parse().unwrap()))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !task.is_finished(),
        "connect must queue for a slot instead of failing immediately"
    );
    // 名额释放后排队者立刻前进：错误来自拨号而不是 WouldBlock。
    drop(guard);
    let result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap();
    let error = match result.expect("task finished") {
        Ok(_) => panic!("dial must fail"),
        Err(error) => error,
    };
    assert_ne!(
        error.kind(),
        io::ErrorKind::WouldBlock,
        "queued connect should proceed to dial: {error}"
    );
}

#[tokio::test]
async fn queue_gives_up_after_two_seconds_with_limit_error() {
    let spec = MieruSpec {
        server: TargetAddr::Ip("127.0.0.1:12345".parse().unwrap()),
        port_end: 12345,
        transport_udp: false,
        username: "u".into(),
        password: "p".into(),
        udp: false,
        multiplexing: 2,
        no_wait: true,
        traffic_pattern: Default::default(),
    };
    struct UnusedDialer;
    #[async_trait::async_trait]
    impl Dialer for UnusedDialer {
        async fn dial_tcp(&self, _: &TargetAddr) -> io::Result<BoxStream> {
            panic!("no slot freed, dial must not run")
        }
    }
    struct UnusedResolver;
    #[async_trait::async_trait]
    impl Resolver for UnusedResolver {
        async fn resolve(&self, _: &str) -> io::Result<Vec<std::net::IpAddr>> {
            panic!("no slot freed, resolve must not run")
        }
    }
    let outbound = MieruOutbound::new(
        "m".into(),
        spec,
        Arc::new(UnusedDialer),
        Arc::new(UnusedResolver),
        Arc::new(UnusedResolver),
        Arc::new(oryn_udp::UdpFactory),
        1,
    );
    let _guard = outbound.slots.clone().try_acquire_owned().unwrap();
    let error = match outbound
        .connect_tcp(&TargetAddr::Ip("10.0.0.1:80".parse().unwrap()))
        .await
    {
        Ok(_) => panic!("connect must fail while no slot frees"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(error.to_string().contains("session limit"), "{error}");
}
