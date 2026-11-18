use super::*;
use oryn_config::TargetAddr;
use smoltcp::phy::{Device, RxToken};

fn network(result: TunnResult<'_>) -> Vec<u8> {
    match result {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        _ => panic!("expected WireGuard network packet"),
    }
}

fn udp_packet(source: SocketAddr, dest: SocketAddr, payload: &[u8]) -> Vec<u8> {
    // IPv6 切片器即使单片也加分片头，先还原成普通 UDP 包。
    let fragment = frag::fragment_udp(source, dest, payload, 1280, 1).remove(0);
    Reassembler::default()
        .push(fragment, Instant::now())
        .unwrap()
}

fn incoming_allowed_ips(v6: bool, duplicate: bool) {
    // 固定的假密钥；两个真实 Noise 会话，不以助手返回值代替收包安全检查。
    let local_key = [0x11; 32];
    let remote_keys = [[0x22; 32], [0x44; 32]];
    let endpoints: [SocketAddr; 2] = [
        "127.0.0.1:10001".parse().unwrap(),
        "127.0.0.1:10002".parse().unwrap(),
    ];
    let default = if v6 { "::/0" } else { "0.0.0.0/0" };
    let specific = if v6 { "fd00:1::/64" } else { "10.1.0.0/16" };
    let peers = remote_keys
        .iter()
        .enumerate()
        .map(|(i, key)| WireGuardPeerSpec {
            endpoint: TargetAddr::Ip(endpoints[i]),
            public_key: PublicKey::from(&StaticSecret::from(*key)).to_bytes(),
            preshared_key: None,
            allowed_ips: vec![Cidr::parse(if duplicate || i == 1 {
                specific
            } else {
                default
            })
            .unwrap()],
            reserved: [0; 3],
        })
        .collect();
    let spec = WireGuardSpec {
        peers,
        private_key: local_key,
        address_v4: Some(("10.0.0.2".parse().unwrap(), 32)),
        address_v6: Some(("fd00::2".parse().unwrap(), 128)),
        mtu: 1280,
        keepalive_secs: 0,
        udp: true,
        remote_dns: false,
        dns: vec![],
        amnezia: None,
        refresh_secs: None,
        tcp_buffers: Default::default(),
    };
    let mut engine = Engine::new(spec, Arc::new(UdpFactory));
    let local_public = PublicKey::from(&StaticSecret::from(local_key)).to_bytes();
    let mut remotes: Vec<_> = remote_keys
        .iter()
        .enumerate()
        .map(|(i, key)| new_tunn(*key, local_public, None, 0, i as u32 + 1))
        .collect();
    let mut buf = [0; WIRE_BUF];
    for i in 0..2 {
        engine.peers[i].endpoint = Some(endpoints[i]);
        let init = network(
            engine.peers[i]
                .tunn
                .format_handshake_initiation(&mut buf, false),
        );
        let response = network(remotes[i].decapsulate(None, &init, &mut buf));
        let confirm = network(engine.peers[i].tunn.decapsulate(None, &response, &mut buf));
        assert!(matches!(
            remotes[i].decapsulate(None, &confirm, &mut buf),
            TunnResult::Done
        ));
    }
    let source: SocketAddr = if v6 { "[fd00:1::1]:7" } else { "10.1.0.1:7" }
        .parse()
        .unwrap();
    let dest: SocketAddr = if v6 {
        "[fd00::2]:1234"
    } else {
        "10.0.0.2:1234"
    }
    .parse()
    .unwrap();
    let owner = if duplicate { 0 } else { 1 };
    assert_eq!(engine.peer_for(source.ip()), Some(owner));
    let packet = udp_packet(source, dest, b"authenticated source");
    // 先证明合法拥有者可交付，再用同一源地址从另一个已认证会话注入。
    for i in [owner, 1 - owner] {
        let mut encrypted = network(remotes[i].encapsulate(&packet, &mut buf));
        engine.incoming(&mut encrypted, endpoints[i]);
        let received = engine
            .device
            .receive(now_smol())
            .map(|(rx, _)| rx.consume(|p| p.to_vec()));
        if i == owner {
            assert_eq!(received.as_deref(), Some(packet.as_slice()));
        } else {
            assert!(
                received.is_none(),
                "non-owner peer injected a globally owned source IP"
            );
        }
    }
    if !duplicate {
        let source = if v6 { "[fd00:2::1]:7" } else { "10.2.0.1:7" }
            .parse()
            .unwrap();
        let packet = udp_packet(source, dest, b"default peer source");
        assert_eq!(engine.peer_for(source.ip()), Some(0));
        let mut encrypted = network(remotes[0].encapsulate(&packet, &mut buf));
        engine.incoming(&mut encrypted, endpoints[0]);
        let (rx, _) = engine
            .device
            .receive(now_smol())
            .expect("default peer remains usable");
        rx.consume(|p| assert_eq!(p, packet));
    }
}

#[test]
fn incoming_allowed_ips_global_owner_v4() {
    incoming_allowed_ips(false, false);
}

#[test]
fn incoming_allowed_ips_global_owner_v6() {
    incoming_allowed_ips(true, false);
}

#[test]
fn incoming_allowed_ips_duplicate_first_peer_v4() {
    incoming_allowed_ips(false, true);
}

#[test]
fn incoming_allowed_ips_duplicate_first_peer_v6() {
    incoming_allowed_ips(true, true);
}

fn control_spec() -> WireGuardSpec {
    WireGuardSpec {
        peers: vec![WireGuardPeerSpec {
            endpoint: TargetAddr::Ip("127.0.0.1:10001".parse().unwrap()),
            public_key: PublicKey::from(&StaticSecret::from([0x22; 32])).to_bytes(),
            preshared_key: None,
            allowed_ips: vec![Cidr::parse("0.0.0.0/0").unwrap()],
            reserved: [0; 3],
        }],
        private_key: [0x11; 32],
        address_v4: Some(("10.0.0.2".parse().unwrap(), 32)),
        address_v6: None,
        mtu: 1280,
        keepalive_secs: 0,
        udp: true,
        remote_dns: true,
        dns: vec!["10.0.0.1:53".parse().unwrap()],
        amnezia: None,
        refresh_secs: None,
        tcp_buffers: Default::default(),
    }
}

async fn saturated_control(kind: &str) {
    let spec = control_spec();
    let tunnel = Tunnel::new(spec.clone());
    tunnel.close();
    tokio::task::yield_now().await;
    let (tx, mut rx) = mpsc::channel(32);
    let mut tunnel = Arc::try_unwrap(tunnel).ok().unwrap();
    tunnel.commands = tx;
    for _ in 0..32 {
        let (reply, _) = oneshot::channel();
        tunnel
            .commands
            .try_send(Command::Udp {
                endpoints: vec![],
                reply,
            })
            .ok()
            .unwrap();
    }
    let mut engine = Engine::new(spec, Arc::new(UdpFactory));
    engine.asleep = true;
    engine.wires.failed_at = Some(Instant::now());
    let e2 = Some("127.0.0.1:10002".parse().unwrap());
    match kind {
        "wake" => {
            for _ in 0..1000 {
                tunnel.on_sleep();
                tunnel.on_wake();
            }
        }
        "network" => tunnel.on_network_changed(),
        _ => {
            for port in 11000..12000 {
                tunnel.update_endpoints(&[Some(SocketAddr::from(([127, 0, 0, 1], port)))]);
            }
            tunnel.update_endpoints(&[e2]);
            tunnel.update_endpoints(&[None]);
        }
    }
    tunnel.control.apply(&mut engine);
    while let Ok(command) = rx.try_recv() {
        engine.command(command);
    }
    // 控制面即使流命令队列已满，也必须保留到引擎消费。
    match kind {
        "wake" => assert!(!engine.asleep),
        "network" => assert!(engine.wires.failed_at.is_none()),
        _ => assert_eq!(engine.peers[0].endpoint, e2),
    }
}

#[tokio::test]
async fn full_queue_wake() {
    saturated_control("wake").await;
}
#[tokio::test]
async fn full_queue_network() {
    saturated_control("network").await;
}
#[tokio::test]
async fn full_queue_endpoint() {
    saturated_control("endpoint").await;
}

#[tokio::test]
async fn old_flow_dns_does_not_roll_back_endpoint() {
    let spec = control_spec();
    let tunnel = Tunnel::new(spec.clone());
    tunnel.close();
    tokio::task::yield_now().await;
    let mut tunnel = Arc::try_unwrap(tunnel).ok().unwrap();
    let (tx, mut rx) = mpsc::channel(32);
    tunnel.commands = tx;
    let e1 = vec![Some("127.0.0.1:10001".parse().unwrap())];
    let e2 = vec![Some("127.0.0.1:10002".parse().unwrap())];
    let mut engine = Engine::new(spec, Arc::new(UdpFactory));
    engine.use_endpoints(&e1);
    let old_flow = engine.open_udp().unwrap();
    engine.use_endpoints(&e2);
    let query = tunnel.resolve(&e1, "uncached.example");
    tokio::pin!(query);
    tokio::select! {
        biased;
        _ = &mut query => panic!("DNS must wait for its session"),
        command = rx.recv() => engine.command(command.unwrap()),
    }
    assert_eq!(engine.peers[0].endpoint, e2[0]);
    assert_eq!(engine.udp.len(), 2);
    drop(old_flow);
}

#[test]
fn buffer_growth_respects_max_and_budget() {
    assert_eq!(grown(16 << 10, 256 << 10, 0, 6 << 20), Some(32 << 10));
    // 不超过上限
    assert_eq!(grown(192 << 10, 256 << 10, 0, 6 << 20), Some(256 << 10));
    assert_eq!(grown(256 << 10, 256 << 10, 0, 6 << 20), None);
    // 增量放不下预算就不扩
    assert_eq!(
        grown(16 << 10, 256 << 10, 100, 100 + (16 << 10)),
        Some(32 << 10)
    );
    assert_eq!(grown(16 << 10, 256 << 10, 101, 100 + (16 << 10)), None);
    // 初始大小不超过上限
    let cfg = WireGuardTcpBuffers::default();
    assert_eq!(initial_buffers(&cfg), (16 << 10, 8 << 10));
}

#[test]
fn receive_grows_when_rounds_are_fast_and_drained() {
    let t0 = Instant::now();
    let cap = 16 << 10;
    let ms = Duration::from_millis;
    // 读得快、5 ms 收满一轮 → 扩容
    let mut fast = Tune::new(t0);
    fast.after_read(t0, cap, 0);
    fast.rx_delivered = cap as u64;
    fast.after_read(t0 + ms(5), cap, 0);
    assert!(fast.rx_grow);
    // 读得快但轮末恰好有一批刚到：这一轮里读空过 → 仍扩容
    let mut burst = Tune::new(t0);
    burst.after_read(t0, cap, 0);
    burst.rx_delivered = (cap / 2) as u64;
    burst.after_read(t0 + ms(2), cap, 0);
    burst.after_read(t0 + ms(5), cap, cap / 2);
    assert!(burst.rx_grow);
    // 读得慢：整轮缓冲都接近满 → 不扩
    let mut slow = Tune::new(t0);
    slow.after_read(t0, cap, cap - 4096);
    for i in 1..=4u64 {
        slow.rx_delivered = i * 4096;
        slow.after_read(t0 + ms(i), cap, cap - 4096);
    }
    assert!(!slow.rx_grow);
    // 流量慢：一轮超过 GROW_ROUND → 不扩
    let mut light = Tune::new(t0);
    light.after_read(t0, cap, 0);
    light.rx_delivered = cap as u64;
    light.after_read(t0 + GROW_ROUND + ms(1), cap, 0);
    assert!(!light.rx_grow);
    // 一轮没收满 → 不判定
    let mut partial = Tune::new(t0);
    partial.after_read(t0, cap, 0);
    partial.rx_delivered = (cap / 2) as u64;
    partial.after_read(t0 + ms(1), cap, 0);
    assert!(!partial.rx_grow);
}

#[test]
fn send_grows_only_when_window_allows_and_progressing() {
    let mut t = Tune::new(Instant::now());
    let cap = 8 << 10;
    t.tx_blocked = true;
    assert!(t.tx_should_grow(cap, cap, (cap / 2) as u64));
    // 对端窗口比缓冲小：瓶颈不在本端缓冲
    assert!(!t.tx_should_grow(cap, cap - 1, (cap / 2) as u64));
    // 没有确认进展（对端可能卡住）
    assert!(!t.tx_should_grow(cap, cap, (cap / 2 - 1) as u64));
    t.tx_blocked = false;
    assert!(!t.tx_should_grow(cap, cap, cap as u64));
}

#[test]
fn tune_grows_within_budget_and_shrinks_when_idle() {
    let _g = crate::resources::test_support::SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::resources::configure(crate::resources::Limits {
        buffer_budget: 64 << 20,
        workers: 1,
    });
    crate::resources::set_pressure(Pressure::Normal);
    let idle_shrink = Pressure::Normal.idle_shrink();
    let mut spec = control_spec();
    let (rx0, tx0) = (16 << 10, 8 << 10);
    // 预算：两条初始连接 + 一次接收扩容（16 KiB）
    spec.tcp_buffers = WireGuardTcpBuffers {
        rx: 64 << 10,
        tx: 32 << 10,
        budget: 2 * (rx0 + tx0) + (16 << 10),
    };
    let mut engine = Engine::new(spec, Arc::new(UdpFactory));
    let dest: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let mut streams = Vec::new();
    for _ in 0..2 {
        let (mut flow, stream) = engine.open_tcp(dest, 0).unwrap();
        flow.connect = None;
        engine.tcp.push(flow);
        streams.push(stream);
    }
    // 第三条放不下初始缓冲
    let err = engine.open_tcp(dest, 0).err().unwrap();
    assert!(err.to_string().contains("budget"), "{err}");
    let now = Instant::now();
    // 两条都想扩：只有第一条放得下预算
    engine.tcp[0].tune.rx_grow = true;
    engine.tcp[1].tune.rx_grow = true;
    assert!(engine.tune(now));
    assert_eq!(engine.tcp[0].rx_cap, 32 << 10);
    assert_eq!(engine.tcp[1].rx_cap, rx0);
    let socket = engine.sockets.get::<tcp::Socket>(engine.tcp[0].handle);
    assert_eq!(socket.recv_capacity(), 32 << 10);
    assert_eq!(engine.buffer_used(), engine.spec.tcp_buffers.budget);
    // 空闲不到收回时长：不收回
    assert!(!engine.tune(now + idle_shrink - Duration::from_millis(1)));
    assert_eq!(engine.tcp[0].rx_cap, 32 << 10);
    // 空闲且缓冲为空：收回到初始大小，预算随之释放
    engine.tune(now + idle_shrink);
    assert_eq!(engine.tcp[0].rx_cap, rx0);
    let socket = engine.sockets.get::<tcp::Socket>(engine.tcp[0].handle);
    assert_eq!(socket.recv_capacity(), rx0);
    assert_eq!(engine.buffer_used(), 2 * (rx0 + tx0));
    assert_eq!(engine.tcp[0].tx_cap, tx0);
    drop(streams);
}

#[test]
fn global_budget_is_shared_and_pressure_stops_growth() {
    let _g = crate::resources::test_support::SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (rx0, tx0) = (16 << 10, 8 << 10);
    let base = crate::resources::buffer_usage().0;
    // 进程级预算：两条初始连接 + 一次 16 KiB 扩容，两个出站共用
    crate::resources::configure(crate::resources::Limits {
        buffer_budget: base + 2 * (rx0 + tx0) + (16 << 10),
        workers: 1,
    });
    crate::resources::set_pressure(Pressure::Normal);
    let dest: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let mut a = Engine::new(control_spec(), Arc::new(UdpFactory));
    let mut b = Engine::new(control_spec(), Arc::new(UdpFactory));
    let mut streams = Vec::new();
    for engine in [&mut a, &mut b] {
        let (mut flow, stream) = engine.open_tcp(dest, 0).unwrap();
        flow.connect = None;
        engine.tcp.push(flow);
        streams.push(stream);
    }
    // 各出站自己的预算都还宽裕，但进程级预算已不够第三条
    let err = a.open_tcp(dest, 0).err().unwrap();
    assert!(err.to_string().contains("budget"), "{err}");
    let now = Instant::now();
    // 内存压力：不扩容
    crate::resources::set_pressure(Pressure::Elevated);
    a.tcp[0].tune.rx_grow = true;
    assert!(!a.tune(now));
    assert_eq!(a.tcp[0].rx_cap, rx0);
    // 压力解除后，进程级预算只够一个出站扩容
    crate::resources::set_pressure(Pressure::Normal);
    a.tcp[0].tune.rx_grow = true;
    b.tcp[0].tune.rx_grow = true;
    assert!(a.tune(now));
    assert!(!b.tune(now));
    assert_eq!((a.tcp[0].rx_cap, b.tcp[0].rx_cap), (32 << 10, rx0));
    // critical：扩容过的缓冲一空就收回，不等空闲时长
    crate::resources::set_pressure(Pressure::Critical);
    a.tune(now);
    assert_eq!(a.tcp[0].rx_cap, rx0);
    // 连接释放后租约归还
    drop(a);
    drop(b);
    drop(streams);
    assert_eq!(crate::resources::buffer_usage().0, base);
    crate::resources::set_pressure(Pressure::Normal);
    crate::resources::configure(crate::resources::Limits::DEFAULT);
}
