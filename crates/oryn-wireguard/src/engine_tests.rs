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
fn tcp_buffer_budget_falls_back_then_refuses() {
    let cfg = WireGuardTcpBuffers {
        rx: 256 * 1024,
        tx: 128 * 1024,
        budget: 2 * 384 * 1024 + 24 * 1024,
    };
    let full = 384 * 1024;
    assert_eq!(tcp_buffer_sizes(&cfg, 0), Some((256 * 1024, 128 * 1024)));
    assert_eq!(tcp_buffer_sizes(&cfg, full), Some((256 * 1024, 128 * 1024)));
    // 两条全尺寸之后只剩 24 KiB：退到最小 16 + 8 KiB
    assert_eq!(
        tcp_buffer_sizes(&cfg, 2 * full),
        Some((16 * 1024, 8 * 1024))
    );
    assert_eq!(tcp_buffer_sizes(&cfg, 2 * full + 1), None);
    // 配置本身小于最小值时不会被放大
    let small = WireGuardTcpBuffers {
        rx: 16 * 1024,
        tx: 8 * 1024,
        budget: 24 * 1024,
    };
    assert_eq!(tcp_buffer_sizes(&small, 0), Some((16 * 1024, 8 * 1024)));
    assert_eq!(tcp_buffer_sizes(&small, 1), None);
}
