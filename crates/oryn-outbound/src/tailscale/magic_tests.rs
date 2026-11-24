use super::*;

fn key() -> SecretKey {
    SecretKey::generate(&mut OsRng)
}
fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
/// A 与 B 互为对端（各自下标 0），A 知道 B 的 netmap 端点 `b_ep`。
fn pair(b_ep: SocketAddr) -> (Magic, Magic) {
    let (ka, kb) = (key(), key());
    let (pa, pb) = (*ka.public_key().as_bytes(), *kb.public_key().as_bytes());
    let a = Magic::new(ka, [1; 32], vec![(Some(pb), vec![b_ep])], [true, true]);
    let b = Magic::new(kb, [2; 32], vec![(Some(pa), vec![])], [true, true]);
    (a, b)
}
fn udp(out: &[Out]) -> Vec<(SocketAddr, Vec<u8>)> {
    out.iter()
        .filter_map(|o| match o {
            Out::Udp(a, p) => Some((*a, p.clone())),
            Out::Derp(..) => None,
        })
        .collect()
}

#[test]
fn disco_codec_roundtrip_and_tamper() {
    let (ka, kb) = (key(), key());
    let pa = *ka.public_key().as_bytes();
    let pb = *kb.public_key().as_bytes();
    for m in [
        Message::Ping { tx: [9; 12], node: Some([3; 32]) },
        Message::Ping { tx: [9; 12], node: None },
        Message::Pong { tx: [8; 12], src: addr("198.51.100.7:41641") },
        Message::Pong { tx: [8; 12], src: addr("[2001:db8::1]:41641") },
        Message::CallMeMaybe(vec![addr("203.0.113.1:1"), addr("[2001:db8::2]:2")]),
    ] {
        let p = seal(&ka, &pa, &pb, &m).unwrap();
        assert!(is_disco(&p));
        assert_eq!(&p[..6], &DISCO_MAGIC);
        assert_eq!(open(&kb, &p), Some((pa, m)));
        let mut bad = p.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&kb, &bad).is_none(), "tampered box must be rejected");
        assert!(open(&ka, &p).is_none(), "only the recipient can open it");
    }
    // 版本非 0、CallMeMaybe 长度不是 18 的倍数一律丢弃；Pong 地址为 v4-mapped
    assert!(Message::decode(&[TYPE_PING, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
    assert!(Message::decode(&[TYPE_CALL_ME_MAYBE, 0, 1, 2, 3]).is_none());
    let pong = Message::Pong { tx: [0; 12], src: addr("1.2.3.4:5") }.encode();
    assert_eq!(&pong[14..30], &Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped().octets());
}

#[test]
fn ping_pong_establishes_trusted_direct_path_then_expires() {
    let b_ep = addr("198.51.100.20:41641");
    let a_src = addr("203.0.113.10:41641");
    let (mut a, mut b) = pair(b_ep);
    let t0 = Instant::now();
    assert_eq!(a.route(0, t0), Route::Derp, "no direct path before any Pong");
    // 有流量后的 tick：向候选发 Ping
    let pings = udp(&a.tick(t0));
    let (to, ping) = pings.iter().find(|(to, _)| *to == b_ep).unwrap().clone();
    assert_eq!(to, b_ep);
    // B 收到 Ping，学到 A 的来源并回 Pong
    let reply = b.on_disco(&ping, Via::Udp(a_src), t0);
    let (back, pong) = udp(&reply)[0].clone();
    assert_eq!(back, a_src);
    assert_eq!(b.peer_for(a_src), Some(0), "B learned A's address from the ping");
    // A 收到 Pong：可信直连，只走 UDP
    let t1 = t0 + Duration::from_millis(20);
    assert!(a.on_disco(&pong, Via::Udp(b_ep), t1).is_empty());
    assert_eq!(a.route(0, t1), Route::Udp(b_ep));
    assert_eq!(a.peer_for(b_ep), Some(0));
    // 信任期过后（没有新的 Pong）回到 UDP + DERP 双发
    let t2 = t1 + TRUST;
    assert_eq!(a.route(0, t2), Route::Both(b_ep));
    // 伪造来源的 Pong 不被接受
    let mut c = Magic::new(key(), [3; 32], vec![], [true, true]);
    assert!(c.on_disco(&pong, Via::Udp(b_ep), t1).is_empty());
}

#[test]
fn heartbeat_keeps_trust_and_timeout_drops_untrusted_best() {
    let b_ep = addr("198.51.100.30:41641");
    let (mut a, mut b) = pair(b_ep);
    let t0 = Instant::now();
    a.route(0, t0);
    let (_, ping) = udp(&a.tick(t0)).into_iter().find(|(t, _)| *t == b_ep).unwrap();
    let pong = udp(&b.on_disco(&ping, Via::Udp(addr("203.0.113.1:1")), t0))[0].1.clone();
    a.on_disco(&pong, Via::Udp(b_ep), t0);
    // 3 s 后心跳只 Ping 最佳地址
    let t1 = t0 + HEARTBEAT;
    a.route(0, t1);
    let beats = udp(&a.tick(t1));
    assert_eq!(beats.len(), 1);
    assert_eq!(beats[0].0, b_ep);
    // 心跳一直没有回应：信任期过后、Ping 超时即撤掉最佳地址，回到 DERP
    let t2 = t1 + PING_TIMEOUT + Duration::from_secs(1);
    a.tick(t2);
    assert_eq!(a.route(0, t2), Route::Derp);
}

#[test]
fn idle_peers_are_not_probed_and_call_me_maybe_goes_over_derp() {
    let b_ep = addr("198.51.100.40:41641");
    let (mut a, mut b) = pair(b_ep);
    a.set_local(vec![addr("192.168.1.5:41641")]);
    let t0 = Instant::now();
    assert!(a.tick(t0).is_empty(), "no traffic, no STUN servers: nothing to send");
    a.route(0, t0);
    let out = a.tick(t0);
    let cmm = out
        .iter()
        .find_map(|o| match o {
            Out::Derp(0, p) => Some(p.clone()),
            _ => None,
        })
        .expect("full ping round sends CallMeMaybe over DERP");
    // CallMeMaybe 只接受经 DERP 的：B 随即向 A 的端点 Ping
    assert!(b.on_disco(&cmm, Via::Udp(addr("192.168.1.5:41641")), t0).is_empty());
    let pings = udp(&b.on_disco(&cmm, Via::Derp(0, 7), t0));
    assert_eq!(pings.len(), 1);
    assert_eq!(pings[0].0, addr("192.168.1.5:41641"));
    // 45 s 无流量后不再探测
    assert!(udp(&a.tick(t0 + ACTIVE)).is_empty());
}

#[test]
fn ping_over_derp_is_answered_over_derp() {
    let (mut a, mut b) = pair(addr("198.51.100.50:1"));
    let t0 = Instant::now();
    a.route(0, t0);
    // 直接构造一个经 DERP 送达的 Ping
    let ka_ping = a.ping(0, addr("198.51.100.50:1"), t0).unwrap();
    let Out::Udp(_, packet) = ka_ping else { panic!() };
    let reply = b.on_disco(&packet, Via::Derp(0, 7), t0);
    assert!(matches!(reply.as_slice(), [Out::Derp(0, _)]));
    // 来自错误 DERP 身份的 disco 包被丢弃
    assert!(b.on_disco(&packet, Via::Derp(1, 7), t0).is_empty());
}

#[test]
fn better_addr_hysteresis_and_bonus() {
    let ms = Duration::from_millis;
    let (pub1, pub2) = (addr("203.0.113.1:1"), addr("203.0.113.2:1"));
    assert!(better((pub1, ms(10)), (pub2, ms(20))));
    assert!(!better((pub1, ms(1000)), (pub2, ms(1005))), "under 1% is noise");
    assert!(!better((pub1, ms(20)), (pub2, ms(10))));
    // 私网地址加 20 分：延迟略差也优先
    assert!(better((addr("192.168.1.2:1"), ms(11)), (pub2, ms(10))));
    assert!(!better((pub1, ms(10)), (pub1, ms(1))), "same address is never better");
}

#[test]
fn stun_request_and_response() {
    let tx = [7u8; 12];
    let req = stun_request(tx);
    assert_eq!(&req[0..2], &[0, 1]);
    assert_eq!(&req[4..8], &STUN_COOKIE);
    assert_eq!(&req[8..20], &tx);
    assert_eq!(u16::from_be_bytes([req[2], req[3]]) as usize, req.len() - 20);
    // 指纹覆盖指纹属性之前的全部字节
    let crc = crc32fast::hash(&req[..req.len() - 8]) ^ 0x5354_554e;
    assert_eq!(&req[req.len() - 4..], &crc.to_be_bytes());
    // XOR-MAPPED-ADDRESS（IPv4）
    let mapped = addr("198.51.100.77:54321");
    let mut resp = vec![0x01, 0x01, 0, 12];
    resp.extend_from_slice(&STUN_COOKIE);
    resp.extend_from_slice(&tx);
    resp.extend([0x00, 0x20, 0, 8, 0, 1]);
    resp.extend_from_slice(&(54321u16 ^ 0x2112).to_be_bytes());
    let ip = [198u8, 51, 100, 77];
    resp.extend(ip.iter().zip(STUN_COOKIE).map(|(a, k)| a ^ k));
    assert_eq!(stun_response(&resp), Some((tx, mapped)));
    assert!(stun_response(&req).is_none(), "a request is not a response");

    let (mut a, _) = pair(addr("198.51.100.1:1"));
    a.set_stun_servers(vec![addr("192.0.2.9:3478")]);
    let t0 = Instant::now();
    let out = udp(&a.tick(t0));
    assert_eq!(out.len(), 1, "first tick STUNs even without traffic");
    let tx: [u8; 12] = out[0].1[8..20].try_into().unwrap();
    let mut resp = resp.clone();
    resp[8..20].copy_from_slice(&tx);
    let fix = |r: &mut Vec<u8>| {
        let ip = [198u8, 51, 100, 77];
        let n = r.len();
        for (i, (a, k)) in ip.iter().zip(STUN_COOKIE).enumerate() {
            r[n - 4 + i] = a ^ k;
        }
    };
    fix(&mut resp);
    assert!(a.on_stun(&resp));
    assert_eq!(a.endpoints(), vec![(mapped, ENDPOINT_STUN)]);
    assert!(!a.on_stun(&resp), "unknown or repeated transaction");
    // 没有活动对端时不再周期 STUN
    assert!(udp(&a.tick(t0 + Duration::from_secs(60))).is_empty());
}

#[test]
fn tables_stay_bounded() {
    let (mut a, _) = pair(addr("198.51.100.1:1"));
    for i in 0..100u16 {
        a.peers[0].add(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 1000 + i));
    }
    assert!(a.peers[0].candidates.len() <= MAX_CANDIDATES);
    let t0 = Instant::now();
    for i in 0..100u16 {
        let _ = a.ping(0, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), i), t0);
    }
    assert!(a.peers[0].pending.len() <= MAX_PENDING);
    a.set_local((0..20).map(|i| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 1)).collect());
    assert!(a.endpoints().len() <= MAX_ENDPOINTS);
}
