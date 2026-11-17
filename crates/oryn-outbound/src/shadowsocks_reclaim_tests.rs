use super::*;
use std::time::{Duration, SystemTime};

fn clock(s: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(s)
}
fn state() -> UdpState {
    UdpState {
        session: 7,
        next: 0,
        windows: Vec::new(),
        wall_high: None,
        clock_failed: false,
    }
}
fn reply(server: u64, packet: u64, client: u64) -> UdpSocketControlData {
    // 真正加密/解密的 SS2022 回包，而非伪造解密结果。
    let config = ss::config(
        &TargetAddr::Ip("127.0.0.1:8388".parse().unwrap()),
        "2022-blake3-aes-128-gcm",
        "AAAAAAAAAAAAAAAAAAAAAA==",
    )
    .unwrap();
    let context = Context::new(ServerType::Local);
    let mut control = UdpSocketControlData::default();
    control.client_session_id = client;
    control.server_session_id = server;
    control.packet_id = packet;
    let mut bytes = BytesMut::new();
    ss::crypto_io::encrypt_server_payload(
        &context,
        config.method(),
        config.key(),
        &ss::address(&TargetAddr::Ip("192.0.2.1:53".parse().unwrap())).unwrap(),
        &control,
        b"reply",
        &mut bytes,
    );
    let (n, _, control) =
        ss::crypto_io::decrypt_server_payload(&context, config.method(), config.key(), &mut bytes)
            .unwrap();
    assert_eq!(&bytes[..n], b"reply");
    control.unwrap()
}
fn accept(s: &mut UdpState, c: &UdpSocketControlData, t: u64) -> bool {
    s.observe_clock(clock(t)).unwrap();
    s.accept_reply(c, t)
}
#[test]
fn fifth_session_and_future_timestamp_inclusive_boundary() {
    let mut s = state();
    for id in 0..4 {
        assert!(accept(&mut s, &reply(id, 0, 7), 100));
    }
    assert!(!accept(&mut s, &reply(4, 0, 7), 159));
    // 首次包的时间戳可能是 130；本地 160 时仍在 ±30 秒内。
    assert!(!accept(&mut s, &reply(4, 0, 7), 160));
    assert!(accept(&mut s, &reply(4, 0, 7), 161));
    assert_eq!(s.windows.len(), 4);
}
#[test]
fn late_packets_extend_but_replay_and_wrong_client_do_not() {
    let mut s = state();
    for id in 0..4 {
        assert!(accept(&mut s, &reply(id, 0, 7), 100));
    }
    assert!(accept(&mut s, &reply(0, 1, 7), 150));
    assert!(!accept(&mut s, &reply(1, 1, 8), 150));
    assert!(!accept(&mut s, &reply(2, 0, 7), 150));
    for id in 4..7 {
        assert!(accept(&mut s, &reply(id, 0, 7), 161));
    }
    assert!(!accept(&mut s, &reply(0, 1, 7), 161));
    assert!(!accept(&mut s, &reply(7, 0, 7), 210));
    assert!(accept(&mut s, &reply(7, 0, 7), 211));
}
#[test]
fn rollback_permanently_closes_association_even_within_one_second() {
    let mut s = state();
    s.observe_clock(clock(100) + Duration::from_millis(500))
        .unwrap();
    assert!(s.observe_clock(clock(100)).is_err());
    assert!(s.observe_clock(clock(200)).is_err());
}
