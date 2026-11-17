//! 固定官方 v3.38.0 的 ±120 秒 rounded-key 发现规则；不依赖实际等待。
use super::*;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn pooled(packet: bool, key_time: u64) -> PooledCarrier {
    let (send, _) = mpsc::channel(1);
    PooledCarrier {
        carrier: Arc::new(Carrier {
            send,
            close_waiters: Arc::new(Semaphore::new(32)),
            sessions: Mutex::new(HashMap::new()),
            stop: CancellationToken::new(),
            packet,
            reusable: true,
            chunk: 1024,
        }),
        key_time,
    }
}

#[test]
fn stale_udp_is_not_selected_even_before_idle_cleanup() {
    let old = pooled(true, 1200);
    assert!(old.accepts_open(1379));
    assert!(!old.accepts_open(1380));
    let fresh = pooled(true, 1380);
    let pool = [old, fresh];
    let selected = pool.iter().find(|c| c.accepts_open(1380)).unwrap();
    assert!(Arc::ptr_eq(&selected.carrier, &pool[1].carrier));
    assert!(!pool[0].retain(1380));
    assert!(pool[0].carrier.stop.is_cancelled());
    assert!(pool[1].retain(1380));
}

#[test]
fn stale_active_udp_drains_without_cancellation_and_tcp_keeps_its_key() {
    let old = pooled(true, 1200);
    let (tx, _rx) = mpsc::channel(1);
    old.carrier.sessions.lock().unwrap().insert(7, tx);
    assert!(!old.accepts_open(1380));
    assert!(old.retain(1380));
    assert!(!old.carrier.stop.is_cancelled());
    assert_eq!(old.carrier.sessions.lock().unwrap().len(), 1);
    let tcp = pooled(false, 1200);
    assert!(tcp.accepts_open(99999));
    assert!(tcp.retain(99999));
    old.carrier.sessions.lock().unwrap().clear();
    assert!(!old.retain(1380));
}

#[test]
fn rollback_also_requires_a_discoverable_udp_key() {
    let c = pooled(true, 1200);
    assert!(c.accepts_open(1020));
    assert!(!c.accepts_open(1019));
}

fn codec(at: u64) -> wire::Codec {
    wire::Codec::new(
        &wire::key("fixture-user", "fixture-password", at),
        "fixture-user".into(),
        true,
        pattern::Pattern::new(&Default::default()),
    )
}

// Codec::decode 只接收服务端方向；这里直接验证真实 OPEN 的 AEAD 元数据。
fn decrypt_open(packet: &[u8], at: u64) -> bool {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305,
    };
    let key = wire::key("fixture-user", "fixture-password", at);
    XChaCha20Poly1305::new((&key).into())
        .decrypt(packet[..24].into(), &packet[24..72])
        .is_ok_and(|meta| meta[0] == 2 && meta[6..10] == 7u32.to_be_bytes())
}

fn discover(packet: &[u8], server_time: u64) -> bool {
    [server_time - 120, server_time, server_time + 120]
        .into_iter()
        .any(|t| decrypt_open(packet, t))
}

#[test]
fn encrypted_open_old_key_exits_discovery_but_existing_session_still_decrypts() {
    let frame = wire::Frame::new(2, 7, 0, vec![5, 1, 0]);
    let packet = codec(1200).encode(&frame).unwrap();
    assert!(discover(&packet, 1379));
    assert!(!discover(&packet, 1380));
    // 服务端已有会话时直接用固定 key；会话移除后只能尝试发现窗口。
    assert!(decrypt_open(&packet, 1200));
    let new_packet = codec(1380).encode(&frame).unwrap();
    assert!(discover(&new_packet, 1380));
    assert!(!decrypt_open(&new_packet, 1200));
}
