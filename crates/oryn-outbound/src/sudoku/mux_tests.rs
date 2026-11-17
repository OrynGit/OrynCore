use super::*;
use tokio::time::{timeout, Duration};

pub(super) async fn frame(peer: &mut tokio::io::DuplexStream) -> (u8, u32, Vec<u8>) {
    let mut h = [0; 9];
    timeout(Duration::from_secs(1), peer.read_exact(&mut h))
        .await
        .unwrap()
        .unwrap();
    let mut data = vec![0; u32::from_be_bytes(h[5..].try_into().unwrap()) as usize];
    peer.read_exact(&mut data).await.unwrap();
    (h[0], u32::from_be_bytes(h[1..5].try_into().unwrap()), data)
}
pub(super) async fn incoming(peer: &mut tokio::io::DuplexStream, kind: u8, id: u32, data: &[u8]) {
    let mut h = vec![kind];
    h.extend(id.to_be_bytes());
    h.extend((data.len() as u32).to_be_bytes());
    peer.write_all(&h).await.unwrap();
    peer.write_all(data).await.unwrap();
    tokio::task::yield_now().await;
}
pub(super) fn setup(capacity: usize) -> (Arc<Session>, tokio::io::DuplexStream) {
    let (a, b) = tokio::io::duplex(capacity);
    (
        Session::new(Box::new(a), Arc::new(CancellationToken::new())),
        b,
    )
}
pub(super) fn target() -> TargetAddr {
    TargetAddr::Ip("127.0.0.1:80".parse().unwrap())
}

#[tokio::test]
async fn reset_is_terminal_for_reads_and_writes() {
    let (s, mut peer) = setup(4096);
    let mut a = s.open(&target()).await.unwrap();
    let (_, id, _) = frame(&mut peer).await;
    let mut b = s.open(&target()).await.unwrap();
    let (_, bid, _) = frame(&mut peer).await;
    incoming(&mut peer, 4, id, b"reset").await;
    assert!(
        a.write_all(b"bad").await.is_err(),
        "write after RESET succeeded"
    );
    for _ in 0..2 {
        assert!(timeout(Duration::from_millis(100), a.read_u8())
            .await
            .unwrap()
            .is_err());
    }
    assert!(a.flush().await.is_err());
    b.write_all(b"ok").await.unwrap();
    b.flush().await.unwrap();
    assert_eq!(frame(&mut peer).await, (2, bid, b"ok".to_vec()));
}

#[tokio::test]
async fn cancelled_open_never_sends_reset_before_open() {
    let (s, mut peer) = setup(1);
    // 第一 OPEN 卡在底层 write，第二 OPEN 已入队但未发送。
    let t = target();
    let mut a = Box::pin(s.open(&t));
    assert!(timeout(Duration::from_millis(20), &mut a).await.is_err());
    let mut b = Box::pin(s.open(&t));
    assert!(timeout(Duration::from_millis(20), &mut b).await.is_err());
    drop(b);
    drop(a);
    let mut opened = std::collections::HashSet::new();
    let mut reset = std::collections::HashSet::new();
    for _ in 0..4 {
        let (kind, id, _) = frame(&mut peer).await;
        match kind {
            1 => {
                assert!(!reset.contains(&id));
                opened.insert(id);
            }
            4 => {
                assert!(opened.contains(&id), "RESET overtook OPEN for {id}");
                reset.insert(id);
            }
            _ => panic!("unexpected frame {kind}"),
        }
    }
    assert_eq!(opened, reset);
    assert!(!s.stop.is_cancelled());
}

#[tokio::test]
async fn completed_shutdown_drop_does_not_reset() {
    let (s, mut peer) = setup(4096);
    let mut a = s.open(&target()).await.unwrap();
    let (_, id, _) = frame(&mut peer).await;
    a.shutdown().await.unwrap();
    drop(a);
    assert_eq!(frame(&mut peer).await, (3, id, vec![]));
    assert!(timeout(Duration::from_millis(30), peer.read_u8())
        .await
        .is_err());
}

#[tokio::test]
async fn slow_stream_resets_without_blocking_shared_reader() {
    let (s, mut peer) = setup(4096);
    let mut a = s.open(&target()).await.unwrap();
    let (_, aid, _) = frame(&mut peer).await;
    let mut b = s.open(&target()).await.unwrap();
    let (_, bid, _) = frame(&mut peer).await;
    for _ in 0..5 {
        incoming(&mut peer, 2, aid, b"a").await;
    }
    incoming(&mut peer, 2, bid, b"b").await;
    assert_eq!(
        timeout(Duration::from_secs(1), b.read_u8())
            .await
            .unwrap()
            .unwrap(),
        b'b'
    );
    assert_eq!(frame(&mut peer).await.0, 4);
    for _ in 0..2 {
        assert!(a.read_u8().await.is_err());
        assert!(a.write_all(b"bad").await.is_err());
        assert!(a.flush().await.is_err());
        assert!(a.shutdown().await.is_err());
    }
    assert!(!s.streams.lock().unwrap().contains_key(&aid));
    assert!(!s.stop.is_cancelled());
    b.write_all(b"ok").await.unwrap();
    b.flush().await.unwrap();
    assert_eq!(frame(&mut peer).await, (2, bid, b"ok".to_vec()));
    drop(a);
    assert!(timeout(Duration::from_millis(20), peer.read_u8())
        .await
        .is_err());
}
