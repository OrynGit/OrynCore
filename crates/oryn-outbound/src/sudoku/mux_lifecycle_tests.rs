use super::tests::{frame, incoming, setup, target};
use super::*;
use tokio::time::timeout;

#[tokio::test]
async fn reset_wakes_pending_read_and_remains_error() {
    let (s, mut peer) = setup(4096);
    let mut a = s.open(&target()).await.unwrap();
    let (_, id, _) = frame(&mut peer).await;
    let mut read = Box::pin(a.read_u8());
    assert!(timeout(Duration::from_millis(10), &mut read).await.is_err());
    incoming(&mut peer, 4, id, b"reset").await;
    assert!(timeout(Duration::from_secs(1), read)
        .await
        .unwrap()
        .is_err());
    assert!(timeout(Duration::from_millis(10), a.read_u8())
        .await
        .unwrap()
        .is_err());
    assert!(a.write_all(b"bad").await.is_err());
}

#[tokio::test]
async fn close_is_only_read_half_close() {
    let (s, mut peer) = setup(4096);
    let mut a = s.open(&target()).await.unwrap();
    let (_, id, _) = frame(&mut peer).await;
    incoming(&mut peer, 3, id, b"").await;
    assert_eq!(a.read(&mut [0]).await.unwrap(), 0);
    a.write_all(b"ok").await.unwrap();
    a.flush().await.unwrap();
    assert_eq!(frame(&mut peer).await, (2, id, b"ok".to_vec()));
    drop(a);
    assert_eq!(frame(&mut peer).await.0, 4);
}

// writer 满载时也必须立即处理后续流；终止帧只能消耗预留容量。
#[tokio::test]
async fn slow_stream_reset_uses_reserved_fifo_slot_with_blocked_writer() {
    for terminal_kind in [2, 3] {
        let (s, mut peer) = setup(4096);
        let mut a = s.open(&target()).await.unwrap();
        let (_, aid, _) = frame(&mut peer).await;
        let mut b = s.open(&target()).await.unwrap();
        let (_, bid, _) = frame(&mut peer).await;
        s.send
            .send(Command::Frame(Frame {
                kind: 2,
                id: aid,
                data: vec![0; 8192],
            }))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        let mut queued = 0;
        while s
            .send
            .try_send(Command::Frame(Frame {
                kind: 2,
                id: bid,
                data: vec![],
            }))
            .is_ok()
        {
            queued += 1;
        }
        assert!(queued <= 62);
        assert_eq!(s.send.capacity(), 0);
        for _ in 0..4 {
            incoming(&mut peer, 2, aid, &[0; 16 * 1024]).await;
        }
        assert_eq!(s.streams.lock().unwrap()[&aid].send.capacity(), 0);
        incoming(&mut peer, terminal_kind, aid, b"x").await;
        incoming(&mut peer, 2, bid, b"b").await;
        assert_eq!(
            timeout(Duration::from_secs(1), b.read_u8())
                .await
                .unwrap()
                .unwrap(),
            b'b'
        );
        assert!(a.read_u8().await.is_err());
        assert!(a.write_all(b"bad").await.is_err());
        assert_eq!(s.streams.lock().unwrap().len(), 1);
        assert_eq!(s.tasks.lock().unwrap().len(), 2);
        assert_eq!(s.send.capacity(), 0);
        assert!(!s.stop.is_cancelled());
        drop(a);
        assert_eq!(frame(&mut peer).await, (2, aid, vec![0; 8192]));
        for _ in 0..queued {
            assert_eq!(frame(&mut peer).await, (2, bid, vec![]));
        }
        let (kind, id, _) = frame(&mut peer).await;
        assert_eq!((kind, id), (4, aid));
        b.write_all(b"alive").await.unwrap();
        b.flush().await.unwrap();
        assert_eq!(frame(&mut peer).await, (2, bid, b"alive".to_vec()));
    }
}

#[tokio::test]
async fn saturated_cancel_queue_backpressures_without_stopping_session() {
    let (s, mut peer) = setup(1);
    let t = target();
    // 底层持续不可写，反复取消；超过队列容量也不关闭共享会话。
    for _ in 0..100 {
        let mut open = Box::pin(s.open(&t));
        assert!(timeout(Duration::from_millis(1), &mut open).await.is_err());
    }
    assert!(!s.stop.is_cancelled());
    let drain = tokio::spawn(async move {
        let mut opened = std::collections::HashSet::new();
        loop {
            let (kind, id, data) = frame(&mut peer).await;
            match kind {
                1 => {
                    opened.insert(id);
                }
                4 => {
                    assert!(opened.remove(&id), "orphan reset");
                }
                2 if data == b"alive" => return peer,
                _ => {}
            }
        }
    });
    let mut b = timeout(Duration::from_secs(1), s.open(&t))
        .await
        .unwrap()
        .unwrap();
    b.write_all(b"alive").await.unwrap();
    b.flush().await.unwrap();
    let _peer = drain.await.unwrap();
}
