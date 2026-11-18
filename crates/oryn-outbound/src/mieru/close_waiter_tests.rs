use super::*;
use std::collections::HashMap;

fn fixture() -> (Arc<Carrier>, mpsc::Receiver<Frame>) {
    let (send, recv) = mpsc::channel(1);
    let carrier = Arc::new(Carrier {
        send,
        close_waiters: Arc::new(Semaphore::new(32)),
        sessions: Mutex::new(HashMap::new()),
        stop: CancellationToken::new(),
        packet: false,
        reusable: true,
        chunk: 8192,
    });
    carrier.send.try_send(Frame::new(6, 0, 0, vec![])).unwrap();
    (carrier, recv)
}

#[tokio::test]
async fn full_queue_single_drop_preserves_shared_carrier() {
    let (carrier, mut recv) = fixture();
    drop(Registration {
        carrier: carrier.clone(),
        id: 1,
    });
    tokio::task::yield_now().await;
    assert!(!carrier.stop.is_cancelled());
    assert_eq!(carrier.close_waiters.available_permits(), 31);
    recv.recv().await.unwrap();
    let close = recv.recv().await.unwrap();
    assert_eq!((close.kind, close.id), (4, 1));
    assert_eq!(carrier.close_waiters.available_permits(), 32);
    assert!(!carrier.stop.is_cancelled());
}

#[tokio::test]
async fn repeated_cancel_open_cannot_accumulate_unbounded_waiters() {
    let (carrier, _recv) = fixture();
    let slots = Arc::new(Semaphore::new(1));
    for id in 1..=33 {
        let permit = slots.clone().try_acquire_owned().unwrap();
        drop(open(carrier.clone(), id, vec![], permit, slots.clone(), 1));
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(slots.available_permits(), 1);
        assert!(carrier.sessions.lock().unwrap().is_empty());
        if id <= 32 {
            assert!(!carrier.stop.is_cancelled());
            assert_eq!(carrier.close_waiters.available_permits(), 32 - id as usize);
        }
    }
    assert!(
        carrier.stop.is_cancelled(),
        "close waiter budget exhaustion must fail closed"
    );
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(carrier.close_waiters.available_permits(), 32);
}

#[test]
fn runtime_cancel_before_first_poll_refunds_waiter_permit() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (carrier, _recv) = fixture();
    {
        let _entered = runtime.enter();
        for id in 1..=32 {
            drop(Registration {
                carrier: carrier.clone(),
                id,
            });
        }
        assert_eq!(carrier.close_waiters.available_permits(), 0);
        assert!(!carrier.stop.is_cancelled());
    }
    // 没有 block_on：关闭任务从未 poll，future 捕获的 permit 也必须退账。
    drop(runtime);
    assert_eq!(carrier.close_waiters.available_permits(), 32);
}

#[tokio::test]
async fn writer_closed_while_waiting_stops_carrier_and_refunds() {
    let (carrier, recv) = fixture();
    drop(Registration {
        carrier: carrier.clone(),
        id: 1,
    });
    drop(recv);
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(carrier.stop.is_cancelled());
    assert_eq!(carrier.close_waiters.available_permits(), 32);
}
