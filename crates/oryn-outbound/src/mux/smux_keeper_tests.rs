//! S5：受控慢写下，取消 open / Drop 的 FIN 等待任务必须有数量上限。
use super::*;

async fn blocked(any: bool) -> (Session, BoxStream, tokio::io::DuplexStream) {
    // 对端不读，写驱动卡在承载，而不是依赖计时制造背压。
    let (carrier, peer) = tokio::io::duplex(1);
    let session = Session::new_mode(Box::new(carrier), any);
    let flow = session.open().await.unwrap();
    tokio::task::yield_now().await;
    while session
        .tx
        .try_send(Command::Frame(2, 1, Bytes::from_static(b"x")))
        .is_ok()
    {}
    (session, flow, peer)
}

async fn cancel_open(session: &Session) {
    let mut open = Box::pin(session.open());
    assert!(futures_util::poll!(&mut open).is_pending());
    drop(open);
}

#[tokio::test]
async fn cancelled_opens_have_a_hard_keeper_limit() {
    for any in [false, true] {
        let (session, mut healthy, _peer) = blocked(any).await;
        for _ in 0..32 {
            cancel_open(&session).await;
            // 一个满队列 Drop 不能立即杀共享会话；旧流仍登记。
            assert_eq!(session.streams.lock().unwrap().len(), 1);
        }
        cancel_open(&session).await;
        assert!(
            session.streams.lock().unwrap().is_empty(),
            "33rd pending FIN must fail closed, not spawn another unaccounted waiter"
        );
        assert!(healthy.write_all(b"still alive?").await.is_err());
    }
}

#[tokio::test]
async fn completed_keepers_release_slots_and_preserve_shared_session() {
    for any in [false, true] {
        let (session, mut healthy, mut peer) = blocked(any).await;
        for _ in 0..MAX_FIN_KEEPERS {
            cancel_open(&session).await;
        }
        assert_eq!(session.fin_keepers.available_permits(), 0);
        let drain = tokio::spawn(async move {
            let mut buf = [0; 4096];
            while peer.read(&mut buf).await.unwrap() != 0 {}
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while session.fin_keepers.available_permits() != MAX_FIN_KEEPERS {
                tokio::task::yield_now().await;
            }
            healthy.write_all(b"healthy").await.unwrap();
            healthy.flush().await.unwrap();
            // 反复开 / drop，不因已经完成的等待者占用旧名额而误关会话。
            for _ in 0..128 {
                drop(session.open().await.unwrap());
                healthy.flush().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(!session.closed());
        drain.abort();
    }
}

#[test]
fn runtime_cancellation_releases_keeper_slots() {
    for polled in [false, true] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (session, healthy, peer) = runtime.block_on(async {
            let (session, healthy, peer) = blocked(false).await;
            for _ in 0..MAX_FIN_KEEPERS {
                cancel_open(&session).await;
            }
            if polled {
                tokio::task::yield_now().await;
            }
            assert_eq!(session.fin_keepers.available_permits(), 0);
            (session, healthy, peer)
        });
        // 包括首次 poll 前取消；任务真正析构后才归还名额。
        drop(runtime);
        assert_eq!(session.fin_keepers.available_permits(), MAX_FIN_KEEPERS);
        drop((session, healthy, peer));
    }
}
