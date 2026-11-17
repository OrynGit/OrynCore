use super::*;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::io::AsyncWriteExt;

struct ControlledIo {
    block: bool,
    entered: Arc<tokio::sync::Notify>,
    dropped: Arc<AtomicBool>,
}
impl Drop for ControlledIo {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}
impl PacketIo for ControlledIo {
    fn send<'a>(
        &'a self,
        _: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.entered.notify_one();
            if self.block {
                std::future::pending().await
            } else {
                Ok(())
            }
        })
    }
    fn recv<'a>(
        &'a mut self,
        _: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(std::future::pending())
    }
}
fn spec() -> KcpSpec {
    KcpSpec {
        mtu: 576,
        tti: 10,
        uplink_capacity: 1,
        downlink_capacity: 1,
        congestion: false,
        read_buffer_size: 8192,
        write_buffer_size: 8192,
        header: "none".into(),
        seed: None,
    }
}
async fn stream(block: bool) -> (KcpStream, Arc<AtomicBool>, Arc<tokio::sync::Notify>) {
    let dropped = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(tokio::sync::Notify::new());
    let stream = KcpStream::connect_io(
        ControlledIo {
            block,
            entered: entered.clone(),
            dropped: dropped.clone(),
        },
        &spec(),
    )
    .await
    .unwrap();
    (stream, dropped, entered)
}
async fn settle() {
    // 单线程 runtime 中只推进就绪任务，不用墙钟推断释放。
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

#[test]
fn drop_waiters_are_bounded_and_reclaimed() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (active, active_dropped, _) = stream(false).await;
        let mut retained = Vec::new();
        for _ in 0..32 {
            let (mut stream, dropped, entered) = stream(true).await;
            stream.write_all(b"blocked").await.unwrap();
            entered.notified().await;
            drop(stream);
            retained.push(dropped);
        }
        // 即使 run 已卡在 send，满额度后的反复 Drop 也不再保留连接。
        for _ in 0..64 {
            let (mut stream, dropped, entered) = stream(true).await;
            stream.write_all(b"blocked").await.unwrap();
            entered.notified().await;
            let task = stream.task.as_ref().unwrap().abort_handle();
            drop(stream);
            settle().await;
            assert!(task.is_finished(), "overflow Drop retained a blocked task");
            assert!(dropped.load(Ordering::SeqCst));
        }
        assert!(!active_dropped.load(Ordering::SeqCst));
        // 只等待完成，不断言实时时长；阻塞 send 必须被500ms兜底取消。
        tokio::time::timeout(Duration::from_secs(5), async {
            while retained.iter().any(|v| !v.load(Ordering::SeqCst)) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        settle().await;
        assert_eq!(CLOSE_WAITERS.available_permits(), 32);
        drop(active);
        settle().await;
        let (mut ordinary, dropped, sent) = stream(false).await;
        // 保持读端打开，排除既有 tx.closed() 早退分支，单独验证 Terminate 机会。
        let (_, replacement) = mpsc::channel(1);
        let _read_rx = std::mem::replace(&mut ordinary.rx, replacement);
        let _command_tx = ordinary.tx.clone();
        drop(ordinary);
        tokio::time::timeout(Duration::from_secs(5), sent.notified())
            .await
            .unwrap();
        settle().await;
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(CLOSE_WAITERS.available_permits(), 32);
        // 不让新 waiter 得到首次 poll，随后销毁 runtime。
        let (unpolled, _, _) = stream(true).await;
        drop(unpolled);
        assert_eq!(CLOSE_WAITERS.available_permits(), 31);
    });
    drop(runtime);
    assert_eq!(CLOSE_WAITERS.available_permits(), 32);
}
