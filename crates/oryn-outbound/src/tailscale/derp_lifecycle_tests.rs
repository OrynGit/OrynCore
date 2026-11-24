use super::*;
use oryn_udp::Datagrams;
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{DuplexStream, ReadBuf};

// duplex 提供真实有限写窗口；flush 模式仅把最终 flush 固定为 Pending。
struct Backpressure {
    io: DuplexStream,
    flush_pending: bool,
    blocked: Arc<AtomicBool>,
}
impl AsyncRead for Backpressure {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, b)
    }
}
impl AsyncWrite for Backpressure {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.io).poll_write(cx, b);
        if result.is_pending() {
            self.blocked.store(true, Ordering::SeqCst);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flush_pending {
            self.blocked.store(true, Ordering::SeqCst);
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
fn pipeline(flush_pending: bool) -> (Relay, DuplexStream, Arc<AtomicBool>) {
    let (io, peer) = tokio::io::duplex(if flush_pending { 8192 } else { 16 });
    let blocked = Arc::new(AtomicBool::new(false));
    let routes = BTreeMap::from([(endpoint(0), (1, [7; 32]))]);
    let (incoming_tx, incoming) = mpsc::channel(QUEUE);
    let (tx, tasks) = start_region(
        Box::new(Backpressure {
            io,
            flush_pending,
            blocked: blocked.clone(),
        }),
        incoming_tx,
        BTreeMap::from([([7; 32], endpoint(0))]),
        routes.clone(),
        None,
    );
    (
        Relay {
            routes,
            senders: BTreeMap::from([(1, tx)]),
            magic: None,
            sockets: [None, None],
            endpoints: tokio::sync::watch::channel(Vec::new()).1,
            incoming: Mutex::new(incoming),
            _tasks: tasks,
        },
        peer,
        blocked,
    )
}
async fn blocked_send(relay: &Relay, blocked: &AtomicBool) {
    relay.try_send_to(&[9; MAX_WIRE], endpoint(0)).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !blocked.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("send must actually reach Pending");
}
async fn closed(relay: &Relay, peer: &mut DuplexStream) {
    tokio::time::timeout(Duration::from_secs(2), relay.disconnected())
        .await
        .expect("reconnect notification must not wait for blocked send");
    assert!(relay.is_closed());
    assert!(relay.try_send_to(&[1], endpoint(0)).is_err());
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut tail))
        .await
        .expect("both stream halves must be dropped")
        .unwrap();
}
#[tokio::test]
async fn eof_interrupts_pending_write_all() {
    let (relay, mut peer, blocked) = pipeline(false);
    blocked_send(&relay, &blocked).await;
    peer.shutdown().await.unwrap();
    closed(&relay, &mut peer).await;
}
#[tokio::test]
async fn eof_interrupts_pending_flush() {
    let (relay, mut peer, blocked) = pipeline(true);
    blocked_send(&relay, &blocked).await;
    peer.shutdown().await.unwrap();
    closed(&relay, &mut peer).await;
}
#[tokio::test]
async fn read_idle_interrupts_pending_write() {
    let (relay, mut peer, blocked) = pipeline(false);
    blocked_send(&relay, &blocked).await;
    tokio::time::sleep(READ_IDLE + Duration::from_millis(100)).await;
    closed(&relay, &mut peer).await;
}
#[tokio::test]
async fn writer_failure_closes_reader_mid_frame() {
    let (relay, mut peer, _) = pipeline(false);
    peer.write_all(&[5, 0, 0]).await.unwrap();
    // 内部队列注入超限帧触发 send 错误；写端退出必须撤销等待剩余首部的读任务。
    relay.senders[&1]
        .send((vec![0; MAX_FRAME + 1], endpoint(0)))
        .await
        .unwrap();
    closed(&relay, &mut peer).await;
}
#[tokio::test]
async fn outgoing_send_does_not_cancel_partial_read_frame() {
    let (relay, mut peer, _) = pipeline(false);
    peer.write_all(&[5, 0, 0]).await.unwrap();
    tokio::task::yield_now().await;
    relay.try_send_to(&[9], endpoint(0)).unwrap();
    let (kind, body) = frame(&mut peer).await.unwrap();
    assert_eq!((kind, body.len()), (4, 33));
    peer.write_all(&[0, 33]).await.unwrap();
    peer.write_all(&[7; 32]).await.unwrap();
    peer.write_all(&[42]).await.unwrap();
    let mut buf = [0; 8];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap(),
        (1, endpoint(0))
    );
    assert_eq!(buf[0], 42);
    assert!(!relay.is_closed());
}
