//! 用可控 Pending 模拟缓冲传输，检查首部状态与帧入队之间的取消窗口。
use super::*;
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct State {
    wire: std::sync::Mutex<Vec<u8>>,
    flush_ready: AtomicBool,
}
struct FlushGate(Arc<State>);
impl AsyncRead for FlushGate {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for FlushGate {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.wire.lock().unwrap().extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.0.flush_ready.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

async fn cancel_at_pending(future: impl Future<Output = io::Result<()>>) {
    let mut future = Box::pin(future);
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn uot_first_flush_cancellation_keeps_request() {
    let state = Arc::new(State::default());
    let target = oryn_config::TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
    let conn = uot::UotConn::new(Box::new(FlushGate(state.clone())), 2, &target).unwrap();
    cancel_at_pending(conn.send_to(b"one", &target)).await;
    state.flush_ready.store(true, Ordering::SeqCst);
    conn.send_to(b"two", &target).await.unwrap();
    let mut expected = vec![0, 1, 1, 2, 3, 4, 0, 53]; // v2 request
    for data in [b"one", b"two"] {
        expected.extend_from_slice(&[0, 1, 2, 3, 4, 0, 53, 0, 3]);
        expected.extend_from_slice(data);
    }
    assert_eq!(*state.wire.lock().unwrap(), expected);
}

#[tokio::test]
async fn xudp_first_flush_cancellation_keeps_new_session() {
    let state = Arc::new(State::default());
    let target = oryn_config::TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
    let conn = packet_encoding::XudpConn::new(Box::new(FlushGate(state.clone())), target.clone());
    cancel_at_pending(conn.send_to(b"one", &target)).await;
    state.flush_ready.store(true, Ordering::SeqCst);
    conn.send_to(b"two", &target).await.unwrap();
    let mut expected = Vec::new();
    for (status, data) in [(1, b"one"), (2, b"two")] {
        expected.extend_from_slice(&[0, 12, 0, 0, status, 1, 2, 0, 53, 1, 1, 2, 3, 4, 0, 3]);
        expected.extend_from_slice(data);
    }
    assert_eq!(*state.wire.lock().unwrap(), expected);
}

#[tokio::test]
async fn frame_writer_preserves_flush_barrier_before_next_frame() {
    let state = Arc::new(State::default());
    let mut writer = FrameWriter::new(FlushGate(state.clone()));
    cancel_at_pending(writer.send(b"one".to_vec())).await;
    assert_eq!(*state.wire.lock().unwrap(), b"one");
    // 首帧已经写出但 flush 未完成：下一帧仍不能越过它。
    cancel_at_pending(writer.send(b"discarded".to_vec())).await;
    assert_eq!(*state.wire.lock().unwrap(), b"one");
    state.flush_ready.store(true, Ordering::SeqCst);
    writer.send(b"two".to_vec()).await.unwrap();
    assert_eq!(*state.wire.lock().unwrap(), b"onetwo");
}
