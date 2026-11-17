use super::*;
use std::future::Future;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn pair() -> (UtunRuntime, UnixDatagram) {
    let (local, peer) = UnixDatagram::pair().unwrap();
    for socket in [&local, &peer] {
        for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            let size: libc::c_int = 256 * 1024;
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_SOCKET,
                        option,
                        (&size as *const libc::c_int).cast(),
                        std::mem::size_of_val(&size) as libc::socklen_t,
                    )
                },
                0
            );
        }
    }
    (UtunRuntime::from_fd(local.as_raw_fd()).unwrap(), peer)
}
fn packet() -> Vec<u8> {
    let mut p = vec![0; 20];
    p[0] = 0x45;
    p[3] = 20;
    p
}
fn send(peer: &UnixDatagram) {
    let mut frame = Vec::new();
    oryn_netstack::utun::encode_frame(IpVersion::V4, &packet(), &mut frame).unwrap();
    peer.send(&frame).unwrap();
}
async fn ready(io: &UtunRuntime) {
    // 不消费 readiness，让单次手工 poll 精确测量预算。
    drop(io.fd.readable().await.unwrap());
    drop(io.fd.writable().await.unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_frames_exhaust_read_budget() {
    let stack = LwipStack::new(1500).unwrap();
    let (mut io, peer) = pair();
    for _ in 0..READ_BURST {
        peer.send(&[0]).unwrap();
    }
    send(&peer);
    ready(&io).await;
    let n = io.next(&stack).await.unwrap();
    assert_eq!(n, 0, "bad frames must consume the read budget");
    assert_eq!(io.next(&stack).await.unwrap(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn finite_errors_exhaust_attempt_budget() {
    let stack = LwipStack::new(1500).unwrap();
    for errno in [libc::EINTR, libc::ENOBUFS] {
        let (mut io, peer) = pair();
        io.enqueue(vec![packet(); WRITE_BURST + 1], &stack).unwrap();
        io.write_errors = vec![errno; WRITE_BURST + 1].into();
        send(&peer);
        ready(&io).await;
        io.next(&stack).await.unwrap();
        assert_eq!(
            io.write_errors.len(),
            1,
            "write errors consumed beyond budget: {errno}"
        );
        assert_eq!(
            io.pending.len(),
            if errno == libc::EINTR {
                WRITE_BURST + 1
            } else {
                1
            }
        );
    }
    let (mut io, peer) = pair();
    io.read_errors = vec![libc::EINTR; READ_BURST + 1].into();
    send(&peer);
    ready(&io).await;
    assert_eq!(io.next(&stack).await.unwrap(), 0);
    assert_eq!(io.read_errors.len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn exhausted_wouldblock_self_wakes_and_cancel_is_safe() {
    let stack = LwipStack::new(1500).unwrap();
    let (mut io, peer) = pair();
    send(&peer);
    ready(&io).await;
    // 最后一次尝试恰好清除 readiness，下一 poll 必须重新登记，不能永久 Pending。
    io.read_errors = vec![libc::EINTR; READ_BURST - 1].into();
    io.read_errors.push_back(libc::EAGAIN);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    {
        let mut next = Box::pin(io.next(&stack));
        assert!(matches!(next.as_mut().poll(&mut cx), Poll::Ready(Ok(0))));
    }
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    send(&peer);
    let n = tokio::time::timeout(Duration::from_secs(1), io.next(&stack))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 2);
    // 取消已经 Pending 的 next，再换一个 future，空闲后仍可被新包唤醒。
    {
        let mut next = Box::pin(io.next(&stack));
        assert!(next.as_mut().poll(&mut cx).is_pending());
    }
    let sender = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        send(&peer);
    };
    let (result, ()) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(1), io.next(&stack)),
        sender
    );
    assert_eq!(result.unwrap().unwrap(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn write_only_errors_pending_has_wake() {
    let stack = LwipStack::new(1500).unwrap();
    for last in [libc::EINTR, libc::ENOBUFS, libc::EAGAIN] {
        let (mut io, _peer) = pair();
        io.enqueue(vec![packet(); WRITE_BURST + 1], &stack).unwrap();
        io.write_errors = vec![libc::EINTR; WRITE_BURST - 1].into();
        io.write_errors.push_back(last);
        drop(io.fd.writable().await.unwrap());
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        {
            let mut next = Box::pin(io.next(&stack));
            assert!(next.as_mut().poll(&mut cx).is_pending());
        }
        assert!(io.write_errors.is_empty());
        assert!(wakes.0.load(Ordering::SeqCst) > 0, "missing wake: {last}");
        assert_eq!(io.pending_bytes, io.pending.len() * 20);
        // 注入 EAGAIN 并未真实填满内核缓冲，不能期待新的 writable 边沿；
        // 该分支只检验末次清除 readiness 后已安排重 poll。
        if last == libc::EAGAIN {
            continue;
        }
        // 取消 Pending 的 future 后，队列仍可继续发送。
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), io.next(&stack))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn successful_bursts_unchanged() {
    let stack = LwipStack::new(1500).unwrap();
    let (mut io, peer) = pair();
    for _ in 0..READ_BURST + 1 {
        send(&peer);
    }
    io.enqueue(vec![packet(); WRITE_BURST + 1], &stack).unwrap();
    ready(&io).await;
    assert_eq!(io.next(&stack).await.unwrap(), READ_BURST);
    assert_eq!(io.pending.len(), 1);
    assert_eq!(io.pending_bytes, 20);
    assert_eq!(io.next(&stack).await.unwrap(), 1);
    assert_eq!(io.pending_bytes, 0);
}
