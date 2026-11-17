use super::HttpObfs;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

// 部分写出后故障，随后底层恢复也不得继续使用已破坏的连接。
struct FailingWriter {
    calls: usize,
    zero: bool,
}

impl tokio::io::AsyncWrite for FailingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.calls += 1;
        Poll::Ready(match self.calls {
            1 => Ok(data.len().min(3)),
            2 if self.zero => Ok(0),
            2 => Err(std::io::ErrorKind::BrokenPipe.into()),
            _ => panic!("terminal writer was polled again"),
        })
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        panic!("terminal writer was flushed")
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        panic!("terminal writer was shut down")
    }
}

#[tokio::test]
async fn partial_request_errors_are_terminal() {
    for zero in [false, true] {
        let mut obfs = HttpObfs::new(FailingWriter { calls: 0, zero }, "example.test", 80);
        let kind = if zero {
            std::io::ErrorKind::WriteZero
        } else {
            std::io::ErrorKind::BrokenPipe
        };
        assert_eq!(obfs.write(b"body").await.unwrap_err().kind(), kind);
        assert_eq!(obfs.write(b"new").await.unwrap_err().kind(), kind);
        assert_eq!(obfs.flush().await.unwrap_err().kind(), kind);
        assert_eq!(obfs.shutdown().await.unwrap_err().kind(), kind);
    }
}

fn once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

// 旧实现首写 Pending 后保留未接纳的输入；取消后短输入收到旧长度。
#[tokio::test]
async fn cancelled_write_never_reports_old_length() {
    let (stream, mut peer) = duplex(8);
    let mut obfs = HttpObfs::new(stream, "example.test", 80);
    let first = b"old-first-payload";
    let accepted = {
        let mut write = std::pin::pin!(obfs.write(first));
        match once(write.as_mut()) {
            Poll::Ready(Ok(n)) => n,
            Poll::Pending => 0,
            other => panic!("{other:?}"),
        }
    };
    // 再次遇到背压后取消，换更短且不同的输入。
    {
        let mut write = std::pin::pin!(obfs.write(b"cancelled-input"));
        assert!(once(write.as_mut()).is_pending());
    }
    let reader = tokio::spawn(async move {
        let mut wire = Vec::new();
        peer.read_to_end(&mut wire).await.unwrap();
        wire
    });
    assert_eq!(obfs.write(b"Z").await.unwrap(), 1);
    obfs.shutdown().await.unwrap();
    let wire = reader.await.unwrap();
    let end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let mut expected = first[..accepted].to_vec();
    expected.push(b'Z');
    assert_eq!(&wire[end..], expected);
}

#[tokio::test]
async fn read_after_first_write_drains_request_without_explicit_flush() {
    let (stream, mut peer) = duplex(8);
    let mut obfs = HttpObfs::new(stream, "example.test", 80);
    obfs.write_all(b"body").await.unwrap();
    let server = async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(peer.read_u8().await.unwrap());
        }
        let mut body = [0; 4];
        peer.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"body");
        peer.write_all(b"HTTP/1.1 200 OK\r\n\r\nreply").await.unwrap();
    };
    let client = async {
        let mut reply = [0; 5];
        obfs.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::join!(server, client);
    }).await.expect("read must drive accepted pending request");
}

#[tokio::test]
async fn flush_drains_accepted_first_request() {
    let (stream, mut peer) = duplex(8);
    let mut obfs = HttpObfs::new(stream, "example.test", 80);
    {
        let mut write = std::pin::pin!(obfs.write(b"body"));
        let _ = once(write.as_mut());
    }
    {
        let mut flush = std::pin::pin!(obfs.flush());
        assert!(
            once(flush.as_mut()).is_pending(),
            "flush must drain request before succeeding"
        );
    }
    let reader = tokio::spawn(async move {
        let mut wire = Vec::new();
        peer.read_to_end(&mut wire).await.unwrap();
        wire
    });
    obfs.flush().await.unwrap();
    obfs.shutdown().await.unwrap();
    let wire = reader.await.unwrap();
    assert!(wire.ends_with(b"\r\n\r\nbody"));
}

#[tokio::test]
async fn first_write_is_bounded_and_shutdown_drains() {
    let (stream, mut peer) = duplex(8);
    let mut obfs = HttpObfs::new(stream, "example.test", 80);
    let data = vec![42; 128 * 1024];
    let n = {
        let mut write = std::pin::pin!(obfs.write(&data));
        match once(write.as_mut()) {
            Poll::Ready(Ok(n)) => n,
            other => panic!("buffered first write must acknowledge acceptance: {other:?}"),
        }
    };
    assert_eq!(n, 16 * 1024);
    let reader = tokio::spawn(async move {
        let mut wire = Vec::new();
        peer.read_to_end(&mut wire).await.unwrap();
        wire
    });
    obfs.shutdown().await.unwrap();
    let wire = reader.await.unwrap();
    let end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(String::from_utf8_lossy(&wire[..end]).contains("Content-Length: 16384\r\n"));
    assert_eq!(&wire[end..], &data[..n]);
}
