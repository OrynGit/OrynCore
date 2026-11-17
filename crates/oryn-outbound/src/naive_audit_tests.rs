use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "hysteria2")]
#[tokio::test]
async fn pending_write_cancellation_cannot_acknowledge_a_different_buffer() {
    let (tx, mut rx) = mpsc::channel(8);
    let mut writer = H3Writer::new(tx);
    let worker = tokio::spawn(async move {
        let mut received = Vec::new();
        while let Some(cmd) = rx.recv().await {
            match cmd {
                H3Command::Data(data, ack) => {
                    received.extend_from_slice(&data);
                    let _ = ack.send(Ok(()));
                }
                H3Command::Flush(ack) => {
                    let _ = ack.send(Ok(()));
                }
                H3Command::Finish(ack) => {
                    let _ = ack.send(Ok(()));
                    break;
                }
            }
        }
        received
    });
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    // 不调度 worker：首次 poll 要么接受数据并报告长度，要么 Pending 且不得偷偷接受。
    let accepted = match Pin::new(&mut writer).poll_write(&mut cx, b"original") {
        Poll::Ready(Ok(n)) => n,
        Poll::Pending => 0,
        Poll::Ready(Err(e)) => panic!("{e}"),
    };
    // 上一个写 Future 被丢弃，下一次写使用长度不同的新缓冲。
    let n = writer.write(b"x").await.unwrap();
    assert_eq!(n, 1, "must report the current buffer's length");
    writer.shutdown().await.unwrap();
    writer.shutdown().await.unwrap();
    assert!(writer.write(b"closed").await.is_err());
    let received = worker.await.unwrap();
    let mut expected = b"original"[..accepted].to_vec();
    expected.push(b'x');
    assert_eq!(received, expected);
}

#[cfg(feature = "hysteria2")]
#[tokio::test]
async fn failed_h3_write_cannot_be_hidden_by_flush_or_next_write() {
    let (tx, mut rx) = mpsc::channel(8);
    let mut writer = H3Writer::new(tx);
    assert_eq!(writer.write(b"data").await.unwrap(), 4);
    let peer = async {
        let H3Command::Data(_, ack) = rx.recv().await.unwrap() else {
            panic!("expected data")
        };
        let _ = ack.send(Err(io::ErrorKind::ConnectionReset.into()));
    };
    let (result, ()) = tokio::join!(writer.flush(), peer);
    assert!(result.is_err());
    assert!(writer.write(b"later").await.is_err());
    assert!(writer.flush().await.is_err());
    assert!(writer.shutdown().await.is_err());
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn empty_read_does_not_consume_padding_or_report_truncation() {
    let (io, mut peer) = tokio::io::duplex(64);
    let mut stream = Padded::new(io);
    peer.write_all(&[0, 2, 0, b'o', b'k']).await.unwrap();
    let mut one = [0];
    stream.read_exact(&mut one).await.unwrap();
    assert_eq!(one, [b'o']);
    assert_eq!(stream.read(&mut []).await.unwrap(), 0);
    stream.read_exact(&mut one).await.unwrap();
    assert_eq!(one, [b'k']);
}
