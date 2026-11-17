//! 对照 mihomo AnyTLS 与 sing smux 的线格式和关闭语义；不依赖公网节点。
use super::*;

#[tokio::test]
#[ignore = "requires local mihomo session peer via ORYN_ANYTLS_AUDIT_PEER"]
async fn mihomo_large_frames_slow_reader_fin_and_session_reuse() {
    use std::io::BufRead;
    struct Peer(std::process::Child);
    impl Drop for Peer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let binary = std::env::var_os("ORYN_ANYTLS_AUDIT_PEER").expect("set ORYN_ANYTLS_AUDIT_PEER");
    let mut peer = Peer(
        std::process::Command::new(binary)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = peer.0.stdout.take().unwrap();
    let addr = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            let mut line = String::new();
            std::io::BufReader::new(stdout)
                .read_line(&mut line)
                .unwrap();
            line.trim().parse::<std::net::SocketAddr>().unwrap()
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let carrier = tokio::net::TcpStream::connect(addr).await.unwrap();
    let session = Session::new_any(Box::new(carrier));
    tokio::time::timeout(Duration::from_secs(10), async {
        for _ in 0..2 {
            let mut stream = session.open().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received.len(), 16 * 65535);
            for block in received.chunks(65535) {
                assert!(block.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
            }
            assert!(stream.write(b"after FIN").await.is_err());
            assert!(!session.closed());
        }
    })
    .await
    .unwrap();
}

async fn peer_frame(peer: &mut tokio::io::DuplexStream, any: bool, kind: u8, id: u32, data: &[u8]) {
    let mut wire = if any {
        let mut h = vec![if kind == 1 { 3 } else { kind }];
        h.extend(id.to_be_bytes());
        h.extend((data.len() as u16).to_be_bytes());
        h
    } else {
        let mut h = vec![1, kind];
        h.extend((data.len() as u16).to_le_bytes());
        h.extend(id.to_le_bytes());
        h
    };
    wire.extend_from_slice(data);
    peer.write_all(&wire).await.unwrap();
}

#[tokio::test]
async fn accepts_full_u16_data_frame_without_resetting_session() {
    for any in [false, true] {
        let (carrier, mut peer) = tokio::io::duplex(256 * 1024);
        let session = Session::new_mode(Box::new(carrier), any);
        let mut flow = session.open().await.unwrap();
        for size in [32769, 65535] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            peer_frame(&mut peer, any, 2, 1, &data).await;
            let mut got = vec![0; size];
            tokio::time::timeout(Duration::from_secs(1), flow.read_exact(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, data);
        }
        assert!(!session.closed());
    }
}

#[tokio::test]
async fn any_shutdown_releases_blocked_receiver_without_dropping_stream() {
    // 分别填满字节预算和帧数预算。shutdown 后仍保留旧 stream，模拟 split 的读半部。
    for (count, size) in [(9, 16384), (129, 1)] {
        let (carrier, mut peer) = tokio::io::duplex(256 * 1024);
        let session = Session::new_any(Box::new(carrier));
        let mut old = session.open().await.unwrap();
        for _ in 0..count {
            peer_frame(&mut peer, true, 2, 1, &vec![1; size]).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        old.shutdown().await.unwrap();
        let mut next = session.open().await.unwrap();
        peer_frame(&mut peer, true, 2, 3, b"next").await;
        let mut got = [0; 4];
        tokio::time::timeout(STALL_TIMEOUT / 2, next.read_exact(&mut got))
            .await
            .expect("closed stream must not block the session")
            .unwrap();
        assert_eq!(&got, b"next");
        assert_eq!(old.read(&mut got).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn any_peer_fin_rejects_writes_but_preserves_queued_data() {
    let (carrier, mut peer) = tokio::io::duplex(4096);
    let session = Session::new_any(Box::new(carrier));
    let mut flow = session.open().await.unwrap();
    peer_frame(&mut peer, true, 2, 1, b"last").await;
    peer_frame(&mut peer, true, 1, 1, b"").await;
    let mut got = Vec::new();
    flow.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"last");
    assert!(flow.write(b"must not be accepted").await.is_err());
    assert!(!session.closed());
}

/// 回归：一条没有正常关闭的流在写命令队列已满时被丢弃，不能连带关闭同一会话上的其它流。
/// 原实现在 FIN 入队失败时直接 abort 整个会话；AnyTLS 并发超过会话上限后多条流共享会话，
/// 一个应用重置连接就会切断同会话的所有流（真机 Speedtest 多线程断开）。
#[tokio::test]
async fn dropping_an_unclosed_stream_with_a_full_queue_keeps_the_session_alive() {
    for any in [true, false] {
        // 小缓冲的承载：对端暂不读取，写任务很快阻塞，命令队列被填满
        let (carrier, mut peer) = tokio::io::duplex(256);
        let session = if any {
            Session::new_any(Box::new(carrier))
        } else {
            Session::new(Box::new(carrier))
        };
        let a = session.open().await.unwrap();
        let mut b = session.open().await.unwrap();
        let writer = tokio::spawn(async move {
            let big = vec![7u8; 512 * 1024];
            let result = tokio::time::timeout(Duration::from_secs(8), b.write_all(&big)).await;
            (b, result)
        });
        tokio::time::sleep(Duration::from_millis(300)).await; // 队列已满，b 卡在背压上
        drop(a); // 没有 shutdown
        let drain = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok(n) = peer.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });
        let (b, result) = writer.await.unwrap();
        let result = result.unwrap_or_else(|_| panic!("any={any}: b stalled"));
        assert!(result.is_ok(), "any={any}: {result:?}");
        assert!(!session.closed(), "any={any}: session was closed");
        drop(b);
        drain.abort();
    }
}

/// 回归：AnyTLS 对服务端发来的未知命令、超长控制帧和无效填充方案只忽略，不关闭会话
/// （sing-anytls 的 recvLoop 同样忽略；原实现会直接把整条会话判为失败）。
#[tokio::test]
async fn anytls_ignores_unknown_commands_oversized_control_frames_and_bad_schemes() {
    let (carrier, mut peer) = tokio::io::duplex(1 << 20);
    let session = Session::new_any(Box::new(carrier));
    let mut stream = session.open().await.unwrap();
    let raw = |cmd: u8, id: u32, data: &[u8]| {
        let mut wire = vec![cmd];
        wire.extend(id.to_be_bytes());
        wire.extend((data.len() as u16).to_be_bytes());
        wire.extend_from_slice(data);
        wire
    };
    // 未知命令 42（带数据）、服务端不该发的 SYN(1) 与 Settings(4)、无效填充方案、
    // 超过 4096 字节的方案、waste，然后才是真正的数据。
    for frame in [
        raw(42, 0, b"abc"),
        raw(1, 1, b""),
        raw(4, 0, b"v=2"),
        raw(6, 0, b"stop=x\n1=bad"),
        raw(6, 0, &vec![b'a'; 5000]),
        raw(0, 0, &[0; 100]),
        raw(2, 1, b"hello"),
    ] {
        peer.write_all(&frame).await.unwrap();
    }
    let mut buf = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
        .await
        .expect("data after the ignored frames must still arrive")
        .unwrap();
    assert_eq!(&buf, b"hello");
    assert!(!session.closed());
}
