use super::*;
use tokio::io::{duplex, DuplexStream};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn stream(io: DuplexStream) -> EncryptedStream<DuplexStream> {
    EncryptedStream::new(
        io,
        Zeroizing::new([7; 96]),
        AeadState::new(b"ctx", &[7; 96]),
        Some(AeadState::new(b"ctx", &[7; 96])),
    )
}
fn record(plain: &[u8]) -> Vec<u8> {
    let mut a = AeadState::new(b"ctx", &[7; 96]);
    let n = plain.len() + 16;
    let mut h = vec![23, 3, 3, (n >> 8) as u8, n as u8];
    h.extend(a.seal(&h, plain).unwrap());
    h
}
#[tokio::test]
async fn flush_error_locks_writer_and_preserves_nonce() {
    struct FlushFails;
    impl AsyncWrite for FlushFails {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let mut writer = EncryptedStream::new(FlushFails, Zeroizing::new([7; 96]),
        AeadState::new(b"ctx", &[7; 96]), Some(AeadState::new(b"ctx", &[7; 96])));
    writer.write_all(b"first").await.unwrap();
    assert_eq!(writer.flush().await.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    let nonce = writer.tx.nonce;
    assert!(writer.write(b"second").await.is_err(), "flush failure must terminate writer");
    assert_eq!(writer.tx.nonce, nonce);
    assert_eq!(writer.flush().await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(writer.shutdown().await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn binary_context_and_aead_match_independent_go_vector() {
    // lukechampine.com/blake3 1.4.1 + Go crypto/aes；不是 UTF-8 的上下文。
    let ctx = [255, 254, 0, 128, 1];
    assert_eq!(
        hex(derive(&ctx, b"material").as_ref()),
        "be01cb8b84167b1ac3ef17d5909ddf6165fe7bae2ade866ec20a17ae3d12a1fa"
    );
    assert_eq!(
        hex(&AeadState::new(&ctx, b"material")
            .seal(&[23, 3, 3, 0, 23], b"payload")
            .unwrap()),
        "73cdb8bc955af80e269be1617600af776e4a3f259848b1"
    );
    assert_eq!(
        *derive(b"ctx", b"input"),
        blake3::derive_key("ctx", b"input")
    );
    assert!(x25519(&StaticSecret::from([1; 32]), &[0; 32]).is_err());
}
#[tokio::test]
async fn records_are_bounded_fragmented_and_rekey_at_nonce_wrap() {
    let (a, b) = duplex(1);
    let mut tx = stream(a);
    let mut rx = stream(b);
    tx.tx.nonce = MAX_NONCE;
    rx.rx.as_mut().unwrap().nonce = MAX_NONCE;
    let data: Vec<_> = (0..40000).map(|i| (i % 251) as u8).collect();
    let writer = async {
        let n = tx.write(&data).await.unwrap();
        assert_eq!(n, 8192);
        assert_eq!(tx.pending.len(), 8213);
        assert_eq!(tx.tx.nonce, [0; 12]); // 当前记录 nonce 0 后更新密钥
        tx.write_all(&data[n..]).await.unwrap();
        tx.shutdown().await.unwrap();
    };
    let reader = async {
        let mut got = Vec::new();
        rx.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, data);
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(writer, reader);
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn cancellation_keeps_partial_header_and_ciphertext() {
    let wire = record(b"cancel-safe");
    for cut in [1, 4, 5, 9, wire.len() - 1] {
        let (a, mut b) = duplex(100);
        let mut rx = stream(a);
        b.write_all(&wire[..cut]).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(2), rx.read_u8())
            .await
            .is_err());
        b.write_all(&wire[cut..]).await.unwrap();
        let mut got = [0; 11];
        rx.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"cancel-safe");
    }
}
#[tokio::test]
async fn tamper_truncation_and_oversize_fail_closed() {
    let wire = record(b"tamper-test");
    let mut cases = Vec::new();
    for cut in 1..wire.len() {
        cases.push(wire[..cut].to_vec());
    }
    for at in [0, 1, 2, 6, wire.len() - 1] {
        let mut w = wire.clone();
        w[at] ^= 1;
        cases.push(w);
    }
    for n in [0u16, 16, 16641, 65535] {
        cases.push(vec![23, 3, 3, (n >> 8) as u8, n as u8]);
    }
    for bytes in cases {
        let (a, mut b) = duplex(100);
        let mut rx = stream(a);
        b.write_all(&bytes).await.unwrap();
        drop(b);
        assert!(rx.read_u8().await.is_err());
        assert!(rx.read_u8().await.is_err());
        assert!(rx.body.len() <= MAX_CIPHERTEXT);
    }
}
#[tokio::test]
async fn expired_ticket_is_evicted_before_connecting() {
    let spec = VlessEncryptionSpec::parse(
        "mlkem768x25519plus.native.0rtt.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    )
    .unwrap()
    .unwrap();
    let client = Client::new(spec);
    *client.tickets.lock().unwrap() = Some(Arc::new(Ticket {
        key: Zeroizing::new([1; 64]),
        value: Zeroizing::new([2; 16]),
        expires: Instant::now() - Duration::from_secs(1),
    }));
    let (a, b) = duplex(1);
    drop(b);
    assert!(client.connect(a).await.is_err());
    assert!(client.tickets.lock().unwrap().is_none());
}
