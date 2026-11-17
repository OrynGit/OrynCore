use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn stream(io: tokio::io::DuplexStream, encrypted: bool) -> SsrStream {
    let key = vec![7; 16];
    let protocol = protocol::Protocol::new(protocol::Kind::AuthSha1V4, key.clone(), "", 0);
    SsrStream {
        io: Box::new(io),
        enc: None,
        dec: None,
        kind: encrypted.then(|| "aes-128-cfb".parse().unwrap()),
        key,
        iv_len: if encrypted { 16 } else { 0 },
        read_iv: Vec::new(),
        codec: protocol.stream(&[1; 16]),
        undecoded: Vec::new(),
        decoded: Vec::new(),
        decoded_pos: 0,
        out: Vec::new(),
        out_pos: 0,
        failed: false,
    }
}

#[tokio::test]
async fn truncated_iv_and_authenticated_frame_are_not_clean_eof() {
    for encrypted in [false, true] {
        let (io, mut peer) = tokio::io::duplex(64);
        let mut stream = stream(io, encrypted);
        peer.write_all(&[0, 1]).await.unwrap();
        peer.shutdown().await.unwrap();
        let error = stream
            .read(&mut [0; 8])
            .await
            .expect_err("truncated protocol data");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}

#[tokio::test]
async fn authentication_failure_is_terminal_instead_of_raw_fallback() {
    let (io, mut peer) = tokio::io::duplex(64);
    let mut stream = stream(io, false);
    peer.write_all(&[0; 8]).await.unwrap();
    assert!(stream.read(&mut [0; 32]).await.is_err());
    peer.write_all(b"unauthenticated").await.unwrap();
    assert!(stream.read(&mut [0; 32]).await.is_err());
    assert!(stream.write(b"after failure").await.is_err());
}
