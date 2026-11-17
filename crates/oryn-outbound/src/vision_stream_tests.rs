//! 真 TLS 对端手工构造公开 Vision 帧，刻意在 TLS 记录边界拆开 UUID / 首部。
use super::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
const UUID: [u8; 16] = [9; 16];

async fn pair() -> (VisionStream, tokio_rustls::server::TlsStream<DuplexStream>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(oryn_tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let (client, server) = tokio::io::duplex(64 * 1024);
    let client = RecordReader::new(Box::new(client) as BoxStream);
    let (client, server) = tokio::join!(
        oryn_tls::connect(client, "localhost", &[], true),
        acceptor.accept(server)
    );
    (
        VisionStream::new(client.unwrap(), UUID, Vec::new()),
        server.unwrap(),
    )
}

fn frame(command: u8, data: &[u8]) -> Vec<u8> {
    let mut wire = UUID.to_vec();
    wire.push(command);
    wire.extend_from_slice(&(data.len() as u16).to_be_bytes());
    wire.extend_from_slice(&3u16.to_be_bytes());
    wire.extend_from_slice(data);
    wire.extend_from_slice(&[0; 3]);
    wire
}

#[tokio::test]
async fn partial_inner_application_record_direct_preserves_all_bytes() {
    let (mut client, mut server) = pair().await;
    // 已完成 TLS1.3 识别，单独刻画发送策略；不伪装成完整内层握手验证。
    client.filter.is_tls = true;
    client.filter.is_tls12_or_above = true;
    client.filter.enable_xtls = true;
    client.filter.packets_to_filter = 0;
    let first = [0x17, 3, 3, 0, 16, 0xaa, 0xbb];
    let rest = [0xcc; 14];
    client.write_all(&first).await.unwrap();
    client.flush().await.unwrap();
    let mut head = [0; 21];
    server.read_exact(&mut head).await.unwrap();
    assert_eq!(&head[..16], &UUID);
    assert_eq!(head[16], COMMAND_DIRECT);
    assert_eq!(u16::from_be_bytes([head[17], head[18]]), first.len() as u16);
    let padding = u16::from_be_bytes([head[19], head[20]]) as usize;
    let mut content = vec![0; first.len() + padding];
    server.read_exact(&mut content).await.unwrap();
    assert_eq!(&content[..first.len()], &first);
    client.write_all(&rest).await.unwrap();
    client.flush().await.unwrap();
    let mut raw = [0; 14];
    server.get_mut().0.read_exact(&mut raw).await.unwrap();
    assert_eq!(raw, rest);
}

#[tokio::test]
async fn tls_record_splits_preserve_uuid_header_end_and_direct() {
    for command in [COMMAND_END, COMMAND_DIRECT] {
        for cut in 1..=21 {
            let (mut client, mut server) = pair().await;
            let wire = frame(command, b"payload");
            server.write_all(&[0, 0]).await.unwrap();
            server.write_all(&wire[..cut]).await.unwrap();
            server.flush().await.unwrap();
            let mut rest = wire[cut..].to_vec();
            rest.extend_from_slice(b"-tail");
            server.write_all(&rest).await.unwrap();
            server.flush().await.unwrap();
            let mut expected = b"payload-tail".to_vec();
            if command == COMMAND_DIRECT {
                // 切换后的字节故意看起来像 TLS 记录：绝不能再交给外层 TLS 解密。
                let raw = b"\x17\x03\x03\x00\x04RAW!";
                server.get_mut().0.write_all(raw).await.unwrap();
                server.get_mut().0.shutdown().await.unwrap();
                expected.extend_from_slice(raw);
            } else {
                server.shutdown().await.unwrap();
            }
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, expected, "command={command} cut={cut}");
        }
    }
}

#[tokio::test]
async fn cancelled_read_keeps_partial_vision_prefix() {
    for cut in [1, 8, 15, 16, 18, 20] {
        let (mut client, mut server) = pair().await;
        let wire = frame(COMMAND_END, b"after cancellation");
        server.write_all(&[0, 0]).await.unwrap();
        server.write_all(&wire[..cut]).await.unwrap();
        server.flush().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read(&mut [0; 64]))
                .await
                .is_err(),
            "prefix bytes must not escape as application data"
        );
        server.write_all(&wire[cut..]).await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"after cancellation");
    }
}

#[tokio::test]
async fn truncated_and_invalid_vision_frames_fail_closed() {
    let valid = frame(COMMAND_END, b"data");
    for wire in [
        valid[..16].to_vec(),
        valid[..19].to_vec(),
        valid[..23].to_vec(),
        valid[..valid.len() - 1].to_vec(),
        frame(255, b"invalid"),
    ] {
        let (mut client, mut server) = pair().await;
        server.write_all(&[0, 0]).await.unwrap();
        server.write_all(&wire).await.unwrap();
        server.shutdown().await.unwrap();
        let error = client.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
        ));
        assert!(client.read(&mut [0; 1]).await.is_err());
        assert!(client.write(b"after failure").await.is_err());
    }
}

#[tokio::test]
async fn one_byte_tls_records_keep_continue_end_and_plain_tail() {
    let (mut client, mut server) = pair().await;
    let mut wire = frame(COMMAND_CONTINUE, b"first");
    wire.extend_from_slice(&frame(COMMAND_END, b"second")[16..]);
    server.write_all(&[0, 0]).await.unwrap();
    for byte in wire {
        server.write_all(&[byte]).await.unwrap();
        server.flush().await.unwrap();
    }
    server.write_all(b"tail").await.unwrap();
    server.shutdown().await.unwrap();
    let mut got = Vec::new();
    client.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"firstsecondtail");
}

#[tokio::test]
async fn empty_record_reader_read_never_waits_for_a_header() {
    let (ours, mut peer) = tokio::io::duplex(64);
    let mut reader = RecordReader::new(ours);
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(20), reader.read(&mut []))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    peer.write_all(&[23, 3, 3, 0, 1, 42]).await.unwrap();
    let mut got = [0; 6];
    reader.read_exact(&mut got).await.unwrap();
    assert_eq!(got, [23, 3, 3, 0, 1, 42]);
}

#[tokio::test]
async fn short_plaintext_including_partial_uuid_is_preserved_at_eof() {
    for data in [b"plain".as_slice(), &UUID[..7]] {
        let (mut client, mut server) = pair().await;
        server.write_all(&[0, 0]).await.unwrap();
        server.write_all(data).await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, data);
    }
}
