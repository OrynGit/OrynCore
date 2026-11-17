//! 真实 QUIC / TLS / HTTP3 上的取消与回收，不以模拟发送队列代替传输背压。
use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type PeerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

struct Pair {
    endpoints: [quinn::Endpoint; 2],
    client: quinn::Connection,
    server: quinn::Connection,
    sender: H3Sender,
    incoming: mpsc::Receiver<PeerStream>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Pair {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        for endpoint in &self.endpoints {
            endpoint.close(0u32.into(), b"test finished");
        }
    }
}
impl Pair {
    async fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(oryn_tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(1024u32.into())
            .receive_window(32768u32.into())
            .send_window(2048)
            .max_concurrent_bidi_streams(8u32.into())
            .max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
        let transport = Arc::new(transport);
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        server_config.transport_config(transport.clone());
        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(oryn_tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        ));
        client_config.transport_config(transport);
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let connect = client_endpoint
            .connect(server_endpoint.local_addr().unwrap(), "localhost")
            .unwrap();
        let (client, server) = tokio::join!(connect, async {
            server_endpoint.accept().await.unwrap().await
        });
        let (client, server) = (client.unwrap(), server.unwrap());
        let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(client.clone()))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let (tx, incoming) = mpsc::channel(4);
        let connection = server.clone();
        let serve = tokio::spawn(async move {
            let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            while let Ok(Some(resolver)) = h3.accept().await {
                let (request, mut stream) = resolver.resolve_request().await.unwrap();
                assert_eq!(request.method(), http::Method::CONNECT);
                stream
                    .send_response(http::Response::builder().status(200).body(()).unwrap())
                    .await
                    .unwrap();
                if tx.send(stream).await.is_err() {
                    break;
                }
            }
        });
        Self {
            endpoints: [client_endpoint, server_endpoint],
            client,
            server,
            sender,
            incoming,
            tasks: vec![driver, serve],
        }
    }
    async fn open(&mut self) -> (H3Stream, PeerStream) {
        let request = http::Request::builder()
            .method("CONNECT")
            .uri("echo.test:443")
            .body(())
            .unwrap();
        let mut stream = self.sender.send_request(request).await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        let peer = self.incoming.recv().await.unwrap();
        let (send, recv) = stream.split();
        (H3Stream::new(send, recv), peer)
    }
    async fn wait_cancel(&self, resets: u64, stops: u64) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let stats = self.server.stats().frame_rx;
                if stats.reset_stream > resets && stats.stop_sending > stops {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("dropping a Flow must cancel both QUIC directions without peer reads");
        assert!(self.client.close_reason().is_none());
    }
}

#[tokio::test]
async fn real_h3_backpressure_drop_cancels_worker_and_preserves_other_flows() {
    let mut pair = Pair::new().await;
    let (mut survivor, mut survivor_peer) = pair.open().await;
    for _ in 0..4 {
        let (mut victim, victim_peer) = pair.open().await;
        let stats = pair.server.stats().frame_rx;
        victim.write_all(&vec![42; 16384]).await.unwrap();
        // 对端不读，数据大于接收信用和本地发送窗口，send_data 必须保持 Pending。
        assert!(
            tokio::time::timeout(Duration::from_millis(100), victim.flush())
                .await
                .is_err()
        );
        let worker = victim.send_task.abort_handle();
        assert!(!worker.is_finished());
        drop(victim);
        pair.wait_cancel(stats.reset_stream, stats.stop_sending)
            .await;
        assert!(
            worker.is_finished(),
            "cancelled send worker must release its owned buffers"
        );
        drop(victim_peer);
    }
    survivor.write_all(b"ping").await.unwrap();
    survivor.shutdown().await.unwrap();
    let mut got = Vec::new();
    while let Some(mut data) = survivor_peer.recv_data().await.unwrap() {
        got.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    }
    assert_eq!(got, b"ping");
    // 正常 shutdown 只关闭上传；下行仍可工作。
    survivor_peer
        .send_data(Bytes::from_static(b"pong"))
        .await
        .unwrap();
    survivor_peer.finish().await.unwrap();
    let mut got = Vec::new();
    survivor.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"pong");
}

#[tokio::test]
async fn real_h3_cancelled_flush_can_resume_without_duplicate_data() {
    let mut pair = Pair::new().await;
    let (mut client, mut peer) = pair.open().await;
    let data: Vec<u8> = (0..16384).map(|i| (i % 251) as u8).collect();
    client.write_all(&data).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), client.flush())
            .await
            .is_err()
    );
    let received = tokio::time::timeout(Duration::from_secs(5), async {
        let upload = async {
            client.flush().await.unwrap();
            client.shutdown().await.unwrap();
        };
        let download = async {
            let mut received = Vec::new();
            while let Some(mut data) = peer.recv_data().await.unwrap() {
                received.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            received
        };
        let ((), received) = tokio::join!(upload, download);
        received
    })
    .await
    .unwrap();
    assert_eq!(received, data);
}

#[tokio::test]
async fn real_h3_drop_before_worker_is_polled_resets_request() {
    let mut pair = Pair::new().await;
    let (client, _peer) = pair.open().await;
    let stats = pair.server.stats().frame_rx;
    let worker = client.send_task.abort_handle();
    drop(client);
    pair.wait_cancel(stats.reset_stream, stats.stop_sending)
        .await;
    assert!(worker.is_finished());
}
