//! S9：真实 QUIC 额度与写背压下，Drop 不保留异步清理等待者。
use super::*;
use futures_util::FutureExt;
struct Pair {
    endpoints: [quinn::Endpoint; 2],
    client: quinn::Connection,
    server: quinn::Connection,
}
impl Drop for Pair {
    fn drop(&mut self) {
        for e in &self.endpoints {
            e.close(0u32.into(), b"done");
        }
    }
}
impl Pair {
    async fn new(uni: u32, window: u32) -> Self {
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
        tls.alpn_protocols = vec![b"tuic".to_vec()];
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(window.into())
            .receive_window(32768u32.into())
            .send_window(2048)
            .max_concurrent_uni_streams(uni.into())
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
        tls.alpn_protocols = vec![b"tuic".to_vec()];
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
        Self {
            endpoints: [client_endpoint, server_endpoint],
            client,
            server,
        }
    }
}

fn hub(conn: quinn::Connection) -> Arc<UdpHub> {
    Arc::new(UdpHub {
        conn,
        sessions: Mutex::new(HashMap::new()),
        next_id: AtomicU16::new(1),
        reassembly: Mutex::new(Reassembly::new(
            REASSEMBLY_BUDGET,
            PENDING_PER_SESSION,
            MAX_FRAGMENTS,
            FRAG_WAIT,
        )),
    })
}
fn drop_packet(hub: &Arc<UdpHub>) {
    drop(hub.open(UdpRelayMode::Native, 1200).unwrap());
    assert!(hub.sessions.lock().unwrap().is_empty());
}
async fn writable(conn: &quinn::Connection) {
    // 等 MAX_STREAMS 到达：只 poll，不消耗额度。
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(Ok(mut send)) = conn.open_uni().now_or_never() {
                send.write_all(b"probe").await.unwrap();
                send.finish().unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn exhausted_credit_drops_do_not_queue_and_recovered_credit_sends_dissociate() {
    let pair = Pair::new(0, 1024).await;
    let hub = hub(pair.client.clone());
    for _ in 0..256 {
        drop_packet(&hub);
        tokio::task::yield_now().await;
    }
    assert!(pair.client.close_reason().is_none());
    pair.server.set_max_concurrent_uni_streams(1u32.into());
    // 旧实现此时会发送额度耗尽期间积攒的 Dissociate。
    assert!(
        tokio::time::timeout(Duration::from_millis(100), pair.server.accept_uni())
            .await
            .is_err(),
        "stale cleanup was queued while uni credit was exhausted"
    );
    writable(&pair.client).await;
    let mut recv = pair.server.accept_uni().await.unwrap();
    assert_eq!(recv.read_to_end(16).await.unwrap(), b"probe");
    // 上一条流 FIN/读取完成后，真实归还额度；正常 Drop 应发送新关联 ID。
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let id = hub.next_id.load(Ordering::Relaxed);
            drop_packet(&hub);
            if let Ok(Ok(mut recv)) =
                tokio::time::timeout(Duration::from_millis(20), pair.server.accept_uni()).await
            {
                assert_eq!(
                    recv.read_to_end(4).await.unwrap(),
                    [5, 3, (id >> 8) as u8, id as u8]
                );
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(pair.client.close_reason().is_none());
}
#[tokio::test]
async fn write_backpressure_resets_only_cleanup_stream_and_returns_credit() {
    let pair = Pair::new(1, 0).await;
    let hub = hub(pair.client.clone());
    drop_packet(&hub);
    tokio::task::yield_now().await;
    // 零 stream window：旧实现停在 write_all，新实现立即 reset。
    // 接收端消费 RESET 后才会归还 QUIC 流额度。
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut recv = pair.server.accept_uni().await.unwrap();
        assert!(matches!(
            recv.read_to_end(4).await,
            Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(_)))
        ));
    })
    .await
    .expect("cleanup did not reset its blocked stream");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(Ok(mut send)) = pair.client.open_uni().now_or_never() {
                send.reset(0u32.into()).unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cleanup retained uni credit under write backpressure");
    assert!(pair.client.close_reason().is_none());
    pair.client
        .send_datagram(Bytes::from_static(b"still alive"))
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), pair.server.read_datagram())
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        b"still alive"
    );
}
