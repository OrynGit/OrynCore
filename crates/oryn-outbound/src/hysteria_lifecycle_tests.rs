//! 真实 QUIC 保持流与受控分片预算回归。
use super::*;

fn hub(budget: usize) -> Arc<UdpHub> {
    Arc::new(UdpHub {
        sessions: Mutex::new(HashMap::new()),
        reassembly: Mutex::new(Reassembly::new(budget, 4, 16, FRAG_WAIT)),
        task: Mutex::new(None),
        keepers: Slots::default(),
    })
}
fn inbox() -> SessionInbox {
    Arc::new(Inbox::new(8))
}

async fn pair() -> ([quinn::Endpoint; 2], quinn::Connection, quinn::Connection) {
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
    ([client_endpoint, server_endpoint], client, server)
}
async fn packet(
    client: &quinn::Connection,
    server: &quinn::Connection,
    hub: &Arc<UdpHub>,
    id: u32,
) -> (HyPacket, quinn::SendStream, quinn::RecvStream) {
    let (mut send, recv) = client.open_bi().await.unwrap();
    send.write_all(b"open").await.unwrap();
    let (peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
    let mut request = [0; 4];
    peer_recv.read_exact(&mut request).await.unwrap();
    let rx = inbox();
    hub.sessions.lock().unwrap().insert(id, rx.clone());
    (
        HyPacket::new(id, client.clone(), hub.clone(), rx, send, recv).unwrap(),
        peer_send,
        peer_recv,
    )
}

#[tokio::test]
async fn hold_eof_and_reset_close_only_associated_packet() {
    let (_endpoints, client, server) = pair().await;
    let hub = hub(1024);
    let target = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
    for reset in [false, true] {
        let (packet, mut peer, _recv) = packet(&client, &server, &hub, 7).await;
        peer.write_all(b"ignored hold bytes").await.unwrap();
        if reset {
            peer.reset(1u32.into()).unwrap();
        } else {
            peer.finish().unwrap();
        }
        let result =
            tokio::time::timeout(Duration::from_secs(1), packet.recv_from(&mut [0; 32])).await;
        assert!(
            result.is_ok(),
            "hold stream closure must wake receiver while QUIC stays live"
        );
        assert_eq!(
            result.unwrap().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(client.close_reason().is_none());
        assert!(packet.send_to(b"closed", &target).await.is_err());
        assert!(!hub.sessions.lock().unwrap().contains_key(&7));
    }
}

#[tokio::test]
async fn dropping_old_packet_preserves_reused_id_and_cancels_reader() {
    let (_endpoints, client, server) = pair().await;
    let hub = hub(1024);
    let (old, old_peer, _recv) = packet(&client, &server, &hub, 7).await;
    let replacement = inbox();
    hub.sessions.lock().unwrap().insert(7, replacement.clone());
    drop(old);
    assert!(
        hub.sessions
            .lock()
            .unwrap()
            .get(&7)
            .is_some_and(|rx| Arc::ptr_eq(rx, &replacement)),
        "old Drop must not remove replacement"
    );
    tokio::time::timeout(Duration::from_secs(1), old_peer.stopped())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hub.keepers.used(), 0);
}

fn frame(session: u32, frag: u8) -> Vec<u8> {
    let mut data = session.to_be_bytes().to_vec();
    data.extend_from_slice(&[0, 1, b'a', 0, 53, 0, 1, frag, 2, 0, 8]);
    data.extend_from_slice(&[frag; 8]);
    data
}
#[tokio::test]
async fn old_keeper_eof_preserves_reused_id() {
    let (_endpoints, client, server) = pair().await;
    let hub = hub(1024);
    let (old, mut peer, _recv) = packet(&client, &server, &hub, 7).await;
    let replacement = inbox();
    hub.sessions.lock().unwrap().insert(7, replacement.clone());
    peer.finish().unwrap();
    tokio::time::timeout(Duration::from_secs(1), old.rx.recv())
        .await
        .unwrap();
    assert!(hub
        .sessions
        .lock()
        .unwrap()
        .get(&7)
        .is_some_and(|rx| Arc::ptr_eq(rx, &replacement)));
    assert_eq!(hub.keepers.used(), 0);
}

#[tokio::test]
async fn aborted_keepers_keep_their_slot_until_task_exits() {
    let (_endpoints, client, server) = pair().await;
    let hub = hub(1024);
    let (packet, _peer, _recv) = packet(&client, &server, &hub, 7).await;
    let reservations: Vec<_> = (1..MAX_SESSIONS)
        .map(|_| hub.keepers.acquire(MAX_SESSIONS).unwrap())
        .collect();
    assert!(hub.keepers.acquire(MAX_SESSIONS).is_none());
    drop(packet);
    // 当前线程尚未 yield，abort 不能提前归还名额、允许累计取消中的任务。
    assert!(hub.keepers.acquire(MAX_SESSIONS).is_none());
    tokio::task::yield_now().await;
    assert_eq!(hub.keepers.used(), MAX_SESSIONS - 1);
    drop(reservations);
    assert_eq!(hub.keepers.used(), 0);
}

#[tokio::test]
async fn unknown_fragments_cannot_consume_live_session_budget() {
    let hub = hub(8);
    for unknown in 100..110 {
        hub.ingest(&frame(unknown, 0));
    }
    let rx = inbox();
    hub.sessions.lock().unwrap().insert(7, rx.clone());
    hub.ingest(&frame(7, 0));
    hub.ingest(&frame(7, 1));
    rx.close();
    assert_eq!(
        rx.recv().await.map(|(body, _)| body),
        Some([vec![0; 8], vec![1; 8]].concat())
    );
}
