//! M8：真实 QUIC 静默 UoS 子流不能占住已撤销关联的额度。
use super::*;
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
        tls.alpn_protocols = vec![b"m8-test".to_vec()];
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
        tls.alpn_protocols = vec![b"m8-test".to_vec()];
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

struct ResolverStub;
#[async_trait]
impl Resolver for ResolverStub {
    async fn resolve(&self, _: &str) -> io::Result<Vec<std::net::IpAddr>> {
        unreachable!()
    }
}
fn receiver(id: u64) -> (Arc<Receiver>, mpsc::Receiver<(Vec<u8>, TargetAddr)>) {
    let (tx, rx) = mpsc::channel(8);
    (
        Arc::new(Receiver {
            id,
            tx,
            stop: CancellationToken::new(),
        }),
        rx,
    )
}
fn target() -> TargetAddr {
    TargetAddr::Ip("127.0.0.1:53".parse().unwrap())
}
async fn packet(stream: &mut quinn::SendStream, data: &[u8]) {
    stream
        .write_all(&(data.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(data).await.unwrap();
}

#[tokio::test]
async fn cancelled_uos_releases_all_children_and_quic_credit() {
    let pair = Pair::new(32, 4096).await;
    let hub = Hub::new(pair.client.clone());
    let (old, mut rx) = receiver(1);
    hub.register(7, &old, target()).unwrap();
    let mut streams = Vec::new();
    for _ in 0..32 {
        let mut stream = pair.server.open_uni().await.unwrap();
        stream.write_all(&7u16.to_be_bytes()).await.unwrap();
        packet(&mut stream, b"ready").await;
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        streams.push(stream);
    }
    // 关联撤销但对端保持全部子流打开；部分帧读取同样必须可取消。
    streams[0].write_all(&[0, 20, 1]).await.unwrap();
    let (control, _incoming) = pair.client.open_bi().await.unwrap();
    let association = Packet {
        hub: hub.clone(),
        receiver: old,
        read: AsyncMutex::new(rx),
        write: AsyncMutex::new(Writer {
            control,
            ids: HashMap::new(),
            streams: HashMap::new(),
        }),
        task: tokio::spawn(std::future::pending()),
        uos: true,
        max_datagram: 1200,
        resolver: Arc::new(ResolverStub),
        _slot: crate::slots::Slots::default().acquire(1).unwrap(),
        _keep: None,
    };
    drop(association);
    let (new, mut new_rx) = receiver(2);
    hub.register(7, &new, target()).unwrap();
    for stream in &mut streams {
        assert!(
            tokio::time::timeout(Duration::from_secs(1), stream.stopped())
                .await
                .expect("cancelled association must stop every UoS stream")
                .unwrap()
                .is_some()
        );
    }
    // Quinn 发送句柄收到 STOP 后仍由调用方结束；归还对端流额度需 RESET/FIN。
    for stream in &mut streams {
        let _ = stream.reset(0u32.into());
    }
    let mut fresh = tokio::time::timeout(Duration::from_secs(1), pair.server.open_uni())
        .await
        .expect("QUIC stream credit must be returned")
        .unwrap();
    fresh.write_all(&7u16.to_be_bytes()).await.unwrap();
    packet(&mut fresh, b"new generation").await;
    let (data, _) = tokio::time::timeout(Duration::from_secs(1), new_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, b"new generation");
    assert!(pair.client.close_reason().is_none());
}

#[tokio::test]
async fn unknown_uos_id_can_arrive_before_control_registration() {
    let pair = Pair::new(32, 4096).await;
    let hub = Hub::new(pair.client.clone());
    let mut stream = pair.server.open_uni().await.unwrap();
    stream.write_all(&9u16.to_be_bytes()).await.unwrap();
    packet(&mut stream, b"early").await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    let (recv, mut rx) = receiver(1);
    hub.register(9, &recv, target()).unwrap();
    let (data, _) = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, b"early");
    recv.stop.cancel();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), stream.stopped())
            .await
            .expect("late registration must bind cancellation")
            .unwrap()
            .is_some()
    );
}
