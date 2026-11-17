//! 真实 QUIC uni 额度背压下的认证取消与并发回归。
use super::*;
struct ResolverStub;
#[async_trait]
impl Resolver for ResolverStub {
    async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
        unreachable!()
    }
}
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
        tls.alpn_protocols = vec![b"tuic".to_vec()];
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(1024u32.into())
            .receive_window(32768u32.into())
            .send_window(2048)
            .max_concurrent_uni_streams(0u32.into())
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
fn outbound() -> Arc<TuicOutbound> {
    TuicOutbound::new(
        "test".into(),
        TuicSpec {
            server: TargetAddr::Ip("127.0.0.1:1".parse().unwrap()),
            uuid: [0; 16],
            password: "test-only".into(),
            udp_relay: UdpRelayMode::Native,
            congestion: oryn_config::QuicCongestion::Cubic,
            heartbeat_ms: 1000,
            tls: oryn_config::TlsSpec {
                sni: None,
                skip_cert_verify: false,
                alpn: vec![],
                fingerprint: None,
                client_fingerprint: None,
                reality: None,
                ech: None,
            },
            disable_sni: false,
            max_udp_packet: 1200,
            max_streams: 8,
            udp: true,
            udp_over_stream: None,
            reduce_rtt: false,
        },
        Arc::new(ResolverStub),
        Arc::new(oryn_udp::UdpFactory),
    )
}
#[tokio::test]
async fn cancelled_auth_closes_half_authenticated_connection() {
    let pair = Pair::new().await;
    let out = outbound();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), out.authenticate(&pair.client))
            .await
            .is_err()
    );
    assert!(
        pair.client.close_reason().is_some(),
        "cancelled authentication must close connection"
    );
    assert!(out.authenticate(&pair.client).await.is_err());
}
#[tokio::test]
async fn auth_peer_failure_is_not_cached_as_success() {
    let pair = Pair::new().await;
    let out = outbound();
    let mut first = Box::pin(out.authenticate(&pair.client));
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut first)
        .await
        .is_err());
    pair.server.close(0u32.into(), b"test peer failure");
    assert!(tokio::time::timeout(Duration::from_secs(1), first)
        .await
        .unwrap()
        .is_err());
    assert!(out.authenticate(&pair.client).await.is_err());
}

#[tokio::test]
async fn concurrent_auth_waits_and_sends_once() {
    let pair = Pair::new().await;
    let out = outbound();
    let mut first = Box::pin(out.authenticate(&pair.client));
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut first)
        .await
        .is_err());
    let mut second = Box::pin(out.authenticate(&pair.client));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut second)
            .await
            .is_err(),
        "concurrent caller skipped pending authentication"
    );
    // 仅等待锁的调用取消不能关闭首个调用拥有的连接。
    drop(second);
    assert!(pair.client.close_reason().is_none());
    let second = out.authenticate(&pair.client);
    pair.server.set_max_concurrent_uni_streams(4u32.into());
    first.await.unwrap();
    second.await.unwrap();
    let mut recv = pair.server.accept_uni().await.unwrap();
    let data = recv.read_to_end(50).await.unwrap();
    assert_eq!(data.len(), 50);
    assert_eq!(&data[..2], &[5, 0]);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), pair.server.accept_uni())
            .await
            .is_err()
    );
}
