//! 真实 Quinn 控制流认证取消回归；TLS 配置沿用 lifecycle pair。
use super::*;

struct NoDns;
#[async_trait]
impl Resolver for NoDns {
    async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
        panic!("literal server address needs no DNS")
    }
}

fn server() -> quinn::Endpoint {
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
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap()
}

async fn hello(conn: &quinn::Connection) -> (quinn::SendStream, quinn::RecvStream) {
    let (send, mut recv) = conn.accept_bi().await.unwrap();
    assert_eq!(
        recv.id().index(),
        0,
        "hello must use the first control stream"
    );
    let mut bytes = [0; 19];
    recv.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes[0], PROTOCOL_VERSION);
    assert_eq!(&bytes[17..], &[0, 0]);
    (send, recv)
}

#[tokio::test]
async fn cancelled_auth_closes_connection_and_retry_uses_first_stream() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let endpoint = server();
        let outbound = HysteriaOutbound::new(
            "test".into(),
            HysteriaSpec {
                server: TargetAddr::Ip(endpoint.local_addr().unwrap()),
                protocol: "udp".into(),
                ports: None,
                auth: vec![],
                up_bps: 1_000_000,
                down_bps: 1_000_000,
                obfs: None,
                tls: oryn_config::TlsSpec {
                    skip_cert_verify: true,
                    alpn: vec!["h3".into()],
                    sni: Some("localhost".into()),
                    fingerprint: None,
                    client_fingerprint: None,
                    reality: None,
                    ech: None,
                },
                hop_min_secs: 10,
                hop_max_secs: 20,
                udp: false,
            },
            Arc::new(NoDns),
            Arc::new(oryn_udp::UdpFactory),
        );
        let mut first = Box::pin(outbound.ready());
        let peer = tokio::select! {
            result = &mut first => panic!("unexpected ready: {}", result.is_ok()),
            incoming = endpoint.accept() => incoming.unwrap().await.unwrap(),
        };
        let (_send, _recv) = tokio::select! {
            result = &mut first => panic!("unexpected ready: {}", result.is_ok()),
            streams = hello(&peer) => streams,
        };
        // 等锁的调用取消不得关闭仍由 first 认证的连接。
        let mut waiter = Box::pin(outbound.ready());
        assert!(futures_util::poll!(&mut waiter).is_pending());
        drop(waiter);
        assert!(peer.close_reason().is_none());
        drop(first);
        tokio::time::timeout(Duration::from_secs(1), peer.closed())
            .await
            .expect("cancelled authentication must close its QUIC connection");
        let retry = outbound.ready();
        let accept = async {
            let peer = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, recv) = hello(&peer).await;
            let mut reply = vec![1];
            reply.extend_from_slice(&1_000_000u64.to_be_bytes());
            reply.extend_from_slice(&1_000_000u64.to_be_bytes());
            reply.extend_from_slice(&0u16.to_be_bytes());
            send.write_all(&reply).await.unwrap();
            (peer, send, recv)
        };
        let (ready, (peer, _send, _recv)) = tokio::join!(retry, accept);
        let (conn, hub, _) = ready.unwrap();
        assert!(conn.close_reason().is_none());
        let (cached, cached_hub, _) = outbound.ready().await.unwrap();
        assert_eq!(cached.stable_id(), conn.stable_id());
        assert!(Arc::ptr_eq(&hub, &cached_hub));
        assert!(peer.close_reason().is_none());
    })
    .await
    .unwrap();
}
