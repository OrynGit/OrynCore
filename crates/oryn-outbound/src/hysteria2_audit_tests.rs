use super::*;

struct NoDns;
#[async_trait]
impl Resolver for NoDns {
    async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
        panic!("rate test must not resolve or open a connection");
    }
}
fn outbound() -> Arc<Hysteria2Outbound> {
    let config = oryn_config::parse_config(
        "proxies:\n  - {name: test, type: hysteria2, server: 127.0.0.1, port: 443, password: fake-password, up: '8 Mbps'}",
    ).unwrap();
    let spec = config
        .outbounds
        .iter()
        .find_map(|o| match &o.kind {
            oryn_config::OutboundKind::Hysteria2(spec) => Some(spec.clone()),
            _ => None,
        })
        .unwrap();
    Hysteria2Outbound::new(
        "test".into(),
        spec,
        Arc::new(NoDns),
        Arc::new(crate::DirectDialer::new(Arc::new(NoDns))),
        Arc::new(oryn_udp::UdpFactory),
    )
}

// 本机真实 h3 认证；每个阶段固定响应，记录实际连接/认证数。
struct AuthPeer {
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<()>,
    value: Arc<Mutex<&'static str>>,
    accepted: Arc<AtomicU64>,
    authed: Arc<AtomicU64>,
    control:
        Option<tokio::sync::mpsc::Receiver<(quinn::Connection, tokio::sync::oneshot::Sender<u16>)>>,
}
impl Drop for AuthPeer {
    fn drop(&mut self) {
        self.task.abort();
        self.endpoint.close(0u32.into(), b"test finished");
    }
}
impl AuthPeer {
    fn new() -> Self {
        Self::controlled(false)
    }
    fn controlled(controlled: bool) -> Self {
        Self::with_uni_limit(controlled, None)
    }
    fn with_uni_limit(controlled: bool, uni: Option<u32>) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
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
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        if let Some(uni) = uni {
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_uni_streams(uni.into());
            config.transport_config(Arc::new(transport));
        }
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let value = Arc::new(Mutex::new("auto"));
        let accepted = Arc::new(AtomicU64::new(0));
        let authed = Arc::new(AtomicU64::new(0));
        let (ep, v, a, n) = (
            endpoint.clone(),
            value.clone(),
            accepted.clone(),
            authed.clone(),
        );
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            while let Some(incoming) = ep.accept().await {
                let conn = incoming.await.unwrap();
                a.fetch_add(1, Ordering::Relaxed);
                let (v, n, tx) = (v.clone(), n.clone(), tx.clone());
                tasks.spawn(async move {
                    let mut h3 = h3::server::Connection::<_, bytes::Bytes>::new(
                        h3_quinn::Connection::new(conn.clone()),
                    )
                    .await
                    .unwrap();
                    while let Ok(Some(resolver)) = h3.accept().await {
                        let (request, mut stream) = resolver.resolve_request().await.unwrap();
                        assert_eq!(request.uri().path(), "/auth");
                        n.fetch_add(1, Ordering::Relaxed);
                        let value = *v.lock().unwrap();
                        let status = if controlled {
                            let (release, wait) = tokio::sync::oneshot::channel();
                            tx.send((conn.clone(), release)).await.unwrap();
                            match wait.await {
                                Ok(status) => status,
                                Err(_) => break,
                            }
                        } else {
                            233
                        };
                        if status == 0 {
                            stream.stop_stream(0x102u64.into());
                            continue;
                        }
                        stream
                            .send_response(
                                http::Response::builder()
                                    .status(status)
                                    .header("hysteria-cc-rx", value)
                                    .header("hysteria-udp", "true")
                                    .body(())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        let _ = stream.finish().await;
                    }
                });
            }
        });
        Self {
            endpoint,
            task,
            value,
            accepted,
            authed,
            control: controlled.then_some(rx),
        }
    }
    fn outbound(&self, upload: bool) -> Arc<Hysteria2Outbound> {
        let mut spec = outbound().spec.clone();
        spec.server = TargetAddr::Ip(self.endpoint.local_addr().unwrap());
        spec.tls.skip_cert_verify = true;
        if !upload {
            spec.up_bps = None;
        }
        Hysteria2Outbound::new(
            "test".into(),
            spec,
            Arc::new(NoDns),
            Arc::new(crate::DirectDialer::new(Arc::new(NoDns))),
            Arc::new(oryn_udp::UdpFactory),
        )
    }
}

#[tokio::test]
async fn real_h3_cancel_during_new_closes_connection() {
    let peer = AuthPeer::with_uni_limit(false, Some(0));
    let out = peer.outbound(false);
    let (ip, port, name) = out.peer().await.unwrap();
    let conn = out.quic.connection(ip, &name, port).await.unwrap();
    let mut auth = Box::pin(out.authenticate(&conn));
    assert!(tokio::time::timeout(Duration::from_millis(100), &mut auth)
        .await
        .is_err());
    assert!(out.auth_driver.lock().unwrap().is_none());
    drop(auth);
    assert!(
        conn.close_reason().is_some(),
        "cancelled h3 new must close connection"
    );
}

// 控制真实服务端响应，而非用 pending 替身代替 h3 IO。
#[tokio::test]
async fn real_h3_auth_cancel_and_errors_roll_back() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for failure in [None, Some(403), Some(0)] {
            let mut peer = AuthPeer::controlled(true);
            let out = peer.outbound(false);
            let owner = out.clone();
            let a = tokio::spawn(async move { owner.ready().await });
            let (server_a, release) = peer.control.as_mut().unwrap().recv().await.unwrap();

            let driver = out.auth_driver.lock().unwrap().clone().unwrap();
            assert!(!driver.is_finished());
            // 排队者取消不能关闭当前认证拥有者的连接。
            let owner = out.clone();
            let mut waiter = Box::pin(owner.ready());
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(waiter.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            drop(waiter);
            assert!(server_a.close_reason().is_none());

            match failure {
                None => {
                    a.abort();
                    assert!(a.await.unwrap_err().is_cancelled());
                }
                Some(status) => {
                    release.send(status).unwrap();
                    assert!(a.await.unwrap().is_err());
                }
            }
            tokio::time::timeout(Duration::from_secs(2), server_a.closed())
                .await
                .expect("failed/cancelled auth must close its QUIC connection");
            tokio::time::timeout(Duration::from_secs(2), async {
                while !driver.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("old auth driver must exit");
            assert!(out.auth.lock().unwrap().is_none());

            let owner = out.clone();
            let b = tokio::spawn(async move { owner.ready().await });
            let (server_b, release) = peer.control.as_mut().unwrap().recv().await.unwrap();
            assert_ne!(server_a.stable_id(), server_b.stable_id());
            release.send(233).unwrap();
            let (client_b, udp) = b.await.unwrap().unwrap();
            assert!(udp);
            assert!(client_b.close_reason().is_none());
            assert_eq!(peer.accepted.load(Ordering::Relaxed), 2);
            assert_eq!(
                out.ready().await.unwrap().0.stable_id(),
                client_b.stable_id()
            );
        }
    })
    .await
    .expect("bounded auth rollback test");
}

async fn check_mode(
    out: &Hysteria2Outbound,
    peer: &AuthPeer,
    bbr: bool,
    count: u64,
) -> quinn::Connection {
    let (conn, udp) = tokio::time::timeout(Duration::from_secs(5), out.ready())
        .await
        .unwrap()
        .unwrap();
    assert!(udp);
    assert_eq!(
        conn.congestion_state()
            .into_any()
            .is::<quinn::congestion::Bbr>(),
        bbr,
        "actual congestion controller, response={:?}",
        peer.value.lock().unwrap()
    );
    let (reused, _) = out.ready().await.unwrap();
    assert_eq!(conn.stable_id(), reused.stable_id());
    assert_eq!(
        peer.accepted.load(Ordering::Relaxed),
        count,
        "connection count"
    );
    assert_eq!(
        peer.authed.load(Ordering::Relaxed),
        count,
        "auth count (cached on reuse)"
    );
    conn
}

#[tokio::test]
async fn real_h3_auto_disconnect_number_reselects_congestion() {
    let peer = AuthPeer::new();
    let out = peer.outbound(true);
    let auto = check_mode(&out, &peer, true, 2).await;
    auto.close(0u32.into(), b"simulate disconnect");
    *peer.value.lock().unwrap() = "100000";
    let number = check_mode(&out, &peer, false, 4).await;
    assert_ne!(auto.stable_id(), number.stable_id());
    assert_eq!(out.brutal.as_ref().unwrap().load(Ordering::Relaxed), 100000);
    number.close(0u32.into(), b"simulate disconnect");
    *peer.value.lock().unwrap() = "auto";
    let auto = check_mode(&out, &peer, true, 6).await;
    auto.close(0u32.into(), b"simulate disconnect");
    *peer.value.lock().unwrap() = "AUTO";
    let _ = check_mode(&out, &peer, false, 8).await;
    assert_eq!(
        out.brutal.as_ref().unwrap().load(Ordering::Relaxed),
        out.spec.up_bps.unwrap()
    );
}

#[tokio::test]
async fn real_h3_without_upload_stays_bbr() {
    let peer = AuthPeer::new();
    let out = peer.outbound(false);
    let auto = check_mode(&out, &peer, true, 1).await;
    auto.close(0u32.into(), b"simulate disconnect");
    *peer.value.lock().unwrap() = "100000";
    let _ = check_mode(&out, &peer, true, 2).await;
}

struct Pair {
    endpoints: [quinn::Endpoint; 2],
    client: quinn::Connection,
    _server: quinn::Connection,
}
impl Drop for Pair {
    fn drop(&mut self) {
        for endpoint in &self.endpoints {
            endpoint.close(0u32.into(), b"test finished");
        }
    }
}
impl Pair {
    async fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(oryn_tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
            )
            .unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(oryn_tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        ));
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let connect = client_endpoint
            .connect(server_endpoint.local_addr().unwrap(), "localhost")
            .unwrap();
        let (client, server) = tokio::join!(connect, async {
            server_endpoint.accept().await.unwrap().await
        });
        Self {
            endpoints: [client_endpoint, server_endpoint],
            client: client.unwrap(),
            _server: server.unwrap(),
        }
    }
}

fn fragment(session: u32, index: u8) -> Vec<u8> {
    let mut frame = session.to_be_bytes().to_vec();
    frame.extend_from_slice(&[0, 1, index, 2]); // packet=1, total=2
    let addr = b"127.0.0.1:53";
    put_varint(&mut frame, addr.len() as u64);
    frame.extend_from_slice(addr);
    frame.extend_from_slice(b"12345678");
    frame
}

#[tokio::test]
async fn unknown_sessions_cannot_consume_reassembly_budget() {
    let pair = Pair::new().await;
    let inbox = Arc::new(Inbox::with_bytes(4, 64));
    let hub = UdpHub {
        conn: pair.client.clone(),
        sessions: Mutex::new(HashMap::from([(1, inbox.clone())])),
        reassembly: Mutex::new(Reassembly::new(8, 4, 16, FRAG_WAIT)),
    };
    // 未知会话的半包会填满载荷预算；合法会话首片因此无法进入。
    hub.ingest(&fragment(2, 0));
    hub.ingest(&fragment(1, 0));
    hub.ingest(&fragment(1, 1));
    let received = tokio::time::timeout(Duration::from_millis(50), inbox.recv()).await;
    assert!(
        received.is_ok(),
        "unknown session consumed live session reassembly budget"
    );
    assert_eq!(received.unwrap().unwrap().0, b"1234567812345678");
}

#[test]
fn udp_auth_boolean_matches_go_parse_bool() {
    for (value, expected) in [
        (None, false),
        (Some("false"), false),
        (Some("0"), false),
        (Some("False"), false),
        (Some("FALSE"), false),
        (Some("f"), false),
        (Some("F"), false),
        (Some("invalid"), false),
        (Some("TrUe"), false),
        (Some("true"), true),
        (Some("1"), true),
        (Some("True"), true),
        (Some("TRUE"), true),
        (Some("t"), true),
        (Some("T"), true),
    ] {
        let mut headers = http::HeaderMap::new();
        if let Some(value) = value {
            headers.insert("hysteria-udp", value.parse().unwrap());
        }
        assert_eq!(auth_udp(&headers), expected, "header={value:?}");
    }
}

#[test]
fn reconnect_recomputes_brutal_rate_from_config() {
    let out = outbound();
    let configured = out.spec.up_bps.unwrap();
    let rate = out.brutal.as_ref().unwrap();
    for server in [configured / 10, configured, configured * 2, 0] {
        // 每次先模拟旧连接协商到低速，再接收新连接速率。
        out.apply_server_rate(&(configured / 100).to_string());
        out.apply_server_rate(&server.to_string());
        let expected = if server == 0 {
            configured
        } else {
            server.min(configured)
        };
        assert_eq!(rate.load(Ordering::Relaxed), expected, "server={server}");
    }
    for header in ["", "invalid", "18446744073709551616", "AUTO", "Auto"] {
        out.apply_server_rate("1");
        out.apply_server_rate(header);
        assert_eq!(rate.load(Ordering::Relaxed), configured, "header={header}");
    }
}
