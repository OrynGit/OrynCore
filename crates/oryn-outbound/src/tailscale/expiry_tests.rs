use super::*;

struct TestResolver;
#[async_trait]
impl Resolver for TestResolver {
    async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
        Ok(vec![])
    }
}

fn fixture() -> (Arc<Session>, Arc<Ready>) {
    let config = oryn_config::parse_config("proxies: [{name: T,type: tailscale}]").unwrap();
    let oryn_config::OutboundKind::Tailscale(spec) = config.outbounds[0].kind.clone() else {
        panic!()
    };
    let resolver = Arc::new(TestResolver);
    let datagrams = Arc::new(oryn_udp::UdpFactory);
    let outbound = TailscaleOutbound::new(
        "T".into(),
        spec,
        Arc::new(crate::DirectDialer::new(resolver.clone())),
        resolver,
        datagrams.clone(),
        None,
        true,
    );
    let mut snapshot = Snapshot::default();
    snapshot
        .apply(serde_json::json!({
            "Node": {"Addresses":["100.64.0.1/32"], "MachineAuthorized":true},
            "Peers": [{"ID":2,"Key":ts_keys::NodeKeyPair::random().public.to_string(),
                "Addresses":["100.64.0.2/32"],"MachineAuthorized":true,"HomeDERP":1}]
        }))
        .unwrap();
    let tunnel = Tunnel::with_factory(
        WireGuardSpec {
            peers: vec![derp::wire_peer(&snapshot.peers[0], 0, false, false)],
            private_key: [1; 32],
            address_v4: Some(("100.64.0.1".parse().unwrap(), 32)),
            address_v6: None,
            mtu: 1280,
            keepalive_secs: 0,
            udp: true,
            remote_dns: false,
            dns: vec![],
            amnezia: None,
            refresh_secs: None,
            tcp_buffers: Default::default(),
        },
        datagrams,
    );
    let ready = Arc::new(Ready {
        scope: "expiry-test".into(),
        snapshot,
        tunnel,
        endpoints: vec![Some("127.0.0.1:9".parse().unwrap())],
        accept_routes: false,
        exit_peer: None,
        exit_allow_lan: false,
    });
    (outbound.session.clone(), ready)
}

async fn expires_held_udp(own: bool, keepalive: bool) {
    let (session, mut ready) = fixture();
    let expiry = snapshot::now() + 2;
    if own {
        Arc::get_mut(&mut ready).unwrap().snapshot.expiry = Some(expiry);
    } else {
        Arc::get_mut(&mut ready).unwrap().snapshot.peers[0].expiry = Some(expiry);
    }
    let udp = ready.tunnel.bind_udp(&ready.endpoints).await.unwrap();
    session.state.write().unwrap().ready = Some(ready.clone());
    let control = async {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if keepalive {
                // 相同 KeepAlive 发布快照，不触发 hard change/revoke。
                let mut next = ready.snapshot.clone();
                next.apply(serde_json::json!({"KeepAlive":true})).unwrap();
                session.state.write().unwrap().ready = Some(Arc::new(Ready {
                    scope: ready.scope.clone(),
                    snapshot: next,
                    tunnel: ready.tunnel.clone(),
                    endpoints: ready.endpoints.clone(),
                    accept_routes: false,
                    exit_peer: None,
                    exit_allow_lan: false,
                }));
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    };
    let guard = expiry_guard(Arc::downgrade(&session), control);
    let tcp = async {
        assert!(ready
            .tunnel
            .connect_tcp(&ready.endpoints, "100.64.0.2:80".parse().unwrap())
            .await
            .is_err());
    };
    let receive = async {
        let mut buf = [0; 32];
        assert!(udp.recv_from(&mut buf).await.is_err());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        let (result, (), ()) = tokio::join!(guard, receive, tcp);
        assert!(result.is_err());
    })
    .await
    .expect("expiry must revoke the published tunnel and wake a held UDP receive");
    assert!(session.state.read().unwrap().ready.is_none());
    assert!(ready.tunnel.bind_udp(&ready.endpoints).await.is_err());
}

#[tokio::test]
async fn expiry_ticks_do_not_cancel_partial_control_reads() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (session, ready) = fixture();
    session.state.write().unwrap().ready = Some(ready.clone());
    let (mut reader, mut writer) = tokio::io::duplex(16);
    let control = async {
        let mut frame = [0; 4];
        reader.read_exact(&mut frame).await?;
        assert_eq!(&frame, b"test");
        Ok(())
    };
    let write = async {
        writer.write_all(b"te").await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        writer.write_all(b"st").await.unwrap();
    };
    let (result, ()) = tokio::join!(expiry_guard(Arc::downgrade(&session), control), write);
    result.unwrap();
    assert!(session.state.read().unwrap().ready.is_some());
    session.revoke(None);
}

#[tokio::test]
async fn expiry_without_netmap_revokes_held_udp() {
    expires_held_udp(true, false).await;
}

#[tokio::test]
async fn expiry_despite_keepalive_revokes_held_udp() {
    expires_held_udp(false, true).await;
}
