use super::*;
use std::sync::Arc;

fn config() -> oryn_config::RuntimeConfig {
    let mut config =
        crate::proxy_providers::compile("rules: ['MATCH,DIRECT']", None, None).unwrap();
    config.dns.public_ip_url = None;
    config.geoip.auto_update = false;
    config.geoip.asn_url = None;
    config
}

async fn pair() -> (TcpStream, TcpStream, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, peer) = listener.accept().await.unwrap();
    (client, server, peer)
}

#[test]
fn admission_actual_factory_unpolled_overload_reload_and_recovery() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(async {
        let ctx = EngineCtx::new(
            oryn_netstack::LwipStack::new(1500).unwrap(),
            config(),
            Default::default(),
            Arc::new(crate::stats::Stats::default()),
        );
        let mut operations = Vec::new();
        let mut clients = Vec::new();
        for index in 0..32 {
            let (client, server, peer) = pair().await;
            clients.push(client);
            operations.push(
                admit(
                    ctx.clone(),
                    server,
                    peer,
                    if index % 2 == 0 {
                        ListenerKind::Http
                    } else {
                        ListenerKind::Socks
                    },
                )
                .unwrap(),
            );
        }
        // 真实入口 future 尚未 poll 已收费；配置代际不能重置旧连接额度。
        ctx.apply_config(config());
        assert!(ctx.admission.try_tcp().is_none());
        let dns: Vec<_> = (0..8).map(|_| ctx.admission.try_dns().unwrap()).collect();
        assert!(ctx.admission.try_dns().is_none());
        let (mut client, server, peer) = pair().await;
        assert!(admit(ctx.clone(), server, peer, ListenerKind::Http).is_none());
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        // try_write 是 best effort：可只关闭，若写入则只能是 503。
        assert!(response.is_empty() || response.starts_with(b"HTTP/1.1 503"));
        drop(operations);
        drop(clients);
        drop(dns);
        let (client, server, peer) = pair().await;
        let operation = admit(ctx.clone(), server, peer, ListenerKind::Socks).unwrap();
        drop(client); // 协商错误路径也必须退账。
        operation.await;
        // 重开额度全部可再取回；未完成握手的连接受 establishing 档（修后 32）约束。
        let recovered: Vec<_> = (0..32).map(|_| ctx.admission.try_tcp().unwrap()).collect();
        assert!(ctx.admission.try_tcp().is_none());
        drop(recovered);
    }));
}

#[test]
fn admission_256_established_local_connections_keep_active_only() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(async {
        let ctx = EngineCtx::new(
            oryn_netstack::LwipStack::new(1500).unwrap(),
            config(),
            Default::default(),
            Arc::new(crate::stats::Stats::default()),
        );
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut clients = Vec::new();
        let mut remotes = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..256 {
            let (mut client, server, peer) = pair().await;
            tasks.push(tokio::task::spawn_local(
                admit(ctx.clone(), server, peer, ListenerKind::Http).unwrap(),
            ));
            client
                .write_all(
                    format!(
                        "CONNECT {} HTTP/1.1\r\nHost: localhost\r\n\r\n",
                        remote.local_addr().unwrap()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            remotes.push(
                tokio::time::timeout(std::time::Duration::from_secs(2), remote.accept())
                    .await
                    .expect("outbound accept timeout")
                    .unwrap()
                    .0,
            );
            let mut response = [0; 39];
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                client.read_exact(&mut response),
            )
            .await
            .expect("CONNECT response timeout")
            .unwrap();
            assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
            clients.push(client);
        }
        assert!(ctx.admission.try_tcp().is_none());
        // 已建立连接继续双向转发；第257条拒绝不影响既有relay。
        clients[0].write_all(b"hello").await.unwrap();
        let mut data = [0; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            remotes[0].read_exact(&mut data),
        )
        .await
        .expect("relay timeout")
        .unwrap();
        assert_eq!(&data, b"hello");
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        assert!(ctx.admission.try_tcp().is_some());
    }));
}
