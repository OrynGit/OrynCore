//! DNS Engine 测试：全部上游都是本机替身（UDP、TCP、DoT、DoH、DoH3、DoQ），证书为自签名。

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::{Buf, Bytes};
use oryn_config::{parse_config, FakeIpFilter, RuntimeConfig};
use oryn_outbound::{build_outbounds, BuildContext, HealthStore};
use oryn_router::{GeoIp, Router};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::*;
use crate::message::{response_for, Message, RData, Record, TYPE_A, TYPE_PTR};

type Log = Arc<Mutex<Vec<Vec<u8>>>>;

/// 按域名回答：`nx.*` 返回 NXDOMAIN，`blocked.example` 返回 0.0.0.0 与 1.1.1.1，
/// 其余返回 `ip`；AAAA 返回空结果。
fn answer(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let m = Message::parse(query).unwrap();
    let q = &m.questions[0];
    let name = q.name.to_ascii_lowercase();
    if name.starts_with("nx.") {
        return response_for(&m, 3, vec![]).serialize();
    }
    let ips: Vec<Ipv4Addr> = if name == "blocked.example" {
        vec![Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(1, 1, 1, 1)]
    } else {
        vec![ip]
    };
    let answers = if q.qtype == TYPE_A {
        ips.into_iter()
            .map(|a| Record {
                name: q.name.clone(),
                rtype: TYPE_A,
                class: 1,
                ttl: 60,
                data: RData::A(a),
            })
            .collect()
    } else {
        vec![]
    };
    response_for(&m, 0, answers).serialize()
}

async fn udp_server(ip: Ipv4Addr) -> (SocketAddr, Log) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let log: Log = Default::default();
    let l = log.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            l.lock().unwrap().push(buf[..n].to_vec());
            let _ = sock.send_to(&answer(&buf[..n], ip), from).await;
        }
    });
    (addr, log)
}

/// 一个关闭的 UDP 端口（查询会超时或被拒绝）。
async fn dead_udp() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.local_addr().unwrap()
}

async fn tcp_server(ip: Ipv4Addr) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                while let Ok(len) = s.read_u16().await {
                    let mut q = vec![0u8; len as usize];
                    s.read_exact(&mut q).await.unwrap();
                    let r = answer(&q, ip);
                    s.write_all(&(r.len() as u16).to_be_bytes()).await.unwrap();
                    s.write_all(&r).await.unwrap();
                }
            });
        }
    });
    addr
}

fn tls_config(alpn: &[&[u8]]) -> rustls::ServerConfig {
    let cert =
        rcgen::generate_simple_self_signed(vec!["dns.test".into(), "127.0.0.1".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key)
    .unwrap();
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    c
}

async fn dot_server(ip: Ipv4Addr) -> SocketAddr {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config(&[])));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(s).await else {
                    return;
                };
                while let Ok(len) = s.read_u16().await {
                    let mut q = vec![0u8; len as usize];
                    s.read_exact(&mut q).await.unwrap();
                    let r = answer(&q, ip);
                    s.write_all(&(r.len() as u16).to_be_bytes()).await.unwrap();
                    s.write_all(&r).await.unwrap();
                    s.flush().await.unwrap();
                }
            });
        }
    });
    addr
}

/// DoH：`h2` 为真时只协商 HTTP/2，否则只协商 HTTP/1.1。
async fn doh_server(ip: Ipv4Addr, h2: bool) -> SocketAddr {
    let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config(alpn)));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(s).await else {
                    return;
                };
                if h2 {
                    let mut conn = ::h2::server::handshake(tls).await.unwrap();
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        tokio::spawn(async move {
                            assert_eq!(req.uri().path(), "/dns-query");
                            let mut body = req.into_body();
                            let mut q = Vec::new();
                            while let Some(Ok(chunk)) = body.data().await {
                                let _ = body.flow_control().release_capacity(chunk.len());
                                q.extend_from_slice(&chunk);
                            }
                            assert_eq!(&q[..2], &[0, 0], "DoH 查询的 ID 为 0");
                            let resp = http::Response::builder().status(200).body(()).unwrap();
                            let mut send = respond.send_response(resp, false).unwrap();
                            send.send_data(Bytes::from(answer(&q, ip)), true).unwrap();
                        });
                    }
                } else {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head_end, len) = loop {
                        let n = tls.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
                            let len: usize = head
                                .lines()
                                .find_map(|l| {
                                    l.strip_prefix("content-length:")
                                        .map(|v| v.trim().parse().unwrap())
                                })
                                .unwrap();
                            break (i + 4, len);
                        }
                    };
                    while buf.len() < head_end + len {
                        let n = tls.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let r = answer(&buf[head_end..head_end + len], ip);
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", r.len());
                    tls.write_all(head.as_bytes()).await.unwrap();
                    tls.write_all(&r).await.unwrap();
                    tls.shutdown().await.ok();
                }
            });
        }
    });
    addr
}

fn quic_server_config(alpn: &[u8]) -> quinn::ServerConfig {
    let tls = tls_config(&[alpn]);
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    quinn::ServerConfig::with_crypto(Arc::new(crypto))
}

async fn doq_server(ip: Ipv4Addr) -> SocketAddr {
    let endpoint =
        quinn::Endpoint::server(quic_server_config(b"doq"), "127.0.0.1:0".parse().unwrap())
            .unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let data = recv.read_to_end(65537).await.unwrap();
                        let q = &data[2..];
                        assert_eq!(&q[..2], &[0, 0], "DoQ 查询的 ID 必须为 0");
                        let r = answer(q, ip);
                        let mut out = (r.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&r);
                        send.write_all(&out).await.unwrap();
                        send.finish().unwrap();
                        let _ = send.stopped().await;
                    });
                }
            });
        }
    });
    addr
}

async fn doh3_server(ip: Ipv4Addr) -> SocketAddr {
    let endpoint =
        quinn::Endpoint::server(quic_server_config(b"h3"), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let mut h3c: ::h3::server::Connection<h3_quinn::Connection, Bytes> =
                    ::h3::server::Connection::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();
                while let Ok(Some(resolver)) = h3c.accept().await {
                    tokio::spawn(async move {
                        let (_req, mut stream) = resolver.resolve_request().await.unwrap();
                        let mut q = Vec::new();
                        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                            while chunk.has_remaining() {
                                let c = chunk.chunk();
                                q.extend_from_slice(c);
                                let n = c.len();
                                chunk.advance(n);
                            }
                        }
                        stream
                            .send_response(http::Response::builder().status(200).body(()).unwrap())
                            .await
                            .unwrap();
                        stream.send_data(Bytes::from(answer(&q, ip))).await.unwrap();
                        stream.finish().await.unwrap();
                    });
                }
            });
        }
    });
    addr
}

fn engine(yaml: &str) -> (Arc<DnsEngine>, RuntimeConfig) {
    let mut cfg = parse_config(yaml).unwrap();
    // 旧的上游协议测试显式把所有域名列入过滤名单；Fake-IP 行为由专门测试覆盖。
    cfg.dns.fake_ip_filter = vec![FakeIpFilter::Glob("*".into())];
    let store = Arc::new(RuleSetStore::new(&cfg.providers));
    for (i, p) in cfg.providers.iter().enumerate() {
        if let oryn_config::ProviderSource::Inline { payload } = &p.source {
            let (set, _) = oryn_router::build_inline(payload, p.behavior);
            store.slot(i).unwrap().set(set, SystemTime::now());
        }
    }
    let e = Arc::new(DnsEngine::new(cfg.dns.clone(), cfg.hosts.clone(), store));
    (e, cfg)
}

/// 建立 Router 与出站，并交给 DNS Engine（respect-rules 需要）。
fn attach_routing(e: &Arc<DnsEngine>, cfg: &RuntimeConfig) -> Arc<Routing> {
    let store = Arc::new(RuleSetStore::new(&cfg.providers));
    let router = Router::new(cfg, store, Arc::new(GeoIp::default()));
    let ctx = BuildContext {
        proxy_resolver: Arc::new(ProxyServerResolver(e.clone())),
        direct_resolver: Arc::new(DirectTargetResolver(e.clone())),
        health: Arc::new(HealthStore::default()),
        selections: Default::default(),
        mieru_sessions: 64,
    };
    let routing = Arc::new(Routing {
        outbounds: build_outbounds(cfg, &ctx),
        router,
    });
    e.set_routing(Arc::downgrade(&routing));
    routing
}

fn src() -> SocketAddr {
    "198.18.0.1:5353".parse().unwrap()
}

async fn query(e: &DnsEngine, name: &str, qtype: u16) -> (Message, QueryOutcome) {
    let q = wire::build_query(0x1234, name, qtype);
    let (resp, out) = e.handle_query(&q, src()).await;
    let m = Message::parse(&resp).unwrap();
    assert_eq!(m.id, 0x1234);
    (m, out)
}

fn ip_of(m: &Message) -> Option<std::net::IpAddr> {
    m.answer_ips().first().copied()
}

#[tokio::test]
async fn udp_cache_mapping_and_forward_rules() {
    let (main, main_log) = udp_server(Ipv4Addr::new(10, 0, 0, 1)).await;
    let (special, _) = udp_server(Ipv4Addr::new(10, 0, 0, 2)).await;
    let (boot, _) = udp_server(Ipv4Addr::new(10, 0, 0, 3)).await;
    let (group2, _) = udp_server(Ipv4Addr::new(10, 0, 0, 4)).await;
    let dead = dead_udp().await;
    let yaml = format!(
        r#"
rule-providers:
  lan: {{type: inline, behavior: domain, payload: ['+.corp.example']}}
dns:
  default-nameserver: ['{boot}']
  nameserver: ['{main}']
  upstreams:
    Group: ['{dead}', '{group2}']
  nameserver-policy:
    '+.policy.example': '{special}'
  forward-rules:
    - DOMAIN-SUFFIX,special.example,{special}
    - DOMAIN-KEYWORD,grp,Group
    - DOMAIN-REGEX,^ads?\.,reject
    - RULE-SET,lan,bootstrap
    - SSID,Home*,{special}
    - CELLULAR,NR,Group
"#
    );
    let (e, _) = engine(&yaml);

    let (m, out) = query(&e, "www.example.com", TYPE_A).await;
    assert_eq!(ip_of(&m), Some("10.0.0.1".parse().unwrap()));
    assert_eq!(out.upstream.as_deref(), Some(main.to_string().as_str()));
    assert_eq!(out.via.as_deref(), Some("DIRECT"), "未设置 Routing 时直连");
    assert_eq!(
        e.lookup_domain(&"10.0.0.1".parse().unwrap()).as_deref(),
        Some("www.example.com")
    );
    let (_, out) = query(&e, "WWW.example.com", TYPE_A).await;
    assert!(out.cached);
    assert_eq!(main_log.lock().unwrap().len(), 1);

    assert_eq!(
        ip_of(&query(&e, "a.special.example", TYPE_A).await.0),
        Some("10.0.0.2".parse().unwrap())
    );
    assert_eq!(
        ip_of(&query(&e, "x.policy.example", TYPE_A).await.0),
        Some("10.0.0.2".parse().unwrap())
    );
    // 上游组：第一个服务器不可用时按顺序使用下一个
    assert_eq!(
        ip_of(&query(&e, "mygrp.example", TYPE_A).await.0),
        Some("10.0.0.4".parse().unwrap())
    );
    // reject：默认 REFUSED
    let (m, out) = query(&e, "ads.example", TYPE_A).await;
    assert_eq!((m.rcode(), out.upstream.as_deref()), (5, Some("reject")));
    // 代理规则集 → 引导 DNS
    assert_eq!(
        ip_of(&query(&e, "a.corp.example", TYPE_A).await.0),
        Some("10.0.0.3".parse().unwrap())
    );
    // NXDOMAIN 透传
    assert_eq!(query(&e, "nx.example", TYPE_A).await.0.rcode(), 3);

    // 按网络匹配
    e.clear_cache();
    e.set_network(NetworkInfo {
        kind: NetworkKind::Wifi,
        ssid: Some("Home-5G".into()),
        ..Default::default()
    });
    assert_eq!(
        ip_of(&query(&e, "www.example.com", TYPE_A).await.0),
        Some("10.0.0.2".parse().unwrap())
    );
    e.clear_cache();
    e.set_network(NetworkInfo {
        kind: NetworkKind::Cellular,
        radio: Some("NR".into()),
        ..Default::default()
    });
    assert_eq!(
        ip_of(&query(&e, "www.example.com", TYPE_A).await.0),
        Some("10.0.0.4".parse().unwrap())
    );
    e.clear_cache();
    e.set_network(NetworkInfo {
        kind: NetworkKind::Cellular,
        radio: Some("LTE".into()),
        ..Default::default()
    });
    assert_eq!(
        ip_of(&query(&e, "www.example.com", TYPE_A).await.0),
        Some("10.0.0.1".parse().unwrap())
    );
}

#[tokio::test]
async fn fake_ip_answers_and_reverse_mapping() {
    let (upstream, _) = udp_server(Ipv4Addr::new(10, 0, 0, 9)).await;
    let yaml = format!(
        "dns:\n  nameserver: ['{upstream}']\n  fake-ip-filter: ['real.example']\n  fake-ip-filter-mode: blacklist\n"
    );
    let cfg = parse_config(&yaml).unwrap();
    let store = Arc::new(RuleSetStore::new(&cfg.providers));
    let e = DnsEngine::new(cfg.dns.clone(), cfg.hosts.clone(), store);

    let (a, out) = query(&e, "fake.example", TYPE_A).await;
    let fake = match ip_of(&a).unwrap() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("expected IPv4 Fake-IP"),
    };
    assert_eq!(fake.octets()[0..2], [198, 18]);
    assert_eq!(out.upstream.as_deref(), Some("fake-ip"));
    let (aaaa, out) = query(&e, "fake.example", crate::wire::TYPE_AAAA).await;
    assert!(aaaa.answers.is_empty());
    assert_eq!(out.upstream.as_deref(), Some("fake-ip"));
    let (https, _) = query(&e, "fake.example", crate::wire::TYPE_HTTPS).await;
    assert!(https.answers.is_empty());
    assert_eq!(e.fake_ip_answers(), 3);
    assert_eq!(e.fake_ip_len(), 1);
    let missing = "198.18.9.9".parse().unwrap();
    assert!(e.lookup_fake_domain(&missing).is_none());
    e.remember_fake_ip(&missing, "Recovered.Example.");
    assert_eq!(e.lookup_fake_domain(&missing).as_deref(), Some("recovered.example"));

    let (ptr, out) = query(&e, &reverse_name(fake), TYPE_PTR).await;
    assert_eq!(out.upstream.as_deref(), Some("fake-ip"));
    assert!(
        matches!(ptr.answers.first().map(|r| &r.data), Some(RData::Name(d)) if d == "fake.example")
    );

    let (real, out) = query(&e, "real.example", TYPE_A).await;
    assert_eq!(ip_of(&real), Some("10.0.0.9".parse().unwrap()));
    assert_eq!(out.upstream.as_deref(), Some(upstream.to_string().as_str()));
}

#[tokio::test]
async fn hosts_ipv6_blocking_ecs_and_reject_response() {
    let (main, log) = udp_server(Ipv4Addr::new(10, 0, 0, 1)).await;
    let yaml = format!(
        r#"
hosts:
  'router.lan': 192.168.1.1
  '+.local.test': ['127.0.0.1', '::1']
  'alias.test': www.example.com
dns:
  nameserver: ['{main}']
  ipv6: false
  blocked-ips: [0.0.0.0/32]
  reject-response: nxdomain
  forward-rules:
    - DOMAIN,bad.example,reject
"#
    );
    let (e, _) = engine(&yaml);
    let (m, out) = query(&e, "router.lan", TYPE_A).await;
    assert_eq!(
        (ip_of(&m), out.upstream.as_deref()),
        (Some("192.168.1.1".parse().unwrap()), Some("hosts"))
    );
    assert_eq!(
        e.lookup_domain(&"192.168.1.1".parse().unwrap()).as_deref(),
        Some("router.lan")
    );
    assert_eq!(
        ip_of(&query(&e, "a.local.test", TYPE_A).await.0),
        Some("127.0.0.1".parse().unwrap())
    );
    // 别名：解析 www.example.com 后以原名称应答
    let (m, _) = query(&e, "alias.test", TYPE_A).await;
    assert_eq!(ip_of(&m), Some("10.0.0.1".parse().unwrap()));
    assert_eq!(m.answers[0].name, "alias.test");
    // ipv6: false
    let (m, out) = query(&e, "www.example.com", TYPE_AAAA).await;
    assert!(m.answers.is_empty() && m.rcode() == 0);
    assert_eq!(out.upstream.as_deref(), Some("ipv6-disabled"));
    // IP 屏蔽
    let (m, _) = query(&e, "blocked.example", TYPE_A).await;
    assert_eq!(
        m.answer_ips(),
        vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()]
    );
    // reject-response: nxdomain
    assert_eq!(query(&e, "bad.example", TYPE_A).await.0.rcode(), 3);

    // ECS：公网 IP 子网附加在上游查询中
    e.set_public_ecs(oryn_config::IpCidr::parse("203.0.113.0/24"));
    query(&e, "ecs.example", TYPE_A).await;
    let last = log.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        Message::parse(&last).unwrap().ecs(),
        oryn_config::IpCidr::parse("203.0.113.0/24")
    );
}

#[tokio::test]
async fn encrypted_transports() {
    let ip = Ipv4Addr::new(10, 9, 9, 9);
    let tcp = tcp_server(ip).await;
    let dot = dot_server(ip).await;
    let doh = doh_server(ip, true).await;
    let doh1 = doh_server(ip, false).await;
    let doq = doq_server(ip).await;
    let doh3 = doh3_server(ip).await;
    let (boot, _) = udp_server(Ipv4Addr::new(127, 0, 0, 1)).await;
    let yaml = format!(
        r#"
dns:
  default-nameserver: ['{boot}']
  skip-cert-verify: true
  upstreams:
    tcp: ['tcp://{tcp}']
    dot: ['tls://dns.test:{p_dot}']
    doh: ['https://127.0.0.1:{p_doh}/dns-query']
    doh1: ['https://dns.test:{p_doh1}']
    doq: ['quic://dns.test:{p_doq}']
    doh3: ['h3://dns.test:{p_doh3}/dns-query']
    doh3param: ['https://dns.test:{p_doh3}#h3=true']
  forward-rules:
    - DOMAIN-SUFFIX,tcp.test,tcp
    - DOMAIN-SUFFIX,dot.test,dot
    - DOMAIN-SUFFIX,doh.test,doh
    - DOMAIN-SUFFIX,doh1.test,doh1
    - DOMAIN-SUFFIX,doq.test,doq
    - DOMAIN-SUFFIX,doh3.test,doh3
    - DOMAIN-SUFFIX,param.test,doh3param
"#,
        p_dot = dot.port(),
        p_doh = doh.port(),
        p_doh1 = doh1.port(),
        p_doq = doq.port(),
        p_doh3 = doh3.port(),
    );
    let (e, _) = engine(&yaml);
    for name in [
        "a.tcp.test",
        "a.dot.test",
        "a.doh.test",
        "a.doh1.test",
        "a.doq.test",
        "a.doh3.test",
        "a.param.test",
    ] {
        let (m, out) = query(&e, name, TYPE_A).await;
        assert_eq!(ip_of(&m), Some(ip.into()), "{name}: {out:?}");
        // 第二个查询复用连接
        let (m, _) = query(&e, &format!("b.{name}"), TYPE_A).await;
        assert_eq!(ip_of(&m), Some(ip.into()), "b.{name}");
    }
}

/// 引导 DNS 可以是 IP 形式的 DoT / DoH / DoH3 / DoQ：用它解析加密上游的域名。
#[tokio::test]
async fn encrypted_bootstrap_servers_resolve_upstream_domains() {
    let ip = Ipv4Addr::new(10, 9, 9, 9);
    // 上游服务器：域名 dns.test 由引导 DNS 解析为 127.0.0.1。
    let upstream = dot_server(ip).await;
    let dot = dot_server(Ipv4Addr::new(127, 0, 0, 1)).await;
    let doh = doh_server(Ipv4Addr::new(127, 0, 0, 1), true).await;
    let doq = doq_server(Ipv4Addr::new(127, 0, 0, 1)).await;
    let doh3 = doh3_server(Ipv4Addr::new(127, 0, 0, 1)).await;
    for (label, boot) in [
        ("dot", format!("tls://{dot}")),
        ("doh", format!("https://{doh}/dns-query")),
        ("doq", format!("quic://{doq}")),
        ("doh3", format!("h3://{doh3}/dns-query")),
    ] {
        let yaml = format!(
            r#"
dns:
  default-nameserver: ['{boot}']
  skip-cert-verify: true
  nameserver: ['tls://dns.test:{p}']
"#,
            p = upstream.port(),
        );
        let (e, _) = engine(&yaml);
        let (m, out) = query(&e, "www.example.com", TYPE_A).await;
        assert_eq!(ip_of(&m), Some(ip.into()), "{label}: {out:?}");
        let (m, _) = query(&e, "b.example.com", TYPE_A).await;
        assert_eq!(ip_of(&m), Some(ip.into()), "{label} 复用连接");
    }
}

/// SOCKS5 替身：只支持 CONNECT，把连接转发到真实目标。
async fn socks_forwarder() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut h = [0u8; 2];
                s.read_exact(&mut h).await.unwrap();
                let mut m = vec![0u8; h[1] as usize];
                s.read_exact(&mut m).await.unwrap();
                s.write_all(&[5, 0]).await.unwrap();
                let mut req = [0u8; 4];
                s.read_exact(&mut req).await.unwrap();
                let mut b = [0u8; 6];
                s.read_exact(&mut b).await.unwrap();
                let target =
                    SocketAddr::from(([b[0], b[1], b[2], b[3]], u16::from_be_bytes([b[4], b[5]])));
                let mut up = tokio::net::TcpStream::connect(target).await.unwrap();
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn respect_rules_and_proxy_server_resolution() {
    let tcp_upstream = tcp_server(Ipv4Addr::new(10, 7, 7, 7)).await;
    let (direct_ns, direct_log) = udp_server(Ipv4Addr::new(10, 1, 1, 1)).await;
    let (proxy_ns, proxy_log) = udp_server(Ipv4Addr::new(10, 2, 2, 2)).await;
    let (boot, boot_log) = udp_server(Ipv4Addr::new(10, 3, 3, 3)).await;
    let socks = socks_forwarder().await;
    let yaml = format!(
        r#"
proxies:
  - {{name: P, type: socks5, server: 127.0.0.1, port: {sp}}}
rules:
  - DOMAIN-SUFFIX,blocked.test,REJECT
  - DOMAIN-SUFFIX,proxied.test,P
  - MATCH,DIRECT
dns:
  default-nameserver: ['{boot}']
  nameserver: ['{direct_ns}', 'tcp://{tcp_upstream}']
  proxy-server-nameserver: ['{proxy_ns}']
"#,
        sp = socks.port()
    );
    let (e, cfg) = engine(&yaml);
    let _routing = attach_routing(&e, &cfg);

    // 分流为 REJECT 的域名：DNS 查询同样被拒绝
    let (m, out) = query(&e, "x.blocked.test", TYPE_A).await;
    assert_eq!((m.rcode(), out.upstream.as_deref()), (5, Some("reject")));
    // 分流为 P：经 SOCKS5 以 TCP 访问上游（UDP 服务器经代理改用 TCP，第一个 UDP 服务器因此失败，回退到 TCP 服务器）
    let (m, out) = query(&e, "x.proxied.test", TYPE_A).await;
    assert_eq!(ip_of(&m), Some("10.7.7.7".parse().unwrap()), "{out:?}");
    assert_eq!(out.via.as_deref(), Some("P"));
    assert!(direct_log.lock().unwrap().is_empty());
    // 其余直连；两个上游并发查询，取先到的应答。
    let (m, out) = query(&e, "plain.test", TYPE_A).await;
    assert_eq!(out.via.as_deref(), Some("DIRECT"));
    assert!(
        [Some("10.1.1.1".parse().unwrap()), Some("10.7.7.7".parse().unwrap())].contains(&ip_of(&m)),
        "{out:?}"
    );

    // 代理服务器域名：强制使用代理域名服务器
    let ips = e.resolve_proxy_server("node.example").await.unwrap();
    assert_eq!(ips, vec![std::net::IpAddr::from([10, 2, 2, 2])]);
    // A 与 AAAA 各查一次，都只发往代理域名服务器。
    let a_queries = proxy_log
        .lock()
        .unwrap()
        .iter()
        .filter(|q| wire::parse_question(q).is_some_and(|q| q.qtype == TYPE_A))
        .count();
    assert_eq!(a_queries, 1);
    assert!(boot_log.lock().unwrap().is_empty());
    // DIRECT 目标：完整流程
    let ips = e.resolve_direct_target("site.example").await.unwrap();
    assert!(
        ips == vec![std::net::IpAddr::from([10, 1, 1, 1])]
            || ips == vec![std::net::IpAddr::from([10, 7, 7, 7])],
        "{ips:?}"
    );
}

/// 上游并发查询：第一个服务器不应答时，第二个服务器的应答立即返回，不等第一个超时。
#[tokio::test]
async fn upstreams_race_instead_of_waiting_for_timeouts() {
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let (fast, _) = udp_server(Ipv4Addr::new(10, 4, 4, 4)).await;
    let yaml = format!(
        "dns:\n  nameserver: ['{}', '{fast}']\n",
        silent.local_addr().unwrap()
    );
    let (e, _) = engine(&yaml);
    let started = std::time::Instant::now();
    let (m, out) = query(&e, "race.test", TYPE_A).await;
    assert_eq!(ip_of(&m), Some("10.4.4.4".parse().unwrap()), "{out:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    drop(silent);
}

/// 同一问题的并发查询只发一次上游。
#[tokio::test]
async fn concurrent_identical_queries_share_one_upstream_request() {
    let (ns, log) = udp_server(Ipv4Addr::new(10, 5, 5, 5)).await;
    let (e, _) = engine(&format!("dns:\n  nameserver: ['{ns}']\n"));
    let (a, b) = tokio::join!(query(&e, "same.test", TYPE_A), query(&e, "same.test", TYPE_A));
    assert_eq!(ip_of(&a.0), Some("10.5.5.5".parse().unwrap()));
    assert_eq!(ip_of(&b.0), Some("10.5.5.5".parse().unwrap()));
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn proxy_server_without_dedicated_nameserver_uses_forward_rules_then_bootstrap() {
    let (special, _) = udp_server(Ipv4Addr::new(10, 5, 5, 5)).await;
    let (boot, _) = udp_server(Ipv4Addr::new(10, 3, 3, 3)).await;
    let (main, main_log) = udp_server(Ipv4Addr::new(10, 1, 1, 1)).await;
    let yaml = format!(
        "dns:\n  default-nameserver: ['{boot}']\n  nameserver: ['{main}']\n  forward-rules:\n    - DOMAIN-SUFFIX,fw.example,{special}\n"
    );
    let (e, _) = engine(&yaml);
    assert_eq!(
        e.resolve_proxy_server("a.fw.example").await.unwrap(),
        vec![std::net::IpAddr::from([10, 5, 5, 5])]
    );
    assert_eq!(
        e.resolve_proxy_server("b.other.example").await.unwrap(),
        vec![std::net::IpAddr::from([10, 3, 3, 3])]
    );
    assert!(main_log.lock().unwrap().is_empty(), "不使用默认上游");
    assert_eq!(
        e.resolve_proxy_server("1.2.3.4").await.unwrap(),
        vec![std::net::IpAddr::from([1, 2, 3, 4])]
    );
}

#[tokio::test]
async fn tailscale_dns_disabled_never_falls_back_to_public_or_hosts() {
    let (dns,cfg)=engine("proxies: [{name: T,type: tailscale}]\nhosts: {'peer.test.ts.net': 203.0.113.1}\ndns: {nameserver-policy: {'+.test.ts.net': 'tailscale://T'}}\nrules: ['MATCH,DIRECT']");
    let _routing = attach_routing(&dns, &cfg);
    let query = wire::build_query(1, "peer.test.ts.net", 1);
    let (response, outcome) = dns.handle_query(&query, src()).await;
    assert_eq!(
        wire::parse_answer(&response).unwrap().rcode,
        wire::RCODE_SERVFAIL
    );
    assert_eq!(outcome.upstream.as_deref(), Some("tailscale://T"));
}

#[tokio::test]
async fn ipv6_target_settings_keep_proxy_resolution_independent() {
    let (e, _) = engine(
        r#"
hosts:
  dual.example: [192.0.2.1, '2001:db8::1']
  v6.example: '2001:db8::2'
  v4.example: 192.0.2.2
dns:
  fake-ip-filter: ['+.example']
"#,
    );
    let v4: IpAddr = "192.0.2.1".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(
        e.resolve_direct_target("dual.example").await.unwrap(),
        [v4, v6]
    );
    e.set_target_ipv6(true, true);
    assert_eq!(
        e.resolve_direct_target("dual.example").await.unwrap(),
        [v6, v4]
    );
    assert_eq!(
        e.resolve_proxy_server("dual.example").await.unwrap(),
        [v4, v6]
    );
    assert_eq!(
        e.resolve_direct_target("v4.example").await.unwrap(),
        ["192.0.2.2".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        e.resolve_direct_target("v6.example").await.unwrap(),
        ["2001:db8::2".parse::<IpAddr>().unwrap()]
    );
    e.set_target_ipv6(false, true);
    assert_eq!(e.resolve_direct_target("dual.example").await.unwrap(), [v4]);
    assert!(e.resolve_direct_target("v6.example").await.is_err());
    assert!(e.resolve_direct_target("[2001:db8::1]").await.is_err());
    assert_eq!(
        e.resolve_proxy_server("v6.example").await.unwrap(),
        ["2001:db8::2".parse::<IpAddr>().unwrap()]
    );
    let (answer, outcome) = query(&e, "dual.example", TYPE_AAAA).await;
    assert!(answer.answers.is_empty());
    assert_eq!(outcome.upstream.as_deref(), Some("ipv6-disabled"));
    e.set_target_ipv6(true, false);
    assert_eq!(
        e.resolve_direct_target("dual.example").await.unwrap(),
        [v4, v6]
    );
}

/// A 查询 SERVFAIL、AAAA 返回地址的上游，统计收到的 A / AAAA 查询数。
async fn v4_failing_server() -> (SocketAddr, Arc<Mutex<(usize, usize)>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let counts = Arc::new(Mutex::new((0, 0)));
    let count = counts.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            let m = Message::parse(&buf[..n]).unwrap();
            let q = &m.questions[0];
            let resp = if q.qtype == TYPE_AAAA {
                count.lock().unwrap().1 += 1;
                let record = Record {
                    name: q.name.clone(),
                    rtype: TYPE_AAAA,
                    class: 1,
                    ttl: 60,
                    data: RData::Aaaa("2001:db8::1".parse().unwrap()),
                };
                response_for(&m, 0, vec![record])
            } else {
                count.lock().unwrap().0 += 1;
                response_for(&m, wire::RCODE_SERVFAIL, vec![])
            };
            let _ = sock.send_to(&resp.serialize(), from).await;
        }
    });
    (addr, counts)
}

#[tokio::test]
async fn failed_a_lookup_without_local_ipv6_reports_dns_error() {
    let (server, counts) = v4_failing_server().await;
    let (e, _) = engine(&format!(
        "dns: {{nameserver: ['{server}'], fake-ip-filter: ['+.example']}}\nrules: ['MATCH,DIRECT']"
    ));
    let v6: IpAddr = "2001:db8::1".parse().unwrap();

    // 未知是否支持 IPv6：仍用 AAAA 结果，但 A 失败时不缓存，下次重新查询 A
    assert_eq!(e.resolve_direct_target("a.example").await.unwrap(), [v6]);
    assert_eq!(e.resolve_direct_target("a.example").await.unwrap(), [v6]);
    let (a, _) = *counts.lock().unwrap();
    assert!(a >= 2, "A queries: {a}");
    let aaaa_before = counts.lock().unwrap().1;

    // 物理网络没有 IPv6：不查 AAAA，报告 DNS 失败而不是交出无法拨通的 IPv6 地址
    e.set_network(NetworkInfo {
        ipv6: Some(false),
        ..Default::default()
    });
    let err = e.resolve_direct_target("b.example").await.unwrap_err();
    assert!(
        err.to_string().contains("cannot resolve b.example: DNS lookup failed"),
        "{err}"
    );
    assert_eq!(counts.lock().unwrap().1, aaaa_before);
}

#[tokio::test]
async fn ipv6_preferred_tcp_falls_back_to_ipv4() {
    use oryn_outbound::{Dialer, DirectDialer};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (e, _) = engine("hosts: {dual.example: ['::1', '127.0.0.1']}");
    e.set_target_ipv6(true, true);
    let dialer = DirectDialer::new(Arc::new(DirectTargetResolver(e)));
    let mut client = tokio::time::timeout(
        Duration::from_secs(3),
        dialer.dial_tcp(&TargetAddr::Domain("dual.example".into(), port)),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    client.write_all(b"ipv4 fallback").await.unwrap();
    let mut bytes = [0; 13];
    server.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ipv4 fallback");
}

#[tokio::test]
async fn ipv6_proxy_preference_is_global_and_independent() {
    let (e, mut cfg) = engine("hosts: {dual.example: ['192.0.2.1', '2001:db8::1'], v4.example: 192.0.2.1, v6.example: '2001:db8::1'}");
    let v4: IpAddr = "192.0.2.1".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(
        e.resolve_proxy_server("dual.example").await.unwrap(),
        [v4, v6]
    );
    e.set_target_ipv6(false, false);
    e.set_proxy_prefer_ipv6(true);
    assert_eq!(
        e.resolve_proxy_server("dual.example").await.unwrap(),
        [v6, v4]
    );
    assert_eq!(e.resolve_direct_target("dual.example").await.unwrap(), [v4]);
    assert_eq!(e.resolve_proxy_server("v4.example").await.unwrap(), [v4]);
    assert_eq!(e.resolve_proxy_server("v6.example").await.unwrap(), [v6]);
    assert_eq!(e.resolve_proxy_server("192.0.2.1").await.unwrap(), [v4]);
    assert_eq!(e.resolve_proxy_server("[2001:db8::1]").await.unwrap(), [v6]);
    e.apply(
        cfg.dns.clone(),
        cfg.hosts.clone(),
        Arc::new(RuleSetStore::new(&[])),
    );
    assert_eq!(
        e.resolve_proxy_server("dual.example").await.unwrap(),
        [v6, v4]
    );
    e.set_proxy_prefer_ipv6(false);
    assert_eq!(
        e.resolve_proxy_server("dual.example").await.unwrap(),
        [v4, v6]
    );
    e.set_proxy_prefer_ipv6(true);
    cfg.dns.ipv6 = false;
    e.apply(cfg.dns, cfg.hosts, Arc::new(RuleSetStore::new(&[])));
    assert_eq!(e.resolve_proxy_server("dual.example").await.unwrap(), [v4]);
}

#[tokio::test]
async fn ipv6_proxy_tcp_falls_back_to_ipv4() {
    use oryn_outbound::{Dialer, DirectDialer};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (e, _) = engine("hosts: {proxy.example: ['::1', '127.0.0.1']}");
    e.set_target_ipv6(false, false);
    e.set_proxy_prefer_ipv6(true);
    let dialer = DirectDialer::new(Arc::new(ProxyServerResolver(e)));
    let mut client = tokio::time::timeout(
        Duration::from_secs(3),
        dialer.dial_tcp(&TargetAddr::Domain("proxy.example".into(), port)),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    client.write_all(b"fallback").await.unwrap();
    let mut bytes = [0; 8];
    server.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"fallback");
}

#[tokio::test]
async fn real_ip_domains_override_filters_and_keep_existing_mappings() {
    let (upstream, _) = udp_server(Ipv4Addr::new(10, 0, 0, 9)).await;
    let cfg = parse_config(&format!("dns:\n  nameserver: ['{upstream}']\n  fake-ip-filter: []\n")).unwrap();
    let store = Arc::new(RuleSetStore::new(&cfg.providers));
    let e = DnsEngine::new(cfg.dns.clone(), cfg.hosts.clone(), store.clone());
    let (old, _) = query(&e, "real.example", TYPE_A).await;
    let fake = ip_of(&old).unwrap();
    assert!(e.is_fake_ip(&fake));
    e.set_real_ip_domains(&["REAL.example.".into(), "*.wild.example".into(), "?chaoxing".into()]).unwrap();
    for name in ["real.example", "a.wild.example", "a.b.wild.example", "xchaoxing"] {
        let (answer, outcome) = query(&e, name, TYPE_A).await;
        assert_eq!(ip_of(&answer), Some("10.0.0.9".parse().unwrap()), "{name}");
        assert_ne!(outcome.upstream.as_deref(), Some("fake-ip"));
    }
    for name in ["sub.real.example", "wild.example", "chaoxing", "xxchaoxing"] {
        let (_, outcome) = query(&e, name, TYPE_A).await;
        assert_eq!(outcome.upstream.as_deref(), Some("fake-ip"), "{name}");
    }
    assert_eq!(e.lookup_fake_domain(&fake).as_deref(), Some("real.example"));
    assert!(e.set_real_ip_domains(&["https://bad".into()]).is_err());
    assert!(!e.should_fake(&e.rt(), "real.example"));
    let mut next = cfg.dns.clone();
    next.fake_ip_filter_mode = FakeIpFilterMode::Whitelist;
    next.fake_ip_filter = vec![FakeIpFilter::Glob("*".into())];
    e.apply(next, cfg.hosts.clone(), store);
    assert_eq!(ip_of(&query(&e, "real.example", TYPE_A).await.0), Some("10.0.0.9".parse().unwrap()));
    assert_eq!(query(&e, "other.example", TYPE_A).await.1.upstream.as_deref(), Some("fake-ip"));
    e.set_real_ip_domains(&[]).unwrap();
    assert_eq!(query(&e, "real.example", TYPE_A).await.1.upstream.as_deref(), Some("fake-ip"));
}

#[tokio::test]
async fn real_ip_domains_preserve_ipv6_hosts_and_dns_rejection() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut bytes = [0u8; 1500];
        loop {
            let (n, from) = socket.recv_from(&mut bytes).await.unwrap();
            let msg = Message::parse(&bytes[..n]).unwrap();
            let q = &msg.questions[0];
            let response = if q.qtype == TYPE_AAAA {
                response_for(&msg, 0, vec![Record { name: q.name.clone(), rtype: TYPE_AAAA, class: 1, ttl: 30, data: RData::Aaaa("2001:db8::1".parse().unwrap()) }]).serialize()
            } else { answer(&bytes[..n], Ipv4Addr::new(10,0,0,9)) };
            socket.send_to(&response, from).await.unwrap();
        }
    });
    let cfg = parse_config(&format!("hosts:\n  host.example: 192.0.2.3\ndns:\n  ipv6: true\n  nameserver: ['{addr}']\n  fake-ip-filter: []\n  forward-rules: ['DOMAIN,blocked.example,REJECT']\n")).unwrap();
    let e = DnsEngine::new(cfg.dns.clone(), cfg.hosts.clone(), Arc::new(RuleSetStore::new(&cfg.providers)));
    e.set_real_ip_domains(&["*".into()]).unwrap();
    assert_eq!(ip_of(&query(&e,"host.example",TYPE_A).await.0), Some("192.0.2.3".parse().unwrap()));
    assert_eq!(query(&e,"blocked.example",TYPE_A).await.1.upstream.as_deref(), Some("reject"));
    assert_eq!(ip_of(&query(&e,"real.example",TYPE_AAAA).await.0), Some("2001:db8::1".parse().unwrap()));
    for qtype in [wire::TYPE_HTTPS, wire::TYPE_SVCB] {
        let (_, outcome) = query(&e,"real.example",qtype).await;
        assert_eq!(outcome.upstream.as_deref(), Some(addr.to_string().as_str()));
    }
    e.set_target_ipv6(false, false);
    assert!(query(&e,"real.example",TYPE_AAAA).await.0.answers.is_empty());
    server.abort();
    let _ = server.await;
}
