//! 热重载与部分资源热更新集成测试（全本机 loopback 替身，不访问公网）。

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use oryn_netstack::packet::{
    self, Parsed, TcpSegment, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::Engine;

const WAIT: Duration = Duration::from_secs(5);

struct TestDir(PathBuf);
impl TestDir {
    fn new(prefix: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("oryn-{prefix}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Tun {
    rx: Receiver<Vec<u8>>,
}
impl Tun {
    fn recv_until<T>(&self, mut f: impl FnMut(&[u8]) -> Option<T>) -> T {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .expect("timed out waiting for tunnel output");
            let pkt = self
                .rx
                .recv_timeout(left)
                .expect("timed out waiting for tunnel output");
            if let Some(v) = f(&pkt) {
                return v;
            }
        }
    }

    fn udp_from(&self, from: SocketAddr, to: SocketAddr) -> Vec<u8> {
        self.recv_until(|p| match packet::parse(p) {
            Parsed::Udp { src, dst, payload } if src == from && dst == to => Some(payload.to_vec()),
            _ => None,
        })
    }
}

fn start_engine(config: &str, options: &str) -> (Engine, Tun) {
    let (tx, rx) = channel();
    let config = if config.contains("fake-ip-filter:") {
        config.to_string()
    } else if let Some(pos) = config.find("dns:\n") {
        let at = pos + "dns:\n".len();
        format!(
            "{}  fake-ip-filter: ['*']\n{}",
            &config[..at],
            &config[at..]
        )
    } else {
        format!("{config}\ndns:\n  fake-ip-filter: ['*']\n")
    };
    let mut engine = Engine::new(config.as_bytes(), options.as_bytes()).unwrap();
    engine.set_output(Box::new(move |pkts: &[Vec<u8>]| {
        for p in pkts {
            let _ = tx.send(p.clone());
        }
    }));
    engine.start().unwrap();
    (engine, Tun { rx })
}

fn input(engine: &Engine, pkt: Vec<u8>) {
    engine.input(vec![pkt]).unwrap();
}

fn cmd(engine: &Engine, req: Value) -> Value {
    let raw = serde_json::to_vec(&req).unwrap();
    engine.command(&raw)
}

fn wait_for(engine: &Engine, req: Value, mut ok: impl FnMut(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let v = cmd(engine, req.clone());
        if ok(&v) {
            return v;
        }
        assert!(Instant::now() < deadline, "condition not met: {v}");
        std::thread::sleep(Duration::from_millis(30));
    }
}

struct RawTcp {
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
}
impl RawTcp {
    fn seg_for_me(&self, pkt: &[u8]) -> Option<TcpSegment> {
        packet::parse_tcp(pkt).filter(|s| s.src == self.dst && s.dst == self.src)
    }

    fn connect(engine: &Engine, tun: &Tun, src: &str, dst: &str) -> RawTcp {
        let mut c = RawTcp {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            seq: 1000,
            ack: 0,
        };
        input(
            engine,
            packet::build_tcp(c.src, c.dst, c.seq, 0, TCP_FLAG_SYN, 65535, &[]).unwrap(),
        );
        let synack = tun.recv_until(|p| {
            c.seg_for_me(p).filter(|s| {
                s.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) == (TCP_FLAG_SYN | TCP_FLAG_ACK)
            })
        });
        assert_eq!(synack.ack, 1001);
        c.seq = 1001;
        c.ack = synack.seq.wrapping_add(1);
        input(
            engine,
            packet::build_tcp(c.src, c.dst, c.seq, c.ack, TCP_FLAG_ACK, 65535, &[]).unwrap(),
        );
        c
    }

    fn send(&mut self, engine: &Engine, data: &[u8]) {
        for chunk in data.chunks(1200) {
            input(
                engine,
                packet::build_tcp(
                    self.src,
                    self.dst,
                    self.seq,
                    self.ack,
                    TCP_FLAG_ACK | TCP_FLAG_PSH,
                    65535,
                    chunk,
                )
                .unwrap(),
            );
            self.seq = self.seq.wrapping_add(chunk.len() as u32);
        }
    }

    fn read_exact(&mut self, engine: &Engine, tun: &Tun, n: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < n {
            let seg = tun.recv_until(|p| {
                self.seg_for_me(p)
                    .filter(|s| !s.payload.is_empty() || s.flags & TCP_FLAG_RST != 0)
            });
            assert_eq!(seg.flags & TCP_FLAG_RST, 0, "connection was reset");
            if seg.seq == self.ack {
                self.ack = self.ack.wrapping_add(seg.payload.len() as u32);
                got.extend_from_slice(&seg.payload);
            }
            input(
                engine,
                packet::build_tcp(
                    self.src,
                    self.dst,
                    self.seq,
                    self.ack,
                    TCP_FLAG_ACK,
                    65535,
                    &[],
                )
                .unwrap(),
            );
        }
        got
    }

    fn expect_reset(&self, tun: &Tun) {
        tun.recv_until(|p| self.seg_for_me(p).filter(|s| s.flags & TCP_FLAG_RST != 0));
    }

    fn close(&mut self, engine: &Engine, tun: &Tun) {
        input(
            engine,
            packet::build_tcp(
                self.src,
                self.dst,
                self.seq,
                self.ack,
                TCP_FLAG_ACK | TCP_FLAG_FIN,
                65535,
                &[],
            )
            .unwrap(),
        );
        self.seq = self.seq.wrapping_add(1);
        let fin = tun.recv_until(|p| self.seg_for_me(p).filter(|s| s.flags & TCP_FLAG_FIN != 0));
        self.ack = fin.seq.wrapping_add(fin.payload.len() as u32 + 1);
        input(
            engine,
            packet::build_tcp(
                self.src,
                self.dst,
                self.seq,
                self.ack,
                TCP_FLAG_ACK,
                65535,
                &[],
            )
            .unwrap(),
        );
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn socks_server(echo: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let log: Arc<Mutex<Vec<String>>> = Default::default();
    let lg = log.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let lg = lg.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; head[1] as usize];
                if s.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if s.write_all(&[5, 0]).await.is_err() {
                    return;
                }
                let mut req = [0u8; 4];
                if s.read_exact(&mut req).await.is_err() {
                    return;
                }
                let (target, port) = match req[3] {
                    1 => {
                        let mut b = [0u8; 6];
                        if s.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        (
                            Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
                            u16::from_be_bytes([b[4], b[5]]),
                        )
                    }
                    3 => {
                        let Ok(len) = s.read_u8().await else { return };
                        let mut b = vec![0u8; len as usize + 2];
                        if s.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        (
                            String::from_utf8_lossy(&b[..len as usize]).into_owned(),
                            u16::from_be_bytes([b[len as usize], b[len as usize + 1]]),
                        )
                    }
                    4 => {
                        let mut b = [0u8; 18];
                        if s.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        let ip: [u8; 16] = b[..16].try_into().unwrap();
                        (
                            format!("[{}]", std::net::Ipv6Addr::from(ip)),
                            u16::from_be_bytes([b[16], b[17]]),
                        )
                    }
                    _ => return,
                };
                lg.lock().unwrap().push(format!("{target}:{port}"));
                if req[1] == 3 {
                    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let p = relay.local_addr().unwrap().port().to_be_bytes();
                    if s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, p[0], p[1]])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    tokio::spawn(async move {
                        let mut buf = [0u8; 2048];
                        while let Ok((n, from)) = relay.recv_from(&mut buf).await {
                            let _ = relay.send_to(&buf[..n], from).await;
                        }
                    });
                    let mut b = [0u8; 16];
                    while matches!(s.read(&mut b).await, Ok(n) if n > 0) {}
                    return;
                }
                if s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .is_err()
                {
                    return;
                }
                let Ok(mut up) = TcpStream::connect(echo).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    (addr, log)
}

async fn dns_server(reply_ip: [u8; 4]) -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            counter.fetch_add(1, Ordering::Relaxed);
            let query = &buf[..n];
            let q = oryn_dns::wire::parse_question(query).unwrap();
            let mut out = query[..q.end].to_vec();
            out[2] = 0x81;
            out[3] = 0x80;
            out[6..8].copy_from_slice(&1u16.to_be_bytes());
            out[8..12].fill(0);
            out.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            out.extend_from_slice(&reply_ip);
            let _ = sock.send_to(&out, from).await;
        }
    });
    (addr, hits)
}

fn dns_query_tun(engine: &Engine, tun: &Tun, id: u16, name: &str) -> Vec<[u8; 4]> {
    let app: SocketAddr = "198.18.0.1:5533".parse().unwrap();
    let dns: SocketAddr = "198.18.0.2:53".parse().unwrap();
    let q = oryn_dns::wire::build_query(id, name, oryn_dns::wire::TYPE_A);
    input(engine, packet::build_udp(app, dns, &q).unwrap());
    let resp = tun.recv_until(|p| match packet::parse(p) {
        Parsed::Udp { src, dst, payload }
            if src == dns && dst == app && oryn_dns::wire::id_of(payload) == Some(id) =>
        {
            Some(payload.to_vec())
        }
        _ => None,
    });
    oryn_dns::wire::parse_answer(&resp)
        .unwrap()
        .ips
        .into_iter()
        .filter_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(v4.octets()),
            std::net::IpAddr::V6(_) => None,
        })
        .collect()
}

fn build_mmdb_country(networks: &[([u8; 4], u8, &str)]) -> Vec<u8> {
    #[derive(Clone, Copy)]
    enum Rec {
        Empty,
        Node(usize),
        Data(usize),
    }
    let mut data = Vec::new();
    let mut offsets: HashMap<String, usize> = HashMap::new();
    let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty, Rec::Empty]];
    for (ip, prefix, code) in networks {
        let off = *offsets.entry(code.to_string()).or_insert_with(|| {
            let off = data.len();
            data.push(0xE1);
            data.push(0x40 | 7);
            data.extend_from_slice(b"country");
            data.push(0xE1);
            data.push(0x40 | 8);
            data.extend_from_slice(b"iso_code");
            data.push(0x40 | code.len() as u8);
            data.extend_from_slice(code.as_bytes());
            off
        });
        let bits = u32::from_be_bytes(*ip);
        let mut node = 0usize;
        for depth in 0..*prefix {
            let bit = ((bits >> (31 - depth)) & 1) as usize;
            if depth + 1 == *prefix {
                nodes[node][bit] = Rec::Data(off);
            } else {
                node = match nodes[node][bit] {
                    Rec::Node(n) => n,
                    _ => {
                        nodes.push([Rec::Empty, Rec::Empty]);
                        let n = nodes.len() - 1;
                        nodes[node][bit] = Rec::Node(n);
                        n
                    }
                };
            }
        }
    }
    let count = nodes.len();
    let mut out = Vec::new();
    for n in &nodes {
        for r in n {
            let v = match *r {
                Rec::Empty => count,
                Rec::Node(i) => i,
                Rec::Data(off) => count + 16 + off,
            } as u32;
            out.extend_from_slice(&v.to_be_bytes()[1..]);
        }
    }
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&data);
    out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
    let key = |out: &mut Vec<u8>, k: &str| {
        out.push(0x40 | k.len() as u8);
        out.extend_from_slice(k.as_bytes());
    };
    out.push(0xE0 | 9);
    key(&mut out, "binary_format_major_version");
    out.extend_from_slice(&[0xA1, 2]);
    key(&mut out, "binary_format_minor_version");
    out.push(0xA0);
    key(&mut out, "build_epoch");
    out.extend_from_slice(&[0x08, 0x02, 0, 0, 0, 0, 0x65, 0, 0, 0]);
    key(&mut out, "database_type");
    key(&mut out, "Test-Country");
    key(&mut out, "description");
    out.push(0xE0);
    key(&mut out, "ip_version");
    out.extend_from_slice(&[0xA1, 4]);
    key(&mut out, "languages");
    out.extend_from_slice(&[0x00, 0x04]);
    key(&mut out, "node_count");
    out.push(0xC4);
    out.extend_from_slice(&(count as u32).to_be_bytes());
    key(&mut out, "record_size");
    out.extend_from_slice(&[0xA1, 24]);
    out
}

#[test]
fn established_tcp_and_udp_survive_reload_and_partial_updates() {
    let _serial = crate::udp::performance_survey::STACK_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let rt = runtime();
    let echo = rt.block_on(tcp_echo());
    let (socks1, log1) = rt.block_on(socks_server(echo));
    let (socks2, log2) = rt.block_on(socks_server(echo));

    let dir = TestDir::new("hr-live-flows");
    let sub_yaml = |port: u16| {
        format!(
            "proxies:\n  - {{name: P1, type: socks5, server: 127.0.0.1, port: {port}, udp: true}}\n"
        )
    };
    std::fs::write(dir.0.join("sub.yaml"), sub_yaml(socks1.port())).unwrap();

    let cfg = r#"
proxy-providers:
  sub: {type: file, path: sub.yaml}
rule-providers:
  dyn: {type: inline, behavior: ipcidr, payload: []}
proxy-groups:
  - {name: G, type: select, use: [sub]}
rules:
  - RULE-SET,dyn,REJECT
  - MATCH,G
"#;
    let opts = json!({"data_dir": dir.0, "local_proxy": {"enabled": false}, "maxmind": null})
        .to_string();
    let (mut engine, tun) = start_engine(cfg, &opts);
    wait_for(&engine, json!({"cmd": "groups"}), |v| {
        v["groups"][0]["now"] == "P1"
    });

    // 建立长期 TCP 与 UDP 会话（走 P1 -> socks1）
    let mut tcp_live = RawTcp::connect(&engine, &tun, "198.18.0.1:41001", "203.0.113.50:8080");
    tcp_live.send(&engine, b"before-tcp");
    assert_eq!(tcp_live.read_exact(&engine, &tun, 10), b"before-tcp");

    let udp_app: SocketAddr = "198.18.0.1:51001".parse().unwrap();
    let udp_dst: SocketAddr = "203.0.113.50:9090".parse().unwrap();
    input(&engine, packet::build_udp(udp_app, udp_dst, b"before-udp").unwrap());
    assert_eq!(tun.udp_from(udp_dst, udp_app), b"before-udp");
    assert_eq!(log1.lock().unwrap().len(), 2);

    // 1. 推送 proxy-provider 把 P1 切换到 socks2：旧流不断，新流走 socks2
    let push_proxy = cmd(
        &engine,
        json!({
            "cmd": "update_proxy_provider",
            "name": "sub",
            "content": sub_yaml(socks2.port()),
        }),
    );
    assert_eq!(push_proxy["ok"], true, "{push_proxy}");
    tcp_live.send(&engine, b"after-proxy");
    assert_eq!(tcp_live.read_exact(&engine, &tun, 11), b"after-proxy");
    input(&engine, packet::build_udp(udp_app, udp_dst, b"after-proxy-udp").unwrap());
    assert_eq!(tun.udp_from(udp_dst, udp_app), b"after-proxy-udp");
    assert!(log2.lock().unwrap().is_empty());

    let mut tcp_new = RawTcp::connect(&engine, &tun, "198.18.0.1:41002", "203.0.113.50:8080");
    tcp_new.send(&engine, b"via-socks2");
    assert_eq!(tcp_new.read_exact(&engine, &tun, 10), b"via-socks2");
    assert_eq!(log2.lock().unwrap().len(), 1);
    tcp_new.close(&engine, &tun);

    // 2. 推送 rule-provider 屏蔽 203.0.113.50/32 + 全量 reload：既有 TCP/UDP 仍不断
    let push_rule = cmd(
        &engine,
        json!({
            "cmd": "update_rule_provider",
            "name": "dyn",
            "payload": ["203.0.113.50/32"],
        }),
    );
    assert_eq!(push_rule["ok"], true, "{push_rule}");

    let tcp_blocked = RawTcp::connect(&engine, &tun, "198.18.0.1:41003", "203.0.113.50:8080");
    tcp_blocked.expect_reset(&tun);

    let full_reload = cmd(
        &engine,
        json!({
            "cmd": "reload",
            "config": "rules:\n  - IP-CIDR,203.0.113.50/32,REJECT\n  - MATCH,DIRECT\n",
        }),
    );
    assert_eq!(full_reload["ok"], true, "{full_reload}");
    wait_for(&engine, json!({"cmd": "stats"}), |v| {
        v["config_generation"].as_u64().unwrap_or(0) >= 2
    });

    tcp_live.send(&engine, b"post-reload");
    assert_eq!(tcp_live.read_exact(&engine, &tun, 11), b"post-reload");
    input(&engine, packet::build_udp(udp_app, udp_dst, b"post-reload-udp").unwrap());
    assert_eq!(tun.udp_from(udp_dst, udp_app), b"post-reload-udp");

    tcp_live.close(&engine, &tun);
    engine.stop();
}

#[test]
fn established_mitm_connection_survives_full_reload() {
    let _serial = crate::udp::performance_survey::STACK_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = TestDir::new("hr-mitm");
    std::fs::create_dir_all(root.0.join("mitm")).unwrap();
    std::fs::create_dir_all(root.0.join("core")).unwrap();
    let ca = oryn_mitm::CertificateAuthority::generate("Oryn hot-reload test CA").unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    std::fs::write(
        root.0.join("mitm/identity.json"),
        serde_json::to_vec(&json!({
            "certificate_der": b64.encode(&ca.material().certificate_der),
            "private_key_der": b64.encode(&ca.material().private_key_der),
        }))
        .unwrap(),
    )
    .unwrap();

    let cfg_for = |path: &str, body: &str| {
        format!(
            "mitm:\n  enabled: true\n  http2: false\n  hostnames: [mitm.test]\nmodules:\n  - format: surge\n    inline: |\n      [Map Local]\n      ^https://mitm.test{path} data-type=text data=\"{body}\" status-code=200\nrules: ['MATCH,DIRECT']\n"
        )
    };
    let opts = json!({"data_dir": root.0.join("core"), "local_proxy": {"enabled": false}}).to_string();
    let (mut engine, tun) = start_engine(&cfg_for("/before", "first-body"), &opts);
    let gen0 = cmd(&engine, json!({"cmd": "stats"}))["config_generation"]
        .as_u64()
        .unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            ca.material().certificate_der.clone(),
        ))
        .unwrap();
    let mut tls_cfg = rustls::ClientConfig::builder_with_provider(oryn_tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_cfg = Arc::new(tls_cfg);

    let flush = |client: &mut rustls::ClientConnection, tcp: &mut RawTcp, engine: &Engine| {
        while client.wants_write() {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            tcp.send(engine, &bytes);
        }
    };
    let recv = |client: &mut rustls::ClientConnection,
                tcp: &mut RawTcp,
                engine: &Engine,
                tun: &Tun| {
        let bytes = tcp.read_exact(engine, tun, 1);
        client.read_tls(&mut bytes.as_slice()).unwrap();
        client.process_new_packets().unwrap();
        flush(client, tcp, engine);
        let mut out = Vec::new();
        let _ = client.reader().read_to_end(&mut out);
        out
    };

    let mut client1 =
        rustls::ClientConnection::new(tls_cfg.clone(), oryn_tls::server_name("mitm.test").unwrap())
            .unwrap();
    let mut tcp1 = RawTcp::connect(&engine, &tun, "198.18.0.1:49811", "203.0.113.10:443");
    flush(&mut client1, &mut tcp1, &engine);
    while client1.is_handshaking() {
        recv(&mut client1, &mut tcp1, &engine, &tun);
    }
    client1
        .writer()
        .write_all(b"GET /before HTTP/1.1\r\nHost: mitm.test\r\n\r\n")
        .unwrap();
    flush(&mut client1, &mut tcp1, &engine);
    let mut resp1 = Vec::new();
    while !resp1.ends_with(b"first-body") {
        resp1.extend(recv(&mut client1, &mut tcp1, &engine, &tun));
        assert!(resp1.len() < 4096);
    }

    // 执行全量 reload 并等待新配置发布完成
    let r = cmd(
        &engine,
        json!({"cmd": "reload", "config": cfg_for("/after", "second-body")}),
    );
    assert_eq!(r["ok"], true, "{r}");
    wait_for(&engine, json!({"cmd": "stats"}), |v| {
        v["config_generation"].as_u64().unwrap_or(0) > gen0
    });

    // 已建立的 MITM TLS Keep-Alive 连接不能被取消，仍可继续完成下一次 HTTP 请求
    client1
        .writer()
        .write_all(b"GET /before HTTP/1.1\r\nHost: mitm.test\r\nConnection: close\r\n\r\n")
        .unwrap();
    flush(&mut client1, &mut tcp1, &engine);
    let mut resp1_next = Vec::new();
    while !resp1_next.ends_with(b"first-body") {
        resp1_next.extend(recv(&mut client1, &mut tcp1, &engine, &tun));
        assert!(resp1_next.len() < 4096);
    }

    // 新连接走新规则响应 second-body
    let mut client2 =
        rustls::ClientConnection::new(tls_cfg, oryn_tls::server_name("mitm.test").unwrap())
            .unwrap();
    let mut tcp2 = RawTcp::connect(&engine, &tun, "198.18.0.1:49812", "203.0.113.10:443");
    flush(&mut client2, &mut tcp2, &engine);
    while client2.is_handshaking() {
        recv(&mut client2, &mut tcp2, &engine, &tun);
    }
    client2
        .writer()
        .write_all(b"GET /after HTTP/1.1\r\nHost: mitm.test\r\nConnection: close\r\n\r\n")
        .unwrap();
    flush(&mut client2, &mut tcp2, &engine);
    let mut resp2 = Vec::new();
    while !resp2.ends_with(b"second-body") {
        resp2.extend(recv(&mut client2, &mut tcp2, &engine, &tun));
        assert!(resp2.len() < 4096);
    }

    engine.stop();
}

#[test]
fn update_rule_provider_payload_file_needs_payload_and_dns_cache() {
    let _serial = crate::udp::performance_survey::STACK_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let rt = runtime();
    let echo = rt.block_on(tcp_echo());
    let (dns, dns_hits) = rt.block_on(dns_server([203, 0, 113, 10]));
    let dir = TestDir::new("hr-rules");
    std::fs::write(dir.0.join("file_dom.txt"), "+.initial-file.example\n").unwrap();

    let cfg = format!(
        r#"
rule-providers:
  dyn_cls: {{type: inline, behavior: classical, payload: ['DOMAIN,cls.example']}}
  file_dom: {{type: file, behavior: domain, format: text, path: file_dom.txt}}
  dns_dom: {{type: inline, behavior: domain, payload: ['+.a-dns.test']}}
rules:
  - RULE-SET,dyn_cls,REJECT
  - RULE-SET,file_dom,REJECT
  - MATCH,DIRECT
dns:
  fake-ip-filter: ['*']
  nameserver: ['{dns}']
  nameserver-policy:
    'rule-set:dns_dom': '{dns}'
"#
    );
    let opts = json!({"data_dir": dir.0, "local_proxy": {"enabled": false}}).to_string();
    let (mut engine, tun) = start_engine(&cfg, &opts);

    // 互斥与空规则拦截
    assert!(
        cmd(
            &engine,
            json!({"cmd": "update_rule_provider", "name": "dyn_cls", "content": "a", "payload": ["b"]})
        )["error"]
            .is_string()
    );
    assert!(
        cmd(
            &engine,
            json!({"cmd": "update_rule_provider", "name": "dyn_cls", "payload": []})
        )["error"]
            .is_string()
    );

    // 触发一次 DNS 缓存
    assert_eq!(dns_query_tun(&engine, &tun, 0x1101, "cached.example"), vec![[203, 0, 113, 10]]);
    assert!(cmd(&engine, json!({"cmd": "stats"}))["dns_cache"].as_u64().unwrap() >= 1);
    let hits_after_query = dns_hits.load(Ordering::Relaxed);

    let stats_before = cmd(&engine, json!({"cmd": "stats"}));
    let gen0 = stats_before["config_generation"].as_u64().unwrap();
    let rev0 = stats_before["resource_revision"].as_u64().unwrap();

    // classical 规则集热更新激活 needs_payload；非 DNS 引用规则集变更不清 DNS 缓存
    let res = cmd(
        &engine,
        json!({
            "cmd": "update_rule_provider",
            "name": "dyn_cls",
            "payload": ["AND,((URL-REGEX,^http://a\\.payload-http\\.test/),(PROTOCOL,HTTP))"],
        }),
    );
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(res["count"], 1);
    let stats_mid = cmd(&engine, json!({"cmd": "stats"}));
    assert_eq!(stats_mid["config_generation"], gen0);
    assert_eq!(stats_mid["resource_revision"], rev0 + 1);
    assert!(stats_mid["dns_cache"].as_u64().unwrap() >= 1, "无关规则集变更不应清空 DNS 缓存");

    // 再次查同域名直接命中缓存
    assert_eq!(dns_query_tun(&engine, &tun, 0x1102, "cached.example"), vec![[203, 0, 113, 10]]);
    assert_eq!(dns_hits.load(Ordering::Relaxed), hits_after_query);

    // 需要读首包的 HTTP 规则对新连接立即生效
    let mut http_rejected = RawTcp::connect(&engine, &tun, "198.18.0.1:42001", &echo.to_string());
    http_rejected.send(&engine, b"GET / HTTP/1.1\r\nHost: a.payload-http.test\r\n\r\n");
    http_rejected.expect_reset(&tun);

    let mut plain_allowed = RawTcp::connect(&engine, &tun, "198.18.0.1:42002", &echo.to_string());
    plain_allowed.send(&engine, b"plain-tcp-ok");
    assert_eq!(plain_allowed.read_exact(&engine, &tun, 12), b"plain-tcp-ok");
    plain_allowed.close(&engine, &tun);

    // 推送 content 并 persist，再改磁盘并用 update_providers 重载 file 规则集
    let pushed_file = cmd(
        &engine,
        json!({
            "cmd": "update_rule_provider",
            "name": "file_dom",
            "content": "+.pushed-disk.test\n",
            "persist": true,
        }),
    );
    assert_eq!(pushed_file["ok"], true, "{pushed_file}");
    assert!(std::fs::read_to_string(dir.0.join("file_dom.txt"))
        .unwrap()
        .contains("pushed-disk.test"));

    std::fs::write(dir.0.join("file_dom.txt"), "+.disk-reloaded.test\n+.second.test\n").unwrap();
    assert_eq!(
        cmd(&engine, json!({"cmd": "update_providers", "name": "file_dom"}))["ok"],
        true
    );
    let providers_state = cmd(&engine, json!({"cmd": "providers"}));
    let file_info = providers_state["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "file_dom")
        .unwrap();
    assert_eq!(file_info["count"], 2);
    assert_eq!(file_info["updating"], false);

    // DNS 引用的规则集更新必须清空 DNS 缓存
    let push_dns = cmd(
        &engine,
        json!({
            "cmd": "update_rule_provider",
            "name": "dns_dom",
            "payload": ["+.b-dns.test"],
        }),
    );
    assert_eq!(push_dns["ok"], true, "{push_dns}");
    assert_eq!(cmd(&engine, json!({"cmd": "stats"}))["dns_cache"], 0);

    engine.stop();
}

#[test]
fn update_proxy_provider_push_file_and_selection_preservation() {
    let _serial = crate::udp::performance_survey::STACK_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let rt = runtime();
    let echo = rt.block_on(tcp_echo());
    let (socks1, log1) = rt.block_on(socks_server(echo));
    let (socks2, log2) = rt.block_on(socks_server(echo));
    let dir = TestDir::new("hr-proxy-prov");
    let sub_body = |p: u16, names: (&str, &str)| {
        format!(
            "proxies:\n  - {{name: {}, type: socks5, server: 127.0.0.1, port: {p}}}\n  - {{name: {}, type: socks5, server: 127.0.0.1, port: {p}}}\n",
            names.0, names.1
        )
    };
    std::fs::write(dir.0.join("sub.yaml"), sub_body(socks1.port(), ("NodeA", "NodeB"))).unwrap();

    let cfg = r#"
proxy-providers:
  sub: {type: file, path: sub.yaml}
proxy-groups:
  - {name: G, type: select, use: [sub]}
rules:
  - MATCH,G
"#;
    let opts = json!({"data_dir": dir.0, "local_proxy": {"enabled": false}}).to_string();
    let (mut engine, tun) = start_engine(cfg, &opts);
    assert_eq!(
        cmd(&engine, json!({"cmd": "select", "group": "G", "name": "NodeB"}))["ok"],
        true
    );

    let before = cmd(&engine, json!({"cmd": "stats"}));
    let gen0 = before["config_generation"].as_u64().unwrap();
    let rev0 = before["resource_revision"].as_u64().unwrap();

    // 推送空节点应被拒绝，原状态不受影响
    assert!(
        cmd(
            &engine,
            json!({"cmd": "update_proxy_provider", "name": "sub", "content": "proxies: []"})
        )["error"]
            .is_string()
    );
    assert_eq!(cmd(&engine, json!({"cmd": "stats"}))["resource_revision"], rev0);

    // 推送合法代理内容切换到 socks2，保持策略组选区 NodeB，且不递增 config_generation
    let ok = cmd(
        &engine,
        json!({
            "cmd": "update_proxy_provider",
            "name": "sub",
            "content": sub_body(socks2.port(), ("NodeA", "NodeB")),
        }),
    );
    assert_eq!(ok["ok"], true, "{ok}");
    assert_eq!(ok["count"], 2);
    let after_push = cmd(&engine, json!({"cmd": "stats"}));
    assert_eq!(after_push["config_generation"], gen0);
    assert!(after_push["resource_revision"].as_u64().unwrap() > rev0);
    assert_eq!(
        cmd(&engine, json!({"cmd": "groups"}))["groups"][0]["now"],
        "NodeB"
    );

    let mut flow2 = RawTcp::connect(&engine, &tun, "198.18.0.1:43001", "203.0.113.60:8080");
    flow2.send(&engine, b"hi-s2");
    assert_eq!(flow2.read_exact(&engine, &tun, 5), b"hi-s2");
    flow2.close(&engine, &tun);
    assert_eq!(log2.lock().unwrap().len(), 1);
    assert!(log1.lock().unwrap().is_empty());

    // 更新磁盘文件并调用无 content 的 update_proxy_provider 重载 file
    std::fs::write(dir.0.join("sub.yaml"), sub_body(socks1.port(), ("NodeA", "NodeC"))).unwrap();
    let reloaded = cmd(
        &engine,
        json!({"cmd": "update_proxy_provider", "name": "sub"}),
    );
    assert_eq!(reloaded["ok"], true, "{reloaded}");
    let groups = cmd(&engine, json!({"cmd": "groups"}));
    let members: Vec<&str> = groups["groups"][0]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert!(members.contains(&"NodeC") && !members.contains(&"NodeB"), "{groups}");

    let mut flow1 = RawTcp::connect(&engine, &tun, "198.18.0.1:43002", "203.0.113.60:8080");
    flow1.send(&engine, b"hi-s1");
    assert_eq!(flow1.read_exact(&engine, &tun, 5), b"hi-s1");
    flow1.close(&engine, &tun);
    assert_eq!(log1.lock().unwrap().len(), 1);

    engine.stop();
}

#[test]
fn patch_config_merge_replace_and_rejections() {
    let _serial = crate::udp::performance_survey::STACK_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let rt = runtime();
    let echo = rt.block_on(tcp_echo());
    let (dns, _) = rt.block_on(dns_server([203, 0, 113, 99]));
    let dir = TestDir::new("hr-patch");

    let cfg = format!(
        "hosts:\n  keep.test: 203.0.113.1\n  drop.test: 203.0.113.2\nrules:\n  - MATCH,DIRECT\ndns:\n  fake-ip-filter: ['*']\n  nameserver: ['{dns}']\n"
    );
    let opts = json!({"data_dir": dir.0, "local_proxy": {"enabled": false}}).to_string();
    let (mut engine, tun) = start_engine(&cfg, &opts);
    let gen0 = cmd(&engine, json!({"cmd": "stats"}))["config_generation"]
        .as_u64()
        .unwrap();

    // 禁止宿主字段与虚拟接口字段变更
    assert!(
        cmd(&engine, json!({"cmd": "patch_config", "patch": "port: 7899\n"}))["error"]
            .is_string()
    );
    let vif = cmd(
        &engine,
        json!({"cmd": "patch_config", "patch": "dns:\n  fake-ip-range: 10.9.0.0/20\n"}),
    );
    assert_eq!(vif["requires_reconnect"], true, "{vif}");

    // merge 补丁：合并 hosts、用 null 删键，并更新 rules
    let merged = cmd(
        &engine,
        json!({
            "cmd": "patch_config",
            "patch": "hosts:\n  drop.test: null\n  added.test: 203.0.113.3\nrules:\n  - DOMAIN,blocked.test,REJECT\n  - MATCH,DIRECT\n",
        }),
    );
    assert_eq!(merged["ok"], true, "{merged}");
    assert_eq!(cmd(&engine, json!({"cmd": "stats"}))["config_generation"], gen0);
    assert_eq!(dns_query_tun(&engine, &tun, 0x2201, "added.test"), vec![[203, 0, 113, 3]]);
    assert_eq!(dns_query_tun(&engine, &tun, 0x2202, "keep.test"), vec![[203, 0, 113, 1]]);
    assert_eq!(dns_query_tun(&engine, &tun, 0x2203, "drop.test"), vec![[203, 0, 113, 99]]);

    // replace 模式整段替换 rules
    let replaced = cmd(
        &engine,
        json!({
            "cmd": "patch_config",
            "mode": "replace",
            "patch": {"rules": ["MATCH,REJECT"]},
        }),
    );
    assert_eq!(replaced["ok"], true, "{replaced}");
    let rejected = RawTcp::connect(&engine, &tun, "198.18.0.1:44001", &echo.to_string());
    rejected.expect_reset(&tun);

    engine.stop();
}

#[test]
fn apply_settings_maxmind_partial_update_preserves_cache_and_cancels_changed_url() {
    let _serial = crate::udp::performance_survey::STACK_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let rt = runtime();
    let (dns, _) = rt.block_on(dns_server([203, 0, 113, 55]));

    let slow_count = Arc::new(AtomicUsize::new(0));
    let slow_counter = slow_count.clone();
    let slow = rt.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let c = slow_counter.clone();
                tokio::spawn(async move {
                    let mut req = [0u8; 4096];
                    if s.read(&mut req).await.unwrap_or(0) == 0 {
                        return;
                    }
                    c.fetch_add(1, Ordering::SeqCst);
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial")
                        .await;
                    let _ = s.read(&mut req).await;
                });
            }
        });
        addr
    });

    let country_mmdb = build_mmdb_country(&[([114, 0, 0, 0], 8, "CN")]);
    let fast_addr = rt.block_on(async move {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let body = Arc::new(country_mmdb);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut req = [0u8; 4096];
                    if s.read(&mut req).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let mut resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    resp.extend_from_slice(&body);
                    let _ = s.write_all(&resp).await;
                });
            }
        });
        addr
    });

    let dir = TestDir::new("hr-maxmind");
    let mut maxmind = json!({
        "geoip_db_url": format!("http://{slow}/slow"),
        "asn_db_url": format!("http://{fast_addr}/missing-asn"),
    });
    let cfg = format!(
        "rules:\n  - MATCH,DIRECT\ndns:\n  fake-ip-filter: ['*']\n  nameserver: ['{dns}']\n"
    );
    let opts = json!({
        "data_dir": dir.0,
        "local_proxy": {"enabled": false},
        "maxmind": maxmind,
    })
    .to_string();
    let (mut engine, tun) = start_engine(&cfg, &opts);

    wait_for(&engine, json!({"cmd": "providers"}), |v| {
        v["geoip"]["updating"] == true && slow_count.load(Ordering::SeqCst) == 1
    });
    // 等待流式临时文件落盘（确认旧下载正在进行）
    let partial = dir.0.join("geoip/country.tmp");
    let deadline = Instant::now() + Duration::from_secs(3);
    while std::fs::metadata(&partial).map(|m| m.len()).unwrap_or(0) < 7 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(dns_query_tun(&engine, &tun, 0x3301, "keep-cache.test"), vec![[203, 0, 113, 55]]);
    let before = cmd(&engine, json!({"cmd": "stats"}));
    let gen0 = before["config_generation"].as_u64().unwrap();
    let rev0 = before["resource_revision"].as_u64().unwrap();
    assert!(before["dns_cache"].as_u64().unwrap() >= 1);

    // 仅修改 geoip_db_url：取消旧 GeoIP 下载并切换新地址，但不重建运行态或清空 DNS 缓存
    maxmind["geoip_db_url"] = json!(format!("http://{fast_addr}/country.mmdb"));
    let reply = cmd(&engine, json!({"cmd": "apply_settings", "maxmind": maxmind}));
    assert_eq!(reply["ok"], true, "{reply}");
    wait_for(&engine, json!({"cmd": "providers"}), |v| {
        v["geoip"]["loaded"] == true
    });

    let after = cmd(&engine, json!({"cmd": "stats"}));
    assert_eq!(after["config_generation"], gen0, "apply_settings(maxmind) 不应递增 config_generation");
    assert!(after["resource_revision"].as_u64().unwrap() > rev0);
    assert!(after["dns_cache"].as_u64().unwrap() >= 1, "应保留 DNS 缓存");
    assert_eq!(slow_count.load(Ordering::SeqCst), 1);

    engine.stop();
}
