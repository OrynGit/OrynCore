//! 有限组合测量：真实 Engine + 保持的 echo 流 + TUN HTTP 模块首次命中 + 一次 reload。
//! 每进程一个 case：extension_budget_combined <light|large|desktop> <全新工作区目录>。
//! dev 本机数据不是 iOS 预算证明；fixture/runtime/配置/对端均计入堆和 footprint。
#[path = "../tests/support/mod.rs"]
mod support;

use oryn_core::{
    alloc::{heap_usage, Counting},
    Engine,
};
use oryn_netstack::packet::{self, TCP_FLAG_ACK, TCP_FLAG_RST};
use std::alloc::System;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use support::{RawTcp, Tun};

#[global_allocator]
static GLOBAL: Counting<System> = Counting(System);

#[cfg(target_os = "macos")]
fn footprint() -> u64 {
    // SAFETY：Darwin 写入同尺寸的 rusage_info_v4。
    let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V4,
            &mut info as *mut _ as *mut libc::rusage_info_t,
        )
    };
    if rc == 0 {
        info.ri_phys_footprint
    } else {
        0
    }
}
#[cfg(not(target_os = "macos"))]
fn footprint() -> u64 {
    0
}
fn sample(phase: &str, start: Instant) {
    let (live, peak) = heap_usage().unwrap();
    println!(
        "{phase},{},{live},{peak},{}",
        start.elapsed().as_micros(),
        footprint()
    );
}

// 关键阶段串行采样，不是流量运行期间的实时并发 stats 测量。
fn sample_stats(engine: &Engine, phase: &str, held: usize) {
    let mut latency = [0u128; 31];
    for us in &mut latency {
        let start = Instant::now();
        let reply = engine.command(br#"{"cmd":"stats"}"#);
        *us = start.elapsed().as_micros();
        assert!(reply.get("error").is_none() && reply["heap_live"].is_u64(), "{reply}");
    }
    latency.sort_unstable();
    let (live, peak) = heap_usage().unwrap();
    println!(
        "# stats phase={phase} held_target={held} samples=31 p50_us={} max_us={} heap_live_bytes={live} heap_cumulative_peak_bytes={peak} phys_footprint_bytes={}",
        latency[15], latency[30], footprint()
    );
}

type ReloadSample = (u128, u128, &'static str, bool);

// desktop 专用：固定容量、串行命令；异常退出也先停止并 join，再释放 handle。
struct ReloadStats {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Vec<ReloadSample>>>,
    origin: Instant,
}
impl ReloadStats {
    fn start(engine: &Engine) -> Self {
        let handle = engine.handle().expect("running engine");
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let origin = Instant::now();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let mut samples = Vec::with_capacity(256);
            for i in 0..256 {
                let after_ready = worker_stop.load(Ordering::Acquire);
                let sent = origin.elapsed().as_micros();
                let reply = oryn_core::run_command(Some(&handle), br#"{"cmd":"stats"}"#);
                let returned = origin.elapsed().as_micros();
                let outcome = match reply.get("error").and_then(|v| v.as_str()) {
                    Some("engine is busy") => "busy",
                    Some("command timed out") => "timeout",
                    Some(_) => "error",
                    None if reply["heap_live"].is_u64() => "success",
                    None => "invalid",
                };
                samples.push((sent, returned, outcome, after_ready));
                if i < 3 {
                    assert_eq!(outcome, "success", "baseline stats: {reply}");
                }
                if after_ready {
                    // 失败也及时结束；finish 会拒绝缺少 ready 后成功的结果。
                    break;
                }
                if i == 2 && tx.send(()).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            samples
        });
        let sampler = Self {
            stop,
            thread: Some(thread),
            origin,
        };
        rx.recv_timeout(Duration::from_secs(10))
            .expect("reload stats baseline barrier");
        sampler
    }

    fn finish(mut self, reload_start: Instant, ready: Instant) {
        self.stop.store(true, Ordering::Release);
        let samples = self.thread.take().unwrap().join().expect("stats sampler");
        let start = reload_start.duration_since(self.origin).as_micros();
        let end = ready.duration_since(self.origin).as_micros();
        let mut latency = Vec::with_capacity(samples.len());
        let mut overlapping = 0;
        for (i, &(sent, returned, outcome, after_ready)) in samples.iter().enumerate() {
            let overlap = sent <= end && returned >= start;
            overlapping += usize::from(overlap);
            if outcome == "success" {
                latency.push(returned - sent);
            }
            println!("# reload_stats sample={i} sent_us={sent} returned_us={returned} run_command_rtt_us={} outcome={outcome} after_ready={after_ready} overlaps_reload={overlap}", returned - sent);
        }
        latency.sort_unstable();
        println!("# reload_stats origin=baseline_start reload_start_us={start} modules_ready_us={end} samples={} overlapping_samples={overlapping} success_rtt_p50_us={} success_rtt_max_us={} cap=256 interval_ms=5", samples.len(), latency[latency.len() / 2], latency.last().unwrap());
        assert!(overlapping > 0, "stats sampling did not overlap reload");
        for outcome in ["success", "busy", "timeout", "error", "invalid"] {
            println!("# reload_stats outcome={outcome} count={}", samples.iter().filter(|s| s.2 == outcome).count());
        }
        assert!(samples.iter().any(|s| s.3 && s.2 == "success"),
            "stats sampling exhausted its bound before post-ready success");
    }
}
impl Drop for ReloadStats {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// 独立本机 HTTP 对端：单线程、最多一个正在处理的请求，8KiB 请求头上限。
// 不使用公网/CA/JS；每次返回固定 JSON，只有真实 Engine 的模块才能产生 oracle。
fn http_peer(
    stop: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let thread = std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) => panic!("accept: {e}"),
            };
            // Darwin accept 继承 listener 的 O_NONBLOCK；timeout 不会清除此标记。
            // listener 保持非阻塞以检查 stop，已接收连接按下面的有界 timeout 阻塞读写。
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            let mut buf = [0; 1024];
            while !header.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0 && header.len() + n <= 8192);
                header.extend_from_slice(&buf[..n]);
            }
            count.fetch_add(1, Ordering::Relaxed);
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"value\":17}").unwrap();
        }
    });
    (addr, thread)
}

fn config(nodes: usize, rules: usize, modules: usize, socks: u16, generation: &str) -> String {
    let mut c = String::from("mode: rule\nlog-level: silent\ngeo-auto-update: false\ngeox-url: {mmdb: '', asn: ''}\ndns:\n  public-ip-url: ''\n  nameserver: ['127.0.0.1:1']\n  default-nameserver: ['127.0.0.1:1']\nproxies:\n");
    for i in 0..nodes {
        writeln!(
            c,
            "  - {{name: node-{i}, type: socks5, server: 127.0.0.1, port: {socks}, udp: false}}"
        )
        .unwrap();
    }
    c.push_str("rules:\n");
    for i in 0..rules {
        writeln!(c, "  - DOMAIN,unused-{i}.invalid,REJECT").unwrap();
    }
    c.push_str("  - MATCH,node-0\nmodules:\n");
    for i in 0..modules {
        // 每模块唯一安全 jq，路径正则需实际命中；无脚本声明/64截断问题。
        writeln!(c, "  - format: surge\n    inline: |\n      #!name=combined-{generation}-{i}\n      [Body Rewrite]\n      http-response-jq ^http://198\\.51\\.100\\.10(?::80)?/m{i}$ '. + {{module: {i}, generation: \"{generation}\"}}'").unwrap();
    }
    c
}
fn assert_modules(engine: &Engine, n: usize, generation: &str) {
    let status = engine.command(br#"{"cmd":"module_status"}"#);
    let list = status["modules"].as_array().unwrap();
    assert_eq!(list.len(), n, "{status}");
    assert!(
        list.iter()
            .all(|m| m["enabled"] == true
                && m.to_string().contains(&format!("combined-{generation}-"))),
        "{status}"
    );
    let warnings = engine.command(br#"{"cmd":"warnings"}"#);
    assert!(
        warnings["warnings"].as_array().unwrap().is_empty(),
        "{warnings}"
    );
}
fn reset(engine: &Engine, flow: &RawTcp) {
    support::input(
        engine,
        packet::build_tcp(
            flow.src,
            flow.dst,
            flow.seq,
            flow.ack,
            TCP_FLAG_RST | TCP_FLAG_ACK,
            0,
            &[],
        )
        .unwrap(),
    );
}
fn request(engine: &Engine, tun: &Tun, port: usize, module: usize, generation: &str) {
    let mut tcp = RawTcp::connect(
        engine,
        tun,
        &format!("198.18.0.1:{port}"),
        "198.51.100.10:80",
    );
    tcp.send(
        engine,
        format!("GET /m{module} HTTP/1.1\r\nHost: 198.51.100.10\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "HTTP deadline");
        let p = tun.rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let Some(seg) = tcp.seg_for_me(&p) else {
            continue;
        };
        assert_eq!(seg.flags & TCP_FLAG_RST, 0, "HTTP reset");
        if !seg.payload.is_empty() && seg.seq == tcp.ack {
            response.extend_from_slice(&seg.payload);
            assert!(response.len() <= 16384);
            tcp.ack = tcp.ack.wrapping_add(seg.payload.len() as u32);
            support::input(
                engine,
                packet::build_tcp(tcp.src, tcp.dst, tcp.seq, tcp.ack, TCP_FLAG_ACK, 65535, &[])
                    .unwrap(),
            );
        }
        if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = std::str::from_utf8(&response[..end]).unwrap();
            assert!(header.starts_with("HTTP/1.1 200"), "{header}");
            let len: usize = header
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .expect("bounded response must have content-length");
            if response.len() >= end + 4 + len {
                let body: serde_json::Value =
                    serde_json::from_slice(&response[end + 4..end + 4 + len]).unwrap();
                assert_eq!(
                    body,
                    serde_json::json!({"value":17,"module":module,"generation":generation})
                );
                break;
            }
        }
    }
    reset(engine, &tcp);
}
fn echo_all(engine: &Engine, tun: &Tun, flows: &mut [RawTcp], generation: &str) {
    // 串行有限突发；其余流持续保持，但不宣称并发饱和吞吐。
    let payload = format!("echo-{generation}-").repeat(512);
    for flow in flows {
        flow.send(engine, payload.as_bytes());
        assert_eq!(
            flow.read_exact(engine, tun, payload.len()),
            payload.as_bytes()
        );
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: extension_budget_combined <light|large|desktop_high> <new workspace directory>"
    );
    let (nodes, rules, modules, held) = match args[1].as_str() {
        "light" => (100, 1000, 2, 8),
        "large" => (1000, 10000, 20, 8),
        #[cfg(target_os = "macos")]
        "desktop_high" => (1000, 10000, 20, 128),
        #[cfg(not(target_os = "macos"))]
        "desktop_high" => panic!("desktop_high case requires macOS"),
        _ => panic!("unknown case"),
    };
    let dir = std::path::Path::new(&args[2]);
    assert!(dir.is_absolute());
    std::fs::create_dir(dir).expect("fresh directory required");
    println!("# case={} nodes={nodes} domain_rules={rules} modules={modules}; {held} echo flows held across first hits/reload; HTTP concurrency=1", args[1]);
    println!("# Rust requested heap includes all fixture inputs/runtime/peers/logs; cumulative peak never reset; footprint is sampled Darwin process footprint, not peak/iOS; no JS/TLS/public network");
    println!("# stats: 31 sequential calls at stage boundaries, not real-time concurrent stats; p50/max are command RTT");
    println!("# desktop reload sampler: run_command RTT, not pure parse or packet latency; 3s command timeout censors slow replies; quantiles include successes only; echo is verified before/after reload, not continuous traffic");
    println!("phase,elapsed_us,heap_live_bytes,heap_cumulative_peak_bytes,phys_footprint_bytes");
    sample("baseline", Instant::now());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(AtomicUsize::new(0));
    let (http, server) = http_peer(stop.clone(), requests.clone());
    let echo = rt.block_on(support::tcp_echo());
    // 一个真实 SOCKS 出站：虚拟 dst:80 映射 HTTP，127.0.0.1:echo 真实连接 echo。
    let (socks, socks_log) = rt.block_on(support::socks_server(None, http));
    let start = Instant::now();
    let config_a = config(nodes, rules, modules, socks.port(), "a");
    let mut options =
        serde_json::json!({"local_proxy":{"enabled":false},"data_dir":dir,"maxmind":null});
    if args[1] == "desktop_high" {
        options["resource_profile"] = serde_json::json!("desktop_high");
    }
    let options = serde_json::to_vec(&options).unwrap();
    sample("fixture_ready", start);
    let start = Instant::now();
    let mut engine = Engine::new(config_a.as_bytes(), &options).unwrap();
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
    sample("engine_new", start);
    let (tx, rx) = std::sync::mpsc::sync_channel(4096);
    engine.set_output(Box::new(move |packets| {
        for p in packets {
            tx.try_send(p.clone()).expect("bounded TUN full");
        }
    }));
    let tun = Tun { rx };
    let start = Instant::now();
    engine.start().unwrap();
    assert_modules(&engine, modules, "a");
    sample("engine_started", start);
    sample_stats(&engine, "engine_started", 0);
    let start = Instant::now();
    let mut flows = Vec::new();
    let echo_port = 41000;
    let http_port = echo_port + held;
    assert!(http_port + modules * 4 <= u16::MAX as usize);
    for i in 0..held {
        let mut flow = RawTcp::connect(
            &engine,
            &tun,
            &format!("198.18.0.1:{}", echo_port + i),
            &echo.to_string(),
        );
        flow.send(&engine, b"hello");
        assert_eq!(flow.read_exact(&engine, &tun, 5), b"hello");
        flows.push(flow);
    }
    echo_all(&engine, &tun, &mut flows, "before");
    sample("echo_flows_held", start);
    sample_stats(&engine, "echo_flows_held", held);
    let start = Instant::now();
    for i in 0..modules {
        request(&engine, &tun, http_port + i, i, "a");
    }
    sample("all_modules_first_hit_a", start);
    sample_stats(&engine, "all_modules_first_hit_a", held);
    let start = Instant::now();
    for i in 0..modules {
        request(&engine, &tun, http_port + modules + i, i, "a");
    }
    echo_all(&engine, &tun, &mut flows, "hot");
    sample("all_modules_repeat_a_flows_held", start);
    sample_stats(&engine, "all_modules_repeat_a_flows_held", held);
    let start = Instant::now();
    let config_b = config(nodes, rules, modules, socks.port(), "b");
    let reload =
        serde_json::to_vec(&serde_json::json!({"cmd":"reload","config":config_b})).unwrap();
    sample("reload_input_with_held_flows", start);
    let reload_stats = (args[1] == "desktop_high").then(|| ReloadStats::start(&engine));
    let start = Instant::now();
    let reply = engine.command(&reload);
    assert_eq!(reply["ok"], true, "{reply}");
    support::wait_for(&engine, r#"{"cmd":"module_status"}"#, |v| {
        v.to_string().contains("combined-b-0")
    });
    assert_modules(&engine, modules, "b");
    let modules_ready = Instant::now();
    sample("reload_applied_marker_b", start);
    if let Some(sampler) = reload_stats {
        sampler.finish(start, modules_ready);
    }
    sample_stats(&engine, "reload_applied_marker_b", held);
    drop(reply);
    drop(reload);
    drop(config_b);
    let start = Instant::now();
    echo_all(&engine, &tun, &mut flows, "after-reload");
    for i in 0..modules {
        request(&engine, &tun, http_port + modules * 2 + i, i, "b");
    }
    sample("old_echo_and_all_new_modules_verified", start);
    sample_stats(&engine, "old_echo_and_all_new_modules_verified", held);
    let start = Instant::now();
    for i in 0..modules {
        request(&engine, &tun, http_port + modules * 3 + i, i, "b");
    }
    assert_eq!(requests.load(Ordering::Relaxed), modules * 4);
    support::wait_for(&engine, r#"{"cmd":"connections"}"#, |v| {
        v["connections"].as_array().is_some_and(|a| a.len() == held)
    });
    sample("repeat_b_flows_still_held", start);
    sample_stats(&engine, "repeat_b_flows_still_held", held);
    let start = Instant::now();
    for flow in &flows {
        reset(&engine, flow);
    }
    support::wait_for(&engine, r#"{"cmd":"connections"}"#, |v| {
        v["connections"].as_array().is_some_and(|a| a.is_empty())
    });
    sample("all_flows_closed", start);
    sample_stats(&engine, "all_flows_closed", 0);
    let start = Instant::now();
    engine.stop();
    drop(engine);
    drop(tun);
    drop(flows);
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    drop(rt);
    drop(socks_log);
    drop(config_a);
    drop(options);
    drop(requests);
    drop(stop);
    sample("stop_join_and_fixture_drop", start);
    println!("# PASS: {modules}/{modules} enabled modules each executed twice per generation; {} real HTTP upstream requests; {held} old echo flows survive reload; no overlapping HTTP generation claimed", modules*4);
}
