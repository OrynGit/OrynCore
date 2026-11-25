//! 脚本与 HTTP 检查内存前后对照基准（A/B 测量）：
//! 用法：`script_memory_bench <text_1m|binary_512k|binary_1m|text_4m|binary_4m>`
//! 每进程只跑一个场景，避免累计 heap peak 与 Darwin phys_footprint 互相污染。

use oryn_core::{
    alloc::{heap_usage, Counting},
    Engine,
};
use oryn_netstack::packet::{
    self, TcpSegment, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN,
};
use std::alloc::System;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[global_allocator]
static GLOBAL: Counting<System> = Counting(System);

#[cfg(target_os = "macos")]
fn footprint() -> u64 {
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

#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    size: usize,
    binary: bool,
    json_mode: bool,
}

fn parse_scenario(arg: &str) -> Scenario {
    match arg {
        "text_1m" => Scenario {
            name: "text_1m",
            size: 1000 * 1024,
            binary: false,
            json_mode: true,
        },
        "binary_512k" => Scenario {
            name: "binary_512k",
            size: 512 * 1024,
            binary: true,
            json_mode: false,
        },
        "binary_1m" => Scenario {
            name: "binary_1m",
            size: 1024 * 1024,
            binary: true,
            json_mode: false,
        },
        "text_4m" => Scenario {
            name: "text_4m",
            size: 4 * 1024 * 1024,
            binary: false,
            json_mode: false,
        },
        "binary_4m" => Scenario {
            name: "binary_4m",
            size: 4 * 1024 * 1024,
            binary: true,
            json_mode: false,
        },
        other => panic!(
            "unknown scenario {other}; expected text_1m|binary_512k|binary_1m|text_4m|binary_4m"
        ),
    }
}

struct ScratchDir(PathBuf);
impl ScratchDir {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("oryn-script-bench-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("modules")).unwrap();
        Self(p)
    }
}
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Tun {
    rx: Receiver<Vec<u8>>,
}
impl Tun {
    fn recv_until<T>(&self, mut f: impl FnMut(&[u8]) -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .expect("timed out waiting for tunnel packet");
            let pkt = self
                .rx
                .recv_timeout(left)
                .expect("timed out waiting for tunnel packet");
            if let Some(v) = f(&pkt) {
                return v;
            }
        }
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

    fn connect(engine: &Engine, tun: &Tun, src: &str, dst: &str) -> Self {
        let mut c = Self {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            seq: 1000,
            ack: 0,
        };
        engine
            .input(vec![packet::build_tcp(
                c.src,
                c.dst,
                c.seq,
                0,
                TCP_FLAG_SYN,
                65535,
                &[],
            )
            .unwrap()])
            .unwrap();
        let synack = tun.recv_until(|p| {
            c.seg_for_me(p).filter(|s| {
                s.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) == (TCP_FLAG_SYN | TCP_FLAG_ACK)
            })
        });
        c.seq = 1001;
        c.ack = synack.seq.wrapping_add(1);
        engine
            .input(vec![packet::build_tcp(
                c.src,
                c.dst,
                c.seq,
                c.ack,
                TCP_FLAG_ACK,
                65535,
                &[],
            )
            .unwrap()])
            .unwrap();
        c
    }

    fn send(&mut self, engine: &Engine, data: &[u8]) {
        for chunk in data.chunks(1200) {
            engine
                .input(vec![packet::build_tcp(
                    self.src,
                    self.dst,
                    self.seq,
                    self.ack,
                    TCP_FLAG_ACK | TCP_FLAG_PSH,
                    65535,
                    chunk,
                )
                .unwrap()])
                .unwrap();
            self.seq = self.seq.wrapping_add(chunk.len() as u32);
        }
    }

    /// 边接收边解析 HTTP 响应并只保留前缀以校验标记，避免客户端额外在堆上保留数 MiB 正文。
    fn read_http_response(&mut self, engine: &Engine, tun: &Tun) -> Result<(String, usize, Vec<u8>), String> {
        let mut buf = Vec::new();
        let mut header_end: Option<usize> = None;
        let mut expected_len: Option<usize> = None;
        let mut prefix = Vec::with_capacity(256);
        let mut body_seen = 0usize;
        let mut header_text = String::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if Instant::now() >= deadline {
                return Err("HTTP response deadline exceeded".into());
            }
            let seg = tun.recv_until(|p| {
                self.seg_for_me(p).filter(|s| {
                    !s.payload.is_empty() || s.flags & (TCP_FLAG_RST | TCP_FLAG_FIN) != 0
                })
            });
            if seg.flags & TCP_FLAG_RST != 0 {
                return Err("connection reset".into());
            }
            if !seg.payload.is_empty() && seg.seq == self.ack {
                self.ack = self.ack.wrapping_add(seg.payload.len() as u32);
                if header_end.is_none() {
                    buf.extend_from_slice(&seg.payload);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_text = String::from_utf8_lossy(&buf[..pos]).into_owned();
                        expected_len = header_text.lines().find_map(|line| {
                            let (k, v) = line.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())
                                .flatten()
                        });
                        let tail = &buf[pos + 4..];
                        body_seen += tail.len();
                        let take = 256usize.saturating_sub(prefix.len()).min(tail.len());
                        prefix.extend_from_slice(&tail[..take]);
                        buf.clear();
                        buf.shrink_to_fit();
                        header_end = Some(pos);
                    }
                } else {
                    body_seen += seg.payload.len();
                    let take = 256usize.saturating_sub(prefix.len()).min(seg.payload.len());
                    prefix.extend_from_slice(&seg.payload[..take]);
                }
            }
            if seg.flags & TCP_FLAG_FIN != 0 {
                self.ack = self.ack.wrapping_add(1);
            }
            engine
                .input(vec![packet::build_tcp(
                    self.src,
                    self.dst,
                    self.seq,
                    self.ack,
                    TCP_FLAG_ACK,
                    65535,
                    &[],
                )
                .unwrap()])
                .unwrap();
            if header_end.is_some() {
                if let Some(len) = expected_len {
                    if body_seen >= len {
                        return Ok((header_text, body_seen, prefix));
                    }
                } else if seg.flags & TCP_FLAG_FIN != 0 {
                    return Ok((header_text, body_seen, prefix));
                }
            } else if seg.flags & TCP_FLAG_FIN != 0 {
                return Err("EOF before HTTP headers".into());
            }
        }
    }

    fn reset(&self, engine: &Engine) {
        engine
            .input(vec![packet::build_tcp(
                self.src,
                self.dst,
                self.seq,
                self.ack,
                TCP_FLAG_RST | TCP_FLAG_ACK,
                0,
                &[],
            )
            .unwrap()])
            .unwrap();
    }
}

/// 启动零缓存流式 HTTP 对端与简化 SOCKS5 转发器（目标全部回落到本地流式 HTTP 对端）。
fn start_peers(
    scenario: Scenario,
    stop: Arc<AtomicBool>,
) -> (u16, Vec<std::thread::JoinHandle<()>>) {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_addr = origin.local_addr().unwrap();
    origin.set_nonblocking(true).unwrap();
    let stop_origin = stop.clone();
    let origin_thread = std::thread::spawn(move || {
        while !stop_origin.load(Ordering::Relaxed) {
            let (mut stream, _) = match origin.accept() {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(_) => break,
            };
            stream.set_nonblocking(false).unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
            let mut hdr = Vec::new();
            let mut tmp = [0u8; 1024];
            while !hdr.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break;
                }
                hdr.extend_from_slice(&tmp[..n]);
            }
            let ct = if scenario.binary {
                "application/octet-stream"
            } else if scenario.json_mode {
                "application/json"
            } else {
                "text/plain"
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                scenario.size
            );
            if stream.write_all(head.as_bytes()).is_err() {
                continue;
            }
            // 用固定栈缓冲分块写出，不对端分配数 MiB 内存。
            let mut sent = 0usize;
            if scenario.json_mode {
                let prefix = b"{\"mark\":\"old\",\"pad\":\"";
                let _ = stream.write_all(prefix);
                sent += prefix.len();
                let mut pad = [b'a'; 16384];
                while sent + 2 < scenario.size {
                    let take = (scenario.size - 2 - sent).min(pad.len());
                    pad[take - 1] = b'a';
                    if stream.write_all(&pad[..take]).is_err() {
                        break;
                    }
                    sent += take;
                }
                let _ = stream.write_all(b"\"}");
            } else if scenario.binary {
                let mut block = [0u8; 16384];
                for (i, b) in block.iter_mut().enumerate() {
                    *b = ((i * 31 + 7) & 0xff) as u8;
                }
                block[0] = 0x11;
                let mut first = true;
                while sent < scenario.size {
                    let take = (scenario.size - sent).min(block.len());
                    if !first {
                        block[0] = 0x22;
                    }
                    first = false;
                    if stream.write_all(&block[..take]).is_err() {
                        break;
                    }
                    sent += take;
                }
            } else {
                let prefix = b"OLD:";
                let _ = stream.write_all(prefix);
                sent += prefix.len();
                let pad = [b'x'; 16384];
                while sent < scenario.size {
                    let take = (scenario.size - sent).min(pad.len());
                    if stream.write_all(&pad[..take]).is_err() {
                        break;
                    }
                    sent += take;
                }
            }
        }
    });

    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_port = socks.local_addr().unwrap().port();
    socks.set_nonblocking(true).unwrap();
    let socks_thread = std::thread::spawn(move || {
        let mut relays = Vec::new();
        while !stop.load(Ordering::Relaxed) {
            let (mut client, _) = match socks.accept() {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(_) => break,
            };
            relays.push(std::thread::spawn(move || {
                client.set_nonblocking(false).unwrap();
                let mut greet = [0u8; 2];
                if client.read_exact(&mut greet).is_err() {
                    return;
                }
                let mut methods = vec![0u8; greet[1] as usize];
                if client.read_exact(&mut methods).is_err() {
                    return;
                }
                let _ = client.write_all(&[5, 0]);
                let mut req = [0u8; 4];
                if client.read_exact(&mut req).is_err() {
                    return;
                }
                match req[3] {
                    1 => {
                        let mut b = [0u8; 6];
                        if client.read_exact(&mut b).is_err() {
                            return;
                        }
                    }
                    3 => {
                        let mut l = [0u8; 1];
                        if client.read_exact(&mut l).is_err() {
                            return;
                        }
                        let mut b = vec![0u8; l[0] as usize + 2];
                        if client.read_exact(&mut b).is_err() {
                            return;
                        }
                    }
                    4 => {
                        let mut b = [0u8; 18];
                        if client.read_exact(&mut b).is_err() {
                            return;
                        }
                    }
                    _ => return,
                }
                let Ok(mut upstream) = TcpStream::connect(origin_addr) else {
                    return;
                };
                let _ = client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                let mut c2 = client.try_clone().unwrap();
                let mut u2 = upstream.try_clone().unwrap();
                let t = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut c2, &mut u2);
                });
                let _ = std::io::copy(&mut upstream, &mut client);
                let _ = t.join();
            }));
        }
        for r in relays {
            let _ = r.join();
        }
    });

    (socks_port, vec![origin_thread, socks_thread])
}

fn main() {
    let arg = std::env::args()
        .nth(1)
        .expect("usage: script_memory_bench <text_1m|binary_512k|binary_1m|text_4m|binary_4m>");
    let scenario = parse_scenario(&arg);
    let scratch = ScratchDir::new(scenario.name);

    // 预填充约 256 KiB 的 $persistentStore，用于测算每次脚本调用的存储加载与放大开销。
    let mut initial_store = BTreeMap::new();
    let val = "s".repeat(32 * 1024);
    for i in 0..8 {
        initial_store.insert(format!("k{i}"), val.clone());
    }
    std::fs::write(
        scratch.0.join("script-store.json"),
        serde_json::to_vec(&initial_store).unwrap(),
    )
    .unwrap();
    drop(initial_store);
    drop(val);

    let script_code = if scenario.binary {
        "let b = $response.body;\n\
         if (!(b instanceof Uint8Array)) throw Error('expected Uint8Array');\n\
         b[0] = 0x7a;\n\
         $done({body: b});\n"
    } else if scenario.json_mode {
        "let obj = JSON.parse($response.body);\n\
         obj.mark = 'new';\n\
         $done({body: JSON.stringify(obj)});\n"
    } else {
        "let s = $response.body;\n\
         if (typeof s !== 'string' || !s.startsWith('OLD:')) throw Error('bad text prefix');\n\
         $done({body: 'NEW:' + s.slice(4)});\n"
    };
    std::fs::write(scratch.0.join("modules/bench.js"), script_code).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let (socks_port, peer_threads) = start_peers(scenario, stop.clone());

    let cfg = format!(
        "mode: rule\nlog-level: silent\ngeo-auto-update: false\n\
         geox-url: {{mmdb: '', asn: ''}}\n\
         dns:\n  public-ip-url: ''\n  nameserver: ['127.0.0.1:1']\n  default-nameserver: ['127.0.0.1:1']\n\
         proxies:\n  - {{name: p, type: socks5, server: 127.0.0.1, port: {socks_port}, udp: false}}\n\
         rules:\n  - MATCH,p\n\
         modules:\n  - format: surge\n    inline: |\n      #!name=bench\n      [Script]\n      bench = type=http-response, pattern=^http://198\\.51\\.100\\.10(?::80)?/bench$, script-path=bench.js, requires-body=true, binary-body-mode={}, max-size=0, timeout=30\n",
        if scenario.binary { "true" } else { "false" }
    );
    let opts = serde_json::to_vec(&serde_json::json!({
        "local_proxy": {"enabled": false},
        "data_dir": scratch.0,
        "maxmind": null
    }))
    .unwrap();

    let mut engine = Engine::new(cfg.as_bytes(), &opts).unwrap();
    let (tx, rx) = channel();
    engine.set_output(Box::new(move |pkts: &[Vec<u8>]| {
        for p in pkts {
            let _ = tx.send(p.clone());
        }
    }));
    engine.start().unwrap();
    let tun = Tun { rx };

    let start = Instant::now();
    let mut tcp = RawTcp::connect(&engine, &tun, "198.18.0.1:42000", "198.51.100.10:80");
    tcp.send(
        &engine,
        b"GET /bench HTTP/1.1\r\nHost: 198.51.100.10\r\nConnection: close\r\n\r\n",
    );
    let outcome = tcp.read_http_response(&engine, &tun);
    let elapsed_ms = start.elapsed().as_millis();
    tcp.reset(&engine);

    let (ok, error) = match outcome {
        Ok((hdr, len, prefix)) => {
            let expected_marker = if scenario.binary {
                prefix.first() == Some(&0x7a)
            } else if scenario.json_mode {
                prefix.starts_with(br#"{"mark":"new""#)
            } else {
                prefix.starts_with(b"NEW:")
            };
            if hdr.contains("200 OK") && len == scenario.size && expected_marker {
                (true, String::new())
            } else {
                (
                    false,
                    format!(
                        "unmodified_or_mismatch len={len}/{} marker={expected_marker}",
                        scenario.size
                    ),
                )
            }
        }
        Err(e) => (false, e),
    };

    let (live, peak) = heap_usage().unwrap_or((0, 0));
    let fp = footprint();
    println!(
        "{},{},{},{},{},{},{}",
        scenario.name, ok, elapsed_ms, live, peak, fp, error
    );

    engine.stop();
    drop(engine);
    stop.store(true, Ordering::Relaxed);
    for t in peer_threads {
        let _ = t.join();
    }
}
