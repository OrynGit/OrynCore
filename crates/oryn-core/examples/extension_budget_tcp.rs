//! 真实 raw IP → lwIP → DIRECT → 本机 echo 的有限 TCP 内存实验。
//! 每进程只跑一个规模：extension_budget_tcp <8|32|64>。
//! 不修改产品 allocator；复用 Engine 集成测试的 RawTcp。
#[path = "../tests/support/mod.rs"]
mod support;

use std::alloc::System;
use std::sync::mpsc::sync_channel;
use std::time::{Duration, Instant};

use oryn_core::alloc::{heap_usage, Counting};
use oryn_netstack::packet::{
    self, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN,
};
use support::{RawTcp, Tun};

#[global_allocator]
static GLOBAL: Counting<System> = Counting(System);

#[cfg(target_os = "macos")]
fn footprint() -> u64 {
    // SAFETY：系统写入同尺寸 rusage_info_v4。
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

fn sample(n: usize, phase: &str) {
    let (live, peak) = heap_usage().expect("Counting installed");
    println!("{n},{phase},{live},{peak},{}", footprint());
}

const BURST: usize = 12000;

struct Flow {
    tcp: RawTcp,
    peer_ack: u32,
    peer_window: u16,
    connected: bool,
    received: usize,
}

// 所有输出由同一个消费者按四元组分发，绝不让单连接 read 吞掉其他连接输出。
fn pump(
    engine: &oryn_core::Engine,
    tun: &Tun,
    flows: &mut [Flow],
    payload: &[u8],
    reading: bool,
    wait: Duration,
) {
    let p = match tun.rx.recv_timeout(wait) {
        Ok(p) => p,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return,
        Err(e) => panic!("TUN disconnected: {e}"),
    };
    let seg = packet::parse_tcp(&p).expect("non-TCP output");
    let f = flows
        .iter_mut()
        .find(|f| seg.src == f.tcp.dst && seg.dst == f.tcp.src)
        .expect("unknown output flow");
    assert_eq!(
        seg.flags & (TCP_FLAG_RST | TCP_FLAG_FIN),
        0,
        "unexpected close"
    );
    assert!(seg.ack <= f.tcp.seq, "ACK beyond offered bytes");
    // 本实验序号不回绕。旧 ACK 不得倒退接收窗口右边界。
    if seg.ack >= f.peer_ack {
        f.peer_ack = seg.ack;
        f.peer_window = seg.window;
    }
    let c = &mut f.tcp;
    let syn = seg.flags & TCP_FLAG_SYN != 0;
    if syn {
        assert!(!f.connected);
        assert_eq!(seg.ack, c.seq);
        c.ack = seg.seq.wrapping_add(1);
        f.connected = true;
    } else if reading && !seg.payload.is_empty() {
        if seg.seq == c.ack {
            let end = f.received + seg.payload.len();
            assert_eq!(seg.payload, payload[f.received..end], "echo mismatch");
            f.received = end;
            c.ack = c.ack.wrapping_add(seg.payload.len() as u32);
        } else {
            assert!(
                seg.seq < c.ack,
                "out-of-order output on local lossless harness"
            );
        }
    }
    if syn || !seg.payload.is_empty() {
        support::input(
            engine,
            packet::build_tcp(
                c.src,
                c.dst,
                c.seq,
                c.ack,
                TCP_FLAG_ACK,
                if reading { 65535 } else { 0 },
                &[],
            )
            .unwrap(),
        );
    }
}

fn until(
    engine: &oryn_core::Engine,
    tun: &Tun,
    flows: &mut [Flow],
    payload: &[u8],
    reading: bool,
    done: impl Fn(&[Flow]) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done(flows) {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for all flow ACKs/echo"
        );
        pump(
            engine,
            tun,
            flows,
            payload,
            reading,
            Duration::from_millis(20),
        );
    }
}

// 10 个 1200B 段；发送前检查实际收到的未缩放窗口（SYN 未协商 scaling）。
fn burst(f: &mut Flow, engine: &oryn_core::Engine, payload: &[u8], window: u16) {
    let c = &mut f.tcp;
    assert!(
        c.seq + payload.len() as u32 <= f.peer_ack + u32::from(f.peer_window),
        "burst exceeds peer window"
    );
    let packets = payload
        .chunks(1200)
        .map(|chunk| {
            let p = packet::build_tcp(
                c.src,
                c.dst,
                c.seq,
                c.ack,
                TCP_FLAG_ACK | TCP_FLAG_PSH,
                window,
                chunk,
            )
            .unwrap();
            c.seq = c.seq.wrapping_add(chunk.len() as u32);
            p
        })
        .collect();
    engine.input(packets).unwrap();
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 2, "usage: extension_budget_tcp <8|32|64>");
    let n: usize = args[1].parse().unwrap();
    assert!(matches!(n, 8 | 32 | 64));
    println!("# macOS/local synthetic experiment; not iOS validation or throughput benchmark");
    println!("# heap=process Rust Counting<System> requested live/cumulative peak (includes harness, excludes C/lwIP malloc and kernel sockets); footprint=Darwin phys_footprint, 0 unavailable");
    println!("# burst=12000 bytes/flow concurrent verified echo; stopped_read=zero advertised window + another finite 12000 bytes/flow, ACK verified, 500ms; close=RST, not graceful FIN");
    println!("# RecvBuffer capacity is private: exercised by real payload, NOT separately measured; cumulative peak is never reset");
    println!("connections,phase,heap_live_bytes,heap_peak_bytes,phys_footprint_bytes");
    sample(n, "baseline");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let echo = rt.block_on(support::tcp_echo());
    let config = b"mode: direct\nlog-level: silent\ngeo-auto-update: false\ngeox-url: {mmdb: '', asn: ''}\ndns:\n  public-ip-url: ''\n  nameserver: ['127.0.0.1:1']\n  default-nameserver: ['127.0.0.1:1']\nrules: ['MATCH,DIRECT']\n";
    let mut engine = oryn_core::Engine::new(
        config,
        br#"{"local_proxy":{"enabled":false},"maxmind":null}"#,
    )
    .unwrap();
    // 有界测试输出，不把任意增长的测试队列误认为产品内存。
    let (tx, rx) = sync_channel(4096);
    engine.set_output(Box::new(move |packets| {
        for p in packets {
            tx.try_send(p.clone()).expect("test TUN queue full");
        }
    }));
    let tun = Tun { rx };
    engine.start().unwrap();
    std::thread::sleep(Duration::from_millis(500));
    sample(n, "engine_idle");
    let mut flows = Vec::with_capacity(n);
    for i in 0..n {
        let tcp = RawTcp {
            src: format!("198.18.0.1:{}", 41000 + i).parse().unwrap(),
            dst: echo,
            seq: 1001,
            ack: 0,
        };
        support::input(
            &engine,
            packet::build_tcp(tcp.src, tcp.dst, 1000, 0, TCP_FLAG_SYN, 65535, &[]).unwrap(),
        );
        flows.push(Flow {
            tcp,
            peer_ack: 1000,
            peer_window: 0,
            connected: false,
            received: 0,
        });
        until(&engine, &tun, &mut flows, &[], true, |fs| {
            fs.iter().all(|f| f.connected)
        });
        // TUN SYN/ACK 仅说明本地TCP握手完成，出站仍可能处于嗅探/拨号阶段。
        // 本例量已建立连接成本，逐条等出站完成，不能把握手突发准入失败混入基线。
        support::wait_for(&engine, r#"{"cmd":"connections"}"#, |v| {
            v["connections"].as_array().is_some_and(|list| {
                list.len() == i + 1 && list.iter().all(|c| c["connect_ms"].is_number())
            })
        });
    }
    std::thread::sleep(Duration::from_millis(500));
    sample(n, "connections_idle");
    let payload: Vec<u8> = (0..BURST).map(|i| (i % 251) as u8).collect();
    for f in &mut flows {
        burst(f, &engine, &payload, 65535);
    }
    until(&engine, &tun, &mut flows, &payload, true, |fs| {
        fs.iter()
            .all(|f| f.received == BURST && f.peer_ack == f.tcp.seq)
    });
    sample(n, "burst_echo_verified");
    for f in &mut flows {
        let c = &f.tcp;
        support::input(
            &engine,
            packet::build_tcp(c.src, c.dst, c.seq, c.ack, TCP_FLAG_ACK, 0, &[]).unwrap(),
        );
        burst(f, &engine, &payload, 0);
    }
    until(&engine, &tun, &mut flows, &payload, false, |fs| {
        fs.iter().all(|f| f.peer_ack == f.tcp.seq)
    });
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        pump(
            &engine,
            &tun,
            &mut flows,
            &payload,
            false,
            Duration::from_millis(10),
        );
    }
    sample(n, "stopped_read_500ms");
    println!("# all {n} flows: first 12000B echo verified; second 12000B ACKed by lwIP, not application-read; finite pressure only");
    for f in &flows {
        let c = &f.tcp;
        support::input(
            &engine,
            packet::build_tcp(
                c.src,
                c.dst,
                c.seq,
                c.ack,
                TCP_FLAG_RST | TCP_FLAG_ACK,
                0,
                &[],
            )
            .unwrap(),
        );
    }
    support::wait_for(&engine, r#"{"cmd":"connections"}"#, |v| {
        v["connections"].as_array().is_some_and(|a| a.is_empty())
    });
    std::thread::sleep(Duration::from_millis(500));
    while tun.rx.try_recv().is_ok() {}
    sample(n, "closed_rst_500ms");
    drop(flows);
    drop(payload);
    engine.stop();
    drop(engine);
    drop(tun);
    drop(rt);
    sample(n, "engine_and_harness_drop");
}
