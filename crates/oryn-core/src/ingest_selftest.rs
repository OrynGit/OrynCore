//! 隧道上行处理能力自测（开发用，默认关闭）。
//!
//! 真机自回环的上行受 App 发送端往 utun 注入包的内核路径限制，没法直接看出「lwIP + relay 这一段本身」能吃多少。
//! 这里在扩展里让 Core 自己扮演一个 TCP 客户端：直接把合法的 TCP 报文喂给 lwIP（不经内核 utun，也没有 App 发送端），
//! 对内存里的合成端点 `198.18.0.4` 上传，统计被确认的字节数。发包、lwIP 处理、relay 与丢弃全部共用事件循环这一个线程，
//! 所以测到的是处理路径吞吐的**下限**。开启方式：Core 数据目录里放 `oryn-ingest-selftest` 标记文件（`oryn_test/loopback.sh -i`），
//! 隧道启动 3 秒后运行 6 秒，结果写到扩展临时目录的 `oryn-ingest-selftest.json`。运行期间发往自测源地址的回包被截下，不会写进 utun。

use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use oryn_netstack::packet::{build_tcp, parse_tcp, TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN};
use oryn_netstack::NetStack;

use crate::context::EngineCtx;

/// 自测用的源地址（隧道 /24 内，不是任何真实主机）。
pub const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 250);
const PAYLOAD: usize = 3900;
const RUN: Duration = Duration::from_secs(6);

thread_local! {
    static CAPTURE: RefCell<Option<VecDeque<Vec<u8>>>> = const { RefCell::new(None) };
}

/// 事件循环 `take_output` 之后调用：自测运行期间把发往自测源地址的包截下，返回剩下的。
pub fn capture(out: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    CAPTURE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(queue) = slot.as_mut() else { return out };
        let mut rest = Vec::with_capacity(out.len());
        for packet in out {
            if packet.len() >= 20 && packet[0] >> 4 == 4 && packet[16..20] == SOURCE.octets() {
                queue.push_back(packet);
            } else {
                rest.push(packet);
            }
        }
        rest
    })
}

fn drain() -> Vec<Vec<u8>> {
    CAPTURE.with(|slot| slot.borrow_mut().as_mut().map(|q| q.drain(..).collect()).unwrap_or_default())
}

fn thread_cpu_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: 传入有效的 timespec 指针。
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) } != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub async fn run(ctx: Rc<EngineCtx>) {
    tokio::time::sleep(Duration::from_secs(3)).await;
    CAPTURE.with(|slot| *slot.borrow_mut() = Some(VecDeque::new()));
    let result = upload(&ctx).await;
    CAPTURE.with(|slot| *slot.borrow_mut() = None);
    let json = match result {
        Ok(value) => value,
        Err(e) => serde_json::json!({ "error": e }),
    };
    let _ = std::fs::write(std::env::temp_dir().join("oryn-ingest-selftest.json"), json.to_string());
}

/// 并发的自测连接数：每条连接 lwIP 最多放行 64 KiB 在途数据（发包器不带窗口缩放），
/// 多条并发才能把「发一批 → 让出线程 → 收 ACK」的往返周期摊薄，测到处理能力而不是周期延迟。
const FLOWS: usize = 8;

struct Flow {
    src: SocketAddr,
    seq: u32,
    ack: u32,
    una: u32,
    window: u32,
}

async fn upload(ctx: &Rc<EngineCtx>) -> Result<serde_json::Value, String> {
    let dst = SocketAddr::from((crate::virtual_interface::SYNTHETIC_V4, 5201));
    let stack = &ctx.stack;
    let mut flows: Vec<Flow> = (0..FLOWS)
        .map(|i| Flow { src: SocketAddr::from((SOURCE, 50000 + i as u16)), seq: 1000, ack: 0, una: 0, window: 65535 })
        .collect();
    for flow in &flows {
        stack.input_packet(&build_tcp(flow.src, dst, flow.seq, 0, TCP_FLAG_SYN, 65535, &[]).ok_or("build syn")?);
    }
    stack.notifier().notify_one();

    // 等所有 SYN-ACK
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut established = 0;
    while established < FLOWS {
        if Instant::now() > deadline {
            return Err(format!("only {established}/{FLOWS} SYN-ACKs"));
        }
        tokio::task::yield_now().await;
        for packet in drain() {
            if let Some(seg) = parse_tcp(&packet) {
                if seg.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) == (TCP_FLAG_SYN | TCP_FLAG_ACK) {
                    if let Some(flow) = flows.iter_mut().find(|f| f.src.port() == seg.dst.port() && f.ack == 0) {
                        flow.ack = seg.seq.wrapping_add(1);
                        established += 1;
                    }
                }
            }
        }
    }
    for flow in &mut flows {
        flow.seq = flow.seq.wrapping_add(1);
        stack.input_packet(&build_tcp(flow.src, dst, flow.seq, flow.ack, TCP_FLAG_ACK, 65535, &[]).ok_or("build ack")?);
        // 首字节 'U'：合成端点据此进入「丢弃全部输入」模式
        stack.input_packet(&build_tcp(flow.src, dst, flow.seq, flow.ack, TCP_FLAG_ACK | TCP_FLAG_PSH, 65535, b"U").ok_or("build U")?);
        flow.seq = flow.seq.wrapping_add(1);
        flow.una = flow.seq;
    }

    let payload = vec![0x5au8; PAYLOAD];
    let (start, cpu_start) = (Instant::now(), thread_cpu_ns());
    // 序号是 32 位，6 秒几十 GB 会回绕：已确认字节数逐个 ACK 累加
    let mut acked: u64 = 0;
    let mut segments = 0u64;
    let mut seen = 0u64;
    while start.elapsed() < RUN {
        for packet in drain() {
            if let Some(seg) = parse_tcp(&packet) {
                seen += 1;
                if let Some(flow) = flows.iter_mut().find(|f| f.src.port() == seg.dst.port()) {
                    if seg.flags & TCP_FLAG_ACK != 0 && (seg.ack.wrapping_sub(flow.una) as i32) > 0 {
                        acked += u64::from(seg.ack.wrapping_sub(flow.una));
                        flow.una = seg.ack;
                    }
                    flow.window = u32::from(seg.window).max(1);
                }
            }
        }
        for flow in &mut flows {
            let mut burst = 0;
            while flow.seq.wrapping_sub(flow.una) + (PAYLOAD as u32) <= flow.window && burst < 32 {
                let packet = build_tcp(flow.src, dst, flow.seq, flow.ack, TCP_FLAG_ACK | TCP_FLAG_PSH, 65535, &payload).ok_or("build data")?;
                stack.input_packet(&packet);
                flow.seq = flow.seq.wrapping_add(PAYLOAD as u32);
                segments += 1;
                burst += 1;
            }
        }
        tokio::task::yield_now().await;
    }
    let elapsed = start.elapsed().as_secs_f64();
    let cpu = (thread_cpu_ns().saturating_sub(cpu_start)) as f64 / 1e9;
    for flow in &flows {
        stack.input_packet(&build_tcp(flow.src, dst, flow.seq, flow.ack, TCP_FLAG_RST | TCP_FLAG_ACK, 0, &[]).ok_or("build rst")?);
    }
    Ok(serde_json::json!({
        "seconds": elapsed, "flows": FLOWS, "bytes_acked": acked, "gbps_acked": acked as f64 * 8.0 / elapsed / 1e9,
        "segments_sent": segments, "packets_seen": seen, "payload": PAYLOAD, "thread_cpu_pct": 100.0 * cpu / elapsed,
        "note": "generator + lwIP + relay + sink all on the event-loop thread; lower bound of the processing path",
    }))
}
