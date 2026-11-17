//! 有界的 iperf3 TCP 客户端。
//!
//! 这里只实现 iperf3 的 TCP（1–8 条并行流）、无认证客户端状态机。连接由选定的
//! [`Outbound`] 建立，控制和数据连接都使用同一个解析后的叶子出站。
//!
//! 隧道未连接时主 App 用 `OrynApp/Services/DirectIperf.swift` 直连运行同一流程，改动协议或上限时需同步。

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oryn_config::TargetAddr;
use oryn_outbound::{resolve, BoxStream, Outbound, PickMeta};
use oryn_router::{FlowContext, Network};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::context::EngineCtx;

const MAX_DURATION: u64 = 60;
/// 并行数据流上限（界面只提供 1 与 8）。
const MAX_THREADS: u64 = 8;
const MAX_SAMPLES: usize = 122;
const MAX_JSON: usize = 64 * 1024;
const BLOCK: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PARAM_EXCHANGE: u8 = 9;
const CREATE_STREAMS: u8 = 10;
const TEST_START: u8 = 1;
const TEST_RUNNING: u8 = 2;
const TEST_END: u8 = 4;
const EXCHANGE_RESULTS: u8 = 13;
const DISPLAY_RESULTS: u8 = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Upload,
    Download,
}

impl Direction {
    fn parse(value: Option<&str>) -> Option<Self> {
        match value.unwrap_or("upload").to_ascii_lowercase().as_str() {
            "upload" | "up" | "send" => Some(Self::Upload),
            "download" | "down" | "receive" => Some(Self::Download),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }

    fn reverse(self) -> bool {
        matches!(self, Self::Download)
    }
}

#[derive(Debug, Clone, Default)]
struct Sample {
    elapsed: f64,
    bytes: u64,
    mbps: f64,
}

#[derive(Debug, Clone, Default)]
struct Phase {
    direction: String,
    bytes: u64,
    average_mbps: f64,
    peak_mbps: f64,
    server_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
struct Snapshot {
    status: String,
    server: String,
    outbound: String,
    chain: Vec<String>,
    direction: String,
    duration: u64,
    elapsed: f64,
    current_mbps: f64,
    average_mbps: f64,
    peak_mbps: f64,
    bytes: u64,
    error: Option<String>,
    samples: Vec<Sample>,
    phases: Vec<Phase>,
}

impl Snapshot {
    fn new(
        server: String,
        outbound: String,
        chain: Vec<String>,
        direction: String,
        duration: u64,
    ) -> Self {
        Self {
            status: "running".into(),
            server,
            outbound,
            chain,
            direction,
            duration,
            elapsed: 0.0,
            current_mbps: 0.0,
            average_mbps: 0.0,
            peak_mbps: 0.0,
            bytes: 0,
            error: None,
            samples: Vec::with_capacity(MAX_SAMPLES),
            phases: Vec::new(),
        }
    }
}

#[derive(Default)]
pub struct Manager {
    current: RefCell<Option<Rc<RefCell<Snapshot>>>>,
    cancel: RefCell<Option<Rc<Cell<bool>>>>,
    task: RefCell<Option<JoinHandle<()>>>,
}

impl Manager {
    pub fn cancel(&self, reason: &str) {
        if let Some(flag) = self.cancel.borrow_mut().take() {
            flag.set(true);
        }
        if let Some(task) = self.task.borrow_mut().take() {
            task.abort();
        }
        if let Some(snapshot) = self.current.borrow().as_ref() {
            let mut snapshot = snapshot.borrow_mut();
            if snapshot.status == "running" {
                snapshot.status = "cancelled".into();
                snapshot.error = Some(reason.to_string());
            }
        }
    }

    fn snapshot(&self) -> Value {
        let Some(snapshot) = self.current.borrow().as_ref().cloned() else {
            return json!({"status":"idle"});
        };
        let value = snapshot_json(&snapshot.borrow());
        value
    }
}

pub fn command(ctx: &Rc<EngineCtx>, req: &Value) -> Value {
    match req.get("cmd").and_then(Value::as_str).unwrap_or("") {
        "iperf_options" => {
            let state = ctx.state();
            json!({"outbounds": state.config.outbounds.iter().map(|o| json!({"name":o.name,"type":o.kind.type_name()})).collect::<Vec<_>>()})
        }
        "iperf_status" => ctx.iperf.snapshot(),
        "iperf_stop" => {
            ctx.iperf.cancel("stopped by user");
            ctx.iperf.snapshot()
        }
        "iperf_start" => start(ctx, req),
        _ => json!({"error":"unknown iperf command"}),
    }
}

fn start(ctx: &Rc<EngineCtx>, req: &Value) -> Value {
    if ctx
        .iperf
        .current
        .borrow()
        .as_ref()
        .is_some_and(|s| s.borrow().status == "running")
    {
        return json!({"error":"an iperf3 test is already running"});
    }
    let server = req
        .get("server")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if server.is_empty() || server.len() > 255 {
        return json!({"error":"iperf3 server is required"});
    }
    let port = req.get("port").and_then(Value::as_u64).unwrap_or(5201);
    if !(1..=65535).contains(&port) {
        return json!({"error":"iperf3 port must be between 1 and 65535"});
    }
    let duration = req
        .get("duration")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .clamp(3, MAX_DURATION);
    let mode = req
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("upload")
        .to_ascii_lowercase();
    let directions = match mode.as_str() {
        "both" | "bidirectional" => vec![Direction::Download, Direction::Upload],
        _ => match Direction::parse(Some(&mode)) {
            Some(direction) => vec![direction],
            None => return json!({"error":"direction must be upload, download or both"}),
        },
    };
    let threads = match parse_threads(req) {
        Ok(value) => value,
        Err(error) => return json!({"error": error}),
    };
    let target = TargetAddr::from_host(server, port as u16);
    let state = ctx.state();
    let outbound_name = req
        .get("outbound")
        .and_then(Value::as_str)
        .unwrap_or("DIRECT");
    let Some(index) = state.config.outbound_index(outbound_name) else {
        return json!({"error":format!("unknown outbound `{outbound_name}`")});
    };
    let Ok(destination) = format!("0.0.0.0:{port}").parse() else {
        return json!({"error":"invalid iperf3 destination"});
    };
    let mut flow = FlowContext::new(0, Network::Tcp, "0.0.0.0:0".parse().unwrap(), destination);
    let Some(decision) = state.router().route_explicit(&mut flow, index) else {
        return json!({"error":"selected outbound is unavailable"});
    };
    let Some(start_outbound) = state.routing.outbounds.get(decision.outbound).cloned() else {
        return json!({"error":"selected outbound is unavailable"});
    };
    let meta = PickMeta {
        source: None,
        target: &target,
        network: Network::Tcp,
    };
    let Some(resolved) = resolve(&start_outbound, &meta) else {
        return json!({"error":"selected outbound rejected the iperf3 test"});
    };
    let chain = resolved.chain;
    let leaf = resolved.leaf;
    let display_outbound = outbound_name.to_string();
    let snapshot = Rc::new(RefCell::new(Snapshot::new(
        server.to_string(),
        display_outbound,
        chain,
        if directions.len() == 2 {
            "both".into()
        } else {
            directions[0].as_str().into()
        },
        duration,
    )));
    let cancel = Rc::new(Cell::new(false));
    *ctx.iperf.current.borrow_mut() = Some(snapshot.clone());
    *ctx.iperf.cancel.borrow_mut() = Some(cancel.clone());
    let manager = Rc::downgrade(&ctx.iperf);
    let target = target.clone();
    let task = tokio::task::spawn_local(async move {
        let result = run_test(
            snapshot.clone(),
            cancel,
            leaf,
            target,
            directions,
            duration,
            threads,
        )
        .await;
        if let Err(error) = result {
            let mut snapshot = snapshot.borrow_mut();
            if snapshot.status == "running" {
                snapshot.status = if error == "cancelled" {
                    "cancelled"
                } else {
                    "failed"
                }
                .into();
                snapshot.error = Some(error);
            }
        } else {
            snapshot.borrow_mut().status = "completed".into();
        }
        if let Some(manager) = manager.upgrade() {
            manager.cancel.borrow_mut().take();
            manager.task.borrow_mut().take();
        }
    });
    *ctx.iperf.task.borrow_mut() = Some(task);
    ctx.iperf.snapshot()
}

async fn run_test(
    snapshot: Rc<RefCell<Snapshot>>,
    cancel: Rc<Cell<bool>>,
    leaf: Arc<dyn Outbound>,
    target: TargetAddr,
    directions: Vec<Direction>,
    duration: u64,
    threads: usize,
) -> Result<(), String> {
    for direction in directions {
        if cancel.get() {
            return Err("cancelled".into());
        }
        snapshot.borrow_mut().direction = direction.as_str().into();
        let phase = run_phase(
            snapshot.clone(),
            cancel.clone(),
            leaf.clone(),
            target.clone(),
            direction,
            duration,
            threads,
        )
        .await?;
        snapshot.borrow_mut().phases.push(phase);
    }
    Ok(())
}

async fn run_phase(
    snapshot: Rc<RefCell<Snapshot>>,
    cancel: Rc<Cell<bool>>,
    leaf: Arc<dyn Outbound>,
    target: TargetAddr,
    direction: Direction,
    duration: u64,
    threads: usize,
) -> Result<Phase, String> {
    snapshot.borrow_mut().samples.clear();
    let mut control = leaf
        .connect_tcp(&target)
        .await
        .map_err(|e| format!("control connection failed: {e}"))?;
    let cookie = cookie();
    write_all_timeout(&mut control, &cookie).await?;
    expect_state(&mut control, PARAM_EXCHANGE).await?;
    write_json(
        &mut control,
        &json!({
            "tcp": true,
            "omit": 0,
            "time": duration,
            "parallel": threads,
            "reverse": direction.reverse(),
            "len": BLOCK,
            "client_version": "3.19.1"
        }),
    )
    .await?;
    expect_state(&mut control, CREATE_STREAMS).await?;
    let mut data = Vec::with_capacity(threads);
    for _ in 0..threads {
        let mut stream = leaf
            .connect_tcp(&target)
            .await
            .map_err(|e| format!("data connection failed: {e}"))?;
        write_all_timeout(&mut stream, &cookie).await?;
        data.push(stream);
    }
    expect_state(&mut control, TEST_START).await?;
    expect_state(&mut control, TEST_RUNNING).await?;

    // 每条数据流一个并发任务，字节数各记在自己的计数器里；任务被丢弃（取消、出错、结束）时一并终止。
    let failure: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let failed = Rc::new(Notify::new());
    let counters: Vec<Rc<Cell<u64>>> = (0..threads).map(|_| Rc::new(Cell::new(0))).collect();
    let mut workers = Workers(Vec::with_capacity(threads));
    for (stream, counter) in data.into_iter().zip(&counters) {
        workers.0.push(tokio::task::spawn_local(stream_worker(
            stream,
            counter.clone(),
            direction,
            failure.clone(),
            failed.clone(),
        )));
    }
    let total = || counters.iter().map(|c| c.get()).sum::<u64>();

    let started = Instant::now();
    let mut next_sample = tokio::time::interval(Duration::from_secs(1));
    next_sample.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    next_sample.tick().await;
    let end = tokio::time::sleep_until(tokio::time::Instant::from_std(
        started + Duration::from_secs(duration),
    ));
    tokio::pin!(end);
    let mut last_sample_bytes = 0_u64;
    let mut last_sample_at = started;
    let mut peak: f64 = 0.0;
    loop {
        if cancel.get() {
            return Err("cancelled".into());
        }
        tokio::select! {
            _ = next_sample.tick() => {
                let bytes = total();
                let at = Instant::now();
                let dt = at.duration_since(last_sample_at).as_secs_f64().max(0.001);
                let rate = (bytes.saturating_sub(last_sample_bytes) as f64 * 8.0 / dt) / 1_000_000.0;
                peak = peak.max(rate);
                let mut s = snapshot.borrow_mut();
                s.elapsed = at.duration_since(started).as_secs_f64();
                s.bytes = bytes;
                s.current_mbps = rate;
                s.average_mbps = bytes as f64 * 8.0 / s.elapsed.max(0.001) / 1_000_000.0;
                s.peak_mbps = peak;
                if s.samples.len() < MAX_SAMPLES {
                    let elapsed = s.elapsed;
                    s.samples.push(Sample { elapsed, bytes, mbps: rate });
                }
                last_sample_bytes = bytes;
                last_sample_at = at;
            }
            _ = failed.notified() => {
                let error = failure.borrow().clone().unwrap_or_else(|| "data transfer failed".into());
                return Err(error);
            }
            _ = &mut end => break,
        }
    }
    let bytes = total();
    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    let average = bytes as f64 * 8.0 / elapsed / 1_000_000.0;
    snapshot.borrow_mut().elapsed = elapsed;
    snapshot.borrow_mut().bytes = bytes;
    snapshot.borrow_mut().average_mbps = average;
    snapshot.borrow_mut().peak_mbps = peak.max(average);
    let stream_bytes: Vec<u64> = counters.iter().map(|c| c.get()).collect();
    // 结束由客户端发起。上传时先停数据流再发 TEST_END；下载时服务端是发送方，
    // 与 iperf3 客户端一样继续读空数据流直到结果交换，否则服务端写数据流失败会直接断开控制连接。
    if direction == Direction::Upload {
        workers.finish().await;
    }
    write_all_timeout(&mut control, &[TEST_END]).await?;
    expect_state(&mut control, EXCHANGE_RESULTS).await?;
    workers.finish().await;
    let streams: Vec<Value> = stream_bytes
        .iter()
        .enumerate()
        .map(|(i, b)| json!({"id":stream_id(i),"bytes":b,"retransmits":-1,"jitter":0.0,"errors":0,"omitted_errors":0,"packets":0,"omitted_packets":0,"start_time":0.0,"end_time":elapsed}))
        .collect();
    write_json(
        &mut control,
        &json!({
            "cpu_util_total": 0.0,
            "cpu_util_user": 0.0,
            "cpu_util_system": 0.0,
            "sender_has_retransmits": -1,
            "streams": streams
        }),
    )
    .await?;
    let server = read_json(&mut control).await?;
    expect_state(&mut control, DISPLAY_RESULTS).await?;
    let server_bytes = server
        .get("streams")
        .and_then(Value::as_array)
        .map(|streams| {
            streams
                .iter()
                .filter_map(|s| s.get("bytes").and_then(Value::as_u64))
                .sum::<u64>()
        });
    Ok(Phase {
        direction: direction.as_str().into(),
        bytes,
        average_mbps: average,
        peak_mbps: peak.max(average),
        server_bytes,
    })
}

/// 数据流任务的集合；丢弃时终止全部任务（取消、出错、提前返回都会走到这里）。
struct Workers(Vec<JoinHandle<()>>);

impl Workers {
    /// 终止全部任务并等它们真正结束，保证数据连接在发送 TEST_END 之前已经关闭。
    async fn finish(&mut self) {
        for handle in self.0.drain(..) {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for Workers {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

/// 一条数据流：上传时循环写、下载时循环读，字节数记入计数器；出错记下原因并唤醒主循环。
async fn stream_worker(
    mut stream: BoxStream,
    counter: Rc<Cell<u64>>,
    direction: Direction,
    failure: Rc<RefCell<Option<String>>>,
    failed: Rc<Notify>,
) {
    let mut buf = vec![0_u8; BLOCK];
    let error = loop {
        let result = if direction == Direction::Upload {
            stream.write(&buf).await
        } else {
            stream.read(&mut buf).await
        };
        match result {
            Ok(0) => break "iperf3 data connection closed".to_string(),
            Ok(n) => counter.set(counter.get().saturating_add(n as u64)),
            Err(e) => break format!("data transfer failed: {e}"),
        }
    };
    failure.borrow_mut().get_or_insert(error);
    failed.notify_one();
}

/// iperf3 给流编号的方式（iperf_add_stream）：第一条是 1，之后依次 3、4、5……（没有 2，
/// 为兼容旧版多流测试保留至今）。结果交换按这个 id 匹配，编号不对服务端会报 invalid id。
fn stream_id(index: usize) -> usize {
    if index == 0 {
        1
    } else {
        index + 2
    }
}

fn parse_threads(req: &Value) -> Result<usize, String> {
    match req.get("threads") {
        None | Some(Value::Null) => Ok(1),
        Some(value) => match value.as_u64() {
            Some(n) if (1..=MAX_THREADS).contains(&n) => Ok(n as usize),
            _ => Err(format!("threads must be between 1 and {MAX_THREADS}")),
        },
    }
}

async fn expect_state(stream: &mut BoxStream, expected: u8) -> Result<(), String> {
    let mut state = [0_u8; 1];
    timeout_read(stream, &mut state).await?;
    if state[0] != expected {
        return Err(format!(
            "unexpected iperf3 state {}; expected {expected}",
            state[0]
        ));
    }
    Ok(())
}

async fn write_all_timeout(stream: &mut BoxStream, bytes: &[u8]) -> Result<(), String> {
    tokio::time::timeout(CONNECT_TIMEOUT, stream.write_all(bytes))
        .await
        .map_err(|_| "iperf3 write timed out".to_string())?
        .map_err(|e| format!("iperf3 write failed: {e}"))
}

async fn timeout_read(stream: &mut BoxStream, bytes: &mut [u8]) -> Result<(), String> {
    tokio::time::timeout(CONNECT_TIMEOUT, stream.read_exact(bytes))
        .await
        .map_err(|_| "iperf3 read timed out".to_string())?
        .map(|_| ())
        .map_err(|e| format!("iperf3 read failed: {e}"))
}

async fn write_json(stream: &mut BoxStream, value: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if body.is_empty() || body.len() > MAX_JSON {
        return Err("iperf3 control message is too large".into());
    }
    let len = (body.len() as u32).to_be_bytes();
    write_all_timeout(stream, &len).await?;
    write_all_timeout(stream, &body).await
}

async fn read_json(stream: &mut BoxStream) -> Result<Value, String> {
    let mut length = [0_u8; 4];
    timeout_read(stream, &mut length).await?;
    let size = u32::from_be_bytes(length) as usize;
    if size == 0 || size > MAX_JSON {
        return Err("iperf3 control message exceeds limit".into());
    }
    let mut body = vec![0_u8; size];
    timeout_read(stream, &mut body).await?;
    serde_json::from_slice(&body).map_err(|e| format!("invalid iperf3 result: {e}"))
}

fn cookie() -> [u8; 37] {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let text = format!(
        "{:032x}{:04x}",
        now,
        COUNTER.fetch_add(1, Ordering::Relaxed) & 0xffff
    );
    let mut out = [0_u8; 37];
    out[..36].copy_from_slice(&text.as_bytes()[..36]);
    out
}

fn snapshot_json(snapshot: &Snapshot) -> Value {
    json!({
        "status": snapshot.status,
        "server": snapshot.server,
        "outbound": snapshot.outbound,
        "chain": snapshot.chain,
        "direction": snapshot.direction,
        "duration": snapshot.duration,
        "elapsed": snapshot.elapsed,
        "current_mbps": snapshot.current_mbps,
        "average_mbps": snapshot.average_mbps,
        "peak_mbps": snapshot.peak_mbps,
        "bytes": snapshot.bytes,
        "error": snapshot.error,
        "samples": snapshot.samples.iter().map(|s| json!({"elapsed":s.elapsed,"bytes":s.bytes,"mbps":s.mbps})).collect::<Vec<_>>(),
        "phases": snapshot.phases.iter().map(|p| json!({"direction":p.direction,"bytes":p.bytes,"average_mbps":p.average_mbps,"peak_mbps":p.peak_mbps,"server_bytes":p.server_bytes})).collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_is_iperf_size() {
        assert_eq!(cookie().len(), 37);
        assert!(cookie()[..36].iter().all(|b| b.is_ascii_hexdigit()));
    }

    /// 与官方 iperf3 服务端的回环互通；本机没有 `iperf3` 时跳过。
    mod official_server {
        use super::*;
        use oryn_outbound::{DirectDialer, DirectOutbound, Resolver};
        use std::net::IpAddr;
        use std::process::{Child, Command, Stdio};

        struct Loopback;

        #[async_trait::async_trait]
        impl Resolver for Loopback {
            async fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
                Ok(vec![IpAddr::from([127, 0, 0, 1])])
            }
        }

        struct Server(Child);

        impl Drop for Server {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        fn start_server() -> Option<(Server, u16)> {
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .ok()?
                .local_addr()
                .ok()?
                .port();
            let child = Command::new("iperf3")
                .args(["-s", "-1", "-B", "127.0.0.1", "-p", &port.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok()?;
            std::thread::sleep(Duration::from_millis(1500));
            Some((Server(child), port))
        }

        async fn run(direction: Direction, threads: usize) -> Option<Phase> {
            let (_server, port) = start_server()?;
            let leaf: Arc<dyn Outbound> = Arc::new(DirectOutbound::new(
                "DIRECT".into(),
                Arc::new(DirectDialer::new(Arc::new(Loopback))),
            ));
            let snapshot = Rc::new(RefCell::new(Snapshot::new(
                "127.0.0.1".into(),
                "DIRECT".into(),
                vec![],
                direction.as_str().into(),
                2,
            )));
            let phase = run_phase(
                snapshot,
                Rc::new(Cell::new(false)),
                leaf,
                TargetAddr::from_host("127.0.0.1", port),
                direction,
                2,
                threads,
            )
            .await
            .expect("iperf3 phase");
            Some(phase)
        }

        async fn check(direction: Direction, threads: usize) {
            let local = tokio::task::LocalSet::new();
            let Some(phase) = local.run_until(run(direction, threads)).await else {
                eprintln!("iperf3 not installed; skipping");
                return;
            };
            assert!(phase.bytes > 1_000_000, "{phase:?}");
            // 服务端上报的字节数是各流之和，应与客户端汇总同一数量级
            let reported = phase.server_bytes.expect("server bytes");
            assert!(reported > 1_000_000, "{phase:?}");
        }

        #[tokio::test(flavor = "current_thread")]
        async fn single_stream_upload_and_download() {
            check(Direction::Upload, 1).await;
            check(Direction::Download, 1).await;
        }

        #[tokio::test(flavor = "current_thread")]
        async fn eight_streams_upload_and_download() {
            check(Direction::Upload, 8).await;
            check(Direction::Download, 8).await;
        }
    }

    #[test]
    fn stream_ids_follow_iperf3_numbering() {
        let ids: Vec<usize> = (0..5).map(stream_id).collect();
        assert_eq!(ids, [1, 3, 4, 5, 6]);
    }

    #[test]
    fn thread_parameter() {
        assert_eq!(parse_threads(&json!({})), Ok(1));
        assert_eq!(parse_threads(&json!({"threads":8})), Ok(8));
        assert!(parse_threads(&json!({"threads":0})).is_err());
        assert!(parse_threads(&json!({"threads":9})).is_err());
        assert!(parse_threads(&json!({"threads":"8"})).is_err());
    }

    #[test]
    fn direction_parsing() {
        assert_eq!(Direction::parse(Some("down")), Some(Direction::Download));
        assert_eq!(Direction::parse(Some("up")), Some(Direction::Upload));
        assert_eq!(Direction::parse(Some("bad")), None);
    }
}
