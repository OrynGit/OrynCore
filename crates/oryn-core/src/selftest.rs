//! 设备端协议自测。
//!
//! 对配置里的每个节点，经该节点的出站向测试服务（`oryn_test/testbed` 的 testd）测：
//! 连接与首字节延迟、不同包长的 TCP 乒乓延迟、单 / 多流上下行吞吐、突发短连接、
//! UDP 回显（小包 / 大包 / 多会话）与 UDP 上下行洪泛，同时记录扩展进程的内存与 CPU。
//! 只测协议层：直接使用出站，不经 TUN / lwIP。
//!
//! 线格式见 `oryn_test/README.md`。结果按行追加到扩展临时目录里的 `oryn-selftest-<label>.jsonl`，
//! 由 `devicectl device copy from` 拉取；同一份数据也能通过 `selftest_status` 取得。

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use oryn_config::{OutboundKind, TargetAddr};
use oryn_outbound::{resolve, BoxStream, Outbound, PacketConn, PickMeta};
use oryn_router::{FlowContext, Network};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;

use crate::context::EngineCtx;

const PATTERN_SIZE: usize = 4096;
const FRAME: usize = 64 * 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_ROWS: usize = 1024;

fn pattern() -> &'static [u8; PATTERN_SIZE] {
    static P: OnceLock<[u8; PATTERN_SIZE]> = OnceLock::new();
    P.get_or_init(|| {
        let mut out = [0_u8; PATTERN_SIZE];
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for chunk in out.chunks_exact_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            chunk.copy_from_slice(&x.to_le_bytes());
        }
        out
    })
}

/// 校验 `chunk`（流内偏移 `pos` 起）与图样一致，返回不一致的字节数。
fn count_bad(chunk: &[u8], pos: u64) -> u64 {
    let pat = pattern();
    let mut bad = 0;
    let mut off = 0;
    while off < chunk.len() {
        let p = ((pos + off as u64) % PATTERN_SIZE as u64) as usize;
        let take = (PATTERN_SIZE - p).min(chunk.len() - off);
        if chunk[off..off + take] != pat[p..p + take] {
            // 只有出现不一致才逐字节数，常态下是一次整段比较
            bad += chunk[off..off + take]
                .iter()
                .zip(&pat[p..p + take])
                .filter(|(a, b)| a != b)
                .count() as u64;
        }
        off += take;
    }
    bad
}

// ---- 进程资源 ----

#[derive(Clone, Copy, Default)]
struct ProcStat {
    cpu_ms: f64,
    footprint_mb: f64,
}

#[cfg(target_vendor = "apple")]
fn proc_stat() -> ProcStat {
    use std::mem::MaybeUninit;
    // CPU：getrusage 的用户 + 系统时间（微秒）
    let mut usage = MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: 只写入局部结构。
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    let cpu_ms = if rc == 0 {
        // SAFETY: 调用成功后结构已被填充。
        let u = unsafe { usage.assume_init() };
        let micros = |t: libc::timeval| t.tv_sec as f64 * 1e6 + t.tv_usec as f64;
        (micros(u.ru_utime) + micros(u.ru_stime)) / 1000.0
    } else {
        0.0
    };
    // 内存：phys_footprint，与 iOS 的 jetsam 口径一致
    let mut info = MaybeUninit::<libc::rusage_info_v2>::zeroed();
    // SAFETY: 缓冲区足够大，flavor 与结构一致。
    let rc = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V2,
            info.as_mut_ptr().cast::<libc::rusage_info_t>(),
        )
    };
    let footprint_mb = if rc == 0 {
        // SAFETY: 调用成功后结构已被填充。
        unsafe { info.assume_init() }.ri_phys_footprint as f64 / 1_048_576.0
    } else {
        0.0
    };
    ProcStat {
        cpu_ms,
        footprint_mb,
    }
}

#[cfg(not(target_vendor = "apple"))]
fn proc_stat() -> ProcStat {
    ProcStat::default()
}

// ---- 统计 ----

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn rtt_stats(samples: &mut [f64], sent: usize) -> Value {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    json!({
        "sent": sent, "ok": samples.len(),
        "p50_ms": round2(percentile(samples, 0.5)),
        "p95_ms": round2(percentile(samples, 0.95)),
        "max_ms": round2(samples.last().copied().unwrap_or(0.0)),
    })
}

// ---- 配置 ----

#[derive(Clone)]
struct Cfg {
    label: String,
    port: u16,
    direct_host: String,
    proxy_host: String,
    secs: u64,
    full: bool,
    include: Vec<String>,
    exclude: Vec<String>,
    limit: usize,
    skip_udp_names: Vec<String>,
    node_timeout: Duration,
    out: PathBuf,
}

impl Cfg {
    fn parse(req: &Value) -> Result<Self, String> {
        let text = |k: &str| {
            req.get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let list = |k: &str| -> Vec<String> {
            req.get(k)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        let direct_host = text("server");
        if direct_host.is_empty() || direct_host.len() > 255 {
            return Err("server is required".into());
        }
        let proxy_host = {
            let t = text("target");
            if t.is_empty() {
                direct_host.clone()
            } else {
                t
            }
        };
        let port = req.get("port").and_then(Value::as_u64).unwrap_or(19000);
        if !(1..=65535).contains(&port) {
            return Err("invalid port".into());
        }
        let label: String = {
            let l = text("label");
            let l = if l.is_empty() { "run".to_string() } else { l };
            l.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(40)
                .collect()
        };
        Ok(Self {
            out: std::env::temp_dir().join(format!("oryn-selftest-{label}.jsonl")),
            label,
            port: port as u16,
            direct_host,
            proxy_host,
            secs: req
                .get("secs")
                .and_then(Value::as_u64)
                .unwrap_or(4)
                .clamp(1, 20),
            full: req.get("mode").and_then(Value::as_str) != Some("quick"),
            include: list("include"),
            exclude: list("exclude"),
            limit: req.get("limit").and_then(Value::as_u64).unwrap_or(1000) as usize,
            skip_udp_names: list("skip_udp"),
            node_timeout: Duration::from_secs(
                req.get("node_timeout")
                    .and_then(Value::as_u64)
                    .unwrap_or(150)
                    .clamp(20, 600),
            ),
        })
    }

    fn selected(&self, name: &str) -> bool {
        (self.include.is_empty() || self.include.iter().any(|s| name.contains(s.as_str())))
            && !self.exclude.iter().any(|s| name.contains(s.as_str()))
    }
}

// ---- 管理器 ----

struct Run {
    status: String,
    label: String,
    total: usize,
    done: usize,
    current: String,
    started: Instant,
    error: Option<String>,
    rows: Vec<Value>,
    out: PathBuf,
}

#[derive(Default)]
pub struct Manager {
    current: RefCell<Option<Rc<RefCell<Run>>>>,
    cancel: RefCell<Option<Rc<Cell<bool>>>>,
    task: RefCell<Option<tokio::task::JoinHandle<()>>>,
}

impl Manager {
    pub fn cancel(&self, reason: &str) {
        if let Some(flag) = self.cancel.borrow_mut().take() {
            flag.set(true);
        }
        if let Some(task) = self.task.borrow_mut().take() {
            task.abort();
        }
        if let Some(run) = self.current.borrow().as_ref() {
            let mut run = run.borrow_mut();
            if run.status == "running" {
                run.status = "cancelled".into();
                run.error = Some(reason.to_string());
            }
        }
    }

    fn running(&self) -> bool {
        self.current
            .borrow()
            .as_ref()
            .is_some_and(|r| r.borrow().status == "running")
    }

    fn snapshot(&self, from: usize) -> Value {
        let Some(run) = self.current.borrow().as_ref().cloned() else {
            return json!({"status":"idle"});
        };
        let run = run.borrow();
        let rows: Vec<&Value> = run.rows.iter().skip(from).collect();
        json!({
            "status": run.status, "label": run.label, "total": run.total, "done": run.done,
            "current": run.current, "elapsed_s": round2(run.started.elapsed().as_secs_f64()),
            "error": run.error, "out": run.out.display().to_string(), "from": from, "rows": rows,
        })
    }
}

pub fn command(ctx: &Rc<EngineCtx>, req: &Value) -> Value {
    match req.get("cmd").and_then(Value::as_str).unwrap_or("") {
        "selftest_start" => start(ctx, req),
        "selftest_status" => {
            let from = req.get("from").and_then(Value::as_u64).unwrap_or(0) as usize;
            ctx.selftest.snapshot(from)
        }
        "selftest_stop" => {
            ctx.selftest.cancel("stopped by user");
            ctx.selftest.snapshot(0)
        }
        _ => json!({"error":"unknown selftest command"}),
    }
}

struct Node {
    name: String,
    kind: &'static str,
    leaf: Arc<dyn Outbound>,
    chain: Vec<String>,
    is_direct: bool,
}

fn collect_nodes(ctx: &Rc<EngineCtx>, cfg: &Cfg) -> Result<Vec<Node>, String> {
    let state = ctx.state();
    let mut nodes = Vec::new();
    for spec in &state.config.outbounds {
        if matches!(spec.kind, OutboundKind::Group(_) | OutboundKind::Reject) {
            continue;
        }
        let is_direct = matches!(spec.kind, OutboundKind::Direct);
        if !is_direct && !cfg.selected(&spec.name) {
            continue;
        }
        let Some(index) = state.config.outbound_index(&spec.name) else {
            continue;
        };
        let target = TargetAddr::from_host(&cfg.proxy_host, cfg.port);
        let destination = format!("0.0.0.0:{}", cfg.port)
            .parse()
            .map_err(|_| "invalid destination".to_string())?;
        let mut flow = FlowContext::new(0, Network::Tcp, "0.0.0.0:0".parse().unwrap(), destination);
        let Some(decision) = state.router().route_explicit(&mut flow, index) else {
            continue;
        };
        let Some(start) = state.routing.outbounds.get(decision.outbound).cloned() else {
            continue;
        };
        let meta = PickMeta {
            source: None,
            target: &target,
            network: Network::Tcp,
        };
        let Some(resolved) = resolve(&start, &meta) else {
            continue;
        };
        nodes.push(Node {
            name: spec.name.clone(),
            kind: spec.kind.type_name(),
            leaf: resolved.leaf,
            chain: resolved.chain,
            is_direct,
        });
        if nodes.len() > cfg.limit {
            break;
        }
    }
    // DIRECT 作为基线放在最前面
    nodes.sort_by_key(|n| !n.is_direct);
    Ok(nodes)
}

fn start(ctx: &Rc<EngineCtx>, req: &Value) -> Value {
    if ctx.selftest.running() {
        return json!({"error":"a selftest is already running"});
    }
    let cfg = match Cfg::parse(req) {
        Ok(c) => c,
        Err(e) => return json!({"error": e}),
    };
    let nodes = match collect_nodes(ctx, &cfg) {
        Ok(n) if !n.is_empty() => n,
        Ok(_) => return json!({"error":"no node matches"}),
        Err(e) => return json!({"error": e}),
    };
    let _ = std::fs::write(&cfg.out, b"");
    let run = Rc::new(RefCell::new(Run {
        status: "running".into(),
        label: cfg.label.clone(),
        total: nodes.len(),
        done: 0,
        current: String::new(),
        started: Instant::now(),
        error: None,
        rows: Vec::new(),
        out: cfg.out.clone(),
    }));
    let cancel = Rc::new(Cell::new(false));
    *ctx.selftest.current.borrow_mut() = Some(run.clone());
    *ctx.selftest.cancel.borrow_mut() = Some(cancel.clone());
    let manager = Rc::downgrade(&ctx.selftest);
    let task = tokio::task::spawn_local(async move {
        for node in nodes {
            if cancel.get() {
                break;
            }
            run.borrow_mut().current = node.name.clone();
            let row = match tokio::time::timeout(cfg.node_timeout, test_node(&cfg, &node)).await {
                Ok(row) => row,
                Err(_) => json!({"name": node.name, "type": node.kind, "status": "timeout",
                    "error": format!("node test exceeded {} s", cfg.node_timeout.as_secs())}),
            };
            append_line(&cfg.out, &row);
            let mut r = run.borrow_mut();
            r.done += 1;
            if r.rows.len() < MAX_ROWS {
                r.rows.push(row);
            }
        }
        {
            let mut r = run.borrow_mut();
            if r.status == "running" {
                r.status = if cancel.get() {
                    "cancelled"
                } else {
                    "completed"
                }
                .into();
            }
            r.current.clear();
        }
        append_line(
            &cfg.out,
            &json!({"summary": true, "done": run.borrow().done}),
        );
        if let Some(m) = manager.upgrade() {
            m.cancel.borrow_mut().take();
            m.task.borrow_mut().take();
        }
    });
    *ctx.selftest.task.borrow_mut() = Some(task);
    ctx.selftest.snapshot(0)
}

fn append_line(path: &PathBuf, row: &Value) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{row}");
    }
}

// ---- 单个节点 ----

struct Env {
    leaf: Arc<dyn Outbound>,
    target: TargetAddr,
    secs: u64,
    full: bool,
}

async fn test_node(cfg: &Cfg, node: &Node) -> Value {
    let host = if node.is_direct {
        &cfg.direct_host
    } else {
        &cfg.proxy_host
    };
    let env = Rc::new(Env {
        leaf: node.leaf.clone(),
        target: TargetAddr::from_host(host, cfg.port),
        secs: cfg.secs,
        full: cfg.full,
    });
    let started = Instant::now();
    let before = proc_stat();
    // 采样峰值内存
    let peak = Rc::new(Cell::new(before.footprint_mb));
    let stop = Rc::new(Cell::new(false));
    let sampler = {
        let (peak, stop) = (peak.clone(), stop.clone());
        tokio::task::spawn_local(async move {
            while !stop.get() {
                peak.set(peak.get().max(proc_stat().footprint_mb));
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
    };

    let mut row = Map::new();
    row.insert("name".into(), json!(node.name));
    row.insert("type".into(), json!(node.kind));
    if node.chain.len() > 1 {
        row.insert("chain".into(), json!(node.chain));
    }
    let mut failures: Vec<String> = Vec::new();
    let mieru_before = oryn_outbound::mieru_counters();

    macro_rules! step {
        ($key:expr, $fut:expr) => {{
            let v: Result<Value, String> = $fut.await;
            match v {
                Ok(v) => {
                    row.insert($key.into(), v);
                }
                Err(e) => {
                    failures.push(format!("{}: {}", $key, e));
                    row.insert($key.into(), json!({"error": e}));
                }
            }
        }};
    }

    // 连接与首字节：失败就不再继续，避免对不通的节点空等
    let connect = t_connect(&env).await;
    let alive = connect.is_ok();
    match connect {
        Ok(v) => {
            row.insert("connect".into(), v);
        }
        Err(e) => {
            failures.push(format!("connect: {e}"));
            row.insert("connect".into(), json!({"error": e}));
        }
    }
    if alive {
        step!("tcp_rtt", t_pingpong(&env));
        step!("tcp_down1", t_down(&env, 1));
        step!("tcp_up1", t_up(&env, 1));
        if env.full {
            step!("tcp_down4", t_down(&env, 4));
            step!("tcp_up4", t_up(&env, 4));
            step!("tcp_down16", t_down(&env, 16));
        } else {
            step!("tcp_down4", t_down(&env, 4));
        }
        step!("tcp_burst", t_burst(&env, if env.full { 64 } else { 24 }));
        let udp_skipped = cfg
            .skip_udp_names
            .iter()
            .any(|s| node.name.contains(s.as_str()));
        if !udp_skipped {
            let echo = t_udp_echo(&env).await;
            // 出站按设计不支持 UDP（HTTP 代理、带插件的 Shadowsocks 等）：不算失败，也不再跑后面的 UDP 项
            let unsupported = matches!(&echo, Err(e)
                if e.contains("does not support UDP") || e.contains("UDP is not enabled"));
            if unsupported {
                row.insert("udp".into(), json!("unsupported by design"));
            } else {
                step!("udp_echo", async { echo });
                step!("udp_big", t_udp_big(&env));
                step!("udp_multi", t_udp_multi(&env, 8));
                step!("udp_down", t_udp_flood_down(&env));
                step!("udp_up", t_udp_flood_up(&env));
            }
        }
    }

    stop.set(true);
    let _ = sampler.await;
    let mieru_after = oryn_outbound::mieru_counters();
    if mieru_after != mieru_before {
        // Mieru UDP 会话的收发统计（增量）：数据报数、窗口外丢弃、重复、重传
        let d = |i: usize| mieru_after[i].saturating_sub(mieru_before[i]);
        row.insert(
            "diag_mieru".into(),
            json!({"rx_frames": d(0), "dropped_outside_window": d(1), "duplicates": d(2), "retransmits": d(3), "window_updates": d(4)}),
        );
    }
    let after = proc_stat();
    row.insert(
        "proc".into(),
        json!({
            "cpu_ms": round2(after.cpu_ms - before.cpu_ms),
            "footprint_before_mb": round2(before.footprint_mb),
            "footprint_after_mb": round2(after.footprint_mb),
            "footprint_peak_mb": round2(peak.get()),
        }),
    );
    row.insert(
        "seconds".into(),
        json!(round2(started.elapsed().as_secs_f64())),
    );
    row.insert(
        "status".into(),
        json!(if !alive {
            "fail"
        } else if failures.is_empty() {
            "ok"
        } else {
            "partial"
        }),
    );
    if !failures.is_empty() {
        row.insert("errors".into(), json!(failures));
    }
    Value::Object(row)
}

// ---- TCP ----

async fn open(env: &Env, mode: u8) -> Result<BoxStream, String> {
    let mut s = tokio::time::timeout(STEP_TIMEOUT, env.leaf.connect_tcp(&env.target))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect: {e}"))?;
    s.write_all(&[mode])
        .await
        .map_err(|e| format!("write: {e}"))?;
    // 有些出站（如 VMess）把写入缓在内部，直到 flush 才发出；真实转发路径每次写完都会 flush
    s.flush().await.map_err(|e| format!("write: {e}"))?;
    Ok(s)
}

async fn t_connect(env: &Env) -> Result<Value, String> {
    let mut times = Vec::new();
    let mut first_error = None;
    for attempt in 0..5 {
        let t0 = Instant::now();
        let result = async {
            let mut s = open(env, b'E').await?;
            s.write_all(b"x").await.map_err(|e| e.to_string())?;
            s.flush().await.map_err(|e| e.to_string())?;
            let mut b = [0_u8; 1];
            tokio::time::timeout(STEP_TIMEOUT, s.read_exact(&mut b))
                .await
                .map_err(|_| "first byte timed out".to_string())?
                .map_err(|e| format!("read: {e}"))?;
            Ok::<_, String>(())
        }
        .await;
        match result {
            Ok(()) => times.push(t0.elapsed().as_secs_f64() * 1000.0),
            Err(e) => {
                first_error.get_or_insert(e);
                // 开头两次都失败就不再重试，避免坏节点把整轮矩阵拖慢
                if times.is_empty() && attempt >= 1 {
                    break;
                }
            }
        }
    }
    if times.is_empty() {
        return Err(first_error.unwrap_or_else(|| "no successful connection".into()));
    }
    let first = times[0];
    let mut v = rtt_stats(&mut times, 5);
    v["first_ms"] = json!(round2(first));
    if let Some(e) = first_error {
        v["error"] = json!(e);
    }
    Ok(v)
}

async fn t_pingpong(env: &Env) -> Result<Value, String> {
    let mut s = open(env, b'E').await?;
    let mut out = Map::new();
    for (size, count) in [(64_usize, 60_usize), (1024, 40), (16 * 1024, 20)] {
        let mut buf = vec![0_u8; size];
        let mut rtts = Vec::new();
        let mut error = None;
        for i in 0..count {
            buf.iter_mut()
                .enumerate()
                .for_each(|(k, b)| *b = (k + i) as u8);
            let t0 = Instant::now();
            let mut back = vec![0_u8; size];
            let r = tokio::time::timeout(STEP_TIMEOUT, async {
                s.write_all(&buf).await?;
                s.flush().await?;
                s.read_exact(&mut back).await.map(|_| ())
            })
            .await;
            match r {
                Ok(Ok(())) if back == buf => rtts.push(t0.elapsed().as_secs_f64() * 1000.0),
                Ok(Ok(())) => {
                    error = Some("echo mismatch".to_string());
                    break;
                }
                Ok(Err(e)) => {
                    error = Some(e.to_string());
                    break;
                }
                Err(_) => {
                    error = Some("timed out".to_string());
                    break;
                }
            }
        }
        let mut v = rtt_stats(&mut rtts, count);
        if let Some(e) = error {
            v["error"] = json!(e);
        }
        out.insert(size.to_string(), v);
    }
    Ok(Value::Object(out))
}

struct Flow {
    bytes: u64,
    bad: u64,
    first_byte_ms: f64,
    error: Option<String>,
    /// 上传：写循环结束时已被写入（尚不一定到达服务端）的字节数与用时
    written: u64,
    write_s: f64,
    /// 上传：每次 write + flush 的耗时统计，用来看发送路径有没有周期性停顿
    writes: u32,
    write_max_ms: f64,
    writes_over_100ms: u32,
}

async fn down_one(env: Rc<Env>, secs: u64) -> Flow {
    let mut flow = Flow {
        bytes: 0,
        bad: 0,
        first_byte_ms: 0.0,
        error: None,
        written: 0,
        write_s: 0.0,
        writes: 0,
        write_max_ms: 0.0,
        writes_over_100ms: 0,
    };
    let t0 = Instant::now();
    let mut s = match open(&env, b'D').await {
        Ok(s) => s,
        Err(e) => {
            flow.error = Some(e);
            return flow;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut buf = vec![0_u8; 128 * 1024];
    let mut pos = 0_u64;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(
            left.max(Duration::from_millis(50)).min(STEP_TIMEOUT),
            s.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => {
                flow.error = Some("closed by server".into());
                break;
            }
            Ok(Ok(n)) => {
                if flow.first_byte_ms == 0.0 {
                    flow.first_byte_ms = t0.elapsed().as_secs_f64() * 1000.0;
                }
                flow.bad += count_bad(&buf[..n], pos);
                pos += n as u64;
                flow.bytes += n as u64;
            }
            Ok(Err(e)) => {
                flow.error = Some(e.to_string());
                break;
            }
            Err(_) => break,
        }
    }
    flow
}

async fn t_down(env: &Rc<Env>, streams: usize) -> Result<Value, String> {
    let secs = env.secs;
    let mut set = JoinSet::new();
    let t0 = Instant::now();
    for _ in 0..streams {
        set.spawn_local(down_one(env.clone(), secs));
    }
    let mut flows = Vec::new();
    while let Some(r) = set.join_next().await {
        flows.push(r.map_err(|e| e.to_string())?);
    }
    summarize_flows(flows, t0.elapsed().as_secs_f64().max(0.001), streams)
}

async fn up_one(env: Rc<Env>, secs: u64) -> Flow {
    let mut flow = Flow {
        bytes: 0,
        bad: 0,
        first_byte_ms: 0.0,
        error: None,
        written: 0,
        write_s: 0.0,
        writes: 0,
        write_max_ms: 0.0,
        writes_over_100ms: 0,
    };
    let mut s = match open(&env, b'U').await {
        Ok(s) => s,
        Err(e) => {
            flow.error = Some(e);
            return flow;
        }
    };
    let mut frame = vec![0_u8; 4 + FRAME];
    frame[..4].copy_from_slice(&(FRAME as u32).to_be_bytes());
    for (i, b) in frame[4..].iter_mut().enumerate() {
        *b = pattern()[i % PATTERN_SIZE];
    }
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let sent = async {
            s.write_all(&frame).await?;
            s.flush().await
        };
        let w0 = Instant::now();
        let outcome = tokio::time::timeout(STEP_TIMEOUT, sent).await;
        let took = w0.elapsed().as_secs_f64() * 1000.0;
        flow.writes += 1;
        flow.write_max_ms = flow.write_max_ms.max(took);
        if took > 100.0 {
            flow.writes_over_100ms += 1;
        }
        match outcome {
            Ok(Ok(())) => flow.bytes += FRAME as u64,
            Ok(Err(e)) => {
                flow.error = Some(format!("write: {e}"));
                break;
            }
            Err(_) => {
                flow.error = Some("write timed out".into());
                break;
            }
        }
    }
    flow.written = flow.bytes;
    flow.write_s = t0.elapsed().as_secs_f64();
    if flow.error.is_none() {
        let _ = s.write_all(&0_u32.to_be_bytes()).await;
        let _ = s.flush().await;
        let mut ack = [0_u8; 16];
        match tokio::time::timeout(Duration::from_secs(20), s.read_exact(&mut ack)).await {
            Ok(Ok(_)) => {
                let total = u64::from_be_bytes(ack[..8].try_into().unwrap());
                let bad = u64::from_be_bytes(ack[8..].try_into().unwrap());
                flow.bytes = total; // 以服务端确认的字节数为准
                flow.bad = bad;
                flow.first_byte_ms = t0.elapsed().as_secs_f64() * 1000.0; // 用作「到收到确认的总时间」
            }
            Ok(Err(e)) => flow.error = Some(format!("ack: {e}")),
            Err(_) => flow.error = Some("ack timed out".into()),
        }
    }
    flow
}

async fn t_up(env: &Rc<Env>, streams: usize) -> Result<Value, String> {
    let secs = env.secs;
    let mut set = JoinSet::new();
    let t0 = Instant::now();
    for _ in 0..streams {
        set.spawn_local(up_one(env.clone(), secs));
    }
    let mut flows = Vec::new();
    while let Some(r) = set.join_next().await {
        flows.push(r.map_err(|e| e.to_string())?);
    }
    // 上传按「开始 → 最后一个确认」计时，这样不会高估
    summarize_flows(flows, t0.elapsed().as_secs_f64().max(0.001), streams)
}

fn summarize_flows(flows: Vec<Flow>, elapsed: f64, streams: usize) -> Result<Value, String> {
    let bytes: u64 = flows.iter().map(|f| f.bytes).sum();
    let bad: u64 = flows.iter().map(|f| f.bad).sum();
    let errors: Vec<String> = flows.iter().filter_map(|f| f.error.clone()).collect();
    let ok = flows
        .iter()
        .filter(|f| f.error.is_none() && f.bytes > 0)
        .count();
    if ok == 0 {
        return Err(errors
            .first()
            .cloned()
            .unwrap_or_else(|| "no data transferred".into()));
    }
    let first_ms = flows
        .iter()
        .filter(|f| f.first_byte_ms > 0.0)
        .map(|f| f.first_byte_ms)
        .fold(f64::MAX, f64::min);
    let mut v = json!({
        "streams": streams, "ok_streams": ok,
        "mbps": round2(bytes as f64 * 8.0 / 1e6 / elapsed),
        "mib": round2(bytes as f64 / 1_048_576.0),
        "seconds": round2(elapsed),
        "first_ms": round2(if first_ms == f64::MAX { 0.0 } else { first_ms }),
    });
    // 上传的写入阶段与等确认阶段分开报告：写得快、确认很晚说明数据积压在发送路径里（缓冲或慢速链路），
    // 总吞吐 = 服务端收到的字节 ÷ 总用时，只看总数会把两种情况混在一起
    let written: u64 = flows.iter().map(|f| f.written).sum();
    if written > 0 {
        let write_s = flows.iter().map(|f| f.write_s).fold(0.0, f64::max);
        v["written_mib"] = json!(round2(written as f64 / 1_048_576.0));
        v["write_seconds"] = json!(round2(write_s));
        v["write_mbps"] = json!(round2(written as f64 * 8.0 / 1e6 / write_s.max(0.001)));
        v["writes"] = json!(flows.iter().map(|f| f.writes).sum::<u32>());
        v["write_max_ms"] = json!(round2(
            flows.iter().map(|f| f.write_max_ms).fold(0.0, f64::max)
        ));
        v["writes_over_100ms"] = json!(flows.iter().map(|f| f.writes_over_100ms).sum::<u32>());
    }
    if bad > 0 {
        v["corrupt_bytes"] = json!(bad);
    }
    if !errors.is_empty() {
        v["errors"] = json!(errors.into_iter().take(3).collect::<Vec<_>>());
    }
    Ok(v)
}

async fn t_burst(env: &Rc<Env>, n: usize) -> Result<Value, String> {
    let mut set = JoinSet::new();
    let t0 = Instant::now();
    for i in 0..n {
        let env = env.clone();
        set.spawn_local(async move {
            let t = Instant::now();
            let r = async {
                let mut s = open(&env, b'E').await?;
                let msg: Vec<u8> = (0..1024).map(|k| (k + i) as u8).collect();
                s.write_all(&msg).await.map_err(|e| e.to_string())?;
                s.flush().await.map_err(|e| e.to_string())?;
                let mut back = vec![0_u8; 1024];
                tokio::time::timeout(STEP_TIMEOUT, s.read_exact(&mut back))
                    .await
                    .map_err(|_| "timed out".to_string())?
                    .map_err(|e| e.to_string())?;
                if back != msg {
                    return Err("mismatch".to_string());
                }
                Ok(())
            }
            .await;
            (r, t.elapsed().as_secs_f64() * 1000.0)
        });
    }
    let mut times = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    while let Some(r) = set.join_next().await {
        match r {
            Ok((Ok(()), ms)) => times.push(ms),
            Ok((Err(e), _)) => errors.push(e),
            Err(e) => errors.push(e.to_string()),
        }
    }
    let ok = times.len();
    let mut v = rtt_stats(&mut times, n);
    v["total_s"] = json!(round2(t0.elapsed().as_secs_f64()));
    if !errors.is_empty() {
        errors.sort();
        errors.dedup();
        v["errors"] = json!(errors.into_iter().take(3).collect::<Vec<_>>());
    }
    if ok == 0 {
        return Err(v["errors"][0]
            .as_str()
            .unwrap_or("all connections failed")
            .to_string());
    }
    Ok(v)
}

// ---- UDP ----

async fn bind(env: &Env) -> Result<Box<dyn PacketConn>, String> {
    tokio::time::timeout(STEP_TIMEOUT, env.leaf.bind_udp(&env.target))
        .await
        .map_err(|_| "udp bind timed out".to_string())?
        .map_err(|e| format!("udp bind: {e}"))
}

/// 洪泛测试的会话号：每次不同，否则服务端按会话号累计的统计会混入上一个节点的数据。
fn session_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    (nanos & 0xffff_0000) | (NEXT.fetch_add(1, Ordering::Relaxed) & 0xffff)
}

fn echo_packet(size: usize, seq: u32) -> Vec<u8> {
    let mut p = vec![0_u8; size.max(5)];
    p[0] = 0x01;
    p[1..5].copy_from_slice(&seq.to_be_bytes());
    for (i, b) in p[5..].iter_mut().enumerate() {
        *b = pattern()[(i + 5) % PATTERN_SIZE];
    }
    p
}

/// 一发一收的回显，连续丢 4 个就判定这个大小不通。
async fn echo_series(pc: &dyn PacketConn, env: &Env, size: usize, count: usize) -> Value {
    let mut rtts = Vec::new();
    let mut buf = vec![0_u8; 65535];
    let mut consecutive = 0;
    let mut sent = 0;
    let mut send_error: Option<String> = None;
    let mut mismatched = 0;
    // 收到了但对不上号的包：记录数量和第一个的长度 / 前几个字节，便于定位格式问题
    let mut recv_error: Option<String> = None;
    let mut stray = 0_u32;
    let mut stray_sample: Option<(usize, String)> = None;
    for seq in 0..count as u32 {
        let pkt = echo_packet(size, seq);
        let t0 = Instant::now();
        sent += 1;
        if let Err(e) = pc.send_to(&pkt, &env.target).await {
            send_error = Some(e.to_string());
            break;
        }
        let got = loop {
            let left = Duration::from_millis(1200).saturating_sub(t0.elapsed());
            if left.is_zero() {
                break false;
            }
            match tokio::time::timeout(left, pc.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) if n == pkt.len() && buf[1..5] == seq.to_be_bytes() => {
                    if buf[..n] != pkt[..] {
                        mismatched += 1;
                    }
                    break true;
                }
                Ok(Ok((n, _))) => {
                    // 迟到的旧包或格式对不上的包
                    stray += 1;
                    if stray_sample.is_none() {
                        let head: Vec<String> = buf[..n.min(12)]
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        stray_sample = Some((n, head.join("")));
                    }
                    continue;
                }
                Ok(Err(e)) => {
                    recv_error.get_or_insert_with(|| e.to_string());
                    break false;
                }
                Err(_) => break false,
            }
        };
        if got {
            rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
            consecutive = 0;
        } else {
            consecutive += 1;
            if consecutive >= 4 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut v = rtt_stats(&mut rtts, sent);
    if let Some(e) = send_error {
        v["send_error"] = json!(e);
    }
    if mismatched > 0 {
        v["mismatch"] = json!(mismatched);
    }
    if let Some(e) = recv_error {
        v["recv_error"] = json!(e);
    }
    if stray > 0 {
        v["stray"] = json!(stray);
        if let Some((n, head)) = stray_sample {
            v["stray_first"] = json!({"len": n, "head": head});
        }
    }
    v
}

async fn t_udp_echo(env: &Rc<Env>) -> Result<Value, String> {
    let pc = bind(env).await?;
    let mut out = Map::new();
    let sizes: &[usize] = if env.full {
        &[64, 512, 1200]
    } else {
        &[64, 1200]
    };
    let mut any = false;
    for &size in sizes {
        let v = echo_series(pc.as_ref(), env, size, 40).await;
        any |= v["ok"].as_u64().unwrap_or(0) > 0;
        out.insert(size.to_string(), v);
    }
    if !any {
        return Err(format!("no UDP echo reply: {}", Value::Object(out)));
    }
    Ok(Value::Object(out))
}

async fn t_udp_big(env: &Rc<Env>) -> Result<Value, String> {
    let pc = bind(env).await?;
    let mut out = Map::new();
    for size in [1400_usize, 1472, 2000, 4000, 8000] {
        let v = echo_series(pc.as_ref(), env, size, 4).await;
        out.insert(size.to_string(), v);
    }
    Ok(Value::Object(out))
}

async fn t_udp_multi(env: &Rc<Env>, sessions: usize) -> Result<Value, String> {
    let mut set = JoinSet::new();
    for _ in 0..sessions {
        let env = env.clone();
        set.spawn_local(async move {
            let pc = bind(&env).await?;
            let v = echo_series(pc.as_ref(), &env, 200, 10).await;
            Ok::<_, String>(v["ok"].as_u64().unwrap_or(0))
        });
    }
    let mut ok_sessions = 0;
    let mut replies = 0;
    let mut errors = Vec::new();
    while let Some(r) = set.join_next().await {
        match r {
            Ok(Ok(n)) => {
                replies += n;
                if n == 10 {
                    ok_sessions += 1;
                }
            }
            Ok(Err(e)) => errors.push(e),
            Err(e) => errors.push(e.to_string()),
        }
    }
    let mut v = json!({"sessions": sessions, "full_sessions": ok_sessions, "replies": replies, "expected": sessions * 10});
    if !errors.is_empty() {
        errors.sort();
        errors.dedup();
        v["errors"] = json!(errors.into_iter().take(3).collect::<Vec<_>>());
    }
    if replies == 0 {
        return Err("no UDP replies from any session".into());
    }
    Ok(v)
}

async fn t_udp_flood_down(env: &Rc<Env>) -> Result<Value, String> {
    let pc = bind(env).await?;
    let sess = session_id();
    let size = 1200_u16;
    let mbps = if env.full { 40.0 } else { 20.0 };
    let pps = mbps * 1e6 / 8.0 / size as f64;
    let secs = env.secs.min(6);
    let count = (pps * secs as f64) as u32;
    let gap_us = (1e6 / pps) as u32;
    let mut req = vec![0x02_u8];
    req.extend_from_slice(&sess.to_be_bytes());
    req.extend_from_slice(&size.to_be_bytes());
    req.extend_from_slice(&count.to_be_bytes());
    req.extend_from_slice(&gap_us.to_be_bytes());
    pc.send_to(&req, &env.target)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let mut seen = vec![false; count as usize];
    let mut received = 0_u32;
    let mut bytes = 0_u64;
    let mut reordered = 0_u32;
    let mut max_seq = 0_u32;
    let mut first: Option<Instant> = None;
    let mut last = Instant::now();
    let hard = Instant::now() + Duration::from_secs(secs + 6);
    let mut buf = vec![0_u8; 65535];
    loop {
        let idle = if first.is_some() {
            Duration::from_millis(1500)
        } else {
            Duration::from_secs(4)
        };
        let left = hard.saturating_duration_since(Instant::now()).min(idle);
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, pc.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n >= 9 && buf[0] == 0x82 && buf[1..5] == sess.to_be_bytes() => {
                let seq = u32::from_be_bytes(buf[5..9].try_into().unwrap());
                if (seq as usize) < seen.len() && !seen[seq as usize] {
                    seen[seq as usize] = true;
                    received += 1;
                    bytes += n as u64;
                    if seq < max_seq {
                        reordered += 1;
                    }
                    max_seq = max_seq.max(seq);
                    first.get_or_insert_with(Instant::now);
                    last = Instant::now();
                    if received == count {
                        break;
                    }
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }
    if received == 0 {
        return Err("no UDP flood packets received".into());
    }
    let span = last
        .duration_since(first.unwrap_or(last))
        .as_secs_f64()
        .max(0.001);
    Ok(json!({
        "target_mbps": mbps, "sent": count, "received": received,
        "loss_pct": round2(100.0 * (1.0 - received as f64 / count as f64)),
        "mbps": round2(bytes as f64 * 8.0 / 1e6 / span),
        "reordered": reordered,
    }))
}

async fn t_udp_flood_up(env: &Rc<Env>) -> Result<Value, String> {
    let pc = bind(env).await?;
    let sess = session_id();
    let size = 1200_usize;
    let mbps = if env.full { 40.0 } else { 20.0 };
    let pps = mbps * 1e6 / 8.0 / size as f64;
    let secs = env.secs.min(6);
    let count = (pps * secs as f64) as u32;
    let gap = Duration::from_secs_f64(1.0 / pps);
    let mut pkt = vec![0_u8; size];
    pkt[0] = 0x03;
    pkt[1..5].copy_from_slice(&sess.to_be_bytes());
    let t0 = Instant::now();
    let mut next = t0;
    let mut send_errors = 0;
    for seq in 0..count {
        pkt[5..9].copy_from_slice(&seq.to_be_bytes());
        if pc.send_to(&pkt, &env.target).await.is_err() {
            send_errors += 1;
        }
        next += gap;
        let now = Instant::now();
        if next > now {
            tokio::time::sleep(next - now).await;
        }
    }
    let send_secs = t0.elapsed().as_secs_f64().max(0.001);
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut query = vec![0x04_u8];
    query.extend_from_slice(&sess.to_be_bytes());
    let mut buf = vec![0_u8; 2048];
    for _ in 0..4 {
        let _ = pc.send_to(&query, &env.target).await;
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(1500), pc.recv_from(&mut buf)).await
        {
            if n >= 21 && buf[0] == 0x84 {
                let got = u32::from_be_bytes(buf[5..9].try_into().unwrap());
                let got_bytes = u64::from_be_bytes(buf[9..17].try_into().unwrap());
                return Ok(json!({
                    "target_mbps": mbps, "sent": count, "received_by_server": got,
                    "loss_pct": round2(100.0 * (1.0 - got as f64 / count as f64)),
                    "mbps": round2(got_bytes as f64 * 8.0 / 1e6 / send_secs),
                    "send_errors": send_errors,
                }));
            }
        }
    }
    Err("no UDP stats reply".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_matches_the_server_generator() {
        // testd 里同一个 xorshift 序列的前 8 字节（小端），防止两端图样悄悄漂移
        let p = pattern();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        assert_eq!(&p[..8], &x.to_le_bytes());
    }

    #[test]
    fn corruption_is_counted_across_segment_boundaries() {
        let p = pattern();
        let mut chunk: Vec<u8> = (0..10_000).map(|i| p[i % PATTERN_SIZE]).collect();
        assert_eq!(count_bad(&chunk, 0), 0);
        chunk[4100] ^= 1;
        assert_eq!(count_bad(&chunk, 0), 1);
        // 偏移不是 4096 倍数时按流位置对齐
        let shifted: Vec<u8> = (100..3000).map(|i| p[i % PATTERN_SIZE]).collect();
        assert_eq!(count_bad(&shifted, 100), 0);
    }

    #[test]
    fn percentiles_are_stable() {
        let mut v = vec![5.0, 1.0, 3.0, 2.0, 4.0];
        let s = rtt_stats(&mut v, 5);
        assert_eq!(s["p50_ms"], json!(3.0));
        assert_eq!(s["max_ms"], json!(5.0));
    }

    #[test]
    fn config_requires_a_server() {
        assert!(Cfg::parse(&json!({})).is_err());
        let cfg = Cfg::parse(
            &json!({"server":"10.0.0.1","target":"127.0.0.1","include":["xray"],"label":"a/b c"}),
        )
        .unwrap();
        assert_eq!(cfg.label, "abc");
        assert!(cfg.selected("xray vless"));
        assert!(!cfg.selected("sing-box vless"));
    }
}
