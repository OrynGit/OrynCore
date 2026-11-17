//! 经选定出站运行的有界 HTTP 网络测试。
//!
//! 测试只测应用层请求到 Cloudflare / Ookla / 中国大陆 CDN 的吞吐，不复用普通流量的规则决策。
//! 选定的策略组在任务开始时解析一次，发现请求和上下行请求都使用同一个叶子出站。
//!
//! 隧道未连接时主 App 用 `OrynApp/Services/DirectNetworkTest.swift` 直连运行，来源、目录（含
//! `china_cdn.json`）、校验与上限改动时需同步。

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use oryn_config::TargetAddr;
use oryn_http::Connector;

mod conn;
mod discovery;
mod meter;
use discovery::Server;
use meter::Meter;
use oryn_outbound::{resolve, BoxStream, Outbound, PickMeta};
use oryn_router::{FlowContext, Network};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

use crate::context::EngineCtx;

/// 计量与决策的时间片；每方向最多 `meter::MAX_TICKS` 片（15 秒）。
const TICK: Duration = Duration::from_millis(500);
const MAX_PHASE: Duration = Duration::from_millis(500 * meter::MAX_TICKS as u64);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const DISCOVERY_MAX_BODY: usize = 128 * 1024;
/// 不限速时每个上传请求的正文；下载大小见 `Server::max_download`。连接保持复用，
/// 请求越大，请求之间的空隙占比越小。正文由零块循环写出，不按大小分配内存。
const UPLOAD_BYTES: usize = 16 * 1024 * 1024;
/// 每条连接每方向最多 128 个请求；时长另有 15 秒上限，方向结束时在途请求直接中止。
const MAX_REQUESTS: usize = 128;
/// 一条连接连续失败这么多次才让整个测试失败；之前每次失败都换新连接重试（服务端限流、
/// 主动断开空闲或长连接时常见），与 Speedtest 容忍个别连接失败的做法一致。
const MAX_CONSECUTIVE_FAILURES: usize = 3;
/// 上传请求的起始大小与目标耗时：每个请求按上一个请求的实际速率调整到约 2 秒，
/// 让等待确认的往返只占很小比例，同时确认足够频繁（上传在确认后才计入读数）。
const UPLOAD_START_BYTES: usize = 256 * 1024;
const UPLOAD_TARGET: Duration = Duration::from_secs(2);
const RETRY_DELAY: Duration = Duration::from_millis(200);

/// 每个请求各自得到 Router 的显式决定，整次测试固定到同一叶节点。
#[derive(Clone)]
struct TestConnector {
    routing: Arc<oryn_dns::Routing>,
    index: usize,
    leaf: Arc<dyn Outbound>,
    limit: Option<(bool, f64)>,
}

#[async_trait::async_trait]
impl Connector for TestConnector {
    async fn connect(&self, host: &str, port: u16) -> io::Result<BoxStream> {
        let mut flow = FlowContext::new(
            0,
            Network::Tcp,
            ([0, 0, 0, 0], 0).into(),
            ([0, 0, 0, 0], port).into(),
        );
        flow.set_domain(host.into(), oryn_router::DomainSource::Explicit);
        self.routing
            .router
            .route_explicit(&mut flow, self.index)
            .ok_or_else(|| io::Error::other("selected outbound is unavailable"))?;
        let stream = self
            .leaf
            .connect_tcp(&TargetAddr::from_host(host, port))
            .await?;
        match self.limit {
            Some((upload, mbps)) => Ok(Box::new(PacedStream {
                stream,
                upload,
                mbps,
                delay: None,
            })),
            None => Ok(stream),
        }
    }
}

/// 包住任意 Connector，在连接读写时即时累计字节：下载计读到的，上传计写出的。
/// 测试服务看到的是 HTTPS 流，计数含少量 TLS / HTTP 头部开销。
#[derive(Clone)]
struct Metered<C> {
    inner: C,
    upload: bool,
    counter: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl<C: Connector> Connector for Metered<C> {
    async fn connect(&self, host: &str, port: u16) -> io::Result<BoxStream> {
        let stream = self.inner.connect(host, port).await?;
        Ok(Box::new(MeteredStream {
            stream,
            upload: self.upload,
            counter: self.counter.clone(),
        }))
    }
}

struct MeteredStream {
    stream: BoxStream,
    upload: bool,
    counter: Arc<AtomicU64>,
}

impl AsyncRead for MeteredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, out);
        if !self.upload {
            let read = out.filled().len() - before;
            self.counter.fetch_add(read as u64, Ordering::Relaxed);
        }
        result
    }
}

impl AsyncWrite for MeteredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
        if let (true, Poll::Ready(Ok(n))) = (self.upload, &result) {
            self.counter.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// TLS 下的有界节流：一次最多 16 KiB，下一次读写前等待本块的速率预算。
struct PacedStream {
    stream: BoxStream,
    upload: bool,
    mbps: f64,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl PacedStream {
    fn ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(delay) = self.delay.as_mut() {
            if delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
        self.delay = None;
        Poll::Ready(())
    }
    fn account(&mut self, bytes: usize) {
        if bytes > 0 {
            self.delay = Some(Box::pin(tokio::time::sleep(Duration::from_secs_f64(
                bytes as f64 * 8.0 / (self.mbps * 1_000_000.0),
            ))));
        }
    }
}

impl AsyncRead for PacedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.upload {
            return Pin::new(&mut self.stream).poll_read(cx, out);
        }
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.ready(cx).is_pending() {
            return Poll::Pending;
        }
        let mut bytes = [0u8; 16 * 1024];
        let len = out.remaining().min(bytes.len());
        let mut part = ReadBuf::new(&mut bytes[..len]);
        match Pin::new(&mut self.stream).poll_read(cx, &mut part) {
            Poll::Ready(Ok(())) => {
                self.account(part.filled().len());
                out.put_slice(part.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for PacedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.upload {
            return Pin::new(&mut self.stream).poll_write(cx, bytes);
        }
        if self.ready(cx).is_pending() {
            return Poll::Pending;
        }
        match Pin::new(&mut self.stream).poll_write(cx, &bytes[..bytes.len().min(16 * 1024)]) {
            Poll::Ready(Ok(n)) => {
                self.account(n);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.upload && self.ready(cx).is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Cloudflare,
    Ookla,
    China,
}

impl Source {
    fn parse(value: Option<&str>) -> Option<Self> {
        match value.unwrap_or("cloudflare").to_ascii_lowercase().as_str() {
            "cloudflare" | "cf" => Some(Self::Cloudflare),
            "ookla" | "speedtest" | "speedtest.net" => Some(Self::Ookla),
            "china" | "cn" => Some(Self::China),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Ookla => "ookla",
            Self::China => "china",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Both,
    Download,
    Upload,
}

impl Direction {
    fn parse(value: Option<&str>) -> Option<Self> {
        match value.unwrap_or("both").to_ascii_lowercase().as_str() {
            "both" | "all" => Some(Self::Both),
            "download" | "down" | "receive" => Some(Self::Download),
            "upload" | "up" | "send" => Some(Self::Upload),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Download => "download",
            Self::Upload => "upload",
        }
    }
}

#[derive(Debug, Clone)]
struct Snapshot {
    status: String,
    source: String,
    outbound: String,
    chain: Vec<String>,
    direction: String,
    /// 每方向的时长上限（秒）；方向可能更早结束。
    duration: u64,
    elapsed: f64,
    /// 当前方向正在使用的连接数。
    connections: usize,
    server: String,
    /// 发现服务器之后才有：id、位置、距离、主机、是否支持上传。
    server_detail: Option<Value>,
    egress_ip: String,
    latency_ms: Option<f64>,
    download_mbps: f64,
    upload_mbps: f64,
    bytes: u64,
    phase: String,
    download_limit_mbps: f64,
    upload_limit_mbps: f64,
    error: Option<String>,
}

impl Snapshot {
    fn new(
        source: Source,
        outbound: String,
        chain: Vec<String>,
        direction: Direction,
        download_limit_mbps: f64,
        upload_limit_mbps: f64,
    ) -> Self {
        Self {
            status: "running".into(),
            source: source.as_str().into(),
            outbound,
            chain,
            direction: direction.as_str().into(),
            duration: MAX_PHASE.as_secs(),
            elapsed: 0.0,
            connections: 0,
            server: match source {
                Source::Cloudflare => "Cloudflare edge".into(),
                Source::Ookla => "Speedtest server".into(),
                Source::China => "China mainland CDN".into(),
            },
            server_detail: None,
            egress_ip: String::new(),
            latency_ms: None,
            download_mbps: 0.0,
            upload_mbps: 0.0,
            bytes: 0,
            phase: "preparing".into(),
            download_limit_mbps,
            upload_limit_mbps,
            error: None,
        }
    }
}

/// 经所选出站获取的服务器列表任务的快照。
#[derive(Debug, Clone)]
struct ServerList {
    status: String,
    source: String,
    outbound: String,
    chain: Vec<String>,
    egress_ip: String,
    servers: Vec<Value>,
    error: Option<String>,
}

impl ServerList {
    fn json(&self) -> Value {
        json!({
            "status": self.status,
            "source": self.source,
            "outbound": self.outbound,
            "chain": self.chain,
            "egress_ip": self.egress_ip,
            "servers": self.servers,
            "error": self.error,
        })
    }
}

#[derive(Default)]
pub struct Manager {
    current: RefCell<Option<Rc<RefCell<Snapshot>>>>,
    cancel: RefCell<Option<Rc<Cell<bool>>>>,
    task: RefCell<Option<JoinHandle<()>>>,
    list: RefCell<Option<Rc<RefCell<ServerList>>>>,
    list_task: RefCell<Option<JoinHandle<()>>>,
}

impl Manager {
    pub fn cancel(&self, reason: &str) {
        self.cancel_list(reason);
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

    fn cancel_list(&self, reason: &str) {
        if let Some(task) = self.list_task.borrow_mut().take() {
            task.abort();
        }
        if let Some(list) = self.list.borrow().as_ref() {
            let mut list = list.borrow_mut();
            if list.status == "running" {
                list.status = "cancelled".into();
                list.error = Some(reason.to_string());
            }
        }
    }

    fn list_snapshot(&self) -> Value {
        match self.list.borrow().as_ref() {
            Some(list) => list.borrow().json(),
            None => json!({"status":"idle","servers":[]}),
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
        "network_test_info" => info(ctx),
        "network_test_status" => ctx.network_test.snapshot(),
        "network_test_stop" => {
            ctx.network_test.cancel("stopped by user");
            ctx.network_test.snapshot()
        }
        "network_test_start" => start(ctx, req),
        "network_test_servers" => start_list(ctx, req),
        "network_test_servers_status" => ctx.network_test.list_snapshot(),
        _ => json!({"error":"unknown network test command"}),
    }
}

fn info(ctx: &Rc<EngineCtx>) -> Value {
    let state = ctx.state();
    let outbounds: Vec<Value> = state
        .config
        .outbounds
        .iter()
        .filter(|o| o.kind.type_name() != "reject" && o.name != "GLOBAL")
        .map(|o| json!({"name": o.name, "type": o.kind.type_name()}))
        .collect();
    let default_outbound = state
        .config
        .outbounds
        .iter()
        .filter(|o| o.name != "GLOBAL")
        .find(|o| {
            matches!(
                o.kind.type_name(),
                "select" | "url-test" | "fallback" | "load-balance"
            )
        })
        .map(|o| o.name.clone())
        .unwrap_or_else(|| "DIRECT".into());
    json!({"outbounds": outbounds, "default_outbound": default_outbound})
}

fn start(ctx: &Rc<EngineCtx>, req: &Value) -> Value {
    if ctx
        .network_test
        .current
        .borrow()
        .as_ref()
        .is_some_and(|s| s.borrow().status == "running")
    {
        return json!({"error":"a network test is already running"});
    }
    let source = match Source::parse(req.get("source").and_then(Value::as_str)) {
        Some(source) => source,
        None => return json!({"error":"source must be cloudflare, ookla or china"}),
    };
    let direction = match Direction::parse(req.get("direction").and_then(Value::as_str)) {
        Some(direction) => direction,
        None => return json!({"error":"direction must be both, download or upload"}),
    };
    if source == Source::China && direction != Direction::Download {
        return json!({"error":"China mainland CDN supports download only"});
    }
    let download_limit_mbps = match parse_limit(req, "download_limit_mbps") {
        Ok(value) => value,
        Err(error) => return json!({"error": error}),
    };
    let upload_limit_mbps = match parse_limit(req, "upload_limit_mbps") {
        Ok(value) => value,
        Err(error) => return json!({"error": error}),
    };
    let threads = match parse_threads(req) {
        Ok(value) => value,
        Err(error) => return json!({"error": error}),
    };
    let outbound_name = req
        .get("outbound")
        .and_then(Value::as_str)
        .unwrap_or("DIRECT");
    let choice = match parse_choice(req) {
        Ok(choice) => choice,
        Err(error) => return json!({"error": error}),
    };
    let (connector, chain) = match prepare(ctx, source, outbound_name) {
        Ok(value) => value,
        Err(error) => return json!({"error": error}),
    };
    // 开始测试时放弃仍在进行的列表任务，避免与数据请求争用同一条路径。
    ctx.network_test.cancel_list("a network test started");
    let snapshot = Rc::new(RefCell::new(Snapshot::new(
        source,
        outbound_name.to_string(),
        chain,
        direction,
        download_limit_mbps.unwrap_or(0.0),
        upload_limit_mbps.unwrap_or(0.0),
    )));
    let cancel = Rc::new(Cell::new(false));
    *ctx.network_test.current.borrow_mut() = Some(snapshot.clone());
    *ctx.network_test.cancel.borrow_mut() = Some(cancel.clone());
    let manager = Rc::downgrade(&ctx.network_test);
    let task = tokio::task::spawn_local(async move {
        let result = run_test(
            snapshot.clone(),
            cancel,
            connector,
            source,
            direction,
            (download_limit_mbps, upload_limit_mbps),
            choice,
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
                snapshot.phase = "finished".into();
            }
        } else {
            let mut snapshot = snapshot.borrow_mut();
            snapshot.status = "completed".into();
            snapshot.phase = "finished".into();
        }
        if let Some(manager) = manager.upgrade() {
            manager.cancel.borrow_mut().take();
            manager.task.borrow_mut().take();
        }
    });
    *ctx.network_test.task.borrow_mut() = Some(task);
    ctx.network_test.snapshot()
}

/// 把所选出站（策略组只解析一次）固定为叶子，返回之后所有请求共用的 Connector 与实际链路。
fn prepare(
    ctx: &Rc<EngineCtx>,
    source: Source,
    outbound_name: &str,
) -> Result<(TestConnector, Vec<String>), String> {
    let state = ctx.state();
    let Some(index) = state.config.outbound_index(outbound_name) else {
        return Err(format!("unknown outbound `{outbound_name}`"));
    };
    let target = match source {
        Source::Cloudflare => TargetAddr::from_host("speed.cloudflare.com", 443),
        Source::Ookla => TargetAddr::from_host("www.speedtest.net", 443),
        Source::China => TargetAddr::from_host("myip.ipip.net", 443),
    };
    let destination = "0.0.0.0:443"
        .parse()
        .map_err(|_| "invalid network test destination".to_string())?;
    let mut flow = FlowContext::new(0, Network::Tcp, "0.0.0.0:0".parse().unwrap(), destination);
    let unavailable = || "selected outbound is unavailable".to_string();
    let decision = state
        .router()
        .route_explicit(&mut flow, index)
        .ok_or_else(unavailable)?;
    let start_outbound = state
        .routing
        .outbounds
        .get(decision.outbound)
        .cloned()
        .ok_or_else(unavailable)?;
    let meta = PickMeta {
        source: None,
        target: &target,
        network: Network::Tcp,
    };
    let rejected = || "selected outbound rejected the network test".to_string();
    let resolved = resolve(&start_outbound, &meta).ok_or_else(rejected)?;
    if resolved.leaf.is_reject() {
        return Err(rejected());
    }
    Ok((
        TestConnector {
            routing: state.routing.clone(),
            index,
            leaf: resolved.leaf,
            limit: None,
        },
        resolved.chain,
    ))
}

/// `server` 缺省、空或 `auto` 表示自动选择；其余为列表中的服务器 id。
fn parse_choice(req: &Value) -> Result<Option<String>, String> {
    let Some(value) = req.get("server") else {
        return Ok(None);
    };
    let Some(text) = value.as_str() else {
        return Err("server must be a string".into());
    };
    let text = text.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("auto") {
        return Ok(None);
    }
    if text.len() > 255 || text.chars().any(char::is_control) {
        return Err("server id is invalid".into());
    }
    Ok(Some(text.to_string()))
}

fn start_list(ctx: &Rc<EngineCtx>, req: &Value) -> Value {
    if ctx
        .network_test
        .current
        .borrow()
        .as_ref()
        .is_some_and(|s| s.borrow().status == "running")
    {
        return json!({"error":"a network test is already running"});
    }
    let source = match Source::parse(req.get("source").and_then(Value::as_str)) {
        Some(source) => source,
        None => return json!({"error":"source must be cloudflare, ookla or china"}),
    };
    let outbound_name = req
        .get("outbound")
        .and_then(Value::as_str)
        .unwrap_or("DIRECT");
    let (connector, chain) = match prepare(ctx, source, outbound_name) {
        Ok(value) => value,
        Err(error) => return json!({"error": error}),
    };
    // 同一时间只有一个列表任务：新请求取代旧请求。
    ctx.network_test.cancel_list("replaced by a newer request");
    let list = Rc::new(RefCell::new(ServerList {
        status: "running".into(),
        source: source.as_str().into(),
        outbound: outbound_name.to_string(),
        chain,
        egress_ip: String::new(),
        servers: Vec::new(),
        error: None,
    }));
    *ctx.network_test.list.borrow_mut() = Some(list.clone());
    let manager = Rc::downgrade(&ctx.network_test);
    let task = tokio::task::spawn_local(async move {
        let result = discovery::list(&connector, source).await;
        {
            let mut list = list.borrow_mut();
            if list.status == "running" {
                match result {
                    Ok((egress_ip, servers)) => {
                        list.status = "completed".into();
                        list.egress_ip = egress_ip;
                        list.servers = servers.iter().map(listed_json).collect();
                    }
                    Err(error) => {
                        list.status = "failed".into();
                        list.error = Some(error);
                    }
                }
            }
        }
        if let Some(manager) = manager.upgrade() {
            manager.list_task.borrow_mut().take();
        }
    });
    *ctx.network_test.list_task.borrow_mut() = Some(task);
    ctx.network_test.list_snapshot()
}

fn listed_json(item: &discovery::Listed) -> Value {
    let s = &item.server;
    json!({
        "id": s.id,
        "name": s.name,
        "location": s.location,
        "distance_km": s.distance_km,
        "latency_ms": item.latency_ms,
        "available": item.latency_ms.is_some(),
        "upload": s.upload.is_some(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_test(
    snapshot: Rc<RefCell<Snapshot>>,
    cancel: Rc<Cell<bool>>,
    connector: TestConnector,
    source: Source,
    direction: Direction,
    limits: (Option<f64>, Option<f64>),
    choice: Option<String>,
    threads: Threads,
) -> Result<(), String> {
    snapshot.borrow_mut().phase = "finding server".into();
    let found = discovery::discover(
        &connector,
        source,
        matches!(direction, Direction::Both | Direction::Download),
        matches!(direction, Direction::Both | Direction::Upload),
        choice.as_deref(),
    )
    .await?;
    {
        let mut s = snapshot.borrow_mut();
        s.server = found.server.name.clone();
        s.server_detail = Some(json!({
            "id": found.server.id,
            "location": found.server.location,
            "distance_km": found.server.distance_km,
            "host": found.server.host(),
            "upload": found.server.upload.is_some(),
        }));
        s.egress_ip = found.egress_ip;
        s.latency_ms = Some(found.latency_ms);
    }
    if cancel.get() {
        return Err("cancelled".into());
    }
    let started = Instant::now();
    for upload in [false, true] {
        let wanted = if upload {
            Direction::Upload
        } else {
            Direction::Download
        };
        if direction != Direction::Both && direction != wanted {
            continue;
        }
        let limit = if upload { limits.1 } else { limits.0 };
        // 限速时每条连接分到的速率在建立时固定，不再加连接。
        let (connections, auto) = match threads {
            Threads::Single => (1, false),
            Threads::Auto => (meter::START_CONNECTIONS, limit.is_none()),
        };
        let per_connection = limit.map(|rate| rate / connections as f64);
        let mut paced = connector.clone();
        paced.limit = per_connection.map(|rate| (upload, rate));
        let full = if upload {
            UPLOAD_BYTES
        } else {
            found.server.max_download()
        };
        let request_bytes = per_connection
            .map(|rate| {
                ((rate * 1_000_000.0 / 8.0 * MAX_PHASE.as_secs_f64() / 4.0) as usize)
                    .clamp(512, full)
            })
            .unwrap_or(full);
        let phase = Phase {
            server: found.server.clone(),
            upload,
            request_bytes,
            connections,
            auto,
            tick: TICK,
            started,
        };
        run_phase(&snapshot, &cancel, paced, &phase).await?;
    }
    Ok(())
}

/// 一个方向的固定参数。
struct Phase {
    server: Server,
    upload: bool,
    request_bytes: usize,
    /// 起始连接数。
    connections: usize,
    /// 是否按读数增加连接。
    auto: bool,
    /// 时间片长度；测试里缩短。
    tick: Duration,
    /// 整次测试的开始时间，用于快照的 `elapsed`。
    started: Instant,
}

/// 一个方向的传输：各连接的 worker 循环发请求，字节在连接读写时即时计数；
/// 监督循环每个时间片把增量交给 [`Meter`]，按它的决定更新读数、增加连接或结束。
/// 任一 worker 出错整个阶段失败；结束时剩余 worker 连同在途请求一起终止。
async fn run_phase<C: Connector + Clone + 'static>(
    snapshot: &Rc<RefCell<Snapshot>>,
    cancel: &Rc<Cell<bool>>,
    connector: C,
    phase: &Phase,
) -> Result<(), String> {
    let phase_name = if phase.upload { "upload" } else { "download" };
    let counter = Arc::new(AtomicU64::new(0));
    let connector = Metered {
        inner: connector,
        upload: phase.upload,
        counter: counter.clone(),
    };
    {
        let mut s = snapshot.borrow_mut();
        s.phase = phase_name.into();
        s.connections = phase.connections;
    }
    let phase_start = Instant::now();
    // 请求超时不超过本方向的上限再多一个时间片；之后的失败不影响读数。
    let deadline = phase_start + phase.tick * (meter::MAX_TICKS as u32 + 1);
    // 上传只在服务端确认后计入：写出的字节可能还停在本机、出站或中间节点的缓冲里。
    let ledger = phase
        .upload
        .then(|| Rc::new(RefCell::new(Ledger::default())));
    let spawn = |workers: &mut Workers| {
        // 位置按记账表只增不减地分配：已结束的 worker 会从 `workers` 里移除。
        let inflight = ledger.clone().map(|ledger| {
            let slot = {
                let mut book = ledger.borrow_mut();
                book.inflight.push(None);
                book.inflight.len() - 1
            };
            Inflight { ledger, slot }
        });
        workers.0.push(tokio::task::spawn_local(phase_worker(
            cancel.clone(),
            connector.clone(),
            phase.server.clone(),
            phase.request_bytes,
            deadline,
            inflight,
        )));
    };
    let mut workers = Workers(Vec::with_capacity(meter::MAX_CONNECTIONS));
    for _ in 0..phase.connections {
        spawn(&mut workers);
    }
    let mut meter = Meter::new(phase.connections, phase.auto, phase.tick.as_secs_f64());
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + phase.tick, phase.tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut counted = 0u64;
    let mut counted_at = 0.0;
    let since = |t: Instant| t.saturating_duration_since(phase_start).as_secs_f64();
    loop {
        ticker.tick().await;
        if cancel.get() {
            return Err("cancelled".into());
        }
        // 出错的 worker 让整个阶段失败；正常结束的（达到请求数上限）只是不再贡献字节。
        let mut running = 0;
        let mut index = 0;
        while index < workers.0.len() {
            if !workers.0[index].is_finished() {
                running += 1;
                index += 1;
                continue;
            }
            match workers.0.swap_remove(index).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err("network test worker stopped".into()),
            }
        }
        let now = since(Instant::now());
        let (delta, settled) = match &ledger {
            None => {
                let total = counter.load(Ordering::Relaxed);
                let delta = total - counted;
                counted = total;
                meter.record(delta, counted_at, now);
                counted_at = now;
                (delta, now)
            }
            Some(ledger) => {
                let mut ledger = ledger.borrow_mut();
                let mut delta = 0;
                for (bytes, from, to) in ledger.done.drain(..) {
                    meter.record(bytes, since(from), since(to));
                    delta += bytes;
                }
                let oldest = ledger.inflight.iter().flatten().min().copied();
                (delta, oldest.map_or(now, since))
            }
        };
        let step = meter.tick(settled);
        {
            let mut s = snapshot.borrow_mut();
            s.elapsed = phase.started.elapsed().as_secs_f64();
            s.bytes = s.bytes.saturating_add(delta);
            s.connections = step.connections;
            if phase.upload {
                s.upload_mbps = step.mbps;
            } else {
                s.download_mbps = step.mbps;
            }
        }
        if step.done || running == 0 {
            break;
        }
        while workers.0.len() < step.connections {
            spawn(&mut workers);
        }
    }
    let result = meter.result();
    if result <= 0.0 {
        return Err(format!("{phase_name} transferred no data"));
    }
    let mut s = snapshot.borrow_mut();
    if phase.upload {
        s.upload_mbps = result;
    } else {
        s.download_mbps = result;
    }
    Ok(())
}

/// 上传的确认记账：各 worker 在途请求的开始时间，以及已确认、待交给 [`Meter`] 的请求。
/// 监督循环每个时间片取走 `done`，所以它的长度受请求速率与时间片限制。
#[derive(Default)]
struct Ledger {
    inflight: Vec<Option<Instant>>,
    /// 字节数、开始发送、收到确认。
    done: Vec<(u64, Instant, Instant)>,
}

/// worker 在 [`Ledger`] 里的位置；丢弃时（结束、出错、被终止）清掉在途记录，不再挡住已确定时间。
struct Inflight {
    ledger: Rc<RefCell<Ledger>>,
    slot: usize,
}

impl Inflight {
    fn set(&self, started: Option<Instant>) {
        self.ledger.borrow_mut().inflight[self.slot] = started;
    }
}

impl Drop for Inflight {
    fn drop(&mut self) {
        self.set(None);
    }
}

/// 一个 worker 的请求循环，在同一条 keep-alive 连接上连续发请求，直到被终止、达到请求数上限
/// 或连续失败 [`MAX_CONSECUTIVE_FAILURES`] 次；失败后换新连接重试。下载字节由 [`Metered`]
/// 即时计数；上传（`ledger` 不为空）在服务端确认后记入，请求大小按实际速率调整。
async fn phase_worker<C: Connector>(
    cancel: Rc<Cell<bool>>,
    connector: C,
    server: Server,
    request_bytes: usize,
    deadline: Instant,
    ledger: Option<Inflight>,
) -> Result<(), String> {
    let upload = ledger.is_some();
    let phase_name = if upload { "upload" } else { "download" };
    let mut conn = conn::SpeedConn::default();
    let mut failures = 0;
    let mut size = if upload {
        UPLOAD_START_BYTES.min(request_bytes)
    } else {
        request_bytes
    };
    for _ in 0..MAX_REQUESTS {
        if cancel.get() {
            return Err("cancelled".into());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let started = Instant::now();
        if let Some(ledger) = &ledger {
            ledger.set(Some(started));
        }
        let transferred = server
            .transfer(
                &mut conn,
                &connector,
                upload,
                size,
                REQUEST_TIMEOUT.min(remaining),
            )
            .await;
        if let Some(ledger) = &ledger {
            ledger.set(None);
        }
        let error = match transferred {
            Ok(0) => format!("{phase_name} response was empty"),
            Ok(bytes) => {
                failures = 0;
                if let Some(ledger) = &ledger {
                    let acked = Instant::now();
                    let mut book = ledger.ledger.borrow_mut();
                    book.done.push((bytes as u64, started, acked));
                    drop(book);
                    // 按实际速率把下一个请求调到约 UPLOAD_TARGET，单步最多放大 4 倍。
                    let took = acked.duration_since(started).as_secs_f64().max(0.001);
                    let wanted = (bytes as f64 * UPLOAD_TARGET.as_secs_f64() / took) as usize;
                    size = wanted
                        .min(size.saturating_mul(4))
                        .clamp(UPLOAD_START_BYTES.min(request_bytes), request_bytes);
                }
                continue;
            }
            Err(_) if Instant::now() >= deadline => break,
            Err(e) => format!("{phase_name} request failed: {e}"),
        };
        failures += 1;
        if failures >= MAX_CONSECUTIVE_FAILURES {
            return Err(error);
        }
        conn = conn::SpeedConn::default();
        tokio::time::sleep(RETRY_DELAY).await;
    }
    Ok(())
}

/// worker 任务的集合；丢弃时终止全部（结束、取消、出错、任务被终止都会走到这里）。
struct Workers(Vec<JoinHandle<Result<(), String>>>);

impl Drop for Workers {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

/// 单线程固定 1 条连接，多线程（`"auto"`）由 [`Meter`] 决定连接数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Threads {
    Single,
    Auto,
}

fn parse_threads(req: &Value) -> Result<Threads, String> {
    match req.get("threads") {
        None | Some(Value::Null) => Ok(Threads::Single),
        Some(value) if value.as_u64() == Some(1) => Ok(Threads::Single),
        Some(value) if value.as_str() == Some("auto") => Ok(Threads::Auto),
        Some(_) => Err("threads must be 1 or \"auto\"".into()),
    }
}

fn parse_limit(req: &Value, key: &str) -> Result<Option<f64>, String> {
    let value = match req.get(key) {
        None => 0.0,
        Some(value) => value
            .as_f64()
            .ok_or_else(|| format!("{key} must be a number"))?,
    };
    if !value.is_finite() || !(0.0..=10_000.0).contains(&value) {
        return Err(format!("{key} must be between 0 and 10000 Mbps"));
    }
    Ok((value > 0.0).then_some(value))
}

fn snapshot_json(snapshot: &Snapshot) -> Value {
    json!({
        "status": snapshot.status,
        "source": snapshot.source,
        "outbound": snapshot.outbound,
        "chain": snapshot.chain,
        "direction": snapshot.direction,
        "duration": snapshot.duration,
        "elapsed": snapshot.elapsed,
        "connections": snapshot.connections,
        "server": snapshot.server,
        "server_detail": snapshot.server_detail,
        "egress_ip": snapshot.egress_ip,
        "latency_ms": snapshot.latency_ms,
        "download_mbps": snapshot.download_mbps,
        "upload_mbps": snapshot.upload_mbps,
        "bytes": snapshot.bytes,
        "phase": snapshot.phase,
        "download_limit_mbps": snapshot.download_limit_mbps,
        "upload_limit_mbps": snapshot.upload_limit_mbps,
        "error": snapshot.error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sources_and_directions() {
        assert_eq!(Source::parse(Some("cn")), Some(Source::China));
        assert_eq!(Source::parse(Some("CF")), Some(Source::Cloudflare));
        assert_eq!(Source::parse(Some("speedtest")), Some(Source::Ookla));
        assert_eq!(Direction::parse(Some("down")), Some(Direction::Download));
        assert_eq!(Direction::parse(Some("bad")), None);
    }

    /// 注入的 Connector：每次连接对应一个内存回环里的小 HTTP 服务端，按请求里的大小应答，
    /// 并记录同时在途的连接数峰值。
    #[derive(Clone, Default)]
    struct Counting {
        active: Arc<std::sync::atomic::AtomicUsize>,
        peak: Arc<std::sync::atomic::AtomicUsize>,
        /// 还要拒绝的连接数（模拟服务端限流或断开）。
        refuse: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Connector for Counting {
        async fn connect(&self, _host: &str, _port: u16) -> io::Result<BoxStream> {
            use std::sync::atomic::Ordering::SeqCst;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if self
                .refuse
                .fetch_update(SeqCst, SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(io::ErrorKind::ConnectionReset.into());
            }
            let now = self.active.fetch_add(1, SeqCst) + 1;
            self.peak.fetch_max(now, SeqCst);
            let active = self.active.clone();
            let (client, mut peer) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    match peer.read(&mut buf).await {
                        Ok(n) if n > 0 => raw.extend_from_slice(&buf[..n]),
                        _ => break,
                    }
                }
                let end = raw.windows(4).position(|w| w == b"\r\n\r\n").map_or(raw.len(), |i| i + 4);
                let head = String::from_utf8_lossy(&raw[..end]).to_string();
                // 上传：读完正文，按 Ookla 的格式确认收到的字节数
                let sent = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse::<usize>().ok());
                let mut received = raw.len() - end;
                while sent.is_some_and(|n| received < n) {
                    match peer.read(&mut buf).await {
                        Ok(n) if n > 0 => received += n,
                        _ => break,
                    }
                }
                // 留一点时间让并发的连接真正重叠
                tokio::time::sleep(Duration::from_millis(20)).await;
                let size = head
                    .split(['?', '&', ' '])
                    .find_map(|p| p.strip_prefix("size=").and_then(|v| v.parse::<usize>().ok()))
                    .unwrap_or(1024);
                let body = match sent {
                    Some(n) => format!("size={n}").into_bytes(),
                    None => vec![1u8; size],
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = peer.write_all(response.as_bytes()).await;
                let _ = peer.write_all(&body).await;
                let _ = peer.shutdown().await;
                active.fetch_sub(1, SeqCst);
            });
            Ok(Box::new(client))
        }
    }

    fn test_server() -> Server {
        Server {
            id: "t".into(),
            name: "t".into(),
            location: String::new(),
            distance_km: None,
            download: "http://t.invalid/download?existing=1".into(),
            upload: None,
            parameter: "size",
            range: false,
            user_agent: None,
        }
    }

    fn snapshot() -> Rc<RefCell<Snapshot>> {
        Rc::new(RefCell::new(Snapshot::new(
            Source::Cloudflare,
            "DIRECT".into(),
            vec![],
            Direction::Download,
            0.0,
            0.0,
        )))
    }

    /// 时间片缩短到 20 ms，整个方向最多 0.6 秒。
    fn phase(connections: usize, auto: bool) -> Phase {
        Phase {
            server: test_server(),
            upload: false,
            request_bytes: 256 * 1024,
            connections,
            auto,
            tick: Duration::from_millis(20),
            started: Instant::now(),
        }
    }

    async fn run_with(connections: usize, auto: bool) -> (Snapshot, usize) {
        let connector = Counting::default();
        let snapshot = snapshot();
        let cancel = Rc::new(Cell::new(false));
        run_phase(&snapshot, &cancel, connector.clone(), &phase(connections, auto))
            .await
            .expect("phase");
        let peak = connector.peak.load(std::sync::atomic::Ordering::SeqCst);
        let result = snapshot.borrow().clone();
        (result, peak)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn single_uses_one_connection_and_auto_scales_up() {
        let local = tokio::task::LocalSet::new();
        let (single, single_peak) = local.run_until(run_with(1, false)).await;
        let (auto, auto_peak) = local.run_until(run_with(meter::START_CONNECTIONS, true)).await;
        assert_eq!(single_peak, 1, "单线程同一时刻只有一条连接");
        // 内存回环的读数远高于每连接阈值，自动模式应加满
        assert_eq!(auto.connections, meter::MAX_CONNECTIONS);
        assert!(auto_peak > meter::START_CONNECTIONS && auto_peak <= meter::MAX_CONNECTIONS);
        // 字节在读取时即时计数，含响应头
        assert!(single.bytes >= 256 * 1024 && single.download_mbps > 0.0);
        assert!(auto.bytes > single.bytes * 3, "{} vs {}", auto.bytes, single.bytes);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fixed_connections_when_scaling_is_off() {
        let local = tokio::task::LocalSet::new();
        let (snapshot, peak) = local.run_until(run_with(meter::START_CONNECTIONS, false)).await;
        assert_eq!(snapshot.connections, meter::START_CONNECTIONS);
        assert_eq!(peak, meter::START_CONNECTIONS);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn upload_counts_acknowledged_bytes_only() {
        let local = tokio::task::LocalSet::new();
        let snap = snapshot();
        let mut upload = phase(2, false);
        upload.upload = true;
        upload.server.upload = Some("http://t.invalid/upload".into());
        upload.request_bytes = 1024 * 1024;
        local
            .run_until(run_phase(&snap, &Rc::new(Cell::new(false)), Counting::default(), &upload))
            .await
            .expect("upload phase");
        let s = snap.borrow();
        assert!(s.upload_mbps > 0.0 && s.download_mbps == 0.0);
        // 只记被确认的请求：总数是整请求大小之和，不含写出后未确认的部分
        let start = UPLOAD_START_BYTES as u64;
        assert!(s.bytes >= start, "{}", s.bytes);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_connections_are_replaced_until_failures_repeat() {
        use std::sync::atomic::Ordering::SeqCst;
        let local = tokio::task::LocalSet::new();
        let cancel = Rc::new(Cell::new(false));
        // 前两次连接被拒绝：单线程 worker 换新连接后继续，测试成功
        let flaky = Counting::default();
        flaky.refuse.store(MAX_CONSECUTIVE_FAILURES - 1, SeqCst);
        let snap = snapshot();
        local
            .run_until(run_phase(&snap, &cancel, flaky, &phase(1, false)))
            .await
            .expect("transient failures are retried");
        assert!(snap.borrow().bytes > 0);
        // 一直被拒绝：连续失败达到上限后整个阶段失败
        let broken = Counting::default();
        broken.refuse.store(usize::MAX, SeqCst);
        let result = local
            .run_until(run_phase(&snapshot(), &cancel, broken, &phase(1, false)))
            .await;
        assert!(result.unwrap_err().contains("request failed"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_stops_all_workers() {
        let local = tokio::task::LocalSet::new();
        let result = local
            .run_until(async {
                let cancel = Rc::new(Cell::new(true));
                run_phase(&snapshot(), &cancel, Counting::default(), &phase(8, true)).await
            })
            .await;
        assert_eq!(result, Err("cancelled".into()));
    }

    #[test]
    fn thread_parameter() {
        assert_eq!(parse_threads(&json!({})), Ok(Threads::Single));
        assert_eq!(parse_threads(&json!({"threads":1})), Ok(Threads::Single));
        assert_eq!(parse_threads(&json!({"threads":"auto"})), Ok(Threads::Auto));
        assert!(parse_threads(&json!({"threads":8})).is_err());
        assert!(parse_threads(&json!({"threads":0})).is_err());
        assert!(parse_threads(&json!({"threads":"8"})).is_err());
    }

    #[test]
    fn server_choice_defaults_to_auto_and_rejects_bad_ids() {
        assert_eq!(parse_choice(&json!({})), Ok(None));
        assert_eq!(parse_choice(&json!({"server":""})), Ok(None));
        assert_eq!(parse_choice(&json!({"server":" AUTO "})), Ok(None));
        assert_eq!(
            parse_choice(&json!({"server":"a.test:8080"})),
            Ok(Some("a.test:8080".into()))
        );
        assert!(parse_choice(&json!({"server":1})).is_err());
        assert!(parse_choice(&json!({"server":"bad\nid"})).is_err());
        assert!(parse_choice(&json!({"server":"x".repeat(300)})).is_err());
    }
}
