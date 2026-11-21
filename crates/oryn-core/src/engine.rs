//! Engine：对外接口（可跨线程调用）与事件循环线程。
//!
//! 线程模型：
//! - `Engine` 的方法可以在任意线程调用（PacketTunnel 的 packetFlow 回调、IPC 等）。
//! - 真正的数据面只运行在一个专用线程上：Tokio current_thread runtime + LocalSet，
//!   lwIP 也只在这个线程上被调用。出站接口可跨线程，为以后引入线程池留余地。
//! - 输入经有界通道送入事件循环，满时丢弃（TCP 会重传）。
//! - 输出（写回隧道的包）在事件循环线程上批量回调给调用方。

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, UNIX_EPOCH};

use log::{error, info};
use oryn_config::{parse_config, ConfigError, Mode, ProviderSource, RuntimeConfig};
use oryn_netstack::{LwipStack, NetStack};
use oryn_router::Network;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::context::EngineCtx;
use crate::options::{EngineOptions, NetworkOptions};
use crate::stats::Stats;
use crate::{geo, health, logging, providers, tcp_flow, udp};

/// 输入通道容量（以批为单位）。
pub const INPUT_QUEUE: usize = 256;
pub const INPUT_MAX_BATCH_PACKETS: usize = 256;
pub const INPUT_MAX_PACKET_BYTES: usize = 64 * 1024;
pub const INPUT_MAX_BATCH_BYTES: usize = 1024 * 1024;
pub const INPUT_QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// 控制命令的等待上限。
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
/// `dns_cache` 命令一次最多返回的缓存记录数。
const DNS_CACHE_LIST_LIMIT: usize = 512;

/// 写回隧道的输出回调，在事件循环线程上调用。
pub type OutputSink = Box<dyn Fn(&[Vec<u8>]) + Send>;

#[derive(Debug)]
pub enum EngineError {
    Config(ConfigError),
    /// 已在运行，或另一个 Engine 占用了协议栈。
    Busy(String),
    NotRunning,
    QueueFull,
    Internal(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Config(e) => write!(f, "{e}"),
            EngineError::Busy(s) => write!(f, "{s}"),
            EngineError::NotRunning => f.write_str("engine is not running"),
            EngineError::QueueFull => f.write_str("input queue is full"),
            EngineError::Internal(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for EngineError {}

enum Msg {
    Packets(Vec<Vec<u8>>, usize),
    Command(Value, std_mpsc::SyncSender<Value>),
}

struct Running {
    stop: tokio::sync::watch::Sender<bool>,
    direct: bool,
    tx: mpsc::Sender<Msg>,
    queued_bytes: Arc<AtomicUsize>,
    thread: Option<JoinHandle<()>>,
}

/// 可跨线程共享的轻量句柄，用于输入包与执行命令，不会被 start/stop 阻塞。
#[derive(Clone)]
pub struct EngineHandle {
    direct: bool,
    tx: mpsc::Sender<Msg>,
    queued_bytes: Arc<AtomicUsize>,
}

impl EngineHandle {
    /// 输入一批来自隧道的 IP 包；队列满时丢弃并返回 `QueueFull`。
    pub fn input(&self, packets: Vec<Vec<u8>>) -> Result<(), EngineError> {
        if self.direct { return Err(EngineError::Busy("direct packet I/O is active".into())); }
        if packets.len() > INPUT_MAX_BATCH_PACKETS {
            return Err(EngineError::QueueFull);
        }
        let bytes = packets.iter().try_fold(0usize, |sum, packet| {
            if packet.len() > INPUT_MAX_PACKET_BYTES {
                return None;
            }
            sum.checked_add(packet.len())
        });
        let Some(bytes) = bytes.filter(|n| *n <= INPUT_MAX_BATCH_BYTES) else {
            return Err(EngineError::QueueFull);
        };
        let mut current = self.queued_bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return Err(EngineError::QueueFull);
            };
            if next > INPUT_QUEUE_BYTES {
                return Err(EngineError::QueueFull);
            }
            match self.queued_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        match self.tx.try_send(Msg::Packets(packets, bytes)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
                Err(EngineError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
                Err(EngineError::NotRunning)
            }
        }
    }

    /// 执行一条需要事件循环的控制命令。
    fn command(&self, req: Value) -> Value {
        let (reply_tx, reply_rx) = std_mpsc::sync_channel(1);
        if self.tx.try_send(Msg::Command(req, reply_tx)).is_err() {
            return json!({ "error": "engine is busy" });
        }
        reply_rx
            .recv_timeout(COMMAND_TIMEOUT)
            .unwrap_or_else(|_| json!({ "error": "command timed out" }))
    }
}

pub struct Engine {
    config: RuntimeConfig,
    /// 配置原文：代理集合更新后重新编译用。
    source: crate::proxy_providers::ConfigSource,
    options: EngineOptions,
    output: Option<OutputSink>,
    running: Option<Running>,
    stats: Arc<Stats>,
}

impl Engine {
    /// `config` 为类 mihomo 的 YAML 配置；`options` 为 JSON 运行参数（可为空）。
    pub fn new(config: &[u8], options: &[u8]) -> Result<Engine, EngineError> {
        logging::init();
        let text = std::str::from_utf8(config)
            .map_err(|_| EngineError::Config(ConfigError("config is not UTF-8".into())))?;
        let options =
            EngineOptions::parse(options).map_err(|e| EngineError::Config(ConfigError(e)))?;
        // 代理集合从数据目录的缓存展开；缺少缓存的在启动时下载后重新编译
        let config = crate::proxy_providers::compile(
            text,
            options.inspection_config.as_deref(),
            options.data_dir.as_deref(),
        )
        .map_err(EngineError::Config)?;
        options.virtual_interface.compile(config.dns.fake_ip_range, options.dns_address)
            .map_err(|e| EngineError::Config(ConfigError(e)))?;
        let source = crate::proxy_providers::ConfigSource {
            text: text.to_string(),
            inspection: options.inspection_config.clone(),
        };
        logging::set_level_override(options.log_level.as_deref());
        logging::set_level(&config.log_level);
        Ok(Engine {
            config,
            source,
            options,
            output: None,
            running: None,
            stats: Arc::new(Stats::default()),
        })
    }

    /// 启动前可查询的不可变接口计划，不依赖事件循环。
    pub fn virtual_interface_plan(&self) -> crate::virtual_interface::VirtualInterfacePlan {
        self.options.virtual_interface.compile(self.config.dns.fake_ip_range, self.options.dns_address).expect("validated interface plan")
    }

    /// 启动前可查询：`start` 就绪前要先下载的代理集合个数，供平台层提示「正在下载」。
    pub fn pending_proxy_provider_downloads(&self) -> usize {
        crate::proxy_providers::missing_count(&self.config, self.options.data_dir.as_deref())
    }

    /// 配置中被忽略的内容。
    pub fn warnings(&self) -> &[String] {
        &self.config.warnings
    }

    /// 设置输出回调，必须在 `start` 之前调用。
    pub fn set_output(&mut self, sink: OutputSink) {
        self.output = Some(sink);
    }

    pub fn is_running(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(|r| r.thread.as_ref().is_some_and(|t| !t.is_finished()))
    }

    pub fn start(&mut self) -> Result<(), EngineError> {
        self.start_with_utun_fd(None)
    }

    /// 启动并由 Rust 直接收发 utun 描述符上的 IP 包（平台层唯一使用的入口）。
    pub fn start_utun(&mut self, utun_fd: RawFd) -> Result<(), EngineError> {
        self.start_with_utun_fd(Some(utun_fd))
    }

    /// 不带 utun 启动（macOS 系统代理模式）：只运行本地 HTTP / SOCKS5 入站与控制命令，
    /// 没有包输入也不需要输出回调，见 docs/plan-macos.md。
    pub fn start_proxy_only(&mut self) -> Result<(), EngineError> {
        self.start_inner(None, true)
    }

    /// 回调式输入输出（`start`）仅供 Rust 集成测试；`Some(fd)` 时直接收发 utun。
    pub fn start_with_utun_fd(&mut self, utun_fd: Option<RawFd>) -> Result<(), EngineError> {
        let direct = utun_fd.is_some();
        self.start_inner(utun_fd, direct)
    }

    /// `direct` 为真时包 I/O 不经过回调（utun 或无包输入），拒绝 `input_packets`。
    fn start_inner(&mut self, utun_fd: Option<RawFd>, direct: bool) -> Result<(), EngineError> {
        if self.running.is_some() {
            return Err(EngineError::Busy("engine is already running".into()));
        }
        // 在调用返回前复制，避免原 FD 被调用方关闭后线程再按号码查找。
        let utun_fd = utun_fd
            .map(|fd| {
                if fd < 0 {
                    return Err(EngineError::Internal("invalid utun fd".into()));
                }
                unsafe { BorrowedFd::borrow_raw(fd) }
                    .try_clone_to_owned()
                    .map_err(|e| EngineError::Internal(format!("duplicate utun fd: {e}")))
            })
            .transpose()?;
        // 直接模式由 Rust 自己写 utun，不需要输出回调；回调式输出只留给 Rust 集成测试。
        let sink = match self.output.take() {
            Some(sink) => sink,
            None if direct => Box::new(|_: &[Vec<u8>]| {}),
            None => {
                return Err(EngineError::Internal(
                    "packet output callback is not set".into(),
                ))
            }
        };
        let (tx, rx) = mpsc::channel(INPUT_QUEUE);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let thread_queue = queued_bytes.clone();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
        let config = self.config.clone();
        let source = self.source.clone();
        let options = self.options.clone();
        let stats = self.stats.clone();
        let thread = std::thread::Builder::new()
            .name("oryn-core".into())
            .spawn(move || {
                run_thread(
                    config,
                    source,
                    options,
                    sink,
                    rx,
                    stats,
                    thread_queue,
                    ready_tx,
                    utun_fd,
                    stop_rx,
                )
            })
            .map_err(|e| EngineError::Internal(format!("failed to spawn thread: {e}")))?;
        match ready_rx.recv() {
            Ok(Ok(())) => {
                self.running = Some(Running {
                    stop: stop_tx,
                    direct,
                    tx,
                    queued_bytes,
                    thread: Some(thread),
                });
                info!("Oryn Core {} started", crate::VERSION);
                Ok(())
            }
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(EngineError::Internal(
                    "event loop thread failed to start".into(),
                ))
            }
        }
    }

    pub fn handle(&self) -> Option<EngineHandle> {
        self.running.as_ref().map(|r| EngineHandle {
            tx: r.tx.clone(),
            queued_bytes: r.queued_bytes.clone(),
            direct: r.direct,
        })
    }

    /// 输入一批来自隧道的 IP 包。
    pub fn input(&self, packets: Vec<Vec<u8>>) -> Result<(), EngineError> {
        self.handle().ok_or(EngineError::NotRunning)?.input(packets)
    }

    /// 执行一条控制命令（JSON），返回 JSON。
    pub fn command(&self, request: &[u8]) -> Value {
        if serde_json::from_slice::<Value>(request).ok().is_some_and(|v| v["cmd"] == "virtual_interface_plan") {
            return json!(self.virtual_interface_plan());
        }
        run_command(self.handle().as_ref(), request)
    }

    pub fn stop(&mut self) {
        if let Some(mut r) = self.running.take() {
            // 独立停止信号不受数据队列满载或遗留句柄影响。
            let _ = r.stop.send(true);
            drop(r.tx);
            if let Some(t) = r.thread.take() {
                let _ = t.join();
            }
            info!("Oryn Core stopped");
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 执行控制命令。`logs`、`version` 不需要事件循环，Engine 未运行时也可用。
pub fn run_command(handle: Option<&EngineHandle>, request: &[u8]) -> Value {
    let req: Value = match serde_json::from_slice(request) {
        Ok(v) => v,
        Err(e) => return json!({ "error": format!("invalid command JSON: {e}") }),
    };
    match req.get("cmd").and_then(Value::as_str) {
        Some("version") => return json!({ "version": crate::VERSION }),
        Some("logs") => {
            let limit = req.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize;
            return json!({ "logs": logging::recent(limit) });
        }
        _ => {}
    }
    match handle {
        Some(h) => h.command(req),
        None => json!({ "error": "engine is not running" }),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_thread(
    config: RuntimeConfig,
    source: crate::proxy_providers::ConfigSource,
    options: EngineOptions,
    sink: OutputSink,
    rx: mpsc::Receiver<Msg>,
    stats: Arc<Stats>,
    queued_bytes: Arc<AtomicUsize>,
    ready: std_mpsc::SyncSender<Result<(), EngineError>>,
    utun_fd: Option<OwnedFd>,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    install_panic_log();
    crate::perf::load_markers(options.data_dir.as_deref());
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("failed to create runtime: {e}");
            let _ = ready.send(Err(EngineError::Internal(format!(
                "failed to create runtime: {e}"
            ))));
            return;
        }
    };
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        let mut stack = match LwipStack::new(options.mtu) {
            Ok(s) => s,
            Err(e) => {
                error!("failed to create the TCP/IP stack: {e}");
                let _ = ready.send(Err(EngineError::Busy(e.to_string())));
                return;
            }
        };
        if let Err(e) = stack.set_loopback(crate::virtual_interface::TUNNEL_V4, options.virtual_interface.loopback_addresses.clone()) {
            let _ = ready.send(Err(EngineError::Internal(e.into())));
            return;
        }
        let utun = match utun_fd {
            Some(fd) => match crate::utun_threads::UtunIo::from_fd(fd.as_raw_fd(), options.mtu) {
                Ok(io) => Some(io),
                Err(e) => {
                    let _ = ready.send(Err(EngineError::Internal(format!(
                        "failed to attach utun fd: {e}"
                    ))));
                    return;
                }
            },
            None => None,
        };
        let mut bootstrap = config;
        // 原始配置由 bootstrap 的 base_config 保留；只暂存启动时禁用的部分，
        // 避免 ctx 构造期间再持有一整份节点和规则。
        let modules = std::mem::take(&mut bootstrap.modules);
        let mitm_enabled = std::mem::replace(&mut bootstrap.mitm.enabled, false);
        info!(
            "starting: mode {}, {} outbounds, {} rules, {} rule providers, {} modules, mtu {}, {} DNS servers, log level {}",
            // 界面选择的模式优先，与 EngineCtx 实际生效的模式一致
            options.mode().unwrap_or(bootstrap.mode).as_str(),
            bootstrap.outbounds.len(),
            bootstrap.rules.len(),
            bootstrap.providers.len(),
            bootstrap.modules.len(),
            options.mtu,
            bootstrap.dns.nameserver.len(),
            log::max_level()
        );
        let ctx = EngineCtx::new(stack, bootstrap, options, stats);
        ctx.local_ipv6.refresh(&ctx);
        if crate::perf::ingest_selftest_enabled() {
            tokio::task::spawn_local(crate::ingest_selftest::run(ctx.clone()));
        }
        *ctx.config_source.borrow_mut() = Some(source.clone());
        // 固定最初的 base，下载期间后台 reload 不能改变失败回退的配置。
        let bootstrap_state = ctx.state();
        // 缺少缓存的代理集合先下载，避免引用它们的策略组在首次启动时为空
        let recompiled = if crate::proxy_providers::fetch_missing(&ctx).await {
            match crate::proxy_providers::compile(&source.text, source.inspection.as_deref(), ctx.data_dir()) {
                Ok(c) => Some(c),
                Err(e) => {
                    error!("recompiling after downloading proxy providers failed: {e}");
                    None
                }
            }
        } else {
            None
        };
        let original = recompiled.unwrap_or_else(|| {
            let mut original = bootstrap_state.base_config.clone();
            original.modules = modules;
            original.mitm.enabled = mitm_enabled;
            original
        });
        drop(bootstrap_state);
        // 启动只用模块的磁盘缓存，联网更新放到就绪之后，避免隧道长时间停在「连接中」。
        let modules = original.modules.clone();
        let (prepared, deferred) = crate::modules::prepare_for_startup(&ctx, original).await;
        ctx.apply_prepared(prepared);
        crate::local_proxy::restart(&ctx);
        crate::scripts::event(&ctx.state(), "engine-started");
        let _ = ready.send(Ok(()));
        if deferred {
            crate::modules::refresh_deferred(&ctx, modules);
        }
        let shutdown_scripts = ctx.script_host.clone();
        #[cfg(feature = "mimalloc")]
        tokio::task::spawn_local(crate::alloc::trim_loop());
        event_loop(ctx, rx, sink, queued_bytes, utun, stop).await;
        shutdown_scripts.cancel();
    });
    // 先结束所有 Flow 任务（关闭各自的 pcb），再释放协议栈与 runtime
    drop(local);
    drop(rt);
}

fn install_panic_log() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            error!("panic: {info}");
            previous(info);
        }));
    });
}

async fn event_loop(
    ctx: Rc<EngineCtx>,
    mut rx: mpsc::Receiver<Msg>,
    sink: OutputSink,
    queued_bytes: Arc<AtomicUsize>,
    mut utun: Option<crate::utun_threads::UtunIo>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    crate::perf::mark_loop_thread();
    let notify = ctx.stack.notifier();
    let timer = tokio::time::sleep(Duration::from_millis(250));
    tokio::pin!(timer);

    let utun_enabled = utun.is_some();
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            _ = stop.changed() => break,
            result = async {
                match utun.as_mut() {
                    Some(io) => Some(io.next(&ctx.stack).await),
                    None => std::future::pending().await,
                }
            }, if utun_enabled => {
                match result {
                    Some(Ok(n)) if n > 0 => {
                        crate::perf::add(&crate::perf::LOOP_UTUN, 1);
                        // 一批包全部交给 lwIP 后统一分发一次
                        let t = std::time::Instant::now();
                        if let Some(io) = utun.as_ref() {
                            io.for_each_received(|packet| ctx.stack.input_packet(packet));
                        }
                        ctx.stack.flush_acks();
                        crate::perf::add(&crate::perf::INPUT_NS, crate::perf::since(t));
                        let t = std::time::Instant::now();
                        dispatch(&ctx);
                        crate::perf::add(&crate::perf::DISPATCH_NS, crate::perf::since(t));
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        log::error!("utun I/O failed: {e}");
                        break;
                    }
                    None => break,
                }
            }
            msg = rx.recv() => match msg {
                Some(Msg::Packets(batch, bytes)) => {
                    queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
                    for p in &batch {
                        ctx.stack.input_packet(p);
                    }
                    dispatch(&ctx);
                }
                Some(Msg::Command(req, reply)) => {
                    dispatch_command(&ctx, req, reply);
                }
                None => break,
            },
            _ = notify.notified() => {
                crate::perf::add(&crate::perf::LOOP_NOTIFY, 1);
                let t = std::time::Instant::now();
                dispatch(&ctx);
                crate::perf::add(&crate::perf::DISPATCH_NS, crate::perf::since(t));
            }
            _ = &mut timer => {
                let next = ctx.stack.poll_timers();
                timer.as_mut().reset(tokio::time::Instant::now() + next);
                dispatch(&ctx);
            }
        }
        crate::perf::add(&crate::perf::LOOP_ITERS, 1);
        let out = crate::ingest_selftest::capture(ctx.stack.take_output());
        if !out.is_empty() {
            if let Some(io) = utun.as_mut() {
                let t = std::time::Instant::now();
                let enqueued = io.enqueue(out, &ctx.stack);
                crate::perf::add(&crate::perf::ENQUEUE_NS, crate::perf::since(t));
                if let Err(e) = enqueued {
                    log::error!("utun write failed: {e}");
                    break;
                }
            } else {
                sink(&out);
                ctx.stack.recycle_output_batch(out);
            }
        } else {
            ctx.stack.recycle_output_batch(out);
        }
    }
}

fn dispatch(ctx: &Rc<EngineCtx>) {
    while let Some(stream) = ctx.stack.poll_tcp() {
        if let Some(operation) = tcp_flow::admit(ctx.clone(), stream) {
            tokio::task::spawn_local(operation);
        }
    }
    while let Some(dg) = ctx.stack.poll_udp() {
        udp::handle_datagram(ctx, dg);
    }
}

fn unix(t: Option<std::time::SystemTime>) -> Value {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(Value::Null, |d| json!(d.as_secs_f64()))
}

fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        5 => "CNAME".into(),
        28 => "AAAA".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        n => n.to_string(),
    }
}

fn dns_cache_json(dns: &oryn_dns::DnsEngine, limit: usize) -> Value {
    let upstreams: Vec<Value> = dns
        .upstream_status()
        .into_iter()
        .map(|u| {
            json!({
                "kind": u.kind,
                "group": u.group,
                "server": u.server,
                "queries": u.queries,
                "failures": u.failures,
                "latency_ms": u.latency_ms,
                "last_error": u.last_error,
            })
        })
        .collect();
    let entries: Vec<Value> = dns
        .cache_snapshot(limit)
        .into_iter()
        .map(|r| {
            json!({
                "domain": r.domain,
                "qtype": qtype_name(r.qtype),
                "ips": r.ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "kind": r.source.kind,
                "group": r.source.group,
                "server": r.source.server,
                "ttl": r.ttl,
                "remaining": r.remaining,
                "expires_at": r.expires_at,
                "fake_ips": r.fake_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "upstreams": upstreams,
        "entries": entries,
        "fake_ip_answers": dns.fake_ip_answers(),
        "fake_ip_leases": dns.fake_ip_len(),
    })
}

fn str_arg<'a>(req: &'a Value, key: &str) -> Option<&'a str> {
    req.get(key).and_then(Value::as_str)
}

fn pcb_json((active, time_wait, listen): (u32, u32, u32)) -> Value {
    json!({"active": active, "time_wait": time_wait, "listen": listen})
}

fn parse_pressure(req: &Value) -> Result<crate::admission::PressureLevel, &'static str> {
    let Some(level) = req.get("level").and_then(Value::as_str) else {
        return Err("pressure requires level");
    };
    match level {
        "normal" => Ok(crate::admission::PressureLevel::Normal),
        "elevated" => Ok(crate::admission::PressureLevel::Elevated),
        "critical" => Ok(crate::admission::PressureLevel::Critical),
        _ => Err("invalid pressure level"),
    }
}

// 令牌属于真实 blocking 工作，而不是可取消的本地 waiter。
static RELOAD_COMPILE: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));

fn dispatch_command(ctx: &Rc<EngineCtx>, req: Value, reply: std_mpsc::SyncSender<Value>) {
    if !ctx.desktop_reload_compile() || req["cmd"] != "reload" {
        let _ = reply.send(handle_command(ctx, &req));
        return;
    }
    let Some(text) = req.get("config").and_then(Value::as_str) else {
        let _ = reply.send(json!({"error": "reload requires config (YAML text)"}));
        return;
    };
    let permit = if ctx.reload_compiling.get() {
        None
    } else {
        RELOAD_COMPILE.clone().try_acquire_owned().ok()
    };
    let Some(permit) = permit else {
        let _ = reply.send(json!({"error": "engine is busy"}));
        return;
    };
    ctx.reload_compiling.set(true);
    let revisions = (ctx.selection_revision.get(), ctx.mode_revision.get());
    let text = text.to_owned();
    let overlay = req.get("inspection_config").and_then(Value::as_str).map(str::to_owned);
    let path = ctx.data_dir().map(std::path::Path::to_owned);
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        #[cfg(test)]
        compile_offload_tests::barrier();
        crate::proxy_providers::compile(&text, overlay.as_deref(), path.as_deref())
    });
    let c = ctx.clone();
    tokio::task::spawn_local(async move {
        let mut req = req;
        let result = match work.await {
            Ok(result) => {
                if c.selection_revision.get() != revisions.0 { req.as_object_mut().unwrap().remove("selections"); }
                if c.mode_revision.get() != revisions.1 { req.as_object_mut().unwrap().remove("mode"); }
                finish_reload(&c, &req, result)
            },
            Err(e) => json!({"error": format!("configuration compile failed: {e}")}),
        };
        let _ = reply.send(result);
        // 有维护事件时保留本地单飞槽，等待有效 prepare 完成后合并一次补偿。
        if c.reload_provider_dirty.get() || c.reload_modules_dirty.get() {
            while c.pending_reload.borrow().as_ref().is_some_and(|p| !p.is_finished()) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        c.reload_compiling.set(false);
        let providers = c.reload_provider_dirty.replace(false);
        let modules = c.reload_modules_dirty.replace(false);
        if providers && c.config_source.borrow().is_some() {
            crate::proxy_providers::schedule_reload(&c);
        } else if modules {
            crate::modules::refresh(&c, c.state());
        }
    });
}

fn handle_command(ctx: &Rc<EngineCtx>, req: &Value) -> Value {
    if ctx.reload_compiling.get() && req["cmd"] == "apply_settings" {
        return json!({"error": "engine is busy"});
    }
    if req["cmd"]
        .as_str()
        .is_some_and(|cmd| cmd.starts_with("selftest_"))
    {
        return crate::selftest::command(ctx, req);
    }
    if req["cmd"]
        .as_str()
        .is_some_and(|cmd| cmd.starts_with("iperf_") || cmd.starts_with("network_test_"))
    {
        return if req["cmd"]
            .as_str()
            .is_some_and(|cmd| cmd.starts_with("iperf_"))
        {
            crate::iperf::command(ctx, req)
        } else {
            crate::network_test::command(ctx, req)
        };
    }
    use std::sync::atomic::Ordering::Relaxed;
    let state = ctx.state();

    match str_arg(req, "cmd").unwrap_or("") {
        "script_status" => {
            json!({"scripts":state.http_plan.scripts.iter().map(|s|json!({"name":s.name,"kind":s.kind,"result":state.scripts.results.lock().unwrap().get(&s.name).cloned()})).collect::<Vec<_>>() })
        }
        "events" => json!({ "events": crate::events::drain() }),
        "script_notifications" => {
            json!({"notifications":state.scripts.notifications.lock().unwrap().drain(..).collect::<Vec<_>>()})
        }
        "run_script" => {
            let Some(name) = str_arg(req, "name") else {
                return json!({"error":"run_script needs name"});
            };
            let Some(spec) = state
                .http_plan
                .scripts
                .iter()
                .find(|s| s.name == name && matches!(s.kind.as_str(), "generic" | "event" | "cron"))
                .cloned()
            else {
                return json!({"error":"unknown manual script"});
            };
            let st = state.clone();
            state.spawn(async move { crate::scripts::auxiliary(st, spec).await });
            json!({"ok":true,"pending":true})
        }
        "module_status" => {
            json!({"modules":state.config.modules.iter().map(|m|json!({"url":m.url,"enabled":m.enabled,"metadata":m.inline.as_ref().map(|i|&i.meta),"arguments":m.inline.as_ref().map(|i|&i.arguments)})).collect::<Vec<_>>() })
        }
        "pressure" => {
            let level = match parse_pressure(req) {
                Ok(level) => level,
                Err(error) => return json!({"error": error}),
            };
            ctx.admission.set_pressure(level);
            // 宿主可同时报告扩展进程还能再用多少内存（字节），用于内存闸
            if let Some(bytes) = req.get("available").and_then(Value::as_u64) {
                if let Some((live, _)) = crate::alloc::heap_usage() {
                    ctx.admission.observe_heap(live as u64, ctx.conns.count(Network::Tcp));
                }
                ctx.admission.report_available(bytes);
            }
            let wg = wireguard_pressure(ctx.admission.wireguard_pressure());
            oryn_outbound::wireguard_resources::set_pressure(wg);
            json!({"ok": true, "pressure": level.as_str(), "establishing_limit": ctx.admission.establishing_limit(), "wireguard_pressure": wg.as_str()})
        }
        "admission_tune" => {
            let num = |key: &str| req.get(key).and_then(Value::as_u64);
            ctx.admission.tune(&crate::admission::Tune {
                active_soft: num("active_soft").map(|v| v as usize),
                establishing_soft: num("establishing_soft").map(|v| v as usize),
                queue_cap: num("queue_cap").map(|v| v as usize),
                queue_timeout_ms: num("queue_timeout_ms"),
                mem_reserve: num("mem_reserve"),
                mem_cost: num("mem_cost"),
            });
            json!({"ok": true, "tuning": ctx.admission.tuning()})
        }
        "stats" => json!({
            "upload": ctx.stats.upload.load(Relaxed),
            "download": ctx.stats.download.load(Relaxed),
            "tcp_total": ctx.stats.tcp_total.load(Relaxed),
            "udp_total": ctx.stats.udp_total.load(Relaxed),
            "dns_queries": ctx.stats.dns_queries.load(Relaxed),
            "tcp_active": ctx.conns.count(Network::Tcp),
            "pressure": ctx.admission.pressure().as_str(),
            "establishing_limit": ctx.admission.establishing_limit(),
            "admission": {
                "active_in_use": ctx.admission.active_in_use(),
                "establishing_in_use": ctx.admission.establishing_in_use(),
                "rejected_active": ctx.admission.counters.rejected_active.load(Relaxed),
                "rejected_establishing": ctx.admission.counters.rejected_establishing.load(Relaxed),
                "rejected_pressure": ctx.admission.counters.rejected_pressure.load(Relaxed),
                "rejected_memory": ctx.admission.counters.rejected_memory.load(Relaxed),
                "rejected_queue_full": ctx.admission.counters.rejected_queue_full.load(Relaxed),
                "rejected_queue_memory": ctx.admission.counters.rejected_queue_memory.load(Relaxed),
                "queued_total": ctx.admission.counters.queued_total.load(Relaxed),
                "queue_timeouts": ctx.admission.counters.queue_timeouts.load(Relaxed),
                "queue_len": ctx.admission.waiting(),
                "peak_queue": ctx.admission.counters.peak_queue.load(Relaxed),
                "max_wait_ms": ctx.admission.counters.max_wait_ms.load(Relaxed),
                "tuning": ctx.admission.tuning(),
                "peak_active": ctx.admission.counters.peak_active.load(Relaxed),
                "peak_establishing": ctx.admission.counters.peak_establishing.load(Relaxed),
            },
            "wireguard_buffers": {
                "used": oryn_outbound::wireguard_resources::buffer_usage().0,
                "budget": oryn_outbound::wireguard_resources::buffer_usage().1,
                "pressure": oryn_outbound::wireguard_resources::pressure().as_str(),
                "workers": oryn_outbound::wireguard_resources::workers_started(),
            },
            "udp_active": ctx.conns.count(Network::Udp),
            "udp_sessions": ctx.udp.count(),
            "dns_cache": ctx.dns.cache_len(),
            "dns_mapping": ctx.dns.mapping_len(),
            "listeners": ctx.stack.listener_count(),
            "lwip_pcb": pcb_json(ctx.stack.pcb_counts()),
            "utun_buffer_full_drops": oryn_netstack::utun::BUFFER_FULL_DROPS.load(Relaxed),
            "output_dropped": ctx.stack.output_dropped(),
            "mode": state.router().mode().as_str(),
            "warnings": state.config.warnings.len(),
            "loop_perf": crate::perf::snapshot(),
            "heap_live": crate::alloc::heap_usage().map(|(live, _)| live),
            "heap_peak": crate::alloc::heap_usage().map(|(_, peak)| peak),
        }),
        "connections" => {
            let limit = req.get("limit").and_then(Value::as_u64).unwrap_or(500) as usize;
            let with_history = req.get("history").and_then(Value::as_bool).unwrap_or(false);
            let mut connections = ctx.conns.snapshot(limit, with_history);
            for connection in &mut connections {
                connection.server = state
                    .config
                    .outbounds
                    .iter()
                    .find(|o| o.name == connection.outbound)
                    .and_then(|o| o.kind.server_addr())
                    .map(ToString::to_string);
            }
            json!({ "connections": connections })
        }
        "clear_connection_history" => {
            ctx.conns.clear_history();
            json!({ "ok": true })
        }
        "close_connection" => {
            let Some(id) = req.get("id").and_then(Value::as_u64) else {
                return json!({ "error": "close_connection requires id" });
            };
            json!({ "ok": ctx.conns.close_one(id), "id": id })
        }
        "close_all_connections" => {
            let closed = ctx.conns.close_all();
            json!({ "ok": true, "closed": closed })
        }
        "smart_explain" => {
            let (Some(group), Some(host)) = (str_arg(req, "group"), str_arg(req, "target")) else {
                return json!({"error":"smart_explain requires group and target"});
            };
            let target = oryn_config::TargetAddr::from_host(host, 443);
            let network = if str_arg(req, "network") == Some("udp") {
                oryn_router::Network::Udp
            } else {
                oryn_router::Network::Tcp
            };
            state
                .routing
                .outbounds
                .iter()
                .find(|o| o.tag() == group)
                .and_then(|o| o.as_group())
                .and_then(|g| g.smart_explain(&target, network))
                .unwrap_or_else(|| json!({"error":"unknown Smart group"}))
        }
        "smart_usage" => {
            let Some(group) = str_arg(req, "group") else {
                return json!({"error":"smart_usage requires group"});
            };
            state
                .routing
                .outbounds
                .iter()
                .find(|o| o.tag() == group)
                .and_then(|o| o.as_group())
                .and_then(|g| g.smart_usage())
                .map(|mut v| {
                    v["group"] = group.into();
                    v
                })
                .unwrap_or_else(|| json!({"error":"unknown Smart group"}))
        }
        "groups" => {
            let groups: Vec<Value> = state
                .routing
                .outbounds
                .iter()
                .filter_map(|o| o.as_group().map(|g| g.status()))
                .map(|g| {
                    json!({
                        "name": g.name,
                        "type": g.kind,
                        "now": g.now,
                        "test_url": g.test_url,
                        "members": g.members.iter().map(|m| json!({
                            "name": m.name,
                            "type": m.kind,
                            "delay": m.delay_ms,
                            "tested": m.tested,
                            "udp_delay": m.udp_delay_ms,
                            "udp_tested": m.udp_tested,
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            json!({ "groups": groups })
        }
        "select" => {
            let (Some(group), Some(name)) = (str_arg(req, "group"), str_arg(req, "name")) else {
                return json!({ "error": "select requires group and name" });
            };
            let Some(g) = state.routing.outbounds.iter().find(|o| o.tag() == group) else {
                return json!({ "error": format!("unknown group `{group}`") });
            };
            match g.as_group() {
                Some(g) if g.select(name) => {
                    ctx.selection_revision.set(ctx.selection_revision.get().wrapping_add(1));
                    ctx.selections
                        .borrow_mut()
                        .insert(group.to_string(), name.to_string());
                    let closed = if ctx.close_on_policy_switch.get() {
                        ctx.conns.close_through(group)
                    } else {
                        0
                    };
                    info!("group `{group}` selected `{name}`, closed {closed} connections");
                    json!({ "ok": true, "closed": closed })
                }
                Some(_) => json!({ "error": format!("`{name}` cannot be selected in `{group}`") }),
                None => json!({ "error": format!("`{group}` is not a group") }),
            }
        }
        "test_group" => {
            let Some(group) = str_arg(req, "group") else {
                return json!({ "error": "test_group requires group" });
            };
            let Some(g) = state
                .routing
                .outbounds
                .iter()
                .find(|o| o.tag() == group && o.as_group().is_some())
                .cloned()
            else {
                return json!({ "error": format!("unknown group `{group}`") });
            };
            let st = state.clone();
            // 可选 member：只测该成员（长按节点）
            let only = str_arg(req, "member").map(str::to_string);
            if req.get("udp").and_then(Value::as_bool).unwrap_or(false) {
                let address = ctx.udp_test_address().to_string();
                if health::parse_udp_test(&address).is_none() {
                    return json!({ "error": format!("invalid UDP test address `{address}`") });
                }
                state.spawn(async move {
                    health::test_group_udp(&st, &g, &address, only.as_deref()).await
                });
            } else {
                state.spawn(async move {
                    health::test_group_member(&st, &g, only.as_deref()).await
                });
            }
            json!({ "ok": true })
        }
        "close_group_connections" => {
            let Some(group) = str_arg(req, "group") else {
                return json!({ "error": "close_group_connections requires group" });
            };
            let closed = ctx.conns.close_through(group);
            info!("closed {closed} connections through `{group}`");
            json!({ "ok": true, "closed": closed })
        }
        "set_mode" => match str_arg(req, "mode").and_then(Mode::parse) {
            Some(mode) => {
                ctx.mode_revision.set(ctx.mode_revision.get().wrapping_add(1));
                ctx.set_mode(mode);
                info!("mode set to {}", mode.as_str());
                json!({ "ok": true })
            }
            None => json!({ "error": "set_mode requires mode: rule / global / direct" }),
        },
        "providers" => {
            let list: Vec<Value> = state
                .config
                .providers
                .iter()
                .zip(state.rule_sets.slots())
                .map(|(p, slot)| {
                    let info = slot.info();
                    let (kind, url) = match &p.source {
                        ProviderSource::Http { url, .. } => ("http", Some(url.clone())),
                        ProviderSource::File { .. } => ("file", None),
                        ProviderSource::Inline { .. } => ("inline", None),
                    };
                    json!({
                        "name": p.name,
                        "type": kind,
                        "behavior": format!("{:?}", p.behavior).to_ascii_lowercase(),
                        "url": url,
                        "count": info.count,
                        "loaded": slot.get().is_some(),
                        "updated_at": unix(info.updated),
                        "error": info.error,
                    })
                })
                .collect();
            let mut list = list;
            list.extend(crate::proxy_providers::status_json(ctx, &state));
            json!({
                "providers": list,
                "geoip": geo::status_json(ctx, &state, geo::Kind::Country),
                "asn": geo::status_json(ctx, &state, geo::Kind::Asn),
            })
        }
        "update_database" => {
            let kind = match str_arg(req, "name") {
                Some("geoip") => geo::Kind::Country,
                Some("asn") => geo::Kind::Asn,
                _ => return json!({ "error": "unknown database" }),
            };
            geo::request(ctx, &state, kind);
            json!({ "ok": true })
        }
        "update_providers" => {
            let only = str_arg(req, "name").map(str::to_string);
            for (i, p) in state.config.providers.iter().enumerate() {
                let wanted = only.as_deref().is_none_or(|n| n == p.name);
                if wanted && matches!(p.source, ProviderSource::Http { .. }) {
                    let (c, s) = (ctx.clone(), state.clone());
                    state.spawn(async move {
                        let _ = providers::download(&c, &s, i).await;
                    });
                }
            }
            for (i, p) in state.config.proxy_providers.iter().enumerate() {
                let wanted = only.as_deref().is_none_or(|n| n == p.name);
                if wanted && matches!(p.source, oryn_config::ProxyProviderSource::Http { .. }) {
                    let (c, s) = (ctx.clone(), state.clone());
                    state.spawn(async move {
                        if let Ok(true) = crate::proxy_providers::download(&c, &s, i).await {
                            crate::proxy_providers::schedule_reload(&c);
                        }
                    });
                }
            }
            if only.as_deref().is_none_or(|n| n == "geoip") {
                geo::request(ctx, &state, geo::Kind::Country);
            }
            if only.as_deref().is_none_or(|n| n == "asn") {
                geo::request(ctx, &state, geo::Kind::Asn);
            }
            json!({ "ok": true })
        }
        "warnings" => json!({ "warnings": state.config.warnings }),
        "clear_dns_cache" => {
            ctx.dns.clear_cache();
            json!({ "ok": true })
        }
        "dns_cache" => {
            let limit = req
                .get("limit")
                .and_then(Value::as_u64)
                .map_or(DNS_CACHE_LIST_LIMIT, |n| {
                    (n as usize).min(DNS_CACHE_LIST_LIMIT)
                });
            dns_cache_json(&ctx.dns, limit)
        }
        "apply_settings" => {
            if let Some(value) = req.get("real_ip_domains") {
                let values = match serde_json::from_value::<Vec<String>>(value.clone()) {
                    Ok(values) => values,
                    Err(_) => return json!({ "error": "real_ip_domains must be a list of hostnames" }),
                };
                if let Err(error) = ctx.dns.set_real_ip_domains(&values) {
                    return json!({ "error": error });
                }
            }
            if let Some(prefer) = req.get("proxy_prefer_ipv6").and_then(Value::as_bool) {
                ctx.dns.set_proxy_prefer_ipv6(prefer);
            }
            if let (Some(support), Some(prefer)) = (
                req.get("ipv6_support").and_then(Value::as_bool),
                req.get("prefer_ipv6").and_then(Value::as_bool),
            ) {
                ctx.dns.set_target_ipv6(support, prefer);
                ctx.state().router().set_ipv6_support(support);
            }
            if let Some(value) = req.get("maxmind") {
                let options: crate::options::MaxMindOptions =
                    match serde_json::from_value(value.clone()) {
                        Ok(options) => options,
                        Err(error) => {
                            return json!({ "error": format!("invalid MaxMind settings: {error}") })
                        }
                    };
                if let Err(error) = options.validate() {
                    return json!({ "error": error });
                }
                if ctx.maxmind.borrow().as_ref() != Some(&options) {
                    *ctx.maxmind.borrow_mut() = Some(options);
                    ctx.apply_config(state.base_config.clone());
                }
            }
            if let Some(value) = req
                .get("close_connections_on_policy_switch")
                .and_then(Value::as_bool)
            {
                ctx.close_on_policy_switch.set(value);
            }
            if let Some(value) = req.get("log_level") {
                logging::set_level_override(value.as_str());
            }
            if let Some(value) = req.get("block_quic").and_then(Value::as_str) {
                if let Err(error) = ctx.set_block_quic(value) {
                    return json!({ "error": error });
                }
            }
            if let Some(value) = req.get("local_proxy") {
                match serde_json::from_value(value.clone()) {
                    Ok(options) => ctx.set_local_proxy(options),
                    Err(error) => {
                        return json!({ "error": format!("invalid local proxy settings: {error}") })
                    }
                }
            }
            json!({ "ok": true })
        }
        "network_changed" => {
            if let Some(net) = req.get("network") {
                if let Ok(n) = serde_json::from_value::<NetworkOptions>(net.clone()) {
                    n.apply_interface();
                    ctx.dns.set_network(n.to_info());
                }
            }
            ctx.dns.reset();
            ctx.local_ipv6.network_changed(ctx);
            // path_changed 为 false 表示只有无线制式变化，接口与地址不变：保留 UDP 会话与出站连接
            let path_changed = req
                .get("path_changed")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if path_changed {
                ctx.udp.clear();
                ctx.public_ip_refresh.notify_one();
                for session in &ctx.state().sessions {
                    session.on_network_changed();
                }
            }
            crate::scripts::event(&ctx.state(), "network-changed");
            if path_changed {
                info!("network changed: cleared DNS cache and UDP sessions");
            } else {
                info!("network changed (radio only): cleared DNS cache");
            }
            json!({ "ok": true })
        }
        "sleep" => {
            ctx.iperf.cancel("tunnel sleeping");
            ctx.network_test.cancel("tunnel sleeping");
            ctx.selftest.cancel("tunnel sleeping");
            for session in &ctx.state().sessions {
                session.on_sleep();
            }
            json!({ "ok": true })
        }
        "wake" => {
            for session in &ctx.state().sessions {
                session.on_wake();
            }
            json!({ "ok": true })
        }
        "virtual_interface_stats" => {
            let (reflected, dropped) = ctx.stack.loopback_counts();
            json!({ "reflected": reflected, "dropped": dropped, "output_dropped": ctx.stack.output_dropped(), "ipv6_rejected": ctx.stack.ipv6_rejected() })
        }
        "reload" => {
            let Some(text) = req.get("config").and_then(Value::as_str) else {
                return json!({ "error": "reload requires config (YAML text)" });
            };
            drop(state);
            let overlay = req.get("inspection_config").and_then(Value::as_str);
            finish_reload(ctx, req, crate::proxy_providers::compile(text, overlay, ctx.data_dir()))
        }
        other => json!({ "error": format!("unknown command `{other}`") }),
    }
}

fn finish_reload(ctx: &Rc<EngineCtx>, req: &Value, result: Result<RuntimeConfig, ConfigError>) -> Value {
    let text = req["config"].as_str().expect("validated reload text");
    let overlay = req.get("inspection_config").and_then(Value::as_str);
    match result {
                Ok(config) => {
                    if let Err(error) = ctx.validate_virtual_interface(&config) {
                        return json!({ "error": error, "requires_reconnect": true });
                    }
                    *ctx.config_source.borrow_mut() = Some(crate::proxy_providers::ConfigSource {
                        text: text.to_string(),
                        inspection: overlay.map(str::to_string),
                    });
                    // 切换到另一个配置时，由调用方一并传入该配置保存的选择与模式
                    if let Some(sel) = req.get("selections").and_then(Value::as_object) {
                        *ctx.selections.borrow_mut() = sel
                            .iter()
                            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                            .collect();
                    }
                    if let Some(mode) = req.get("mode") {
                        ctx.mode_override.set(mode.as_str().and_then(Mode::parse));
                    }
                    logging::set_level(&config.log_level);
                    let warnings = config.warnings.clone();
                    let c = ctx.clone();
                    if let Some(previous) = ctx.pending_reload.borrow_mut().take() {
                        previous.abort();
                    }
                    *ctx.pending_reload.borrow_mut() = Some(tokio::task::spawn_local(async move {
                        let prepared = crate::modules::prepare_for_apply(&c, config).await;
                        c.apply_prepared(prepared);
                        crate::scripts::event(&c.state(), "profile-reloaded");
                    }));
                    info!("configuration reload scheduled");
                    json!({ "ok": true, "warnings": warnings })
                }
                Err(e) => {
                    error!("configuration reload failed: {e}");
                    json!({ "error": e.to_string() })
                }
    }
}

pub(crate) fn apply_inspection_overlay(
    config: &mut RuntimeConfig,
    text: &str,
) -> Result<(), ConfigError> {
    let overlay = parse_config(text)?;
    // 本机设置没有「跳过源站证书校验」这一项，保留配置文件里显式写的值，免得它被 overlay 静默清掉
    let skip_verify = config.mitm.skip_server_cert_verify;
    config.mitm = overlay.mitm;
    config.mitm.skip_server_cert_verify = skip_verify;
    config.modules.extend(overlay.modules);
    Ok(())
}

#[cfg(test)]
#[path = "compile_offload_tests.rs"]
mod compile_offload_tests;

// 用 utun 帧格式测试，只在 utun 平台运行。
#[cfg(all(test, not(any(target_os = "android", target_os = "linux"))))]
mod utun_tests {
    include!("utun_direct_measurement.rs");
    use super::*;
    use oryn_netstack::packet::{build_tcp, parse_tcp, TCP_FLAG_SYN};
    use oryn_netstack::utun::{decode_frame, encode_frame, IpVersion};
    use std::os::unix::net::UnixDatagram;

    /// lwIP 是进程内单例，这里的测试必须串行。
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn proxy_only_engine_serves_local_socks_without_packet_io() {
        use std::io::{Read, Write};
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let options = format!(r#"{{"local_proxy":{{"enabled":true,"http_port":0,"socks_port":{port}}}}}"#);
        let mut engine = Engine::new(b"rules:\n  - MATCH,REJECT\n", options.as_bytes()).unwrap();
        engine.start_proxy_only().unwrap();
        let handle = engine.handle().unwrap();
        assert!(handle.input(Vec::new()).is_err());
        let mut socks = None;
        for _ in 0..50 {
            if let Ok(s) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                socks = Some(s);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut socks = socks.expect("local SOCKS5 listener");
        socks.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        socks.write_all(&[5, 1, 0]).unwrap();
        let mut reply = [0; 2];
        socks.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [5, 0]);
        assert!(engine.command(br#"{"cmd":"stats"}"#).get("error").is_none());
        engine.stop();
    }

    /// 上行处理路径自测（`ingest_selftest.rs`）：Core 自己扮演 TCP 客户端对合成端点上传。耗时约 10 秒，手动跑：
    /// `cargo test --release -p oryn-core --lib ingest_selftest_reports_throughput -- --ignored --nocapture`
    #[test]
    #[ignore = "manual dev measurement, about 10 seconds"]
    fn ingest_selftest_reports_throughput() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("oryn-ingest-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("oryn-ingest-selftest"), b"").unwrap();
        let result_path = std::env::temp_dir().join("oryn-ingest-selftest.json");
        let _ = std::fs::remove_file(&result_path);
        let (local, _peer) = UnixDatagram::pair().unwrap();
        let options = format!(r#"{{"data_dir":"{}"}}"#, dir.display());
        let mut engine = Engine::new(b"rules:\n  - MATCH,REJECT\n", options.as_bytes()).unwrap();
        engine.start_with_utun_fd(Some(local.as_raw_fd())).unwrap();
        let mut text = None;
        for _ in 0..200 {
            std::thread::sleep(Duration::from_millis(100));
            if let Ok(t) = std::fs::read_to_string(&result_path) {
                text = Some(t);
                break;
            }
        }
        engine.stop();
        let _ = std::fs::remove_dir_all(&dir);
        let text = text.expect("self-test result");
        println!("{text}");
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(value.get("error").is_none(), "{text}");
        assert!(value["bytes_acked"].as_u64().unwrap() > 0, "{text}");
    }

    #[test]
    fn self_loopback_address_bypasses_rules_to_localhost() {
        use std::io::Read;
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (local, peer) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        // 规则全部 REJECT：自回环地址仍须直连本机，而不是匹配规则。
        let mut engine = Engine::new(b"rules:\n  - MATCH,REJECT\n", b"{}").unwrap();
        engine.start_with_utun_fd(Some(local.as_raw_fd())).unwrap();
        let send = |packet: Vec<u8>| {
            let mut frame = Vec::new();
            encode_frame(IpVersion::V4, &packet, &mut frame).unwrap();
            peer.send(&frame).unwrap();
        };
        let src = "198.18.0.1:40001".parse().unwrap();
        let dst = std::net::SocketAddr::from((crate::virtual_interface::SELF_V4, port));
        send(build_tcp(src, dst, 1, 0, TCP_FLAG_SYN, 65535, &[]).unwrap());
        let mut bytes = [0; 2048];
        let n = peer.recv(&mut bytes).unwrap();
        let synack = parse_tcp(decode_frame(&bytes[..n]).unwrap().1).unwrap();
        assert_eq!(synack.flags & 0x04, 0);
        send(build_tcp(src, dst, 2, synack.seq.wrapping_add(1), 0x18, 65535, b"ping").unwrap());
        listener.set_nonblocking(false).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        accepted.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut got = [0; 4];
        accepted.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");
        engine.stop();
    }

    #[test]
    fn utun_engine_syn_rejects_double_input_and_stops_with_backpressure() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (local, peer) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.set_write_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let mut engine = Engine::new(b"rules:\n  - MATCH,REJECT\n", b"{}").unwrap();
        engine.set_output(Box::new(|_| panic!("FD backend called packetFlow")));
        engine.start_with_utun_fd(Some(local.as_raw_fd())).unwrap();
        let handle = engine.handle().unwrap();
        assert!(handle.input(Vec::new()).is_err());
        let packet = build_tcp(
            "198.18.0.10:40000".parse().unwrap(),
            "203.0.113.7:443".parse().unwrap(),
            1,
            0,
            TCP_FLAG_SYN,
            65535,
            &[],
        )
        .unwrap();
        let mut frame = Vec::new();
        encode_frame(IpVersion::V4, &packet, &mut frame).unwrap();
        peer.send(&frame).unwrap();
        let mut bytes = [0; 2048];
        let n = peer.recv(&mut bytes).unwrap();
        let (_, ip) = decode_frame(&bytes[..n]).unwrap();
        let synack = parse_tcp(ip).unwrap();
        assert_eq!(synack.ack, 2);
        let ack = build_tcp(synack.dst, synack.src, 2, synack.seq.wrapping_add(1), 0x10, 65535, &[]).unwrap();
        let mut ack_frame = Vec::new();
        encode_frame(IpVersion::V4, &ack, &mut ack_frame).unwrap();
        peer.send(&ack_frame).unwrap();
        let n = peer.recv(&mut bytes).unwrap();
        let (_, ip) = decode_frame(&bytes[..n]).unwrap();
        assert_ne!(parse_tcp(ip).unwrap().flags & 0x04, 0); // 经真实 Flow/Router/REJECT 返回 RST。

        // 对端停止读取，重复 SYN 产生回包；仍应处理控制和独立停止。
        for _ in 0..512 {
            if peer.send(&frame).is_err() {
                break;
            }
        }
        assert!(engine.command(br#"{"cmd":"stats"}"#).get("error").is_none());
        let start = std::time::Instant::now();
        engine.stop();
        assert!(start.elapsed() < Duration::from_secs(2));
        // 保留 handle 和原 FD，stop 不能等待它们被析构，也不能关闭原 FD。
        assert!(local.peer_addr().is_ok());
        assert!(handle.input(Vec::new()).is_err());
    }

    #[test]
    fn startup_custom_range_reload_and_restart() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let config = "mode: direct\ngeo-auto-update: false\ngeox-url: {asn: ''}\ndns:\n  public-ip-url: ''\n  fake-ip-range: 10.8.0.0/20\nrules: ['MATCH,REJECT']\n";
        let mut engine = Engine::new(config.as_bytes(), br#"{"local_proxy":{"enabled":false}}"#).unwrap();
        for _ in 0..2 {
            engine.start_proxy_only().unwrap();
            assert!(engine.is_running());
            assert!(matches!(engine.start_proxy_only(), Err(EngineError::Busy(_))));
            assert_eq!(engine.command(br#"{"cmd":"stats"}"#)["mode"], "direct");
            let reload = json!({"cmd":"reload", "config":config.replace("mode: direct", "mode: global")});
            assert!(engine.command(&serde_json::to_vec(&reload).unwrap())["error"].is_null());
            for _ in 0..100 {
                if engine.command(br#"{"cmd":"stats"}"#)["mode"] == "global" { break; }
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(engine.command(br#"{"cmd":"stats"}"#)["mode"], "global");
            engine.stop();
            assert!(!engine.is_running());
            assert!(engine.warnings().is_empty());
        }
    }

    #[test]
    fn real_ip_domains_options_and_command_contract() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let config = b"rules: ['MATCH,REJECT']";
        assert!(Engine::new(config, br#"{"real_ip_domains":["https://invalid"]}"#).is_err());
        let opts = br#"{"local_proxy":{"enabled":false},"real_ip_domains":["Example.COM."]}"#;
        let mut engine = Engine::new(config, opts).unwrap();
        assert_eq!(engine.options.real_ip_domains, ["example.com"]);
        engine.set_output(Box::new(|_| {}));
        engine.start().unwrap();
        for req in [
            br#"{"cmd":"apply_settings","real_ip_domains":null}"#.as_slice(),
            br#"{"cmd":"apply_settings","real_ip_domains":["a","A"]}"#.as_slice(),
        ] {
            assert!(engine.command(req)["error"].is_string());
        }
        assert_eq!(engine.command(br#"{"cmd":"apply_settings","real_ip_domains":["*.example","?chaoxing"]}"#)["ok"], true);
        assert_eq!(engine.command(br#"{"cmd":"apply_settings","real_ip_domains":[]}"#)["ok"], true);
        engine.stop();
    }

    #[test]
    fn vif_engine_reflects_without_routing_and_keeps_active_plan() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let config = b"rules: ['MATCH,REJECT']\n";
        let opts = br#"{"local_proxy":{"enabled":false},"virtual_interface":{"loopbackAddresses":["10.7.0.1"]}}"#;
        let mut engine = Engine::new(config, opts).unwrap();
        let plan = engine.command(br#"{"cmd":"virtual_interface_plan"}"#);
        assert!(plan["required"].as_array().unwrap().contains(&json!("10.7.0.1/32")));
        let (local, peer) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        engine.start_utun(local.as_raw_fd()).unwrap();
        let packet = build_tcp("198.18.0.1:50000".parse().unwrap(), "10.7.0.1:8080".parse().unwrap(), 42, 0, 2, 65535, b"").unwrap();
        let mut frame = Vec::new(); encode_frame(IpVersion::V4, &packet, &mut frame).unwrap();
        peer.send(&frame).unwrap();
        let mut bytes = [0;2048]; let n = peer.recv(&mut bytes).unwrap();
        let (_, ip) = decode_frame(&bytes[..n]).unwrap();
        let reflected = parse_tcp(ip).unwrap();
        assert_eq!(reflected.src.to_string(), "10.7.0.1:50000");
        assert_eq!(reflected.dst.to_string(), "198.18.0.1:8080");
        assert_eq!((reflected.seq, reflected.flags), (42,2));
        assert_eq!(engine.command(br#"{"cmd":"stats"}"#)["tcp_total"], 0);
        assert_eq!(engine.command(br#"{"cmd":"virtual_interface_stats"}"#)["reflected"], 1);
        let reload = json!({"cmd":"reload", "config":"dns:\n  fake-ip-range: 10.8.0.0/20\nrules: ['MATCH,DIRECT']\n", "mode":"global"});
        let reply = engine.command(reload.to_string().as_bytes());
        assert_eq!(reply["requires_reconnect"], true, "{reply}");
        assert_eq!(engine.command(br#"{"cmd":"stats"}"#)["mode"], "rule");
        assert_eq!(engine.command(br#"{"cmd":"virtual_interface_plan"}"#), plan);
        assert_eq!(engine.command(br#"{"cmd":"apply_settings","ipv6_support":false}"#)["ok"], true);
        assert_eq!(engine.command(br#"{"cmd":"apply_settings","block_quic":"always"}"#)["ok"], true);
        assert!(engine.command(br#"{"cmd":"apply_settings","block_quic":"sometimes"}"#)["error"].is_string());
        peer.send(&frame).unwrap(); assert!(peer.recv(&mut bytes).unwrap() > 0);
        // 普通目标仍由 lwIP 恢复 Flow，REJECT 规则在握手后返回 RST。
        let ordinary = build_tcp("198.18.0.1:50001".parse().unwrap(), "203.0.113.1:443".parse().unwrap(), 1,0,2,65535,b"").unwrap();
        encode_frame(IpVersion::V4, &ordinary, &mut frame).unwrap(); peer.send(&frame).unwrap();
        let n = peer.recv(&mut bytes).unwrap(); let (_, ip) = decode_frame(&bytes[..n]).unwrap();
        let synack = parse_tcp(ip).unwrap(); assert_eq!(synack.flags & 0x12, 0x12);
        let ack = build_tcp(synack.dst, synack.src, 2, synack.seq.wrapping_add(1), 16,65535,b"").unwrap();
        encode_frame(IpVersion::V4, &ack, &mut frame).unwrap(); peer.send(&frame).unwrap();
        let n = peer.recv(&mut bytes).unwrap(); let (_, ip) = decode_frame(&bytes[..n]).unwrap();
        assert_ne!(parse_tcp(ip).unwrap().flags & 4, 0);
        engine.stop();
        // 测试回调入口经过同一 Netstack，不能另走一套反射逻辑。
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        let mut engine = Engine::new(config, opts).unwrap();
        engine.set_output(Box::new(move |batch| { for p in batch { let _ = tx.try_send(p.clone()); } }));
        engine.start().unwrap(); engine.input(vec![packet]).unwrap();
        let reflected = parse_tcp(&rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
        assert_eq!(reflected.src.to_string(), "10.7.0.1:50000");
        engine.stop();
    }

    /// 回归：读空 utun 后必须登记读就绪唤醒。空闲一段时间后送入的 SYN，
    /// 应在远小于 lwIP 定时器间隔（最长约 1 秒）的时间内得到回应。
    #[test]
    fn utun_engine_wakes_promptly_after_idle() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (local, peer) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut engine = Engine::new(b"rules:\n  - MATCH,REJECT\n", b"{}").unwrap();
        engine.start_with_utun_fd(Some(local.as_raw_fd())).unwrap();
        let mut bytes = [0; 2048];
        let mut worst = Duration::ZERO;
        for i in 0..6u16 {
            // 让事件循环空闲下来，lwIP 定时器进入较长的睡眠
            std::thread::sleep(Duration::from_millis(400));
            let packet = build_tcp(
                format!("198.18.0.10:{}", 41000 + i).parse().unwrap(),
                "203.0.113.7:443".parse().unwrap(),
                1,
                0,
                TCP_FLAG_SYN,
                65535,
                &[],
            )
            .unwrap();
            let mut frame = Vec::new();
            encode_frame(IpVersion::V4, &packet, &mut frame).unwrap();
            let start = std::time::Instant::now();
            peer.send(&frame).unwrap();
            let n = peer.recv(&mut bytes).unwrap();
            worst = worst.max(start.elapsed());
            let (_, ip) = decode_frame(&bytes[..n]).unwrap();
            assert_eq!(parse_tcp(ip).unwrap().ack, 2);
        }
        engine.stop();
        assert!(worst < Duration::from_millis(100), "worst SYN-ACK latency {worst:?}");
    }
}

/// Core 的压力等级换成 WG 出站的等级（两者含义一致，分别定义以免 oryn-wireguard 依赖 Core）。
fn wireguard_pressure(level: crate::admission::PressureLevel) -> oryn_outbound::wireguard_resources::Pressure {
    use crate::admission::PressureLevel as P;
    use oryn_outbound::wireguard_resources::Pressure as W;
    match level {
        P::Normal => W::Normal,
        P::Elevated => W::Elevated,
        P::Critical => W::Critical,
    }
}
