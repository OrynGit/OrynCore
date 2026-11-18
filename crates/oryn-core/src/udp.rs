//! UDP：发往隧道 DNS 地址的查询交给 DNS Engine，其余按 (源, 目的) 建立会话。
//!
//! 每个会话是一个 Flow，只路由一次（路由前可对 QUIC 嗅探）；实际任务与队列均有硬上限。
//! 关闭会话会永久取消整条处理链；任务真正退出时才归还额度。

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use log::{debug, warn};
use oryn_config::TargetAddr;
use oryn_netstack::{NetStack, UdpDatagram};
use oryn_outbound::{resolve, PickMeta};
use oryn_router::{DomainSource, FlowContext, Network};
use tokio::sync::{mpsc, watch};

use crate::context::{EngineCtx, MAX_CONCURRENT_DNS};
use crate::sniff::{self, QuicProbe, SNIFF_TIMEOUT};

pub(crate) const CONSTRAINED_MAX_SESSIONS: usize = 512;
#[allow(dead_code)]
pub(crate) const DESKTOP_HIGH_MAX_SESSIONS: usize = 2048;
#[cfg(test)]
const MAX_SESSIONS: usize = CONSTRAINED_MAX_SESSIONS;
const SESSION_QUEUE: usize = 64;
const SESSION_QUEUE_BYTES: usize = 256 * 1024;
const TOTAL_SESSION_QUEUE_BYTES: usize = 4 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// 被拒绝或建立失败的会话只为吸收同一五元组的后续包（免得每包重新路由），
/// 不必活满正常会话的空闲时间：QUIC 洪泛被拒时空转任务不再堆积 60 秒。
const DEAD_SESSION_IDLE: Duration = Duration::from_secs(10);
/// 每个会话的接收缓冲。隧道 MTU 之上的数据报本来也无法写回，因此不需要 64 KiB。
const RECV_BUF: usize = 4096;

type Key = (SocketAddr, SocketAddr);

struct Session {
    close: watch::Sender<bool>,
    tx: mpsc::Sender<Vec<u8>>,
    queued_bytes: Rc<Cell<usize>>,
    generation: u64,
    last_active: Rc<Cell<Instant>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        // 独立于数据队列，移除即通知，不等待缓冲包排空。
        self.close.send_replace(true);
    }
}

pub struct UdpManager {
    sessions: RefCell<HashMap<Key, Session>>,
    generation: Cell<u64>,
    queued_bytes: Rc<Cell<usize>>,
    /// 删除表项不等于任务退出；额度必须跟随真实 future 的所有权。
    tasks: Rc<Cell<usize>>,
    max_sessions: usize,
}

struct TaskPermit(Rc<Cell<usize>>);
impl Drop for TaskPermit {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

/// 接收队列与预算同寿命：任务未 poll、取消或提前返回也归还剩余计费。
struct SessionQueue {
    _task: TaskPermit,
    rx: mpsc::Receiver<Vec<u8>>,
    bytes: Rc<Cell<usize>>,
    total: Rc<Cell<usize>>,
    ctx: Weak<EngineCtx>,
    key: Key,
    generation: u64,
}

impl SessionQueue {
    async fn recv(&mut self) -> Option<Vec<u8>> {
        let payload = self.rx.recv().await?;
        self.bytes
            .set(self.bytes.get().saturating_sub(payload.len()));
        self.total
            .set(self.total.get().saturating_sub(payload.len()));
        Some(payload)
    }
}

impl Drop for SessionQueue {
    fn drop(&mut self) {
        // 正常出队已经退账；这里只归还尚在队列内的剩余量。
        self.rx.close();
        self.total
            .set(self.total.get().saturating_sub(self.bytes.replace(0)));
        if let Some(ctx) = self.ctx.upgrade() {
            ctx.udp.remove_if(&self.key, self.generation);
        }
    }
}

impl Default for UdpManager {
    fn default() -> Self {
        Self::new(CONSTRAINED_MAX_SESSIONS)
    }
}

impl UdpManager {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: RefCell::new(HashMap::new()),
            generation: Cell::new(0),
            queued_bytes: Rc::new(Cell::new(0)),
            tasks: Rc::new(Cell::new(0)),
            max_sessions,
        }
    }

    pub fn count(&self) -> usize {
        self.sessions.borrow().len()
    }

    #[cfg(test)]
    pub(crate) fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// 丢弃全部表项并通知任务永久退出；额度仍由任务 RAII 归还。
    pub fn clear(&self) {
        self.sessions.borrow_mut().clear();
    }

    fn remove_if(&self, key: &Key, generation: u64) {
        let mut s = self.sessions.borrow_mut();
        if s.get(key).is_some_and(|x| x.generation == generation) {
            s.remove(key);
        }
    }

    fn acquire_task(&self) -> Option<TaskPermit> {
        if self.tasks.get() >= self.max_sessions {
            return None;
        }
        self.tasks.set(self.tasks.get() + 1);
        Some(TaskPermit(self.tasks.clone()))
    }

    fn reserve(&self, len: usize) -> bool {
        if len > SESSION_QUEUE_BYTES {
            return false;
        }
        let Some(next) = self.queued_bytes.get().checked_add(len) else {
            return false;
        };
        if next > TOTAL_SESSION_QUEUE_BYTES {
            return false;
        }
        self.queued_bytes.set(next);
        true
    }

    fn release(&self, len: usize) {
        self.queued_bytes
            .set(self.queued_bytes.get().saturating_sub(len));
    }
}

pub fn handle_datagram(ctx: &Rc<EngineCtx>, dg: UdpDatagram) {
    // 合成吞吐端点（198.18.0.4）：测量用，直接丢弃并计数，不进路由与出站
    if dg.dst.ip() == std::net::IpAddr::V4(crate::virtual_interface::SYNTHETIC_V4) {
        crate::perf::add(&crate::perf::SYNTH_UDP_PKTS, 1);
        crate::perf::add(&crate::perf::SYNTH_UDP_BYTES, dg.payload.len() as u64);
        return;
    }
    if ctx.is_dns_target(false, dg.dst.ip(), dg.dst.port()) {
        handle_dns(ctx, dg);
        return;
    }

    let key = (dg.src, dg.dst);
    {
        let sessions = ctx.udp.sessions.borrow();
        if let Some(s) = sessions.get(&key) {
            s.last_active.set(Instant::now());
            // 队列满时丢弃：UDP 本身允许丢包
            let payload_len = dg.payload.len();
            if s.queued_bytes
                .get()
                .checked_add(payload_len)
                .is_some_and(|bytes| bytes <= SESSION_QUEUE_BYTES)
                && ctx.udp.reserve(payload_len)
            {
                if s.tx.try_send(dg.payload).is_ok() {
                    s.queued_bytes
                        .set(s.queued_bytes.get().saturating_add(payload_len));
                } else {
                    ctx.udp.release(payload_len);
                }
            }
            return;
        }
    }

    // 先拿实际任务名额，覆盖分配队列与 spawn 后尚未 poll 的时期。
    // 满额只丢新会话的数据报，保留现有会话；不能淘汰表项后无限创建 Pending 任务。
    let Some(task) = ctx.udp.acquire_task() else {
        return;
    };
    let mut sessions = ctx.udp.sessions.borrow_mut();
    let payload_len = dg.payload.len();
    if !ctx.udp.reserve(payload_len) {
        return;
    }
    let (tx, rx) = mpsc::channel(SESSION_QUEUE);
    let queued_bytes = Rc::new(Cell::new(0));
    if tx.try_send(dg.payload).is_ok() {
        queued_bytes.set(payload_len);
    } else {
        ctx.udp.release(payload_len);
        return;
    }
    let generation = ctx.udp.generation.get() + 1;
    ctx.udp.generation.set(generation);
    let last_active = Rc::new(Cell::new(Instant::now()));
    sessions.insert(
        key,
        Session {
            close: watch::channel(false).0,
            tx,
            queued_bytes: queued_bytes.clone(),
            generation,
            last_active: last_active.clone(),
        },
    );
    drop(sessions);

    // 在 future 创建前构造，覆盖 spawn 后尚未首次 poll 就被取消的情况。
    let queue = SessionQueue {
        _task: task,
        rx,
        bytes: queued_bytes,
        total: ctx.udp.queued_bytes.clone(),
        ctx: Rc::downgrade(ctx),
        key,
        generation,
    };
    tokio::task::spawn_local(run_session(ctx.clone(), key, queue, last_active));
}

async fn run_session(
    ctx: Rc<EngineCtx>,
    key: Key,
    mut rx: SessionQueue,
    last_active: Rc<Cell<Instant>>,
) {
    let Some(mut close) = ctx
        .udp
        .sessions
        .borrow()
        .get(&key)
        .filter(|s| s.generation == rx.generation)
        .map(|s| s.close.subscribe())
    else {
        return;
    };
    let idle = Cell::new(IDLE_TIMEOUT);
    // 整条处理链只创建一次；取消后丢弃 PacketConn，不重试部分完成的 send。
    // 共享协议既有的 fail-closed 边界仍可能关闭共享承载。
    tokio::select! {
        biased;
        _ = async { while !*close.borrow_and_update() {
            if close.changed().await.is_err() { break; }
        }} => {},
        _ = async { loop {
            tokio::time::sleep_until(tokio::time::Instant::from_std(last_active.get() + idle.get())).await;
            if last_active.get().elapsed() >= idle.get() { break; }
        }} => {},
        _ = run_session_io(&ctx, key, &mut rx, &last_active, &idle) => {},
    }
}

async fn run_session_io(
    ctx: &Rc<EngineCtx>,
    key: Key,
    rx: &mut SessionQueue,
    last_active: &Rc<Cell<Instant>>,
    idle_limit: &Cell<Duration>,
) {
    let (source, destination) = key;
    let id = ctx.next_id();
    ctx.stats.udp_total.fetch_add(1, Ordering::Relaxed);
    if crate::virtual_interface::is_tunnel_subnet(destination.ip()) {
        warn!("UDP #{id} {source} → {destination} is inside the tunnel subnet; dropped");
        return;
    }

    let state = ctx.state();
    let fake_ip = ctx.dns.is_fake_ip(&destination.ip());
    let mut flow = FlowContext::new(id, Network::Udp, source, destination);
    if fake_ip {
        if let Some(domain) = ctx.dns.lookup_fake_domain(&destination.ip()) {
            flow.set_domain(domain, DomainSource::FakeIp);
        }
    } else if let Some(domain) = ctx.dns.lookup_domain(&destination.ip()) {
        flow.set_domain(domain, DomainSource::DnsMapping);
    }
    let mapping_missing = fake_ip && flow.domain.is_none();

    // 映射缺失时先从 QUIC Initial 找回域名，避免把 Fake-IP 当真实地址拨出去。
    let mut pending: Vec<Vec<u8>> = Vec::new();
    if mapping_missing {
        let mut probe = QuicProbe::new();
        let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(payload)) => match probe.push_any(payload) {
                    Some(Some(domain)) => {
                        warn!("UDP #{id} {source} → {destination} Fake-IP mapping missing; recovered {domain}");
                        ctx.dns.remember_fake_ip(&destination.ip(), &domain);
                        flow.set_domain(domain, DomainSource::Sniffed);
                        break;
                    }
                    Some(None) => break,
                    None => {}
                },
                Ok(None) => return,
                Err(_) => break,
            }
        }
        pending = probe.datagrams;
        if flow.domain.is_none() {
            warn!("UDP #{id} {source} → {destination} Fake-IP mapping missing; dropped");
            return;
        }
    }

    // 仅在当前规则表会走到 IP 类规则时解析一次真实地址。
    if fake_ip && state.router().needs_ip_resolution(&flow) {
        if let Some(domain) = flow.domain.clone() {
            if let Ok(ips) = ctx.dns.resolve_direct_target(&domain).await {
                if let Some(ip) = ips.into_iter().next() {
                    flow.destination = SocketAddr::new(ip, destination.port());
                }
            }
        }
    }

    // QUIC 嗅探：路由前先收集首批数据报
    let mut override_destination = false;
    let global_quic_block = ctx.block_quic() == "always" && destination.port() == 443;
    let mitm_quic_block = ctx.block_quic() != "never"
        && state.config.mitm.enabled
        && state.config.mitm.auto_quic_block
        && destination.port() == 443;
    if !fake_ip
        && (sniff::quic_applies(&state.config.sniffer, &flow)
            || global_quic_block
            || mitm_quic_block)
    {
        let mut probe = QuicProbe::new();
        let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(payload)) => {
                    if let Some(result) = probe.push(&state.config.sniffer, payload) {
                        if let Some(s) = result {
                            flow.set_domain(s.domain, DomainSource::Sniffed);
                            override_destination = s.override_destination;
                        }
                        break;
                    }
                }
                Ok(None) => return,
                Err(_) => break,
            }
        }
        pending = probe.datagrams;
    }

    // `PROTOCOL,QUIC` 等规则看首个数据报；会话由数据报创建，通常已在队列中。
    let payload_rules = state.router().needs_payload(&flow);
    if global_quic_block || mitm_quic_block || payload_rules {
        if pending.is_empty() {
            if let Ok(Some(data)) = tokio::time::timeout(SNIFF_TIMEOUT, rx.recv()).await {
                pending.push(data);
            }
        }
        flow.is_quic = pending.first().is_some_and(|d| is_quic_initial(d));
        if global_quic_block && flow.is_quic {
            ctx.conns.record_failed(
                &flow,
                vec!["REJECT".to_string()],
                "BLOCK-QUIC".to_string(),
                "quic",
                "QUIC is blocked",
            );
            return;
        }
    }
    flow.package = crate::android_package::lookup(&flow);
    let decision = state.router().route(&flow);
    flow.route = Some(decision);
    let rule = state.router().rule_text(decision.rule);
    let target = match (&flow.domain, fake_ip || override_destination) {
        (Some(d), true) => TargetAddr::Domain(d.clone(), destination.port()),
        _ => TargetAddr::Ip(destination),
    };
    let start = state.routing.outbounds[decision.outbound].clone();
    let resolved = resolve(
        &start,
        &PickMeta {
            source: Some(source),
            target: &target,
            network: Network::Udp,
        },
    );
    let chain: Vec<String> = resolved
        .as_ref()
        .map(|r| r.chain.clone())
        .unwrap_or_else(|| vec![start.tag().to_string()]);
    let label = sniff::label(&flow, destination);
    debug!(
        "UDP #{id} {source} → {label} matched {rule} → {}",
        chain.join(" → ")
    );
    let conn = ctx.conns.register(&flow, chain.clone(), rule);
    if flow.is_quic || pending.first().is_some_and(|d| is_quic_initial(d)) {
        conn.set_protocol("quic");
    }
    drop(state);

    let cancelled = conn.cancelled();
    tokio::pin!(cancelled);
    // 覆盖 bind、嗅探保留首包与普通发送；任意阶段取消均永久结束。
    let io = async {
        let packet_conn = match resolved {
            Some(r) if !r.leaf.is_reject() => match r.leaf.bind_udp(&target).await {
                Ok(c) => Some(c),
                Err(e) => {
                    warn!(
                        "UDP #{id} {label} via {} failed to set up: {e}",
                        chain.join(" → ")
                    );
                    conn.set_error(&e);
                    None
                }
            },
            _ => {
                conn.set_error("Rejected by policy");
                None
            }
        };

        if let Some(pc) = &packet_conn {
            for payload in pending.drain(..) {
                if pc.send_to(&payload, &target).await.is_ok() {
                    conn.add_up(payload.len() as u64);
                    ctx.stats.add_up(payload.len() as u64);
                }
            }
        }

        // 被拒绝的会话不收包，不分配接收缓冲
        let mut buf = if packet_conn.is_some() {
            vec![0u8; RECV_BUF]
        } else {
            Vec::new()
        };
        let idle = if packet_conn.is_some() {
            IDLE_TIMEOUT
        } else {
            DEAD_SESSION_IDLE
        };
        idle_limit.set(idle);
        loop {
            let deadline = tokio::time::Instant::from_std(last_active.get() + idle);
            match &packet_conn {
                // 被拒绝或建立失败：在空闲超时前持续丢弃，避免每个包都重新路由
                None => tokio::select! {
                    p = rx.recv() => match p {
                        Some(_) => {} // recv 已经退账。
                        None => break,
                    },
                    _ = tokio::time::sleep_until(deadline) => {
                        if last_active.get().elapsed() >= idle { break; }
                    }
                },
                Some(pc) => tokio::select! {
                    p = rx.recv() => match p {
                        Some(payload) => {
                            let n = payload.len() as u64;
                            if let Err(e) = pc.send_to(&payload, &target).await {
                                debug!("UDP #{id} send failed: {e}");
                            } else {
                                conn.add_up(n);
                                ctx.stats.add_up(n);
                            }
                        }
                        None => break,
                    },
                    r = pc.recv_from(&mut buf) => match r {
                        Ok((n, from)) => {
                            let from = match from {
                                TargetAddr::Ip(a) if !override_destination && !fake_ip => a,
                                // 改写了目标（或返回域名）时，回包以应用原本的目的地址作为来源
                                _ => destination,
                            };
                            last_active.set(Instant::now());
                            ctx.stack.send_udp(from, source, &buf[..n]);
                            conn.add_down(n as u64);
                            ctx.stats.add_down(n as u64);
                        }
                        Err(e) => {
                            debug!("UDP #{id} receive failed: {e}");
                            break;
                        }
                    },
                    _ = tokio::time::sleep_until(deadline) => {
                        if last_active.get().elapsed() >= idle { break; }
                    }
                },
            }
        }
    };
    tokio::select! {
        biased;
        _ = &mut cancelled => {},
        _ = io => {},
    }
    drop(conn); // SessionQueue 退账并按 generation 移除会话。
}

/// QUIC v1 / v2 的长包头（Initial 等）。
fn is_quic_initial(d: &[u8]) -> bool {
    d.len() >= 5
        && d[0] & 0xc0 == 0xc0
        && matches!(&d[1..5], [0, 0, 0, 1] | [0x6b, 0x33, 0x43, 0xcf])
}

#[cfg(test)]
#[path = "udp_performance_survey.rs"]
pub(crate) mod performance_survey;

#[cfg(test)]
#[path = "udp_pending_tests.rs"]
mod pending_tests;

fn handle_dns(ctx: &Rc<EngineCtx>, dg: UdpDatagram) {
    if ctx.dns_inflight.get() >= MAX_CONCURRENT_DNS {
        debug!("too many concurrent DNS queries, dropping query");
        return;
    }
    ctx.dns_inflight.set(ctx.dns_inflight.get() + 1);
    let ctx = ctx.clone();
    tokio::task::spawn_local(async move {
        ctx.stats.dns_queries.fetch_add(1, Ordering::Relaxed);
        let (resp, outcome) = ctx.dns.handle_query(&dg.payload, dg.src).await;
        if let Some(domain) = &outcome.domain {
            debug!(
                "DNS {domain} → {} via {}{}",
                outcome.upstream.as_deref().unwrap_or("-"),
                outcome.via.as_deref().unwrap_or("-"),
                if outcome.cached { " (cached)" } else { "" }
            );
        }
        ctx.stack.send_udp(dg.dst, dg.src, &resp);
        ctx.dns_inflight.set(ctx.dns_inflight.get() - 1);
    });
}
