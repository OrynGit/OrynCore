//! 按目标学习的 Smart。物理拨号仅在可观测适配器中记账，未知路径不伪装成双栈。
use crate::{BoxStream, Dialer, Outbound, PacketConn, PickMeta, Resolver, SessionControl};
use async_trait::async_trait;
use oryn_config::{ServerStrategy, SmartSpec, SmartTuning, TargetAddr};
use oryn_router::Network;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_RECORDS: usize = 16384;
const MAX_LEASES: usize = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    Unknown,
    V4,
    V6,
}
impl Family {
    fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }
}
#[derive(Clone)]
pub struct Candidate {
    pub node: String,
    pub family: Family,
    pub outbound: Arc<dyn Outbound>,
    pub factor: f64,
    pub tcp_only: bool,
    pub server: Option<TargetAddr>,
    pub udp_only: bool,
    pub supports_udp: bool,
}
#[derive(Clone, Debug)]
struct Evidence {
    success: f64,
    failure: f64,
    delay: Option<f64>,
    jitter: f64,
    at: Instant,
}
impl Default for Evidence {
    fn default() -> Self {
        Self {
            success: 0.0,
            failure: 0.0,
            delay: None,
            jitter: 0.0,
            at: Instant::now(),
        }
    }
}
impl Evidence {
    fn values(&self, now: Instant, t: &SmartTuning) -> (f64, f64) {
        let decay = 2f64.powf(-now.duration_since(self.at).as_secs_f64() / t.half_life_secs);
        (self.success * decay, self.failure * decay)
    }
    fn reliability(&self, now: Instant, t: &SmartTuning) -> f64 {
        self.reliability_with(now, t, 0.9)
    }
    fn reliability_with(&self, now: Instant, t: &SmartTuning, prior: f64) -> f64 {
        let (s, f) = self.values(now, t);
        (s + prior * t.prior_strength) / (s + f + t.prior_strength)
    }
    fn record(&mut self, success: bool, delay: Option<f64>, now: Instant, t: &SmartTuning) {
        let (s, f) = self.values(now, t);
        self.success = s + f64::from(success);
        self.failure = f + f64::from(!success);
        self.at = now;
        if let Some(d) = delay {
            if let Some(old) = self.delay {
                self.jitter = self.jitter * 0.8 + (d - old).abs() * 0.2;
                self.delay = Some(old * 0.8 + d * 0.2);
            } else {
                self.delay = Some(d);
            }
        }
    }
}
#[derive(Default)]
struct PathHealth {
    evidence: Evidence,
    failures: u32,
    last_failure: Option<Instant>,
    open_until: Option<Instant>,
    cooldown: u64,
    recovering: bool,
}
impl PathHealth {
    fn eligible(&self, now: Instant) -> bool {
        self.open_until
            .is_none_or(|until| until <= now && !self.recovering)
    }
    fn record(&mut self, success: bool, delay: Option<f64>, now: Instant, t: &SmartTuning) {
        self.evidence.record(success, delay, now, t);
        self.recovering = false;
        if success {
            self.failures = 0;
            self.open_until = None;
            self.cooldown = 0;
        } else {
            if self.last_failure.is_none_or(|at| {
                now.duration_since(at) > Duration::from_secs(t.failure_window_secs)
            }) {
                self.failures = 0;
            }
            self.failures += 1;
            self.last_failure = Some(now);
            if self.failures >= t.consecutive_failures || self.open_until.is_some() {
                self.cooldown = (self.cooldown * 2).clamp(t.open_initial_secs, t.open_max_secs);
                self.open_until = Some(now + Duration::from_secs(self.cooldown));
            }
        }
    }
}
#[derive(Clone, PartialEq, Eq, Hash)]
struct PathKey(String, Family);
#[derive(Clone, PartialEq, Eq, Hash)]
struct TargetKey(String, bool, PathKey);
struct Lease {
    path: PathKey,
    created: Instant,
    used: Instant,
    challenger: Option<PathKey>,
    confirmations: u8,
    evaluated: Instant,
}
#[derive(Default)]
pub struct State {
    epoch: u64,
    tuning: SmartTuning,
    /// 目标键的 HMAC 密钥；只有摘要进入统计与磁盘。
    salt: [u8; 16],
    loaded: bool,
    dirty: bool,
    store: Option<std::path::PathBuf>,
    probes: HashMap<PathKey, Evidence>,
    new_leases: u64,
    paths: HashMap<PathKey, PathHealth>,
    targets: HashMap<TargetKey, Evidence>,
    endpoints: HashMap<(PathKey, SocketAddr), PathHealth>,
    leases: HashMap<(IpAddr, String), Lease>,
}
#[derive(Default)]
pub struct Registry {
    states: Mutex<HashMap<String, Arc<Mutex<State>>>>,
}
impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartRegistry")
            .field("groups", &self.states.lock().unwrap().len())
            .finish()
    }
}
impl Registry {
    pub fn get(&self, key: String) -> Arc<Mutex<State>> {
        let mut states = self.states.lock().unwrap();
        if let Some(s) = states.get(&key) {
            return s.clone();
        }
        if states.len() >= 64 {
            states.retain(|_, s| Arc::strong_count(s) > 1);
        }
        // 满载只跳过跨重载复用，不扩大注册表。
        let state = Arc::new(Mutex::new(State {
            salt: rand::random(),
            ..State::default()
        }));
        if states.len() < 64 {
            states.insert(key, state.clone());
        }
        state
    }
}
pub struct Smart {
    pub resolver: Option<Arc<dyn Resolver>>,
    pub candidates: Vec<Candidate>,
    pub spec: SmartSpec,
    pub state: Arc<Mutex<State>>,
}
fn host(target: &TargetAddr) -> String {
    match target {
        TargetAddr::Domain(d, _) => d.trim_end_matches('.').to_lowercase(),
        TargetAddr::Ip(a) => a.ip().to_string(),
    }
}
impl Smart {
    fn target_key(&self, target: &TargetAddr) -> String {
        let host = host(target);
        if matches!(target, TargetAddr::Domain(_, _)) {
            if let Some((id, _)) =
                self.spec.services.iter().find(|(_, patterns)| {
                    patterns.iter().any(|p| oryn_config::glob_match(p, &host))
                })
            {
                return format!("service:{id}");
            }
        }
        host
    }

    /// 可注册域名（公共后缀列表）；本身就是可注册域名、IP 或显式服务时没有站点先验。
    fn site_key(&self, target: &TargetAddr) -> Option<String> {
        if !self.spec.tuning.site_prior {
            return None;
        }
        let TargetAddr::Domain(_, _) = target else {
            return None;
        };
        let host = host(target);
        if self.target_key(target) != host {
            return None;
        }
        psl::domain_str(&host)
            .filter(|site| *site != host)
            .map(|site| format!("site:{site}"))
    }

    pub fn pick(self: &Arc<Self>, meta: &PickMeta) -> Option<Arc<dyn Outbound>> {
        let plain = self.target_key(meta.target);
        let udp = meta.network == Network::Udp;
        let client = meta
            .source
            .map(|s| s.ip())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let target = digest(&state.salt, &plain);
        let site = self.site_key(meta.target).map(|s| digest(&state.salt, &s));
        let t = state.tuning;
        let idle = Duration::from_secs(t.idle_timeout_secs);
        // 每个候选的路径键与目标键只构造一次：原来打分、两轮可靠性过滤、探索与租约比较
        // 各自克隆节点名和目标摘要，全部发生在组锁内。
        let keys: Vec<(PathKey, TargetKey)> = self
            .candidates
            .iter()
            .map(|c| {
                let path = PathKey(c.node.clone(), c.family);
                let key = TargetKey(target.clone(), udp, path.clone());
                (path, key)
            })
            .collect();
        let mut scored: Vec<(usize, f64)> = self
            .candidates
            .iter()
            .enumerate()
            .filter(|(i, c)| {
                !c.outbound.is_reject()
                    && !(!udp && c.udp_only)
                    && !(udp && (c.tcp_only || !c.supports_udp))
                    && !(udp && c.outbound.kind() == "http")
                    && !(udp
                        && (self.spec.require_family_control
                            || matches!(
                                self.spec.server_strategy,
                                ServerStrategy::V4Only | ServerStrategy::V6Only
                            )))
                    && state.paths.get(&keys[*i].0).is_none_or(|p| p.eligible(now))
            })
            .map(|(i, c)| {
                let path = &keys[i].0;
                let carrier = state.paths.get(path).map(|p| &p.evidence);
                let target_stats = state.targets.get(&keys[i].1);
                // 未观测路径只有一份端到端证据，不重复相乘。
                // 站点先验只取兄弟主机的证据（站点总量减去本主机），避免同一批样本重复计数。
                let prior = site
                    .as_ref()
                    .and_then(|site| {
                        state
                            .targets
                            .get(&TargetKey(site.clone(), udp, path.clone()))
                    })
                    .map_or(0.9, |p| {
                        let (ps, pf) = p.values(now, &t);
                        let (hs, hf) = target_stats.map_or((0.0, 0.0), |h| h.values(now, &t));
                        let (s, f) = ((ps - hs).max(0.0), (pf - hf).max(0.0));
                        (s + 0.9 * t.prior_strength) / (s + f + t.prior_strength)
                    });
                let r = target_stats.map_or(prior, |s| s.reliability_with(now, &t, prior))
                    * if c.family == Family::Unknown {
                        1.0
                    } else {
                        carrier.map_or(0.9, |s| s.reliability(now, &t))
                    };
                let d = carrier
                    .and_then(|s| s.delay)
                    .or_else(|| state.probes.get(path).and_then(|p| p.delay))
                    .unwrap_or(300.0);
                let j = carrier.map_or(0.0, |s| s.jitter);
                let preferred = matches!(
                    (self.spec.server_strategy, c.family),
                    (ServerStrategy::PreferV4, Family::V4) | (ServerStrategy::PreferV6, Family::V6)
                );
                (
                    i,
                    r.powi(3) / (1.0 + d / 300.0) / (1.0 + j / 100.0)
                        * c.factor
                        * if preferred { 1.03 } else { 1.0 }
                        * match c.family {
                            Family::V4 => t.family_v4,
                            Family::V6 => t.family_v6,
                            Family::Unknown => 1.0,
                        },
                )
            })
            .collect();
        // 有足够证据且显著不可靠时，名称权重不得让其回到正常池。
        // 每个候选只算一次，下面的下界与过滤两轮共用
        let mut reliabilities = vec![None; self.candidates.len()];
        for &(i, _) in &scored {
            reliabilities[i] = state.targets.get(&keys[i].1).map(|s| {
                let (a, b) = s.values(now, &t);
                (s.reliability(now, &t), a + b)
            });
        }
        let reliability = |i: usize| reliabilities[i];
        let best_lower = scored
            .iter()
            .filter_map(|(i, _)| reliability(*i))
            .filter(|(_, n)| *n >= t.min_samples)
            .map(|(p, n)| p - 2.0 * (p * (1.0 - p) / (n + t.prior_strength)).sqrt())
            .fold(0.0, f64::max);
        scored.retain(|(i, _)| {
            reliability(*i).is_none_or(|(p, n)| {
                n < t.min_samples
                    || p + 2.0 * (p * (1.0 - p) / (n + t.prior_strength)).sqrt()
                        >= best_lower - 0.05
            })
        });
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        let &(mut chosen, best) = scored.first()?;
        if !state
            .leases
            .get(&(client, target.clone()))
            .is_some_and(|l| now.duration_since(l.used) < idle)
        {
            state.new_leases = state.new_leases.wrapping_add(1);
            if t.explore_ratio > 0.0
                && state
                    .new_leases
                    .is_multiple_of((1.0 / t.explore_ratio).round().max(1.0) as u64)
            {
                chosen = scored
                    .iter()
                    .min_by(|(a, _), (b, _)| {
                        let evidence = |i: usize| {
                            state.targets.get(&keys[i].1).map_or(0.0, |s| {
                                let (a, b) = s.values(now, &t);
                                a + b
                            })
                        };
                        evidence(*a).total_cmp(&evidence(*b))
                    })
                    .map_or(chosen, |(i, _)| *i);
            }
        }
        let lease_key = (client, target.clone());
        if let Some(lease) = state.leases.get_mut(&lease_key) {
            if now.duration_since(lease.used) < idle {
                if let Some(&(current, score)) =
                    scored.iter().find(|(i, _)| lease.path == keys[*i].0)
                {
                    if now.duration_since(lease.created) < Duration::from_secs(t.min_hold_secs)
                        || best <= score * (1.0 + t.switch_margin)
                    {
                        chosen = current;
                        lease.confirmations = 0;
                    } else {
                        let key = keys[chosen].0.clone();
                        if now.duration_since(lease.evaluated) >= Duration::from_secs(10) {
                            lease.confirmations = if lease.challenger.as_ref() == Some(&key) {
                                lease.confirmations + 1
                            } else {
                                1
                            };
                            lease.challenger = Some(key);
                            lease.evaluated = now;
                        }
                        if lease.confirmations < t.switch_confirmations {
                            chosen = current;
                        }
                    }
                    lease.used = now;
                }
            }
        }
        let candidate = &self.candidates[chosen];
        let path = keys[chosen].0.clone();
        if state.leases.len() >= MAX_LEASES && !state.leases.contains_key(&lease_key) {
            if let Some(old) = state
                .leases
                .iter()
                .min_by_key(|(_, v)| v.used)
                .map(|(k, _)| k.clone())
            {
                state.leases.remove(&old);
            }
        }
        if state
            .leases
            .get(&lease_key)
            .is_none_or(|l| l.path != path || now.duration_since(l.used) >= idle)
        {
            state.leases.insert(
                lease_key,
                Lease {
                    path,
                    created: now,
                    used: now,
                    challenger: None,
                    confirmations: 0,
                    evaluated: now,
                },
            );
        }
        let epoch = state.epoch;
        drop(state);
        // 以节点最佳路径排序；地址数量不产生额外抽签机会。
        let mut order = vec![chosen];
        order.extend(
            scored
                .iter()
                .map(|(i, _)| *i)
                .filter(|i| *i != chosen && self.candidates[*i].node == candidate.node),
        );
        order.extend(
            scored
                .iter()
                .map(|(i, _)| *i)
                .filter(|i| self.candidates[*i].node != candidate.node),
        );
        if order.len() < usize::from(t.max_attempts) {
            let repeat: Vec<_> = order
                .iter()
                .copied()
                .filter(|i| self.candidates[*i].family != Family::Unknown)
                .collect();
            order.extend(repeat);
        }
        log::debug!(
            "smart select node={} family={} target={} network={:?} score={:.4}",
            candidate.outbound.tag(),
            candidate.family.name(),
            plain,
            meta.network,
            scored
                .iter()
                .find(|(i, _)| *i == chosen)
                .map_or(0.0, |(_, s)| *s)
        );
        Some(Arc::new(Plan {
            smart: self.clone(),
            order,
            target,
            site,
            udp,
            epoch,
            client,
            winner: Mutex::new(None),
        }))
    }
}
impl SessionControl for Smart {
    fn on_network_changed(&self) {
        let mut s = self.state.lock().unwrap();
        let epoch = s.epoch.wrapping_add(1);
        // 学习状态清空，但密钥与存储位置保留。标记为脏：下一次保存写出空快照覆盖磁盘上的旧证据，
        // 否则在新网络积累到证据之前重启，会把已失效网络的路径经验读回来。
        let store = s.store.take();
        *s = State {
            epoch,
            salt: s.salt,
            loaded: true,
            store,
            tuning: s.tuning,
            dirty: true,
            ..State::default()
        };
    }
    fn on_sleep(&self) {}
    fn on_wake(&self) {
        self.on_network_changed();
    }
}
struct Plan {
    smart: Arc<Smart>,
    order: Vec<usize>,
    target: String,
    site: Option<String>,
    udp: bool,
    epoch: u64,
    client: IpAddr,
    winner: Mutex<Option<usize>>,
}
#[derive(Clone)]
struct Trace {
    state: Arc<Mutex<State>>,
    path: PathKey,
    epoch: u64,
    endpoint: Arc<Mutex<Option<SocketAddr>>>,
    carrier_ready: Arc<std::sync::atomic::AtomicBool>,
}
tokio::task_local! { static TRACE: Trace; }
/// 每个变体有独立拨号器；不修改传给协议的服务器身份。
pub struct FamilyDialer {
    pub resolver: Arc<dyn Resolver>,
    pub family: Family,
}
#[async_trait]
impl Dialer for FamilyDialer {
    async fn dial_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let addrs = crate::resolve_target(&*self.resolver, target).await?;
        let trace = TRACE.try_with(Clone::clone).ok();
        let addrs: Vec<_> = addrs
            .into_iter()
            .filter(|a| a.is_ipv6() == (self.family == Family::V6))
            .collect();
        // 排序与挑选在同一次加锁里完成，每个地址只查一次记录（原来每次比较、每个候选各加锁并克隆路径键）
        let addr = match &trace {
            None => addrs.first().copied(),
            Some(t) => {
                let state = t.state.lock().unwrap();
                let now = Instant::now();
                let mut ranked: Vec<_> = addrs
                    .iter()
                    .map(|addr| {
                        let record = state.endpoints.get(&(t.path.clone(), *addr));
                        (
                            record.and_then(|e| e.last_failure),
                            record.is_none_or(|e| e.eligible(now)),
                            *addr,
                        )
                    })
                    .collect();
                // 稳定排序：与原来 `sort_by_key(last_failure)` 的顺序一致
                ranked.sort_by_key(|(failure, _, _)| *failure);
                ranked
                    .into_iter()
                    .find(|(_, eligible, _)| *eligible)
                    .map(|(_, _, addr)| addr)
            }
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no eligible server address for requested family",
            )
        })?;
        let start = Instant::now();
        let result =
            tokio::time::timeout(Duration::from_secs(3), oryn_udp::iface::connect_tcp(addr))
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "smart carrier connect timeout",
                    ))
                });
        if let Some(t) = trace {
            *t.endpoint.lock().unwrap() = Some(addr);
            t.carrier_ready
                .store(result.is_ok(), std::sync::atomic::Ordering::Relaxed);
            let mut state = t.state.lock().unwrap();
            let tn = state.tuning;
            if state.epoch == t.epoch {
                if state.endpoints.len() >= MAX_RECORDS {
                    state.endpoints.retain(|_, v| {
                        v.last_failure
                            .is_some_and(|at| at.elapsed() < Duration::from_secs(600))
                    });
                    if state.endpoints.len() >= MAX_RECORDS {
                        state.endpoints.clear();
                    }
                }
                state
                    .endpoints
                    .entry((t.path.clone(), addr))
                    .or_default()
                    .record(
                        result.is_ok(),
                        result
                            .is_ok()
                            .then(|| start.elapsed().as_secs_f64() * 1000.0),
                        Instant::now(),
                        &tn,
                    );
                // 单地址失败只作用于 Endpoint，成功可以作为路径级承载证据。
                state.dirty = true;
                if result.is_ok() {
                    state.paths.entry(t.path).or_default().record(
                        true,
                        Some(start.elapsed().as_secs_f64() * 1000.0),
                        Instant::now(),
                        &tn,
                    );
                } else if addrs.iter().all(|a| {
                    state.endpoints.get(&(t.path.clone(), *a)).is_some_and(|e| {
                        e.last_failure.is_some_and(|at| {
                            at.elapsed() < Duration::from_secs(tn.failure_window_secs)
                        })
                    })
                }) {
                    state
                        .paths
                        .entry(t.path)
                        .or_default()
                        .record(false, None, Instant::now(), &tn);
                }
            }
        }
        let stream = result?;
        let _ = stream.set_nodelay(true);
        Ok(Box::new(stream))
    }
}
fn target_event(
    smart: &Smart,
    key: TargetKey,
    site: Option<String>,
    epoch: u64,
    success: bool,
    delay: Option<f64>,
) {
    let mut state = smart.state.lock().unwrap();
    if state.epoch != epoch {
        return;
    }
    if state.targets.len() >= MAX_RECORDS && !state.targets.contains_key(&key) {
        if let Some(old) = state
            .targets
            .iter()
            .min_by_key(|(_, v)| v.at)
            .map(|(k, _)| k.clone())
        {
            state.targets.remove(&old);
        }
    }
    state.dirty = true;
    let tn = state.tuning;
    if let Some(site) = site {
        let site_key = TargetKey(site, key.1, key.2.clone());
        if state.targets.len() < MAX_RECORDS || state.targets.contains_key(&site_key) {
            state
                .targets
                .entry(site_key)
                .or_default()
                .record(success, delay, Instant::now(), &tn);
        }
    }
    state
        .targets
        .entry(key)
        .or_default()
        .record(success, delay, Instant::now(), &tn);
}
#[async_trait]
impl Outbound for Plan {
    fn tag(&self) -> &str {
        self.smart.candidates[self.order[0]].outbound.tag()
    }
    fn kind(&self) -> &'static str {
        "smart-path"
    }
    fn dns_scope(&self) -> Option<String> {
        self.smart.candidates[self.order[0]].outbound.dns_scope()
    }
    async fn query_dns(&self, name: &str, qtype: u16) -> io::Result<crate::TailnetDnsAnswer> {
        self.smart.candidates[self.order[0]]
            .outbound
            .query_dns(name, qtype)
            .await
    }
    fn actual_tag(&self) -> Option<String> {
        self.winner
            .lock()
            .unwrap()
            .map(|i| self.smart.candidates[i].outbound.tag().to_string())
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let tn = self.smart.spec.tuning;
        tokio::time::timeout(Duration::from_secs(tn.total_timeout_secs), async {
            let mut attempts=0u8; let mut cursor=0;
            let mut last=io::Error::new(io::ErrorKind::NotConnected,"all Smart candidates unavailable");
            while cursor<self.order.len() && attempts<tn.max_attempts {
                let a=self.order[cursor]; cursor+=1; attempts+=1;
                let first=self.attempt(a,target); tokio::pin!(first);
                let second=self.order.get(cursor).copied().filter(|b| self.smart.candidates[*b].node==self.smart.candidates[a].node && self.smart.candidates[*b].family!=Family::Unknown && attempts<tn.max_attempts);
                if let Some(b)=second {
                    let early=tokio::select! {result=&mut first=>Some(result), _=tokio::time::sleep(Duration::from_millis(tn.fallback_delay_ms))=>None};
                    if let Some(result)=early {match result {Ok(stream)=>return Ok(stream),Err(e)=>last=e}}
                    else {
                        cursor+=1; attempts+=1;
                        let other=self.attempt(b,target); tokio::pin!(other);
                        let (result,remaining)=tokio::select! {r=&mut first=>(r,true),r=&mut other=>(r,false)};
                        if let Ok(stream)=result {return Ok(stream);}
                        let result=if remaining {other.await} else {first.await};
                        match result {Ok(stream)=>return Ok(stream),Err(e)=>last=e}
                    }
                } else {match first.await {Ok(stream)=>return Ok(stream),Err(e)=>last=e}}
                // 未适配协议的内部尝试不可观测，不在外面再叠加重试。
                if self.smart.candidates[a].family==Family::Unknown {break;}
            }
            Err(last)
        }).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"Smart total connection budget exhausted"))?
    }
    async fn bind_udp(&self, target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        let c = &self.smart.candidates[self.order[0]];
        // UDP socket 创建无远端证据；既不投成功票，也不进行业务数据重放。
        let inner = tokio::time::timeout(
            Duration::from_secs(self.smart.spec.tuning.total_timeout_secs),
            c.outbound.bind_udp(target),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Smart UDP setup timeout"))??;
        Ok(Box::new(ObservedPacket {
            inner,
            smart: self.smart.clone(),
            key: TargetKey(
                self.target.clone(),
                self.udp,
                PathKey(c.node.clone(), Family::Unknown),
            ),
            site: self.site.clone(),
            epoch: self.epoch,
            observed: std::sync::atomic::AtomicBool::new(false),
        }))
    }
}
struct ObservedStream {
    inner: BoxStream,
    smart: Arc<Smart>,
    key: TargetKey,
    site: Option<String>,
    epoch: u64,
    committed: Option<Instant>,
    responded: bool,
}
impl AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Ok(()))) && buf.filled().len() > before && !self.responded
        {
            self.responded = true;
            target_event(
                &self.smart,
                self.key.clone(),
                self.site.clone(),
                self.epoch,
                true,
                self.committed.map(|t| t.elapsed().as_secs_f64() * 1000.0),
            );
        }
        result
    }
}
impl AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !buf.is_empty() && self.committed.is_none() {
            self.committed = Some(Instant::now());
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if bufs.iter().any(|b| !b.is_empty()) && self.committed.is_none() {
            self.committed = Some(Instant::now());
        }
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}
struct ObservedPacket {
    inner: Box<dyn PacketConn>,
    smart: Arc<Smart>,
    key: TargetKey,
    site: Option<String>,
    epoch: u64,
    observed: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl PacketConn for ObservedPacket {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        self.inner.send_to(buf, target).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let result = self.inner.recv_from(buf).await?;
        if !self
            .observed
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            target_event(
                &self.smart,
                self.key.clone(),
                self.site.clone(),
                self.epoch,
                true,
                None,
            );
        }
        Ok(result)
    }
}

pub fn build(
    config: &oryn_config::RuntimeConfig,
    group: &oryn_config::GroupSpec,
    members: &[Arc<dyn Outbound>],
    ctx: &crate::BuildContext,
    name: &str,
    data_dir: Option<&std::path::Path>,
) -> Arc<Smart> {
    fn identity(index: usize, config: &oryn_config::RuntimeConfig) -> String {
        let spec = &config.outbounds[index];
        let detour = spec.dialer.map(|i| identity(i, config)).unwrap_or_default();
        let providers: Vec<_> = config
            .proxy_providers
            .iter()
            .filter(|p| p.members.contains(&index))
            .map(|p| p.name.as_str())
            .collect();
        let material = format!("{:?}|{}|{:?}", spec.kind, detour, providers);
        ring::digest::digest(&ring::digest::SHA256, material.as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    let deps = crate::LeafDeps {
        proxy_resolver: ctx.proxy_resolver.clone(),
        direct_resolver: ctx.direct_resolver.clone(),
        direct_dialer: Arc::new(crate::DirectDialer::new(ctx.direct_resolver.clone())),
        data_dir: None,
        mieru_sessions: ctx.mieru_sessions,
    };
    let mut candidates = Vec::new();
    for (&index, outbound) in group.members.iter().zip(members) {
        let spec = &config.outbounds[index];
        let node = identity(index, config);
        let factor = group.smart.factor(outbound.tag());
        let precise = oryn_config::smart_family_capable(&spec.kind, spec.dialer.is_some());
        if precise {
            for family in [Family::V4, Family::V6] {
                if matches!(
                    (group.smart.server_strategy, family),
                    (ServerStrategy::V4Only, Family::V6) | (ServerStrategy::V6Only, Family::V4)
                ) {
                    continue;
                }
                let dialer: Arc<dyn Dialer> = Arc::new(FamilyDialer {
                    resolver: ctx.proxy_resolver.clone(),
                    family,
                });
                // 每个地址族都重新构造一份出站：拨号器限定地址族，连接池 / 复用会话不与其他路径共享。
                let variant =
                    crate::build_leaf(spec, &deps, dialer, Arc::new(oryn_udp::UdpFactory))
                        .expect("family-capable kinds are leaf outbounds");
                candidates.push(Candidate {
                    node: node.clone(),
                    family,
                    outbound: variant,
                    factor,
                    tcp_only: true,
                    server: oryn_config::smart_server(&spec.kind).cloned(),
                    udp_only: false,
                    supports_udp: false,
                });
            }
        }
        candidates.push(Candidate {
            node,
            family: Family::Unknown,
            outbound: outbound.clone(),
            factor,
            tcp_only: false,
            server: None,
            udp_only: precise,
            supports_udp: udp_capable(&spec.kind),
        });
    }
    candidates.sort_by(|a, b| {
        a.node
            .cmp(&b.node)
            .then((a.family as u8).cmp(&(b.family as u8)))
    });
    let key = format!(
        "{}:{:?}",
        name,
        candidates
            .iter()
            .map(|c| (&c.node, c.family))
            .collect::<Vec<_>>()
    );
    let state = ctx.health.smart.get(key.clone());
    state.lock().unwrap().tuning = group.smart.tuning;
    if let Some(dir) = data_dir {
        let mut s = state.lock().unwrap();
        if !s.loaded {
            s.loaded = true;
            let path = dir
                .join("smart")
                .join(format!("{}.json", digest(&[0; 16], &key)));
            load(&mut s, &path);
            s.store = Some(path);
        }
    }
    Arc::new(Smart {
        resolver: Some(ctx.proxy_resolver.clone()),
        state,
        candidates,
        spec: group.smart.clone(),
    })
}

struct Recovery {
    state: Arc<Mutex<State>>,
    path: PathKey,
    epoch: u64,
}
impl Drop for Recovery {
    fn drop(&mut self) {
        let mut s = self.state.lock().unwrap();
        if s.epoch == self.epoch {
            if let Some(p) = s.paths.get_mut(&self.path) {
                p.recovering = false;
            }
        }
    }
}
impl Plan {
    async fn attempt(&self, i: usize, target: &TargetAddr) -> io::Result<BoxStream> {
        let c = &self.smart.candidates[i];
        let path = PathKey(c.node.clone(), c.family);
        {
            let mut s = self.smart.state.lock().unwrap();
            if s.epoch != self.epoch {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Smart network context changed",
                ));
            }
            if let Some(p) = s.paths.get_mut(&path) {
                if !p.eligible(Instant::now()) {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "Smart path circuit open",
                    ));
                }
                if p.open_until.is_some() {
                    p.recovering = true;
                }
            }
        }
        let _recovery = Recovery {
            state: self.smart.state.clone(),
            path: path.clone(),
            epoch: self.epoch,
        };
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let trace = Trace {
            state: self.smart.state.clone(),
            path: path.clone(),
            epoch: self.epoch,
            endpoint: Arc::new(Mutex::new(None)),
            carrier_ready: ready.clone(),
        };
        match TRACE.scope(trace, c.outbound.connect_tcp(target)).await {
            Ok(stream) => {
                *self.winner.lock().unwrap() = Some(i);
                let mut state = self.smart.state.lock().unwrap();
                if state.epoch == self.epoch {
                    if let Some(lease) = state.leases.get_mut(&(self.client, self.target.clone())) {
                        if lease.path != path {
                            lease.created = Instant::now();
                            lease.confirmations = 0;
                        }
                        lease.path = path.clone();
                        lease.used = Instant::now();
                    }
                }
                drop(state);
                log::debug!(
                    "smart connected node={} family={}",
                    c.outbound.tag(),
                    c.family.name()
                );
                Ok(Box::new(ObservedStream {
                    inner: stream,
                    smart: self.smart.clone(),
                    key: TargetKey(self.target.clone(), false, path),
                    site: self.site.clone(),
                    epoch: self.epoch,
                    committed: None,
                    responded: false,
                }))
            }
            Err(e) => {
                if ready.load(std::sync::atomic::Ordering::Relaxed)
                    && !matches!(
                        e.kind(),
                        io::ErrorKind::Unsupported
                            | io::ErrorKind::AddrNotAvailable
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                    )
                {
                    target_event(
                        &self.smart,
                        TargetKey(self.target.clone(), false, path),
                        self.site.clone(),
                        self.epoch,
                        false,
                        None,
                    );
                }
                Err(e)
            }
        }
    }
}
impl Smart {
    pub fn explain(&self, target: &TargetAddr, network: Network) -> serde_json::Value {
        let target = self.target_key(target);
        let now = Instant::now();
        let s = self.state.lock().unwrap();
        let hashed = digest(&s.salt, &target);
        serde_json::json!({"target":target,"network":if network==Network::Udp{"udp"}else{"tcp"},"epoch":s.epoch,"target_family":"unknown","paths":self.candidates.iter().filter(|c| if network==Network::Udp{!c.tcp_only}else{!c.udp_only}).map(|c|{
            let key=PathKey(c.node.clone(),c.family);let p=s.paths.get(&key);let t=s.targets.get(&TargetKey(hashed.clone(),network==Network::Udp,key.clone()));
            let (success,failure)=t.map_or((0.0,0.0),|t|t.values(now,&s.tuning));
            let carrier=p.map_or(0.9,|p|p.evidence.reliability(now,&s.tuning));let response=t.map_or(0.9,|t|t.reliability(now,&s.tuning));
            let delay=p.and_then(|p|p.evidence.delay);let jitter=p.map_or(0.0,|p|p.evidence.jitter);
            let q=(response*if c.family==Family::Unknown{1.0}else{carrier}).powi(3)/(1.0+delay.unwrap_or(300.0)/300.0)/(1.0+jitter/100.0);
            serde_json::json!({"node":c.outbound.tag(),"node_id":c.node,"server_family":c.family.name(),"carrier_delay_ms":delay,"success":success,"failure":failure,"confidence":if success+failure<s.tuning.min_samples{"warming"}else{"observed"},"base_score":q,"name_factor":c.factor,"score":q*c.factor,"eligible":p.is_none_or(|p|p.eligible(now)),"circuit":p.map_or("closed",|p|if p.open_until.is_some(){if p.eligible(now){"half_open"}else{"open"}}else{"closed"}),"endpoints":s.endpoints.iter().filter(|((path,_),_)|path==&key).take(16).map(|((_,addr),e)|serde_json::json!({"address":addr.to_string(),"eligible":e.eligible(now),"recent_failures":e.failures})).collect::<Vec<_>>()})
        }).collect::<Vec<_>>()})
    }
}

const RETENTION_SECS: u64 = 7 * 24 * 3600;
const MAX_PERSISTED_TARGETS: usize = 4096;

/// 目标键的带密钥摘要：磁盘上只有它，不出现明文域名（仅防随手翻看，不防拿到整个文件的字典攻击）。
fn digest(salt: &[u8; 16], text: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, salt);
    ring::hmac::sign(&key, text.as_bytes()).as_ref()[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn family_of(name: &str) -> Option<Family> {
    match name {
        "ipv4" => Some(Family::V4),
        "ipv6" => Some(Family::V6),
        "unknown" => Some(Family::Unknown),
        _ => None,
    }
}
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
fn snapshot(e: &Evidence, now: Instant, t: &SmartTuning) -> serde_json::Value {
    let (s, f) = e.values(now, t);
    serde_json::json!({"s": s, "f": f, "d": e.delay, "j": e.jitter})
}
/// 读回证据；按快照之后经过的墙钟时间继续衰减。
fn restore(v: &serde_json::Value, gap: f64, now: Instant, t: &SmartTuning) -> Option<Evidence> {
    let num = |k: &str| v.get(k).and_then(serde_json::Value::as_f64);
    let decay = 2f64.powf(-gap / t.half_life_secs);
    let (s, f) = (num("s")?, num("f")?);
    if !(s.is_finite() && f.is_finite() && (0.0..1e6).contains(&s) && (0.0..1e6).contains(&f)) {
        return None;
    }
    Some(Evidence {
        success: s * decay,
        failure: f * decay,
        delay: num("d").filter(|d| d.is_finite() && *d >= 0.0),
        jitter: num("j")
            .filter(|j| j.is_finite() && *j >= 0.0)
            .unwrap_or(0.0),
        at: now,
    })
}
fn load(state: &mut State, path: &std::path::Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    // 顺手清理同目录里长期不用的旧快照（成员变化会换文件名）。
    if let Some(dir) = path.parent() {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age.as_secs() > RETENTION_SECS);
            if old && entry.path() != path {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    if meta.len() > 8 << 20 {
        return;
    }
    let Some(doc) = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
    else {
        return;
    };
    let saved = doc
        .get("saved")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let gap = unix_now().saturating_sub(saved);
    let salt = doc
        .get("salt")
        .and_then(serde_json::Value::as_str)
        .filter(|s| s.len() == 32)
        .and_then(|s| {
            let mut out = [0u8; 16];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
            }
            Some(out)
        });
    if doc.get("v").and_then(serde_json::Value::as_u64) != Some(1)
        || gap > RETENTION_SECS
        || salt.is_none()
    {
        return;
    }
    state.salt = salt.unwrap_or_default();
    let tn = state.tuning;
    let now = Instant::now();
    let gap = gap as f64;
    let entry = |v: &serde_json::Value| -> Option<(PathKey, Evidence)> {
        let node = v.get("n")?.as_str().filter(|n| n.len() <= 128)?;
        let family = family_of(v.get("fam")?.as_str()?)?;
        Some((
            PathKey(node.to_string(), family),
            restore(v, gap, now, &tn)?,
        ))
    };
    for v in doc
        .get("paths")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_RECORDS)
    {
        if let Some((key, evidence)) = entry(v) {
            state.paths.entry(key).or_default().evidence = evidence;
        }
    }
    for v in doc
        .get("targets")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PERSISTED_TARGETS)
    {
        let hash = v
            .get("h")
            .and_then(serde_json::Value::as_str)
            .filter(|h| h.len() == 24);
        let udp = v.get("udp").and_then(serde_json::Value::as_bool);
        if let (Some(hash), Some(udp), Some((path, evidence))) = (hash, udp, entry(v)) {
            state
                .targets
                .insert(TargetKey(hash.to_string(), udp, path), evidence);
        }
    }
}
impl Smart {
    /// 把学习状态写盘（原子替换）；无新证据或没有存储位置时什么也不做。热路径不调用。
    pub fn save(&self) {
        let (path, bytes) = {
            let mut s = self.state.lock().unwrap();
            let Some(path) = s.store.clone() else { return };
            if !s.dirty {
                return;
            }
            s.dirty = false;
            let tn = s.tuning;
            let now = Instant::now();
            let mut targets: Vec<_> = s.targets.iter().collect();
            targets.sort_by_key(|(_, e)| std::cmp::Reverse(e.at));
            targets.truncate(MAX_PERSISTED_TARGETS);
            let with_path = |mut v: serde_json::Value, p: &PathKey| {
                v["n"] = p.0.clone().into();
                v["fam"] = p.1.name().into();
                v
            };
            let doc = serde_json::json!({
                "v": 1,
                "saved": unix_now(),
                "salt": s.salt.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "paths": s.paths.iter().map(|(k, p)| with_path(snapshot(&p.evidence, now, &tn), k)).collect::<Vec<_>>(),
                "targets": targets.iter().map(|(k, e)| {
                    let mut v = with_path(snapshot(e, now, &tn), &k.2);
                    v["h"] = k.0.clone().into();
                    v["udp"] = k.1.into();
                    v
                }).collect::<Vec<_>>(),
            });
            (path, serde_json::to_vec(&doc).unwrap_or_default())
        };
        if bytes.is_empty() {
            return;
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // 临时文件名带进程号与随机后缀：共享同一 state 的多个实例并发保存时不互踩
        let tmp = path.with_extension(format!(
            "{}.{:08x}.tmp",
            std::process::id(),
            rand::random::<u32>()
        ));
        if std::fs::write(&tmp, &bytes)
            .and_then(|()| std::fs::rename(&tmp, &path))
            .is_err()
        {
            let _ = std::fs::remove_file(&tmp);
            self.state.lock().unwrap().dirty = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct Mock {
        name: &'static str,
        slow: bool,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl Outbound for Mock {
        fn tag(&self) -> &str {
            self.name
        }
        fn kind(&self) -> &'static str {
            "mock"
        }
        async fn connect_tcp(&self, _: &TargetAddr) -> io::Result<BoxStream> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.slow {
                std::future::pending::<()>().await;
            }
            let (client, mut server) = tokio::io::duplex(128);
            tokio::spawn(async move {
                let mut buf = [0; 16];
                if let Ok(n) = server.read(&mut buf).await {
                    let _ = server.write_all(&buf[..n]).await;
                }
            });
            Ok(Box::new(client))
        }
        async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
    fn smart() -> (Arc<Smart>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let candidates = [(Family::V6, true, "v6"), (Family::V4, false, "v4")]
            .into_iter()
            .map(|(family, slow, name)| Candidate {
                node: "node-id".into(),
                family,
                outbound: Arc::new(Mock {
                    name,
                    slow,
                    calls: calls.clone(),
                }),
                factor: 1.0,
                tcp_only: true,
                server: None,
                udp_only: false,
                supports_udp: false,
            })
            .collect();
        (
            Arc::new(Smart {
                resolver: None,
                candidates,
                spec: SmartSpec::default(),
                state: Arc::new(Mutex::new(State::default())),
            }),
            calls,
        )
    }
    fn target() -> TargetAddr {
        TargetAddr::Domain("API.Example.COM.".into(), 443)
    }
    #[test]
    fn smart_decay_reduces_confidence_not_quality_to_zero() {
        let now = Instant::now();
        let mut e = Evidence::default();
        e.record(true, Some(50.0), now, &SmartTuning::default());
        let (s, f) = e.values(now + Duration::from_secs(600), &SmartTuning::default());
        assert!((s - 0.5).abs() < 0.0001);
        assert_eq!(f, 0.0);
        assert!(e.reliability(now + Duration::from_secs(86400), &SmartTuning::default()) > 0.89);
    }
    #[test]
    fn smart_circuit_weight_and_network_epoch() {
        let (smart, _) = smart();
        let p = PathKey("node-id".into(), Family::V6);
        {
            let mut s = smart.state.lock().unwrap();
            let p = s.paths.entry(p).or_default();
            for _ in 0..3 {
                p.record(false, None, Instant::now(), &SmartTuning::default());
            }
        }
        let target = target();
        let selected = smart
            .pick(&PickMeta {
                source: None,
                target: &target,
                network: Network::Tcp,
            })
            .unwrap();
        assert_eq!(selected.tag(), "v4");
        smart.on_network_changed();
        assert!(smart.state.lock().unwrap().paths.is_empty());
        assert_eq!(smart.state.lock().unwrap().epoch, 1);
    }
    #[tokio::test]
    async fn smart_dual_stack_race_cancel_neutral_and_payload_once() {
        let (smart, calls) = smart();
        let target = target();
        let plan = smart
            .pick(&PickMeta {
                source: None,
                target: &target,
                network: Network::Tcp,
            })
            .unwrap();
        let mut stream = tokio::time::timeout(Duration::from_secs(2), plan.connect_tcp(&target))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plan.actual_tag().as_deref(), Some("v4"));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(
            smart.state.lock().unwrap().targets.is_empty(),
            "ready is not target success"
        );
        stream.write_all(b"hello").await.unwrap();
        let mut b = [0; 5];
        stream.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hello");
        drop(stream);
        let state = smart.state.lock().unwrap();
        assert_eq!(state.targets.len(), 1);
        let e = state.targets.values().next().unwrap();
        assert_eq!(e.success, 1.0);
        assert_eq!(e.failure, 0.0);
        assert!(
            state.paths.is_empty(),
            "unobserved mock carrier and canceled loser stay neutral"
        );
    }
    #[tokio::test]
    async fn smart_user_cancel_is_neutral() {
        let (smart, _) = smart();
        let target = target();
        let plan = smart
            .pick(&PickMeta {
                source: None,
                target: &target,
                network: Network::Tcp,
            })
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), plan.connect_tcp(&target))
                .await
                .is_err()
        );
        let s = smart.state.lock().unwrap();
        assert!(s.targets.is_empty());
        assert!(s.paths.is_empty());
    }
    fn meta(target: &TargetAddr) -> PickMeta<'_> {
        PickMeta {
            source: None,
            target,
            network: Network::Tcp,
        }
    }
    #[test]
    fn smart_weight_cannot_bypass_reliability_gate() {
        let (base, _) = smart();
        let mut candidates = base.candidates.clone();
        candidates[0].factor = 5.0; // v6 获得最大偏好
        candidates[0].outbound = Arc::new(Mock {
            name: "v6",
            slow: false,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let smart = Arc::new(Smart {
            resolver: None,
            candidates,
            spec: SmartSpec::default(),
            state: Arc::new(Mutex::new(State::default())),
        });
        let target = target();
        let key = |family| {
            TargetKey(
                digest(&[0; 16], "api.example.com"),
                false,
                PathKey("node-id".into(), family),
            )
        };
        {
            let mut s = smart.state.lock().unwrap();
            for _ in 0..60 {
                s.targets.entry(key(Family::V6)).or_default().record(
                    false,
                    None,
                    Instant::now(),
                    &SmartTuning::default(),
                );
                s.targets.entry(key(Family::V4)).or_default().record(
                    true,
                    Some(40.0),
                    Instant::now(),
                    &SmartTuning::default(),
                );
            }
        }
        assert_eq!(smart.pick(&meta(&target)).unwrap().tag(), "v4");
    }
    #[test]
    fn smart_all_paths_open_fails_without_direct_fallback() {
        let (smart, _) = smart();
        {
            let mut s = smart.state.lock().unwrap();
            for family in [Family::V4, Family::V6] {
                let p = s
                    .paths
                    .entry(PathKey("node-id".into(), family))
                    .or_default();
                for _ in 0..3 {
                    p.record(false, None, Instant::now(), &SmartTuning::default());
                }
            }
        }
        assert!(smart.pick(&meta(&target())).is_none());
    }
    #[test]
    fn smart_lease_holds_and_is_bounded() {
        let (smart, _) = smart();
        let target = target();
        let first = smart.pick(&meta(&target)).unwrap().tag().to_string();
        // 保持期内即使对端路径证据明显更好也不切换。
        {
            let mut s = smart.state.lock().unwrap();
            let other = if first == "v4" {
                Family::V6
            } else {
                Family::V4
            };
            let k = TargetKey(
                digest(&[0; 16], "api.example.com"),
                false,
                PathKey("node-id".into(), other),
            );
            for _ in 0..50 {
                s.targets.entry(k.clone()).or_default().record(
                    true,
                    Some(10.0),
                    Instant::now(),
                    &SmartTuning::default(),
                );
            }
        }
        assert_eq!(smart.pick(&meta(&target)).unwrap().tag(), first);
        for i in 0..(MAX_LEASES + 50) {
            let t = TargetAddr::Domain(format!("h{i}.example"), 443);
            let _ = smart.pick(&meta(&t));
        }
        assert!(smart.state.lock().unwrap().leases.len() <= MAX_LEASES);
    }
    /// 本机微基准：只测真实 pick，不建连接；预生成目标和预填充不计时。
    #[test]
    #[ignore = "manual release-mode performance survey"]
    fn core_survey_smart_lease_cost() {
        const SAMPLES: usize = 2048;
        const ROUNDS: usize = 7;
        let seed: Vec<_> = (0..MAX_LEASES)
            .map(|i| TargetAddr::Domain(format!("seed-{i}.example"), 443))
            .collect();
        let fresh: Vec<_> = (0..SAMPLES)
            .map(|i| TargetAddr::Domain(format!("fresh-{i}.example"), 443))
            .collect();
        let mut medians = [Vec::new(), Vec::new(), Vec::new()];
        let mut tails = [Vec::new(), Vec::new(), Vec::new()];
        let labels = ["nonfull_new", "full_hit", "full_new"];
        for round in 0..ROUNDS {
            // 轮换执行顺序，避免固定顺序与预热/温度变化完全重合。
            for step in 0..3 {
                let case = (round + step) % 3;
                let (smart, calls) = smart();
                let prefill = if case == 0 { 512 } else { MAX_LEASES };
                for target in &seed[..prefill] {
                    assert!(smart.pick(&meta(target)).is_some());
                }
                assert_eq!(smart.state.lock().unwrap().leases.len(), prefill);
                let mut nanos = Vec::with_capacity(SAMPLES);
                for target in if case == 1 { &seed[..SAMPLES] } else { &fresh } {
                    let start = Instant::now();
                    let picked = std::hint::black_box(smart.pick(&meta(target)));
                    let elapsed = start.elapsed().as_nanos();
                    assert!(picked.is_some());
                    nanos.push(elapsed);
                }
                let expected = if case == 0 {
                    prefill + SAMPLES
                } else {
                    MAX_LEASES
                };
                assert_eq!(smart.state.lock().unwrap().leases.len(), expected);
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                nanos.sort_unstable();
                let median = nanos[SAMPLES / 2];
                let p99 = nanos[(SAMPLES * 99).div_ceil(100) - 1];
                medians[case].push(median);
                tails[case].push(p99);
                println!("smart round={} case={} candidates=2 samples={} leases={} median_ns={} p99_ns={}",
                    round + 1, labels[case], SAMPLES, expected, median, p99);
            }
        }
        for case in 0..3 {
            medians[case].sort_unstable();
            tails[case].sort_unstable();
            println!(
                "smart summary case={} rounds={} median_of_medians_ns={} median_of_p99_ns={}",
                labels[case],
                ROUNDS,
                medians[case][ROUNDS / 2],
                tails[case][ROUNDS / 2]
            );
        }
    }

    #[test]
    fn smart_equivalent_reload_keeps_state() {
        let registry = Registry::default();
        let a = registry.get("group:[(\"n\", V4)]".into());
        a.lock().unwrap().new_leases = 7;
        let b = registry.get("group:[(\"n\", V4)]".into());
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(b.lock().unwrap().new_leases, 7);
        assert!(!Arc::ptr_eq(&a, &registry.get("other".into())));
    }
    #[test]
    fn smart_persistence_round_trip_hashes_targets_and_expires() {
        let dir = std::env::temp_dir().join(format!("oryn-smart-{}", unix_now()));
        let file = dir.join("smart/test.json");
        let (a, _) = smart();
        let hash = digest(&a.state.lock().unwrap().salt, "secret-host.example");
        {
            let mut s = a.state.lock().unwrap();
            s.store = Some(file.clone());
            let key = TargetKey(hash.clone(), false, PathKey("node-id".into(), Family::V4));
            for _ in 0..30 {
                s.targets.entry(key.clone()).or_default().record(
                    true,
                    Some(80.0),
                    Instant::now(),
                    &SmartTuning::default(),
                );
            }
            s.paths
                .entry(PathKey("node-id".into(), Family::V6))
                .or_default()
                .record(false, None, Instant::now(), &SmartTuning::default());
            s.dirty = true;
        }
        a.save();
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains("secret-host"), "no plaintext host on disk");
        assert!(!a.state.lock().unwrap().dirty);
        // 无新证据不重复写。
        std::fs::remove_file(&file).unwrap();
        a.save();
        assert!(!file.exists());
        a.state.lock().unwrap().dirty = true;
        a.save();

        let mut fresh = State::default();
        load(&mut fresh, &file);
        assert_eq!(fresh.salt, a.state.lock().unwrap().salt);
        let key = TargetKey(hash, false, PathKey("node-id".into(), Family::V4));
        let (s, f) = fresh.targets[&key].values(Instant::now(), &SmartTuning::default());
        assert!((s - 30.0).abs() < 0.5 && f == 0.0);
        assert_eq!(
            fresh.paths[&PathKey("node-id".into(), Family::V6)]
                .evidence
                .failure
                .round(),
            1.0
        );
        // 熔断路径只存证据：熔断状态不随磁盘恢复。
        assert!(fresh.paths[&PathKey("node-id".into(), Family::V6)].eligible(Instant::now()));

        // 过期快照与损坏文件被忽略。
        let mut doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        doc["saved"] = 1.into();
        std::fs::write(&file, serde_json::to_vec(&doc).unwrap()).unwrap();
        let mut expired = State::default();
        load(&mut expired, &file);
        assert!(expired.targets.is_empty());
        std::fs::write(&file, b"{not json").unwrap();
        load(&mut expired, &file);
        assert!(expired.targets.is_empty() && expired.paths.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[tokio::test]
    async fn smart_tuning_changes_budget_and_circuit() {
        let (base, calls) = smart();
        let tuning = SmartTuning {
            max_attempts: 1,
            total_timeout_secs: 1,
            consecutive_failures: 1,
            ..SmartTuning::default()
        };
        let smart = Arc::new(Smart {
            resolver: None,
            candidates: base.candidates.clone(),
            spec: SmartSpec {
                tuning,
                ..SmartSpec::default()
            },
            state: Arc::new(Mutex::new(State {
                tuning,
                ..State::default()
            })),
        });
        let target = target();
        let plan = smart.pick(&meta(&target)).unwrap();
        // 只允许 1 次尝试：慢的 v6 不会触发 v4 回退，整体在 1 秒预算内失败。
        assert!(plan.connect_tcp(&target).await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        // 一次失败即熔断。
        let path = PathKey("node-id".into(), Family::V6);
        {
            let mut s = smart.state.lock().unwrap();
            s.paths
                .entry(path.clone())
                .or_default()
                .record(false, None, Instant::now(), &tuning);
            assert!(!s.paths[&path].eligible(Instant::now()));
        }
    }
    #[test]
    fn smart_site_prior_uses_public_suffix_and_sibling_evidence() {
        let (base, _) = smart();
        let tuning = SmartTuning {
            site_prior: true,
            ..SmartTuning::default()
        };
        let smart = Arc::new(Smart {
            resolver: None,
            candidates: base.candidates.clone(),
            spec: SmartSpec {
                tuning,
                ..SmartSpec::default()
            },
            state: Arc::new(Mutex::new(State {
                tuning,
                ..State::default()
            })),
        });
        let dom = |h: &str| TargetAddr::Domain(h.into(), 443);
        assert_eq!(
            smart.site_key(&dom("a.example.co.uk")).as_deref(),
            Some("site:example.co.uk")
        );
        assert_eq!(
            smart.site_key(&dom("www.example.com")).as_deref(),
            Some("site:example.com")
        );
        assert!(
            smart.site_key(&dom("example.co.uk")).is_none(),
            "already registrable"
        );
        assert!(smart.site_key(&dom("foo.co.uk")).is_none());
        assert!(smart
            .site_key(&TargetAddr::Ip("1.2.3.4:443".parse().unwrap()))
            .is_none());
        // 兄弟主机在 v6 上反复失败、v4 上成功；新主机应借用这份先验。
        let site = digest(&[0; 16], "site:example.co.uk");
        let path = |f| PathKey("node-id".into(), f);
        for _ in 0..60 {
            target_event(
                &smart,
                TargetKey(digest(&[0; 16], "b.example.co.uk"), false, path(Family::V6)),
                Some(site.clone()),
                0,
                false,
                None,
            );
            target_event(
                &smart,
                TargetKey(digest(&[0; 16], "b.example.co.uk"), false, path(Family::V4)),
                Some(site.clone()),
                0,
                true,
                Some(40.0),
            );
        }
        assert_eq!(
            smart.pick(&meta(&dom("c.example.co.uk"))).unwrap().tag(),
            "v4"
        );
    }
    struct SilentUdp {
        reply: bool,
    }
    #[async_trait]
    impl PacketConn for SilentUdp {
        async fn send_to(&self, _: &[u8], _: &TargetAddr) -> io::Result<()> {
            Ok(())
        }
        async fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
            if self.reply {
                Ok((0, target()))
            } else {
                std::future::pending().await
            }
        }
    }
    #[tokio::test]
    async fn smart_udp_without_reply_is_neutral_and_reply_is_success() {
        let (smart, _) = smart();
        let key = TargetKey(
            digest(&[0; 16], "dns.example"),
            true,
            PathKey("node-id".into(), Family::Unknown),
        );
        let make = |reply| ObservedPacket {
            inner: Box::new(SilentUdp { reply }),
            smart: smart.clone(),
            key: key.clone(),
            site: None,
            epoch: 0,
            observed: std::sync::atomic::AtomicBool::new(false),
        };
        let silent = make(false);
        silent.send_to(b"q", &target()).await.unwrap();
        let mut buf = [0u8; 8];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), silent.recv_from(&mut buf))
                .await
                .is_err()
        );
        assert!(
            smart.state.lock().unwrap().targets.is_empty(),
            "socket creation, send and silence carry no evidence"
        );
        let talking = make(true);
        talking.recv_from(&mut buf).await.unwrap();
        talking.recv_from(&mut buf).await.unwrap();
        let s = smart.state.lock().unwrap();
        assert_eq!(s.targets[&key].success, 1.0, "one vote per socket");
    }
    #[test]
    fn smart_records_stay_bounded() {
        let (smart, _) = smart();
        for i in 0..(MAX_RECORDS + 200) {
            target_event(
                &smart,
                TargetKey(format!("h{i}"), false, PathKey("n".into(), Family::V4)),
                Some(format!("site{}", i % 50)),
                0,
                true,
                None,
            );
        }
        assert!(smart.state.lock().unwrap().targets.len() <= MAX_RECORDS);
    }
    #[test]
    fn smart_target_failures_do_not_open_global_path() {
        let (smart, _) = smart();
        let key = TargetKey(
            "broken.example".into(),
            false,
            PathKey("node-id".into(), Family::V4),
        );
        for _ in 0..100 {
            target_event(&smart, key.clone(), None, 0, false, None);
        }
        assert!(smart.state.lock().unwrap().paths.is_empty());
        let target = TargetAddr::from_host("other.example", 443);
        assert!(smart
            .pick(&PickMeta {
                source: None,
                target: &target,
                network: Network::Tcp
            })
            .is_some());
    }
}

#[cfg(test)]
mod integration {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    struct LocalDns;
    #[async_trait]
    impl Resolver for LocalDns {
        async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
            Ok(vec!["127.0.0.1".parse().unwrap()])
        }
    }
    struct TwoAddrDns;
    #[async_trait]
    impl Resolver for TwoAddrDns {
        async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
            // 第一个地址无监听（连接被拒），第二个可用。
            Ok(vec![
                "127.0.0.2".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
            ])
        }
    }
    #[tokio::test]
    async fn smart_single_address_failure_stays_at_endpoint() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move { while server.accept().await.is_ok() {} });
        let state = Arc::new(Mutex::new(State::default()));
        let path = PathKey("node-id".into(), Family::V4);
        let dialer = FamilyDialer {
            resolver: Arc::new(TwoAddrDns),
            family: Family::V4,
        };
        let target = TargetAddr::Domain("server.test".into(), port);
        let dial = || {
            let trace = Trace {
                state: state.clone(),
                path: path.clone(),
                epoch: 0,
                endpoint: Arc::new(Mutex::new(None)),
                carrier_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            TRACE.scope(trace, dialer.dial_tcp(&target))
        };
        assert!(dial().await.is_err(), "first address refuses");
        {
            let s = state.lock().unwrap();
            let bad: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();
            assert_eq!(s.endpoints[&(path.clone(), bad)].failures, 1);
            assert!(
                !s.paths.contains_key(&path),
                "one bad address must not mark the whole path"
            );
        }
        // 失败过的地址排到后面，第二次直接用可用地址。
        assert!(dial().await.is_ok());
        let s = state.lock().unwrap();
        assert!(s.paths[&path].eligible(Instant::now()));
        assert_eq!(s.paths[&path].evidence.success, 1.0);
    }
    fn config(name: &str, port: u16) -> oryn_config::RuntimeConfig {
        oryn_config::parse_config(&format!("proxies:\n - {{name: {name}, type: http, server: server.test, port: {port}}}\nproxy-groups:\n - {{name: Auto, type: smart, proxies: [{name}], smart: {{server-ip: ipv4_only}}}}\nrules: ['MATCH,Auto']")).unwrap()
    }
    #[test]
    fn smart_builds_dual_family_variants_for_supported_protocols() {
        let config = oryn_config::parse_config(
            "proxies:\n - {name: ss, type: ss, server: a.test, port: 1, cipher: aes-128-gcm, password: p}\n - {name: tw, type: trojan, server: b.test, port: 443, password: p, network: ws, ws-opts: {path: /}}\n - {name: hy, type: http, server: c.test, port: 80}\nproxy-groups:\n - {name: Auto, type: smart, proxies: [ss, tw, hy]}\nrules: ['MATCH,Auto']",
        )
        .unwrap();
        let ctx = crate::BuildContext {
            proxy_resolver: Arc::new(LocalDns),
            direct_resolver: Arc::new(LocalDns),
            health: Arc::new(crate::HealthStore::default()),
            selections: HashMap::new(),
            mieru_sessions: 64,
        };
        let built = crate::build_outbounds(&config, &ctx);
        let group = built.iter().find(|o| o.tag() == "Auto").unwrap();
        let smart = group.as_group().unwrap().smart.as_ref().unwrap();
        for family in [Family::V4, Family::V6, Family::Unknown] {
            assert_eq!(
                smart
                    .candidates
                    .iter()
                    .filter(|c| c.family == family)
                    .count(),
                3,
                "{family:?}"
            );
        }
    }
    fn smart_test_ctx() -> crate::BuildContext {
        crate::BuildContext {
            proxy_resolver: Arc::new(LocalDns),
            direct_resolver: Arc::new(LocalDns),
            health: Arc::new(crate::HealthStore::default()),
            selections: HashMap::new(),
            mieru_sessions: 64,
        }
    }
    fn smart_of(built: &[Arc<dyn Outbound>]) -> Arc<Smart> {
        built
            .iter()
            .find(|o| o.tag() == "Auto")
            .unwrap()
            .as_group()
            .unwrap()
            .smart
            .clone()
            .unwrap()
    }
    #[test]
    fn smart_family_matrix_covers_pooled_protocols_and_keeps_udp_native_opaque() {
        let config = oryn_config::parse_config(
            "proxies:
 - {name: sn, type: snell, server: s.test, port: 1, psk: k, version: 4, reuse: true}
 - {name: at, type: anytls, server: s.test, port: 1, password: p}
 - {name: tg, type: trojan, server: s.test, port: 1, password: p, network: grpc, grpc-opts: {grpc-service-name: g}}
 - {name: so, type: ss, server: s.test, port: 1, cipher: aes-128-gcm, password: p, plugin: obfs, plugin-opts: {mode: http, host: x.test}}
 - {name: sm, type: ss, server: s.test, port: 1, cipher: aes-128-gcm, password: p, smux: {enabled: true}}
 - {name: h2, type: hysteria2, server: s.test, port: 443, password: p}
 - {name: ch, type: trojan, server: s.test, port: 443, password: p, dialer-proxy: sm}
proxy-groups:
 - {name: Auto, type: smart, proxies: [sn, at, tg, so, sm, h2, ch]}
rules: ['MATCH,Auto']",
        )
        .unwrap();
        let smart = smart_of(&crate::build_outbounds(&config, &smart_test_ctx()));
        let count = |tag: &str, family: Family| {
            smart
                .candidates
                .iter()
                .filter(|c| c.outbound.tag() == tag && c.family == family)
                .count()
        };
        for tag in ["sn", "at", "tg", "so", "sm"] {
            assert_eq!(count(tag, Family::V4), 1, "{tag} v4");
            assert_eq!(count(tag, Family::V6), 1, "{tag} v6");
            assert_eq!(count(tag, Family::Unknown), 1, "{tag} unknown");
        }
        // UDP / QUIC 承载与链式节点没有可限定的地址族，只做节点级调度。
        for tag in ["h2", "ch"] {
            assert_eq!(count(tag, Family::V4) + count(tag, Family::V6), 0, "{tag}");
            assert_eq!(count(tag, Family::Unknown), 1, "{tag} unknown");
        }
        // 冷启动探针的服务器地址对新增协议同样可用。
        for tag in ["sn", "at", "tg", "so", "sm"] {
            assert!(
                smart
                    .candidates
                    .iter()
                    .filter(|c| c.outbound.tag() == tag && c.family != Family::Unknown)
                    .all(|c| c.server.is_some()),
                "{tag} server"
            );
        }
    }
    /// 每种连接池 / 复用 / 插件协议的地址族变体都必须经受限拨号器连接服务器：
    /// IPv4 变体到达监听端口，IPv6 变体在没有 IPv6 服务器地址时失败且不碰任何地址。
    #[tokio::test]
    async fn smart_pooled_protocol_variants_dial_only_their_own_family() {
        let mut listeners = Vec::new();
        for _ in 0..5 {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let port = l.local_addr().unwrap().port();
            let counter = hits.clone();
            tokio::spawn(async move {
                // 立即断开：握手失败即可，只关心连接是否到达。
                while let Ok((s, _)) = l.accept().await {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    drop(s);
                }
            });
            listeners.push((port, hits));
        }
        let p = |i: usize| listeners[i].0;
        let config = oryn_config::parse_config(&format!(
            "proxies:
 - {{name: sn, type: snell, server: s.test, port: {}, psk: k, version: 4, reuse: true}}
 - {{name: at, type: anytls, server: s.test, port: {}, password: p}}
 - {{name: tg, type: trojan, server: s.test, port: {}, password: p, network: grpc, grpc-opts: {{grpc-service-name: g}}}}
 - {{name: so, type: ss, server: s.test, port: {}, cipher: aes-128-gcm, password: p, plugin: obfs, plugin-opts: {{mode: http, host: x.test}}}}
 - {{name: sm, type: ss, server: s.test, port: {}, cipher: aes-128-gcm, password: p, smux: {{enabled: true}}}}
proxy-groups:
 - {{name: Auto, type: smart, proxies: [sn, at, tg, so, sm]}}
rules: ['MATCH,Auto']",
            p(0),
            p(1),
            p(2),
            p(3),
            p(4)
        ))
        .unwrap();
        let smart = smart_of(&crate::build_outbounds(&config, &smart_test_ctx()));
        for (i, tag) in ["sn", "at", "tg", "so", "sm"].into_iter().enumerate() {
            let target = TargetAddr::Domain("example.test".into(), 443);
            let variant = |family| {
                smart
                    .candidates
                    .iter()
                    .find(|c| c.outbound.tag() == tag && c.family == family)
                    .unwrap()
                    .outbound
                    .clone()
            };
            let hits = &listeners[i].1;
            let before = hits.load(std::sync::atomic::Ordering::SeqCst);
            let v6 = tokio::time::timeout(
                Duration::from_secs(3),
                variant(Family::V6).connect_tcp(&target),
            )
            .await
            .expect("v6 must fail fast");
            assert!(v6.is_err(), "{tag}: v6 variant must not connect");
            assert_eq!(
                hits.load(std::sync::atomic::Ordering::SeqCst),
                before,
                "{tag}: v6 variant reached an IPv4 server address"
            );
            let _ = tokio::time::timeout(
                Duration::from_secs(3),
                variant(Family::V4).connect_tcp(&target),
            )
            .await;
            // connect 在内核完成握手后即可返回，accept 任务稍后才计数。
            let mut reached = false;
            for _ in 0..50 {
                if hits.load(std::sync::atomic::Ordering::SeqCst) > before {
                    reached = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(reached, "{tag}: v4 variant never reached the server");
        }
    }
    #[tokio::test]
    async fn smart_real_http_server_identity_target_family_and_rename() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (mut s, _) = server.accept().await.unwrap();
            let mut request = Vec::new();
            let mut b = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut b).await.unwrap();
                request.push(b[0]);
                assert!(request.len() < 2048);
            }
            assert!(String::from_utf8_lossy(&request).contains("[2001:db8::1]:443"));
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut b = [0; 4];
            s.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"ping");
            s.write_all(b"pong").await.unwrap();
        });
        let ctx = crate::BuildContext {
            proxy_resolver: Arc::new(LocalDns),
            direct_resolver: Arc::new(LocalDns),
            health: Arc::new(crate::HealthStore::default()),
            selections: HashMap::new(),
            mieru_sessions: 64,
        };
        let first = crate::build_outbounds(&config("Before", port), &ctx);
        let group = first.iter().find(|o| o.tag() == "Auto").unwrap();
        let target = TargetAddr::from_host("2001:db8::1", 443);
        let selected = crate::resolve(
            group,
            &PickMeta {
                source: None,
                target: &target,
                network: Network::Tcp,
            },
        )
        .unwrap();
        let mut stream = selected.leaf.connect_tcp(&target).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut b = [0; 4];
        stream.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"pong");
        peer.await.unwrap();
        let smart = group.as_group().unwrap().smart.as_ref().unwrap();
        assert_eq!(smart.state.lock().unwrap().paths.len(), 1);
        let renamed = crate::build_outbounds(&config("After", port), &ctx);
        let next = renamed
            .iter()
            .find(|o| o.tag() == "Auto")
            .unwrap()
            .as_group()
            .unwrap()
            .smart
            .as_ref()
            .unwrap();
        assert!(Arc::ptr_eq(&smart.state, &next.state));
        assert_eq!(next.candidates[0].outbound.tag(), "After");
    }
    #[test]
    fn smart_service_grouping_and_network_separation() {
        let ctx = crate::BuildContext {
            proxy_resolver: Arc::new(LocalDns),
            direct_resolver: Arc::new(LocalDns),
            health: Arc::new(crate::HealthStore::default()),
            selections: HashMap::new(),
            mieru_sessions: 64,
        };
        let config=oryn_config::parse_config("proxy-groups:\n - name: Auto\n   type: smart\n   proxies: [DIRECT]\n   smart:\n     services:\n      - id: account\n        domains: [login.example, api.example]\n").unwrap();
        let built = crate::build_outbounds(&config, &ctx);
        let s = built
            .iter()
            .find(|o| o.tag() == "Auto")
            .unwrap()
            .as_group()
            .unwrap()
            .smart
            .as_ref()
            .unwrap();
        assert_eq!(
            s.target_key(&TargetAddr::from_host("api.example", 443)),
            "service:account"
        );
        assert_eq!(
            s.target_key(&TargetAddr::from_host("other.example", 443)),
            "other.example"
        );
        assert!(
            TargetKey(
                "service:account".into(),
                false,
                PathKey("x".into(), Family::Unknown)
            ) != TargetKey(
                "service:account".into(),
                true,
                PathKey("x".into(), Family::Unknown)
            )
        );
    }
}

impl Smart {
    /// 只探测显式配置的代理服务器 TCP 承载，不访问任意网站、不发送业务数据。
    pub async fn probe(&self, index: usize) {
        let Some(resolver) = &self.resolver else {
            return;
        };
        let paths: Vec<_> = self
            .candidates
            .iter()
            .filter(|c| c.server.is_some())
            .collect();
        if paths.is_empty() {
            return;
        }
        let c = paths[index % paths.len()];
        let path = PathKey(c.node.clone(), c.family);
        let epoch = self.state.lock().unwrap().epoch;
        let dialer = FamilyDialer {
            resolver: resolver.clone(),
            family: c.family,
        };
        let start = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            dialer.dial_tcp(c.server.as_ref().unwrap()),
        )
        .await;
        // 没有 TRACE，探针不能进入真实流量统计。
        if let Ok(Ok(_stream)) = result {
            let mut state = self.state.lock().unwrap();
            if state.epoch != epoch {
                return;
            }
            let tn = state.tuning;
            state.probes.entry(path.clone()).or_default().record(
                true,
                Some(start.elapsed().as_secs_f64() * 1000.0),
                Instant::now(),
                &tn,
            );
            if let Some(p) = state.paths.get_mut(&path) {
                p.failures = 0;
                p.open_until = None;
                p.recovering = false;
            }
        }
    }
}
fn udp_capable(kind: &oryn_config::OutboundKind) -> bool {
    use oryn_config::OutboundKind::*;
    match kind {
        Direct | Sudoku(_) | ShadowQuic(_) => true,
        Reject | Http { .. } | Group(_) => false,
        Socks5 { udp, .. } | Shadowsocks { udp, .. } => *udp,
        Trojan { stream, .. } | Vless { stream, .. } | Vmess { stream, .. } => stream.udp,
        AnyTls(s) => s.udp,
        Ssr(s) => s.udp,
        Mieru(s) => s.udp,
        Snell(s) => s.udp,
        Naive(s) => s.uot.is_some(),
        Ssh(s) => s.udp_gateway.is_some(),
        Hysteria2(s) => s.udp,
        Hysteria(s) => s.udp,
        Tuic(s) => s.udp,
        WireGuard(s) => s.udp,
        Tailscale(s) => s.enabled && s.udp,
    }
}
