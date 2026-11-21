//! Oryn DNS Engine。
//!
//! 查询流程（来自隧道内应用的查询）：
//! 1. `ipv6: false` 时 AAAA 返回空结果；
//! 2. 主机映射（`hosts`）；
//! 3. 应答缓存；
//! 4. 转发规则选出上游（组 / 单个服务器 / 引导 DNS / 拒绝），未命中用 `nameserver`；
//! 5. 按顺序逐个服务器查询：每个服务器所用的出站按服务器参数或分流规则决定（`respect-rules`），
//!    查询附加 ECS；
//! 6. 结果去除被屏蔽的 IP 等，写入缓存与 IP → 域名映射。
//!
//! 另有两种内部解析：代理服务器域名（代理域名服务器 / 转发规则 / 引导 DNS，始终直连）
//! 与加密 DNS 服务器自身的域名（只用引导 DNS）。格式说明见 `docs/config.md`。

mod cache;
mod fakeip;
mod real_ip;
pub use real_ip::normalize_real_ip_domains;
pub mod message;
mod quic_socket;
mod transport;
pub mod wire;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use log::{debug, warn};
use oryn_config::{
    glob_match, suffix_match, DnsProto, DnsSpec, DnsVia, FakeIpFilter, FakeIpFilterMode,
    ForwardMatch, ForwardTarget, HostEntry, HostValue, IpCidr, RejectResponse, ServerSpec,
    TargetAddr,
};
use oryn_outbound::{resolve, Outbound, PickMeta, Resolver};
use oryn_router::{DomainSource, FlowContext, Network, Router, RuleSetStore};

pub use cache::{BoundedMap, CacheKey, CacheSource, DnsCache, DomainMapping};
pub use fakeip::{parse_reverse_name, reverse_name};
pub use transport::{framed, Via, UPSTREAM_TIMEOUT};

use message::{Message, RData, Record, TYPE_A, TYPE_AAAA, TYPE_PTR};
use transport::Client;

const CACHE_CAPACITY: usize = 1024;
const MAPPING_CAPACITY: usize = 4096;
const MAX_CLIENTS: usize = 32;
const MAX_HOST_CACHE: usize = 256;
/// 同时合并的在途查询上限；超过时不合并，各自查询。
const MAX_INFLIGHT: usize = 256;
/// 等待在途查询结果的最长时间。
const FLIGHT_WAIT: Duration = Duration::from_secs(6);
/// 上游统计条目上限（按 类别 + 组 + 服务器 计）。
const MAX_UPSTREAM_STATS: usize = 128;
/// 诊断快照中错误文本的最大长度。
const MAX_ERROR_TEXT: usize = 160;
const HOST_CACHE_TTL: Duration = Duration::from_secs(300);
const HOSTS_TTL: u32 = 10;
/// 主机映射别名的最大跳转次数。
const MAX_ALIAS_DEPTH: u8 = 4;

/// 分流所需的运行时对象，由 Core 在每次加载配置时创建。
pub struct Routing {
    pub router: Router,
    pub outbounds: Vec<Arc<dyn Outbound>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkKind {
    #[default]
    Unknown,
    Wifi,
    Cellular,
    Wired,
    Other,
}

/// 当前网络，用于 `SSID` / `BSSID` / `CELLULAR` 转发规则。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkInfo {
    pub kind: NetworkKind,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    /// 蜂窝无线制式，如 `LTE`、`NR`。
    pub radio: Option<String>,
    /// 物理网络是否支持 IPv6（`NWPath.supportsIPv6`）；`None` 表示未知，按支持处理。
    pub ipv6: Option<bool>,
}

/// 一次查询的处理结果，用于日志。
#[derive(Debug, Clone, Default)]
pub struct QueryOutcome {
    pub domain: Option<String>,
    /// 应答来源：服务器地址、`hosts`、`cache`、`fake-ip`、`reject`、`ipv6-disabled`。
    pub upstream: Option<String>,
    /// 查询经过的出站链路。
    pub via: Option<String>,
    pub cached: bool,
}

/// 缓存记录快照，供 `dns_cache` 控制命令使用。
#[derive(Debug, Clone)]
pub struct CacheRecord {
    pub domain: String,
    pub qtype: u16,
    pub ips: Vec<IpAddr>,
    pub source: CacheSource,
    pub ttl: u32,
    pub remaining: u32,
    /// 到期时刻（Unix 秒）。
    pub expires_at: f64,
    pub fake_ips: Vec<IpAddr>,
}

/// 单个上游服务器的运行统计。
#[derive(Debug, Clone, Default)]
pub struct UpstreamStatus {
    pub kind: &'static str,
    pub group: Option<String>,
    pub server: String,
    pub queries: u64,
    pub failures: u64,
    pub latency_ms: Option<u64>,
    pub last_error: Option<String>,
}

/// 上游统计的键：类别、上游组名、服务器原文。
type UpstreamKey = (&'static str, Option<String>, String);

#[derive(Default)]
struct UpstreamCounter {
    queries: u64,
    failures: u64,
    latency_ms: Option<u64>,
    last_error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// 隧道内应用的查询。
    App,
    /// DIRECT 连接的目标域名。
    DirectTarget,
    /// 代理服务器的域名。
    ProxyServer,
}

struct DnsRuntime {
    spec: DnsSpec,
    hosts: Vec<HostEntry>,
    /// 与 `spec.forward` 对齐的已编译正则。
    regexes: Vec<Option<oryn_config::CompactRegex>>,
    rule_sets: Arc<RuleSetStore>,
}

enum Decision {
    Direct,
    Proxy(Arc<dyn Outbound>, Vec<String>),
    Reject,
}

pub struct DnsEngine {
    runtime: RwLock<Arc<DnsRuntime>>,
    routing: RwLock<Weak<Routing>>,
    cache: Mutex<DnsCache>,
    mapping: Mutex<DomainMapping>,
    fakeip: Mutex<fakeip::FakeIpPool>,
    clients: Mutex<HashMap<String, Arc<Client>>>,
    /// 引导解析与代理服务器解析的结果。
    host_cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
    upstream_stats: Mutex<BoundedMap<UpstreamKey, UpstreamCounter>>,
    network: RwLock<NetworkInfo>,
    public_ecs: RwLock<Option<IpCidr>>,
    next_id: AtomicU16,
    /// 本地 Fake-IP 应答次数。这类应答不经过上游，也不进入普通缓存。
    fake_answers: AtomicU64,
    /// 本机应用目标设置：bit 0 支持 IPv6，bit 1 优先 IPv6；节点解析不使用它。
    target_ip_policy: AtomicU8,
    proxy_prefer_ipv6: AtomicBool,
    /// Core 综合判定的本机 IPv6 可用性（见 oryn-core `local_ipv6`）；不可用时本机拨号用的解析不查 AAAA。
    local_ipv6: AtomicBool,
    real_ip_domains: RwLock<Vec<String>>,
    /// 在途的上游查询（singleflight），值为等待方订阅的结果通道。
    inflight: Mutex<HashMap<CacheKey, tokio::sync::watch::Receiver<Option<Vec<u8>>>>>,
}

enum Flight<'a> {
    Leader(FlightGuard<'a>),
    Follower(tokio::sync::watch::Receiver<Option<Vec<u8>>>),
    Solo,
}

/// 领头查询的守卫：完成时广播应答；被取消（drop）时移除条目，等待方随即自己查询。
struct FlightGuard<'a> {
    engine: &'a DnsEngine,
    key: CacheKey,
    tx: tokio::sync::watch::Sender<Option<Vec<u8>>>,
}

impl FlightGuard<'_> {
    fn finish(self, resp: &[u8]) {
        let _ = self.tx.send(Some(resp.to_vec()));
    }
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        let mut map = self.engine.inflight.lock().unwrap();
        if map
            .get(&self.key)
            .is_some_and(|rx| rx.same_channel(&self.tx.subscribe()))
        {
            map.remove(&self.key);
        }
    }
}

async fn wait_flight(mut rx: tokio::sync::watch::Receiver<Option<Vec<u8>>>) -> Option<Vec<u8>> {
    tokio::time::timeout(FLIGHT_WAIT, async move {
        loop {
            if let Some(v) = rx.borrow_and_update().clone() {
                return Some(v);
            }
            if rx.changed().await.is_err() {
                return rx.borrow().clone();
            }
        }
    })
    .await
    .ok()
    .flatten()
}

fn compile(spec: DnsSpec, hosts: Vec<HostEntry>, rule_sets: Arc<RuleSetStore>) -> DnsRuntime {
    let regexes = spec
        .forward
        .iter()
        .map(|r| match &r.matcher {
            ForwardMatch::DomainRegex(p) => {
                oryn_config::compile_regex(p).ok()
            }
            _ => None,
        })
        .collect();
    DnsRuntime {
        spec,
        hosts,
        regexes,
        rule_sets,
    }
}

impl DnsEngine {
    pub fn new(spec: DnsSpec, hosts: Vec<HostEntry>, rule_sets: Arc<RuleSetStore>) -> Self {
        let fake_ip_range = spec.fake_ip_range;
        DnsEngine {
            runtime: RwLock::new(Arc::new(compile(spec, hosts, rule_sets))),
            routing: RwLock::new(Weak::new()),
            cache: Mutex::new(DnsCache::new(CACHE_CAPACITY)),
            mapping: Mutex::new(DomainMapping::new(MAPPING_CAPACITY)),
            fakeip: Mutex::new(fakeip::FakeIpPool::new(fake_ip_range)),
            clients: Mutex::new(HashMap::new()),
            host_cache: Mutex::new(HashMap::new()),
            upstream_stats: Mutex::new(BoundedMap::new(MAX_UPSTREAM_STATS)),
            network: RwLock::new(NetworkInfo::default()),
            public_ecs: RwLock::new(None),
            next_id: AtomicU16::new(0x4f52),
            fake_answers: AtomicU64::new(0),
            target_ip_policy: AtomicU8::new(1),
            proxy_prefer_ipv6: AtomicBool::new(false),
            local_ipv6: AtomicBool::new(true),
            real_ip_domains: RwLock::new(Vec::new()),
            inflight: Mutex::new(HashMap::new()),
        }
    }

    fn join_flight(&self, key: &CacheKey, purpose: Purpose) -> Flight<'_> {
        // 节点解析不进缓存，也不合并（每次都要新鲜结果）。
        if purpose == Purpose::ProxyServer {
            return Flight::Solo;
        }
        let mut map = self.inflight.lock().unwrap();
        if let Some(rx) = map.get(key) {
            return Flight::Follower(rx.clone());
        }
        if map.len() >= MAX_INFLIGHT {
            return Flight::Solo;
        }
        let (tx, rx) = tokio::sync::watch::channel(None);
        map.insert(key.clone(), rx);
        Flight::Leader(FlightGuard {
            engine: self,
            key: key.clone(),
            tx,
        })
    }

    /// 重新加载 DNS 配置：清空缓存与上游连接。
    pub fn apply(&self, spec: DnsSpec, hosts: Vec<HostEntry>, rule_sets: Arc<RuleSetStore>) {
        self.fakeip.lock().unwrap().configure(spec.fake_ip_range);
        *self.runtime.write().unwrap() = Arc::new(compile(spec, hosts, rule_sets));
        self.upstream_stats.lock().unwrap().clear();
        self.reset();
    }

    pub fn set_target_ipv6(&self, support: bool, prefer: bool) {
        let policy = u8::from(support) | (u8::from(prefer) << 1);
        if self.target_ip_policy.swap(policy, Ordering::Relaxed) != policy {
            self.reset();
        }
    }

    /// 仅调整节点解析，新连接使用新偏好，保留已有会话。
    /// 由 Core 设置；变化时清空主机缓存，避免沿用另一种判定下的结果。
    pub fn set_local_ipv6(&self, available: bool) {
        if self.local_ipv6.swap(available, Ordering::Relaxed) != available {
            self.host_cache.lock().unwrap().clear();
        }
    }

    pub fn set_proxy_prefer_ipv6(&self, prefer: bool) {
        if self.proxy_prefer_ipv6.swap(prefer, Ordering::Relaxed) != prefer {
            self.host_cache
                .lock()
                .unwrap()
                .retain(|key, _| !key.starts_with("p:"));
        }
    }

    /// 先完整校验再替换；保留旧 Fake-IP 映射供已有连接使用。
    pub fn set_real_ip_domains(&self, values: &[String]) -> Result<(), String> {
        let values = normalize_real_ip_domains(values)?;
        let mut current = self.real_ip_domains.write().unwrap();
        if *current != values {
            *current = values;
            self.clear_cache();
        }
        Ok(())
    }

    pub fn target_ipv6_supported(&self) -> bool {
        self.target_ip_policy.load(Ordering::Relaxed) & 1 != 0
    }

    /// 设置 App Group 数据目录并恢复 Fake-IP 映射。
    pub fn set_data_dir(&self, data_dir: Option<&Path>) {
        self.fakeip.lock().unwrap().set_path(data_dir);
    }

    pub fn persist(&self) {
        self.fakeip.lock().unwrap().save_if_due(true);
    }

    pub fn set_routing(&self, routing: Weak<Routing>) {
        *self.routing.write().unwrap() = routing;
    }

    pub fn set_network(&self, info: NetworkInfo) {
        *self.network.write().unwrap() = info;
    }

    pub fn network(&self) -> NetworkInfo {
        self.network.read().unwrap().clone()
    }

    pub fn set_public_ecs(&self, subnet: Option<IpCidr>) {
        *self.public_ecs.write().unwrap() = subnet;
    }

    pub fn public_ecs(&self) -> Option<IpCidr> {
        *self.public_ecs.read().unwrap()
    }

    pub fn public_ip_url(&self) -> Option<String> {
        self.rt().spec.public_ip_url.clone()
    }

    /// 清空缓存、上游连接与内部解析结果（网络切换时调用）。
    pub fn reset(&self) {
        self.cache.lock().unwrap().clear();
        self.clients.lock().unwrap().clear();
        self.host_cache.lock().unwrap().clear();
    }

    pub fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
        self.host_cache.lock().unwrap().clear();
    }

    pub fn cache_len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// 未过期的缓存记录，从新到旧，最多 `limit` 条。
    pub fn cache_snapshot(&self, limit: usize) -> Vec<CacheRecord> {
        let now = Instant::now();
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        let records: Vec<CacheRecord> = {
            let cache = self.cache.lock().unwrap();
            cache
                .recent(limit)
                .into_iter()
                .map(|(key, entry)| {
                    let left = entry.expires.saturating_duration_since(now);
                    CacheRecord {
                        domain: key.name.clone(),
                        qtype: key.qtype,
                        ips: wire::parse_answer(&entry.response)
                            .map(|a| a.ips)
                            .unwrap_or_default(),
                        source: entry.source.clone(),
                        ttl: entry.ttl,
                        remaining: left.as_secs() as u32,
                        expires_at: wall + left.as_secs_f64(),
                        fake_ips: Vec::new(),
                    }
                })
                .collect()
        };
        let fakeip = self.fakeip.lock().unwrap();
        records
            .into_iter()
            .map(|mut r| {
                r.fake_ips = fakeip
                    .peek_ip(&r.domain)
                    .map(IpAddr::V4)
                    .into_iter()
                    .collect();
                r
            })
            .collect()
    }

    /// 当前配置中所有上游服务器及其统计，按 代理服务器 → 上游组 → 默认 的顺序。
    pub fn upstream_status(&self) -> Vec<UpstreamStatus> {
        let rt = self.rt();
        let mut list: Vec<UpstreamStatus> = Vec::new();
        let mut push = |kind: &'static str, group: Option<&str>, servers: &[ServerSpec]| {
            for server in servers {
                if list.iter().any(|u| {
                    u.kind == kind && u.group.as_deref() == group && u.server == server.raw
                }) {
                    continue;
                }
                list.push(UpstreamStatus {
                    kind,
                    group: group.map(str::to_string),
                    server: server.raw.clone(),
                    ..Default::default()
                });
            }
        };
        push("proxy-server", None, &rt.spec.proxy_server);
        for g in &rt.spec.upstreams {
            push("group", Some(&g.name), &g.servers);
        }
        push("nameserver", None, &rt.spec.nameserver);
        let stats = self.upstream_stats.lock().unwrap();
        for u in &mut list {
            if let Some(c) = stats.get(&(u.kind, u.group.clone(), u.server.clone())) {
                u.queries = c.queries;
                u.failures = c.failures;
                u.latency_ms = c.latency_ms;
                u.last_error = c.last_error.clone();
            }
        }
        list
    }

    fn record_upstream(
        &self,
        kind: &'static str,
        group: &Option<String>,
        server: &str,
        result: Result<Duration, &io::Error>,
    ) {
        let key = (kind, group.clone(), server.to_string());
        let mut stats = self.upstream_stats.lock().unwrap();
        let mut counter =
            stats
                .get(&key)
                .map_or_else(UpstreamCounter::default, |c| UpstreamCounter {
                    queries: c.queries,
                    failures: c.failures,
                    latency_ms: c.latency_ms,
                    last_error: c.last_error.clone(),
                });
        counter.queries += 1;
        match result {
            Ok(elapsed) => {
                counter.latency_ms = Some(elapsed.as_millis() as u64);
                counter.last_error = None;
            }
            Err(e) => {
                counter.failures += 1;
                let mut text = e.to_string();
                if text.len() > MAX_ERROR_TEXT {
                    let mut end = MAX_ERROR_TEXT;
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    text.truncate(end);
                }
                counter.last_error = Some(text);
            }
        }
        stats.insert(key, counter);
    }

    pub fn mapping_len(&self) -> usize {
        self.mapping.lock().unwrap().len()
    }

    /// IP → 域名反查。
    pub fn lookup_domain(&self, ip: &IpAddr) -> Option<String> {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*ip),
            _ => *ip,
        };
        if let IpAddr::V4(v4) = ip {
            if let Some(domain) = self.fakeip.lock().unwrap().lookup_domain(&v4) {
                return self.unscoped_domain(domain);
            }
        }
        self.mapping.lock().unwrap().lookup(&ip).map(str::to_string)
    }

    /// 地址位于 Fake-IP 池内时，即使映射缺失也返回 true。
    pub fn is_fake_ip(&self, ip: &IpAddr) -> bool {
        self.fakeip.lock().unwrap().contains(*ip)
    }

    /// 嗅探恢复出的域名补回映射，使同一 Fake-IP 的后续连接不必再嗅探。
    pub fn remember_fake_ip(&self, ip: &IpAddr, domain: &str) {
        let v4 = match ip {
            IpAddr::V4(v4) => *v4,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4,
                None => return,
            },
        };
        let mut pool = self.fakeip.lock().unwrap();
        if pool.claim(v4, domain) {
            pool.save_if_due(true);
        }
    }

    pub fn fake_ip_len(&self) -> usize {
        self.fakeip.lock().unwrap().len()
    }

    pub fn fake_ip_answers(&self) -> u64 {
        self.fake_answers.load(Ordering::Relaxed)
    }

    pub fn lookup_fake_domain(&self, ip: &IpAddr) -> Option<String> {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*ip),
            _ => *ip,
        };
        let IpAddr::V4(v4) = ip else { return None };
        let domain = self.fakeip.lock().unwrap().lookup_domain(&v4)?;
        self.unscoped_domain(domain)
    }

    fn unscoped_domain(&self, domain: String) -> Option<String> {
        let Some(value) = domain.strip_prefix("@tailscale:") else {
            return Some(domain);
        };
        let (scope, name) = value.split_once('|')?;
        let routing = self.routing.read().unwrap().upgrade()?;
        routing
            .outbounds
            .iter()
            .any(|o| o.dns_scope().as_deref() == Some(scope))
            .then(|| name.to_string())
    }

    fn rt(&self) -> Arc<DnsRuntime> {
        self.runtime.read().unwrap().clone()
    }

    fn alloc_id(&self) -> u16 {
        self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }

    /// 处理一个来自隧道的查询。总会返回应答（失败时为错误响应）。
    pub async fn handle_query(&self, query: &[u8], source: SocketAddr) -> (Vec<u8>, QueryOutcome) {
        let Some(q) = wire::parse_question(query) else {
            return (
                wire::build_error(query, None, wire::RCODE_FORMERR),
                QueryOutcome::default(),
            );
        };
        self.lookup(query, &q, Purpose::App, Some(source), 0).await
    }

    async fn lookup(
        &self,
        query: &[u8],
        q: &wire::Question,
        purpose: Purpose,
        source: Option<SocketAddr>,
        depth: u8,
    ) -> (Vec<u8>, QueryOutcome) {
        let rt = self.rt();
        let mut outcome = QueryOutcome {
            domain: Some(q.name.clone()),
            ..Default::default()
        };

        // 在 hosts、Tailscale 与缓存之前拦截，且不影响节点解析。
        if q.qtype == TYPE_AAAA && purpose != Purpose::ProxyServer && !self.target_ipv6_supported()
        {
            outcome.upstream = Some("ipv6-disabled".into());
            return (empty_response(query, q), outcome);
        }

        let identity_servers = match self.forward_target(&rt, &q.name) {
            Some(ForwardTarget::Servers(s)) => Some(s.as_slice()),
            Some(ForwardTarget::Upstream(i)) => Some(rt.spec.upstreams[*i].servers.as_slice()),
            None => Some(rt.spec.nameserver.as_slice()),
            _ => None,
        };
        if let Some(server) = identity_servers
            .and_then(|servers| servers.iter().find(|s| s.proto == DnsProto::Tailscale))
        {
            outcome.upstream = Some(server.raw.clone());
            if self.domain_rejected(&q.name, source) {
                return (reject_response(query, q, rt.spec.reject_response), outcome);
            }
            let result = async {
                // 代理与控制面 bootstrap 必须独立，拒绝递归进入自身身份。
                if purpose == Purpose::ProxyServer {
                    return Err(io::Error::other(
                        "Tailscale DNS cannot resolve bootstrap proxy endpoints",
                    ));
                }
                let routing = self
                    .routing
                    .read()
                    .unwrap()
                    .upgrade()
                    .ok_or_else(|| io::Error::other("DNS routing is unavailable"))?;
                let DnsVia::Outbound(i) = server.via else {
                    return Err(io::Error::other("invalid Tailscale DNS binding"));
                };
                let outbound = routing
                    .outbounds
                    .get(i)
                    .ok_or_else(|| io::Error::other("Tailscale DNS outbound missing"))?;
                let answer = outbound.query_dns(&q.name, q.qtype).await?;
                let message =
                    Message::parse(query).ok_or_else(|| io::Error::other("invalid DNS query"))?;
                let mut records = Vec::new();
                if answer.exists {
                    if purpose == Purpose::App
                        && self.should_fake(&rt, &q.name)
                        && matches!(
                            q.qtype,
                            TYPE_A | TYPE_AAAA | wire::TYPE_SVCB | wire::TYPE_HTTPS
                        )
                    {
                        if q.qtype == TYPE_A {
                            let scope = outbound.dns_scope().ok_or_else(|| {
                                io::Error::other("Tailscale identity changed during DNS lookup")
                            })?;
                            let key = format!("@tailscale:{scope}|{}", q.name);
                            let ip =
                                self.fakeip.lock().unwrap().allocate(&key).ok_or_else(|| {
                                    io::Error::other("identity Fake-IP pool is full")
                                })?;
                            records.push(Record {
                                name: q.name.clone(),
                                rtype: TYPE_A,
                                class: 1,
                                ttl: 1,
                                data: RData::A(ip),
                            });
                            self.fakeip.lock().unwrap().save_if_due(true);
                        }
                    } else {
                        for ip in answer.ips {
                            let data = match ip {
                                IpAddr::V4(ip) if q.qtype == TYPE_A => RData::A(ip),
                                IpAddr::V6(ip) if q.qtype == TYPE_AAAA && rt.spec.ipv6 => {
                                    RData::Aaaa(ip)
                                }
                                _ => continue,
                            };
                            records.push(Record {
                                name: q.name.clone(),
                                rtype: q.qtype,
                                class: 1,
                                ttl: 1,
                                data,
                            });
                        }
                        if let Some(ptr) = answer.ptr {
                            records.push(Record {
                                name: q.name.clone(),
                                rtype: TYPE_PTR,
                                class: 1,
                                ttl: 1,
                                data: RData::Name(ptr),
                            });
                        }
                    }
                }
                Ok(
                    message::response_for(&message, if answer.exists { 0 } else { 3 }, records)
                        .serialize(),
                )
            }
            .await;
            return (
                result.unwrap_or_else(|_| {
                    wire::build_error(query, Some(q.end), wire::RCODE_SERVFAIL)
                }),
                outcome,
            );
        }

        if rt.spec.use_hosts {
            if let Some(entry) = rt.hosts.iter().find(|h| h.pattern.matches(&q.name)) {
                outcome.upstream = Some("hosts".into());
                return (
                    self.hosts_answer(query, q, &entry.value, purpose, source, depth)
                        .await,
                    outcome,
                );
            }
        }

        // 隧道内应用的 Fake-IP 应答在本地完成；内部解析仍走上游。
        if purpose == Purpose::App {
            if q.qtype == TYPE_PTR {
                if let Some(ip) = fakeip::parse_reverse_name(&q.name) {
                    if let Some(domain) = self.lookup_fake_domain(&IpAddr::V4(ip)) {
                        outcome.upstream = Some("fake-ip".into());
                        let msg = Message::parse(query).expect("parsed DNS query");
                        return (
                            message::response_for(
                                &msg,
                                0,
                                vec![Record {
                                    name: q.name.clone(),
                                    rtype: TYPE_PTR,
                                    class: q.qclass,
                                    ttl: 1,
                                    data: RData::Name(domain),
                                }],
                            )
                            .serialize(),
                            outcome,
                        );
                    }
                }
            }
            if self.should_fake(&rt, &q.name)
                && matches!(
                    q.qtype,
                    TYPE_A | TYPE_AAAA | wire::TYPE_SVCB | wire::TYPE_HTTPS
                )
            {
                if matches!(
                    self.forward_target(&rt, &q.name),
                    Some(ForwardTarget::Reject)
                ) || self.domain_rejected(&q.name, source)
                {
                    outcome.upstream = Some("reject".into());
                    return (reject_response(query, q, rt.spec.reject_response), outcome);
                }
                outcome.upstream = Some("fake-ip".into());
                self.fake_answers.fetch_add(1, Ordering::Relaxed);
                let response = if q.qtype == TYPE_A {
                    let Some(ip) = self.fakeip.lock().unwrap().allocate(&q.name) else {
                        return (
                            wire::build_error(query, Some(q.end), wire::RCODE_SERVFAIL),
                            outcome,
                        );
                    };
                    let msg = Message::parse(query).expect("parsed DNS query");
                    message::response_for(
                        &msg,
                        0,
                        vec![Record {
                            name: q.name.clone(),
                            rtype: TYPE_A,
                            class: q.qclass,
                            ttl: 1,
                            data: RData::A(ip),
                        }],
                    )
                    .serialize()
                } else {
                    empty_response(query, q)
                };
                // 新租约立刻落盘。系统 DNS 缓存会跨进程重启保留 Fake-IP，映射若只在内存里，重启后会对不上。
                self.fakeip.lock().unwrap().save_if_due(true);
                return (response, outcome);
            }
        }

        if q.qtype == TYPE_AAAA && !rt.spec.ipv6 {
            outcome.upstream = Some("ipv6-disabled".into());
            return (empty_response(query, q), outcome);
        }

        let key = CacheKey {
            name: q.name.clone(),
            qtype: q.qtype,
            qclass: q.qclass,
        };
        if purpose != Purpose::ProxyServer {
            let cached = self.cache.lock().unwrap().get(&key);
            if let Some(mut resp) = cached {
                wire::set_id(&mut resp, q.id);
                outcome.cached = true;
                outcome.upstream = Some("cache".into());
                return (resp, outcome);
            }
        }

        // 同一问题已有在途查询时等待其结果（singleflight），不重复打到上游。
        let leader = match self.join_flight(&key, purpose) {
            Flight::Follower(rx) => match wait_flight(rx).await {
                Some(mut resp) => {
                    wire::set_id(&mut resp, q.id);
                    outcome.cached = true;
                    outcome.upstream = Some("in-flight".into());
                    return (resp, outcome);
                }
                // 领头查询被取消或超时：自己查。
                None => None,
            },
            Flight::Leader(guard) => Some(guard),
            Flight::Solo => None,
        };
        let resp = self
            .query_upstream(&rt, query, q, &key, purpose, source, &mut outcome)
            .await;
        if let Some(guard) = leader {
            guard.finish(&resp);
        }
        (resp, outcome)
    }

    /// 并发查询所选的全部上游，取最先成功的应答（与 mihomo 一致）；
    /// 全部失败时返回 SERVFAIL（若有服务器被规则拒绝则返回拒绝响应）。
    #[allow(clippy::too_many_arguments)]
    async fn query_upstream(
        &self,
        rt: &DnsRuntime,
        query: &[u8],
        q: &wire::Question,
        key: &CacheKey,
        purpose: Purpose,
        source: Option<SocketAddr>,
        outcome: &mut QueryOutcome,
    ) -> Vec<u8> {
        // 选择上游
        let (kind, group, servers): (&'static str, Option<String>, Vec<ServerSpec>) = if purpose
            == Purpose::ProxyServer
            && !rt.spec.proxy_server.is_empty()
        {
            ("proxy-server", None, rt.spec.proxy_server.clone())
        } else {
            match self.forward_target(rt, &q.name) {
                Some(ForwardTarget::Reject) => {
                    outcome.upstream = Some("reject".into());
                    return reject_response(query, q, rt.spec.reject_response);
                }
                Some(ForwardTarget::Upstream(i)) => {
                    let g = &rt.spec.upstreams[*i];
                    ("group", Some(g.name.clone()), g.servers.clone())
                }
                Some(ForwardTarget::Servers(s)) => ("servers", None, s.clone()),
                Some(ForwardTarget::Bootstrap) => ("bootstrap", None, rt.spec.bootstrap.clone()),
                None if purpose == Purpose::ProxyServer => {
                    ("bootstrap", None, rt.spec.bootstrap.clone())
                }
                None => ("nameserver", None, rt.spec.nameserver.clone()),
            }
        };

        let mut rejected = false;
        let mut candidates = Vec::with_capacity(servers.len());
        for server in &servers {
            let decision = if purpose == Purpose::ProxyServer {
                Decision::Direct
            } else {
                self.decide(rt, server, &q.name, source)
            };
            match decision {
                Decision::Reject => rejected = true,
                Decision::Direct => candidates.push((server, Via::Direct, "DIRECT".to_string())),
                Decision::Proxy(leaf, chain) => {
                    candidates.push((server, Via::Proxy(leaf), chain.join(" → ")))
                }
            }
        }
        let chains: Vec<String> = candidates.iter().map(|c| c.2.clone()).collect();
        let targets: Vec<&ServerSpec> = candidates.iter().map(|c| c.0).collect();
        type Exchange<'a> = std::pin::Pin<
            Box<dyn std::future::Future<Output = (usize, io::Result<Vec<u8>>, Duration)> + Send + 'a>,
        >;
        let mut pending: Vec<Exchange<'_>> = candidates
            .into_iter()
            .enumerate()
            .map(|(i, (server, via, _))| {
                let outgoing = self.with_ecs(query, server);
                Box::pin(async move {
                    let started = Instant::now();
                    let result = self.exchange(server, via, &outgoing, rt).await;
                    (i, result, started.elapsed())
                }) as Exchange<'_>
            })
            .collect();
        let mut last_err = None;
        while !pending.is_empty() {
            let (slot, (i, result, elapsed)) = std::future::poll_fn(|cx| {
                for (n, f) in pending.iter_mut().enumerate() {
                    if let std::task::Poll::Ready(v) = f.as_mut().poll(cx) {
                        return std::task::Poll::Ready((n, v));
                    }
                }
                std::task::Poll::Pending
            })
            .await;
            drop(pending.swap_remove(slot));
            let server = targets[i];
            self.record_upstream(kind, &group, &server.raw, result.as_ref().map(|_| elapsed));
            match result {
                Ok(resp) => {
                    let mut resp = post_process(resp, server, &rt.spec.blocked_ips);
                    let source = CacheSource {
                        kind,
                        group: group.clone(),
                        server: server.raw.clone(),
                    };
                    self.store(key, &resp, purpose, source);
                    outcome.upstream = Some(server.raw.clone());
                    outcome.via = Some(chains[i].clone());
                    wire::set_id(&mut resp, q.id);
                    // 其余在途查询随 pending 一起丢弃（取消）。
                    return resp;
                }
                Err(e) => {
                    debug!("DNS {} via {} ({}) failed: {e}", q.name, server.raw, chains[i]);
                    last_err = Some(e);
                }
            }
        }
        if let Some(e) = last_err {
            warn!("DNS query for {} failed on all servers: {e}", q.name);
        }
        if rejected {
            outcome.upstream = Some("reject".into());
            return reject_response(query, q, rt.spec.reject_response);
        }
        wire::build_error(query, Some(q.end), wire::RCODE_SERVFAIL)
    }

    fn forward_target<'a>(&self, rt: &'a DnsRuntime, domain: &str) -> Option<&'a ForwardTarget> {
        // 只借读锁：原来每次查询都克隆一份网络信息（SSID / BSSID / 制式字符串）
        let net = self.network.read().unwrap();
        rt.spec.forward.iter().enumerate().find_map(|(i, r)| {
            let hit = match &r.matcher {
                ForwardMatch::Domain(d) => domain == d,
                ForwardMatch::DomainSuffix(s) => suffix_match(domain, s),
                ForwardMatch::DomainKeyword(k) => domain.contains(k.as_str()),
                ForwardMatch::DomainWildcard(w) => glob_match(w, domain),
                ForwardMatch::DomainRegex(_) => {
                    rt.regexes[i].as_ref().is_some_and(|r| r.is_match(domain))
                }
                ForwardMatch::Pattern(p) => p.matches(domain),
                ForwardMatch::RuleSet(idx) => rt.rule_sets.matches_domain(*idx, domain),
                ForwardMatch::Ssid(p) => net.ssid.as_deref().is_some_and(|s| glob_match(p, s)),
                ForwardMatch::Bssid(p) => net.bssid.as_deref().is_some_and(|b| glob_match(p, b)),
                ForwardMatch::Cellular(p) => {
                    net.kind == NetworkKind::Cellular
                        && (p == "*" || net.radio.as_deref().is_some_and(|r| glob_match(p, r)))
                }
                ForwardMatch::Final => true,
            };
            hit.then_some(&r.target)
        })
    }

    fn should_fake(&self, rt: &DnsRuntime, domain: &str) -> bool {
        if self.real_ip_domains.read().unwrap().iter().any(|p| glob_match(p, domain)) {
            return false;
        }
        let listed = rt.spec.fake_ip_filter.iter().any(|f| match f {
            FakeIpFilter::Domain(pattern) => pattern.matches(domain),
            FakeIpFilter::Glob(pattern) => oryn_config::glob_match(pattern, domain),
            FakeIpFilter::RuleSet(i) => rt.rule_sets.matches_domain(*i, domain),
        });
        match rt.spec.fake_ip_filter_mode {
            FakeIpFilterMode::Blacklist => !listed,
            FakeIpFilterMode::Whitelist => listed,
        }
    }

    fn domain_rejected(&self, domain: &str, source: Option<SocketAddr>) -> bool {
        let Some(routing) = self.routing.read().unwrap().upgrade() else {
            return false;
        };
        let src = source.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let dst = SocketAddr::from(([0, 0, 0, 0], 53));
        let mut ctx = FlowContext::new(0, Network::Udp, src, dst);
        ctx.set_domain(domain.to_string(), DomainSource::DnsQuery);
        let decision = routing.router.route(&ctx);
        routing
            .outbounds
            .get(decision.outbound)
            .is_some_and(|o| o.is_reject())
    }

    /// 决定发往某个服务器的查询经过哪个出站。
    fn decide(
        &self,
        rt: &DnsRuntime,
        server: &ServerSpec,
        domain: &str,
        source: Option<SocketAddr>,
    ) -> Decision {
        let Some(routing) = self.routing.read().unwrap().upgrade() else {
            return Decision::Direct;
        };
        let start = match server.via {
            DnsVia::Direct => return Decision::Direct,
            DnsVia::Outbound(i) => match routing.outbounds.get(i) {
                Some(o) => o.clone(),
                None => return Decision::Direct,
            },
            DnsVia::Default if !rt.spec.respect_rules => return Decision::Direct,
            DnsVia::Default | DnsVia::Rules => {
                let dst = SocketAddr::new(
                    server
                        .host_ip()
                        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    server.port,
                );
                let src = source.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
                let mut ctx = FlowContext::new(0, Network::Udp, src, dst);
                ctx.set_domain(domain.to_string(), DomainSource::DnsQuery);
                let decision = routing.router.route(&ctx);
                routing.outbounds[decision.outbound].clone()
            }
        };
        let target = TargetAddr::Domain(domain.to_string(), server.port);
        let meta = PickMeta {
            source,
            target: &target,
            network: Network::Udp,
        };
        match resolve(&start, &meta) {
            None => Decision::Reject,
            Some(r) => match r.leaf.kind() {
                "direct" => Decision::Direct,
                "reject" => Decision::Reject,
                _ => Decision::Proxy(r.leaf, r.chain),
            },
        }
    }

    fn with_ecs(&self, query: &[u8], server: &ServerSpec) -> Vec<u8> {
        let (subnet, replace) = match server.ecs {
            Some(s) => (Some(s), server.ecs_override),
            None => (self.public_ecs(), false),
        };
        let Some(subnet) = subnet else {
            return query.to_vec();
        };
        match Message::parse(query) {
            Some(mut m) => {
                m.set_ecs(subnet, replace);
                m.serialize()
            }
            None => query.to_vec(),
        }
    }

    async fn exchange(
        &self,
        server: &ServerSpec,
        via: Via,
        query: &[u8],
        rt: &DnsRuntime,
    ) -> io::Result<Vec<u8>> {
        let client = self.client(server, via, rt).await?;
        client.exchange(query).await
    }

    async fn client(
        &self,
        server: &ServerSpec,
        via: Via,
        rt: &DnsRuntime,
    ) -> io::Result<Arc<Client>> {
        let key = format!("{}|{}", server.raw, via.key());
        if let Some(c) = self.clients.lock().unwrap().get(&key) {
            // 缓存键只含出站标签；换成本次查询刚解析出的出站，避免沿用过期的策略组快照
            // （例如唤醒或换网后 epoch 已失效的 Smart Plan，会让此后每次新建连接都立即失败）。
            c.set_via(via);
            return Ok(c.clone());
        }
        let ip = match server.host_ip() {
            Some(ip) => ip,
            None => *self
                .bootstrap_resolve(&server.host)
                .await?
                .first()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("cannot resolve DNS server {}", server.host),
                    )
                })?,
        };
        Ok(self.client_at(key, server, via, ip, rt))
    }

    /// 已知地址时取得（或创建）复用连接的客户端。
    fn client_at(
        &self,
        key: String,
        server: &ServerSpec,
        via: Via,
        ip: IpAddr,
        rt: &DnsRuntime,
    ) -> Arc<Client> {
        let client = Arc::new(Client::new(
            server.clone(),
            via,
            SocketAddr::new(ip, server.port),
            rt.spec.skip_cert_verify,
        ));
        let mut clients = self.clients.lock().unwrap();
        if clients.len() >= MAX_CLIENTS && !clients.contains_key(&key) {
            // 只淘汰一个（优先没有其他持有者的），避免全部 DoT / DoH / QUIC 连接同时重建。
            let victim = clients
                .iter()
                .find(|(_, c)| Arc::strong_count(c) == 1)
                .or_else(|| clients.iter().next())
                .map(|(k, _)| k.clone());
            if let Some(victim) = victim {
                clients.remove(&victim);
            }
        }
        clients.entry(key).or_insert(client).clone()
    }

    fn store(&self, key: &CacheKey, resp: &[u8], purpose: Purpose, source: CacheSource) {
        let Some(answer) = wire::parse_answer(resp) else {
            return;
        };
        if purpose == Purpose::ProxyServer {
            return;
        }
        {
            let mut mapping = self.mapping.lock().unwrap();
            for ip in &answer.ips {
                mapping.record(*ip, &key.name);
            }
        }
        if answer.rcode == 0 || answer.rcode == 3 {
            self.cache.lock().unwrap().put_with_source(
                key.clone(),
                resp.to_vec(),
                answer.min_ttl.or(answer.negative_ttl),
                source,
            );
        }
    }

    async fn hosts_answer(
        &self,
        query: &[u8],
        q: &wire::Question,
        value: &HostValue,
        purpose: Purpose,
        source: Option<SocketAddr>,
        depth: u8,
    ) -> Vec<u8> {
        let Some(msg) = Message::parse(query) else {
            return wire::build_error(query, Some(q.end), wire::RCODE_FORMERR);
        };
        let ips: Vec<IpAddr> = match value {
            HostValue::Ips(ips) => ips.clone(),
            HostValue::Alias(alias) => {
                if depth >= MAX_ALIAS_DEPTH || (q.qtype != TYPE_A && q.qtype != TYPE_AAAA) {
                    Vec::new()
                } else {
                    let sub = wire::build_query(self.alloc_id(), alias, q.qtype);
                    let sq = wire::parse_question(&sub).expect("自己构造的查询");
                    // hosts 别名的目标必须按真实上游解析，不能被 Fake-IP 再次改写。
                    let alias_purpose = if purpose == Purpose::App {
                        Purpose::DirectTarget
                    } else {
                        purpose
                    };
                    let (resp, _) =
                        Box::pin(self.lookup(&sub, &sq, alias_purpose, source, depth + 1)).await;
                    wire::parse_answer(&resp).map(|a| a.ips).unwrap_or_default()
                }
            }
        };
        let name = msg
            .questions
            .first()
            .map(|q| q.name.clone())
            .unwrap_or_default();
        let answers: Vec<Record> = ips
            .into_iter()
            .filter_map(|ip| match (ip, q.qtype) {
                (IpAddr::V4(a), TYPE_A) => Some(Record {
                    name: name.clone(),
                    rtype: TYPE_A,
                    class: 1,
                    ttl: HOSTS_TTL,
                    data: RData::A(a),
                }),
                (IpAddr::V6(a), TYPE_AAAA) => Some(Record {
                    name: name.clone(),
                    rtype: TYPE_AAAA,
                    class: 1,
                    ttl: HOSTS_TTL,
                    data: RData::Aaaa(a),
                }),
                _ => None,
            })
            .collect();
        if purpose == Purpose::App {
            let mut mapping = self.mapping.lock().unwrap();
            for r in &answers {
                match r.data {
                    RData::A(a) => mapping.record(IpAddr::V4(a), &q.name),
                    RData::Aaaa(a) => mapping.record(IpAddr::V6(a), &q.name),
                    _ => {}
                }
            }
        }
        message::response_for(&msg, 0, answers).serialize()
    }

    /// 应用目标与节点各用自己的本机偏好返回双栈候选，供拨号路径顺序尝试。
    async fn resolve_name(&self, host: &str, purpose: Purpose) -> io::Result<Vec<IpAddr>> {
        let host = oryn_config::normalize_domain(host);
        let policy = if purpose == Purpose::ProxyServer {
            1 | (u8::from(self.proxy_prefer_ipv6.load(Ordering::Relaxed)) << 1)
        } else {
            self.target_ip_policy.load(Ordering::Relaxed)
        };
        if let Ok(ip) = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            if purpose == Purpose::DirectTarget && ip.is_ipv6() && policy & 1 == 0 {
                return Err(io::Error::other("IPv6 destinations are disabled"));
            }
            return Ok(vec![ip]);
        }
        let cache_key = format!(
            "{}:{policy}:{host}",
            if purpose == Purpose::ProxyServer {
                "p"
            } else {
                "d"
            }
        );
        if let Some(ips) = self.host_cached(&cache_key) {
            return Ok(ips);
        }
        // 返回地址与失败原因（SERVFAIL、超时等；NOERROR / NXDOMAIN 不算失败）。
        let lookup = |qtype| {
            let host = &host;
            async move {
                let query = wire::build_query(self.alloc_id(), host, qtype);
                let q = wire::parse_question(&query).expect("自己构造的查询");
                let (resp, _) = Box::pin(self.lookup(&query, &q, purpose, None, 0)).await;
                match wire::parse_answer(&resp) {
                    Some(a) if a.rcode == 0 || a.rcode == wire::RCODE_NXDOMAIN => (a.ips, None),
                    Some(a) => (a.ips, Some(format!("rcode {}", a.rcode))),
                    None => (Vec::new(), Some("malformed response".to_string())),
                }
            }
        };
        // 这些地址都由本机直接拨号：物理网络没有 IPv6 时 AAAA 结果只会得到 No route to host。
        let local_ipv6 = self.local_ipv6.load(Ordering::Relaxed)
            && self.network.read().unwrap().ipv6 != Some(false);
        let ((v4, v4_err), (v6, v6_err)) = if policy & 1 != 0 && self.rt().spec.ipv6 && local_ipv6 {
            tokio::join!(lookup(TYPE_A), lookup(TYPE_AAAA))
        } else {
            (lookup(TYPE_A).await, (Vec::new(), None))
        };
        let failure = v4_err.or(v6_err);
        let ips: Vec<_> = if policy & 3 == 3 {
            v6.into_iter().chain(v4).collect()
        } else {
            v4.into_iter().chain(v6).collect()
        };
        if ips.is_empty() {
            let reason = failure.map(|e| format!(": DNS lookup failed ({e})"));
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("cannot resolve {host}{}", reason.unwrap_or_default()),
            ));
        }
        // 只有一个地址族查询失败时结果不完整，不缓存，下次重新查询。
        // 带设置快照的键防止热更新前的在途查询污染新偏好的缓存。
        if failure.is_none() {
            self.host_store(cache_key, ips.clone());
        }
        Ok(ips)
    }

    /// 只用引导 DNS 解析（加密 DNS 服务器自身的域名）。
    async fn bootstrap_resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let key = format!("b:{host}");
        if let Some(ips) = self.host_cached(&key) {
            return Ok(ips);
        }
        let rt = self.rt();
        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {host}"));
        // 本机没有 IPv6 时不查 AAAA（与本机拨号用的解析一致）。
        let qtypes: &[u16] = if self.local_ipv6.load(Ordering::Relaxed) {
            &[TYPE_A, TYPE_AAAA]
        } else {
            &[TYPE_A]
        };
        for &qtype in qtypes {
            for server in &rt.spec.bootstrap {
                let query = wire::build_query(self.alloc_id(), host, qtype);
                let Some(ip) = server.host_ip() else { continue };
                // 引导服务器必然是 IP，复用连接（DoT / DoH / DoQ 不必每次重新握手）。
                let client_key = format!("{}|DIRECT", server.raw);
                let cached = self.clients.lock().unwrap().get(&client_key).cloned();
                let client = match cached {
                    Some(c) => c,
                    None => self.client_at(client_key, server, Via::Direct, ip, &rt),
                };
                match client.exchange(&query).await {
                    Ok(resp) => {
                        match wire::parse_answer(&resp) {
                            Some(a) if !a.ips.is_empty() => {
                                self.host_store(key, a.ips.clone());
                                return Ok(a.ips);
                            }
                            // NOERROR / NXDOMAIN 是确定的「该类型没有记录」，换下一种类型；
                            // SERVFAIL 等错误码或无法解析的应答换下一台引导服务器。
                            Some(a) if a.rcode == 0 || a.rcode == 3 => break,
                            _ => {
                                last = io::Error::other(format!(
                                    "bootstrap {} returned an error for {host}",
                                    server.raw
                                ))
                            }
                        }
                    }
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    fn host_cached(&self, key: &str) -> Option<Vec<IpAddr>> {
        let cache = self.host_cache.lock().unwrap();
        cache
            .get(key)
            .filter(|(_, at)| at.elapsed() < HOST_CACHE_TTL)
            .map(|(ips, _)| ips.clone())
    }

    fn host_store(&self, key: String, ips: Vec<IpAddr>) {
        let mut cache = self.host_cache.lock().unwrap();
        if cache.len() >= MAX_HOST_CACHE && !cache.contains_key(&key) {
            // 先清过期条目，仍满时只淘汰最旧的一条，不整表清空。
            cache.retain(|_, (_, at)| at.elapsed() < HOST_CACHE_TTL);
            if cache.len() >= MAX_HOST_CACHE {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest);
                }
            }
        }
        cache.insert(key, (ips, Instant::now()));
    }

    /// 解析代理服务器的域名。
    pub async fn resolve_proxy_server(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.resolve_name(host, Purpose::ProxyServer).await
    }

    /// 解析 DIRECT 连接的目标域名（完整流程）。
    pub async fn resolve_direct_target(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.resolve_name(host, Purpose::DirectTarget).await
    }
}

impl Drop for DnsEngine {
    fn drop(&mut self) {
        self.fakeip.get_mut().unwrap().save_if_due(true);
    }
}

/// 供出站解析代理服务器域名。
pub struct ProxyServerResolver(pub Arc<DnsEngine>);

#[async_trait]
impl Resolver for ProxyServerResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.0.resolve_proxy_server(host).await
    }
}

/// 供 DIRECT 出站解析目标域名。
pub struct DirectTargetResolver(pub Arc<DnsEngine>);

#[async_trait]
impl Resolver for DirectTargetResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.0.resolve_direct_target(host).await
    }
}

fn empty_response(query: &[u8], q: &wire::Question) -> Vec<u8> {
    match Message::parse(query) {
        Some(m) => message::response_for(&m, 0, Vec::new()).serialize(),
        None => wire::build_error(query, Some(q.end), 0),
    }
}

fn reject_response(query: &[u8], q: &wire::Question, kind: RejectResponse) -> Vec<u8> {
    let rcode = match kind {
        RejectResponse::Refused => wire::RCODE_REFUSED,
        RejectResponse::NxDomain => wire::RCODE_NXDOMAIN,
    };
    wire::build_error(query, Some(q.end), rcode)
}

/// 去除被屏蔽的 IP，以及服务器参数 `disable-ipv4` / `disable-ipv6` 对应的记录。
fn post_process(resp: Vec<u8>, server: &ServerSpec, blocked: &[IpCidr]) -> Vec<u8> {
    if blocked.is_empty() && !server.disable_ipv4 && !server.disable_ipv6 {
        return resp;
    }
    let Some(mut m) = Message::parse(&resp) else {
        return resp;
    };
    let changed = m.retain_answers(|r| match r.data {
        RData::A(a) => !server.disable_ipv4 && !blocked.iter().any(|c| c.contains(IpAddr::V4(a))),
        RData::Aaaa(a) => {
            !server.disable_ipv6 && !blocked.iter().any(|c| c.contains(IpAddr::V6(a)))
        }
        _ => true,
    });
    if changed {
        m.serialize()
    } else {
        resp
    }
}

#[cfg(test)]
mod tests;
