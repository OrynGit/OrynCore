//! 策略组健康检查：url-test / fallback / load-balance 定期测试成员延迟。

use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oryn_config::TargetAddr;
use oryn_http::{probe_unified, OutboundConnector, Url};
use oryn_outbound::{resolve, Outbound, PickMeta};
use oryn_router::Network;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::context::RuntimeState;

/// 启动后等待一会儿再做第一次检查，让 DNS 等先就绪。
const INITIAL_DELAY: Duration = Duration::from_secs(1);

/// 同时进行的探测数上限，所有策略组共用。每个探测都是一次完整握手（TLS / QUIC / WireGuard 等），
/// 节点多时不加限制会让 Extension 内存瞬间越过 jetsam 上限（2026-10-03 真机实测 50 MB 被杀）。
static PROBE_LIMIT: Semaphore = Semaphore::const_new(6);

/// 每次调用最多保留六个未回收任务；共享探测预算仍由 PROBE_LIMIT 控制。
const PROBE_TASK_LIMIT: usize = 6;

fn probe_task_limit() -> usize {
    #[cfg(test)]
    {
        scheduling_tests::window()
    }
    #[cfg(not(test))]
    {
        PROBE_TASK_LIMIT
    }
}

pub fn spawn_checks(state: &Rc<RuntimeState>) {
    if state.routing.outbounds.iter().any(|o| {
        o.as_group()
            .is_some_and(|g| g.kind() == oryn_config::GroupKind::Smart)
    }) {
        state.spawn(smart_loop(Rc::downgrade(state)));
    }
    for (i, o) in state.routing.outbounds.iter().enumerate() {
        if o.as_group().is_some_and(|g| g.kind().needs_health_check()) {
            state.spawn(group_loop(Rc::downgrade(state), i));
        }
    }
}

/// 代理集合自带的健康检查：定期测试集合的全部节点，结果写入共享的健康状态，
/// 所有引用这些节点的策略组都能看到（select 组显示延迟，url-test 等据此选择）。
pub fn spawn_provider_checks(state: &Rc<RuntimeState>) {
    for (i, p) in state.config.proxy_providers.iter().enumerate() {
        if p.health.is_some() && !p.members.is_empty() {
            state.spawn(provider_loop(Rc::downgrade(state), i));
        }
    }
}

async fn provider_loop(state: Weak<RuntimeState>, index: usize) {
    tokio::time::sleep(INITIAL_DELAY).await;
    let mut first = true;
    loop {
        let Some(st) = state.upgrade() else { return };
        let Some(provider) = st.config.proxy_providers.get(index) else {
            return;
        };
        let Some(spec) = provider.health.clone() else {
            return;
        };
        let members: Vec<Arc<dyn Outbound>> = provider
            .members
            .iter()
            .filter_map(|&m| st.routing.outbounds.get(m).cloned())
            .collect();
        // lazy：引用这些节点的策略组近期都没有被使用时跳过（首次除外）
        let tags: Vec<&str> = members.iter().map(|m| m.tag()).collect();
        let used = st.routing.outbounds.iter().any(|o| {
            o.as_group().is_some_and(|g| {
                g.idle_secs().is_some_and(|s| s < spec.interval_secs)
                    && g.members().iter().any(|m| tags.contains(&m.tag()))
            })
        });
        if first || !spec.lazy || used {
            test_members(&st, members, &spec).await;
        }
        drop(st);
        first = false;
        tokio::time::sleep(Duration::from_secs(spec.interval_secs)).await;
    }
}

async fn group_loop(state: Weak<RuntimeState>, index: usize) {
    tokio::time::sleep(INITIAL_DELAY).await;
    let mut first = true;
    loop {
        let Some(st) = state.upgrade() else { return };
        let group = st.routing.outbounds[index].clone();
        let Some(g) = group.as_group() else { return };
        let spec = g.health_spec().clone();
        // lazy：近期没有被使用的策略组跳过检查（首次除外）
        let used = g.idle_secs().is_some_and(|s| s < spec.interval_secs);
        if first || !spec.lazy || used {
            let before = g.status().now;
            test_group(&st, &group).await;
            let after = g.status().now;
            if before.is_some() && after.is_some() && before != after {
                crate::events::push(
                    "policy_group",
                    format!("{} switched", group.tag()),
                    format!(
                        "{} → {}",
                        before.unwrap_or_default(),
                        after.unwrap_or_default()
                    ),
                );
            }
        }
        drop(st);
        first = false;
        tokio::time::sleep(Duration::from_secs(spec.interval_secs)).await;
    }
}

/// 并发测试策略组的所有成员，结果写入共享的健康状态。
pub async fn test_group(state: &RuntimeState, group: &Arc<dyn Outbound>) {
    test_group_member(state, group, None, None).await;
}

/// 手动延迟测试超时的允许范围（毫秒）。
const MANUAL_TIMEOUT_MS: std::ops::RangeInclusive<u64> = 500..=30_000;

/// 把 App 传来的手动测试超时限制在允许范围内。
pub fn clamp_manual_timeout(ms: u64) -> Duration {
    Duration::from_millis(ms.clamp(*MANUAL_TIMEOUT_MS.start(), *MANUAL_TIMEOUT_MS.end()))
}

/// 只测试策略组中名为 `only` 的成员（`None` 为全部成员）；使用该组的探测地址，
/// 超时取 `timeout`（手动测试），缺省时用该组的健康检查超时。
pub async fn test_group_member(
    state: &RuntimeState,
    group: &Arc<dyn Outbound>,
    only: Option<&str>,
    timeout: Option<Duration>,
) {
    let Some(g) = group.as_group() else { return };
    let mut spec = g.health_spec().clone();
    if let Some(timeout) = timeout {
        spec.timeout_ms = timeout.as_millis() as u64;
    }
    let members = g
        .members()
        .iter()
        .filter(|m| only.is_none_or(|name| m.tag() == name))
        .cloned()
        .collect();
    test_members(state, members, &spec).await;
}

async fn test_members(
    state: &RuntimeState,
    members: Vec<Arc<dyn Outbound>>,
    spec: &oryn_config::HealthSpec,
) {
    let target = match Url::parse(&spec.url) {
        Ok(u) => TargetAddr::from_host(&u.host, u.port),
        Err(_) => return,
    };
    let mut set = JoinSet::new();
    for member in members {
        if member.is_reject() {
            continue;
        }
        if set.len() >= probe_task_limit() {
            set.join_next().await;
        }
        let health = state.health.clone();
        let url = spec.url.clone();
        let target = target.clone();
        let timeout = Duration::from_millis(spec.timeout_ms);
        set.spawn_local(async move {
            // 超时从拿到名额后才开始计，排队时间不算进延迟
            let Ok(_permit) = PROBE_LIMIT.acquire().await else {
                return;
            };
            let meta = PickMeta {
                source: None,
                target: &target,
                network: Network::Tcp,
            };
            let delay = match resolve(&member, &meta) {
                Some(r) => probe_unified(&OutboundConnector(r.leaf), &url, timeout, false)
                    .await
                    .ok()
                    .map(|d| d.as_millis().min(u32::MAX as u128) as u32),
                None => None,
            };
            health.record(member.tag(), delay);
        });
        #[cfg(test)]
        scheduling_tests::observe(set.len());
    }
    while set.join_next().await.is_some() {}
}

/// 最近一次「经代理」探测的结果；只有一份，覆盖写入。
#[derive(Clone, Copy, Default)]
struct ProxyProbe {
    delay_ms: Option<u32>,
    checked_at_ms: Option<u64>,
    running: bool,
    started_at_ms: u64,
}

static PROXY_PROBE: std::sync::Mutex<ProxyProbe> = std::sync::Mutex::new(ProxyProbe {
    delay_ms: None,
    checked_at_ms: None,
    running: false,
    started_at_ms: 0,
});

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 开始一次「经代理」探测：测试地址按分流规则选出口，与普通流量走同一条路。
/// 已有探测在进行时返回 false，不重复发起；超过最长超时仍未结束的（例如任务随重载被取消）视为已结束。
pub fn begin_proxy_probe() -> bool {
    let mut probe = PROXY_PROBE.lock().unwrap();
    let now = unix_ms();
    let stale = now.saturating_sub(probe.started_at_ms) > MANUAL_TIMEOUT_MS.end() + 5_000;
    if probe.running && !stale {
        return false;
    }
    probe.running = true;
    probe.started_at_ms = now;
    true
}

/// 执行 [`begin_proxy_probe`] 登记的探测并写回结果。
pub async fn run_proxy_probe(routing: Arc<oryn_dns::Routing>, url: String, timeout: Duration) {
    let connector = crate::download::RulesConnector(routing);
    let delay = match PROBE_LIMIT.acquire().await {
        Ok(_permit) => probe_unified(&connector, &url, timeout, false)
            .await
            .ok()
            .map(|d| d.as_millis().min(u32::MAX as u128) as u32),
        Err(_) => None,
    };
    *PROXY_PROBE.lock().unwrap() = ProxyProbe {
        delay_ms: delay,
        checked_at_ms: Some(unix_ms()),
        running: false,
        started_at_ms: 0,
    };
}

/// `proxy_probe` 命令的返回：`delay` 为毫秒（null 表示失败或未测），`checked_at` 为 Unix 毫秒。
pub fn proxy_probe_status() -> serde_json::Value {
    let mut probe = *PROXY_PROBE.lock().unwrap();
    probe.running &= unix_ms().saturating_sub(probe.started_at_ms) <= MANUAL_TIMEOUT_MS.end() + 5_000;
    serde_json::json!({
        "delay": probe.delay_ms,
        "checked_at": probe.checked_at_ms,
        "testing": probe.running,
    })
}

/// UDP 延迟测试地址的默认值，格式 `域名@DNS 服务器[:端口]`。
pub const DEFAULT_UDP_TEST: &str = "apple.com@1.1.1.1";

/// 解析 `域名@DNS 服务器[:端口]`，返回查询域名与服务器地址。
pub fn parse_udp_test(address: &str) -> Option<(String, TargetAddr)> {
    let (domain, server) = address.split_once('@')?;
    let (domain, server) = (domain.trim(), server.trim());
    if domain.is_empty() || server.is_empty() {
        return None;
    }
    let target = match server.parse::<std::net::SocketAddr>() {
        Ok(addr) => TargetAddr::from(addr),
        Err(_) => match server.parse::<std::net::IpAddr>() {
            Ok(ip) => TargetAddr::from(std::net::SocketAddr::new(ip, 53)),
            Err(_) => match server.rsplit_once(':') {
                Some((host, port)) => TargetAddr::from_host(host, port.parse().ok()?),
                None => TargetAddr::from_host(server, 53),
            },
        },
    };
    Some((domain.to_string(), target))
}

/// 并发做 UDP 延迟测试：经每个成员发一次 DNS 查询并计时，结果只用于展示。
pub async fn test_group_udp(
    state: &RuntimeState,
    group: &Arc<dyn Outbound>,
    address: &str,
    only: Option<&str>,
    timeout: Option<Duration>,
) {
    let Some(g) = group.as_group() else { return };
    let timeout = timeout.unwrap_or_else(|| Duration::from_millis(g.health_spec().timeout_ms));
    let Some((domain, target)) = parse_udp_test(address) else {
        return;
    };
    let mut set = JoinSet::new();
    for member in g.members().to_vec() {
        if member.is_reject() || only.is_some_and(|name| member.tag() != name) {
            continue;
        }
        if set.len() >= probe_task_limit() {
            set.join_next().await;
        }
        let health = state.health.clone();
        let (domain, target) = (domain.clone(), target.clone());
        set.spawn_local(async move {
            let Ok(_permit) = PROBE_LIMIT.acquire().await else {
                return;
            };
            let meta = PickMeta {
                source: None,
                target: &target,
                network: Network::Udp,
            };
            let delay = match resolve(&member, &meta) {
                Some(r) => udp_probe(r.leaf, &domain, &target, timeout).await,
                None => None,
            };
            health.record_udp(member.tag(), delay);
        });
        #[cfg(test)]
        scheduling_tests::observe(set.len());
    }
    while set.join_next().await.is_some() {}
}

/// 绑定 UDP、发一个 A 查询并等待同一事务号的应答；连接建立时间计入延迟。
async fn udp_probe(
    leaf: Arc<dyn Outbound>,
    domain: &str,
    target: &TargetAddr,
    timeout: Duration,
) -> Option<u32> {
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos())
        & 0xffff) as u16;
    let query = oryn_dns::message::Message {
        id,
        flags: 0x0100,
        questions: vec![oryn_dns::message::Question {
            name: domain.to_string(),
            qtype: 1,
            qclass: 1,
        }],
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
    }
    .serialize();
    let started = Instant::now();
    let run = async {
        let pc = leaf.bind_udp(target).await.ok()?;
        pc.send_to(&query, target).await.ok()?;
        let mut buf = [0_u8; 1500];
        loop {
            let (n, _) = pc.recv_from(&mut buf).await.ok()?;
            if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                return Some(());
            }
        }
    };
    tokio::time::timeout(timeout, run).await.ok().flatten()?;
    Some(started.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

/// 一个 Engine 共用每 5 秒一次的探针预算，最多 12 次/分钟、并发 1；同一循环负责定期保存学习状态。
async fn smart_loop(state: Weak<RuntimeState>) {
    let mut round = 0usize;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let Some(st) = state.upgrade() else {
            return;
        };
        let groups: Vec<_> = st
            .routing
            .outbounds
            .iter()
            .filter(|o| {
                o.as_group()
                    .is_some_and(|g| g.kind() == oryn_config::GroupKind::Smart)
            })
            .cloned()
            .collect();
        if groups.is_empty() {
            return;
        }
        // 每分钟把有新证据的 Smart 学习状态落盘一次（热路径不碰磁盘）。
        if round % 12 == 11 {
            for group in groups.iter().filter_map(|g| g.as_group()) {
                group.smart_save();
            }
        }
        let selected = groups[round % groups.len()].clone();
        let path = round / groups.len();
        round = round.wrapping_add(1);
        drop(st);
        if let Some(group) = selected.as_group() {
            group.smart_probe(path).await;
        }
    }
}

#[cfg(test)]
#[path = "health_scheduling_tests.rs"]
mod scheduling_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_test_address_forms() {
        let (domain, target) = parse_udp_test("apple.com@1.1.1.1").unwrap();
        assert_eq!(domain, "apple.com");
        assert_eq!(target.to_string(), "1.1.1.1:53");
        let (_, target) = parse_udp_test("a.com@dns.example:5353").unwrap();
        assert_eq!(target.to_string(), "dns.example:5353");
        assert!(parse_udp_test("apple.com").is_none());
        assert!(parse_udp_test("@1.1.1.1").is_none());
    }

    #[test]
    fn manual_timeout_is_clamped() {
        assert_eq!(clamp_manual_timeout(3000), Duration::from_millis(3000));
        assert_eq!(clamp_manual_timeout(10), Duration::from_millis(500));
        assert_eq!(clamp_manual_timeout(120_000), Duration::from_secs(30));
    }
}
