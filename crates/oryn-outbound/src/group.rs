//! 策略组：select / url-test / fallback / load-balance。
//!
//! 策略组本身也是一个 Outbound。连接时先用 [`resolve`] 沿策略组一路选出最终的叶子出站，
//! 得到完整链路（如 `Proxy → Auto → Tokyo`）后再由叶子出站建立连接。

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use oryn_config::{GroupKind, HealthSpec, LbStrategy, TargetAddr};
use oryn_router::Network;

use crate::{BoxStream, Outbound, PacketConn};

/// 选择成员时参考的连接信息。
#[derive(Debug, Clone, Copy)]
pub struct PickMeta<'a> {
    pub source: Option<SocketAddr>,
    pub target: &'a TargetAddr,
    pub network: Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    /// 最近一次检查的延迟；`None` 表示失败。
    pub delay_ms: Option<u32>,
    pub checked_at: SystemTime,
}

impl Health {
    pub fn alive(&self) -> bool {
        self.delay_ms.is_some()
    }
}

/// 各出站最近一次健康检查的结果，按名称索引，同一配置内的策略组共享。
#[derive(Debug, Default)]
pub struct HealthStore {
    pub(crate) smart: Arc<crate::smart::Registry>,
    map: Mutex<HashMap<String, Health>>,
    /// 手动 UDP 延迟测试的结果；只用于展示，不参与 url-test / fallback 选择。
    udp: Mutex<HashMap<String, Health>>,
}

impl HealthStore {
    pub fn inherit_smart(previous: &Self) -> Self {
        Self {
            smart: previous.smart.clone(),
            ..Self::default()
        }
    }
    pub fn get(&self, name: &str) -> Option<Health> {
        self.map.lock().unwrap().get(name).copied()
    }

    pub fn get_udp(&self, name: &str) -> Option<Health> {
        self.udp.lock().unwrap().get(name).copied()
    }

    pub fn record_udp(&self, name: &str, delay_ms: Option<u32>) {
        self.udp.lock().unwrap().insert(
            name.to_string(),
            Health {
                delay_ms,
                checked_at: SystemTime::now(),
            },
        );
    }

    pub fn record(&self, name: &str, delay_ms: Option<u32>) {
        self.map.lock().unwrap().insert(
            name.to_string(),
            Health {
                delay_ms,
                checked_at: SystemTime::now(),
            },
        );
    }

    /// 增量重载后裁剪已移除节点的陈旧测速记录。
    pub fn retain_names(&self, keep: &HashSet<&str>) {
        self.map.lock().unwrap().retain(|k, _| keep.contains(k.as_str()));
        self.udp.lock().unwrap().retain(|k, _| keep.contains(k.as_str()));
    }
}

const STICKY_TTL: Duration = Duration::from_secs(600);
const MAX_STICKY: usize = 4096;

pub struct GroupOutbound {
    pub(crate) smart: Option<Arc<crate::smart::Smart>>,
    name: String,
    kind: GroupKind,
    members: Vec<Arc<dyn Outbound>>,
    health_spec: HealthSpec,
    disable_udp: bool,
    store: Arc<HealthStore>,
    /// select 的选择；url-test 的当前成员。
    selected: Mutex<usize>,
    rr: AtomicUsize,
    sticky: Mutex<HashMap<(IpAddr, String), (usize, Instant)>>,
    /// 最近一次被使用的时间（Unix 秒），供 `lazy` 健康检查判断。
    last_used: AtomicU64,
}

/// 供界面展示的策略组状态。
#[derive(Debug, Clone)]
pub struct GroupStatus {
    pub name: String,
    pub kind: &'static str,
    /// select / url-test / fallback 的当前成员。
    pub now: Option<String>,
    pub members: Vec<MemberStatus>,
    pub test_url: String,
}

#[derive(Debug, Clone)]
pub struct MemberStatus {
    pub name: String,
    pub kind: &'static str,
    pub delay_ms: Option<u32>,
    pub tested: bool,
    pub udp_delay_ms: Option<u32>,
    pub udp_tested: bool,
    /// 最近一次 TCP / UDP 延迟测试完成的时间（Unix 毫秒）；界面据此判断手动测试是否已出结果。
    pub checked_at_ms: Option<u64>,
    pub udp_checked_at_ms: Option<u64>,
}

fn unix_ms(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fnv(s: &str) -> u64 {
    let mut h = Fnv(0xcbf29ce484222325);
    std::fmt::Write::write_str(&mut h, s).unwrap();
    h.0
}

/// 边格式化边做 FNV-1a，结果与先 `format!` 再 `fnv` 相同，不分配字符串。
struct Fnv(u64);

impl std::fmt::Write for Fnv {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        for b in s.as_bytes() {
            self.0 ^= *b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
        Ok(())
    }
}

/// Jump consistent hash（Lamping & Veach）。
fn jump_hash(mut key: u64, buckets: usize) -> usize {
    let (mut b, mut j): (i64, i64) = (-1, 0);
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b + 1) as f64 * ((1u64 << 31) as f64 / ((key >> 33) + 1) as f64)) as i64;
    }
    b.max(0) as usize
}

fn host_key(t: &TargetAddr) -> String {
    match t {
        TargetAddr::Domain(d, _) => d.clone(),
        TargetAddr::Ip(a) => a.ip().to_string(),
    }
}

impl GroupOutbound {
    pub fn new(
        name: String,
        kind: GroupKind,
        members: Vec<Arc<dyn Outbound>>,
        health_spec: HealthSpec,
        disable_udp: bool,
        store: Arc<HealthStore>,
        selected: Option<&str>,
    ) -> GroupOutbound {
        let initial = selected
            .and_then(|s| members.iter().position(|m| m.tag() == s))
            .unwrap_or(0);
        GroupOutbound {
            smart: None,
            name,
            kind,
            members,
            health_spec,
            disable_udp,
            store,
            selected: Mutex::new(initial),
            rr: AtomicUsize::new(0),
            sticky: Mutex::new(HashMap::new()),
            last_used: AtomicU64::new(0),
        }
    }

    pub fn smart_save(&self) {
        if let Some(s) = &self.smart {
            s.save();
        }
    }

    pub async fn smart_probe(&self, index: usize) {
        if let Some(s) = &self.smart {
            s.probe(index).await;
        }
    }

    pub fn smart_explain(
        &self,
        target: &TargetAddr,
        network: Network,
    ) -> Option<serde_json::Value> {
        self.smart.as_ref().map(|s| s.explain(target, network))
    }

    /// Smart 组的使用状态；非 Smart 组为 `None`。
    pub fn smart_usage(&self) -> Option<serde_json::Value> {
        self.smart.as_ref().map(|s| s.usage())
    }

    pub fn kind(&self) -> GroupKind {
        self.kind
    }

    pub fn members(&self) -> &[Arc<dyn Outbound>] {
        &self.members
    }

    pub fn health_spec(&self) -> &HealthSpec {
        &self.health_spec
    }

    pub fn health_store(&self) -> &Arc<HealthStore> {
        &self.store
    }

    pub fn current_member_name(&self) -> Option<String> {
        if self.members.is_empty() {
            return None;
        }
        match self.kind {
            GroupKind::LoadBalance(_) | GroupKind::Smart => None,
            _ => Some(self.members[self.current_index()].tag().to_string()),
        }
    }

    /// 最近一次被使用距今的秒数；从未使用返回 `None`。
    pub fn idle_secs(&self) -> Option<u64> {
        match self.last_used.load(Ordering::Relaxed) {
            0 => None,
            t => Some(now_secs().saturating_sub(t)),
        }
    }

    /// 选择 select 策略组的成员。
    pub fn select(&self, member: &str) -> bool {
        if self.kind != GroupKind::Select {
            return false;
        }
        match self.members.iter().position(|m| m.tag() == member) {
            Some(i) => {
                *self.selected.lock().unwrap() = i;
                true
            }
            None => false,
        }
    }

    fn health(&self, i: usize) -> Option<Health> {
        let m = &self.members[i];
        match m.kind() {
            "direct" => Some(self.store.get(m.tag()).unwrap_or(Health {
                delay_ms: Some(0),
                checked_at: SystemTime::now(),
            })),
            "reject" => Some(Health {
                delay_ms: None,
                checked_at: SystemTime::now(),
            }),
            _ => self.store.get(m.tag()),
        }
    }

    /// 未检查过的成员视为可用。
    fn is_alive(&self, i: usize) -> bool {
        self.health(i).is_none_or(|h| h.alive())
    }

    fn alive_members(&self) -> Vec<usize> {
        let alive: Vec<usize> = (0..self.members.len())
            .filter(|&i| self.is_alive(i))
            .collect();
        if alive.is_empty() {
            (0..self.members.len()).collect()
        } else {
            alive
        }
    }

    fn current_index(&self) -> usize {
        match self.kind {
            GroupKind::Select => *self.selected.lock().unwrap(),
            GroupKind::UrlTest { tolerance_ms } => {
                let mut sel = self.selected.lock().unwrap();
                let delay = |i: usize| self.health(i).and_then(|h| h.delay_ms);
                let best = (0..self.members.len())
                    .filter_map(|i| delay(i).map(|d| (d, i)))
                    .min();
                if let Some((best_delay, best)) = best {
                    match delay(*sel) {
                        Some(cur) if cur <= best_delay.saturating_add(tolerance_ms) => {}
                        _ => *sel = best,
                    }
                }
                *sel
            }
            GroupKind::Fallback => (0..self.members.len())
                .find(|&i| self.is_alive(i))
                .unwrap_or(0),
            GroupKind::LoadBalance(_) | GroupKind::Smart => 0,
        }
    }

    /// 为一次连接选择成员。返回 `None` 表示拒绝（策略组禁用了 UDP）。
    pub fn pick(&self, meta: &PickMeta) -> Option<Arc<dyn Outbound>> {
        self.last_used.store(now_secs(), Ordering::Relaxed);
        if self.disable_udp && meta.network == Network::Udp {
            return None;
        }
        // 空策略组（应由配置层拒绝）不能让下面的取下标 panic，按拒绝处理
        if self.members.is_empty() {
            return None;
        }
        if self.kind == GroupKind::Smart {
            return self.smart.as_ref().and_then(|smart| smart.pick(meta));
        }
        let i = match self.kind {
            GroupKind::LoadBalance(strategy) => {
                let alive = self.alive_members();
                match strategy {
                    LbStrategy::RoundRobin => {
                        alive[self.rr.fetch_add(1, Ordering::Relaxed) % alive.len()]
                    }
                    LbStrategy::ConsistentHashing => {
                        alive[jump_hash(fnv(&host_key(meta.target)), alive.len())]
                    }
                    LbStrategy::StickySessions => {
                        let key = (
                            meta.source
                                .map(|s| s.ip())
                                .unwrap_or(IpAddr::from([0, 0, 0, 0])),
                            host_key(meta.target),
                        );
                        let mut sticky = self.sticky.lock().unwrap();
                        let now = Instant::now();
                        match sticky.get_mut(&key) {
                            Some((i, at))
                                if now.duration_since(*at) < STICKY_TTL && alive.contains(i) =>
                            {
                                // 命中即刷新：持续使用的会话不会在 TTL 到期时被重新分配
                                *at = now;
                                *i
                            }
                            _ => {
                                if sticky.len() >= MAX_STICKY {
                                    sticky
                                        .retain(|_, (_, at)| now.duration_since(*at) < STICKY_TTL);
                                    // 仍然满：只淘汰最久未用的一个，而不是清空让全部会话集体换节点
                                    if sticky.len() >= MAX_STICKY {
                                        if let Some(oldest) = sticky
                                            .iter()
                                            .min_by_key(|(_, (_, at))| *at)
                                            .map(|(k, _)| k.clone())
                                        {
                                            sticky.remove(&oldest);
                                        }
                                    }
                                }
                                let seed = {
                                    let mut h = Fnv(0xcbf29ce484222325);
                                    let _ = std::fmt::Write::write_fmt(
                                        &mut h,
                                        format_args!("{}|{}", key.0, key.1),
                                    );
                                    h.0
                                };
                                let i = alive[jump_hash(seed, alive.len())];
                                sticky.insert(key, (i, now));
                                i
                            }
                        }
                    }
                }
            }
            _ => self.current_index(),
        };
        Some(self.members[i].clone())
    }

    pub fn status(&self) -> GroupStatus {
        let now = match self.kind {
            GroupKind::LoadBalance(_) | GroupKind::Smart => None,
            _ => Some(self.members[self.current_index()].tag().to_string()),
        };
        GroupStatus {
            name: self.name.clone(),
            kind: self.kind.type_name(),
            now,
            members: (0..self.members.len())
                .map(|i| {
                    let h = self.health(i);
                    let udp = self.store.get_udp(self.members[i].tag());
                    let recorded = self.store.get(self.members[i].tag());
                    MemberStatus {
                        name: self.members[i].tag().to_string(),
                        kind: self.members[i].kind(),
                        delay_ms: h.and_then(|h| h.delay_ms),
                        tested: h.is_some() && recorded.is_some(),
                        udp_delay_ms: udp.and_then(|u| u.delay_ms),
                        udp_tested: udp.is_some(),
                        checked_at_ms: recorded.map(|r| unix_ms(r.checked_at)),
                        udp_checked_at_ms: udp.map(|u| unix_ms(u.checked_at)),
                    }
                })
                .collect(),
            test_url: self.health_spec.url.clone(),
        }
    }
}

/// 沿策略组选出的最终出站与完整链路。
pub struct Resolved {
    pub leaf: Arc<dyn Outbound>,
    /// 从起点到叶子的名称，含两端。
    pub chain: Vec<String>,
}

const MAX_DEPTH: usize = 16;

/// 从 `start` 出发，逐级选择策略组成员直到叶子出站。返回 `None` 表示被拒绝。
pub fn resolve(start: &Arc<dyn Outbound>, meta: &PickMeta) -> Option<Resolved> {
    let mut cur = start.clone();
    let mut chain = Vec::new();
    for _ in 0..MAX_DEPTH {
        let next = match cur.as_group() {
            Some(g) => {
                chain.push(cur.tag().to_string());
                g.pick(meta)?
            }
            None => {
                chain.push(cur.tag().to_string());
                return Some(Resolved { leaf: cur, chain });
            }
        };
        cur = next;
    }
    log::warn!(
        "policy group nesting exceeds {MAX_DEPTH} levels starting at {}; rejecting",
        start.tag()
    );
    None
}

fn rejected() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, "rejected by policy group")
}

#[async_trait]
impl Outbound for GroupOutbound {
    fn tag(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        self.kind.type_name()
    }

    fn session_control(&self) -> Option<Arc<dyn crate::SessionControl>> {
        self.smart
            .as_ref()
            .map(|s| s.clone() as Arc<dyn crate::SessionControl>)
    }

    fn as_group(&self) -> Option<&GroupOutbound> {
        Some(self)
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let meta = PickMeta {
            source: None,
            target,
            network: Network::Tcp,
        };
        let member = self.pick(&meta).ok_or_else(rejected)?;
        member.connect_tcp(target).await
    }

    async fn bind_udp(&self, first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        let meta = PickMeta {
            source: None,
            target: first_target,
            network: Network::Udp,
        };
        let member = self.pick(&meta).ok_or_else(rejected)?;
        member.bind_udp(first_target).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Leaf(&'static str, &'static str);

    #[async_trait]
    impl Outbound for Leaf {
        fn tag(&self) -> &str {
            self.0
        }
        fn kind(&self) -> &'static str {
            self.1
        }
        async fn connect_tcp(&self, _t: &TargetAddr) -> io::Result<BoxStream> {
            Err(io::ErrorKind::Other.into())
        }
        async fn bind_udp(&self, _t: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
            Err(io::ErrorKind::Other.into())
        }
    }

    fn leaves() -> Vec<Arc<dyn Outbound>> {
        vec![
            Arc::new(Leaf("A", "socks5")),
            Arc::new(Leaf("B", "socks5")),
            Arc::new(Leaf("C", "socks5")),
        ]
    }

    fn group(kind: GroupKind, store: &Arc<HealthStore>, selected: Option<&str>) -> GroupOutbound {
        GroupOutbound::new(
            "G".into(),
            kind,
            leaves(),
            HealthSpec::default(),
            false,
            store.clone(),
            selected,
        )
    }

    fn meta<'a>(t: &'a TargetAddr) -> PickMeta<'a> {
        PickMeta {
            source: Some("10.0.0.2:1234".parse().unwrap()),
            target: t,
            network: Network::Tcp,
        }
    }

    #[test]
    fn select_and_url_test() {
        let store = Arc::new(HealthStore::default());
        let t = TargetAddr::Domain("a.com".into(), 443);
        let g = group(GroupKind::Select, &store, Some("B"));
        assert_eq!(g.pick(&meta(&t)).unwrap().tag(), "B");
        assert!(g.select("C") && !g.select("Z"));
        assert_eq!(g.pick(&meta(&t)).unwrap().tag(), "C");

        let g = group(GroupKind::UrlTest { tolerance_ms: 50 }, &store, None);
        store.record("A", Some(300));
        store.record("B", Some(100));
        store.record("C", None);
        assert_eq!(g.pick(&meta(&t)).unwrap().tag(), "B");
        // 差距在容差内不切换
        store.record("A", Some(80));
        assert_eq!(g.pick(&meta(&t)).unwrap().tag(), "B");
        store.record("A", Some(20));
        assert_eq!(g.pick(&meta(&t)).unwrap().tag(), "A");
        assert!(!g.select("B"), "url-test 不能手动选择");
    }

    #[test]
    fn fallback_and_load_balance() {
        let store = Arc::new(HealthStore::default());
        let t = TargetAddr::Domain("a.com".into(), 443);
        let g = group(GroupKind::Fallback, &store, None);
        assert_eq!(g.pick(&meta(&t)).unwrap().tag(), "A", "未检查视为可用");
        store.record("A", None);
        assert_eq!(g.pick(&meta(&t)).unwrap().tag(), "B");

        let g = group(GroupKind::LoadBalance(LbStrategy::RoundRobin), &store, None);
        let picks: Vec<String> = (0..4)
            .map(|_| g.pick(&meta(&t)).unwrap().tag().to_string())
            .collect();
        assert_eq!(picks, ["B", "C", "B", "C"], "跳过不可用的 A");

        let g = group(
            GroupKind::LoadBalance(LbStrategy::ConsistentHashing),
            &store,
            None,
        );
        let first = g.pick(&meta(&t)).unwrap().tag().to_string();
        for _ in 0..5 {
            assert_eq!(g.pick(&meta(&t)).unwrap().tag(), first);
        }
        let spread: std::collections::HashSet<String> = (0..50)
            .map(|i| {
                g.pick(&meta(&TargetAddr::Domain(format!("s{i}.com"), 443)))
                    .unwrap()
                    .tag()
                    .to_string()
            })
            .collect();
        assert_eq!(spread.len(), 2, "不同目标分散到可用成员");

        let g = group(
            GroupKind::LoadBalance(LbStrategy::StickySessions),
            &store,
            None,
        );
        let first = g.pick(&meta(&t)).unwrap().tag().to_string();
        assert_eq!(g.pick(&meta(&t)).unwrap().tag(), first);
    }

    #[test]
    fn resolve_chain_and_udp() {
        let store = Arc::new(HealthStore::default());
        let inner: Arc<dyn Outbound> = Arc::new(group(GroupKind::Select, &store, Some("C")));
        let direct: Arc<dyn Outbound> = Arc::new(Leaf("DIRECT", "direct"));
        let outer: Arc<dyn Outbound> = Arc::new(GroupOutbound::new(
            "Outer".into(),
            GroupKind::Select,
            vec![inner, direct],
            HealthSpec::default(),
            true,
            store,
            None,
        ));
        let t = TargetAddr::Domain("a.com".into(), 443);
        let r = resolve(&outer, &meta(&t)).unwrap();
        assert_eq!(r.chain, ["Outer", "G", "C"]);
        assert_eq!(r.leaf.tag(), "C");
        let udp = PickMeta {
            network: Network::Udp,
            ..meta(&t)
        };
        assert!(resolve(&outer, &udp).is_none(), "disable-udp");
        assert!(jump_hash(12345, 1) == 0 && jump_hash(12345, 10) < 10);
    }
}
