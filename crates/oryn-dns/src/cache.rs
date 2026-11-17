//! 有上限的 DNS 缓存与 IP → 域名映射。

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 按插入顺序淘汰的有界表。
///
/// 单条删除只删哈希表，顺序队列里的旧位置靠插入代号识别为失效、留到出队或整理时丢弃：
/// 原来每次删除都 `retain` 扫描整个队列，缓存命中遇到过期项时是 O(n)。
/// 失效位置超过容量后整体整理一次，队列长度不超过两倍容量，摊还 O(1)。
pub struct BoundedMap<K, V> {
    map: HashMap<K, (V, u64)>,
    order: VecDeque<(K, u64)>,
    capacity: usize,
    next_gen: u64,
}

impl<K: Hash + Eq + Clone, V> BoundedMap<K, V> {
    pub fn new(capacity: usize) -> Self {
        BoundedMap {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
            next_gen: 0,
        }
    }

    pub fn insert(&mut self, k: K, v: V) {
        let _ = self.insert_with_eviction(k, v);
    }

    fn insert_with_eviction(&mut self, k: K, v: V) -> Option<(K, V)> {
        // 已有的键原地替换，保持原来的淘汰位置
        if let Some(slot) = self.map.get_mut(&k) {
            slot.0 = v;
            return None;
        }
        let generation = self.next_gen;
        self.next_gen += 1;
        self.map.insert(k.clone(), (v, generation));
        self.order.push_back((k, generation));
        let evicted = if self.map.len() > self.capacity {
            self.pop_oldest()
        } else {
            None
        };
        self.compact_if_sparse();
        evicted
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        self.map.get(k).map(|(v, _)| v)
    }

    pub fn remove(&mut self, k: &K) {
        if self.map.remove(k).is_some() {
            self.compact_if_sparse();
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    /// 只保留满足条件的项（批量清理），并顺带整理顺序队列。
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        self.map.retain(|k, (v, _)| keep(k, v));
        self.compact();
    }

    fn live(&self, k: &K, generation: u64) -> bool {
        self.map.get(k).is_some_and(|(_, g)| *g == generation)
    }

    fn compact(&mut self) {
        let map = &self.map;
        self.order
            .retain(|(k, g)| map.get(k).is_some_and(|(_, mg)| mg == g));
    }

    fn compact_if_sparse(&mut self) {
        if self.order.len() > self.capacity.saturating_mul(2) {
            self.compact();
        }
    }

    /// Remove and return the oldest entry, if any.
    fn pop_oldest(&mut self) -> Option<(K, V)> {
        while let Some((key, generation)) = self.order.pop_front() {
            if self.live(&key, generation) {
                let (value, _) = self.map.remove(&key)?;
                return Some((key, value));
            }
        }
        None
    }

    /// 按插入顺序从新到旧遍历。
    pub fn iter_newest(&self) -> impl Iterator<Item = (&K, &V)> {
        self.order.iter().rev().filter_map(|(k, g)| {
            self.map
                .get(k)
                .filter(|(_, mg)| mg == g)
                .map(|(v, _)| (k, v))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// 缓存记录的来源，只用于诊断展示。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheSource {
    /// 上游类别：`nameserver`、`group`、`servers`、`bootstrap`、`proxy-server`。
    pub kind: &'static str,
    /// `kind == "group"` 时的上游组名。
    pub group: Option<String>,
    /// 应答服务器的原始写法，如 `tls://dns.example:853`。
    pub server: String,
}

pub struct CacheEntry {
    pub response: Vec<u8>,
    pub expires: Instant,
    /// 写入时（夹紧后）的 TTL 秒数。
    pub ttl: u32,
    pub source: CacheSource,
}

pub struct DnsCache {
    inner: BoundedMap<CacheKey, CacheEntry>,
    bytes: usize,
    /// 最早可能过期时间；提前删除只会让清理提前，不会漏掉过期项。
    next_expiry: Option<Instant>,
}

/// TTL 上下限：避免 0 TTL 导致缓存无效，也避免长期持有过期结果。
const MIN_TTL: u32 = 5;
const MAX_TTL: u32 = 3600;
/// 没有应答记录（NXDOMAIN / 空结果）时的缓存时间。
const NEGATIVE_TTL: u32 = 30;
/// 单条 DNS 响应和整个缓存的硬上限。
///
/// UDP DNS 响应的最大合法长度接近 64 KiB；将单条限制设为 64 KiB 可以避免
/// 异常响应直接占用大量内存。总预算限制在 4 MiB，避免 1024 个大响应把
/// PacketTunnel 推到内存上限。
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_CACHE_BYTES: usize = 4 * 1024 * 1024;

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        DnsCache {
            inner: BoundedMap::new(capacity),
            bytes: 0,
            next_expiry: None,
        }
    }

    pub fn get(&mut self, key: &CacheKey) -> Option<Vec<u8>> {
        let now = Instant::now();
        match self.inner.get(key) {
            Some(e) if e.expires > now => Some(e.response.clone()),
            Some(_) => {
                if let Some(old) = self.inner.get(key).map(|e| e.response.len()) {
                    self.inner.remove(key);
                    self.bytes = self.bytes.saturating_sub(old);
                }
                None
            }
            None => None,
        }
    }

    pub fn put(&mut self, key: CacheKey, response: Vec<u8>, ttl: Option<u32>) {
        self.put_with_source(key, response, ttl, CacheSource::default());
    }

    pub fn put_with_source(
        &mut self,
        key: CacheKey,
        response: Vec<u8>,
        ttl: Option<u32>,
        source: CacheSource,
    ) {
        if response.len() > MAX_RESPONSE_BYTES {
            return;
        }
        // TTL 0 表示应答不应被缓存（常用于动态调度），不夹成 MIN_TTL；同时丢掉旧条目。
        if ttl == Some(0) {
            if let Some(old) = self.inner.get(&key).map(|e| e.response.len()) {
                self.inner.remove(&key);
                self.bytes = self.bytes.saturating_sub(old);
            }
            return;
        }
        let ttl = ttl.map_or(NEGATIVE_TTL, |t| t.clamp(MIN_TTL, MAX_TTL));
        let expires = Instant::now() + Duration::from_secs(ttl as u64);
        // Replace existing values without temporarily double-counting their bytes.
        if let Some(old) = self.inner.get(&key).map(|e| e.response.len()) {
            self.inner.remove(&key);
            self.bytes = self.bytes.saturating_sub(old);
        }
        self.prune_expired(Instant::now());
        self.next_expiry = Some(self.next_expiry.map_or(expires, |next| next.min(expires)));
        if response.len() > MAX_CACHE_BYTES {
            return;
        }
        while self.bytes + response.len() > MAX_CACHE_BYTES {
            let Some((_, old)) = self.inner.pop_oldest() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(old.response.len());
        }
        self.bytes += response.len();
        if let Some((_, old)) = self.inner.insert_with_eviction(
            key,
            CacheEntry {
                response,
                expires,
                ttl,
                source,
            },
        ) {
            self.bytes = self.bytes.saturating_sub(old.response.len());
        }
    }

    fn prune_expired(&mut self, now: Instant) {
        if self.next_expiry.is_none_or(|next| next > now) {
            return;
        }
        let mut next = None;
        let bytes = &mut self.bytes;
        // 一次整理顺序，避免每个过期项都扫描一次整个队列。
        self.inner.retain(|_, entry| {
            if entry.expires <= now {
                *bytes -= entry.response.len();
                false
            } else {
                next = Some(next.map_or(entry.expires, |t: Instant| t.min(entry.expires)));
                true
            }
        });
        self.next_expiry = next;
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// 未过期的记录，从新到旧，最多 `limit` 条。
    pub fn recent(&self, limit: usize) -> Vec<(&CacheKey, &CacheEntry)> {
        let now = Instant::now();
        self.inner
            .iter_newest()
            .filter(|(_, e)| e.expires > now)
            .take(limit)
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        self.inner.clear();
        self.bytes = 0;
        self.next_expiry = None;
    }
}

/// IP → 域名。同一 IP 以最近一次解析为准。
pub struct DomainMapping {
    inner: BoundedMap<IpAddr, String>,
}

impl DomainMapping {
    pub fn new(capacity: usize) -> Self {
        DomainMapping {
            inner: BoundedMap::new(capacity),
        }
    }

    pub fn record(&mut self, ip: IpAddr, domain: &str) {
        // 已存在时 BoundedMap::insert 只更新值，不改变淘汰顺序
        self.inner.insert(ip, domain.to_string());
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<&str> {
        self.inner.get(ip).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: usize) -> CacheKey {
        CacheKey {
            name: format!("{n}.example"),
            qtype: 1,
            qclass: 1,
        }
    }

    #[test]
    fn mixed_expiry_reclaims_bytes_and_preserves_fifo() {
        let mut c = DnsCache::new(4);
        c.put(key(0), vec![0; 100], Some(3600));
        c.put(key(1), vec![1; 200], Some(5));
        c.put(key(2), vec![2; 300], Some(3600));
        let short_expiry = c.inner.get(&key(1)).unwrap().expires;
        c.prune_expired(short_expiry);
        assert_eq!(c.bytes, 400);
        assert!(c.get(&key(1)).is_none());
        assert_eq!(c.next_expiry, Some(c.inner.get(&key(0)).unwrap().expires));
        c.put(key(3), vec![3; 100], Some(3600));
        c.put(key(4), vec![4; 100], Some(3600));
        c.put(key(5), vec![5; 100], Some(3600));
        assert!(c.get(&key(0)).is_none());
        assert_eq!(c.bytes, 600);
        assert_eq!(c.inner.order.len(), 4);
    }

    #[test]
    fn expired_batch_and_replacement_keep_budget_exact() {
        let mut c = DnsCache::new(1024);
        for n in 0..1024 {
            c.put(key(n), vec![0; 100], Some(5));
        }
        // 替换最早项并延长 TTL；保守的最早时间仍须保留，以回收其他项。
        c.put(key(0), vec![1; 200], Some(3600));
        c.prune_expired(Instant::now() + Duration::from_secs(6));
        assert_eq!(c.len(), 1);
        assert_eq!(c.bytes, 200);
        assert_eq!(c.inner.order.len(), 1);
        assert_eq!(c.get(&key(0)), Some(vec![1; 200]));
        c.clear();
        assert_eq!(c.next_expiry, None);
        assert_eq!(c.bytes, 0);
        c.put(key(1), vec![2; 10], Some(5));
        c.prune_expired(Instant::now() + Duration::from_secs(6));
        assert!(c.is_empty());
        assert_eq!(c.bytes, 0);
        assert_eq!(c.next_expiry, None);
    }

    #[test]
    fn bounded_eviction() {
        let mut m = BoundedMap::new(2);
        m.insert(1, "a");
        m.insert(2, "b");
        m.insert(1, "a2");
        m.insert(3, "c");
        assert_eq!(m.len(), 2);
        assert!(m.get(&1).is_none());
        assert_eq!(m.get(&2), Some(&"b"));
        assert_eq!(m.get(&3), Some(&"c"));
    }

    #[test]
    fn mapping_latest_wins() {
        let mut m = DomainMapping::new(10);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        m.record(ip, "a.com");
        m.record(ip, "b.com");
        assert_eq!(m.lookup(&ip), Some("b.com"));
    }

    #[test]
    fn cache_expiry() {
        let mut c = DnsCache::new(4);
        let k = CacheKey {
            name: "a".into(),
            qtype: 1,
            qclass: 1,
        };
        c.put(k.clone(), vec![1, 2], Some(100));
        assert_eq!(c.get(&k), Some(vec![1, 2]));
        c.inner.insert(
            k.clone(),
            CacheEntry {
                response: vec![3],
                expires: Instant::now(),
                ttl: 0,
                source: CacheSource::default(),
            },
        );
        assert_eq!(c.get(&k), None);
        assert!(c.is_empty());
    }

    #[test]
    fn cache_has_entry_and_byte_limits() {
        let mut c = DnsCache::new(1000);
        let key = |n| CacheKey {
            name: format!("{n}.example"),
            qtype: 1,
            qclass: 1,
        };
        c.put(key(0), vec![0; MAX_RESPONSE_BYTES + 1], Some(60));
        assert_eq!(c.len(), 0);
        for n in 0..100 {
            c.put(key(n), vec![n as u8; MAX_RESPONSE_BYTES], Some(60));
        }
        assert!(c.len() <= MAX_CACHE_BYTES / MAX_RESPONSE_BYTES);
        assert!(c.get(&key(0)).is_none());
    }

    #[test]
    fn recent_is_newest_first_and_skips_expired() {
        let mut c = DnsCache::new(8);
        let key = |n: u8| CacheKey {
            name: format!("{n}.example"),
            qtype: 1,
            qclass: 1,
        };
        let source = CacheSource {
            kind: "group",
            group: Some("Domestic".into()),
            server: "tls://dns.example:853".into(),
        };
        c.put_with_source(key(1), vec![1], Some(60), source.clone());
        c.put_with_source(key(2), vec![2], Some(1), source.clone());
        c.put(key(3), vec![3], Some(60));
        let names: Vec<_> = c.recent(10).iter().map(|(k, _)| k.name.clone()).collect();
        assert_eq!(names, ["3.example", "2.example", "1.example"]);
        assert_eq!(c.recent(1).len(), 1);
        let (_, first) = c.recent(10)[2];
        assert_eq!(first.source, source);
        assert_eq!(first.ttl, 60);
        // MIN_TTL 夹紧：TTL 1 写入为 5
        assert_eq!(c.recent(10)[1].1.ttl, MIN_TTL);
        // TTL 0 不缓存，并替换掉旧条目。
        c.put(key(3), vec![3], Some(0));
        assert!(c.get(&key(3)).is_none());
    }
}
