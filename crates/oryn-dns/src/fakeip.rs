//! 有界的 Fake-IP 地址池与域名映射。

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use oryn_config::IpCidr;

pub const CAPACITY: usize = 8192;
const MAGIC: &[u8] = b"ORYNFAKE1";
const SAVE_INTERVAL: Duration = Duration::from_secs(30);
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
const RESERVED_START: u32 = (198u32 << 24) | (18u32 << 16);
const RESERVED_END: u32 = RESERVED_START | 0xff;

// 槽位最多 CAPACITY 个；淘汰时原位复用，命中不分配 LRU 字符串。
const NO_SLOT: usize = usize::MAX;

struct Lease {
    domain: String,
    ip: Ipv4Addr,
    prev: usize,
    next: usize,
}

pub struct FakeIpPool {
    range: IpCidr,
    start: u32,
    end: u32,
    cursor: u32,
    by_domain: HashMap<String, usize>,
    by_ip: HashMap<Ipv4Addr, usize>,
    leases: Vec<Lease>,
    oldest: usize,
    newest: usize,
    path: Option<PathBuf>,
    dirty: bool,
    last_save: Instant,
}

impl FakeIpPool {
    pub fn new(range: IpCidr) -> Self {
        let (start, end) = range.range_v4().expect("Fake-IP range must be IPv4");
        FakeIpPool {
            range: range.network(),
            start,
            end,
            cursor: start,
            by_domain: HashMap::new(),
            by_ip: HashMap::new(),
            leases: Vec::new(),
            oldest: NO_SLOT,
            newest: NO_SLOT,
            path: None,
            dirty: false,
            last_save: Instant::now(),
        }
    }

    #[allow(dead_code)]
    pub fn range(&self) -> IpCidr {
        self.range
    }

    pub fn len(&self) -> usize {
        self.by_domain.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.by_domain.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        matches!(ip, IpAddr::V4(v4) if self.range.contains(IpAddr::V4(v4))
            && !(RESERVED_START..=RESERVED_END).contains(&u32::from(v4)))
    }

    pub fn lookup_domain(&mut self, ip: &Ipv4Addr) -> Option<String> {
        let slot = *self.by_ip.get(ip)?;
        self.touch(slot);
        Some(self.leases[slot].domain.clone())
    }

    /// 只读查询，不更新最近使用顺序（诊断用）。
    pub fn peek_ip(&self, domain: &str) -> Option<Ipv4Addr> {
        self.by_domain.get(domain).map(|&slot| self.leases[slot].ip)
    }

    #[allow(dead_code)]
    pub fn lookup_ip(&mut self, domain: &str) -> Option<Ipv4Addr> {
        let slot = *self.by_domain.get(domain)?;
        self.touch(slot);
        Some(self.leases[slot].ip)
    }

    /// 把已经出现在链路上、但池里没有记录的地址补登记。不淘汰已有租约。
    pub fn claim(&mut self, ip: Ipv4Addr, domain: &str) -> bool {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty()
            || domain.len() > 253
            || !self.contains(IpAddr::V4(ip))
            || self.by_ip.contains_key(&ip)
            || self.by_domain.contains_key(&domain)
            || self.leases.len() >= CAPACITY
        {
            return false;
        }
        self.insert_lease(&domain, ip, None);
        self.dirty = true;
        true
    }

    pub fn allocate(&mut self, domain: &str) -> Option<Ipv4Addr> {
        if let Some(&slot) = self.by_domain.get(domain) {
            self.touch(slot);
            return Some(self.leases[slot].ip);
        }
        // 地址池（最小 /20，4096 个）可能小于租约容量：池满时不再扫描，直接淘汰最旧租约并
        // 复用其地址（与 mihomo 的 LRU 复用一致），否则 /20 用满后会永久分配失败。
        let free = if self.by_ip.len() < self.usable() {
            self.next_free()
        } else {
            None
        };
        let at_capacity = self.leases.len() >= CAPACITY;
        if let (Some(addr), false) = (free, at_capacity) {
            self.insert_lease(domain, addr, None);
            self.dirty = true;
            return Some(addr);
        }
        // 身份租约不能在容量压力下被复用给另一身份；仅在淘汰时遍历跳过。
        let mut slot = self.oldest;
        while slot != NO_SLOT && self.leases[slot].domain.starts_with("@tailscale:") {
            slot = self.leases[slot].next;
        }
        if slot == NO_SLOT {
            return None;
        }
        self.detach(slot);
        let old = &self.leases[slot];
        let old_ip = old.ip;
        self.by_domain.remove(&old.domain);
        self.by_ip.remove(&old_ip);
        let addr = free.unwrap_or(old_ip);
        self.insert_lease(domain, addr, Some(slot));
        self.dirty = true;
        Some(addr)
    }

    /// 地址池中可分配的地址数（去掉隧道保留段）。
    fn usable(&self) -> usize {
        let span = u64::from(self.end) - u64::from(self.start) + 1;
        let lo = self.start.max(RESERVED_START);
        let hi = self.end.min(RESERVED_END);
        let reserved = if lo <= hi { u64::from(hi - lo) + 1 } else { 0 };
        usize::try_from(span - reserved).unwrap_or(usize::MAX)
    }

    /// 从游标开始找下一个未占用、非保留的地址。
    fn next_free(&mut self) -> Option<Ipv4Addr> {
        let span = u64::from(self.end) - u64::from(self.start) + 1;
        for _ in 0..span {
            let ip = self.cursor;
            self.cursor = if self.cursor == self.end {
                self.start
            } else {
                self.cursor + 1
            };
            if (RESERVED_START..=RESERVED_END).contains(&ip)
                || self.by_ip.contains_key(&Ipv4Addr::from(ip))
            {
                continue;
            }
            return Some(Ipv4Addr::from(ip));
        }
        None
    }

    pub fn set_path(&mut self, data_dir: Option<&Path>) {
        self.path = data_dir.map(|p| p.join("fakeip.bin"));
        if self.path.is_some() {
            self.load();
        }
    }

    pub fn configure(&mut self, range: IpCidr) {
        if self.range != range.network() {
            self.range = range.network();
            let (start, end) = range.range_v4().expect("Fake-IP range must be IPv4");
            self.start = start;
            self.end = end;
            self.cursor = start;
            self.by_domain.clear();
            self.by_ip.clear();
            self.clear_leases();
            self.dirty = false;
            self.load();
        }
    }

    pub fn save_if_due(&mut self, force: bool) {
        if !self.dirty || (!force && self.last_save.elapsed() < SAVE_INTERVAL) {
            return;
        }
        let Some(path) = self.path.clone() else {
            return;
        };
        if self.write(&path).is_ok() {
            self.dirty = false;
            self.last_save = Instant::now();
        }
    }

    fn clear_leases(&mut self) {
        self.leases.clear();
        self.oldest = NO_SLOT;
        self.newest = NO_SLOT;
    }

    fn detach(&mut self, slot: usize) {
        let (prev, next) = (self.leases[slot].prev, self.leases[slot].next);
        if prev == NO_SLOT {
            self.oldest = next;
        } else {
            self.leases[prev].next = next;
        }
        if next == NO_SLOT {
            self.newest = prev;
        } else {
            self.leases[next].prev = prev;
        }
    }

    fn append(&mut self, slot: usize) {
        self.leases[slot].prev = self.newest;
        self.leases[slot].next = NO_SLOT;
        if self.newest == NO_SLOT {
            self.oldest = slot;
        } else {
            self.leases[self.newest].next = slot;
        }
        self.newest = slot;
    }

    fn insert_lease(&mut self, domain: &str, ip: Ipv4Addr, reuse: Option<usize>) {
        let slot = reuse.unwrap_or(self.leases.len());
        let lease = Lease {
            domain: domain.to_string(),
            ip,
            prev: NO_SLOT,
            next: NO_SLOT,
        };
        if reuse.is_some() {
            self.leases[slot] = lease;
        } else {
            self.leases.push(lease);
        }
        self.by_domain.insert(domain.to_string(), slot);
        self.by_ip.insert(ip, slot);
        self.append(slot);
    }

    /// 只更新最近使用顺序；不置脏，避免每个发往 Fake-IP 的连接都触发定期重写状态文件
    /// （顺序只影响淘汰先后，映射本身没有变化）。
    fn touch(&mut self, slot: usize) {
        if self.newest != slot {
            self.detach(slot);
            self.append(slot);
        }
    }

    fn ordered_leases(&self) -> impl Iterator<Item = &Lease> {
        std::iter::successors((self.oldest != NO_SLOT).then_some(self.oldest), |&slot| {
            (self.leases[slot].next != NO_SLOT).then_some(self.leases[slot].next)
        })
        .map(|slot| &self.leases[slot])
    }

    fn load(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let Ok(metadata) = fs::metadata(&path) else {
            return;
        };
        if metadata.len() > MAX_STATE_BYTES {
            return;
        }
        let Ok(bytes) = fs::read(path) else { return };
        if bytes.len() < MAGIC.len() + 14 || &bytes[..MAGIC.len()] != MAGIC {
            return;
        }
        let mut pos = MAGIC.len();
        let start = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let end = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let cursor = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        if start != self.start || end != self.end || cursor < start || cursor > end {
            return;
        }
        let Some(count) = bytes
            .get(pos..pos + 2)
            .and_then(|v| v.try_into().ok().map(u16::from_be_bytes))
        else {
            return;
        };
        pos += 2;
        self.cursor = cursor;
        self.by_domain.clear();
        self.by_ip.clear();
        self.clear_leases();
        let mut truncated = false;
        for _ in 0..usize::from(count).min(CAPACITY) {
            let Some(len) = bytes
                .get(pos..pos + 2)
                .and_then(|v| v.try_into().ok().map(u16::from_be_bytes))
            else {
                truncated = true;
                break;
            };
            pos += 2;
            let len = usize::from(len);
            let Some(domain_bytes) = bytes.get(pos..pos + len) else {
                truncated = true;
                break;
            };
            pos += len;
            let Some(ip_bytes) = bytes.get(pos..pos + 4) else {
                truncated = true;
                break;
            };
            pos += 4;
            let Ok(domain) = std::str::from_utf8(domain_bytes) else {
                truncated = true;
                break;
            };
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(ip_bytes).unwrap());
            if !self.contains(IpAddr::V4(ip))
                || self.by_ip.contains_key(&ip)
                || self.by_domain.contains_key(domain)
            {
                continue;
            }
            self.insert_lease(domain, ip, None);
        }
        // 中途损坏时保留已读出的有效租约，但标记为脏，下次保存写回一份完整一致的文件，
        // 不把残缺文件当作有效状态留在磁盘上。
        if truncated {
            log::warn!(
                "Fake-IP state file truncated; kept {} leases",
                self.leases.len()
            );
        }
        self.dirty = truncated;
    }

    fn write(&self, path: &Path) -> io::Result<()> {
        let mut out = Vec::with_capacity(32 + self.by_domain.len() * 32);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.start.to_be_bytes());
        out.extend_from_slice(&self.end.to_be_bytes());
        out.extend_from_slice(&self.cursor.to_be_bytes());
        out.extend_from_slice(&(self.leases.len().min(CAPACITY) as u16).to_be_bytes());
        for lease in self.ordered_leases().take(CAPACITY) {
            let bytes = lease.domain.as_bytes();
            if bytes.len() > u16::MAX as usize {
                continue;
            }
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(bytes);
            out.extend_from_slice(&lease.ip.octets());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("bin.tmp");
        fs::write(&tmp, out)?;
        fs::rename(tmp, path)
    }
}

pub fn reverse_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

pub fn parse_reverse_name(name: &str) -> Option<Ipv4Addr> {
    let labels: Vec<_> = name.trim_end_matches('.').split('.').collect();
    if labels.len() != 6
        || !labels[4].eq_ignore_ascii_case("in-addr")
        || !labels[5].eq_ignore_ascii_case("arpa")
    {
        return None;
    }
    Some(Ipv4Addr::new(
        labels[3].parse().ok()?,
        labels[2].parse().ok()?,
        labels[1].parse().ok()?,
        labels[0].parse().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 本机缓存文件写入微基准；不代表闪存持久化或完整 DNS 延迟。
    #[test]
    #[ignore = "manual performance survey; writes workspace target/scratch"]
    fn survey_fakeip_persistence_cost() {
        use std::hint::black_box;
        const SAMPLES: usize = 101;
        fn report(size: usize, mode: &str, mut samples: Vec<u128>) {
            samples.sort_unstable();
            println!(
                "fakeip leases={size} mode={mode} samples={} median_ns={} p99_ns={} max_ns={}",
                samples.len(),
                samples[samples.len() / 2],
                samples[(samples.len() * 99).div_ceil(100) - 1],
                samples.last().unwrap()
            );
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/scratch")
            .join(format!("fakeip-survey-{}", std::process::id()));
        for size in [1024, CAPACITY] {
            let dir = root.join(size.to_string());
            let range = IpCidr::parse("198.18.0.0/15").unwrap();
            let mut pool = FakeIpPool::new(range);
            pool.set_path(Some(&dir));
            for n in 0..size {
                pool.allocate(&format!("host-{n:05}.survey.example"))
                    .unwrap();
            }
            for mode in ["clean", "not_due", "due"] {
                let mut samples = Vec::with_capacity(SAMPLES);
                for _ in 0..SAMPLES {
                    pool.dirty = mode != "clean";
                    pool.last_save = if mode == "not_due" {
                        Instant::now()
                    } else {
                        Instant::now() - SAVE_INTERVAL - Duration::from_secs(1)
                    };
                    let start = Instant::now();
                    black_box(&mut pool).save_if_due(false);
                    samples.push(start.elapsed().as_nanos());
                    if mode == "due" {
                        assert!(!pool.dirty, "save must succeed");
                    }
                }
                report(size, mode, samples);
            }
            let bytes = fs::metadata(dir.join("fakeip.bin")).unwrap().len();
            let mut restored = FakeIpPool::new(range);
            restored.set_path(Some(&dir));
            assert_eq!(restored.len(), size);
            for lease in pool.ordered_leases() {
                assert_eq!(restored.peek_ip(&lease.domain), Some(lease.ip));
            }
            let original_order: Vec<_> = pool.ordered_leases().map(|l| &l.domain).collect();
            let restored_order: Vec<_> = restored.ordered_leases().map(|l| &l.domain).collect();
            assert_eq!(original_order, restored_order);
            println!("fakeip leases={size} snapshot_bytes={bytes} reload=ok");
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// 比较现有预估容量与精确计长；仅测 snapshot，不混入文件系统噪声。
    #[test]
    #[ignore = "manual cold-path capacity experiment"]
    fn completion_snapshot_capacity_cost() {
        use std::hint::black_box;
        fn snapshot(pool: &FakeIpPool, exact: bool) -> (Vec<u8>, usize) {
            let capacity = if exact {
                MAGIC.len() + 14 + pool.ordered_leases().take(CAPACITY)
                    .filter(|l| l.domain.len() <= u16::MAX as usize)
                    .map(|l| l.domain.len() + 6).sum::<usize>()
            } else {
                32 + pool.by_domain.len() * 32
            };
            let mut out = Vec::with_capacity(capacity);
            out.extend_from_slice(MAGIC);
            out.extend_from_slice(&pool.start.to_be_bytes());
            out.extend_from_slice(&pool.end.to_be_bytes());
            out.extend_from_slice(&pool.cursor.to_be_bytes());
            out.extend_from_slice(&(pool.leases.len().min(CAPACITY) as u16).to_be_bytes());
            let mut growths = 0;
            for lease in pool.ordered_leases().take(CAPACITY) {
                let bytes = lease.domain.as_bytes();
                if bytes.len() > u16::MAX as usize { continue; }
                let before = out.capacity();
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(bytes);
                out.extend_from_slice(&lease.ip.octets());
                growths += usize::from(out.capacity() != before);
            }
            (out, growths)
        }
        for domain_len in [25, 120, 250] {
            let mut pool = FakeIpPool::new(IpCidr::parse("198.18.0.0/15").unwrap());
            for n in 0..CAPACITY {
                let mut domain = format!("host-{n:05}.");
                domain.push_str(&"a".repeat(domain_len - domain.len()));
                pool.allocate(&domain).unwrap();
            }
            let baseline = snapshot(&pool, false);
            let exact = snapshot(&pool, true);
            assert_eq!(baseline.0, exact.0);
            assert_eq!(exact.1, 0);
            let mut times = [Vec::new(), Vec::new()];
            // 交替次序，计时包括计长、分配、序列化与释放。
            for round in 0..101 {
                for mode in [round % 2, 1 - round % 2] {
                    let start = Instant::now();
                    drop(black_box(snapshot(black_box(&pool), mode == 1)));
                    times[mode].push(start.elapsed().as_nanos());
                }
            }
            for t in &mut times { t.sort_unstable(); }
            println!("snapshot leases={} domain_len={domain_len} bytes={} baseline_capacity={} exact_capacity={} baseline_growths={} baseline_ns={} exact_ns={}",
                CAPACITY, baseline.0.len(), baseline.0.capacity(), exact.0.capacity(), baseline.1, times[0][50], times[1][50]);
        }
    }

    #[test]
    fn completion_force_and_failed_save_keep_contract() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/scratch")
            .join(format!("fakeip-contract-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let range = IpCidr::parse("198.18.0.0/15").unwrap();
        let mut pool = FakeIpPool::new(range);
        pool.set_path(Some(&dir));
        let ip = pool.allocate("forced.example").unwrap();
        pool.last_save = Instant::now();
        let before = pool.last_save;
        pool.save_if_due(false);
        assert!(pool.dirty);
        assert!(!dir.join("fakeip.bin").exists());
        // 临时文件路径是目录，写入必须失败，不清 dirty / 不推进时钟。
        fs::create_dir(dir.join("fakeip.bin.tmp")).unwrap();
        pool.save_if_due(true);
        assert!(pool.dirty);
        assert_eq!(pool.last_save, before);
        fs::remove_dir(dir.join("fakeip.bin.tmp")).unwrap();
        pool.save_if_due(true);
        assert!(!pool.dirty);
        let mut restored = FakeIpPool::new(range);
        restored.set_path(Some(&dir));
        assert_eq!(restored.peek_ip("forced.example"), Some(ip));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn lru_matches_reference_after_hits_and_slot_reuse() {
        use std::collections::VecDeque;
        let mut pool = FakeIpPool::new(IpCidr::parse("198.18.0.0/15").unwrap());
        let mut reference = VecDeque::new();
        for n in 0..CAPACITY {
            let name = format!("host-{n}.test");
            let ip = pool.allocate(&name).unwrap();
            reference.push_back((name, ip));
        }
        let mut state = 1234567u64;
        for n in 0..512 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let index = (state as usize) % reference.len();
            if n % 4 == 0 {
                let (old, ip) = reference.pop_front().unwrap();
                let name = format!("new-{n}.test");
                let new_ip = pool.allocate(&name).unwrap();
                assert!(pool.peek_ip(&old).is_none());
                assert!(pool.lookup_domain(&ip).is_none());
                reference.push_back((name, new_ip));
            } else {
                let (name, ip) = reference.remove(index).unwrap();
                match n % 4 {
                    1 => assert_eq!(pool.allocate(&name), Some(ip)),
                    2 => assert_eq!(pool.lookup_ip(&name), Some(ip)),
                    _ => assert_eq!(pool.lookup_domain(&ip).as_deref(), Some(name.as_str())),
                }
                reference.push_back((name, ip));
            }
        }
        let actual: Vec<_> = pool
            .ordered_leases()
            .map(|l| (l.domain.clone(), l.ip))
            .collect();
        assert_eq!(actual, reference.into_iter().collect::<Vec<_>>());
        assert_eq!(pool.leases.len(), CAPACITY);
        assert!(pool.leases.capacity() <= CAPACITY);
        assert_eq!(pool.by_domain.len(), CAPACITY);
        assert_eq!(pool.by_ip.len(), CAPACITY);
        // 更新已是最新的节点，以及清空后重新分配。
        let last = actual.last().unwrap();
        assert_eq!(pool.allocate(&last.0), Some(last.1));
        pool.configure(IpCidr::parse("198.19.0.0/24").unwrap());
        assert!(pool.is_empty());
        let ip = pool.allocate("only.test").unwrap();
        assert_eq!(pool.lookup_ip("only.test"), Some(ip));
        assert_eq!(pool.ordered_leases().count(), 1);
    }

    #[test]
    fn small_pool_reuses_oldest_address_when_full() {
        // /20 = 4096 个地址，小于租约容量 8192。
        let mut pool = FakeIpPool::new(IpCidr::parse("10.0.0.0/20").unwrap());
        let first = pool.allocate("host-0.test").unwrap();
        for n in 1..4096 {
            pool.allocate(&format!("host-{n}.test")).unwrap();
        }
        let ip = pool.allocate("late.test").expect("full small pool must recycle");
        assert_eq!(ip, first);
        assert!(pool.peek_ip("host-0.test").is_none());
        assert_eq!(pool.lookup_domain(&ip).as_deref(), Some("late.test"));
        assert_eq!(pool.by_ip.len(), 4096);
    }

    #[test]
    fn all_identity_leases_refuse_eviction() {
        let mut pool = FakeIpPool::new(IpCidr::parse("198.18.0.0/15").unwrap());
        for n in 0..CAPACITY {
            pool.allocate(&format!("@tailscale:{n}|peer.test")).unwrap();
        }
        assert!(pool.allocate("normal.test").is_none());
        assert_eq!(pool.ordered_leases().count(), CAPACITY);
        assert!(pool.lookup_ip("@tailscale:0|peer.test").is_some());
    }

    #[test]
    fn claim_registers_an_unmapped_address_without_evicting() {
        let mut pool = FakeIpPool::new(IpCidr::parse("198.18.0.0/15").unwrap());
        let existing = pool.allocate("kept.example").unwrap();
        let recovered = Ipv4Addr::new(198, 18, 4, 9);
        assert!(pool.claim(recovered, "Recovered.Example."));
        assert_eq!(pool.lookup_domain(&recovered).as_deref(), Some("recovered.example"));
        assert_eq!(pool.lookup_domain(&existing).as_deref(), Some("kept.example"));
        assert!(!pool.claim(recovered, "other.example"));
        assert!(!pool.claim(Ipv4Addr::new(198, 18, 0, 9), "tunnel.example"));
        assert!(!pool.claim(Ipv4Addr::new(1, 2, 3, 4), "outside.example"));
    }

    #[test]
    fn alloc_skips_tunnel_and_reuses_domain() {
        let range = IpCidr::parse("198.18.0.0/15").unwrap();
        let mut p = FakeIpPool::new(range);
        let a = p.allocate("a.example").unwrap();
        assert_eq!(a, Ipv4Addr::new(198, 18, 1, 0));
        assert_eq!(p.allocate("a.example"), Some(a));
        assert_eq!(p.lookup_domain(&a), Some("a.example".into()));
    }

    #[test]
    fn reverse_roundtrip() {
        let ip = Ipv4Addr::new(198, 19, 2, 7);
        assert_eq!(parse_reverse_name(&reverse_name(ip)), Some(ip));
    }

    #[test]
    fn persistence_roundtrip_and_bad_file() {
        let dir = std::env::temp_dir().join(format!("oryn-fakeip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let range = IpCidr::parse("198.19.0.0/20").unwrap();
        let mut first = FakeIpPool::new(range);
        first.set_path(Some(&dir));
        let ip = first.allocate("persist.example").unwrap();
        let other = first.allocate("other.example").unwrap();
        first.lookup_domain(&ip);
        first.save_if_due(true);
        let mut second = FakeIpPool::new(range);
        second.set_path(Some(&dir));
        let ordered: Vec<_> = second.ordered_leases().map(|l| l.domain.as_str()).collect();
        assert_eq!(ordered, ["other.example", "persist.example"]);
        assert_eq!(second.peek_ip("other.example"), Some(other));
        assert_eq!(second.lookup_domain(&ip), Some("persist.example".into()));
        fs::write(dir.join("fakeip.bin"), b"broken").unwrap();
        let mut third = FakeIpPool::new(range);
        third.set_path(Some(&dir));
        assert!(third.is_empty());
        let _ = fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    #[test]
    fn identity_lease_is_not_evicted_or_reused() {
        let mut pool = FakeIpPool::new(IpCidr::parse("198.18.0.0/15").unwrap());
        let old = pool.allocate("@tailscale:old|peer.test").unwrap();
        for n in 0..CAPACITY + 2 {
            pool.allocate(&format!("normal-{n}.test")).unwrap();
        }
        assert_eq!(
            pool.lookup_domain(&old).as_deref(),
            Some("@tailscale:old|peer.test")
        );
        let new = pool.allocate("@tailscale:new|peer.test").unwrap();
        assert_ne!(new, old);
    }
}
