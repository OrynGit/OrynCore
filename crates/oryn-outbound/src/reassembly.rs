//! Hysteria2 / TUIC 共用的 UDP 分片重组。
//!
//! 上限（未经真机验证）：总字节预算、每会话同时等待的包数、每包分片数、等待时间。
//! 超限的分片直接丢弃，不扩大缓冲；过期的半包丢掉时归还它占用的预算。

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

pub(crate) struct Reassembly<S, A> {
    packets: HashMap<(S, u16), Pending<A>>,
    bytes: usize,
    /// Pending 的载荷之外还包含 HashMap、分片槽位等元数据；单独计费，
    /// 否则空载荷分片可以用很小的内存耗尽表。
    metadata: usize,
    budget: usize,
    metadata_budget: usize,
    max_entries: usize,
    per_session: usize,
    max_fragments: u8,
    wait: Duration,
}

struct Pending<A> {
    parts: Vec<Option<Vec<u8>>>,
    got: usize,
    bytes: usize,
    at: Instant,
    addr: Option<A>,
    metadata: usize,
}

impl<S: Copy + Eq + Hash, A> Reassembly<S, A> {
    pub(crate) fn new(
        budget: usize,
        per_session: usize,
        max_fragments: u8,
        wait: Duration,
    ) -> Self {
        // 每个条目至少占用一个 HashMap 节点和 `total` 个分片槽位。
        // 元数据预算取载荷预算的四分之一，并设下小的绝对下限，
        // 同时限制条目数，避免零长度 UDP 帧制造无限多 Pending。
        let metadata_budget = budget.saturating_div(4).max(1024);
        let max_entries = (metadata_budget / 128).clamp(1, 256);
        Self {
            packets: HashMap::new(),
            bytes: 0,
            metadata: 0,
            budget,
            metadata_budget,
            max_entries,
            per_session,
            max_fragments,
            wait,
        }
    }

    /// 收下一片。包齐了返回完整载荷与地址；未齐、超限、重复或非法时返回 None。
    /// `addr` 可以每片都带（Hysteria2），也可以只在第 0 片带（TUIC）；以先到的为准。
    pub(crate) fn insert(
        &mut self,
        session: S,
        packet: u16,
        index: u8,
        total: u8,
        addr: Option<A>,
        payload: Vec<u8>,
    ) -> Option<(Vec<u8>, A)> {
        if total == 0 || total > self.max_fragments || index >= total {
            return None;
        }
        // 第 0 片必须携带地址；否则完成后无法安全投递，且攻击者可以
        // 先占用重组预算再等待一个永远不会到来的地址。
        if index == 0 && addr.is_none() {
            return None;
        }
        // 未分片的包（绝大多数）不碰重组表，也不跑过期扫描
        if total == 1 {
            if payload.len() > self.budget {
                return None;
            }
            return addr.map(|addr| (payload, addr));
        }
        self.expire();
        let key = (session, packet);
        let is_new = !self.packets.contains_key(&key);
        if is_new && self.packets.keys().filter(|(s, _)| *s == session).count() >= self.per_session
        {
            return None;
        }
        // 补齐已有包最后一片的分片立即完成并归还预算，不受全局字节预算限制：
        // 否则预算被（其他会话的）分片占满时，这个包永远完成不了，只能等超时
        let slot = usize::from(index);
        let completes = self.packets.get(&key).is_some_and(|e| {
            e.parts.len() == usize::from(total)
                && e.parts.get(slot).is_some_and(Option::is_none)
                && e.got + 1 == e.parts.len()
        });
        if !completes && self.bytes.saturating_add(payload.len()) > self.budget {
            return None;
        }
        let metadata = 64usize.saturating_add(usize::from(total).saturating_mul(16));
        if is_new
            && (self.packets.len() >= self.max_entries
                || self.metadata.saturating_add(metadata) > self.metadata_budget)
        {
            return None;
        }
        let added = payload.len();
        let entry = self.packets.entry(key).or_insert_with(|| Pending {
            parts: (0..total).map(|_| None).collect(),
            got: 0,
            bytes: 0,
            at: Instant::now(),
            addr: None,
            metadata,
        });
        if entry.parts.len() != usize::from(total) || entry.parts[slot].is_some() {
            return None;
        }
        entry.parts[slot] = Some(payload);
        entry.got += 1;
        entry.bytes += added;
        if entry.addr.is_none() {
            entry.addr = addr;
        }
        self.bytes += added;
        if is_new {
            self.metadata += metadata;
        }
        if entry.got != entry.parts.len() {
            return None;
        }
        let done = self.packets.remove(&key)?;
        self.bytes -= done.bytes;
        self.metadata -= done.metadata;
        let addr = done.addr?;
        Some((done.parts.into_iter().flatten().flatten().collect(), addr))
    }

    fn expire(&mut self) {
        if self.packets.is_empty() {
            return;
        }
        let wait = self.wait;
        let before = self.packets.len();
        self.packets
            .retain(|_, pending| pending.at.elapsed() < wait);
        if self.packets.len() == before {
            return;
        }
        self.bytes = self.packets.values().map(|pending| pending.bytes).sum();
        self.metadata = self.packets.values().map(|pending| pending.metadata).sum();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(wait_ms: u64) -> Reassembly<u16, &'static str> {
        Reassembly::new(100, 2, 4, Duration::from_millis(wait_ms))
    }

    #[test]
    fn single_and_out_of_order() {
        let mut t = table(3000);
        assert_eq!(
            t.insert(1, 0, 0, 1, Some("a"), vec![9]),
            Some((vec![9], "a"))
        );
        assert_eq!(t.insert(1, 5, 2, 3, None, vec![3]), None);
        assert_eq!(t.insert(1, 5, 0, 3, Some("a"), vec![1]), None);
        // 重复的分片被忽略
        assert_eq!(t.insert(1, 5, 0, 3, Some("a"), vec![7]), None);
        assert_eq!(
            t.insert(1, 5, 1, 3, None, vec![2]),
            Some((vec![1, 2, 3], "a"))
        );
        assert_eq!(t.bytes, 0);
    }

    #[test]
    fn completing_fragment_bypasses_full_budget() {
        let mut t = table(3000);
        // 会话 1 的包等最后一片；会话 2 的垃圾分片把预算占满
        assert_eq!(t.insert(1, 1, 0, 2, Some("a"), vec![1; 10]), None);
        assert_eq!(t.insert(2, 1, 0, 2, Some("b"), vec![0; 90]), None);
        assert_eq!(t.bytes, 100);
        // 补齐会话 1 的最后一片仍能完成，并归还预算
        assert_eq!(
            t.insert(1, 1, 1, 2, None, vec![2; 5]),
            Some(([vec![1; 10], vec![2; 5]].concat(), "a"))
        );
        assert_eq!(t.bytes, 90);
        // 不能完成包的新分片仍受预算约束
        assert_eq!(t.insert(1, 2, 0, 2, Some("a"), vec![0; 20]), None);
        assert_eq!(t.bytes, 90);
    }

    #[test]
    fn rejects_invalid_and_over_limits() {
        let mut t = table(3000);
        assert_eq!(t.insert(1, 0, 0, 0, Some("a"), vec![1]), None);
        assert_eq!(t.insert(1, 0, 3, 3, Some("a"), vec![1]), None);
        assert_eq!(
            t.insert(1, 0, 0, 5, Some("a"), vec![1]),
            None,
            "超过每包分片数"
        );
        // 每会话最多 2 个未完成包
        t.insert(1, 1, 0, 2, Some("a"), vec![1]);
        t.insert(1, 2, 0, 2, Some("a"), vec![1]);
        assert_eq!(t.insert(1, 3, 0, 2, Some("a"), vec![1]), None);
        assert_eq!(t.packets.len(), 2);
        // 其它会话不受影响；总预算 100 字节
        assert_eq!(t.insert(2, 1, 0, 2, Some("b"), vec![0; 98]), None);
        assert_eq!(t.bytes, 100);
        assert_eq!(t.insert(2, 2, 0, 2, Some("b"), vec![0; 1]), None);
        assert_eq!(t.bytes, 100, "超出预算的分片不入表");
        // 分片数与第一片不一致
        assert_eq!(t.insert(1, 1, 1, 3, None, vec![1]), None);
        // 没有地址的包不交付
        let mut t = table(3000);
        t.insert(1, 9, 1, 2, None, vec![2]);
        assert_eq!(t.insert(1, 9, 0, 2, None, vec![1]), None);
    }

    #[test]
    fn expiry_returns_budget() {
        let mut t = table(30);
        t.insert(1, 1, 0, 2, Some("a"), vec![0; 60]);
        assert_eq!(t.insert(2, 1, 0, 2, Some("b"), vec![0; 60]), None);
        assert_eq!(t.bytes, 60, "预算已满，第二个会话的分片被拒绝");
        std::thread::sleep(Duration::from_millis(40));
        t.insert(2, 1, 0, 2, Some("b"), vec![0; 60]);
        assert_eq!(t.bytes, 60, "过期的半包归还了预算");
        assert_eq!(
            t.insert(2, 1, 1, 2, None, vec![1]).map(|(b, _)| b.len()),
            Some(61)
        );
        assert_eq!(t.bytes, 0);
    }

    #[test]
    fn metadata_budget_bounds_empty_payload_entries() {
        let mut t = Reassembly::new(100, 2, 4, Duration::from_secs(3));
        for session in 1..=8 {
            assert!(t.insert(session, 1, 0, 2, Some("a"), Vec::new()).is_none());
        }
        // 空载荷不增加 bytes，但第 9 个 Pending 仍受元数据/条目预算限制。
        assert!(t.insert(9, 1, 0, 2, Some("a"), Vec::new()).is_none());
        assert_eq!(t.packets.len(), t.max_entries);
        assert!(t.metadata <= t.metadata_budget);
        assert!(t.insert(1, 1, 1, 2, None, Vec::new()).is_some());
        assert_eq!(t.metadata, t.packets.len() * 96);
    }
}
