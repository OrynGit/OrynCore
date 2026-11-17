//! Engine 级入口预算；准入同步判定，超限的 TCP 进入有界等待队列而不是立刻 RST。
//!
//! 三道关：active 额度、establishing 额度、内存余量闸。前两者是计数，随压力等级收紧；
//! 内存闸由宿主（iOS 的 PacketTunnel）每秒报告 `os_proc_available_memory()`，Core 按「每条新连接约
//! `cost` 字节」逐条扣减，余量低于 `reserve` 就不再放行。任一关不通过时，连接（lwIP 已完成握手）
//! 在有界队列里等待额度释放，超时才 RST——页面一次并发几十条连接时，应用看到的是略慢，而不是失败。
use std::{
    cell::RefCell,
    future::Future,
    sync::{
        atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

pub const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// 排队等额度的最长时间。单元测试里取 0，保持「满额立即失败」的原语义，便于断言边界。
pub(crate) fn patience(secs: u64) -> Duration {
    if cfg!(test) {
        Duration::ZERO
    } else {
        Duration::from_secs(secs)
    }
}
/// 默认的等待队列容量与最长等待。
const DEFAULT_QUEUE_CAP: usize = 256;
const DEFAULT_QUEUE_TIMEOUT_MS: u64 = 15_000;
/// 等待者即使没收到唤醒也每隔这么久复查一次（唤醒与复查之间的竞争窗口上限）。
const RECHECK: Duration = Duration::from_millis(250);
/// 内存闸默认值：每条新连接按 64 KiB 计（真机实测空闲连接约 40 KiB，含 TLS 外层相近），保留 8 MiB 余量。
const DEFAULT_MEM_COST: u64 = 64 * 1024;
const DEFAULT_MEM_RESERVE: u64 = 8 * 1024 * 1024;
/// 一个等待中的连接（lwIP pcb + 接收缓冲 + 任务）实测约占 16 KiB。
const WAITER_COST: u64 = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PressureLevel {
    Normal = 0,
    Elevated = 1,
    Critical = 2,
}

impl PressureLevel {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Elevated,
            2 => Self::Critical,
            _ => Self::Normal,
        }
    }
}

/// 准入的累计观测：拒绝 / 排队次数与已用额度高水位，随 `stats` 输出，用于判断限额是否真的被撞到。
#[derive(Default)]
pub struct AdmissionCounters {
    pub rejected_active: AtomicU64,
    pub rejected_establishing: AtomicU64,
    pub rejected_pressure: AtomicU64,
    pub rejected_memory: AtomicU64,
    pub rejected_queue_full: AtomicU64,
    pub rejected_queue_memory: AtomicU64,
    pub queued_total: AtomicU64,
    pub queue_timeouts: AtomicU64,
    pub peak_active: AtomicU64,
    pub peak_establishing: AtomicU64,
    pub peak_queue: AtomicU64,
    /// 排队连接最终拿到额度的最长等待（毫秒）。
    pub max_wait_ms: AtomicU64,
}

pub struct Admission {
    pub counters: AdmissionCounters,
    active: Option<Arc<Semaphore>>,
    active_capacity: usize,
    /// 软上限：不超过信号量容量，可运行时调整，已有连接不受影响。
    active_soft: AtomicUsize,
    establishing: Arc<Semaphore>,
    establishing_capacity: usize,
    base_establishing: AtomicUsize,
    pressure: AtomicU8,
    dns: Arc<Semaphore>,
    notify: Arc<Notify>,
    waiting: Arc<AtomicUsize>,
    queue_cap: AtomicUsize,
    queue_timeout_ms: AtomicU64,
    /// 宿主报告的可用内存（字节）；`u64::MAX` 表示未知，不启用内存闸。
    mem_available: AtomicU64,
    mem_reserve: AtomicU64,
    mem_cost: AtomicU64,
    /// 自上次报告以来按内存闸放行的新连接数。
    mem_admitted: AtomicU64,
    /// 观测到的每连接堆成本（字节，0 = 尚无观测）与连接很少时的堆基线。
    mem_cost_observed: AtomicU64,
    heap_base: AtomicU64,
}

impl Default for Admission {
    fn default() -> Self {
        Self::new(crate::options::ResourceProfile::Constrained)
    }
}

impl Admission {
    pub(crate) fn new(profile: crate::options::ResourceProfile) -> Self {
        let limits = profile.limits();
        Self::from_limits(limits.active, limits.establishing, limits.establishing_soft, limits.dns)
    }

    pub(crate) fn from_limits(active: Option<usize>, establishing: usize, establishing_soft: usize, dns: usize) -> Self {
        Self {
            counters: AdmissionCounters::default(),
            active_capacity: active.unwrap_or(0),
            active_soft: AtomicUsize::new(active.unwrap_or(usize::MAX)),
            active: active.map(|limit| Arc::new(Semaphore::new(limit))),
            establishing: Arc::new(Semaphore::new(establishing)),
            establishing_capacity: establishing,
            base_establishing: AtomicUsize::new(establishing_soft.min(establishing)),
            pressure: AtomicU8::new(PressureLevel::Normal as u8),
            dns: Arc::new(Semaphore::new(dns)),
            notify: Arc::new(Notify::new()),
            waiting: Arc::new(AtomicUsize::new(0)),
            queue_cap: AtomicUsize::new(DEFAULT_QUEUE_CAP),
            queue_timeout_ms: AtomicU64::new(DEFAULT_QUEUE_TIMEOUT_MS),
            mem_available: AtomicU64::new(u64::MAX),
            mem_reserve: AtomicU64::new(DEFAULT_MEM_RESERVE),
            mem_cost: AtomicU64::new(DEFAULT_MEM_COST),
            mem_admitted: AtomicU64::new(0),
            mem_cost_observed: AtomicU64::new(0),
            heap_base: AtomicU64::new(0),
        }
    }
}

/// 开发调参（`admission_tune` 命令）：所有字段可选，只改给出的。
#[derive(Default, Debug)]
pub struct Tune {
    pub active_soft: Option<usize>,
    pub establishing_soft: Option<usize>,
    pub queue_cap: Option<usize>,
    pub queue_timeout_ms: Option<u64>,
    pub mem_reserve: Option<u64>,
    pub mem_cost: Option<u64>,
}

impl Admission {
    pub(crate) fn pressure(&self) -> PressureLevel {
        PressureLevel::from_u8(self.pressure.load(Ordering::Relaxed))
    }

    pub(crate) fn set_pressure(&self, level: PressureLevel) {
        self.pressure.store(level as u8, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    /// 宿主每秒报告一次扩展进程还能再用多少内存；同时清零「本周期已放行」计数。
    pub(crate) fn report_available(&self, bytes: u64) {
        self.mem_available.store(bytes, Ordering::Relaxed);
        self.mem_admitted.store(0, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    /// 用 Core 堆的实际占用校准每连接成本：连接很少时记下基线；连接多起来后，
    /// 成本 = (当前堆 − 基线) / 连接数 × 1.3，夹在 [mem_cost, 384 KiB]。
    /// 经 HTTP 检查 / MITM 的连接比纯转发的贵得多，固定估价会让内存闸放得太松。
    pub(crate) fn observe_heap(&self, heap_live: u64, active: usize) {
        if active <= 2 {
            self.heap_base.store(heap_live, Ordering::Relaxed);
        } else if active >= 16 {
            let base = self.heap_base.load(Ordering::Relaxed);
            let per = heap_live.saturating_sub(base) / active as u64;
            let cost = (per * 13 / 10).min(384 * 1024);
            // 平滑：新值占 1/2，避免单次抖动
            let old = self.mem_cost_observed.load(Ordering::Relaxed);
            self.mem_cost_observed.store(if old == 0 { cost } else { (old + cost) / 2 }, Ordering::Relaxed);
        }
    }

    fn effective_cost(&self) -> u64 {
        self.mem_cost.load(Ordering::Relaxed).max(self.mem_cost_observed.load(Ordering::Relaxed))
    }

    pub(crate) fn tune(&self, t: &Tune) {
        if let Some(v) = t.active_soft {
            self.active_soft.store(v, Ordering::Relaxed);
        }
        if let Some(v) = t.establishing_soft {
            self.base_establishing.store(v.min(self.establishing_capacity), Ordering::Relaxed);
        }
        if let Some(v) = t.queue_cap {
            self.queue_cap.store(v, Ordering::Relaxed);
        }
        if let Some(v) = t.queue_timeout_ms {
            self.queue_timeout_ms.store(v, Ordering::Relaxed);
        }
        if let Some(v) = t.mem_reserve {
            self.mem_reserve.store(v, Ordering::Relaxed);
        }
        if let Some(v) = t.mem_cost {
            self.mem_cost.store(v.max(1), Ordering::Relaxed);
        }
        self.notify.notify_waiters();
    }

    pub(crate) fn tuning(&self) -> serde_json::Value {
        serde_json::json!({
            "active_soft": self.active.as_ref().map(|_| self.active_soft.load(Ordering::Relaxed)),
            "active_capacity": self.active.as_ref().map(|_| self.active_capacity),
            "establishing_soft": self.base_establishing.load(Ordering::Relaxed),
            "establishing_capacity": self.establishing_capacity,
            "queue_cap": self.queue_cap.load(Ordering::Relaxed),
            "queue_timeout_ms": self.queue_timeout_ms.load(Ordering::Relaxed),
            "mem_reserve": self.mem_reserve.load(Ordering::Relaxed),
            "mem_cost": self.mem_cost.load(Ordering::Relaxed),
            "mem_cost_observed": self.mem_cost_observed.load(Ordering::Relaxed),
            "mem_available": Some(self.mem_available.load(Ordering::Relaxed)).filter(|v| *v != u64::MAX),
        })
    }

    pub(crate) fn waiting(&self) -> usize {
        self.waiting.load(Ordering::Relaxed)
    }

    pub(crate) fn establishing_limit(&self) -> usize {
        let level = self.pressure();
        let base = self.base_establishing.load(Ordering::Relaxed);
        match level {
            PressureLevel::Normal => base,
            PressureLevel::Elevated => match base {
                16 => 8,
                8 => 4,
                48 => 24,
                base => (base / 2).max(1),
            },
            PressureLevel::Critical => match base {
                16 => 4,
                8 => 2,
                48 => 8,
                base => (base / 4).max(1),
            },
        }
    }

    /// 当前已占用的 active 额度（无上限档位返回 0）。
    pub fn active_in_use(&self) -> usize {
        self.active
            .as_ref()
            .map_or(0, |s| self.active_capacity - s.available_permits())
    }

    pub fn establishing_in_use(&self) -> usize {
        self.establishing_capacity - self.establishing.available_permits()
    }

    pub fn try_tcp(&self) -> Option<TcpPermit> {
        self.try_tcp_inner(true)
    }

    fn try_tcp_inner(&self, count: bool) -> Option<TcpPermit> {
        let c = &self.counters;
        let bump = |counter: &AtomicU64| {
            if count {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        };
        let active = match self.active.as_ref() {
            None => None,
            Some(semaphore) => {
                // 软上限：已用额度达到上限就拒绝新连接，已有的不撤销。
                if self.active_capacity - semaphore.available_permits() >= self.active_soft.load(Ordering::Relaxed) {
                    bump(&c.rejected_active);
                    return None;
                }
                match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        bump(&c.rejected_active);
                        return None;
                    }
                }
            }
        };
        let Ok(establishing) = self.establishing.clone().try_acquire_owned() else {
            bump(&c.rejected_establishing);
            return None;
        };
        // The semaphore retains its original capacity so existing handshakes are
        // never revoked. A reduced target only rejects new handshakes.
        let in_use = self.establishing_capacity - self.establishing.available_permits();
        if in_use > self.establishing_limit() {
            drop(establishing);
            bump(&c.rejected_pressure);
            return None;
        }
        // 内存闸：宿主报告了可用内存时，按每条连接的估计成本逐条扣减。
        let available = self.mem_available.load(Ordering::Relaxed);
        if available != u64::MAX {
            let cost = self.effective_cost();
            let budget = available.saturating_sub(self.mem_reserve.load(Ordering::Relaxed));
            let admitted = self.mem_admitted.load(Ordering::Relaxed);
            if (admitted + 1).saturating_mul(cost) > budget {
                drop(establishing);
                bump(&c.rejected_memory);
                return None;
            }
            self.mem_admitted.fetch_add(1, Ordering::Relaxed);
        }
        c.peak_establishing.fetch_max(in_use as u64, Ordering::Relaxed);
        c.peak_active.fetch_max(self.active_in_use() as u64, Ordering::Relaxed);
        Some(TcpPermit {
            _active: active,
            phase: Establishing {
                permit: RefCell::new(Some(establishing)),
                on_timeout: RefCell::new(None),
                notify: self.notify.clone(),
            },
            deadline: Instant::now() + ESTABLISH_TIMEOUT,
            notify: self.notify.clone(),
        })
    }

    /// 预占一个等待名额；队列满返回 None（调用方应立即 RST）。
    pub fn try_wait_slot(&self) -> Option<WaitSlot> {
        let cap = self.queue_cap.load(Ordering::Relaxed);
        let n = self.waiting.fetch_add(1, Ordering::Relaxed);
        if n >= cap {
            self.waiting.fetch_sub(1, Ordering::Relaxed);
            self.counters.rejected_queue_full.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // 等待者本身也占内存：队列不能把余量吃到保留值的一半以下（真机重负载下 213 个等待者吃掉了约 3 MiB）
        let available = self.mem_available.load(Ordering::Relaxed);
        if available != u64::MAX {
            let floor = self.mem_reserve.load(Ordering::Relaxed) / 2;
            if available.saturating_sub(floor) < (n as u64 + 1) * WAITER_COST {
                self.waiting.fetch_sub(1, Ordering::Relaxed);
                self.counters.rejected_queue_memory.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        self.counters.queued_total.fetch_add(1, Ordering::Relaxed);
        self.counters.peak_queue.fetch_max(n as u64 + 1, Ordering::Relaxed);
        Some(WaitSlot { waiting: self.waiting.clone() })
    }

    /// 等待额度；超时返回 None（调用方 RST）。名额在返回时释放。
    pub async fn wait_tcp(&self, slot: WaitSlot) -> Option<TcpPermit> {
        let _slot = slot;
        let started = Instant::now();
        let deadline = started + Duration::from_millis(self.queue_timeout_ms.load(Ordering::Relaxed));
        loop {
            // 先登记再复查，避免「复查失败 → 释放 → 通知 → 才开始等」的丢失唤醒
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(permit) = self.try_tcp_inner(false) {
                self.counters
                    .max_wait_ms
                    .fetch_max(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                return Some(permit);
            }
            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep(RECHECK) => {}
                _ = tokio::time::sleep_until(deadline) => {
                    self.counters.queue_timeouts.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
        }
    }

    pub fn try_dns(&self) -> Option<OwnedSemaphorePermit> {
        self.dns.clone().try_acquire_owned().ok()
    }
}

/// 等待名额（RAII）。
pub struct WaitSlot {
    waiting: Arc<AtomicUsize>,
}

impl Drop for WaitSlot {
    fn drop(&mut self) {
        self.waiting.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct TcpPermit {
    _active: Option<OwnedSemaphorePermit>,
    phase: Establishing,
    deadline: Instant,
    notify: Arc<Notify>,
}

impl Drop for TcpPermit {
    fn drop(&mut self) {
        // 字段（信号量许可）在本函数之后才释放；waiters 至多晚 RECHECK 复查即可见，这里只加速。
        self.notify.notify_waiters();
    }
}

pub struct Establishing {
    permit: RefCell<Option<OwnedSemaphorePermit>>,
    on_timeout: RefCell<Option<Box<dyn FnOnce()>>>,
    notify: Arc<Notify>,
}
impl Establishing {
    pub fn on_timeout(&self, callback: impl FnOnce() + 'static) {
        *self.on_timeout.borrow_mut() = Some(Box::new(callback));
    }

    pub fn clear_timeout(&self) {
        self.on_timeout.borrow_mut().take();
    }

    /// 在 relay / inspection 之前归还建立额度；active 仍由外层 future 持有。
    pub fn complete(&self) {
        self.permit.borrow_mut().take();
        self.clear_timeout();
        self.notify.notify_waiters();
    }
}

impl TcpPermit {
    pub fn phase(&self) -> &Establishing {
        &self.phase
    }

    /// 单一绝对期限只约束建立；建立完成后绝不取消长连接。
    pub async fn run<T>(&self, operation: impl Future<Output = T>) -> Option<T> {
        tokio::pin!(operation);
        tokio::select! {
            result = &mut operation => Some(result),
            _ = tokio::time::sleep_until(self.deadline) => {
                if self.phase.permit.borrow().is_some() {
                    if let Some(callback) = self.phase.on_timeout.borrow_mut().take() {
                        callback();
                    }
                    None
                } else {
                    Some(operation.await)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_shared_stages_dns_and_raii() {
        let budget = Admission::default();
        let mut active = Vec::new();
        let active_limit = if cfg!(target_os = "macos") { 64 } else { 96 };
        for _ in 0..active_limit {
            let permit = budget.try_tcp().unwrap();
            permit.phase().complete();
            active.push(permit);
        }
        assert!(budget.try_tcp().is_none());
        let dns: Vec<_> = (0..4).map(|_| budget.try_dns().unwrap()).collect();
        assert!(budget.try_dns().is_none());
        drop(dns);
        assert!(budget.try_dns().is_some());
        drop(active);
        let pending: Vec<_> = (0..8).map(|_| budget.try_tcp().unwrap()).collect();
        assert!(budget.try_tcp().is_none());
        drop(pending);
        assert_eq!(budget.active.as_ref().unwrap().available_permits(), active_limit);
        assert_eq!(budget.establishing.available_permits(), 8);
        assert_eq!(budget.establishing_limit(), 8);
        let permit = budget.try_tcp().unwrap();
        let unpolled = async move { permit.run(std::future::pending::<()>()).await };
        drop(unpolled);
        assert_eq!(budget.active.as_ref().unwrap().available_permits(), active_limit);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn desktop_high_admission_has_requested_tcp_window() {
        let budget = Admission::new(crate::options::ResourceProfile::DesktopHigh);
        let mut held = Vec::new();
        for _ in 0..48 {
            let permit = budget.try_tcp().unwrap();
            held.push(permit);
        }
        assert!(budget.try_tcp().is_none());
        assert!(budget.active.is_none());
        assert_eq!(budget.establishing.available_permits(), 0);
        for permit in &held {
            permit.phase().complete();
        }
        assert_eq!(budget.establishing.available_permits(), 48);
        held.clear();
        for _ in 0..512 {
            let permit = budget.try_tcp().unwrap();
            permit.phase().complete();
            held.push(permit);
        }
        assert!(budget.active.is_none());
    }

    #[test]
    fn pressure_limits_keep_existing_permits_and_restore() {
        // 与 iOS 旧档位（establishing 16）同形的参数；不依赖平台专用的档位枚举。
        let budget = Admission::from_limits(Some(96), 16, 16, 4);
        let normal: Vec<_> = (0..16).map(|_| budget.try_tcp().unwrap()).collect();
        budget.set_pressure(PressureLevel::Critical);
        assert_eq!(budget.establishing_limit(), 4);
        assert!(budget.try_tcp().is_none());
        drop(normal);
        let critical: Vec<_> = (0..4).map(|_| budget.try_tcp().unwrap()).collect();
        assert!(budget.try_tcp().is_none());
        budget.set_pressure(PressureLevel::Elevated);
        assert_eq!(budget.establishing_limit(), 8);
        let elevated: Vec<_> = (0..4).map(|_| budget.try_tcp().unwrap()).collect();
        assert!(budget.try_tcp().is_none());
        drop((critical, elevated));
        budget.set_pressure(PressureLevel::Normal);
        let restored: Vec<_> = (0..16).map(|_| budget.try_tcp().unwrap()).collect();
        assert!(budget.try_tcp().is_none());
        drop(restored);
    }

    #[tokio::test]
    async fn queued_connection_proceeds_when_a_permit_is_released() {
        let budget = Admission::from_limits(Some(2), 2, 2, 4);
        let a = budget.try_tcp().unwrap();
        a.phase().complete();
        let b = budget.try_tcp().unwrap();
        b.phase().complete();
        assert!(budget.try_tcp().is_none());
        let slot = budget.try_wait_slot().unwrap();
        assert_eq!(budget.waiting(), 1);
        let released = async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            drop(a);
        };
        let (permit, ()) = tokio::join!(budget.wait_tcp(slot), released);
        assert!(permit.is_some());
        assert_eq!(budget.waiting(), 0);
        assert_eq!(budget.counters.queued_total.load(Ordering::Relaxed), 1);
        assert!(budget.counters.max_wait_ms.load(Ordering::Relaxed) >= 20);
    }

    #[tokio::test]
    async fn queue_is_bounded_and_times_out() {
        let budget = Admission::from_limits(Some(1), 1, 1, 4);
        let held = budget.try_tcp().unwrap();
        budget.tune(&Tune { queue_cap: Some(2), queue_timeout_ms: Some(60), ..Tune::default() });
        let first = budget.try_wait_slot().unwrap();
        let second = budget.try_wait_slot().unwrap();
        assert!(budget.try_wait_slot().is_none());
        assert_eq!(budget.counters.rejected_queue_full.load(Ordering::Relaxed), 1);
        let (a, b) = tokio::join!(budget.wait_tcp(first), budget.wait_tcp(second));
        assert!(a.is_none() && b.is_none());
        assert_eq!(budget.counters.queue_timeouts.load(Ordering::Relaxed), 2);
        assert_eq!(budget.waiting(), 0);
        drop(held);
        assert!(budget.try_tcp().is_some());
    }

    #[test]
    fn waiting_queue_leaves_memory_headroom() {
        let budget = Admission::from_limits(Some(8), 8, 8, 4);
        budget.tune(&Tune { mem_reserve: Some(1 << 20), queue_cap: Some(1000), ..Tune::default() });
        // 可用 0.5 MiB + 0.5 MiB（保留的一半）→ 只能再容纳 (1.0 - 0.5) MiB / 16 KiB = 32 个等待者
        budget.report_available(1 << 20);
        let slots: Vec<_> = std::iter::from_fn(|| budget.try_wait_slot()).take(100).collect();
        assert_eq!(slots.len(), 32, "{}", slots.len());
        assert_eq!(budget.counters.rejected_queue_memory.load(Ordering::Relaxed), 1);
        // 余量不足保留的一半时一个都不收
        budget.report_available(400 << 10);
        drop(slots);
        assert!(budget.try_wait_slot().is_none());
    }

    #[test]
    fn observed_heap_cost_tightens_the_memory_gate() {
        let budget = Admission::from_limits(Some(256), 256, 256, 4);
        budget.tune(&Tune { mem_reserve: Some(0), mem_cost: Some(64 << 10), ..Tune::default() });
        budget.observe_heap(5 << 20, 0); // 基线 5 MiB
        // 32 条连接把堆推到 5 + 8 MiB：每条 256 KiB × 1.3 ≈ 333 KiB
        budget.observe_heap(13 << 20, 32);
        let cost = budget.mem_cost_observed.load(Ordering::Relaxed);
        assert!(cost > 300 << 10 && cost <= 384 << 10, "{cost}");
        // 3 MiB 可用：按 ~333 KiB 只放行 9 条，而不是按 64 KiB 的 48 条
        budget.report_available(3 << 20);
        let held: Vec<_> = std::iter::from_fn(|| budget.try_tcp()).take(100).collect();
        assert!((8..=10).contains(&held.len()), "{}", held.len());
        // 连接很少时不更新成本（避免把基线噪声当成成本）
        budget.observe_heap(40 << 20, 3);
        assert_eq!(budget.mem_cost_observed.load(Ordering::Relaxed), cost);
    }

    #[test]
    fn memory_gate_admits_by_reported_headroom_and_resets_each_report() {
        let budget = Admission::from_limits(Some(64), 64, 64, 4);
        budget.tune(&Tune { mem_reserve: Some(10 << 20), mem_cost: Some(1 << 20), ..Tune::default() });
        // 未报告：不启用
        let free: Vec<_> = (0..10).map(|_| budget.try_tcp().unwrap()).collect();
        drop(free);
        // 13 MiB 可用 - 10 MiB 保留 = 3 条
        budget.report_available(13 << 20);
        let held: Vec<_> = (0..3).map(|_| budget.try_tcp().unwrap()).collect();
        assert!(budget.try_tcp().is_none());
        assert_eq!(budget.counters.rejected_memory.load(Ordering::Relaxed), 1);
        // 下一次报告重新计数
        budget.report_available(15 << 20);
        let more: Vec<_> = (0..5).map(|_| budget.try_tcp().unwrap()).collect();
        assert!(budget.try_tcp().is_none());
        // 余量低于保留值时一条也不放行
        budget.report_available(9 << 20);
        assert!(budget.try_tcp().is_none());
        drop((held, more));
    }

    #[tokio::test]
    async fn timeout_callback_only_runs_on_deadline_not_cancellation() {
        use std::{cell::Cell, rc::Rc};
        let budget = Admission::default();
        let timed_out = Rc::new(Cell::new(0));
        let mut permit = budget.try_tcp().unwrap();
        permit.deadline = Instant::now();
        let flag = timed_out.clone();
        permit.phase().on_timeout(move || flag.set(flag.get() + 1));
        assert!(permit.run(std::future::pending::<()>()).await.is_none());
        assert_eq!(timed_out.get(), 1);
        drop(permit);
        let permit = budget.try_tcp().unwrap();
        let flag = timed_out.clone();
        permit.phase().on_timeout(move || flag.set(flag.get() + 1));
        drop(permit);
        assert_eq!(timed_out.get(), 1);
        let mut permit = budget.try_tcp().unwrap();
        permit.deadline = Instant::now();
        let flag = timed_out.clone();
        permit.phase().on_timeout(move || flag.set(flag.get() + 1));
        permit.phase().complete();
        assert_eq!(
            permit
                .run(async {
                    tokio::task::yield_now().await;
                    1
                })
                .await,
            Some(1)
        );
        assert_eq!(timed_out.get(), 1);
    }

    #[tokio::test]
    async fn deadline_does_not_limit_relay() {
        let budget = Admission::default();
        let mut permit = budget.try_tcp().unwrap();
        permit.deadline = Instant::now();
        assert!(permit.run(std::future::pending::<()>()).await.is_none());
        permit.phase().complete();
        assert_eq!(
            permit
                .run(async {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    42
                })
                .await,
            Some(42)
        );
    }
}
