//! 进程级资源：WG 引擎工作线程与全部 WG / Tailscale 出站共享的隧道内 TCP 缓冲预算。
//!
//! 方案见 Oryn_dev/docs/oryncore/plans/plan-wg-worker-and-global-budget.md。
//! - 工作线程：引擎 task 不再占用 Core 事件循环线程（那里还有 lwIP、Router、relay）。线程在第一次创建
//!   `Tunnel` 时启动并常驻进程，数量在启动前由 [`configure`] 按资源档位设定，之后不再改变。
//! - 全局预算：每条隧道内 TCP 连接持有一个 [`Lease`]，开连接、扩容、收回时增减，释放时自动归还。
//!   上限与内存压力等级可随时更新（Core 收到宿主的内存报告时）。

use std::future::Future;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::task::JoinHandle;

/// 进程级资源政策，由 Core 按资源档位设置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// 全部 WG / Tailscale 出站隧道内 TCP 缓冲的合计上限（字节）。
    pub buffer_budget: usize,
    /// 引擎工作线程数；只在第一个 `Tunnel` 创建之前设置有效。
    pub workers: usize,
}

impl Limits {
    /// 未经 Core 设置时的取值（与 iOS 档位相同，偏保守）。
    pub const DEFAULT: Limits = Limits {
        buffer_budget: 6 * 1024 * 1024,
        workers: 1,
    };
    const MAX_WORKERS: usize = 8;
}

/// 内存压力等级：只有宿主上报可用内存的平台（iOS）会高于 `Normal`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Pressure {
    Normal = 0,
    /// 不再扩容，空闲收回提前。
    Elevated = 1,
    /// 不再扩容，扩容过的缓冲一旦为空立即收回。
    Critical = 2,
}

impl Pressure {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Elevated,
            2 => Self::Critical,
            _ => Self::Normal,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }

    /// 扩容过的缓冲空闲多久后收回到初始大小。
    pub(crate) fn idle_shrink(self) -> Duration {
        match self {
            Self::Normal => Duration::from_secs(5),
            Self::Elevated => Duration::from_secs(1),
            Self::Critical => Duration::ZERO,
        }
    }
}

struct Global {
    budget: AtomicUsize,
    used: AtomicUsize,
    workers: AtomicUsize,
    pressure: AtomicU8,
}

impl Global {
    const fn new() -> Self {
        Global {
            budget: AtomicUsize::new(Limits::DEFAULT.buffer_budget),
            used: AtomicUsize::new(0),
            workers: AtomicUsize::new(Limits::DEFAULT.workers),
            pressure: AtomicU8::new(Pressure::Normal as u8),
        }
    }
}

#[cfg(not(test))]
static GLOBAL_STATE: Global = Global::new();

#[cfg(not(test))]
fn global() -> &'static Global {
    &GLOBAL_STATE
}

// 测试并行运行：每个测试线程一份预算与压力，互不干扰（直接在测试线程上驱动 Engine 的测试才依赖它）。
#[cfg(test)]
fn global() -> &'static Global {
    thread_local!(static STATE: &'static Global = Box::leak(Box::new(Global::new())));
    STATE.with(|g| *g)
}

/// 设置进程级资源政策。预算随时生效（已持有的租约不收回，只影响之后的申请）；
/// 工作线程数在线程启动后不再改变。
pub fn configure(limits: Limits) {
    global()
        .budget
        .store(limits.buffer_budget, Ordering::Relaxed);
    if WORKERS.get().is_none() {
        global().workers.store(
            limits.workers.clamp(1, Limits::MAX_WORKERS),
            Ordering::Relaxed,
        );
    }
}

pub fn set_pressure(pressure: Pressure) {
    global().pressure.store(pressure as u8, Ordering::Relaxed);
}

pub fn pressure() -> Pressure {
    Pressure::from_u8(global().pressure.load(Ordering::Relaxed))
}

/// 当前缓冲用量与上限（字节），供诊断。
pub fn buffer_usage() -> (usize, usize) {
    (
        global().used.load(Ordering::Relaxed),
        global().budget.load(Ordering::Relaxed),
    )
}

/// 已启动的工作线程数（未启动为 0）。
pub fn workers_started() -> usize {
    WORKERS.get().map_or(0, |w| w.handles.len())
}

/// 从全局预算里尝试再拿 `bytes`。
fn take(bytes: usize) -> bool {
    let budget = global().budget.load(Ordering::Relaxed);
    global()
        .used
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            used.checked_add(bytes).filter(|&n| n <= budget)
        })
        .is_ok()
}

fn give_back(bytes: usize) {
    global().used.fetch_sub(bytes, Ordering::AcqRel);
}

/// 一条连接占用的全局缓冲预算；Drop 时归还。
#[derive(Debug)]
pub(crate) struct Lease {
    bytes: usize,
}

impl Lease {
    /// 申请 `bytes`；预算不够返回 None。
    pub(crate) fn acquire(bytes: usize) -> Option<Lease> {
        // 不能写成 `then_some(Lease { .. })`：失败时临时租约被 Drop，会把没拿到的字节「归还」
        if take(bytes) {
            Some(Lease { bytes })
        } else {
            None
        }
    }

    /// 把租约调整到 `bytes`：变大时向预算申请增量，申请不到返回 false 且不变；变小时归还差额。
    pub(crate) fn resize(&mut self, bytes: usize) -> bool {
        if bytes > self.bytes {
            if !take(bytes - self.bytes) {
                return false;
            }
        } else {
            give_back(self.bytes - bytes);
        }
        self.bytes = bytes;
        true
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        give_back(self.bytes);
    }
}

struct Workers {
    handles: Vec<Handle>,
    next: AtomicUsize,
}

static WORKERS: OnceLock<Workers> = OnceLock::new();

fn workers() -> &'static Workers {
    WORKERS.get_or_init(|| {
        let n = global().workers.load(Ordering::Relaxed);
        let handles = (0..n)
            .map(|i| {
                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                std::thread::Builder::new()
                    .name(format!("oryn-wg-{i}"))
                    .spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("wireguard worker runtime");
                        tx.send(rt.handle().clone())
                            .expect("wireguard worker handle");
                        // 常驻进程：引擎 task 随各自的 Tunnel 结束
                        rt.block_on(std::future::pending::<()>());
                    })
                    .expect("spawn wireguard worker thread");
                rx.recv().expect("wireguard worker started")
            })
            .collect();
        log::info!("wireguard: {n} engine worker thread(s)");
        Workers {
            handles,
            next: AtomicUsize::new(0),
        }
    })
}

/// 把引擎 task 投到某个工作线程（轮转）。
pub(crate) fn spawn<F>(future: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let w = workers();
    let i = w.next.fetch_add(1, Ordering::Relaxed) % w.handles.len();
    w.handles[i].spawn(future)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    /// 全局预算是进程级的，涉及它的测试串行执行。
    pub(crate) static SERIAL: Mutex<()> = Mutex::new(());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_respects_budget_and_returns_on_drop() {
        let _g = test_support::SERIAL
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let base = buffer_usage().0;
        configure(Limits {
            buffer_budget: base + 100,
            workers: 1,
        });
        let mut a = Lease::acquire(60).unwrap();
        assert!(Lease::acquire(41).is_none());
        let b = Lease::acquire(40).unwrap();
        assert_eq!(buffer_usage().0, base + 100);
        // 扩不了：不变
        assert!(!a.resize(61));
        assert_eq!(buffer_usage().0, base + 100);
        // 缩小归还差额
        assert!(a.resize(10));
        assert_eq!(buffer_usage().0, base + 50);
        assert!(a.resize(60));
        drop(b);
        drop(a);
        assert_eq!(buffer_usage().0, base);
        configure(Limits::DEFAULT);
    }

    #[test]
    fn pressure_controls_idle_shrink() {
        assert_eq!(Pressure::Normal.idle_shrink(), Duration::from_secs(5));
        assert_eq!(Pressure::Elevated.idle_shrink(), Duration::from_secs(1));
        assert_eq!(Pressure::Critical.idle_shrink(), Duration::ZERO);
        assert!(Pressure::Critical > Pressure::Elevated);
    }
}
