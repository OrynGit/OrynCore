//! 内存分配器：Core 堆用量统计与（可选的）空闲页回收。
//!
//! iOS / macOS 的系统 malloc 释放后不把空闲页还给系统：这些页仍是脏页，计入 `phys_footprint`，
//! 也就计入 Extension 约 50 MiB 的 jetsam 上限。实测（Darwin 27）分配约 40 MiB 再全部释放后，
//! footprint 仍是 40.7 MiB，`malloc_zone_pressure_relief` 回收 0 字节。
//!
//! 曾在 Extension 里改用 mimalloc（`mimalloc` 特性，配合 [`trim`]），本机测量有效，但真机上
//! 启动后几秒 footprint 就到 40–48 MiB、随即被杀（2026-11-08）：mimalloc 的堆按线程划分，
//! Extension 里有大量系统线程调用 Core，每个线程各占一批页面，`mi_collect` 又只整理调用线程。
//! 所以 Extension 现在用 [`Counting`] 包一层系统分配器，只统计 Core 堆的实际用量，供平台层
//! 在内存告警里与进程 footprint 对照。`mimalloc` 特性保留给本机实验（见 `examples/footprint.rs`）。

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::time::Duration;

/// 事件循环整理空闲页的间隔（只在开启 `mimalloc` 特性时有作用）。
pub const TRIM_INTERVAL: Duration = Duration::from_secs(2);

/// 把调用线程堆中已空的页面归还给系统；未开启 `mimalloc` 特性时什么也不做。
pub fn trim() {
    #[cfg(feature = "mimalloc")]
    // SAFETY：mi_collect 没有前置条件，可在任意线程调用。
    unsafe {
        libmimalloc_sys::mi_collect(true);
    }
}

static INSTALLED: AtomicBool = AtomicBool::new(false);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// 统计在用字节数与峰值的分配器包装。每次分配 / 释放只多两三次 relaxed 原子操作。
///
/// ```ignore
/// #[global_allocator]
/// static GLOBAL: oryn_core::alloc::Counting<std::alloc::System> = oryn_core::alloc::Counting(std::alloc::System);
/// ```
pub struct Counting<A>(pub A);

impl<A> Counting<A> {
    #[inline]
    fn add(size: usize) {
        let live = LIVE.fetch_add(size, Relaxed) + size;
        if live > PEAK.load(Relaxed) {
            PEAK.fetch_max(live, Relaxed);
            INSTALLED.store(true, Relaxed);
        }
    }
}

// SAFETY：所有调用原样转发给内层分配器，只额外更新计数。
unsafe impl<A: GlobalAlloc> GlobalAlloc for Counting<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = self.0.alloc(layout);
        if !p.is_null() {
            Self::add(layout.size());
        }
        p
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = self.0.alloc_zeroed(layout);
        if !p.is_null() {
            Self::add(layout.size());
        }
        p
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = self.0.realloc(ptr, layout, new_size);
        if !p.is_null() {
            // 先加后减，免得并发读到下溢的值
            Self::add(new_size);
            LIVE.fetch_sub(layout.size(), Relaxed);
        }
        p
    }
}

/// Core 堆（Rust 与经 `rust-alloc` 接入的 QuickJS）当前在用的字节数与峰值；
/// 全局分配器不是 [`Counting`] 时为 `None`。
pub fn heap_usage() -> Option<(usize, usize)> {
    INSTALLED.load(Relaxed).then(|| (LIVE.load(Relaxed), PEAK.load(Relaxed)))
}

/// 事件循环线程上的定期整理任务（只在开启 `mimalloc` 特性时启动）。
#[cfg(feature = "mimalloc")]
pub(crate) async fn trim_loop() {
    let mut tick = tokio::time::interval(TRIM_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        trim();
    }
}
