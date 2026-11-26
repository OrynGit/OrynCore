//! Oryn 执行配额钩子（原实现无此文件）。仅在当前运行线程设置，不跨请求保留预算。
use std::boxed::Box;
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};

/// 单次默认执行允许的单个逻辑值体积上限（4 MiB，与移动扩展正文上限对齐）。
pub const DEFAULT_MAX_VALUE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
struct Budget {
    steps: usize,
    bytes: usize,
    max_val: usize,
    depth: usize,
    end: Instant,
}

std::thread_local! {
    static BUDGET: RefCell<Option<Budget>> = const { RefCell::new(None) };
}

/// 超过预算使用不可被 jq try/catch 捕获的 unwind；宿主必须用 catch_unwind 包裹一次完整执行。
#[derive(Debug)]
pub struct Exhausted;

/// 按默认正文上限（4 MiB）启用当前线程配额。
pub fn start() {
    start_with(DEFAULT_MAX_VALUE_BYTES);
}

/// 按调用方正文上限启用当前线程配额（移动 4 MiB / 桌面 8 MiB 等）。
///
/// 单个逻辑值按 `max_body * 2`（至少 8 MiB）设限，避免 2–4 MiB JSON 因容器头与标量开销误触发；
/// 累计流过体积按 `max_val * 8` 计费（允许管线多阶段传递同一正文），同时保留时间、步数和深度硬顶。
pub fn start_with(max_body: usize) {
    let max_val = max_body
        .saturating_mul(2)
        .max(DEFAULT_MAX_VALUE_BYTES * 2);
    let bytes = max_val.saturating_mul(8);
    BUDGET.with(|b| {
        *b.borrow_mut() = Some(Budget {
            steps: 2_000_000,
            bytes,
            max_val,
            depth: 0,
            // 与 HTTP 改写总预算（500 ms）对齐，避免 2–4 MiB JSON 在移动降频或调试构建下误超时。
            end: Instant::now() + Duration::from_millis(500),
        })
    });
}

/// 当前线程允许的单个逻辑值体积上限；未启用配额时返回默认上限的 2 倍（8 MiB）。
pub fn max_value_bytes() -> usize {
    BUDGET.with(|b| {
        b.borrow()
            .as_ref()
            .map_or(DEFAULT_MAX_VALUE_BYTES * 2, |v| v.max_val)
    })
}

/// 清除配额。
pub fn clear() {
    BUDGET.with(|b| *b.borrow_mut() = None);
}

/// 每个解释步骤及 iterator 输出检查时间和累计值体积。
pub fn charge(bytes: usize) {
    let exceeded = BUDGET.with(|b| {
        let mut b = b.borrow_mut();
        let Some(v) = b.as_mut() else {
            return false;
        };
        if v.steps == 0
            || bytes > v.bytes
            || ((v.steps & 0xff) == 0 && Instant::now() >= v.end)
        {
            return true;
        }
        v.steps -= 1;
        v.bytes -= bytes;
        false
    });
    if exceeded {
        std::panic::resume_unwind(Box::new(Exhausted));
    }
}

/// 一次同步求值调用的栈深度守卫。
pub struct Depth;

/// 进入解释器同步调用。
pub fn enter() -> Depth {
    charge(0);
    let exceeded = BUDGET.with(|b| {
        if let Some(v) = b.borrow_mut().as_mut() {
            v.depth += 1;
            v.depth > 128
        } else {
            false
        }
    });
    if exceeded {
        std::panic::resume_unwind(Box::new(Exhausted));
    }
    Depth
}

impl Drop for Depth {
    fn drop(&mut self) {
        BUDGET.with(|b| {
            if let Some(v) = b.borrow_mut().as_mut() {
                v.depth = v.depth.saturating_sub(1);
            }
        });
    }
}
