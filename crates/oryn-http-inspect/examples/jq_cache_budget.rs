//! 唯一 jq 保留预算：仅 public Program/Rc harness，不调用或修改产品 Plan。
//! 用法：jq_cache_budget permanent|lru8|lru16 scan|mixed
//! 固定32唯一安全filter；scan依序访问32项，mixed每个冷项前访问4热点。
//! cold为首次完整trace，hot为继续重复20次trace（不保证LRU命中）。
//! 各策略从空cache开始，miss执行compile+run；不包含产品加载逐声明验证。
//! compile_calls为公开API次数；lazy_builds_inferred为新Program首次run次数，
//! 当前实现每个miss实际build两次，后者是依据API实现推算而非内部探针。
//! 请求堆live/阶段peak包含harness，不是RSS/footprint或iOS预算验收。
use oryn_jq::Program;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::Instant,
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn added(n: usize) {
    let live = LIVE.fetch_add(n, Relaxed) + n;
    PEAK.fetch_max(live, Relaxed);
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            added(l.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(l) };
        if !p.is_null() {
            added(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let out = unsafe { System.realloc(p, l, n) };
        if !out.is_null() {
            if n >= l.size() {
                added(n - l.size());
            } else {
                LIVE.fetch_sub(l.size() - n, Relaxed);
            }
        }
        out
    }
}
#[global_allocator]
static ALLOC: Counting = Counting;

// 永久策略不维护LRU次序；容量策略按最旧→最新排列。最多32项线性查找，
// 有意保留小缓存的查找/Rc维护开销；所有外借Rc在下一次请求前释放。
struct Cache {
    entries: Vec<(usize, Rc<Program>)>,
    capacity: usize,
    permanent: bool,
    compiles: usize,
}
impl Cache {
    fn get(&mut self, id: usize, source: &str) -> Rc<Program> {
        if let Some(i) = self.entries.iter().position(|(key, _)| *key == id) {
            if self.permanent {
                return Rc::clone(&self.entries[i].1);
            }
            let entry = self.entries.remove(i);
            let program = Rc::clone(&entry.1);
            self.entries.push(entry);
            return program;
        }
        // 先释放被逐出项，再编译，避免人为制造capacity+1峰值。
        if self.entries.len() == self.capacity {
            self.entries.remove(0);
        }
        self.compiles += 1;
        let program = Rc::new(Program::compile(source).unwrap());
        self.entries.push((id, Rc::clone(&program)));
        program
    }
}
struct Row {
    stage: &'static str,
    runs: usize,
    compiles: usize,
    before: usize,
    live: usize,
    peak: usize,
    ns: u128,
    entries: usize,
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).expect("permanent|lru8|lru16 required");
    let pattern = args.get(2).expect("scan|mixed required");
    assert_eq!(args.len(), 3);
    let capacity = match mode.as_str() {
        "permanent" => 32,
        "lru8" => 8,
        "lru16" => 16,
        _ => panic!("expected permanent|lru8|lru16"),
    };
    // 相同复杂度，不靠空白制造唯一源码；每个filter有不同且完整验证的输出。
    let sources: Vec<_> = (0..32).map(|i| format!(".ok = {i} | del(.ad)")).collect();
    let input = serde_json::json!({"ad": true, "items": [1, 2], "ok": -1});
    let expected: Vec<_> = (0..32)
        .map(|i| serde_json::json!({"items": [1, 2], "ok": i}))
        .collect();
    let trace: Vec<usize> = match pattern.as_str() {
        "scan" => (0..32).collect(),
        "mixed" => (4..32).flat_map(|cold| [0, 1, 2, 3, cold]).collect(),
        _ => panic!("expected scan|mixed"),
    };
    let mut rows = Vec::with_capacity(3);
    let baseline = LIVE.load(Relaxed);
    let mut cache = Cache {
        entries: Vec::with_capacity(capacity),
        capacity,
        permanent: mode == "permanent",
        compiles: 0,
    };
    for (stage, repeats) in [("cold", 1), ("hot", 20)] {
        let before = LIVE.load(Relaxed);
        PEAK.store(before, Relaxed);
        let compiles = cache.compiles;
        let start = Instant::now();
        for _ in 0..repeats {
            for &id in &trace {
                let program = cache.get(id, &sources[id]);
                let output = program.run(&input).unwrap();
                assert_eq!(output, expected[id]);
                std::hint::black_box(output);
            }
        }
        let ns = start.elapsed().as_nanos();
        rows.push(Row {
            stage,
            runs: repeats * trace.len(),
            compiles: cache.compiles - compiles,
            before,
            live: LIVE.load(Relaxed),
            peak: PEAK.load(Relaxed),
            ns,
            entries: cache.entries.len(),
        });
    }
    drop(cache);
    let after_drop = LIVE.load(Relaxed);
    assert_eq!(after_drop, baseline, "cache must release all retained heap");
    println!("mode,pattern,stage,runs,compile_calls,lazy_builds_inferred,entries,baseline_B,before_B,live_B,retained_B,peak_B,peak_above_baseline_B,elapsed_ns,ns_per_run,after_drop_B");
    for r in rows {
        println!(
            "{mode},{pattern},{},{},{},{},{},{baseline},{},{},{},{},{},{},{:.1},{after_drop}",
            r.stage,
            r.runs,
            r.compiles,
            r.compiles,
            r.entries,
            r.before,
            r.live,
            r.live - baseline,
            r.peak,
            r.peak - baseline,
            r.ns,
            r.ns as f64 / r.runs as f64
        );
    }
}
