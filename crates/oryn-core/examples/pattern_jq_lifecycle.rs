//! 合成 Plan 生命周期测量；无 JS、文件资源或网络。固定 100 regex + 3 jq。
//! 单线程 GlobalAlloc 请求字节计数，不代表 RSS/footprint 或分配器实际块大小。
//! 每阶段 peak 独立重置到入口 live；输出放在全部测量之后，避免日志污染。
use oryn_http_inspect::{compile_module, Message, Plan};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    fmt::Write,
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
// 仅在 System 成功后记账；realloc 只记录净增量，不虚构旧新块同时存活。
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            added(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            added(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, n: usize) -> *mut u8 {
        let out = unsafe { System.realloc(p, layout, n) };
        if !out.is_null() {
            if n >= layout.size() {
                added(n - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - n, Relaxed);
            }
        }
        out
    }
}
#[global_allocator]
static ALLOC: Counting = Counting;

struct Sample {
    label: &'static str,
    before: usize,
    live: usize,
    peak: usize,
    ns: u128,
}
fn measure<T>(rows: &mut Vec<Sample>, label: &'static str, f: impl FnOnce() -> T) -> T {
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    let start = Instant::now();
    let result = f();
    let ns = start.elapsed().as_nanos();
    let live = LIVE.load(Relaxed);
    let peak = PEAK.load(Relaxed);
    rows.push(Sample {
        label,
        before,
        live,
        peak,
        ns,
    });
    result
}
fn load() -> Plan {
    let mut text = String::from("[Rewrite]\n");
    for i in 0..100 {
        // 所有前缀都是 https://wide.example/；完整匹配必须含对应数字和 /hit。
        writeln!(text, r#"response if ${{url}} ~= /^https:\/\/wide\.example\/(?:item{i})\/[0-9]+\/hit$/ then response.header.set("X-Unexpected", "hit")"#).unwrap();
    }
    for (i, filter) in [
        ".ok = 1",
        ".ok = 2 | del(.ad)",
        ".ok = 3 | .items |= map(. + 1)",
    ]
    .iter()
    .enumerate()
    {
        writeln!(
            text,
            r#"response if ${{url}} == "https://jq.example/{i}" then response.json.jq("{filter}")"#
        )
        .unwrap();
    }
    let ir = oryn_module::parse(&text, Some(oryn_module::ModuleFormat::Loon)).unwrap();
    let plan = compile_module(&ir, &Default::default(), &Default::default()).unwrap();
    assert_eq!(plan.response.len(), 103);
    assert!(plan.warnings.is_empty());
    assert!(plan.scripts.is_empty());
    plan
}
const BODY: &[u8] = br#"{"ad":true,"items":[1,2],"ok":0}"#;
fn apply(plan: &Plan, url: &str, expected_ok: Option<u64>) {
    let mut response = Message {
        url: url.into(),
        method: "GET".into(),
        status: Some(200),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: BODY.to_vec(),
    };
    let request = response.clone();
    plan.apply_response(&mut response, &request).unwrap();
    assert!(response.header("X-Unexpected").is_none());
    if let Some(ok) = expected_ok {
        let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["ok"], ok);
        if ok == 2 {
            assert!(value.get("ad").is_none());
        }
        if ok == 3 {
            assert_eq!(value["items"], serde_json::json!([2, 3]));
        }
    } else {
        assert_eq!(response.body, BODY);
    }
    // 响应、请求、校验临时值均在阶段结束前释放，仅 Plan 持续存活。
}
fn main() {
    let mut rows = Vec::with_capacity(16);
    let plan = measure(&mut rows, "load", load);
    measure(&mut rows, "unmatched_host", || {
        apply(&plan, "https://other.example/miss", None)
    });
    measure(&mut rows, "wide_prefix_first_fail", || {
        apply(&plan, "https://wide.example/miss", None)
    });
    measure(&mut rows, "wide_prefix_repeat_fail", || {
        apply(&plan, "https://wide.example/miss", None)
    });
    for (url, first, repeat, ok) in [
        ("https://jq.example/0", "jq_0_first", "jq_0_repeat", 1),
        ("https://jq.example/1", "jq_1_first", "jq_1_repeat", 2),
        ("https://jq.example/2", "jq_2_first", "jq_2_repeat", 3),
    ] {
        measure(&mut rows, first, || apply(&plan, url, Some(ok)));
        measure(&mut rows, repeat, || apply(&plan, url, Some(ok)));
    }
    measure(&mut rows, "drop_plan", || drop(plan));
    println!("stage,before_live_B,live_B,live_delta_B,stage_peak_B,peak_above_entry_B,elapsed_ns");
    for row in rows {
        println!(
            "{},{},{},{},{},{},{}",
            row.label,
            row.before,
            row.live,
            row.live as i128 - row.before as i128,
            row.peak,
            row.peak - row.before,
            row.ns
        );
    }
}
