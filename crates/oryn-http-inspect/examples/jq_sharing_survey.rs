//! 真实 Plan 生命周期，以及 public Program 的独立/同源码 Rc 对照。
//! plan 使用当前产品编译路径（含 Plan 共享）；baseline/shared 仅是 Program 对照，
//! 不能当作真实 Plan A/B。未共享 Plan 基线须保留旧 revision 的独立 binary/worktree。
//! 每条声明均 compile 校验，首次 run 仍懒编译，无全局 cache。
//! Rust 请求堆字节（非 malloc 块大小/RSS/footprint）；realloc 记净增量。
//! 用法：jq_sharing_survey plan|baseline|shared 40|2 [hot_sweeps=500]
//! 40 条交替重复两种 safe jq；2 条各一种，作为少量唯一声明对照。
use oryn_http_inspect::{compile_module, Message, Plan};
use oryn_jq::Program;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    fmt::Write,
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
struct Sample {
    label: &'static str,
    before: usize,
    live: usize,
    peak: usize,
    ns: u128,
    runs: usize,
}
fn measure<T>(
    rows: &mut Vec<Sample>,
    label: &'static str,
    runs: usize,
    f: impl FnOnce() -> T,
) -> T {
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    let start = Instant::now();
    let out = f();
    let ns = start.elapsed().as_nanos();
    let live = LIVE.load(Relaxed);
    let peak = PEAK.load(Relaxed);
    rows.push(Sample {
        label,
        before,
        live,
        peak,
        ns,
        runs,
    });
    out
}
const FILTERS: [&str; 2] = [".ok = 1", ".ok = 2 | del(.ad)"];
const BODY: &[u8] = br#"{"ad":true,"items":[1,2],"ok":0}"#;
const EXPECTED: [&[u8]; 2] = [
    br#"{"ad":true,"items":[1,2],"ok":1}"#,
    br#"{"items":[1,2],"ok":2}"#,
];
enum Runner {
    Plan(Plan),
    Independent(Vec<Program>),
    Shared(Vec<Rc<Program>>),
}
impl Runner {
    fn load(mode: &str, n: usize, text: &str) -> Self {
        match mode {
            "plan" => {
                let ir = oryn_module::parse(text, Some(oryn_module::ModuleFormat::Loon)).unwrap();
                let plan = compile_module(&ir, &Default::default(), &Default::default()).unwrap();
                assert_eq!(plan.response.len(), n);
                assert!(plan.warnings.is_empty());
                assert!(plan.scripts.is_empty());
                Self::Plan(plan)
            }
            "baseline" => Self::Independent(
                (0..n)
                    .map(|i| Program::compile(FILTERS[i % 2]).unwrap())
                    .collect(),
            ),
            "shared" => {
                let mut programs: Vec<Rc<Program>> = Vec::with_capacity(n);
                for i in 0..n {
                    // 不跳过重复声明的编译验证，保留逐条失败的机会及顺序。
                    let validated = Program::compile(FILTERS[i % 2]).unwrap();
                    let p = if i < 2 {
                        Rc::new(validated)
                    } else {
                        drop(validated);
                        Rc::clone(&programs[i % 2])
                    };
                    programs.push(p);
                }
                Self::Shared(programs)
            }
            _ => panic!("expected plan, baseline or shared"),
        }
    }
    fn sweep(&self, urls: &[String]) {
        for (i, url) in urls.iter().enumerate() {
            let bytes = match self {
                Self::Plan(p) => {
                    let mut response = Message {
                        url: url.clone(),
                        method: "GET".into(),
                        status: Some(200),
                        headers: vec![("Content-Type".into(), "application/json".into())],
                        body: BODY.to_vec(),
                    };
                    let request = response.clone();
                    p.apply_response(&mut response, &request).unwrap();
                    assert_eq!(response.status, Some(200));
                    assert_eq!(response.header("Content-Type"), Some("application/json"));
                    assert_eq!(
                        response.header("Content-Length"),
                        Some(EXPECTED[i % 2].len().to_string().as_str())
                    );
                    assert_eq!(response.url, request.url);
                    assert_eq!(response.method, request.method);
                    response.body
                }
                Self::Independent(ps) => run(&ps[i]),
                Self::Shared(ps) => run(&ps[i]),
            };
            // 每次运行均逐字节比较相同 oracle，不只比较 checksum / 某个字段。
            assert_eq!(bytes, EXPECTED[i % 2]);
            std::hint::black_box(bytes);
        }
    }
}
fn run(p: &Program) -> Vec<u8> {
    let input = serde_json::from_slice(BODY).unwrap();
    serde_json::to_vec(&p.run(&input).unwrap()).unwrap()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).expect("mode required");
    let n: usize = args.get(2).expect("count required").parse().unwrap();
    assert!(n == 40 || n == 2);
    let hot: usize = args.get(3).map_or(500, |v| v.parse().unwrap());
    assert!(hot > 0);
    let urls: Vec<_> = (0..n).map(|i| format!("https://jq.example/{i}")).collect();
    let mut text = String::from("[Rewrite]\n");
    for (i, url) in urls.iter().enumerate() {
        writeln!(
            text,
            r#"response if ${{url}} == "{url}" then response.json.jq("{}")"#,
            FILTERS[i % 2]
        )
        .unwrap();
    }
    let mut rows = Vec::with_capacity(5);
    let runner = measure(&mut rows, "load_validate_each", 0, || {
        Runner::load(mode, n, &text)
    });
    measure(&mut rows, "first_sweep", n, || runner.sweep(&urls));
    measure(&mut rows, "repeat_sweep", n, || runner.sweep(&urls));
    measure(&mut rows, "hot_sweeps", n * hot, || {
        for _ in 0..hot {
            runner.sweep(&urls);
        }
    });
    measure(&mut rows, "drop", 0, || drop(runner));
    println!("mode,count,stage,before_B,live_B,delta_B,peak_B,peak_above_entry_B,elapsed_ns,runs,runs_per_second");
    for r in rows {
        println!(
            "{mode},{n},{},{},{},{},{},{},{},{},{:.3}",
            r.label,
            r.before,
            r.live,
            r.live as i128 - r.before as i128,
            r.peak,
            r.peak - r.before,
            r.ns,
            r.runs,
            r.runs as f64 * 1e9 / r.ns as f64
        );
    }
}
