//! Pattern / Plan 冷热 clone 链；请求堆阶段峰值，不是 footprint。
use oryn_http_inspect::{Action, CompiledRule, Condition, Expr, Message, Pattern, Plan};
use std::{
    alloc::{GlobalAlloc, Layout, System},
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

const INPUT: &str = "https://clone.test/item/42";
fn message() -> Message {
    Message {
        url: INPUT.into(),
        method: "GET".into(),
        status: None,
        headers: vec![],
        body: b"item/42".to_vec(),
    }
}
fn run(plan: &Plan) {
    let mut m = message();
    assert!(plan.apply_request(&mut m).unwrap().is_none());
    assert_eq!(m.header("X-Capture"), Some("42"));
    assert_eq!(m.body, b"value=42");
    assert_eq!(m.url, INPUT);
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let kind = args.get(1).expect("meta-prefix|meta|fancy-prefix|fancy");
    let warm = args.get(2).expect("cold|warm") == "warm";
    let source = match kind.as_str() {
        "meta-prefix" => r"^https://clone\.test/item/(\d+)$",
        "meta" => r"item/(\d+)$",
        "fancy-prefix" => r"^https://clone\.test/item/(?=\d)(\d+)$",
        "fancy" => r"item/(?=\d)(\d+)$",
        _ => panic!("unknown case"),
    };
    let mut rows = Vec::with_capacity(10);
    let (p, plan) = measure(&mut rows, "load", 1, || {
        let p = Pattern::new(source, "").unwrap();
        let plan = Plan {
            request: vec![CompiledRule {
                condition: Condition::Match(
                    Expr::Variable("url".into()),
                    p.clone(),
                    Some("cap".into()),
                ),
                actions: vec![
                    Action::HeaderSet("X-Capture".into(), Expr::Template("${cap.1}".into())),
                    Action::BodyRegex(
                        Pattern::new(r"item/(\d+)", "").unwrap(),
                        Expr::Literal("value=$1".into()),
                    ),
                ],
                dialect: oryn_module::ModuleFormat::Loon,
                source: String::new(),
            }],
            ..Plan::default()
        };
        (p, plan)
    });
    measure(&mut rows, "warm_source", usize::from(warm), || {
        if warm {
            assert!(p.matches(INPUT));
            run(&plan);
        }
    });
    let (ps, plans) = measure(&mut rows, "clone_chain", 32, || {
        let mut ps = vec![p];
        let mut plans = vec![plan];
        for _ in 1..32 {
            ps.push(ps.last().unwrap().clone());
            plans.push(plans.last().unwrap().clone());
        }
        (ps, plans)
    });
    measure(&mut rows, "prefix_miss", 32, || {
        for p in &ps {
            assert!(!p.matches("https://other.test/no"));
        }
    });
    let sweep = || {
        for (p, plan) in ps.iter().zip(&plans) {
            assert!(p.matches(INPUT));
            run(plan);
        }
    };
    measure(&mut rows, "first", 32, sweep);
    measure(&mut rows, "repeat", 32, sweep);
    measure(&mut rows, "hot", 32000, || {
        for _ in 0..1000 {
            sweep();
        }
    });
    // Plan 含 Rc<jq>，从来不是 Send；仅 Pattern 做线程共享性能与 trait 验证。
    measure(&mut rows, "threads", 400000, || {
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|s| {
            for p in &ps[..4] {
                let barrier = &barrier;
                s.spawn(move || {
                    barrier.wait();
                    for _ in 0..100000 {
                        assert!(p.matches(std::hint::black_box(INPUT)));
                    }
                });
            }
        });
    });
    measure(&mut rows, "drop", 0, || drop((ps, plans)));
    println!("kind,warm,stage,before,live,peak,ns,runs");
    for r in rows {
        println!(
            "{kind},{warm},{},{},{},{},{},{}",
            r.label, r.before, r.live, r.peak, r.ns, r.runs
        );
    }
}
