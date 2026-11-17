//! 内存测量：用给定配置以 proxy-only 模式启动 Engine，按时间线打印进程 phys_footprint、
//! Rust 堆的当前 / 峰值字节，与 Core 日志交错输出，用来定位哪个阶段涨了内存。
//!
//! ```bash
//! cargo run --release -p oryn-core --example footprint -- <config.yaml> <data_dir> [秒数]
//! ```
//!
//! macOS 的 footprint 与 iOS Extension 不完全一致（系统库、映射方式不同），但 Rust 堆的数值可比。
//! 环境变量 `ORYN_FOOTPRINT_BIG=<KiB>`：打印不小于该大小的单次分配（默认 1024 KiB）；
//! `ORYN_FOOTPRINT_PROXY=<端口>`：开启本地 HTTP / SOCKS5 代理，用外部工具经它灌流量；
//! `ORYN_FOOTPRINT_RELOADS=<n>`：启动后每 3 秒发一次 `reload`（模拟代理集合更新后的重新编译）。
//! 加 `--features mimalloc` 时底层分配器与 Extension 相同（mimalloc + 定期整理），否则为系统 malloc。

use std::alloc::{GlobalAlloc, Layout};

#[cfg(feature = "mimalloc")]
use mimalloc::MiMalloc as Inner;
#[cfg(not(feature = "mimalloc"))]
use std::alloc::System as Inner;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static BIG: AtomicUsize = AtomicUsize::new(1024 * 1024);
static BIG_SEEN: AtomicUsize = AtomicUsize::new(0);

fn record_alloc(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
    if size >= BIG.load(Ordering::Relaxed) {
        BIG_SEEN.fetch_add(1, Ordering::Relaxed);
        // 不能在分配器里分配：直接写 stderr
        let mut buf = [0u8; 64];
        let s = fmt_kib(&mut buf, size);
        unsafe { libc::write(2, s.as_ptr() as *const _, s.len()) };
    }
}

fn fmt_kib(buf: &mut [u8; 64], size: usize) -> &[u8] {
    let prefix = b"[footprint] big alloc ";
    let mut n = prefix.len();
    buf[..n].copy_from_slice(prefix);
    let mut digits = [0u8; 20];
    let mut v = size / 1024;
    let mut d = 0;
    loop {
        digits[d] = b'0' + (v % 10) as u8;
        d += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while d > 0 {
        d -= 1;
        buf[n] = digits[d];
        n += 1;
    }
    for &c in b" KiB\n" {
        buf[n] = c;
        n += 1;
    }
    &buf[..n]
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = Inner.alloc(layout);
        if !p.is_null() {
            record_alloc(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = Inner.alloc_zeroed(layout);
        if !p.is_null() {
            record_alloc(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        Inner.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = Inner.realloc(ptr, layout, new_size);
        if !p.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            record_alloc(new_size);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn footprint() -> usize {
    let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V4,
            &mut info as *mut _ as *mut libc::rusage_info_t,
        )
    };
    if rc == 0 {
        info.ri_phys_footprint as usize
    } else {
        0
    }
}

fn mib(n: usize) -> f64 {
    n as f64 / (1024.0 * 1024.0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: footprint <config.yaml> <data_dir> [seconds]");
        std::process::exit(2);
    }
    if let Some(kib) = std::env::var("ORYN_FOOTPRINT_BIG").ok().and_then(|v| v.parse::<usize>().ok()) {
        BIG.store(kib * 1024, Ordering::Relaxed);
    }
    let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(60);
    let config = std::fs::read(&args[1]).expect("read config");
    std::fs::create_dir_all(&args[2]).expect("data dir");
    let started = Instant::now();
    let stamp = move || started.elapsed().as_secs_f64();
    let base = (footprint(), LIVE.load(Ordering::Relaxed));
    println!(
        "{:7.2}s  start  footprint {:6.2} MiB  heap {:6.2} MiB",
        0.0,
        mib(base.0),
        mib(base.1)
    );
    oryn_core::logging::set_callback(Some(Box::new(move |level, msg| {
        if level <= log::Level::Info {
            let line: String = msg.chars().take(140).collect();
            println!(
                "{:7.2}s  [{:5}] heap {:6.2} MiB  {line}",
                stamp(),
                level,
                mib(LIVE.load(Ordering::Relaxed))
            );
        }
    })));
    // ORYN_FOOTPRINT_PROXY=<HTTP 端口>：在该端口（SOCKS5 为其 +1）开启本地代理，用来从外部灌流量
    let mut options = serde_json::json!({ "data_dir": args[2] });
    if let Some(port) = std::env::var("ORYN_FOOTPRINT_PROXY").ok().and_then(|v| v.parse::<u16>().ok()) {
        options["local_proxy"] = serde_json::json!({ "enabled": true, "http_port": port, "socks_port": port + 1 });
    }
    let options = options.to_string();
    let mut engine = oryn_core::Engine::new(&config, options.as_bytes()).expect("engine");
    println!(
        "{:7.2}s  compiled  footprint {:6.2} MiB  heap {:6.2} MiB",
        started.elapsed().as_secs_f64(),
        mib(footprint()),
        mib(LIVE.load(Ordering::Relaxed))
    );
    engine.start_proxy_only().expect("start");
    let reloads: usize = std::env::var("ORYN_FOOTPRINT_RELOADS").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let text = String::from_utf8_lossy(&config).into_owned();
    let mut next_reload = Instant::now() + Duration::from_secs(5);
    let mut reloaded = 0;
    let mut peak_fp = 0usize;
    let end = Instant::now() + Duration::from_secs(secs);
    let mut last = (0usize, 0usize);
    while Instant::now() < end {
        std::thread::sleep(Duration::from_millis(200));
        if reloaded < reloads && Instant::now() >= next_reload {
            let req = serde_json::json!({"cmd": "reload", "config": text}).to_string();
            let reply = engine.command(req.as_bytes());
            reloaded += 1;
            next_reload = Instant::now() + Duration::from_secs(3);
            println!(
                "{:7.2}s  reload #{reloaded} → {}  footprint {:6.2} MiB  heap {:6.2} MiB",
                started.elapsed().as_secs_f64(),
                reply.get("ok").map_or("error", |_| "ok"),
                mib(footprint()),
                mib(LIVE.load(Ordering::Relaxed))
            );
        }
        let fp = footprint();
        let live = LIVE.load(Ordering::Relaxed);
        peak_fp = peak_fp.max(fp);
        // 只在变化超过 0.5 MiB 时打印
        if fp.abs_diff(last.0) > 512 * 1024 || live.abs_diff(last.1) > 512 * 1024 {
            println!(
                "{:7.2}s  sample  footprint {:6.2} MiB  heap {:6.2} MiB  heap peak {:6.2} MiB",
                started.elapsed().as_secs_f64(),
                mib(fp),
                mib(live),
                mib(PEAK.load(Ordering::Relaxed))
            );
            last = (fp, live);
        }
    }
    let before = footprint();
    oryn_core::alloc::trim();
    println!(
        "trim  footprint {:6.2} → {:6.2} MiB (main thread)",
        mib(before),
        mib(footprint())
    );
    println!(
        "end  footprint {:6.2} MiB (peak {:6.2})  heap {:6.2} MiB (peak {:6.2})  big allocs {}",
        mib(footprint()),
        mib(peak_fp),
        mib(LIVE.load(Ordering::Relaxed)),
        mib(PEAK.load(Ordering::Relaxed)),
        BIG_SEEN.load(Ordering::Relaxed)
    );
    drop(engine);
}
