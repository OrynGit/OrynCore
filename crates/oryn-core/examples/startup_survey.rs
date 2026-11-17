//! 无流量启动调查：每次调用只运行一个合成 case，不读取配置或缓存目录。
//! 用法：startup_survey <nodes: 0|100|1000> <rules: 0|1000|10000>
//! rules 是额外 DOMAIN 规则数，另有一条 MATCH,REJECT。所有节点均为未拨号的环回假 SOCKS5。

use std::alloc::System;
use std::fmt::Write;
use std::time::{Duration, Instant};

use oryn_core::alloc::{heap_usage, Counting};

#[global_allocator]
static GLOBAL: Counting<System> = Counting(System);

#[derive(Clone, Copy, Default)]
struct Sample {
    phase: &'static str,
    elapsed_us: u128,
    live: usize,
    peak: usize,
    footprint: u64,
}

#[cfg(target_os = "macos")]
fn footprint() -> u64 {
    // SAFETY：系统按 rusage_info_v4 布局写入同尺寸结构。
    let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V4,
            &mut info as *mut _ as *mut libc::rusage_info_t,
        )
    };
    if rc == 0 {
        info.ri_phys_footprint
    } else {
        0
    }
}

#[cfg(not(target_os = "macos"))]
fn footprint() -> u64 {
    0 // 不支持或调用失败时为 0，不表示真实 footprint 为零。
}

fn sample(phase: &'static str, elapsed_us: u128) -> Sample {
    let (live, peak) = heap_usage().expect("Counting allocator installed");
    Sample {
        phase,
        elapsed_us,
        live,
        peak,
        footprint: footprint(),
    }
}

fn synthetic_config(nodes: usize, rules: usize) -> String {
    let mut config = String::from(
        "mode: rule\nlog-level: silent\ngeo-auto-update: false\n\
         geox-url: {mmdb: 'http://127.0.0.1:1/unused.mmdb', asn: ''}\n\
         dns:\n  public-ip-url: ''\n  nameserver: ['127.0.0.1:1']\n  default-nameserver: ['127.0.0.1:1']\n\
         proxy-groups: []\nproxy-providers: {}\nrule-providers: {}\n",
    );
    if nodes == 0 {
        config.push_str("proxies: []\n");
    } else {
        config.push_str("proxies:\n");
        for n in 0..nodes {
            writeln!(
                config,
                "  - {{name: fake-{n}, type: socks5, server: 127.0.0.1, port: 1, udp: false}}"
            )
            .unwrap();
        }
    }
    config.push_str("rules:\n");
    for n in 0..rules {
        writeln!(config, "  - DOMAIN,host-{n}.invalid,REJECT").unwrap();
    }
    config.push_str("  - MATCH,REJECT\n");
    config
}

fn main() {
    let (nodes, rules) = {
        let args: Vec<_> = std::env::args().collect();
        assert_eq!(args.len(), 3, "usage: startup_survey <nodes> <rules>");
        (
            args[1].parse::<usize>().expect("nodes"),
            args[2].parse::<usize>().expect("rules"),
        )
    };
    assert!(matches!(nodes, 0 | 100 | 1000), "unsupported node count");
    assert!(matches!(rules, 0 | 1000 | 10000), "unsupported rule count");
    // 数组放栈上，所有格式化输出推迟到测量完成，避免 stdout 初始化污染阶段差值。
    let mut samples = [Sample::default(); 8];
    samples[0] = sample("baseline", 0);
    let config = synthetic_config(nodes, rules);
    let config_bytes = config.len();
    // 不传 data_dir / maxmind / inspection_config，不读取用户缓存或脚本。
    let options = br#"{"local_proxy":{"enabled":false},"data_dir":null,"maxmind":null}"#;
    samples[1] = sample("config_ready", 0);
    let begin = Instant::now();
    let mut engine = oryn_core::Engine::new(config.as_bytes(), options).expect("Engine::new");
    samples[2] = sample("new", begin.elapsed().as_micros());
    assert!(
        engine.warnings().is_empty(),
        "unexpected config warnings: {:?}",
        engine.warnings()
    );
    let begin = Instant::now();
    engine.start_proxy_only().expect("start_proxy_only");
    samples[3] = sample("start", begin.elapsed().as_micros());
    // 超过 health 首次检查的 1 秒延迟；此配置没有任何 health 任务。
    std::thread::sleep(Duration::from_millis(1200));
    samples[4] = sample("idle_1200ms", 0);
    let begin = Instant::now();
    engine.stop(); // join 事件循环线程，不把尚未结束的 runtime 当作释放残留。
    samples[5] = sample("stop", begin.elapsed().as_micros());
    let begin = Instant::now();
    drop(engine);
    samples[6] = sample("drop_engine", begin.elapsed().as_micros());
    drop(config);
    samples[7] = sample("drop_inputs", 0);
    println!("nodes,rules_extra,config_bytes,phase,elapsed_us,heap_live_bytes,heap_peak_bytes,phys_footprint_bytes");
    for s in samples {
        println!(
            "{nodes},{rules},{config_bytes},{},{},{},{},{}",
            s.phase, s.elapsed_us, s.live, s.peak, s.footprint
        );
    }
}
