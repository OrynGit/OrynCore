//! 合成模块启动/热重载基线。参数：modules nodes rules scratch-directory。
//! 独立进程运行一个 case；必须配合 deny network sandbox，不接入任何真实配置。
#[allow(dead_code)]
mod survey {
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

    // 沿用 startup_survey 的配置、Counting<System>、Darwin footprint 和栈上采样。
    pub fn run() {
        let args: Vec<_> = std::env::args().collect();
        assert_eq!(
            args.len(),
            5,
            "usage: extension_budget_startup <modules> <nodes> <rules> <scratch-directory>"
        );
        let modules: usize = args[1].parse().unwrap();
        let nodes: usize = args[2].parse().unwrap();
        let rules: usize = args[3].parse().unwrap();
        assert!(matches!(modules, 0 | 20 | 50));
        assert!(matches!(nodes, 100 | 1000));
        assert!(matches!(rules, 1000 | 10000));
        let dir = std::path::Path::new(&args[4]);
        assert!(dir.is_absolute());
        // 新目录避免误读用户缓存；只创建一个安全的本机脚本，不注册事件脚本。
        std::fs::create_dir(dir).expect("scratch-directory must not already exist");
        std::fs::create_dir(dir.join("modules")).unwrap();
        std::fs::write(dir.join("modules/noop.js"), "$done({});\n").unwrap();
        let options = serde_json::to_vec(&serde_json::json!({
            "local_proxy":{"enabled":false}, "data_dir":dir, "maxmind":null
        }))
        .unwrap();
        let mut samples = [Sample::default(); 13];
        samples[0] = sample("baseline", 0);
        let begin = Instant::now();
        let mut config = synthetic_config(nodes, rules);
        if modules > 0 {
            config.push_str("modules:\n");
            for m in 0..modules {
                writeln!(config, "  - format: surge\n    inline: |\n      #!name=synthetic-{m}\n      [Rule]\n      DOMAIN,module-{m}.invalid,REJECT\n      [URL Rewrite]\n      ^http://module-{m}\\.invalid/ad reject\n      [Script]\n      noop-{m} = type=http-response, pattern=^http://module-{m}\\.invalid/body, script-path=noop.js, requires-body=true").unwrap();
            }
        }
        let bytes = config.len();
        samples[1] = sample("config_ready", begin.elapsed().as_micros());
        let begin = Instant::now();
        let mut engine = oryn_core::Engine::new(config.as_bytes(), &options).unwrap();
        assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
        samples[2] = sample("new", begin.elapsed().as_micros());
        let begin = Instant::now();
        engine.start_proxy_only().unwrap();
        samples[3] = sample("start", begin.elapsed().as_micros());
        assert_modules(&engine, modules);
        std::thread::sleep(Duration::from_millis(1200));
        samples[4] = sample("idle_1200ms", 0);
        // 改变 mode 作为异步 apply_config 完成屏障，不把 scheduled 响应当完成。
        let begin = Instant::now();
        let reload = serde_json::to_vec(&serde_json::json!({"cmd":"reload", "config":config.replacen("mode: rule", "mode: global", 1)})).unwrap();
        samples[5] = sample("reload_input", begin.elapsed().as_micros());
        let begin = Instant::now();
        let response = engine.command(&reload);
        assert_eq!(response["ok"], true, "{response}");
        drop(response);
        samples[6] = sample("reload_scheduled", begin.elapsed().as_micros());
        loop {
            if engine.command(br#"{"cmd":"stats"}"#)["mode"] == "global" {
                break;
            }
            assert!(begin.elapsed() < Duration::from_secs(30), "reload timeout");
            std::thread::sleep(Duration::from_millis(1));
        }
        samples[7] = sample("reload_applied", begin.elapsed().as_micros());
        assert_modules(&engine, modules);
        drop(reload);
        std::thread::sleep(Duration::from_millis(100));
        samples[8] = sample("reload_settled", 0);
        let begin = Instant::now();
        engine.stop(); // 取消后台任务并 join；不是刻意中断正在编译的 reload。
        samples[9] = sample("stop_join", begin.elapsed().as_micros());
        drop(engine);
        samples[10] = sample("drop_engine", 0);
        drop(config);
        drop(options);
        samples[11] = sample("drop_inputs", 0);
        std::thread::sleep(Duration::from_millis(100));
        samples[12] = sample("post_drop_100ms", 0);
        println!("modules,nodes,rules_extra,config_bytes,phase,elapsed_us,heap_live_bytes,heap_peak_bytes,phys_footprint_bytes");
        for s in samples {
            println!(
                "{modules},{nodes},{rules},{bytes},{},{},{},{},{}",
                s.phase, s.elapsed_us, s.live, s.peak, s.footprint
            );
        }
    }
    fn assert_modules(engine: &oryn_core::Engine, expected: usize) {
        let warnings = engine.command(br#"{"cmd":"warnings"}"#);
        let items = warnings["warnings"].as_array().unwrap();
        assert!(items.is_empty(), "{warnings}");
        let modules = engine.command(br#"{"cmd":"module_status"}"#);
        let list = modules["modules"].as_array().expect("modules command");
        assert_eq!(list.len(), expected);
        assert!(
            list.iter()
                .all(|m| m["enabled"] == true && m["metadata"].is_object()),
            "{modules}"
        );
    }
}
fn main() {
    survey::run();
}
