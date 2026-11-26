//! 模块、jq 与 HTTP 规则引擎前后对照基准（A/B 测量）：
//! 用法：`module_perf_bench <jq_compile_63|jq_exec_512k|jq_exec_2m|json_chain_8|plan_match_500|module_ir_clone_52>`
//! 每进程只跑一个场景，避免累计 heap peak 与 Darwin phys_footprint 互相污染。

use oryn_core::{
    alloc::{heap_usage, Counting},
    Engine,
};
use oryn_http_inspect::{compile_module, Message, Plan, Resources};
use oryn_module::{parse, ModuleFormat};
use std::alloc::System;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

#[global_allocator]
static GLOBAL: Counting<System> = Counting(System);

#[cfg(target_os = "macos")]
fn footprint() -> u64 {
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
    0
}

fn make_feed_json(target_bytes: usize) -> Vec<u8> {
    let mut out = String::with_capacity(target_bytes + 4096);
    out.push_str(
        r#"{"ad":{"id":1,"banner":"top"},"splash":{"img":"https://cdn.example/s.jpg"},"a0":1,"a1":2,"a2":3,"a3":4,"a4":5,"a5":6,"a6":7,"a7":8,"items":["#,
    );
    let mut i = 0usize;
    while out.len() + 180 < target_bytes {
        if i > 0 {
            out.push(',');
        }
        let is_ad = i.is_multiple_of(4);
        out.push_str(&format!(
            r#"{{"id":{i},"is_ad":{is_ad},"kind":"{}","title":"Item title number {i} for feed payload benchmark","summary":"Some representative json payload text padding for item {i}"}}"#,
            if is_ad { "promo" } else { "post" }
        ));
        i += 1;
    }
    out.push_str("]}");
    out.into_bytes()
}

fn make_req(url: &str) -> Message {
    Message {
        url: url.into(),
        method: "GET".into(),
        status: None,
        headers: vec![
            ("Host".into(), url.split('/').nth(2).unwrap_or("example").into()),
            ("User-Agent".into(), "OrynBench/1.0".into()),
        ],
        body: Vec::new(),
    }
}

fn make_resp(url: &str, body: Vec<u8>) -> Message {
    Message {
        url: url.into(),
        method: "GET".into(),
        status: Some(200),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Length".into(), body.len().to_string()),
        ],
        body,
    }
}

fn bench_jq_compile_63() {
    let mut text = String::from("#!name=jq63\n[Rewrite]\n");
    for i in 0..63 {
        let expr = match i % 5 {
            0 => format!("del(.ad, .a{}) | .items |= map(select(.is_ad != true))", i % 8),
            1 => format!("if (.kind? | IN(\"promo_{i}\", \"ad_{i}\")) then del(.splash) else del(.ad) end"),
            2 => format!(".items |= (map(select(.id != {i})) | .[:50]) | del(.splash)"),
            3 => format!("with_entries(select(.key != \"ad\" and .key != \"a{}\"))", i % 8),
            _ => format!(".meta = {{tag: \"f{i}\", clean: true}} | del(.ad, .splash)"),
        };
        text.push_str(&format!(
            "^https://app{i}.example/feed$ response-body-json-jq '{expr}'\n"
        ));
    }
    let ir = parse(&text, Some(ModuleFormat::Loon)).unwrap();
    let plan = compile_module(&ir, &BTreeMap::new(), &Resources::new()).unwrap();
    assert_eq!(plan.response.len(), 63, "warnings={:?}", plan.warnings);
    drop(ir);
    drop(text);

    let sample = br#"{"ad":1,"splash":1,"a0":1,"a1":2,"a2":3,"a3":4,"a4":5,"a5":6,"a6":7,"a7":8,"items":[{"id":1,"is_ad":true},{"id":2,"is_ad":false}]}"#;
    let start = Instant::now();
    let mut ok_count = 0usize;
    for i in 0..63 {
        let url = format!("https://app{i}.example/feed");
        let req = make_req(&url);
        let mut resp = make_resp(&url, sample.to_vec());
        plan.apply_response(&mut resp, &req).unwrap();
        if resp.body != sample {
            ok_count += 1;
        }
    }
    let elapsed_us = start.elapsed().as_micros();
    let (live, peak) = heap_usage().unwrap_or((0, 0));
    let fp = footprint();
    println!(
        "jq_compile_63,{},{},{},{},{},compiled={ok_count}/63",
        ok_count == 63,
        elapsed_us,
        live,
        peak,
        fp
    );
    black_box(&plan);
}

fn bench_jq_exec(name: &str, payload_bytes: usize) {
    let text = "#!name=jqexec\n[Rewrite]\n^https://feed.example/v1/list$ response-body-json-jq 'del(.ad, .splash) | .items |= map(select(.is_ad != true))'\n";
    let ir = parse(text, Some(ModuleFormat::Loon)).unwrap();
    let plan = compile_module(&ir, &BTreeMap::new(), &Resources::new()).unwrap();
    assert_eq!(plan.response.len(), 1, "warnings={:?}", plan.warnings);
    drop(ir);

    // 预热一次，确保 filter 已编译，本次仅测执行路径内存与耗时。
    let url = "https://feed.example/v1/list";
    let req = make_req(url);
    let mut warm = make_resp(
        url,
        br#"{"ad":1,"splash":2,"items":[{"is_ad":true},{"is_ad":false}]}"#.to_vec(),
    );
    plan.apply_response(&mut warm, &req).unwrap();
    assert!(!warm.body.windows(5).any(|w| w == b"\"ad\":"));
    drop(warm);

    let payload = make_feed_json(payload_bytes);
    let orig_len = payload.len();
    let mut resp = make_resp(url, payload);

    let start = Instant::now();
    let res = plan.apply_response(&mut resp, &req);
    let elapsed_us = start.elapsed().as_micros();
    let out_len = resp.body.len();
    let modified = res.is_ok()
        && out_len < orig_len
        && !resp.body.windows(5).any(|w| w == b"\"ad\":")
        && !resp.body.windows(9).any(|w| w == b"\"splash\":");
    let (live, peak) = heap_usage().unwrap_or((0, 0));
    let fp = footprint();
    println!(
        "{name},{modified},{elapsed_us},{live},{peak},{fp},in={orig_len};out={out_len}"
    );
    black_box(&resp);
    black_box(&plan);
}

fn bench_json_chain_8() {
    let text = "#!name=json8\n[Rewrite]\n^https://chain.example/v1/feed$ response-body-json-del a0 a1 a2 a3 a4 a5 a6 a7\n";
    let ir = parse(text, Some(ModuleFormat::Loon)).unwrap();
    let plan = compile_module(&ir, &BTreeMap::new(), &Resources::new()).unwrap();
    assert_eq!(plan.response.len(), 1, "warnings={:?}", plan.warnings);
    drop(ir);

    let url = "https://chain.example/v1/feed";
    let req = make_req(url);
    let payload = make_feed_json(512 * 1024);
    let orig_len = payload.len();

    let start = Instant::now();
    let mut ok = true;
    let mut out_len = 0usize;
    for _ in 0..10 {
        let mut resp = make_resp(url, payload.clone());
        plan.apply_response(&mut resp, &req).unwrap();
        out_len = resp.body.len();
        ok &= out_len < orig_len
            && !resp.body.windows(5).any(|w| w == b"\"a0\":")
            && !resp.body.windows(5).any(|w| w == b"\"a7\":");
        black_box(&resp.body);
    }
    let elapsed_us = start.elapsed().as_micros();
    let (live, peak) = heap_usage().unwrap_or((0, 0));
    let fp = footprint();
    println!(
        "json_chain_8,{ok},{elapsed_us},{live},{peak},{fp},runs=10;in={orig_len};out={out_len}"
    );
    black_box(&plan);
}

fn bench_plan_match_500(escaped_hosts: bool) {
    let mut text = String::from("#!name=match500\n[Rewrite]\n");
    let dot = if escaped_hosts { "\\." } else { "." };
    for i in 0..66 {
        text.push_str(&format!("^https?://opt{i}{dot}example/api/ad$ reject\n"));
    }
    for i in 0..398 {
        text.push_str(&format!(
            "^https://exact{i}{dot}example/v1/feed$ response-body-json-del ad\n"
        ));
    }
    for i in 0..36 {
        text.push_str(&format!("^https://[^/]+\\.wild{i}\\.example/ad$ reject\n"));
    }
    text.push_str("[Script]\n");
    for i in 0..90 {
        text.push_str(&format!(
            "http-response ^https://script{i}{dot}example/api$ script-path=s.js, requires-body=true, tag=sc{i}\n"
        ));
    }
    let mut resources = Resources::new();
    resources.insert("s.js".into(), Arc::from(b"$done({});".as_slice()));
    let ir = parse(&text, Some(ModuleFormat::Loon)).unwrap();
    let plan: Plan = compile_module(&ir, &BTreeMap::new(), &resources).unwrap();
    assert_eq!(plan.request.len(), 102, "req warnings={:?}", plan.warnings);
    assert_eq!(plan.response.len(), 398, "resp warnings={:?}", plan.warnings);
    assert_eq!(plan.scripts.len(), 90, "script warnings={:?}", plan.warnings);
    drop(ir);
    drop(text);
    drop(resources);

    let (live_before, _) = heap_usage().unwrap_or((0, 0));
    let mut cold_req = make_req("https://unmatched.example/home");
    let cold_resp = make_resp("https://unmatched.example/home", Vec::new());
    let _ = plan.needs_body_after_rewrite(&cold_req, None);
    let _ = plan.apply_request_with_effects(&mut cold_req).unwrap();
    let _ = plan.needs_body_after_rewrite(&cold_resp, Some(&cold_req));
    let _ = plan.scripts(&cold_resp, Some(&cold_req));
    let (live_after_cold, _) = heap_usage().unwrap_or((0, 0));
    let cold_delta = live_after_cold as isize - live_before as isize;

    let pairs: Vec<(Message, Message)> = (0..1000)
        .map(|k| {
            let url = match k % 10 {
                0 => format!("https://exact{}.example/v1/feed", k % 398),
                1 => format!("https://exact{}.example/v1/other", k % 398),
                2 => format!("https://script{}.example/api", k % 90),
                _ => format!("https://unmatched{k}.example/index.html"),
            };
            (make_req(&url), make_resp(&url, Vec::new()))
        })
        .collect();

    let start = Instant::now();
    let mut body_hits = 0usize;
    let mut req_hits = 0usize;
    let mut script_hits = 0usize;
    for round in 0..10 {
        for (req, resp) in &pairs {
            let mut m = req.clone();
            if plan.needs_body_after_rewrite(&m, None) {
                body_hits += 1;
            }
            if let Ok((Some(_), _)) = plan.apply_request_with_effects(&mut m) {
                req_hits += 1;
            }
            if plan.needs_body_after_rewrite(resp, Some(&m)) {
                body_hits += 1;
            }
            script_hits += plan.scripts(resp, Some(&m)).len();
        }
        black_box(round);
    }
    let elapsed_us = start.elapsed().as_micros();
    let (live, peak) = heap_usage().unwrap_or((0, 0));
    let fp = footprint();
    let label = if escaped_hosts {
        "plan_match_500_host"
    } else {
        "plan_match_500"
    };
    println!(
        "{label},true,{elapsed_us},{live},{peak},{fp},cold_delta={cold_delta};body_hits={body_hits};req_hits={req_hits};script_hits={script_hits}"
    );
    black_box(&plan);
}

struct ScratchDir(PathBuf);
impl ScratchDir {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("oryn-mod-bench-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("modules")).unwrap();
        Self(p)
    }
}
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bench_module_ir_clone_52() {
    let scratch = ScratchDir::new("ir52");
    std::fs::write(scratch.0.join("modules/common.js"), b"$done({});\n").unwrap();

    let mut cfg = String::from(
        "mode: rule\nlog-level: silent\ngeo-auto-update: false\n\
         geox-url: {mmdb: '', asn: ''}\n\
         dns:\n  public-ip-url: ''\n  nameserver: ['127.0.0.1:1']\n  default-nameserver: ['127.0.0.1:1']\n\
         rules:\n  - MATCH,DIRECT\n\
         modules:\n",
    );
    for m in 0..52 {
        cfg.push_str("  - format: surge\n    inline: |\n");
        cfg.push_str(&format!(
            "      #!name=mod_{m}\n      #!desc=Synthetic adblock module number {m}\n"
        ));
        cfg.push_str("      [Rule]\n");
        for r in 0..30 {
            cfg.push_str(&format!("      DOMAIN-SUFFIX,ad{r}.mod{m}.example,REJECT\n"));
        }
        cfg.push_str("      [URL Rewrite]\n");
        for r in 0..30 {
            cfg.push_str(&format!("      ^https://api{r}.mod{m}.example/ad$ - reject\n"));
        }
        cfg.push_str("      [Script]\n");
        cfg.push_str(&format!(
            "      s{m} = type=http-response, pattern=^https://sc.mod{m}.example/api$, script-path=common.js, requires-body=true\n"
        ));
        cfg.push_str("      [MITM]\n");
        cfg.push_str(&format!(
            "      hostname = %APPEND% api0.mod{m}.example, sc.mod{m}.example\n"
        ));
    }
    let opts = serde_json::to_vec(&serde_json::json!({
        "local_proxy": {"enabled": false},
        "data_dir": scratch.0,
        "maxmind": null
    }))
    .unwrap();

    let start = Instant::now();
    let mut engine = Engine::new(cfg.as_bytes(), &opts).unwrap();
    drop(cfg);
    engine.set_output(Box::new(|_| {}));
    engine.start().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let elapsed_us = start.elapsed().as_micros();
    let (live, peak) = heap_usage().unwrap_or((0, 0));
    let fp = footprint();
    println!("module_ir_clone_52,true,{elapsed_us},{live},{peak},{fp},modules=52");
    engine.stop();
    drop(engine);
}

fn main() {
    let arg = std::env::args().nth(1).expect(
        "usage: module_perf_bench <jq_compile_63|jq_exec_512k|jq_exec_2m|json_chain_8|plan_match_500|module_ir_clone_52>",
    );
    match arg.as_str() {
        "jq_compile_63" => bench_jq_compile_63(),
        "jq_exec_512k" => bench_jq_exec("jq_exec_512k", 512 * 1024),
        "jq_exec_2m" => bench_jq_exec("jq_exec_2m", 2 * 1024 * 1024),
        "json_chain_8" => bench_json_chain_8(),
        "plan_match_500" => bench_plan_match_500(false),
        "plan_match_500_host" => bench_plan_match_500(true),
        "module_ir_clone_52" => bench_module_ir_clone_52(),
        other => panic!("unknown scenario: {other}"),
    }
}
