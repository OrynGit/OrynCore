//! 只用于单独运行的测量；不执行脚本、不连接公网。夹具计入进程堆。
use oryn_config::{Mode, RuntimeConfig};
use std::{
    alloc::System,
    fmt::Write as _,
    io::{Read, Write},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    time::{Duration, Instant},
};
#[global_allocator]
static ALLOC: crate::alloc::Counting<System> = crate::alloc::Counting(System);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static PREPARE_STARTED: AtomicUsize = AtomicUsize::new(0);
static PREPARE_DROPPED: AtomicUsize = AtomicUsize::new(0);
static STATE_DROPPED: AtomicUsize = AtomicUsize::new(0);
pub(crate) fn local_resource(source: &str) -> bool {
    ACTIVE.load(SeqCst) && source.starts_with("http://127.0.0.1:")
}
fn bit(mode: Mode) -> usize {
    match mode {
        Mode::Rule => 1,
        Mode::Global => 2,
        Mode::Direct => 4,
    }
}
pub(crate) struct PrepareProbe(usize);
impl PrepareProbe {
    pub(crate) fn new(config: &RuntimeConfig) -> Self {
        let id = if ACTIVE.load(SeqCst) {
            bit(config.mode)
        } else {
            0
        };
        if id != 0 {
            PREPARE_STARTED.fetch_or(id, SeqCst);
            eprintln!("prepare_enter marker={id}");
        }
        Self(id)
    }
}
impl Drop for PrepareProbe {
    fn drop(&mut self) {
        if self.0 != 0 {
            PREPARE_DROPPED.fetch_or(self.0, SeqCst);
            eprintln!("prepare_future_drop marker={}", self.0);
        }
    }
}
pub(crate) fn state_drop(config: &RuntimeConfig) {
    if ACTIVE.load(SeqCst) {
        let id = bit(config.mode);
        STATE_DROPPED.fetch_or(id, SeqCst);
        eprintln!("runtime_state_drop marker={id}");
    }
}
fn sample(phase: &str) {
    let (live, peak) = crate::alloc::heap_usage().unwrap();
    let mut footprint = 0;
    #[cfg(target_os = "macos")]
    unsafe {
        let mut info: libc::rusage_info_v4 = std::mem::zeroed();
        if libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V4,
            &mut info as *mut _ as *mut libc::rusage_info_t,
        ) == 0
        {
            footprint = info.ri_phys_footprint;
        }
    }
    eprintln!("sample,{phase},{live},{peak},{footprint}");
}
fn wait(mut predicate: impl FnMut() -> bool) {
    let start = Instant::now();
    while !predicate() {
        assert!(start.elapsed() < Duration::from_secs(30), "barrier timeout");
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn config(mode: &str) -> String {
    let mut s = format!("mode: {mode}\nlog-level: silent\ngeo-auto-update: false\ngeox-url: {{mmdb: 'http://127.0.0.1:1/unused', asn: ''}}\ndns:\n  public-ip-url: ''\n  nameserver: ['127.0.0.1:1']\n  default-nameserver: ['127.0.0.1:1']\nproxies:\n");
    for n in 0..1000 {
        writeln!(
            s,
            "  - {{name: fake-{n}, type: socks5, server: 127.0.0.1, port: 1}}"
        )
        .unwrap();
    }
    s.push_str("rules:\n");
    for n in 0..10000 {
        writeln!(s, "  - DOMAIN,host-{n}.invalid,REJECT").unwrap();
    }
    s.push_str("  - MATCH,DIRECT\nmodules:\n");
    for n in 0..2 {
        writeln!(s, "  - format: surge\n    inline: |\n      #!name=safe-{n}\n      [Rule]\n      DOMAIN,module-{n}.invalid,REJECT").unwrap();
    }
    s
}
#[test]
#[ignore = "standalone large lifecycle/heap measurement"]
fn continuous_reload_lifecycle_heap() {
    let _stack = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    struct ResetProbe;
    impl Drop for ResetProbe {
        fn drop(&mut self) { ACTIVE.store(false, SeqCst); }
    }
    let _reset = ResetProbe;
    PREPARE_STARTED.store(0, SeqCst);
    PREPARE_DROPPED.store(0, SeqCst);
    STATE_DROPPED.store(0, SeqCst);
    ACTIVE.store(true, SeqCst);
    sample("baseline");
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../scratchpad/reload-lifecycle-data-{}",
        std::process::id()
    ));
    std::fs::create_dir(&dir).expect("use fresh fixture directory");
    let options = serde_json::to_vec(
        &serde_json::json!({"local_proxy":{"enabled":false},"data_dir":dir,"maxmind":null}),
    )
    .unwrap();
    let initial = config("rule");
    let mut engine = crate::Engine::new(initial.as_bytes(), &options).unwrap();
    engine.start_proxy_only().unwrap();
    wait(|| PREPARE_DROPPED.load(SeqCst) & 1 != 0);
    std::thread::sleep(Duration::from_millis(1200));
    // 清掉启动占位 RuntimeState 的 Drop；此后 marker=1 是真实旧运行态。
    STATE_DROPPED.store(0, SeqCst);
    sample("stable_start");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 16384);
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        entered_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        let body = "#!name=barrier-A\n[Rule]\nDOMAIN,a.invalid,REJECT\n";
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    });
    let mut a = config("global");
    writeln!(
        a,
        "  - format: surge\n    url: http://127.0.0.1:{port}/barrier.sgmodule"
    )
    .unwrap();
    let a_cmd = serde_json::to_vec(&serde_json::json!({"cmd":"reload","config":a})).unwrap();
    assert_eq!(engine.command(&a_cmd)["ok"], true);
    entered_rx.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(PREPARE_STARTED.load(SeqCst) & 2, 2);
    assert_eq!(PREPARE_DROPPED.load(SeqCst) & 2, 0);
    assert_eq!(STATE_DROPPED.load(SeqCst) & 1, 0);
    sample("A_resource_barrier");
    let b = config("direct");
    let b_cmd = serde_json::to_vec(&serde_json::json!({"cmd":"reload","config":b})).unwrap();
    sample("B_input_ready");
    assert_eq!(engine.command(&b_cmd)["ok"], true);
    wait(|| {
        engine.command(br#"{"cmd":"stats"}"#)["mode"] == "direct"
            && PREPARE_DROPPED.load(SeqCst) & 6 == 6
            && STATE_DROPPED.load(SeqCst) & 1 == 1
    });
    sample("B_applied_A_and_old_dropped");
    release_tx.send(()).unwrap();
    server.join().unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(engine.command(br#"{"cmd":"stats"}"#)["mode"], "direct");
    assert_eq!(
        STATE_DROPPED.load(SeqCst) & 2,
        0,
        "A must never publish RuntimeState"
    );
    sample("late_A_response_final_B");
    engine.stop();
    assert_eq!(STATE_DROPPED.load(SeqCst) & 4, 4);
    sample("stop_join");
    drop((engine, initial, a, a_cmd, b, b_cmd, options));
    sample("drop_engine_and_inputs");
    std::thread::sleep(Duration::from_millis(100));
    sample("post_drop_100ms");
    ACTIVE.store(false, SeqCst);
}
