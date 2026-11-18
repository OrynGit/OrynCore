//! `oryn`：不依赖 App 的桌面独立核心。
//!
//! - `oryn run -c config.yaml [-d 数据目录]`：启动 Engine。`tun.enable` 为 true 时（目前仅 Linux）
//!   由 `oryn-host` 创建 TUN 并设置路由，Core 直接收发 TUN 上的 IP 包；否则只开本地 HTTP /
//!   SOCKS5 入站（与 `oryn_engine_start_proxy` 相同）。`SIGINT` / `SIGTERM` 退出并还原路由，
//!   `SIGHUP` 重新读取配置并用控制命令 `reload` 热重载。
//! - `oryn check -c config.yaml`：只解析、编译配置。
//!
//! 方案见 Oryn_dev/docs/oryncore/plans/plan-desktop-tun-bare-core.md。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

use oryn_config::desktop::{parse_desktop, DesktopSettings};
use oryn_core::Engine;
use serde_json::json;

const USAGE: &str = "Usage:
  oryn run -c <config.yaml> [-d <data-dir>]   start the core
  oryn check -c <config.yaml>                 validate the config and exit
  oryn version                                print the version

Signals (run): SIGINT / SIGTERM stop and restore routes; SIGHUP reloads the config.
The data directory defaults to the directory of the config file.";

struct Args {
    command: String,
    config: PathBuf,
    data_dir: Option<PathBuf>,
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let command = it.next().ok_or("missing command")?;
    let mut config = None;
    let mut data_dir = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-c" | "--config" => config = Some(PathBuf::from(it.next().ok_or("-c needs a path")?)),
            "-d" | "--data-dir" => data_dir = Some(PathBuf::from(it.next().ok_or("-d needs a path")?)),
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let config = config.ok_or("missing -c <config.yaml>")?;
    Ok(Args { command, config, data_dir })
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1).peekable();
    match args.peek().map(String::as_str) {
        None | Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some("version" | "-v" | "--version") => {
            println!("oryn {}", oryn_core::VERSION);
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    let args = match parse_args(args) {
        Ok(a) if a.command == "run" || a.command == "check" => a,
        Ok(a) => return usage_error(&format!("unknown command `{}`", a.command)),
        Err(e) => return usage_error(&e),
    };
    // 先屏蔽信号再创建任何线程，子线程继承屏蔽字，信号只由等待线程接收
    let signals = if args.command == "run" { Some(block_signals()) } else { None };
    install_logger();
    let result = match args.command.as_str() {
        "check" => check(&args),
        _ => run(&args, signals.expect("signals blocked for run")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            // 日志回调可能被过滤（log-level: silent），错误总是写到 stderr
            eprintln!("oryn: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("oryn: {msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn install_logger() {
    oryn_core::logging::set_callback(Some(Box::new(|level, msg| {
        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "{} {:<5} {msg}", timestamp(), level);
    })));
}

/// UTC 时间 `HH:MM:SS.mmm`，不引入时间库。
fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() % 86_400;
    format!("{:02}:{:02}:{:02}.{:03}", secs / 3600, secs / 60 % 60, secs % 60, now.subsec_millis())
}

fn read_config(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn data_dir(args: &Args) -> Result<PathBuf, String> {
    let dir = match &args.data_dir {
        Some(d) => d.clone(),
        None => args
            .config
            .canonicalize()
            .map_err(|e| format!("cannot resolve {}: {e}", args.config.display()))?
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create data dir {}: {e}", dir.display()))?;
    Ok(dir)
}

/// 由宿主设置组装 Engine 运行参数（JSON，字段见 `oryn_core::EngineOptions`）。
fn engine_options(desktop: &DesktopSettings, data_dir: &Path) -> Vec<u8> {
    let mut local = json!({ "enabled": true });
    if let Some(p) = desktop.http_port {
        local["http_port"] = json!(p);
    }
    if let Some(p) = desktop.socks_port {
        local["socks_port"] = json!(p);
    }
    if let Some(lan) = desktop.allow_lan {
        local["allow_external"] = json!(lan);
    }
    let mut options = json!({
        "data_dir": data_dir,
        "local_proxy": local,
        "system_version": std::env::consts::OS,
    });
    // 桌面额度只在 macOS / Linux 上存在（见 oryn_core::ResourceProfile）
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        options["resource_profile"] = json!("desktop_high");
    }
    if let Some(tun) = &desktop.tun {
        options["mtu"] = json!(tun.mtu);
        options["dns_hijack"] = json!(tun
            .dns_hijack
            .iter()
            .map(|h| {
                let proto = match (h.tcp, h.udp) {
                    (true, false) => "tcp://",
                    (false, true) => "udp://",
                    _ => "",
                };
                let host = match h.ip {
                    None => "any".to_string(),
                    Some(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
                    Some(ip) => ip.to_string(),
                };
                format!("{proto}{host}:{}", h.port)
            })
            .collect::<Vec<_>>());
    }
    serde_json::to_vec(&options).expect("options serialize")
}

fn load(args: &Args) -> Result<(String, DesktopSettings, Engine), String> {
    let text = read_config(&args.config)?;
    let desktop = parse_desktop(&text).map_err(|e| format!("invalid config: {e}"))?;
    for w in &desktop.warnings {
        log::warn!("{w}");
    }
    let dir = data_dir(args)?;
    let engine = Engine::new(text.as_bytes(), &engine_options(&desktop, &dir))
        .map_err(|e| format!("invalid config: {e}"))?;
    for w in engine.warnings() {
        log::warn!("{w}");
    }
    Ok((text, desktop, engine))
}

fn check(args: &Args) -> Result<(), String> {
    let (_, desktop, _) = load(args)?;
    let mode = match &desktop.tun {
        Some(t) => format!("TUN ({})", t.device.as_deref().unwrap_or("default device")),
        None => "proxy only".into(),
    };
    println!("configuration OK: {mode}");
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signal {
    Stop(libc::c_int),
    Reload,
}

/// 屏蔽 SIGINT / SIGTERM / SIGHUP，由专门线程 `sigwait` 接收并转交主线程。
fn block_signals() -> mpsc::Receiver<Signal> {
    // SAFETY: sigset_t 用 sigemptyset 初始化；pthread_sigmask 只改当前线程的屏蔽字。
    let set = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    };
    let (tx, rx) = mpsc::sync_channel(8);
    struct Set(libc::sigset_t);
    // SAFETY: sigset_t 是普通数据，只在等待线程里读取。
    unsafe impl Send for Set {}
    let set = Set(set);
    std::thread::Builder::new()
        .name("oryn-signals".into())
        .spawn(move || {
            let set = set;
            loop {
                let mut sig: libc::c_int = 0;
                // SAFETY: set 有效，sig 是输出参数。
                if unsafe { libc::sigwait(&set.0, &mut sig) } != 0 {
                    continue;
                }
                let s = if sig == libc::SIGHUP { Signal::Reload } else { Signal::Stop(sig) };
                if tx.try_send(s).is_err() && matches!(s, Signal::Stop(_)) {
                    // 主线程没在收：第二次退出信号直接结束
                    std::process::exit(130);
                }
            }
        })
        .expect("spawn signal thread");
    rx
}

fn run(args: &Args, signals: mpsc::Receiver<Signal>) -> Result<(), String> {
    let (_, desktop, mut engine) = load(args)?;
    // 先建 TUN 与路由，再设出站防回环，最后启动 Engine：Core 启动期间的下载已经带标记 / 绑定
    let tunnel = match &desktop.tun {
        Some(tun) => Some(
            oryn_host::Tunnel::open(tun, desktop.effective_routing_mark())
                .map_err(|e| format!("TUN setup failed: {e}"))?,
        ),
        None => None,
    };
    let guard = oryn_host::protect_outbound(&desktop, tunnel.as_ref().map(|t| t.index()))
        .map_err(|e| format!("outbound setup failed: {e}"))?;
    match &tunnel {
        Some(t) => engine.start_utun(t.raw_fd()),
        None => engine.start_proxy_only(),
    }
    .map_err(|e| format!("failed to start: {e}"))?;
    log::info!(
        "oryn {} running ({}); config {}",
        oryn_core::VERSION,
        tunnel.as_ref().map(|t| format!("TUN {}", t.name())).unwrap_or_else(|| "proxy only".into()),
        args.config.display()
    );
    let mut current = desktop;
    let result = loop {
        match signals.recv_timeout(Duration::from_secs(1)) {
            Ok(Signal::Stop(sig)) => {
                log::info!("received signal {sig}, stopping");
                break Ok(());
            }
            Ok(Signal::Reload) => reload(&engine, args, &mut current),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !engine.is_running() {
                    break Err("the core stopped unexpectedly".to_string());
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break Err("signal thread exited".into()),
        }
    };
    engine.stop();
    // 停止监测，再删路由规则并关闭 TUN（Linux 上两者都有 Drop；其他平台是空壳）
    #[allow(clippy::drop_non_drop)]
    {
        drop(guard);
        drop(tunnel);
    }
    result
}

/// `SIGHUP`：重新读取配置文件，用控制命令 `reload` 热重载。宿主设置的变化需要重启。
fn reload(engine: &Engine, args: &Args, current: &mut DesktopSettings) {
    let text = match read_config(&args.config) {
        Ok(t) => t,
        Err(e) => {
            log::error!("reload failed: {e}");
            return;
        }
    };
    match parse_desktop(&text) {
        Ok(next) => {
            let changed = next.tun != current.tun
                || next.routing_mark != current.routing_mark
                || next.interface_name != current.interface_name
                || next.http_port != current.http_port
                || next.socks_port != current.socks_port
                || next.allow_lan != current.allow_lan;
            if changed {
                log::warn!("tun, routing-mark, interface-name and local proxy port changes take effect after a restart");
            }
        }
        Err(e) => {
            log::error!("reload failed: invalid config: {e}");
            return;
        }
    }
    let request = json!({ "cmd": "reload", "config": text }).to_string();
    let reply = engine.command(request.as_bytes());
    match reply.get("error").and_then(|e| e.as_str()) {
        Some(e) => log::error!("reload failed: {e}"),
        None => log::info!("config reloaded from {}", args.config.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Args, String> {
        parse_args(list.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_arguments() {
        let a = args(&["run", "-c", "a.yaml", "-d", "/tmp/x"]).unwrap();
        assert_eq!((a.command.as_str(), a.config.to_str(), a.data_dir.as_deref()), ("run", Some("a.yaml"), Some(Path::new("/tmp/x"))));
        assert!(args(&["run"]).is_err());
        assert!(args(&["run", "-c"]).is_err());
        assert!(args(&["run", "-c", "a", "--bogus"]).is_err());
    }

    #[test]
    fn options_carry_ports_and_tun_settings() {
        let desktop = parse_desktop(
            "port: 7890\nsocks-port: 7891\nallow-lan: true\ntun:\n  enable: true\n  mtu: 1500\n  dns-hijack: [any:53, 'udp://[2001:db8::1]:53', 'tcp://1.1.1.1:53']\n",
        )
        .unwrap();
        let opts: serde_json::Value = serde_json::from_slice(&engine_options(&desktop, Path::new("/tmp/d"))).unwrap();
        assert_eq!(opts["local_proxy"], json!({"enabled": true, "http_port": 7890, "socks_port": 7891, "allow_external": true}));
        assert_eq!(opts["mtu"], 1500);
        assert_eq!(opts["dns_hijack"], json!(["any:53", "udp://[2001:db8::1]:53", "tcp://1.1.1.1:53"]));
        // 序列化后的写法能被 Core 重新解析
        let engine = Engine::new(b"rules: ['MATCH,DIRECT']", &engine_options(&desktop, Path::new("/tmp/d")));
        assert!(engine.is_ok());
    }
}
