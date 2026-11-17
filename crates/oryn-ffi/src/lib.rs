//! OrynCore 的 C ABI。
//!
//! 头文件 `include/oryn_core.h` 由 cbindgen 在构建时根据本文件生成（见 `build.rs`、
//! `cbindgen.toml`），不要手动修改。导出项上的文档注释会写入头文件。
//!
//! 每个导出函数都用 `catch_unwind` 包裹，panic 不会跨越 FFI 边界。
#![allow(clippy::missing_safety_doc)]

use base64::Engine as _;
use std::ffi::{c_char, c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Mutex, RwLock};

use oryn_core::{
    run_command, Engine, EngineError, EngineHandle,
};

/// 系统分配器外包一层计数，`stats` 命令据此报告 Core 堆的实际用量（`heap_live` / `heap_peak`），
/// 平台层在内存告警里与进程 footprint 对照。不用 mimalloc 的原因见 `oryn_core::alloc`。
#[global_allocator]
static GLOBAL: oryn_core::alloc::Counting<std::alloc::System> = oryn_core::alloc::Counting(std::alloc::System);

/// 成功。
pub const ORYN_OK: i32 = 0;
/// 参数无效（如空指针）。
pub const ORYN_ERR_INVALID_ARGUMENT: i32 = -1;
/// 配置解析或校验失败。
pub const ORYN_ERR_CONFIG: i32 = -2;
/// 已在运行，或另一个 Engine 占用了协议栈。
pub const ORYN_ERR_BUSY: i32 = -3;
/// Engine 未运行。
pub const ORYN_ERR_NOT_RUNNING: i32 = -4;
/// 输入队列已满，本批数据已丢弃。
pub const ORYN_ERR_QUEUE_FULL: i32 = -5;
/// 内部错误。
pub const ORYN_ERR_INTERNAL: i32 = -6;

/// 日志级别：错误。
pub const ORYN_LOG_ERROR: i32 = 1;
/// 日志级别：警告。
pub const ORYN_LOG_WARN: i32 = 2;
/// 日志级别：信息。
pub const ORYN_LOG_INFO: i32 = 3;
/// 日志级别：调试。
pub const ORYN_LOG_DEBUG: i32 = 4;
/// 日志级别：跟踪。
pub const ORYN_LOG_TRACE: i32 = 5;

/// 日志回调，可能在任意线程调用。`message` 只在回调期间有效。
pub type OrynLogFn =
    Option<unsafe extern "C" fn(context: *mut c_void, level: i32, message: *const c_char)>;

/// 平台层保护 Core 自己创建的出站 socket，避免 Android VPN 回流。
pub type OrynSocketProtectFn = Option<unsafe extern "C" fn(context: *mut c_void, fd: i32) -> i32>;

/// Engine 句柄（不透明）。
pub struct OrynEngine {
    engine: Mutex<Engine>,
    /// 创建时固定，可在启动前无锁读取。
    virtual_interface_plan: serde_json::Value,
    /// 创建时固定：启动就绪前要先下载的代理集合个数（`startup_downloads` 命令）。
    startup_downloads: usize,
    /// 输入与命令只需要句柄，不与 start/stop 争用 `engine` 锁。
    handle: RwLock<Option<EngineHandle>>,
}

/// 可跨线程传递的裸指针（调用方保证其在回调期间有效）。
#[derive(Clone, Copy)]
struct SendPtr(*mut c_void);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

fn status_of(e: &EngineError) -> i32 {
    match e {
        EngineError::Config(_) => ORYN_ERR_CONFIG,
        EngineError::Busy(_) => ORYN_ERR_BUSY,
        EngineError::NotRunning => ORYN_ERR_NOT_RUNNING,
        EngineError::QueueFull => ORYN_ERR_QUEUE_FULL,
        EngineError::Internal(_) => ORYN_ERR_INTERNAL,
    }
}

fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s.replace('\0', " "))
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}

unsafe fn write_error(out: *mut *mut c_char, msg: &str) {
    if !out.is_null() {
        *out = to_c_string(msg);
    }
}

unsafe fn bytes<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if p.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(p, len))
    }
}

fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}

/// Core 版本号（静态字符串，不需要释放）。
#[no_mangle]
pub extern "C" fn oryn_version() -> *const c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}

/// 生成一份新的 MITM CA，返回 JSON，其中两个字段是 Base64 DER。
/// 私钥只应由 PacketTunnel 写入受 Data Protection 保护的 App Group 文件。
#[no_mangle]
pub extern "C" fn oryn_mitm_generate_ca() -> *mut c_char {
    guard(
        ptr::null_mut(),
        || match oryn_mitm::CertificateAuthority::generate("Oryn MITM CA") {
            Ok(ca) => {
                let b64 = base64::engine::general_purpose::STANDARD;
                let body = serde_json::json!({
                    "certificate_der": b64.encode(&ca.material().certificate_der),
                    "private_key_der": b64.encode(&ca.material().private_key_der),
                });
                to_c_string(&body.to_string())
            }
            Err(_) => ptr::null_mut(),
        },
    )
}

/// 设置全局日志回调；`callback` 为 NULL 时取消。
#[no_mangle]
pub extern "C" fn oryn_set_log_callback(callback: OrynLogFn, context: *mut c_void) {
    let ctx = SendPtr(context);
    guard((), || match callback {
        Some(cb) => oryn_core::logging::set_callback(Some(Box::new(move |level, msg| {
            let ctx = ctx;
            let level = match level {
                log::Level::Error => 1,
                log::Level::Warn => 2,
                log::Level::Info => 3,
                log::Level::Debug => 4,
                log::Level::Trace => 5,
            };
            if let Ok(c) = CString::new(msg.replace('\0', " ")) {
                unsafe { cb(ctx.0, level, c.as_ptr()) };
            }
        }))),
        None => oryn_core::logging::set_callback(None),
    })
}

/// 解析配置并创建 Engine。
///
/// `config` 为类 mihomo 格式的 YAML 配置；`options` 为 JSON 运行参数（可为空），字段见 `EngineOptions`：
/// `data_dir`、`dns_address`、`mtu`、`selections`、`mode`、`network`。
///
/// 失败返回 NULL，`*status` 为错误码，`*error_message`（可为 NULL）为错误说明，需用
/// `oryn_string_free` 释放。create / start / stop / destroy 由调用方保证不并发。
/// 设置平台层的出站 socket 保护回调；传 NULL 清除。
#[no_mangle]
pub unsafe extern "C" fn oryn_set_socket_protect_callback(
    callback: OrynSocketProtectFn,
    context: *mut c_void,
) {
    oryn_udp::set_socket_protect_callback(callback, context);
}

#[no_mangle]
pub unsafe extern "C" fn oryn_engine_create(
    config: *const u8,
    config_len: usize,
    options: *const u8,
    options_len: usize,
    status: *mut i32,
    error_message: *mut *mut c_char,
) -> *mut OrynEngine {
    let set_status = |s: i32| {
        if !status.is_null() {
            *status = s;
        }
    };
    guard(ptr::null_mut(), || {
        let (Some(cfg), Some(opts)) = (bytes(config, config_len), bytes(options, options_len))
        else {
            set_status(ORYN_ERR_INVALID_ARGUMENT);
            write_error(error_message, "config or options is a null pointer");
            return ptr::null_mut();
        };
        match Engine::new(cfg, opts) {
            Ok(engine) => {
                set_status(ORYN_OK);
                Box::into_raw(Box::new(OrynEngine {
                    virtual_interface_plan: serde_json::json!(engine.virtual_interface_plan()),
                    startup_downloads: engine.pending_proxy_provider_downloads(),
                    engine: Mutex::new(engine),
                    handle: RwLock::new(None),
                }))
            }
            Err(e) => {
                set_status(status_of(&e));
                write_error(error_message, &e.to_string());
                ptr::null_mut()
            }
        }
    })
}

/// 启动事件循环，并让 Rust 直接收发 utun 描述符上的 IP 包。
/// 描述符由平台层取得并验证；Core 在线程内 dup 一个副本，调用方仍保留原句柄。
/// 失败时 `*error_message`（可为 NULL）为错误说明。
#[no_mangle]
pub unsafe extern "C" fn oryn_engine_start(
    engine: *mut OrynEngine,
    fd: i32,
    error_message: *mut *mut c_char,
) -> i32 {
    let Some(e) = engine.as_ref() else {
        return ORYN_ERR_INVALID_ARGUMENT;
    };
    if fd < 0 {
        return ORYN_ERR_INVALID_ARGUMENT;
    }
    guard(ORYN_ERR_INTERNAL, || {
        let Ok(mut g) = e.engine.lock() else {
            return ORYN_ERR_INTERNAL;
        };
        match g.start_utun(fd) {
            Ok(()) => {
                *e.handle.write().unwrap() = g.handle();
                ORYN_OK
            }
            Err(err) => {
                write_error(error_message, &err.to_string());
                status_of(&err)
            }
        }
    })
}

/// 不带 utun 启动事件循环（macOS 系统代理模式）：只运行本地 HTTP / SOCKS5 入站与控制命令。
/// 失败时 `*error_message`（可为 NULL）为错误说明。
#[no_mangle]
pub unsafe extern "C" fn oryn_engine_start_proxy(
    engine: *mut OrynEngine,
    error_message: *mut *mut c_char,
) -> i32 {
    let Some(e) = engine.as_ref() else {
        return ORYN_ERR_INVALID_ARGUMENT;
    };
    guard(ORYN_ERR_INTERNAL, || {
        let Ok(mut g) = e.engine.lock() else {
            return ORYN_ERR_INTERNAL;
        };
        match g.start_proxy_only() {
            Ok(()) => {
                *e.handle.write().unwrap() = g.handle();
                ORYN_OK
            }
            Err(err) => {
                write_error(error_message, &err.to_string());
                status_of(&err)
            }
        }
    })
}

/// 事件循环是否仍在运行；供平台层处理实验 I/O 后端的异步失败。
#[no_mangle]
pub unsafe extern "C" fn oryn_engine_is_running(engine: *mut OrynEngine) -> i32 {
    guard(0, || {
        engine
            .as_ref()
            .and_then(|e| e.engine.lock().ok())
            .is_some_and(|e| e.is_running()) as i32
    })
}

/// 执行控制命令，`request` 为 JSON，如 `{"cmd":"stats"}`。可在任意线程调用。
/// 返回 JSON 字符串（需 `oryn_string_free` 释放），失败时包含 `error` 字段。
#[no_mangle]
pub unsafe extern "C" fn oryn_engine_command(
    engine: *mut OrynEngine,
    request: *const u8,
    request_len: usize,
) -> *mut c_char {
    guard(ptr::null_mut(), || {
        let Some(req) = bytes(request, request_len) else {
            return to_c_string(r#"{"error":"request is a null pointer"}"#);
        };
        let cmd = serde_json::from_slice::<serde_json::Value>(req).ok().and_then(|v| v["cmd"].as_str().map(str::to_owned));
        if cmd.as_deref() == Some("virtual_interface_plan") {
            return to_c_string(&engine.as_ref().map(|e| e.virtual_interface_plan.clone()).unwrap_or(serde_json::json!({"error":"invalid engine"})).to_string());
        }
        // 启动前即可查询，不等待（也不需要）事件循环。
        if cmd.as_deref() == Some("startup_downloads") {
            return to_c_string(&engine.as_ref().map(|e| serde_json::json!({"proxy_providers": e.startup_downloads})).unwrap_or(serde_json::json!({"error":"invalid engine"})).to_string());
        }
        let handle = engine
            .as_ref()
            .and_then(|e| e.handle.read().ok().and_then(|h| h.clone()));
        to_c_string(&run_command(handle.as_ref(), req).to_string())
    })
}

/// 停止事件循环并释放所有连接。可重复调用。
#[no_mangle]
pub unsafe extern "C" fn oryn_engine_stop(engine: *mut OrynEngine) {
    let Some(e) = engine.as_ref() else { return };
    guard((), || {
        if let Ok(mut h) = e.handle.write() {
            *h = None;
        }
        if let Ok(mut g) = e.engine.lock() {
            g.stop();
        }
    })
}

/// 停止并释放 Engine。
#[no_mangle]
pub unsafe extern "C" fn oryn_engine_destroy(engine: *mut OrynEngine) {
    if engine.is_null() {
        return;
    }
    oryn_engine_stop(engine);
    guard((), || drop(Box::from_raw(engine)))
}

/// 释放 Core 返回的字符串。
#[no_mangle]
pub unsafe extern "C" fn oryn_string_free(s: *mut c_char) {
    if !s.is_null() {
        guard((), || drop(CString::from_raw(s)))
    }
}

/// 验证导入的 MITM CA 和 PKCS#8 私钥是否有效且匹配，不保存、不输出私钥。
#[no_mangle]
pub unsafe extern "C" fn oryn_mitm_validate_ca(
    cert: *const u8,
    cert_len: usize,
    key: *const u8,
    key_len: usize,
) -> i32 {
    guard(ORYN_ERR_INTERNAL, || {
        if cert_len > 32768 || key_len > 32768 {
            return ORYN_ERR_INVALID_ARGUMENT;
        }
        let (Some(cert), Some(key)) = (bytes(cert, cert_len), bytes(key, key_len)) else {
            return ORYN_ERR_INVALID_ARGUMENT;
        };
        match oryn_mitm::CertificateAuthority::from_material(oryn_mitm::CaMaterial {
            certificate_der: cert.to_vec(),
            private_key_der: key.to_vec(),
        }) {
            Ok(_) => ORYN_OK,
            Err(_) => ORYN_ERR_CONFIG,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn counting_allocator_reports_live_heap() {
        let before = oryn_core::alloc::heap_usage().expect("counting allocator installed").0;
        let block = vec![1u8; 4 << 20];
        let (live, peak) = oryn_core::alloc::heap_usage().unwrap();
        assert!(live >= before + (4 << 20) - (1 << 20), "live {live} before {before}");
        assert!(peak >= live);
        drop(block);
    }

    #[test]
    fn vif_plan_is_available_before_start_through_c_abi() {
        unsafe {
            let cfg = b"rules: ['MATCH,REJECT']";
            let opts = br#"{"virtual_interface":{"loopbackAddresses":["10.7.0.1"]}}"#;
            let mut status = 0;
            let engine = oryn_engine_create(cfg.as_ptr(), cfg.len(), opts.as_ptr(), opts.len(), &mut status, ptr::null_mut());
            assert!(!engine.is_null());
            let req = br#"{"cmd":"virtual_interface_plan"}"#;
            let response = oryn_engine_command(engine, req.as_ptr(), req.len());
            let value: serde_json::Value = serde_json::from_str(CStr::from_ptr(response).to_str().unwrap()).unwrap();
            assert!(value["required"].as_array().unwrap().contains(&serde_json::json!("10.7.0.1/32")));
            assert_eq!(oryn_engine_is_running(engine),0);
            oryn_string_free(response); oryn_engine_destroy(engine);
        }
    }

    #[test]
    fn startup_downloads_counts_uncached_providers_before_start() {
        unsafe {
            let dir = std::env::temp_dir().join(format!("oryn-ffi-startup-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let cfg = b"proxy-providers:\n  sub:\n    type: http\n    url: https://sub.invalid/a.yaml\n    path: ./sub.yaml\nproxy-groups:\n  - {name: P, type: select, use: [sub]}\nrules: ['MATCH,P']\n";
            let opts = serde_json::to_vec(&serde_json::json!({"data_dir": dir})).unwrap();
            let mut status = 0;
            let engine = oryn_engine_create(cfg.as_ptr(), cfg.len(), opts.as_ptr(), opts.len(), &mut status, ptr::null_mut());
            assert!(!engine.is_null(), "status {status}");
            let req = br#"{"cmd":"startup_downloads"}"#;
            let response = oryn_engine_command(engine, req.as_ptr(), req.len());
            let value: serde_json::Value = serde_json::from_str(CStr::from_ptr(response).to_str().unwrap()).unwrap();
            assert_eq!(value["proxy_providers"], 1, "{value}");
            oryn_string_free(response); oryn_engine_destroy(engine);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn lifecycle_and_errors() {
        unsafe {
            let mut status = 0;
            let mut err: *mut c_char = ptr::null_mut();
            let bad = b"rules:\n  - DOMAIN,a.com,Nope\n";
            assert!(oryn_engine_create(
                bad.as_ptr(),
                bad.len(),
                ptr::null(),
                0,
                &mut status,
                &mut err
            )
            .is_null());
            assert_eq!(status, ORYN_ERR_CONFIG);
            assert!(!CStr::from_ptr(err).to_str().unwrap().is_empty());
            oryn_string_free(err);

            let good = b"mode: rule\n";
            let opts = b"{\"mtu\":1500}";
            let e = oryn_engine_create(
                good.as_ptr(),
                good.len(),
                opts.as_ptr(),
                opts.len(),
                &mut status,
                ptr::null_mut(),
            );
            assert!(!e.is_null());
            // 无效描述符被拒绝；有效描述符（socketpair）启动后 Core 在运行。
            assert_eq!(
                oryn_engine_start(e, -1, ptr::null_mut()),
                ORYN_ERR_INVALID_ARGUMENT
            );
            assert_eq!(oryn_engine_is_running(e), 0);
            let (local, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
            assert_eq!(
                oryn_engine_start(e, std::os::fd::AsRawFd::as_raw_fd(&local), ptr::null_mut()),
                ORYN_OK
            );
            assert_eq!(oryn_engine_is_running(e), 1);
            let req = b"{\"cmd\":\"stats\"}";
            let r = oryn_engine_command(e, req.as_ptr(), req.len());
            assert!(CStr::from_ptr(r).to_str().unwrap().contains("\"upload\""));
            oryn_string_free(r);
            oryn_engine_stop(e);
            oryn_engine_stop(e);
            oryn_engine_destroy(e);
            assert!(CStr::from_ptr(oryn_version())
                .to_str()
                .unwrap()
                .starts_with("0."));
        }
    }
}
