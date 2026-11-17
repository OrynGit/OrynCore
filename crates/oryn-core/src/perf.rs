//! 事件循环分段计时（诊断用）：`stats` 的 `loop_perf` 字段。
//!
//! 计数器全是 Relaxed 原子；开销只有每段两次 `Instant::now()`。
//! `thread_cpu_ns` 是事件循环线程累计 CPU 时间，与各段耗时之差就是 relay / 出站任务等其余部分。

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

/// 开发标记文件（放在 Core 数据目录里，由 App 的自动测试按需写入 / 清除；普通设备上不存在）。
/// - `oryn-perf-debug`：打开重量级诊断（PC 采样线程、心跳文件）。
/// - `oryn-no-offload`：关闭大流量出站卸载（做受控 A/B 对比用）。
/// - `oryn-offload-up`：上行字节也触发卸载（实验）。
static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static INGEST_SELFTEST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static NO_OFFLOAD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static OFFLOAD_UP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Engine 启动时读取一次标记文件。
pub fn load_markers(dir: Option<&std::path::Path>) {
    let has = |name: &str| dir.is_some_and(|d| d.join(name).exists());
    DEBUG.store(has("oryn-perf-debug"), Relaxed);
    NO_OFFLOAD.store(has("oryn-no-offload"), Relaxed);
    INGEST_SELFTEST.store(has("oryn-ingest-selftest"), Relaxed);
    OFFLOAD_UP.store(has("oryn-offload-up"), Relaxed);
}

pub fn debug_enabled() -> bool {
    DEBUG.load(Relaxed)
}

/// `oryn-offload-up`：上行（写出站流）累计字节也触发卸载（实验用，默认只按下行字节触发）。
pub fn offload_up_enabled() -> bool {
    OFFLOAD_UP.load(Relaxed)
}

/// `oryn-ingest-selftest`：隧道启动后在扩展里自己扮演 TCP 客户端上传，测处理路径吞吐（见 `ingest_selftest.rs`）。
pub fn ingest_selftest_enabled() -> bool {
    INGEST_SELFTEST.load(Relaxed)
}

pub fn offload_enabled() -> bool {
    !NO_OFFLOAD.load(Relaxed)
}

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        $(pub static $name: AtomicU64 = AtomicU64::new(0);)*
    };
}

counters!(
    RX_NS, RX_PKTS, RX_BYTES, TX_NS, TX_PKTS, TX_BYTES, TX_WOULDBLOCK, UTUN_POLLS, INPUT_NS,
    DISPATCH_NS, ENQUEUE_NS, LOOP_ITERS, LOOP_UTUN, LOOP_NOTIFY, LOOP_TIMER, LOOP_MSG, RX_CALLS,
    TX_CALLS, RX_MODE, TX_MODE, TX_QUEUE_DROPS, READER_CPU_NS, WRITER_CPU_NS, IO_ERRORS, LAST_ERRNO, OFFLOADED, KQ_SUM, KQ_N, KQ_MAX, UQ_SUM, UQ_N, UQ_MAX, TQ_SUM, TQ_N, TQ_MAX, SYNTH_UDP_PKTS, SYNTH_UDP_BYTES,
);

/// 供 `stats` 查询系统 utun MTU 的描述符（提供方 fd 在 Engine 存活期间有效）。
pub static UTUN_FD: AtomicI32 = AtomicI32::new(-1);

#[inline]
pub fn add(counter: &AtomicU64, value: u64) {
    counter.fetch_add(value, Relaxed);
}

#[inline]
pub fn since(start: Instant) -> u64 {
    start.elapsed().as_nanos() as u64
}

fn thread_cpu_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: 传入有效的 timespec 指针。
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// 整个进程累计的 CPU 时间（用户 + 内核），含全部线程；用来看扩展一共占了几个核。
fn process_cpu_ns() -> u64 {
    // SAFETY: 传入有效的 rusage 指针。
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let ns = |t: libc::timeval| t.tv_sec as u64 * 1_000_000_000 + t.tv_usec as u64 * 1_000;
    ns(usage.ru_utime) + ns(usage.ru_stime)
}

/// 在事件循环线程上调用，`thread_cpu_ns` 才是该线程的值。
pub fn snapshot() -> serde_json::Value {
    serde_json::json!({
        "thread_cpu_ns": thread_cpu_ns(),
        "proc_cpu_ns": process_cpu_ns(),
        "profile": profile(),
        "utun": utun_mtu(UTUN_FD.load(Relaxed)),
        "rx_ns": RX_NS.load(Relaxed), "rx_pkts": RX_PKTS.load(Relaxed), "rx_bytes": RX_BYTES.load(Relaxed),
        "tx_ns": TX_NS.load(Relaxed), "tx_pkts": TX_PKTS.load(Relaxed), "tx_bytes": TX_BYTES.load(Relaxed),
        "tx_wouldblock": TX_WOULDBLOCK.load(Relaxed), "utun_polls": UTUN_POLLS.load(Relaxed),
        "input_ns": INPUT_NS.load(Relaxed), "dispatch_ns": DISPATCH_NS.load(Relaxed),
        "enqueue_ns": ENQUEUE_NS.load(Relaxed),
        "loop_iters": LOOP_ITERS.load(Relaxed), "loop_utun": LOOP_UTUN.load(Relaxed),
        "loop_notify": LOOP_NOTIFY.load(Relaxed), "loop_timer": LOOP_TIMER.load(Relaxed),
        "loop_msg": LOOP_MSG.load(Relaxed),
        "rx_calls": RX_CALLS.load(Relaxed), "tx_calls": TX_CALLS.load(Relaxed),
        "rx_mode": RX_MODE.load(Relaxed), "tx_mode": TX_MODE.load(Relaxed),
        "tx_queue_drops": TX_QUEUE_DROPS.load(Relaxed),
        "offloaded_flows": OFFLOADED.load(Relaxed),
        "queue_depth": {
            "kernel_ctl_pkts": { "sum": KQ_SUM.load(Relaxed), "n": KQ_N.load(Relaxed), "max": KQ_MAX.load(Relaxed) },
            "reader_to_loop_pkts": { "sum": UQ_SUM.load(Relaxed), "n": UQ_N.load(Relaxed), "max": UQ_MAX.load(Relaxed) },
            "loop_to_writer_pkts": { "sum": TQ_SUM.load(Relaxed), "n": TQ_N.load(Relaxed), "max": TQ_MAX.load(Relaxed) },
        }, "synth_udp_pkts": SYNTH_UDP_PKTS.load(Relaxed), "synth_udp_bytes": SYNTH_UDP_BYTES.load(Relaxed), "io_errors": IO_ERRORS.load(Relaxed), "last_errno": LAST_ERRNO.load(Relaxed),
        "reader_cpu_ns": READER_CPU_NS.load(Relaxed), "writer_cpu_ns": WRITER_CPU_NS.load(Relaxed),
    })
}

/// utun 接口名与系统实际 MTU（Darwin：UTUN_OPT_IFNAME + SIOCGIFMTU）。诊断 `NEPacketTunnelNetworkSettings.mtu` 是否生效。
#[cfg(target_vendor = "apple")]
pub fn utun_mtu(fd: std::os::fd::RawFd) -> serde_json::Value {
    let mut name = [0u8; 32];
    let mut len = name.len() as libc::socklen_t;
    // SYSPROTO_CONTROL = 2, UTUN_OPT_IFNAME = 2
    let rc = unsafe { libc::getsockopt(fd, 2, 2, name.as_mut_ptr().cast(), &mut len) };
    if rc != 0 {
        return serde_json::Value::Null;
    }
    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        mtu: i32,
        pad: [u8; 12],
    }
    let mut req = IfReq { name: [0; 16], mtu: 0, pad: [0; 12] };
    let n = name.iter().position(|b| *b == 0).unwrap_or(15).min(15);
    req.name[..n].copy_from_slice(&name[..n]);
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return serde_json::Value::Null;
    }
    // SIOCGIFMTU = _IOWR('i', 51, struct ifreq)
    let rc = unsafe { libc::ioctl(sock, 0xc020_6933, &mut req as *mut IfReq) };
    let current = if rc == 0 { req.mtu } else { -1 };
    unsafe { libc::close(sock) };
    let buffers = {
        let get = |option: libc::c_int| -> i64 {
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
            let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, option, (&mut value as *mut libc::c_int).cast(), &mut len) };
            if rc == 0 { value as i64 } else { -1 }
        };
        serde_json::json!({ "rcvbuf": get(libc::SO_RCVBUF), "sndbuf": get(libc::SO_SNDBUF) })
    };
    let ifname = String::from_utf8_lossy(&name[..n]).into_owned();
    serde_json::json!({ "name": ifname, "mtu": current, "buf": buffers, "ifstats": interface_stats(&ifname) })
}

#[cfg(not(target_vendor = "apple"))]
pub fn utun_mtu(_fd: std::os::fd::RawFd) -> serde_json::Value {
    serde_json::Value::Null
}

// ---- 事件循环线程 PC 采样（Apple 平台，诊断用）----
//
// 采样线程以 ~500 Hz 挂起事件循环线程、读取 PC、立刻恢复；结果落在固定大小的原子哈希表里，
// 挂起期间不分配内存、不加锁（否则被挂起的线程若持有 malloc 锁会死锁）。
// `stats.loop_perf.profile` 返回 [pc, 次数] 列表与主镜像基址，离线用 `nm` 符号化。

#[cfg(target_vendor = "apple")]
mod sampler {
    use super::*;
    use std::sync::atomic::{AtomicU32, AtomicBool};

    const SLOTS: usize = 8192;
    const NAME_SLOTS_OR_SLOTS: usize = SLOTS;
    static NAME_KEYS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
    static NAME_COUNTS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
    static MAIN_BASE: AtomicU64 = AtomicU64::new(0);
    static KEYS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
    static COUNTS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
    pub static LOOP_PORT: AtomicU32 = AtomicU32::new(0);
    static STARTED: AtomicBool = AtomicBool::new(false);
    static SAMPLES: AtomicU64 = AtomicU64::new(0);
    static MISSES: AtomicU64 = AtomicU64::new(0);

    extern "C" {
        fn pthread_mach_thread_np(thread: libc::pthread_t) -> u32;
        fn thread_suspend(thread: u32) -> i32;
        fn thread_resume(thread: u32) -> i32;
        fn thread_get_state(thread: u32, flavor: i32, state: *mut u32, count: *mut u32) -> i32;
    }

    pub fn mark_loop_thread() {
        if !debug_enabled() {
            return;
        }
        // SAFETY: 取当前线程的 mach 端口。
        LOOP_PORT.store(unsafe { pthread_mach_thread_np(libc::pthread_self()) }, Relaxed);
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        if unsafe { libc::dladdr(mark_loop_thread as *const () as *const libc::c_void, &mut info) } != 0 {
            MAIN_BASE.store(info.dli_fbase as u64, Relaxed);
        }
        if STARTED.swap(true, Relaxed) {
            return;
        }
        let _ = std::thread::Builder::new().name("oryn-sampler".into()).spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_millis(2));
            let port = LOOP_PORT.load(Relaxed);
            if port == 0 {
                continue;
            }
            // ARM_THREAD_STATE64 = 6；x0..x28, fp, lr, sp, pc, cpsr, flags
            let mut state = [0u64; 34];
            let mut count = 68u32;
            let pc = unsafe {
                if thread_suspend(port) != 0 {
                    continue;
                }
                let rc = thread_get_state(port, 6, state.as_mut_ptr().cast(), &mut count);
                thread_resume(port);
                if rc != 0 { 0 } else { state[32] }
            };
            if pc == 0 {
                continue;
            }
            SAMPLES.fetch_add(1, Relaxed);
            // 目标线程已恢复运行：此时再用 dladdr 给非主镜像的 PC 取符号名（dyld 锁不会被被挂起的线程占住）
            let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
            let found = unsafe { libc::dladdr(pc as *const libc::c_void, &mut info) } != 0;
            let main = MAIN_BASE.load(Relaxed);
            if found && info.dli_fbase as u64 != main {
                let key = if info.dli_sname.is_null() {
                    (info.dli_fbase as u64) | (1 << 63)
                } else {
                    info.dli_sname as u64
                };
                record_in(&NAME_KEYS, &NAME_COUNTS, key);
            } else {
                record_in(&KEYS, &COUNTS, pc);
            }
        });
    }

    fn record_in(keys: &[AtomicU64; NAME_SLOTS_OR_SLOTS], counts: &[AtomicU64; NAME_SLOTS_OR_SLOTS], pc: u64) {
        let mut i = (pc.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 51) as usize % SLOTS;
        for _ in 0..64 {
            let key = keys[i].load(Relaxed);
            if key == pc {
                counts[i].fetch_add(1, Relaxed);
                return;
            }
            if key == 0
                && (keys[i].compare_exchange(0, pc, Relaxed, Relaxed).is_ok() || keys[i].load(Relaxed) == pc)
            {
                counts[i].fetch_add(1, Relaxed);
                return;
            }
            i = (i + 1) % SLOTS;
        }
        MISSES.fetch_add(1, Relaxed);
    }

    pub fn profile() -> serde_json::Value {
        let mut top: Vec<(u64, u64)> = (0..SLOTS)
            .filter_map(|i| {
                let k = KEYS[i].load(Relaxed);
                (k != 0).then(|| (k, COUNTS[i].load(Relaxed)))
            })
            .collect();
        top.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        top.truncate(400);
        // 主镜像基址：取本函数地址所在镜像
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        let base = if unsafe { libc::dladdr(profile as *const () as *const libc::c_void, &mut info) } != 0 {
            info.dli_fbase as u64
        } else {
            0
        };
        // 非主镜像：键是 dli_sname 指针（镜像常驻，指针有效）或 fbase|1<<63
        let mut named: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for i in 0..SLOTS {
            let k = NAME_KEYS[i].load(Relaxed);
            if k == 0 {
                continue;
            }
            let name = if k >> 63 == 1 {
                format!("image@{:#x}", k & !(1 << 63))
            } else {
                // SAFETY: dladdr 返回的符号名指向镜像里的 C 字符串，镜像不会卸载。
                unsafe { std::ffi::CStr::from_ptr(k as *const libc::c_char) }.to_string_lossy().into_owned()
            };
            *named.entry(name).or_default() += NAME_COUNTS[i].load(Relaxed);
        }
        serde_json::json!({
            "base": base, "samples": SAMPLES.load(Relaxed), "misses": MISSES.load(Relaxed),
            "top": top.into_iter().map(|(pc, n)| [pc, n]).collect::<Vec<_>>(),
            "other": named,
        })
    }
}

#[cfg(target_vendor = "apple")]
pub fn mark_loop_thread() {
    sampler::mark_loop_thread();
}
#[cfg(target_vendor = "apple")]
pub fn profile() -> serde_json::Value {
    sampler::profile()
}
#[cfg(not(target_vendor = "apple"))]
pub fn mark_loop_thread() {}
#[cfg(not(target_vendor = "apple"))]
pub fn profile() -> serde_json::Value {
    serde_json::Value::Null
}

/// utun 接口在内核里的统计（`getifaddrs` 的 AF_LINK `if_data`）：收发包数与字节、错误、输入队列丢包。
/// 内核往 utun 入队失败（控制套接字缓冲满等）算 `oerrors`；`iqdrops` 是输入队列丢包。
#[cfg(target_vendor = "apple")]
fn interface_stats(name: &str) -> serde_json::Value {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs 返回的链表由 freeifaddrs 释放。
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return serde_json::Value::Null;
    }
    let mut result = serde_json::Value::Null;
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: 链表节点在 freeifaddrs 之前有效。
        let entry = unsafe { &*cursor };
        let matches_name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_str().is_ok_and(|n| n == name);
        let is_link = !entry.ifa_addr.is_null() && unsafe { (*entry.ifa_addr).sa_family } as i32 == libc::AF_LINK;
        if matches_name && is_link && !entry.ifa_data.is_null() {
            // SAFETY: AF_LINK 条目的 ifa_data 指向 struct if_data。
            let data = unsafe { &*(entry.ifa_data as *const libc::if_data) };
            result = serde_json::json!({
                "ipackets": data.ifi_ipackets, "ierrors": data.ifi_ierrors,
                "opackets": data.ifi_opackets, "oerrors": data.ifi_oerrors,
                "ibytes": data.ifi_ibytes, "obytes": data.ifi_obytes,
                "iqdrops": data.ifi_iqdrops, "noproto": data.ifi_noproto, "collisions": data.ifi_collisions,
            });
            break;
        }
        cursor = entry.ifa_next;
    }
    // SAFETY: 释放 getifaddrs 分配的链表。
    unsafe { libc::freeifaddrs(head) };
    result
}

/// 记录一次队列深度采样（总和 / 次数 / 最大值），`stats.loop_perf.queue_depth` 输出。
pub fn sample_depth(sum: &AtomicU64, n: &AtomicU64, max: &AtomicU64, depth: u64) {
    sum.fetch_add(depth, Relaxed);
    n.fetch_add(1, Relaxed);
    max.fetch_max(depth, Relaxed);
}
