//! utun 读写线程：把每包 `recvmsg` / `sendmsg` 系统调用移出 lwIP 所在的事件循环线程。
//!
//! 真机测量（见 Oryn_dev/docs/oryncore/changelog/changelog-tunnel-throughput.md）：utun MTU 被 iOS 钳在 1500，上行时事件循环
//! 线程 50% 以上的 CPU 花在 utun 读取上，每秒包数受单线程系统调用开销限制。这里：
//! - 读线程 `poll` 等待可读，一次唤醒读到读空（Darwin 上先尝试批量 `recvmsg_x`，不支持则退回
//!   单包 `recvmsg`），按批交给事件循环；
//! - 写线程接收事件循环交来的输出包，批量发送（同样先尝试 `sendmsg_x`）；
//! - lwIP、Router、relay 仍只在事件循环线程，不跨线程共享任何 lwIP 状态；线程之间只交换 `Vec<u8>`。
//!
//! 所有队列有界：读队列满时读线程停止读取（内核 utun 缓冲满后丢包，TCP 自行退避）；
//! 写队列满时丢弃新包（与原 `UtunRuntime` 的有界丢弃一致）。

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use oryn_netstack::utun::decode_frame;
use oryn_netstack::LwipStack;
use tokio::sync::Notify;

use crate::perf;

/// 一次读取 / 发送的最大包数。
const BATCH: usize = 32;
/// 读队列最多积压的包数；满了读线程暂停读取。
const RX_QUEUE_MAX: usize = 512;
/// 回收池里最多保留的读缓冲数。
const RX_POOL_MAX: usize = 512;
/// 写队列上限，与原 `UtunRuntime` 一致。
const TX_QUEUE_MAX_PKTS: usize = 4096;
const TX_QUEUE_MAX_BYTES: usize = 4 * 1024 * 1024;
/// 写线程发送完毕、等待事件循环回收的缓冲数上限。
const TX_DONE_MAX: usize = 256;
const AF_HEADER_LEN: usize = 4;
/// utun 套接字收发缓冲目标大小。
const SOCKET_BUFFER: libc::c_int = 8 * 1024 * 1024;

/// Darwin 的 `struct msghdr_x`（`recvmsg_x` / `sendmsg_x` 使用的批量消息头）。
#[repr(C)]
struct MsgHdrX {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut libc::iovec,
    msg_iovlen: libc::c_int,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: libc::c_int,
    msg_datalen: usize,
}

type BatchFn = unsafe extern "C" fn(libc::c_int, *mut MsgHdrX, libc::c_uint, libc::c_int) -> isize;

/// 运行时查找 Darwin 的批量收发函数（不在公开头文件里，只能 dlsym）；找不到就走单包路径。
fn lookup_batch(name: &str) -> Option<BatchFn> {
    #[cfg(target_vendor = "apple")]
    {
        let symbol = std::ffi::CString::new(name).ok()?;
        // SAFETY: dlsym 只读取符号地址；函数签名与 XNU `bsd/sys/socket_private.h` 声明一致。
        let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
        if address.is_null() {
            return None;
        }
        // SAFETY: 地址来自上面的符号，签名见上。
        Some(unsafe { std::mem::transmute::<*mut libc::c_void, BatchFn>(address) })
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let _ = name;
        None
    }
}

/// 批量调用被内核拒绝（协议不支持）时返回 true，调用方永久退回单包路径。
fn batch_unsupported(errno: i32) -> bool {
    matches!(
        errno,
        libc::ENOTSUP | libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL | libc::ENOTSOCK
    )
}

/// 描述符本身失效、必须结束数据面的错误；其余错误（缓冲不足、瞬时失败等）只计数并继续。
fn fatal_errno(code: i32) -> bool {
    matches!(code, libc::EBADF | libc::ENOTCONN | libc::ENXIO | libc::ENODEV | libc::ENOTSOCK)
}

fn note_error(code: i32) {
    perf::add(&perf::IO_ERRORS, 1);
    perf::LAST_ERRNO.store(code as u64, Relaxed);
}

struct RxQueue {
    frames: Vec<Vec<u8>>,
}

struct TxQueue {
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
    /// 写线程正在等待新包。
    idle: bool,
}

struct Shared {
    fd: OwnedFd,
    wake_read: OwnedFd,
    wake_write: OwnedFd,
    stop: AtomicBool,
    error: Mutex<Option<io::Error>>,
    rx: Mutex<RxQueue>,
    rx_ready: Notify,
    rx_space: Condvar,
    rx_pool: Mutex<Vec<Vec<u8>>>,
    tx: Mutex<TxQueue>,
    tx_ready: Condvar,
    tx_done: Mutex<Vec<Vec<u8>>>,
    frame_cap: usize,
}

impl Shared {
    fn fail(&self, error: io::Error) {
        let mut slot = self.error.lock().unwrap();
        if slot.is_none() {
            *slot = Some(error);
        }
        drop(slot);
        self.rx_ready.notify_one();
    }

    fn stopped(&self) -> bool {
        self.stop.load(Relaxed)
    }
}

pub struct UtunThreads {
    shared: Arc<Shared>,
    /// 事件循环当前正在处理的一批帧（含 4 字节 address-family 头）。
    current: Vec<Vec<u8>>,
    threads: Vec<JoinHandle<()>>,
}

impl UtunThreads {
    /// 复制 `fd`（调用方保留原描述符）并启动读写线程。`mtu` 用于确定读缓冲大小。
    pub fn from_fd(fd: RawFd, mtu: u16) -> io::Result<Self> {
        // SAFETY: dup 的结果由本对象独占。
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(dup) };
        let mut pipe = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (wake_read, wake_write) =
            unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
        perf::UTUN_FD.store(owned.as_raw_fd(), Relaxed);
        // 内核 utun 控制套接字的收发缓冲默认很小：多条高速连接的在途数据（窗口 × 连接数）超出时内核静默丢包，
        // TCP 进入拥塞恢复，吞吐掉到 1/3（真机 4 流以上）。调大它们，生效值写进 `stats.loop_perf.utun_buf`。
        for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            let size: libc::c_int = SOCKET_BUFFER;
            unsafe {
                libc::setsockopt(
                    owned.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            };
        }
        let shared = Arc::new(Shared {
            fd: owned,
            wake_read,
            wake_write,
            stop: AtomicBool::new(false),
            error: Mutex::new(None),
            rx: Mutex::new(RxQueue { frames: Vec::new() }),
            rx_ready: Notify::new(),
            rx_space: Condvar::new(),
            rx_pool: Mutex::new(Vec::new()),
            tx: Mutex::new(TxQueue { packets: VecDeque::new(), bytes: 0, idle: false }),
            tx_ready: Condvar::new(),
            tx_done: Mutex::new(Vec::new()),
            frame_cap: (mtu as usize + 64).clamp(2048, 65_535 + 64),
        });
        let mut threads = Vec::new();
        if perf::debug_enabled() {
            let shared = shared.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("oryn-utun-beat".into())
                    .spawn(move || heartbeat(shared))
                    .map_err(|e| io::Error::other(format!("failed to spawn heartbeat: {e}")))?,
            );
        }
        for (name, run) in [
            ("oryn-utun-rx", reader as fn(Arc<Shared>)),
            ("oryn-utun-tx", writer as fn(Arc<Shared>)),
        ] {
            let shared = shared.clone();
            threads.push(
                std::thread::Builder::new()
                    .name(name.into())
                    .spawn(move || run(shared))
                    .map_err(|e| io::Error::other(format!("failed to spawn {name}: {e}")))?,
            );
        }
        Ok(Self { shared, current: Vec::new(), threads })
    }

    /// 等待读线程交来一批包，返回包数。读线程出错时返回该错误。
    pub async fn next(&mut self) -> io::Result<usize> {
        // 上一批已处理完：缓冲还给读线程复用
        if !self.current.is_empty() {
            let mut pool = self.shared.rx_pool.lock().unwrap();
            let room = RX_POOL_MAX.saturating_sub(pool.len());
            for mut frame in self.current.drain(..).take(room) {
                frame.clear();
                pool.push(frame);
            }
            self.current.clear();
        }
        loop {
            {
                let mut queue = self.shared.rx.lock().unwrap();
                if !queue.frames.is_empty() {
                    perf::sample_depth(&perf::UQ_SUM, &perf::UQ_N, &perf::UQ_MAX, queue.frames.len() as u64);
                    std::mem::swap(&mut self.current, &mut queue.frames);
                    drop(queue);
                    self.shared.rx_space.notify_one();
                    return Ok(self.current.len());
                }
            }
            if let Some(error) = self.shared.error.lock().unwrap().take() {
                return Err(error);
            }
            self.shared.rx_ready.notified().await;
        }
    }

    /// 最近一次 `next` 读到的包（IP 包，不含 address-family 头）。
    pub fn for_each_received(&self, mut f: impl FnMut(&[u8])) {
        for frame in &self.current {
            f(&frame[AF_HEADER_LEN..]);
        }
    }

    /// 把 Core 产生的输出包交给写线程。
    pub fn enqueue(&mut self, mut packets: Vec<Vec<u8>>, stack: &LwipStack) -> io::Result<()> {
        {
            let mut done = self.shared.tx_done.lock().unwrap();
            for packet in done.drain(..) {
                stack.recycle_output_packet(packet);
            }
        }
        let mut queue = self.shared.tx.lock().unwrap();
        let mut invalid = false;
        for packet in packets.drain(..) {
            if !matches!(packet.first().map(|b| b >> 4), Some(4) | Some(6)) {
                invalid = true;
                continue;
            }
            if queue.packets.len() >= TX_QUEUE_MAX_PKTS
                || queue.bytes.saturating_add(packet.len()) > TX_QUEUE_MAX_BYTES
            {
                perf::add(&perf::TX_QUEUE_DROPS, 1);
                stack.recycle_output_packet(packet);
                continue; // 有界丢弃，不阻塞或终止事件循环。
            }
            queue.bytes += packet.len();
            queue.packets.push_back(packet);
        }
        let wake = queue.idle;
        drop(queue);
        if wake {
            self.shared.tx_ready.notify_one();
        }
        stack.recycle_output_batch(packets);
        if invalid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Core produced an invalid IP packet",
            ));
        }
        Ok(())
    }
}

impl Drop for UtunThreads {
    fn drop(&mut self) {
        self.shared.stop.store(true, Relaxed);
        // 叫醒 poll 中的读 / 写线程以及等待条件变量的线程
        let byte = 1u8;
        unsafe { libc::write(self.shared.wake_write.as_raw_fd(), (&byte as *const u8).cast(), 1) };
        self.shared.rx_space.notify_all();
        {
            let _guard = self.shared.tx.lock().unwrap();
            self.shared.tx_ready.notify_all();
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// 在 `fd` 上等待事件，同时监听停止管道。返回 false 表示应当退出。
fn wait_fd(shared: &Shared, events: libc::c_short, timeout_ms: libc::c_int) -> io::Result<bool> {
    let mut fds = [
        libc::pollfd { fd: shared.fd.as_raw_fd(), events, revents: 0 },
        libc::pollfd { fd: shared.wake_read.as_raw_fd(), events: libc::POLLIN, revents: 0 },
    ];
    loop {
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
        if rc >= 0 {
            return Ok(!shared.stopped());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn thread_cpu() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) } != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// 读到 `bufs[..n]`（每个缓冲预留 `frame_cap` 容量），返回收到的帧数，0 表示暂无数据。
fn read_frames(
    fd: RawFd,
    bufs: &mut [Vec<u8>],
    cap: usize,
    batch_fn: &mut Option<BatchFn>,
) -> io::Result<usize> {
    let want = bufs.len();
    if let Some(call) = *batch_fn {
        let mut iov: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
        let mut hdrs: [MsgHdrX; BATCH] = unsafe { std::mem::zeroed() };
        for i in 0..want {
            iov[i] = libc::iovec { iov_base: bufs[i].as_mut_ptr().cast(), iov_len: cap };
            hdrs[i].msg_iov = &mut iov[i];
            hdrs[i].msg_iovlen = 1;
        }
        let start = Instant::now();
        let n = unsafe { call(fd, hdrs.as_mut_ptr(), want as libc::c_uint, libc::MSG_DONTWAIT) };
        perf::add(&perf::RX_NS, perf::since(start));
        perf::add(&perf::RX_CALLS, 1);
        if n >= 0 {
            let n = n as usize;
            for i in 0..n {
                let len = if hdrs[i].msg_flags & libc::MSG_TRUNC != 0 {
                    0
                } else {
                    hdrs[i].msg_datalen.min(cap)
                };
                // SAFETY: 内核已写入前 `len` 字节，容量为 `cap`。
                unsafe { bufs[i].set_len(len) };
            }
            return Ok(n);
        }
        let code = errno();
        if code == libc::EAGAIN || code == libc::EINTR {
            return Ok(0);
        }
        if batch_unsupported(code) && code != libc::EINVAL {
            perf::RX_MODE.store(1, Relaxed);
            *batch_fn = None; // 退回单包路径，本次不丢数据
        } else if fatal_errno(code) {
            return Err(io::Error::from_raw_os_error(code));
        } else {
            // 瞬时错误：计数，退回单包路径重试这一批（EINVAL 多半是批量参数问题）
            note_error(code);
            if code == libc::EINVAL {
                perf::RX_MODE.store(1, Relaxed);
                *batch_fn = None;
            }
            return Ok(0);
        }
    } else {
        perf::RX_MODE.store(1, Relaxed);
    }
    let mut count = 0;
    while count < want {
        let buf = &mut bufs[count];
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: cap };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let start = Instant::now();
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
        perf::add(&perf::RX_NS, perf::since(start));
        perf::add(&perf::RX_CALLS, 1);
        if n < 0 {
            let code = errno();
            if code == libc::EAGAIN {
                break;
            }
            if code == libc::EINTR {
                continue;
            }
            if fatal_errno(code) {
                return Err(io::Error::from_raw_os_error(code));
            }
            note_error(code);
            break;
        }
        let len = if msg.msg_flags & libc::MSG_TRUNC != 0 { 0 } else { n as usize };
        unsafe { buf.set_len(len) };
        count += 1;
    }
    Ok(count)
}

fn reader(shared: Arc<Shared>) {
    let fd = shared.fd.as_raw_fd();
    let cap = shared.frame_cap;
    let mut batch_fn = lookup_batch("recvmsg_x");
    perf::RX_MODE.store(if batch_fn.is_some() { 2 } else { 1 }, Relaxed);
    let mut bufs: Vec<Vec<u8>> = (0..BATCH).map(|_| Vec::with_capacity(cap)).collect();
    let mut valid: Vec<Vec<u8>> = Vec::with_capacity(BATCH);
    let mut last_errors = 0u64;
    'outer: loop {
        match wait_fd(&shared, libc::POLLIN, -1) {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => {
                shared.fail(e);
                break;
            }
        }
        perf::READER_CPU_NS.store(thread_cpu(), Relaxed);
        loop {
            if shared.stopped() {
                break 'outer;
            }
            // 读队列满：暂停读取，等事件循环消费
            {
                let mut queue = shared.rx.lock().unwrap();
                while queue.frames.len() >= RX_QUEUE_MAX && !shared.stopped() {
                    queue = shared.rx_space.wait_timeout(queue, Duration::from_millis(20)).unwrap().0;
                }
            }
            if perf::debug_enabled() {
                // 内核 utun 控制套接字接收缓冲里等着我们取走的包数（SO_NUMRCVPKT = 0x1112）
                let mut pending: libc::c_int = 0;
                let mut len = std::mem::size_of_val(&pending) as libc::socklen_t;
                if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, 0x1112, (&mut pending as *mut libc::c_int).cast(), &mut len) } == 0 {
                    perf::sample_depth(&perf::KQ_SUM, &perf::KQ_N, &perf::KQ_MAX, pending.max(0) as u64);
                }
            }
            let received = match read_frames(fd, &mut bufs, cap, &mut batch_fn) {
                Ok(n) => n,
                Err(e) => {
                    shared.fail(e);
                    break 'outer;
                }
            };
            if received == 0 {
                if perf::IO_ERRORS.load(Relaxed) != last_errors {
                    last_errors = perf::IO_ERRORS.load(Relaxed);
                    std::thread::sleep(Duration::from_millis(1)); // 持续出错时不空转
                }
                break;
            }
            for buf in bufs.iter_mut().take(received) {
                let ok = !buf.is_empty() && decode_frame(buf).is_ok();
                if ok {
                    perf::add(&perf::RX_PKTS, 1);
                    perf::add(&perf::RX_BYTES, (buf.len() - AF_HEADER_LEN) as u64);
                    valid.push(std::mem::take(buf));
                } else {
                    buf.clear();
                }
            }
            if !valid.is_empty() {
                shared.rx.lock().unwrap().frames.append(&mut valid);
                shared.rx_ready.notify_one();
            }
            // 补齐被交出去的缓冲
            if bufs.iter().any(|b| b.capacity() == 0) {
                let mut pool = shared.rx_pool.lock().unwrap();
                for buf in bufs.iter_mut().filter(|b| b.capacity() == 0) {
                    *buf = pool.pop().unwrap_or_else(|| Vec::with_capacity(cap));
                }
            }
        }
    }
}

enum Sent {
    All,
    Dropped,
}

fn writer(shared: Arc<Shared>) {
    let fd = shared.fd.as_raw_fd();
    let mut batch_fn = lookup_batch("sendmsg_x");
    perf::TX_MODE.store(if batch_fn.is_some() { 2 } else { 1 }, Relaxed);
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(BATCH);
    loop {
        {
            let mut queue = shared.tx.lock().unwrap();
            while queue.packets.is_empty() && !shared.stopped() {
                queue.idle = true;
                queue = shared.tx_ready.wait(queue).unwrap();
            }
            queue.idle = false;
            if shared.stopped() {
                break;
            }
            perf::sample_depth(&perf::TQ_SUM, &perf::TQ_N, &perf::TQ_MAX, queue.packets.len() as u64);
            let take = queue.packets.len().min(BATCH);
            for _ in 0..take {
                let packet = queue.packets.pop_front().unwrap();
                queue.bytes -= packet.len();
                batch.push(packet);
            }
        }
        perf::WRITER_CPU_NS.store(thread_cpu(), Relaxed);
        if let Err(e) = send_batch(&shared, fd, &mut batch, &mut batch_fn) {
            shared.fail(e);
            break;
        }
        let mut done = shared.tx_done.lock().unwrap();
        let room = TX_DONE_MAX.saturating_sub(done.len());
        done.extend(batch.drain(..).take(room));
        drop(done);
        batch.clear();
    }
}

/// 诊断心跳：每 250 ms 把计数与队列长度写到临时目录，事件循环卡死后仍可从设备上取回。
fn heartbeat(shared: Arc<Shared>) {
    let path = std::env::temp_dir().join("oryn-perf-heartbeat.json");
    let mut seq = 0u64;
    while !shared.stopped() {
        let _ = wait_fd_timeout(&shared, 250);
        seq += 1;
        let rx_len = shared.rx.try_lock().map(|q| q.frames.len() as i64).unwrap_or(-1);
        let (tx_len, tx_idle) = shared.tx.try_lock().map(|q| (q.packets.len() as i64, q.idle)).unwrap_or((-1, false));
        let mut value = perf::snapshot();
        value["seq"] = seq.into();
        value["rx_queue"] = rx_len.into();
        value["tx_queue"] = tx_len.into();
        value["tx_idle"] = tx_idle.into();
        value["error"] = shared.error.try_lock().map(|e| e.as_ref().map(|e| e.to_string())).unwrap_or(None).into();
        let _ = std::fs::write(&path, value.to_string());
    }
}

/// 只睡眠，被停止管道叫醒时提前返回。
fn wait_fd_timeout(shared: &Shared, ms: libc::c_int) -> io::Result<()> {
    let mut fds = [libc::pollfd { fd: shared.wake_read.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
    unsafe { libc::poll(fds.as_mut_ptr(), 1, ms) };
    Ok(())
}

fn af_header(packet: &[u8]) -> [u8; AF_HEADER_LEN] {
    let af = if packet[0] >> 4 == 6 { libc::AF_INET6 } else { libc::AF_INET };
    (af as u32).to_be_bytes()
}

/// 发送整批；内核缓冲满（`EAGAIN`）时等待可写，`ENOBUFS` 丢弃该包（TCP 会重传）。
fn send_batch(
    shared: &Shared,
    fd: RawFd,
    batch: &mut [Vec<u8>],
    batch_fn: &mut Option<BatchFn>,
) -> io::Result<()> {
    let mut index = 0;
    while index < batch.len() {
        if shared.stopped() {
            return Ok(());
        }
        if let Some(call) = *batch_fn {
            let count = (batch.len() - index).min(BATCH);
            let headers: Vec<[u8; AF_HEADER_LEN]> =
                batch[index..index + count].iter().map(|p| af_header(p)).collect();
            let mut iov: [libc::iovec; BATCH * 2] = unsafe { std::mem::zeroed() };
            let mut hdrs: [MsgHdrX; BATCH] = unsafe { std::mem::zeroed() };
            for i in 0..count {
                let packet = &batch[index + i];
                iov[2 * i] = libc::iovec { iov_base: headers[i].as_ptr().cast_mut().cast(), iov_len: AF_HEADER_LEN };
                iov[2 * i + 1] = libc::iovec { iov_base: packet.as_ptr().cast_mut().cast(), iov_len: packet.len() };
                hdrs[i].msg_iov = &mut iov[2 * i];
                hdrs[i].msg_iovlen = 2;
                hdrs[i].msg_datalen = AF_HEADER_LEN + packet.len();
            }
            let start = Instant::now();
            let n = unsafe { call(fd, hdrs.as_mut_ptr(), count as libc::c_uint, libc::MSG_DONTWAIT) };
            perf::add(&perf::TX_NS, perf::since(start));
            perf::add(&perf::TX_CALLS, 1);
            if n > 0 {
                for packet in &batch[index..index + n as usize] {
                    perf::add(&perf::TX_PKTS, 1);
                    perf::add(&perf::TX_BYTES, packet.len() as u64);
                }
                index += n as usize;
                continue;
            }
            let code = if n == 0 { libc::EAGAIN } else { errno() };
            match code {
                libc::EINTR => continue,
                libc::EAGAIN => {
                    perf::add(&perf::TX_WOULDBLOCK, 1);
                    if !wait_fd(shared, libc::POLLOUT, 100)? {
                        return Ok(());
                    }
                    continue;
                }
                libc::ENOBUFS => {
                    oryn_netstack::utun::BUFFER_FULL_DROPS.fetch_add(1, Relaxed);
                    index += 1; // 丢弃队首，继续
                    continue;
                }
                c if batch_unsupported(c) => {
                    perf::TX_MODE.store(1, Relaxed);
                    *batch_fn = None;
                    note_error(c);
                    continue;
                }
                c if fatal_errno(c) => return Err(io::Error::from_raw_os_error(c)),
                c => {
                    note_error(c);
                    index += 1; // 丢弃队首，继续
                    continue;
                }
            }
        }
        match send_one(shared, fd, &batch[index])? {
            Sent::All => {
                perf::add(&perf::TX_PKTS, 1);
                perf::add(&perf::TX_BYTES, batch[index].len() as u64);
            }
            Sent::Dropped => {}
        }
        index += 1;
    }
    Ok(())
}

fn send_one(shared: &Shared, fd: RawFd, packet: &[u8]) -> io::Result<Sent> {
    let header = af_header(packet);
    let mut iov = [
        libc::iovec { iov_base: header.as_ptr().cast_mut().cast(), iov_len: AF_HEADER_LEN },
        libc::iovec { iov_base: packet.as_ptr().cast_mut().cast(), iov_len: packet.len() },
    ];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = 2;
    loop {
        let start = Instant::now();
        let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
        perf::add(&perf::TX_NS, perf::since(start));
        perf::add(&perf::TX_CALLS, 1);
        if n >= 0 {
            return Ok(Sent::All);
        }
        match errno() {
            libc::EINTR => continue,
            libc::EAGAIN => {
                perf::add(&perf::TX_WOULDBLOCK, 1);
                if !wait_fd(shared, libc::POLLOUT, 100)? {
                    return Ok(Sent::Dropped);
                }
            }
            libc::ENOBUFS => {
                oryn_netstack::utun::BUFFER_FULL_DROPS.fetch_add(1, Relaxed);
                return Ok(Sent::Dropped);
            }
            c if fatal_errno(c) => return Err(io::Error::from_raw_os_error(c)),
            c => {
                note_error(c);
                return Ok(Sent::Dropped);
            }
        }
    }
}

/// 事件循环使用的 utun 驱动：Apple 平台用读写线程，其余平台（Android）与回退路径用事件循环内 `poll` 读写。
pub enum UtunIo {
    Threads(UtunThreads),
    Poll(crate::utun_runtime::UtunRuntime),
}

impl UtunIo {
    pub fn from_fd(fd: RawFd, mtu: u16) -> io::Result<Self> {
        #[cfg(target_vendor = "apple")]
        {
            if std::env::var_os("ORYN_UTUN_POLL").is_none() {
                return Ok(Self::Threads(UtunThreads::from_fd(fd, mtu)?));
            }
        }
        let _ = mtu;
        Ok(Self::Poll(crate::utun_runtime::UtunRuntime::from_fd(fd)?))
    }

    pub async fn next(&mut self, stack: &LwipStack) -> io::Result<usize> {
        match self {
            Self::Threads(io) => io.next().await,
            Self::Poll(io) => io.next(stack).await,
        }
    }

    pub fn for_each_received(&self, mut f: impl FnMut(&[u8])) {
        match self {
            Self::Threads(io) => io.for_each_received(f),
            Self::Poll(io) => io.received().iter().for_each(|p| f(p)),
        }
    }

    pub fn enqueue(&mut self, packets: Vec<Vec<u8>>, stack: &LwipStack) -> io::Result<()> {
        match self {
            Self::Threads(io) => io.enqueue(packets, stack),
            Self::Poll(io) => io.enqueue(packets, stack),
        }
    }
}
