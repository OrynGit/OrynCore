//! lwIP 用户态协议栈。进程内同一时刻只允许一个实例，且只能在创建它的线程上使用。

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use log::{debug, warn};
use tokio::sync::Notify;

use crate::lwip::{self, err_t, tcp_pcb, ERR_ABRT, ERR_OK, ERR_VAL};
use crate::packet::{self, Parsed};
use crate::tcp::LwipTcpStream;
use crate::{NetStack, UdpDatagram};

static IN_USE: AtomicBool = AtomicBool::new(false);

/// 监听端口数上限，须不大于 lwipopts.h 的 MEMP_NUM_TCP_PCB_LISTEN。
const MAX_LISTENERS: usize = 120;
/// 待取走的新连接上限。
const MAX_PENDING_ACCEPT: usize = 256;
/// 待写回隧道的包数上限。
const MAX_OUTPUT_PACKETS: usize = 4096;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
/// 仅复用不超过虚拟接口 MTU（iOS 上限 4064 + 余量）的包；不把拥塞/大包高水位变成常驻内存。
/// 池最多保留 512 个（≈ 2 MiB）：4 KiB 的包每个都走 malloc/free 时，真机采样里 madvise 占事件循环线程约 10%。
const MAX_RECYCLED_PACKETS: usize = 512;
const MAX_RECYCLED_CAPACITY: usize = 4160;
const MAX_RECYCLED_BATCH: usize = 256;
/// 待处理的 UDP 数据报上限。
const MAX_PENDING_UDP: usize = 1024;
const MAX_PENDING_UDP_BYTES: usize = 1024 * 1024;
/// 定时器最长休眠。
const MAX_TIMER_SLEEP: Duration = Duration::from_millis(1000);

pub(crate) struct StackShared {
    output: RefCell<Vec<Vec<u8>>>,
    recycled: RefCell<Vec<Vec<u8>>>,
    output_bytes: Cell<usize>,
    output_dropped: Cell<u64>,
    accepted: RefCell<VecDeque<LwipTcpStream>>,
    udp_in: RefCell<VecDeque<UdpDatagram>>,
    udp_in_bytes: Cell<usize>,
    listeners: RefCell<HashMap<u16, Listener>>,
    tick: Cell<u64>,
    notify: Rc<Notify>,
    /// 当前有未确认数据的连接数，用来在连接之间分配发送窗口（见 tcp.rs `send_cap`）。
    pub(crate) senders: Cell<u32>,
}

struct Listener {
    pcb: *mut tcp_pcb,
    last_used: u64,
}

impl StackShared {
    pub(crate) fn wake(&self) {
        self.notify.notify_one();
    }

    fn output_full(&self, len: usize) -> bool {
        self.output.borrow().len() >= MAX_OUTPUT_PACKETS
            || self.output_bytes.get().saturating_add(len) > MAX_OUTPUT_BYTES
    }

    /// 把 lwIP 输出的 pbuf 链直接拷进回收的 Vec（只拷一次）。
    ///
    /// # Safety
    /// `p` 必须是有效的 pbuf 链。
    unsafe fn copy_output_pbuf(&self, p: *const lwip::pbuf) {
        let len = lwip::oryn_pbuf_tot_len(p) as usize;
        // 满队列不再先分配、复制然后丢弃。
        if len == 0 || self.output_full(len) {
            self.output_dropped.set(self.output_dropped.get() + 1);
            return;
        }
        let mut packet = self.recycled.borrow_mut().pop().unwrap_or_default();
        packet.clear();
        packet.reserve(len);
        let copied = lwip::pbuf_copy_partial(p, packet.as_mut_ptr().cast(), len as u16, 0) as usize;
        packet.set_len(copied);
        self.push_output(packet);
    }

    fn push_output(&self, pkt: Vec<u8>) {
        let mut out = self.output.borrow_mut();
        if out.len() >= MAX_OUTPUT_PACKETS
            || self.output_bytes.get().saturating_add(pkt.len()) > MAX_OUTPUT_BYTES
        {
            self.output_dropped.set(self.output_dropped.get() + 1);
            return;
        }
        self.output_bytes
            .set(self.output_bytes.get().saturating_add(pkt.len()));
        out.push(pkt);
        drop(out);
        self.wake();
    }
}

pub struct LwipStack {
    shared: Rc<StackShared>,
    /// 交给 C 侧的上下文指针（持有一份强引用，Drop 时释放）。
    ctx: *const StackShared,
    loopback: crate::loopback::Loopback,
    loopback_reflected: Cell<u64>,
    loopback_dropped: Cell<u64>,
    /// 本机没有 IPv6 时在握手前拒绝全局 IPv6（见 `packet::gate_global_ipv6`）。
    reject_global_ipv6: Cell<bool>,
    ipv6_rejected: Cell<u64>,
}

impl LwipStack {
    pub fn new(mtu: u16) -> io::Result<Self> {
        if IN_USE.swap(true, Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "another netstack instance is already running",
            ));
        }
        let shared = Rc::new(StackShared {
            output: RefCell::new(Vec::new()),
            recycled: RefCell::new(Vec::new()),
            output_bytes: Cell::new(0),
            output_dropped: Cell::new(0),
            accepted: RefCell::new(VecDeque::new()),
            udp_in: RefCell::new(VecDeque::new()),
            udp_in_bytes: Cell::new(0),
            listeners: RefCell::new(HashMap::new()),
            tick: Cell::new(0),
            notify: Rc::new(Notify::new()),
            senders: Cell::new(0),
        });
        let ctx = Rc::into_raw(shared.clone());
        unsafe { lwip::oryn_lwip_setup(mtu, Some(on_output), ctx as *mut c_void) };
        Ok(LwipStack {
            shared,
            ctx,
            loopback: Default::default(),
            loopback_reflected: Cell::new(0),
            loopback_dropped: Cell::new(0),
            reject_global_ipv6: Cell::new(false),
            ipv6_rejected: Cell::new(0),
        })
    }

    pub fn set_loopback(&mut self, source: Ipv4Addr, aliases: Vec<Ipv4Addr>) -> Result<(), &'static str> {
        self.loopback = crate::loopback::Loopback::new(source, aliases)?;
        Ok(())
    }

    pub fn loopback_counts(&self) -> (u64, u64) { (self.loopback_reflected.get(), self.loopback_dropped.get()) }

    /// 本机没有 IPv6 时打开：发往全局 IPv6 的新连接在握手前被拒绝。
    pub fn set_reject_global_ipv6(&self, on: bool) {
        self.reject_global_ipv6.set(on);
    }

    pub fn ipv6_rejected(&self) -> u64 {
        self.ipv6_rejected.get()
    }

    /// 有输出或新连接时被唤醒。
    pub fn notifier(&self) -> Rc<Notify> {
        self.shared.notify.clone()
    }

    /// 交付/丢弃完成后归还独占包；大包不入池，池最多保留 128 KiB 容量。
    pub fn recycle_output_packet(&self, mut packet: Vec<u8>) {
        if packet.capacity() == 0 || packet.capacity() > MAX_RECYCLED_CAPACITY {
            return;
        }
        let mut recycled = self.shared.recycled.borrow_mut();
        if recycled.len() < MAX_RECYCLED_PACKETS {
            packet.clear();
            recycled.push(packet);
        }
    }

    /// 回收已消费批次；保留小批次容器，丢弃拥塞期间增长的容器。
    pub fn recycle_output_batch(&self, mut packets: Vec<Vec<u8>>) {
        for packet in packets.drain(..) {
            self.recycle_output_packet(packet);
        }
        if packets.capacity() <= MAX_RECYCLED_BATCH {
            let mut output = self.shared.output.borrow_mut();
            if output.is_empty() && output.capacity() < packets.capacity() {
                *output = packets;
            }
        }
    }

    pub fn output_dropped(&self) -> u64 {
        self.shared.output_dropped.get()
    }

    /// lwIP 的 TCP pcb 数量：(active, time-wait, listen)。诊断用，遍历链表。
    pub fn pcb_counts(&self) -> (u32, u32, u32) {
        let mut out = [0u32; 3];
        unsafe { lwip::oryn_lwip_pcb_counts(out.as_mut_ptr()) };
        (out[0], out[1], out[2])
    }

    pub fn listener_count(&self) -> usize {
        self.shared.listeners.borrow().len()
    }

    fn ensure_listener(&self, port: u16) {
        let tick = self.shared.tick.get() + 1;
        self.shared.tick.set(tick);
        let mut listeners = self.shared.listeners.borrow_mut();
        if let Some(l) = listeners.get_mut(&port) {
            l.last_used = tick;
            return;
        }
        if listeners.len() >= MAX_LISTENERS {
            // 淘汰最久未用的监听；已建立的连接不受影响
            if let Some((&old, _)) = listeners.iter().min_by_key(|(_, l)| l.last_used) {
                let l = listeners.remove(&old).unwrap();
                unsafe {
                    lwip::tcp_arg(l.pcb, std::ptr::null_mut());
                    lwip::tcp_close(l.pcb);
                }
            }
        }
        let pcb = unsafe { lwip::oryn_tcp_listen(port, self.ctx as *mut c_void, Some(on_accept)) };
        if pcb.is_null() {
            warn!("failed to listen on port {port}");
            return;
        }
        listeners.insert(
            port,
            Listener {
                pcb,
                last_used: tick,
            },
        );
    }
}

impl NetStack for LwipStack {
    type TcpStream = LwipTcpStream;

    fn input_packet(&self, pkt: &[u8]) {
        if self.reject_global_ipv6.get() {
            if let packet::Ipv6Gate::Reply(reply) = packet::gate_global_ipv6(pkt) {
                self.ipv6_rejected
                    .set(self.ipv6_rejected.get().saturating_add(1));
                self.shared.push_output(reply);
                return;
            }
        }
        match self.loopback.reflect(pkt) {
            crate::loopback::Reflection::Pass => {},
            crate::loopback::Reflection::Drop => {
                self.loopback_dropped.set(self.loopback_dropped.get().saturating_add(1));
                return;
            },
            crate::loopback::Reflection::Packet(packet) => {
                self.loopback_reflected.set(self.loopback_reflected.get().saturating_add(1));
                self.shared.push_output(packet);
                return;
            },
        }
        match packet::parse(pkt) {
            Parsed::Udp { src, dst, payload } => {
                if packet::is_non_unicast(dst.ip()) {
                    return;
                }
                let mut q = self.shared.udp_in.borrow_mut();
                if q.len() < MAX_PENDING_UDP
                    && self.shared.udp_in_bytes.get().saturating_add(payload.len())
                        <= MAX_PENDING_UDP_BYTES
                {
                    self.shared
                        .udp_in_bytes
                        .set(self.shared.udp_in_bytes.get() + payload.len());
                    q.push_back(UdpDatagram {
                        src,
                        dst,
                        payload: payload.to_vec(),
                    });
                }
                return;
            }
            Parsed::Tcp { dst_port, syn } => {
                if syn {
                    self.ensure_listener(dst_port);
                }
            }
            Parsed::Other => {}
            Parsed::Invalid => return,
        }
        let err = unsafe { lwip::oryn_lwip_input(pkt.as_ptr(), pkt.len()) };
        if err != ERR_OK {
            debug!("lwIP input failed: {err}");
        }
    }

    fn poll_tcp(&self) -> Option<LwipTcpStream> {
        self.shared.accepted.borrow_mut().pop_front()
    }

    fn poll_udp(&self) -> Option<UdpDatagram> {
        let dg = self.shared.udp_in.borrow_mut().pop_front();
        if let Some(ref dg) = dg {
            self.shared.udp_in_bytes.set(
                self.shared
                    .udp_in_bytes
                    .get()
                    .saturating_sub(dg.payload.len()),
            );
        }
        dg
    }

    fn send_udp(&self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        if let Some(pkt) = packet::build_udp(src, dst, payload) {
            self.shared.push_output(pkt);
        }
    }

    fn take_output(&self) -> Vec<Vec<u8>> {
        self.shared.output_bytes.set(0);
        std::mem::take(&mut *self.shared.output.borrow_mut())
    }

    fn poll_timers(&self) -> Duration {
        unsafe { lwip::oryn_lwip_check_timeouts() };
        let ms = unsafe { lwip::oryn_lwip_sleeptime() };
        Duration::from_millis(ms as u64).clamp(Duration::from_millis(10), MAX_TIMER_SLEEP)
    }
}

impl Drop for LwipStack {
    fn drop(&mut self) {
        // 待取走的连接先释放（会关闭各自的 pcb），再清理 lwIP 内剩余的一切
        self.shared.accepted.borrow_mut().clear();
        self.shared.listeners.borrow_mut().clear();
        unsafe {
            lwip::oryn_lwip_reset();
            drop(Rc::from_raw(self.ctx));
        }
        IN_USE.store(false, Ordering::SeqCst);
    }
}

unsafe extern "C" fn on_output(ctx: *mut c_void, p: *const lwip::pbuf) {
    if ctx.is_null() || p.is_null() {
        return;
    }
    let shared = &*(ctx as *const StackShared);
    shared.copy_output_pbuf(p);
}

unsafe extern "C" fn on_accept(arg: *mut c_void, newpcb: *mut tcp_pcb, err: err_t) -> err_t {
    if arg.is_null() || newpcb.is_null() || err != ERR_OK {
        return ERR_VAL;
    }
    let shared = &*(arg as *const StackShared);
    if shared.accepted.borrow().len() >= MAX_PENDING_ACCEPT {
        lwip::tcp_abort(newpcb);
        return ERR_ABRT;
    }
    // 从裸指针恢复一份 Rc，供连接回调唤醒事件循环
    Rc::increment_strong_count(arg as *const StackShared);
    let shared_rc = Rc::from_raw(arg as *const StackShared);
    let stream = LwipTcpStream::attach(newpcb, Rc::downgrade(&shared_rc));
    shared.accepted.borrow_mut().push_back(stream);
    shared.wake();
    ERR_OK
}
