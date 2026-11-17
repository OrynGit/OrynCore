//! 基于 lwIP pcb 的 TCP 流，实现 `AsyncRead + AsyncWrite`。
//!
//! 生命周期：lwIP 回调通过 `tcp_arg` 持有 [`ConnState`] 的一份强引用。
//! - lwIP 释放 pcb 时（`err` 回调）释放这份引用；
//! - Rust 侧先 Drop 时，先解除回调再关闭 pcb，同样释放这份引用。
//!
//! 所有 lwIP 调用都在不持有 `RefCell` 借用的情况下进行，避免回调重入时冲突。

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::lwip::{self, err_t, pbuf, tcp_pcb, ERR_CLSD, ERR_MEM, ERR_OK};
use crate::stack::StackShared;

/// 与 lwipopts.h 的 TCP_SND_BUF 一致。
const SND_BUF: usize = 512 * 1024;
/// 所有正在发送的连接共享的在途数据预算，以及单连接下限。
///
/// 真机测量：往内核 utun 写入的在途数据超过约 1 MiB（4 KiB 包 ≈ 256 个）后，内核入站队列静默丢包，
/// TCP 进入拥塞恢复，多条下行连接的总吞吐从 11 Gbps 掉到 3–4 Gbps。连接少时每条仍可用满 SND_BUF。
const SEND_BUDGET: usize = 512 * 1024;
const SEND_MIN: usize = 32 * 1024;
/// 新连接的初始接收窗口（与握手里不带缩放的 65535 一致）。
///
/// lwIP 的接收窗口是「窗口 + 已缓冲」守恒的：消费多少放行多少，窗口自己不会变大，所以初始值就是上限。
/// 这里做接收窗口的“慢启动”（见 `poll_read`）：relay 读完后缓冲不超过窗口一半时额外多放行，直到 `RCV_WND_MAX`；
/// 对端慢、缓冲一直排不空的连接保持小窗口，避免很多慢连接各自缓冲 256 KiB。
const INITIAL_RCV_WND: u32 = 65535;
const RCV_WND_MAX: u32 = 512 * 1024;

fn send_cap(senders: u32) -> usize {
    (SEND_BUDGET / senders.max(1) as usize).clamp(SEND_MIN, SND_BUF)
}

struct ConnState {
    /// 是否已计入 `StackShared::senders`（有未确认数据）。
    sending: Cell<bool>,
    /// 当前放行的接收窗口总量（窗口 + 已缓冲），从 `INITIAL_RCV_WND` 起按需增长。
    rcv_window: Cell<u32>,
    pcb: Cell<*mut tcp_pcb>,
    recv: RefCell<RecvBuffer>,
    eof: Cell<bool>,
    error: Cell<Option<err_t>>,
    read_waker: RefCell<Option<Waker>>,
    write_waker: RefCell<Option<Waker>>,
    tx_shutdown: Cell<bool>,
    stack: Weak<StackShared>,
}

/// 可复用的接收缓冲。旧路径为每个 lwIP pbuf 分配临时 `Vec`，再复制进
/// `VecDeque`；现在由连接持有存储，保留 lwIP 的 TCP 背压，同时消除每包分配。
struct RecvBuffer {
    data: Vec<u8>,
    offset: usize,
}

impl RecvBuffer {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            offset: 0,
        }
    }

    fn available(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn compact_for(&mut self, additional: usize) {
        if self.offset == 0 {
            return;
        }
        let spare = self.data.capacity().saturating_sub(self.data.len());
        if spare < additional && self.offset >= self.data.len() / 2 {
            let remaining = self.available();
            self.data.copy_within(self.offset.., 0);
            self.data.truncate(remaining);
            self.offset = 0;
        }
    }

    unsafe fn append_pbuf(&mut self, p: *const pbuf, len: usize) -> usize {
        self.compact_for(len);
        self.data.reserve(len);
        let old_len = self.data.len();
        let dst = self.data.spare_capacity_mut().as_mut_ptr() as *mut c_void;
        let copied = lwip::pbuf_copy_partial(p, dst, len as u16, 0) as usize;
        self.data.set_len(old_len + copied);
        copied
    }

    fn read_into(&mut self, buf: &mut ReadBuf<'_>) -> usize {
        let n = self.available().min(buf.remaining());
        if n == 0 {
            return 0;
        }
        buf.put_slice(&self.data[self.offset..self.offset + n]);
        self.offset += n;
        if self.offset == self.data.len() {
            self.data.clear();
            self.offset = 0;
        }
        n
    }
}

impl ConnState {
    /// 进入 / 离开“有未确认数据”状态时维护全局计数。
    fn set_sending(&self, on: bool) {
        if self.sending.replace(on) == on {
            return;
        }
        if let Some(s) = self.stack.upgrade() {
            let n = s.senders.get();
            s.senders.set(if on { n + 1 } else { n.saturating_sub(1) });
        }
    }

    fn wake_read(&self) {
        if let Some(w) = self.read_waker.borrow_mut().take() {
            w.wake();
        }
    }

    fn wake_write(&self) {
        if let Some(w) = self.write_waker.borrow_mut().take() {
            w.wake();
        }
    }

    /// 通知事件循环把 lwIP 产生的输出写回隧道。
    fn flush(&self) {
        if let Some(s) = self.stack.upgrade() {
            s.wake();
        }
    }
}

pub struct LwipTcpStream {
    state: Rc<ConnState>,
    /// 应用原本要连接的地址（即 Flow 的目的地址）。
    local: SocketAddr,
    /// 应用的源地址。
    remote: SocketAddr,
}

impl LwipTcpStream {
    /// 在 accept 回调中接管新连接。
    pub(crate) unsafe fn attach(pcb: *mut tcp_pcb, stack: Weak<StackShared>) -> Self {
        let (local, remote) = endpoints(pcb);
        let state = Rc::new(ConnState {
            pcb: Cell::new(pcb),
            recv: RefCell::new(RecvBuffer::new()),
            eof: Cell::new(false),
            error: Cell::new(None),
            read_waker: RefCell::new(None),
            write_waker: RefCell::new(None),
            tx_shutdown: Cell::new(false),
            sending: Cell::new(false),
            rcv_window: Cell::new(INITIAL_RCV_WND),
            stack,
        });
        let arg = Rc::into_raw(state.clone()) as *mut c_void;
        lwip::tcp_arg(pcb, arg);
        lwip::tcp_recv(pcb, Some(on_recv));
        lwip::tcp_sent(pcb, Some(on_sent));
        lwip::tcp_err(pcb, Some(on_err));
        lwip::tcp_poll(pcb, Some(on_poll), lwip::TCP_POLL_INTERVAL);
        lwip::oryn_tcp_nagle_disable(pcb);
        lwip::oryn_tcp_init_rcv_wnd(pcb, INITIAL_RCV_WND);
        LwipTcpStream {
            state,
            local,
            remote,
        }
    }

    /// Flow 的目的地址。
    pub fn destination(&self) -> SocketAddr {
        self.local
    }

    /// Flow 的源地址。
    pub fn source(&self) -> SocketAddr {
        self.remote
    }

    /// 发送 RST 立即终止连接（用于 REJECT）。
    pub fn abort(self) {
        let pcb = self.detach();
        if !pcb.is_null() {
            unsafe { lwip::tcp_abort(pcb) };
            self.state.flush();
        }
    }

    /// 解除 lwIP 回调并释放 lwIP 持有的引用，返回 pcb（可能为空）。
    fn detach(&self) -> *mut tcp_pcb {
        self.state.set_sending(false);
        let pcb = self.state.pcb.replace(std::ptr::null_mut());
        if !pcb.is_null() {
            unsafe {
                lwip::tcp_arg(pcb, std::ptr::null_mut());
                lwip::tcp_recv(pcb, None);
                lwip::tcp_sent(pcb, None);
                lwip::tcp_err(pcb, None);
                lwip::tcp_poll(pcb, None, 0);
                drop(Rc::from_raw(Rc::as_ptr(&self.state)));
            }
        }
        pcb
    }

    fn io_error(&self) -> io::Error {
        match self.state.error.get() {
            Some(lwip::ERR_RST) => io::ErrorKind::ConnectionReset.into(),
            Some(lwip::ERR_ABRT) => io::ErrorKind::ConnectionAborted.into(),
            Some(e) => io::Error::other(format!("lwIP error {e}")),
            None => io::ErrorKind::NotConnected.into(),
        }
    }

    fn ack_received(&self, mut n: usize) {
        let pcb = self.state.pcb.get();
        if pcb.is_null() {
            return;
        }
        while n > 0 {
            let chunk = n.min(u16::MAX as usize);
            unsafe { lwip::tcp_recved(pcb, chunk as u16) };
            n -= chunk;
        }
        self.state.flush();
    }
}

impl Drop for LwipTcpStream {
    fn drop(&mut self) {
        let pcb = self.detach();
        if !pcb.is_null() {
            unsafe {
                if lwip::tcp_close(pcb) != ERR_OK {
                    lwip::tcp_abort(pcb);
                }
            }
            self.state.flush();
        }
    }
}

impl AsyncRead for LwipTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = {
            let n = self.state.recv.borrow_mut().read_into(buf);
            n
        };
        if n > 0 {
            let window = self.state.rcv_window.get();
            // 消费者跟得上（读完后缓冲不超过窗口一半）才增长；稳定传输时新数据一直在来，缓冲很难读空
            let keeping_up = self.state.recv.borrow().available() <= window as usize / 2;
            let extra = if keeping_up { (RCV_WND_MAX - window).min(n as u32) } else { 0 };
            self.state.rcv_window.set(window + extra);
            self.ack_received(n + extra as usize);
            return Poll::Ready(Ok(()));
        }
        if self.state.eof.get() {
            return Poll::Ready(Ok(()));
        }
        if self.state.error.get().is_some() || self.state.pcb.get().is_null() {
            return Poll::Ready(Err(self.io_error()));
        }
        *self.state.read_waker.borrow_mut() = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for LwipTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pcb = self.state.pcb.get();
        if pcb.is_null() || self.state.error.get().is_some() {
            return Poll::Ready(Err(self.io_error()));
        }
        if self.state.tx_shutdown.get() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let space = unsafe { lwip::oryn_tcp_sndbuf(pcb) } as usize;
        let inflight = SND_BUF.saturating_sub(space);
        let senders = self.state.stack.upgrade().map_or(1, |s| s.senders.get());
        let allowed = send_cap(senders).saturating_sub(inflight).min(space);
        if allowed == 0 {
            *self.state.write_waker.borrow_mut() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.len().min(allowed).min(u16::MAX as usize);
        let err = unsafe {
            lwip::tcp_write(
                pcb,
                buf.as_ptr() as *const c_void,
                n as u16,
                lwip::TCP_WRITE_FLAG_COPY,
            )
        };
        if err == ERR_MEM {
            // 内存或队列已满：等 sent / poll 回调唤醒
            *self.state.write_waker.borrow_mut() = Some(cx.waker().clone());
            unsafe { lwip::tcp_output(pcb) };
            self.state.flush();
            return Poll::Pending;
        }
        if err != ERR_OK {
            return Poll::Ready(Err(io::Error::other(format!("tcp_write failed: {err}"))));
        }
        self.state.set_sending(true);
        unsafe { lwip::tcp_output(pcb) };
        self.state.flush();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let pcb = self.state.pcb.get();
        if !pcb.is_null() && !self.state.tx_shutdown.replace(true) {
            unsafe { lwip::tcp_shutdown(pcb, 0, 1) };
            self.state.flush();
        }
        Poll::Ready(Ok(()))
    }
}

unsafe fn endpoints(pcb: *mut tcp_pcb) -> (SocketAddr, SocketAddr) {
    let mut la = [0u8; 16];
    let mut ra = [0u8; 16];
    let (mut lp, mut rp) = (0u16, 0u16);
    let family = lwip::oryn_tcp_endpoints(pcb, la.as_mut_ptr(), &mut lp, ra.as_mut_ptr(), &mut rp);
    let ip = |a: [u8; 16]| -> IpAddr {
        if family == 6 {
            IpAddr::V6(Ipv6Addr::from(a))
        } else {
            IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))
        }
    };
    (SocketAddr::new(ip(la), lp), SocketAddr::new(ip(ra), rp))
}

unsafe fn state<'a>(arg: *mut c_void) -> Option<&'a ConnState> {
    (arg as *const ConnState).as_ref()
}

unsafe extern "C" fn on_recv(
    arg: *mut c_void,
    pcb: *mut tcp_pcb,
    p: *mut pbuf,
    _err: err_t,
) -> err_t {
    let Some(st) = state(arg) else {
        // 已解除绑定：丢弃数据
        if !p.is_null() {
            lwip::tcp_recved(pcb, lwip::oryn_pbuf_tot_len(p));
            lwip::pbuf_free(p);
        }
        return ERR_OK;
    };
    if p.is_null() {
        st.eof.set(true);
        st.wake_read();
        return ERR_OK;
    }
    let len = lwip::oryn_pbuf_tot_len(p) as usize;
    let copied = st.recv.borrow_mut().append_pbuf(p, len);
    lwip::pbuf_free(p);
    if copied != len {
        st.error.set(Some(ERR_MEM));
    }
    st.wake_read();
    ERR_OK
}

unsafe extern "C" fn on_sent(arg: *mut c_void, pcb: *mut tcp_pcb, _len: u16) -> err_t {
    if let Some(st) = state(arg) {
        if lwip::oryn_tcp_sndbuf(pcb) as usize >= SND_BUF {
            st.set_sending(false); // 全部确认
        }
        st.wake_write();
    }
    ERR_OK
}

unsafe extern "C" fn on_poll(arg: *mut c_void, _pcb: *mut tcp_pcb) -> err_t {
    if let Some(st) = state(arg) {
        st.wake_write();
    }
    ERR_OK
}

/// lwIP 已释放 pcb（RST、超时、正常关闭等）。
unsafe extern "C" fn on_err(arg: *mut c_void, err: err_t) {
    if arg.is_null() {
        return;
    }
    let st = Rc::from_raw(arg as *const ConnState);
    st.set_sending(false);
    st.pcb.set(std::ptr::null_mut());
    if err == ERR_CLSD {
        st.eof.set(true);
    } else {
        st.error.set(Some(err));
    }
    st.wake_read();
    st.wake_write();
    // st 在这里被 drop，释放 lwIP 持有的引用
}
