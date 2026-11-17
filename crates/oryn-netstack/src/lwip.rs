//! lwIP 与胶水层的 FFI 声明。所有函数只能在 Core 事件循环线程调用。
#![allow(non_camel_case_types, dead_code)]

use std::ffi::{c_char, c_int, c_void};

#[repr(C)]
pub struct tcp_pcb {
    _private: [u8; 0],
}

#[repr(C)]
pub struct pbuf {
    _private: [u8; 0],
}

pub type err_t = i8;
pub const ERR_OK: err_t = 0;
pub const ERR_MEM: err_t = -1;
pub const ERR_VAL: err_t = -6;
pub const ERR_ABRT: err_t = -13;
pub const ERR_RST: err_t = -14;
pub const ERR_CLSD: err_t = -15;

pub const TCP_WRITE_FLAG_COPY: u8 = 0x01;
/// tcp_poll 间隔，单位为粗粒度定时器周期（500ms）。
pub const TCP_POLL_INTERVAL: u8 = 2;

pub type OutputFn = Option<unsafe extern "C" fn(ctx: *mut c_void, p: *const pbuf)>;
pub type TcpAcceptFn = Option<unsafe extern "C" fn(*mut c_void, *mut tcp_pcb, err_t) -> err_t>;
pub type TcpRecvFn =
    Option<unsafe extern "C" fn(*mut c_void, *mut tcp_pcb, *mut pbuf, err_t) -> err_t>;
pub type TcpSentFn = Option<unsafe extern "C" fn(*mut c_void, *mut tcp_pcb, u16) -> err_t>;
pub type TcpErrFn = Option<unsafe extern "C" fn(*mut c_void, err_t)>;
pub type TcpPollFn = Option<unsafe extern "C" fn(*mut c_void, *mut tcp_pcb) -> err_t>;

extern "C" {
    // 胶水层（csrc/oryn_lwip_shim.c）
    pub fn oryn_lwip_setup(mtu: u16, output: OutputFn, ctx: *mut c_void);
    pub fn oryn_lwip_input(data: *const u8, len: usize) -> err_t;
    pub fn oryn_lwip_check_timeouts();
    pub fn oryn_lwip_flush_acks();
    pub fn oryn_lwip_sleeptime() -> u32;
    pub fn oryn_lwip_reset();
    pub fn oryn_lwip_pcb_counts(out: *mut u32);
    pub fn oryn_tcp_listen(port: u16, arg: *mut c_void, accept: TcpAcceptFn) -> *mut tcp_pcb;
    pub fn oryn_tcp_sndbuf(pcb: *const tcp_pcb) -> u32;
    pub fn oryn_tcp_init_rcv_wnd(pcb: *mut tcp_pcb, wnd: u32);
    pub fn oryn_tcp_nagle_disable(pcb: *mut tcp_pcb);
    pub fn oryn_tcp_endpoints(
        pcb: *const tcp_pcb,
        local_addr: *mut u8,
        local_port: *mut u16,
        remote_addr: *mut u8,
        remote_port: *mut u16,
    ) -> c_int;
    pub fn oryn_pbuf_tot_len(p: *const pbuf) -> u16;

    // lwIP raw API
    pub fn tcp_arg(pcb: *mut tcp_pcb, arg: *mut c_void);
    pub fn tcp_recv(pcb: *mut tcp_pcb, recv: TcpRecvFn);
    pub fn tcp_sent(pcb: *mut tcp_pcb, sent: TcpSentFn);
    pub fn tcp_err(pcb: *mut tcp_pcb, err: TcpErrFn);
    pub fn tcp_poll(pcb: *mut tcp_pcb, poll: TcpPollFn, interval: u8);
    pub fn tcp_write(pcb: *mut tcp_pcb, data: *const c_void, len: u16, flags: u8) -> err_t;
    pub fn tcp_output(pcb: *mut tcp_pcb) -> err_t;
    pub fn tcp_recved(pcb: *mut tcp_pcb, len: u16);
    pub fn tcp_close(pcb: *mut tcp_pcb) -> err_t;
    pub fn tcp_abort(pcb: *mut tcp_pcb);
    pub fn tcp_shutdown(pcb: *mut tcp_pcb, shut_rx: c_int, shut_tx: c_int) -> err_t;
    pub fn pbuf_free(p: *mut pbuf) -> u8;
    pub fn pbuf_copy_partial(p: *const pbuf, data: *mut c_void, len: u16, offset: u16) -> u16;
}

/// lwIP（NO_SYS）需要的毫秒时钟。
#[no_mangle]
pub extern "C" fn sys_now() -> u32 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u32
}

/// lwIP 断言失败：记录后终止。断言失败意味着内部状态已损坏，继续运行更危险。
#[no_mangle]
pub unsafe extern "C" fn oryn_lwip_assert(msg: *const c_char, file: *const c_char, line: c_int) {
    let s = |p: *const c_char| {
        if p.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    };
    log::error!("lwIP assertion failed: {} ({}:{})", s(msg), s(file), line);
    std::process::abort();
}
