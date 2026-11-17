//! Engine 事件循环中的可选 utun I/O 驱动。

#[cfg(test)]
#[path = "utun_runtime_tests.rs"]
mod tests;

use std::collections::VecDeque;
use std::io;
use std::os::fd::RawFd;

use oryn_netstack::{IpVersion, LwipStack, PacketIo};
use tokio::io::unix::AsyncFd;

#[cfg(target_os = "android")]
type PlatformPacketIo = oryn_netstack::AndroidTunPacketIo;
#[cfg(not(target_os = "android"))]
type PlatformPacketIo = oryn_netstack::UtunPacketIo;

const MAX_PENDING_PACKETS: usize = 4096;
const MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;
/// 每次 poll 最多写尝试次数（成功、错误、WouldBlock 均计数）。
const WRITE_BURST: usize = 64;
/// 每次 poll 最多读尝试次数：一次唤醒读到读空（或到上限）再统一分发，
/// 不再每包跑一轮 select、dispatch 与 take_output。
const READ_BURST: usize = 32;
/// 复用的收包缓冲超过这个容量（偶发的大包）用完就释放，常驻内存只按普通 MTU 计。
const RX_KEEP_CAPACITY: usize = 16 * 1024;

pub struct UtunRuntime {
    fd: AsyncFd<PlatformPacketIo>,
    pending: VecDeque<(IpVersion, Vec<u8>)>,
    pending_bytes: usize,
    /// 收包缓冲，跨批次复用（`input_packet` 只借用包内容），前 `received` 个是本批读到的包。
    rx: Vec<Vec<u8>>,
    received: usize,
    // 仅测试进程启动前注入；测试内不修改环境，避免并发 set_var。
    #[cfg(test)]
    measurement_bursts: (usize, usize),
    #[cfg(test)]
    read_errors: VecDeque<i32>,
    #[cfg(test)]
    write_errors: VecDeque<i32>,
}

impl UtunRuntime {
    /// 从调用方 fd 创建一个独占副本；不会关闭或改变 provider 的原始 fd。
    pub fn from_fd(fd: RawFd) -> io::Result<Self> {
        // SAFETY: fd 的有效性和 provider 归属由平台层在启动前负责验证；这里不接管原 fd。
        let borrowed = <PlatformPacketIo as PacketIo>::from_borrowed_fd(fd)?;
        let owned = borrowed.try_clone()?;
        {
            use std::os::fd::AsRawFd;
            crate::perf::UTUN_FD.store(owned.as_raw_fd(), std::sync::atomic::Ordering::Relaxed);
        }
        Ok(Self {
            fd: AsyncFd::new(owned)?,
            pending: VecDeque::new(),
            pending_bytes: 0,
            rx: Vec::new(),
            received: 0,
            #[cfg(test)]
            measurement_bursts: match std::env::var("ORYN_TEST_UTUN_BURSTS").as_deref() {
                Ok("128/64") => (128, 64),
                Ok("64/32") | Err(_) => (WRITE_BURST, READ_BURST),
                Ok(_) => panic!("invalid ORYN_TEST_UTUN_BURSTS"),
            },
            #[cfg(test)]
            read_errors: VecDeque::new(),
            #[cfg(test)]
            write_errors: VecDeque::new(),
        })
    }

    /// 推进 utun 收发：先尽量写出待发包（每次最多 `WRITE_BURST` 个，保持与控制通道公平），
    /// 再连续读入站包直到读空或满 `READ_BURST` 个。返回本批读到的包数，包内容由 `received()` 借出；
    /// 0 表示只完成了写出或丢弃了坏帧。
    ///
    /// `try_io` 遇到 `WouldBlock` 时会清除就绪标记，这时必须重新轮询就绪状态，
    /// 才会登记唤醒；否则读空或写满之后，事件循环要等别的事件（lwIP 定时器最长约 1 秒）
    /// 才会再处理 utun，表现为每次往返随机多出几十到几百毫秒。
    pub async fn next(&mut self, stack: &LwipStack) -> io::Result<usize> {
        for buf in &mut self.rx[..self.received] {
            if buf.capacity() > RX_KEEP_CAPACITY {
                *buf = Vec::new();
            }
        }
        self.received = 0;
        #[cfg(not(test))]
        let (write_burst, read_burst) = (WRITE_BURST, READ_BURST);
        #[cfg(test)]
        let (write_burst, read_burst) = self.measurement_bursts;
        std::future::poll_fn(|cx| {
            use std::task::Poll;
            crate::perf::add(&crate::perf::UTUN_POLLS, 1);
            let mut wrote = 0usize;
            let mut write_attempts = 0usize;
            while write_attempts < write_burst {
                let Some((version, packet)) = self.pending.front() else {
                    break;
                };
                let mut guard = match self.fd.poll_write_ready(cx) {
                    Poll::Ready(Ok(guard)) => guard,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    // 已登记写就绪唤醒
                    Poll::Pending => break,
                };
                write_attempts += 1;
                let t = std::time::Instant::now();
                let io_result = guard.try_io(|fd| {
                    #[cfg(test)]
                    if let Some(errno) = self.write_errors.pop_front() {
                        return Err(io::Error::from_raw_os_error(errno));
                    }
                    fd.get_ref().send_packet(*version, packet)
                });
                crate::perf::add(&crate::perf::TX_NS, crate::perf::since(t));
                match io_result {
                    Ok(Ok(())) => {
                        crate::perf::add(&crate::perf::TX_PKTS, 1);
                        crate::perf::add(&crate::perf::TX_BYTES, packet.len() as u64);
                        let packet = self.pending.pop_front().unwrap().1;
                        self.pending_bytes -= packet.len();
                        stack.recycle_output_packet(packet);
                        wrote += 1;
                    }
                    Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                    // 内核发送缓冲满：丢弃这个包（TCP 会重传），不让一次拥塞终止整个隧道
                    Ok(Err(e)) if oryn_netstack::utun::is_buffer_full(&e) => {
                        let packet = self.pending.pop_front().unwrap().1;
                        self.pending_bytes -= packet.len();
                        stack.recycle_output_packet(packet);
                    }
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    // WouldBlock：就绪已清除，回到循环顶部重新轮询以登记唤醒
                    Err(_) => crate::perf::add(&crate::perf::TX_WOULDBLOCK, 1),
                }
            }
            if write_attempts == write_burst {
                // 最后一次可能是 WouldBlock：即使就绪被清除，也保证下一 poll
                // 能重新登记唤醒。EINTR 不消费队列，但同样必须让出执行权。
                cx.waker().wake_by_ref();
            }
            let mut skipped = false;
            let Self {
                fd,
                rx,
                received,
                #[cfg(test)]
                read_errors,
                ..
            } = &mut *self;
            // 读满一批时就绪标记仍在，下次调用会立刻继续读
            let mut read_attempts = 0usize;
            while read_attempts < read_burst {
                let mut guard = match fd.poll_read_ready_mut(cx) {
                    Poll::Ready(Ok(guard)) => guard,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    // 已登记读就绪唤醒
                    Poll::Pending => break,
                };
                if rx.len() <= *received {
                    rx.push(Vec::new());
                }
                let packet = &mut rx[*received];
                read_attempts += 1;
                let t = std::time::Instant::now();
                let io_result = guard.try_io(|fd| {
                    #[cfg(test)]
                    if let Some(errno) = read_errors.pop_front() {
                        return Err(io::Error::from_raw_os_error(errno));
                    }
                    fd.get_mut().recv_packet(packet)
                });
                crate::perf::add(&crate::perf::RX_NS, crate::perf::since(t));
                match io_result {
                    Ok(Ok(_)) => {
                        crate::perf::add(&crate::perf::RX_PKTS, 1);
                        crate::perf::add(&crate::perf::RX_BYTES, rx[*received].len() as u64);
                        *received += 1
                    }
                    Ok(Err(e))
                        if matches!(
                            e.kind(),
                            io::ErrorKind::InvalidData | io::ErrorKind::Interrupted
                        ) =>
                    {
                        skipped = true;
                    }
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    // WouldBlock：重新轮询以登记唤醒
                    Err(_) => continue,
                }
            }
            if read_attempts == read_burst {
                // 不清除仍有效的 readiness；若末次 WouldBlock 已清除它，
                // 自唤醒保证不会在尚未重新 poll readiness 时永久 Pending。
                cx.waker().wake_by_ref();
            }
            if *received > 0 || wrote > 0 || skipped {
                Poll::Ready(Ok(*received))
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// 最近一次 `next` 读到的包。
    pub fn received(&self) -> &[Vec<u8>] {
        &self.rx[..self.received]
    }

    pub fn enqueue(&mut self, mut packets: Vec<Vec<u8>>, stack: &LwipStack) -> io::Result<()> {
        for packet in packets.drain(..) {
            let version = match packet.first().map(|byte| byte >> 4) {
                Some(4) => IpVersion::V4,
                Some(6) => IpVersion::V6,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Core produced an invalid IP packet",
                    ))
                }
            };
            if self.pending.len() >= MAX_PENDING_PACKETS
                || self.pending_bytes.saturating_add(packet.len()) > MAX_PENDING_BYTES
            {
                stack.recycle_output_packet(packet);
                continue; // 有界丢弃，不阻塞或终止事件循环。
            }
            self.pending_bytes += packet.len();
            self.pending.push_back((version, packet));
        }
        stack.recycle_output_batch(packets);
        Ok(())
    }
}
