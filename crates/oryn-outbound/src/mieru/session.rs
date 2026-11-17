// 线格式与 ACK 语义参考 enfein/mieru pkg/protocol/session.go
// @ a366b4a2d08a42178704f3126d71f82a27e014a5；Copyright (C) 2023–2026 mieru authors.
// Modified for Oryn: 独立的 Tokio 有界状态机，AIMD 窗口与指数退避。
// SPDX-License-Identifier: GPL-3.0-or-later
use super::{
    carrier::Carrier,
    wire::{
        bad, Frame, MAX_SESSIONS, MIN_RECV_WINDOW, MIN_WINDOW, RECV_BUDGET, RECV_WINDOW, WINDOW,
        WINDOW_BUDGET,
    },
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::{mpsc, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
#[path = "close_waiter_tests.rs"]
mod close_waiter_tests;

#[cfg(test)]
#[path = "receive_tests.rs"]
mod receive_tests;

type Failure = Arc<Mutex<Option<(io::ErrorKind, String)>>>;

/// UDP 会话的累计统计，只用于诊断（自测会取增量）：数据报数、窗口外丢弃、重复、重传、窗口更新。
pub(super) static COUNTERS: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
fn count(i: usize) {
    COUNTERS[i].fetch_add(1, Ordering::Relaxed);
}
pub struct Stream {
    inner: DuplexStream,
    stop: CancellationToken,
    failure: Failure,
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl Stream {
    fn error(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .unwrap()
            .as_ref()
            .map(|(k, s)| io::Error::new(*k, s.clone()))
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = b.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, b) {
            Poll::Ready(Ok(())) if b.filled().len() == before => {
                Poll::Ready(self.error().map_or(Ok(()), Err))
            }
            r => r,
        }
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(e) = self.error() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
struct Registration {
    carrier: Arc<Carrier>,
    id: u32,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.carrier.sessions.lock().unwrap().remove(&self.id);
        if !self.carrier.reusable {
            self.carrier.stop.cancel();
        }
        if self.carrier.stop.is_cancelled() {
            return;
        }
        // 关闭帧通知服务端释放这个会话。发送队列暂时满时不能直接丢掉（服务端会话会一直留到超时），
        // 放到后台等空位，等待时间和任务数量均有界。
        let frame = Frame::new(4, self.id, 0, vec![]);
        if let Err(tokio::sync::mpsc::error::TrySendError::Full(frame)) =
            self.carrier.send.try_send(frame)
        {
            // spawn 前收费：包括尚未首次 poll 的任务；活跃流退出不归还此名额。
            let Ok(permit) = self.carrier.close_waiters.clone().try_acquire_owned() else {
                // 真正耗尽关闭预算才降级关闭共享载体，避免对端积累孤儿会话。
                self.carrier.stop.cancel();
                return;
            };
            let send = self.carrier.send.clone();
            let stop = self.carrier.stop.clone();
            let waiter = async move {
                let _permit = permit;
                tokio::select! {
                    biased;
                    _ = stop.cancelled() => {},
                    result = tokio::time::timeout(Duration::from_secs(10), send.send(frame)) => {
                        // 无法交付关闭通知时明确关闭载体；不能静默丢失关闭。
                        if !matches!(result, Ok(Ok(()))) {
                            stop.cancel();
                        }
                    }
                }
            };
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(waiter);
            } else {
                self.carrier.stop.cancel();
            }
        }
    }
}

pub fn open(
    carrier: Arc<Carrier>,
    id: u32,
    request: Vec<u8>,
    permit: OwnedSemaphorePermit,
    slots: Arc<Semaphore>,
) -> Stream {
    let (app, bridge) = tokio::io::duplex(16 * 1024);
    let (tx, rx) = mpsc::channel(if carrier.packet { RECV_WINDOW } else { 2 });
    carrier.sessions.lock().unwrap().insert(id, tx);
    let registration = Registration {
        carrier: carrier.clone(),
        id,
    };
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let failure: Failure = Arc::new(Mutex::new(None));
    let errors = failure.clone();
    tokio::spawn(async move {
        let _registration = registration;
        let _permit = permit;
        let mut bridge = bridge;
        let work = run(&carrier, id, request, &mut bridge, rx, &slots);
        let result = tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            _ = carrier.stop.cancelled() => Err(io::Error::new(io::ErrorKind::ConnectionReset, "Mieru carrier closed")),
            result = work => result,
        };
        // 先记下错误再关桥接：否则读者可能先看到干净 EOF，读不到真实错误
        if let Err(e) = result {
            *errors.lock().unwrap() = Some((e.kind(), e.to_string()));
        }
        drop(bridge);
    });
    Stream {
        inner: app,
        stop,
        failure,
    }
}
struct Pending {
    frame: Frame,
    sent: Instant,
    tries: u8,
}
/// 确认最多延迟这么久合并（与官方实现的 packetAckDelay 相同）。
const ACK_DELAY: Duration = Duration::from_millis(1);
/// 按序数据攒到这么多段时不等延迟、立即确认，让高速下发送端的窗口及时前移（这时确认点名的序号每次都不同）。
const ACK_EVERY: u32 = 32;
/// UDP 会话发送端的拥塞与重传状态（Reno 式）：
/// 慢启动按被确认的段数增长，拥塞避免每个窗口加一段；一次丢包事件（一个恢复周期内）只减半一次；
/// 重复确认点名的缺口段若已发出超过约一个往返就立即重传（对端确认最多合并 1 ms，窗口小时等不到三次重复确认）；
/// 超时按往返时延估算，只重传最早未确认的那一段，不把整个在途窗口全部重发。
struct Sender {
    congestion: usize,
    threshold: usize,
    grown: usize,
    /// 丢包恢复点：发生丢包时已发出的最大序号之后；在它之前再发现的丢包属于同一事件，不再减半。
    recovery: u32,
    srtt: Option<Duration>,
    rttvar: Duration,
}
impl Sender {
    fn new() -> Self {
        Self {
            congestion: 4,
            threshold: WINDOW,
            grown: 0,
            recovery: 0,
            srtt: None,
            rttvar: Duration::ZERO,
        }
    }
    /// 新确认了 `acked` 段。
    fn on_acked(&mut self, acked: usize) {
        if self.congestion < self.threshold {
            self.congestion = (self.congestion + acked).min(WINDOW);
        } else {
            self.grown += acked;
            while self.grown >= self.congestion {
                self.grown -= self.congestion;
                self.congestion = (self.congestion + 1).min(WINDOW);
            }
        }
    }
    /// 发现序号 `seq` 的段丢了。`next_send` 是当前已发出的下一个序号。
    fn on_loss(&mut self, seq: u32, next_send: u32) {
        if seq < self.recovery {
            return;
        }
        self.recovery = next_send;
        self.threshold = (self.congestion / 2).max(2);
        self.congestion = self.threshold;
        self.grown = 0;
    }
    /// 重复确认判定丢包前，缺口段至少要已经发出这么久（一个往返加少量乱序余量）。
    fn loss_delay(&self) -> Duration {
        let srtt = self.srtt.unwrap_or(RTO_INITIAL);
        srtt + (srtt / 4).max(Duration::from_millis(2))
    }
    /// 只用没有重传过的段采样（Karn）。
    fn on_rtt(&mut self, sample: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(sample);
                self.rttvar = sample / 2;
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(sample);
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((srtt * 7 + sample) / 8);
            }
        }
    }
    fn rto(&self) -> Duration {
        match self.srtt {
            Some(srtt) => (srtt + self.rttvar * 4).clamp(RTO_MIN, RTO_MAX),
            None => RTO_INITIAL,
        }
    }
}
const RTO_INITIAL: Duration = Duration::from_millis(250);
const RTO_MIN: Duration = Duration::from_millis(40);
const RTO_MAX: Duration = Duration::from_secs(2);
async fn run(
    carrier: &Carrier,
    id: u32,
    request: Vec<u8>,
    bridge: &mut DuplexStream,
    mut input: mpsc::Receiver<Frame>,
    slots: &Semaphore,
) -> io::Result<()> {
    let mut pending = BTreeMap::<u32, Pending>::new();
    let mut reorder = BTreeMap::<u32, Frame>::new();
    let mut reorder_bytes = 0usize;
    let mut output = VecDeque::<u8>::new();
    let mut next_send = 1u32;
    let mut next_recv = 0u32;
    let mut remote_window = WINDOW;
    let mut sender = Sender::new();
    let mut established = false;
    let mut eof = false;
    let mut closed = false;
    // 已收到但还没确认的数据段数，以及最迟何时发出这次确认
    let mut unacked = 0u32;
    let mut ack_at = Instant::now();
    let open = Frame::new(2, id, 0, request);
    carrier.write(open.clone()).await?;
    if carrier.packet {
        pending.insert(
            0,
            Pending {
                frame: open,
                sent: Instant::now(),
                tries: 0,
            },
        );
    }
    let (mut app_read, mut app_write) = tokio::io::split(bridge);
    let mut buf = vec![0u8; carrier.chunk];
    let mut timer = tokio::time::interval(Duration::from_millis(20));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_recv = Instant::now();
    let mut last_ack = Instant::now();
    macro_rules! send_ack {
        () => {{
            let mut ack = Frame::new(8, id, next_send, vec![]);
            ack.ack = next_recv;
            ack.window = receive_window(&output, &reorder, recv_limit(slots));
            carrier.write(ack).await?;
            last_ack = Instant::now();
            unacked = 0;
        }};
    }
    loop {
        if closed && output.is_empty() {
            return Ok(());
        }
        // Mieru 会话没有半关闭：应用只关写端（shutdown，echo / SMTP 式「发完再等回复」）时不发关闭帧，
        // 继续接收直到服务端关闭；应用丢弃整条流时 `Stream::drop` 取消任务，`Registration` 发关闭帧。
        let can_read = !eof
            && (!carrier.packet
                || (established
                    && pending.len()
                        < sender
                            .congestion
                            .min(remote_window)
                            .min(window_limit(slots))));
        let can_receive = !closed && (carrier.packet || output.len() <= 32 * 1024);
        let contiguous = output.make_contiguous();
        tokio::select! {
            _ = tokio::time::sleep_until(ack_at), if carrier.packet && unacked > 0 => {
                send_ack!();
            }
            result = app_write.write(contiguous), if !contiguous.is_empty() => {
                let n = result?;
                if n == 0 {
                    return Ok(());
                }
                let high = receive_high(recv_limit(slots));
                let blocked = output.len() > high;
                output.drain(..n);
                // 缓冲超过上限时通告窗口为 0，对端会停发；读空到上限以下必须马上通告新窗口，
                // 否则对端要等空闲确认才继续，下载被卡成「一阵一停」。
                if carrier.packet && blocked && output.len() <= high {
                    count(4);
                    send_ack!();
                }
            }
            result = app_read.read(&mut buf[..carrier.chunk]), if can_read => {
                let n = result?;
                if n == 0 {
                    eof = true;
                    continue;
                }
                let mut frame = Frame::new(6, id, next_send, buf[..n].to_vec());
                next_send = next_send
                    .checked_add(1)
                    .ok_or_else(|| bad("Mieru sequence exhausted"))?;
                // 数据段顺带确认，攒着的确认随之清零
                frame.ack = next_recv;
                frame.window = receive_window(&output, &reorder, recv_limit(slots));
                carrier.write(frame.clone()).await?;
                unacked = 0;
                if carrier.packet {
                    pending.insert(frame.seq, Pending { frame, sent: Instant::now(), tries: 0 });
                }
            }
            frame = input.recv(), if can_receive => {
                let Some(frame) = frame else {
                    return Err(bad("Mieru session reader closed"));
                };
                last_recv = Instant::now();
                if frame.status != 0 {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Mieru session rejected"));
                }
                if matches!(frame.kind, 4 | 5) {
                    if frame.kind == 4 {
                        carrier.write(Frame::new(5, id, next_send, vec![])).await?;
                    }
                    closed = true;
                    continue;
                }
                if frame.kind >= 7 && carrier.packet {
                    if frame.ack > next_send {
                        return Err(bad("Mieru invalid acknowledgement"));
                    }
                    let lowest = pending.keys().next().copied();
                    let now = Instant::now();
                    let mut acked = 0;
                    while let Some(entry) = pending.first_entry() {
                        if *entry.key() >= frame.ack {
                            break;
                        }
                        let p = entry.remove();
                        if p.tries == 0 {
                            sender.on_rtt(now.duration_since(p.sent));
                        }
                        acked += 1;
                    }
                    if acked > 0 {
                        sender.on_acked(acked);
                    } else if lowest == Some(frame.ack) && frame.kind == 9 {
                        // 纯确认没有推进，点名的正是最早未确认段：对端已收到它后面的数据。
                        // 它若已发出超过约一个往返，就认定丢失并立即重传（不必等三次重复确认或超时）。
                        let loss_delay = sender.loss_delay();
                        if let Some(p) = pending.get_mut(&frame.ack) {
                            if now.duration_since(p.sent) >= loss_delay {
                                p.frame.ack = next_recv;
                                p.frame.window =
                                    receive_window(&output, &reorder, recv_limit(slots));
                                carrier.write(p.frame.clone()).await?;
                                count(3);
                                p.tries = p.tries.saturating_add(1);
                                p.sent = now;
                                sender.on_loss(frame.ack, next_send);
                            }
                        }
                    }
                    remote_window = usize::from(frame.window).min(WINDOW);
                }
                if frame.kind == 9 {
                    continue;
                }
                if frame.kind == 3 {
                    established = true;
                    pending.remove(&0);
                }
                if carrier.packet {
                    count(0);
                    let in_order = frame.seq == next_recv;
                    if frame.seq < next_recv {
                        count(2);
                    }
                    let limit = recv_limit(slots);
                    // 按序包也必须收费：已认证对端可能无视零窗口，不能让 output 持续增长。
                    // 乱序准入额外留出一段给 next_recv，避免重排缓存挤满后无法补缺口。
                    // 拒收不推进累计序号，应用排空恢复窗口后由对端重传。
                    let reserve = if in_order { 0 } else { MAX_SEGMENT };
                    if (in_order
                        || (frame.seq > next_recv
                            && frame.seq - next_recv < limit as u32))
                        && output.len() + reorder_bytes + frame.payload.len()
                            <= receive_bytes(limit).saturating_sub(reserve)
                    {
                        if let std::collections::btree_map::Entry::Vacant(slot) = reorder.entry(frame.seq) {
                            reorder_bytes += frame.payload.len();
                            slot.insert(frame);
                        }
                    } else if frame.seq >= next_recv {
                        count(1);
                    }
                    while let Some(frame) = reorder.remove(&next_recv) {
                        reorder_bytes -= frame.payload.len();
                        output.extend(frame.payload);
                        next_recv = next_recv
                            .checked_add(1)
                            .ok_or_else(|| bad("Mieru sequence exhausted"))?;
                    }
                    // 确认一律合并，不逐包回：官方发送端对「被确认报文点名为 unAckSeq」的在途段计数，
                    // 满 3 次就当丢包提前重传并收缩拥塞窗口（earlyRetransmission）。逐包确认、给重复段也立即确认，
                    // 会让还在路上的下一段被点名多次，触发伪重传，重传带来的重复段又引出更多确认，窗口始终很小。
                    // 与官方客户端一样把确认最多延迟 ACK_DELAY 合并；真有缺口时每个延迟窗口一个重复确认，
                    // 足以触发对端的快速重传。按序且积累较多时立即确认（序号每次都不同，不会被重复点名）。
                    if unacked == 0 {
                        ack_at = Instant::now() + ACK_DELAY;
                    }
                    unacked += 1;
                    if in_order && reorder.is_empty() && unacked >= ACK_EVERY {
                        send_ack!();
                    }
                } else {
                    if frame.seq != next_recv {
                        return Err(bad("Mieru unexpected TCP sequence"));
                    }
                    next_recv = next_recv
                        .checked_add(1)
                        .ok_or_else(|| bad("Mieru sequence exhausted"))?;
                    if output.len() + frame.payload.len() > 64 * 1024 {
                        return Err(bad("Mieru slow reader exceeded receive limit"));
                    }
                    output.extend(frame.payload);
                }
            }
            _ = timer.tick(), if carrier.packet => {
                if last_recv.elapsed() > Duration::from_secs(120) {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "Mieru peer timed out"));
                }
                let rto = sender.rto();
                // 超时只重传最早未确认的一段：没有选择确认，后面的段多半已经到了，
                // 缺口补上后累计确认会一下推进；整窗重发只会制造重复段并连续减半窗口。
                if let Some((&seq, p)) = pending.iter_mut().next() {
                    if p.sent.elapsed() >= rto * (1u32 << p.tries.min(4)) {
                        if p.tries >= 8 {
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "Mieru retransmission limit reached"));
                        }
                        p.frame.ack = next_recv;
                        p.frame.window = receive_window(&output, &reorder, recv_limit(slots));
                        carrier.write(p.frame.clone()).await?;
                        count(3);
                        p.tries += 1;
                        p.sent = Instant::now();
                        sender.on_loss(seq, next_send);
                    }
                }
                if unacked > 0 || (established && last_ack.elapsed() >= Duration::from_millis(500)) {
                    send_ack!();
                }
            }
        }
    }
}
/// 待交给应用的数据超过它就通告窗口 0；随接收窗口缩放，会话多时缓存也更小。
fn receive_high(limit: usize) -> usize {
    (limit * 128).max(32 * 1024)
}
/// 一个 UDP 会话缓存的乱序与待读数据上限：接收窗口 × 单个数据报的最大载荷再留余量。
/// 对端的分段不一定是我们发送用的 1 KiB（官方服务端约 1.3 KiB），按 1 KiB 算会在窗口没满时先撞上字节上限。
fn receive_bytes(limit: usize) -> usize {
    limit * MAX_SEGMENT + 64 * 1024
}
/// 单个 UDP 数据报能承载的最大载荷（线上数据报不超过 1500 字节）。
const MAX_SEGMENT: usize = 1500;
fn active_sessions(slots: &Semaphore) -> usize {
    MAX_SESSIONS
        .saturating_sub(slots.available_permits())
        .max(1)
}
/// 现在这个会话可以使用的发送窗口：节点预算按活跃会话数平分。
fn window_limit(slots: &Semaphore) -> usize {
    (WINDOW_BUDGET / active_sessions(slots)).clamp(MIN_WINDOW, WINDOW)
}
/// 现在这个会话可以使用的接收窗口：同样按活跃会话数平分节点预算。
fn recv_limit(slots: &Semaphore) -> usize {
    (RECV_BUDGET / active_sessions(slots)).clamp(MIN_RECV_WINDOW, RECV_WINDOW)
}
fn receive_window(output: &VecDeque<u8>, reorder: &BTreeMap<u32, Frame>, limit: usize) -> u16 {
    if output.len() > receive_high(limit) {
        0
    } else {
        limit.saturating_sub(reorder.len()).min(u16::MAX as usize) as u16
    }
}
