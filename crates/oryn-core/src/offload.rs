//! 大流量连接的出站 I/O 卸载。
//!
//! lwIP、Router 与全部连接任务都在一个事件循环线程上。真机采样：自回环下行时该线程 25–45% 的 CPU 花在出站 socket 的
//! `read` / `write` 里（回环一跳里内核还会替对端做 TCP 处理）；换成加密的代理协议，加解密也在同一个线程上。
//!
//! `Offload` 包住出站流。连接前期原样在事件循环线程上读写（小请求没有额外的线程切换延迟）；**从出站流读出**
//! （下行）的字节数超过 [`PROMOTE_BYTES`] 后把出站流整体交给两个工作线程：工作线程负责 socket 读写与协议加解密，事件循环线程只在
//! 有界的字节队列和 lwIP 之间搬运数据。出站流是 `Send` 的（`BoxStream`），其 I/O 注册仍属于创建它的运行时，
//! 工作线程轮询它时就绪事件仍由事件循环线程的 reactor 派发、再唤醒工作线程。
//!
//! 只按下行字节数触发：真机自回环上行（本机→出站）本来受 App 发送端往 utun 灌包的内核路径限制（1–8 流都在
//! 8–10 Gbps），卸载多出的一次拷贝与线程切换反而让上行降到 4.7–8.8 Gbps；上行为主的连接保持在事件循环线程。
//! 以后若上行出站协议的加密成为瓶颈，可以再加一个按上行字节数的阈值。
//!
//! 队列有界（每方向 [`QUEUE_CAP`]），满了对端自然被反压；块缓冲取自有上限的全局池。

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};

use oryn_outbound::BoxStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;

/// 从出站流读出的累计字节超过这么多后卸载。
pub const PROMOTE_BYTES: u64 = 512 * 1024;
/// 单块大小。
const CHUNK: usize = 64 * 1024;
/// 每方向最多排队的字节数。
const QUEUE_CAP: usize = 128 * 1024;
/// 全局块缓冲池最多保留的块数（≈ 2 MiB）。
const POOL_MAX: usize = 32;
const WORKER_THREADS: usize = 2;

fn workers() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKER_THREADS)
            .thread_name("oryn-offload")
            .thread_stack_size(512 * 1024)
            .enable_all()
            .build()
            .expect("failed to create the offload runtime")
    })
}

fn pool() -> &'static Mutex<Vec<Vec<u8>>> {
    static POOL: OnceLock<Mutex<Vec<Vec<u8>>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(Vec::new()))
}

fn take_chunk() -> Vec<u8> {
    let mut chunk = pool().lock().unwrap().pop().unwrap_or_default();
    chunk.clear();
    chunk.reserve(CHUNK);
    chunk
}

fn give_chunk(mut chunk: Vec<u8>) {
    if chunk.capacity() < CHUNK || chunk.capacity() > 2 * CHUNK {
        return;
    }
    chunk.clear();
    let mut pool = pool().lock().unwrap();
    if pool.len() < POOL_MAX {
        pool.push(chunk);
    }
}

#[derive(Default)]
struct State {
    /// 事件循环 → 出站。
    to_remote: VecDeque<Vec<u8>>,
    to_remote_bytes: usize,
    /// 出站 → 事件循环；第二项是队首块已读走的偏移。
    from_remote: VecDeque<(Vec<u8>, usize)>,
    from_remote_bytes: usize,
    /// 事件循环侧关闭了写方向（`poll_shutdown`）。
    local_shutdown: bool,
    /// 事件循环侧整个丢弃了。
    local_dropped: bool,
    remote_eof: bool,
    error: Option<(io::ErrorKind, String)>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

struct Shared {
    state: Mutex<State>,
    /// 唤醒写任务：有新数据或关闭。
    writer: Notify,
    /// 唤醒读任务：队列腾出了空间或关闭。
    reader: Notify,
}

impl Shared {
    fn fail(&self, error: &io::Error) {
        let mut state = self.state.lock().unwrap();
        if state.error.is_none() {
            state.error = Some((error.kind(), error.to_string()));
        }
        let wakers = (state.read_waker.take(), state.write_waker.take());
        drop(state);
        wake_all(wakers);
    }
}

fn wake_all(wakers: (Option<Waker>, Option<Waker>)) {
    if let Some(w) = wakers.0 {
        w.wake();
    }
    if let Some(w) = wakers.1 {
        w.wake();
    }
}

/// 事件循环线程一侧的管道端，实现 `AsyncRead + AsyncWrite`。
pub struct PipeEnd {
    shared: Arc<Shared>,
}

impl PipeEnd {
    fn poll_read_inner(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.state.lock().unwrap();
        if let Some((chunk, offset)) = state.from_remote.front_mut() {
            let n = (chunk.len() - *offset).min(buf.remaining());
            buf.put_slice(&chunk[*offset..*offset + n]);
            *offset += n;
            let finished = *offset == chunk.len();
            if finished {
                if let Some((chunk, _)) = state.from_remote.pop_front() {
                    give_chunk(chunk);
                }
            }
            state.from_remote_bytes -= n;
            drop(state);
            self.shared.reader.notify_one();
            return Poll::Ready(Ok(()));
        }
        if let Some((kind, message)) = state.error.take() {
            return Poll::Ready(Err(io::Error::new(kind, message)));
        }
        if state.remote_eof {
            return Poll::Ready(Ok(()));
        }
        state.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_write_inner(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        {
            let mut state = self.shared.state.lock().unwrap();
            if let Some((kind, message)) = state.error.take() {
                return Poll::Ready(Err(io::Error::new(kind, message)));
            }
            if state.local_shutdown {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if state.to_remote_bytes >= QUEUE_CAP {
                state.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        let n = data.len().min(CHUNK);
        let mut chunk = take_chunk();
        chunk.extend_from_slice(&data[..n]);
        {
            let mut state = self.shared.state.lock().unwrap();
            state.to_remote_bytes += n;
            state.to_remote.push_back(chunk);
        }
        self.shared.writer.notify_one();
        Poll::Ready(Ok(n))
    }

    fn shutdown_inner(&mut self) {
        let mut state = self.shared.state.lock().unwrap();
        if !state.local_shutdown {
            state.local_shutdown = true;
            drop(state);
            self.shared.writer.notify_one();
        }
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock().unwrap();
        state.local_dropped = true;
        // 丢弃没读走的数据，块还给池
        for (chunk, _) in state.from_remote.drain(..) {
            give_chunk(chunk);
        }
        state.from_remote_bytes = 0;
        drop(state);
        self.shared.writer.notify_one();
        self.shared.reader.notify_one();
    }
}

/// 工作线程：把写队列里的块依次写到出站流（队列空时 flush）。
async fn writer_task<W: AsyncWrite + Unpin>(shared: Arc<Shared>, mut remote: W) {
    // 卸载前事件循环线程可能已经写进出站流内部缓冲但没 flush，先刷出去
    if let Err(e) = remote.flush().await {
        shared.fail(&e);
        return;
    }
    loop {
        let (chunk, closing) = {
            let mut state = shared.state.lock().unwrap();
            if state.local_dropped || state.error.is_some() {
                return;
            }
            match state.to_remote.pop_front() {
                Some(chunk) => {
                    state.to_remote_bytes -= chunk.len();
                    let wake = state.write_waker.take();
                    drop(state);
                    if let Some(w) = wake {
                        w.wake();
                    }
                    (Some(chunk), false)
                }
                None => (None, state.local_shutdown),
            }
        };
        match chunk {
            Some(chunk) => {
                if let Err(e) = remote.write_all(&chunk).await {
                    shared.fail(&e);
                    return;
                }
                give_chunk(chunk);
                // 队列空了就 flush，保证请求不被出站流的缓冲拖住
                let empty = shared.state.lock().unwrap().to_remote.is_empty();
                if empty {
                    if let Err(e) = remote.flush().await {
                        shared.fail(&e);
                        return;
                    }
                }
            }
            None if closing => {
                let _ = remote.shutdown().await;
                return;
            }
            None => shared.writer.notified().await,
        }
    }
}

/// 工作线程：从出站流读块放进读队列。
async fn reader_task<R: AsyncRead + Unpin>(shared: Arc<Shared>, mut remote: R) {
    loop {
        // 等队列有空位
        loop {
            let (stop, has_room) = {
                let state = shared.state.lock().unwrap();
                (state.local_dropped || state.error.is_some(), state.from_remote_bytes < QUEUE_CAP)
            };
            if stop {
                return;
            }
            if has_room {
                break;
            }
            shared.reader.notified().await;
        }
        let mut chunk = take_chunk();
        let result = remote.read_buf(&mut chunk).await;
        match result {
            Ok(0) => {
                let mut state = shared.state.lock().unwrap();
                state.remote_eof = true;
                let wake = state.read_waker.take();
                drop(state);
                give_chunk(chunk);
                if let Some(w) = wake {
                    w.wake();
                }
                return;
            }
            Ok(n) => {
                let mut state = shared.state.lock().unwrap();
                if state.local_dropped {
                    return;
                }
                state.from_remote_bytes += n;
                state.from_remote.push_back((chunk, 0));
                let wake = state.read_waker.take();
                drop(state);
                if let Some(w) = wake {
                    w.wake();
                }
            }
            Err(e) => {
                shared.fail(&e);
                return;
            }
        }
    }
}

fn spawn_pipe(remote: BoxStream) -> PipeEnd {
    let shared = Arc::new(Shared {
        state: Mutex::new(State::default()),
        writer: Notify::new(),
        reader: Notify::new(),
    });
    let (read_half, write_half) = tokio::io::split(remote);
    let rt = workers();
    rt.spawn(reader_task(shared.clone(), read_half));
    rt.spawn(writer_task(shared.clone(), write_half));
    PipeEnd { shared }
}

enum Mode {
    /// 仍在事件循环线程上直接读写。
    Direct(Option<BoxStream>),
    Pipe(PipeEnd),
}

/// 出站流包装：前期直连，超过阈值后卸载到工作线程。
pub struct Offload {
    mode: Mode,
    /// 从出站流读出的累计字节（下行）。
    moved: u64,
    /// 写进出站流的累计字节（上行）；只在 `oryn-offload-up` 实验标记存在时参与触发。
    moved_up: u64,
    threshold: u64,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl Offload {
    pub fn new(remote: BoxStream) -> Self {
        Self::with_threshold(remote, PROMOTE_BYTES)
    }

    pub fn with_threshold(remote: BoxStream, threshold: u64) -> Self {
        Self { mode: Mode::Direct(Some(remote)), moved: 0, moved_up: 0, threshold, read_waker: None, write_waker: None }
    }

    /// 刚完成一次读（处在干净的边界上）时检查是否该卸载。
    fn maybe_promote(&mut self) {
        let up = crate::perf::offload_up_enabled() && self.moved_up >= self.threshold;
        if (self.moved < self.threshold && !up) || !crate::perf::offload_enabled() {
            return;
        }
        let Mode::Direct(stream) = &mut self.mode else { return };
        let Some(stream) = stream.take() else { return };
        self.mode = Mode::Pipe(spawn_pipe(stream));
        crate::perf::add(&crate::perf::OFFLOADED, 1);
        // 另一个方向可能正挂在原来的流上等就绪；以后它们的事件不再唤醒事件循环线程的任务，这里主动唤醒让它们改为轮询管道。
        wake_all((self.read_waker.take(), self.write_waker.take()));
    }
}

impl AsyncRead for Offload {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match &mut this.mode {
            Mode::Direct(Some(stream)) => {
                let before = buf.filled().len();
                let result = Pin::new(stream.as_mut()).poll_read(cx, buf);
                match &result {
                    Poll::Pending => this.read_waker = Some(cx.waker().clone()),
                    Poll::Ready(Ok(())) => {
                        this.moved += (buf.filled().len() - before) as u64;
                        this.read_waker = None;
                        this.maybe_promote();
                    }
                    Poll::Ready(Err(_)) => this.read_waker = None,
                }
                result
            }
            Mode::Direct(None) => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
            Mode::Pipe(pipe) => pipe.poll_read_inner(cx, buf),
        }
    }
}

impl AsyncWrite for Offload {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match &mut this.mode {
            Mode::Direct(Some(stream)) => {
                let result = Pin::new(stream.as_mut()).poll_write(cx, data);
                match &result {
                    Poll::Pending => this.write_waker = Some(cx.waker().clone()),
                    Poll::Ready(Ok(n)) => {
                        this.moved_up += *n as u64;
                        this.write_waker = None;
                        this.maybe_promote();
                    }
                    Poll::Ready(Err(_)) => this.write_waker = None,
                }
                result
            }
            Mode::Direct(None) => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
            Mode::Pipe(pipe) => pipe.poll_write_inner(cx, data),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.mode {
            Mode::Direct(Some(stream)) => Pin::new(stream.as_mut()).poll_flush(cx),
            Mode::Direct(None) => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
            // 工作线程在队列排空时自己 flush
            Mode::Pipe(_) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.mode {
            Mode::Direct(Some(stream)) => Pin::new(stream.as_mut()).poll_shutdown(cx),
            Mode::Direct(None) => Poll::Ready(Ok(())),
            Mode::Pipe(pipe) => {
                pipe.shutdown_inner();
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    /// 两个方向同时传大量数据，卸载发生在传输中途；校验内容与顺序，并检查半关闭。
    #[tokio::test(flavor = "current_thread")]
    async fn promotes_midstream_and_preserves_data_both_ways() {
        let (near, mut far) = tokio::io::duplex(32 * 1024);
        let mut offload = Offload::with_threshold(Box::new(near), 256 * 1024);
        let up = pattern(4 * 1024 * 1024 + 123, 7);
        let down = pattern(3 * 1024 * 1024 + 77, 9);
        let (up_len, down_len) = (up.len(), down.len());

        let peer = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut far);
            let write_down = async {
                w.write_all(&down).await.unwrap();
                w.shutdown().await.unwrap();
            };
            let read_up = async {
                let mut got = Vec::new();
                r.read_to_end(&mut got).await.unwrap();
                got
            };
            let ((), got) = tokio::join!(write_down, read_up);
            got
        });

        let (mut r, mut w) = tokio::io::split(&mut offload);
        let send = async {
            w.write_all(&up).await.unwrap();
            w.shutdown().await.unwrap();
        };
        let recv = async {
            let mut got = Vec::new();
            r.read_to_end(&mut got).await.unwrap();
            got
        };
        let ((), received) = tokio::join!(send, recv);
        let peer_got = peer.await.unwrap();

        assert_eq!(received.len(), down_len);
        assert!(received == pattern(down_len, 9), "download corrupted");
        assert_eq!(peer_got.len(), up_len);
        assert!(peer_got == pattern(up_len, 7), "upload corrupted");
        assert!(matches!(offload.mode, Mode::Pipe(_)), "should have been promoted");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn below_threshold_stays_direct() {
        let (near, mut far) = tokio::io::duplex(4096);
        let mut offload = Offload::new(Box::new(near));
        offload.write_all(b"ping").await.unwrap();
        offload.flush().await.unwrap();
        let mut buf = [0u8; 4];
        far.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert!(matches!(offload.mode, Mode::Direct(_)));
    }

    /// 出站流出错要传到事件循环线程一侧，丢弃管道要关闭出站流。
    #[tokio::test(flavor = "current_thread")]
    async fn errors_propagate_and_drop_closes_remote() {
        let (near, mut far) = tokio::io::duplex(1024);
        let mut offload = Offload::with_threshold(Box::new(near), 1);
        // 下行读到数据即卸载；之后对端关闭 → 事件循环侧读到 EOF
        far.write_all(&[2u8; 16]).await.unwrap();
        let mut got = [0u8; 16];
        offload.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [2u8; 16]);
        assert!(matches!(offload.mode, Mode::Pipe(_)));
        offload.write_all(&[1u8; 16]).await.unwrap();
        let mut buf = [0u8; 16];
        far.read_exact(&mut buf).await.unwrap();
        far.shutdown().await.unwrap();
        let mut tail = Vec::new();
        offload.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty());
        drop(offload);
        // 事件循环侧丢弃后工作线程释放出站流，对端写会失败
        let mut closed = false;
        for _ in 0..200 {
            if far.write_all(&[0u8; 64]).await.is_err() {
                closed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(closed, "remote should be closed after the pipe is dropped");
    }
}
