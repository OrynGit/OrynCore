//! smux v1 线格式独立实现：8 字节小端首部；单流接收缓冲 128 KiB。
//!
//! smux v1 与 AnyTLS 都没有逐流的流量控制。某条流的缓冲满时，读取任务等待它被消费
//! （与 xtaci/smux、sing-anytls 一样阻塞整个会话，对端靠承载 TCP 的窗口减速），
//! 会话里只有这条流时一直等待（与普通 TCP 零窗口一样）；同一会话还有其他流时，
//! 等待超过 `STALL_TIMEOUT` 才关闭这条流，避免一条不再读取的流永久卡住其他流。
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU32};
use tokio::sync::Semaphore;

/// 单流接收缓冲上限。
const STREAM_BUDGET: usize = 128 * 1024;
/// 写任务一次合并写出的字节上限（两条满帧）。
const BATCH: usize = 32 * 1024;
/// 单流缓冲满且同一会话还有其他流时，读取任务最多等待这么久；超时视为这条流已停止读取。
#[cfg(not(test))]
const STALL_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const STALL_TIMEOUT: Duration = Duration::from_millis(300);
#[derive(Debug)]
enum Command {
    Frame(u8, u32, Bytes),
    Flush(oneshot::Sender<io::Result<()>>),
}
/// 把数据交给流，缓冲满时等待。返回 true 表示这条流停滞并挡住了同一会话的其他流。
async fn deliver_or_stall(
    deliver: impl std::future::Future<Output = ()>,
    id: u32,
    streams: &StdMutex<HashMap<u32, Reader>>,
    failure: &tokio::sync::Notify,
) -> io::Result<bool> {
    tokio::pin!(deliver);
    loop {
        tokio::select! {
            _ = &mut deliver => return Ok(false),
            _ = tokio::time::sleep(STALL_TIMEOUT) => {
                if streams.lock().unwrap().keys().any(|other| *other != id) {
                    return Ok(true);
                }
            }
            _ = failure.notified() => return Err(err("session writer failed")),
        }
    }
}
struct Reader {
    tx: mpsc::Sender<Bytes>,
    failed: Arc<AtomicBool>,
    /// 剩余的接收缓冲字节数；读取时归还，流结束时关闭。
    budget: Arc<Semaphore>,
    peer_closed: Arc<PeerClosed>,
}
#[derive(Default)]
struct PeerClosed {
    closed: AtomicBool,
    writer: futures_util::task::AtomicWaker,
}
pub(super) struct Session {
    /// AnyTLS 会话：流的 FIN 是整条流的关闭，不是半关闭。
    any: bool,
    tx: mpsc::Sender<Command>,
    streams: Arc<StdMutex<HashMap<u32, Reader>>>,
    next: AtomicU32,
    fin_keepers: Arc<Semaphore>,
    read_abort: tokio::task::AbortHandle,
    write_abort: tokio::task::AbortHandle,
    read_driver: Driver,
    write_driver: Driver,
}
impl Session {
    pub(super) fn new(carrier: BoxStream) -> Self {
        Self::new_mode(carrier, false)
    }
    pub(super) fn new_any(carrier: BoxStream) -> Self {
        Self::new_mode(carrier, true)
    }
    fn new_mode(carrier: BoxStream, any: bool) -> Self {
        let (mut read, mut write) = tokio::io::split(carrier);
        let (tx, mut rx) = mpsc::channel::<Command>(8);
        let streams = Arc::new(StdMutex::new(HashMap::<u32, Reader>::new()));
        let output = streams.clone();
        let padding = Arc::new(StdMutex::new(
            super::any_padding::Scheme::parse(super::any_padding::DEFAULT.as_bytes()).unwrap(),
        ));
        let read_padding = padding.clone();
        let failure = Arc::new(tokio::sync::Notify::new());
        let read_failure = failure.clone();
        let write_driver = tokio::spawn(async move {
            let mut writes = 1;
            let mut next: Option<Command> = None;
            // 帧编码：AnyTLS 与 smux 的头不同
            let encode = |kind: u8, id: u32, data: &[u8], out: &mut Vec<u8>| {
                if any {
                    let cmd = match kind {
                        0 => 1,
                        1 => 3,
                        2 => 2,
                        _ => kind,
                    };
                    out.push(cmd);
                    out.extend(id.to_be_bytes());
                    out.extend((data.len() as u16).to_be_bytes());
                } else {
                    out.extend([1, kind]);
                    out.extend((data.len() as u16).to_le_bytes());
                    out.extend(id.to_le_bytes());
                }
                out.extend_from_slice(data);
            };
            loop {
                let cmd = match next.take() {
                    Some(cmd) => cmd,
                    None => match rx.recv().await {
                        Some(cmd) => cmd,
                        None => break,
                    },
                };
                let result = match cmd {
                    Command::Frame(kind, id, data) => {
                        let mut wire = Vec::with_capacity(data.len() + 8);
                        encode(kind, id, &data, &mut wire);
                        let first_writes = writes;
                        writes += 1;
                        // 队列里已经有后续帧时合并成一次写入（上限 BATCH 字节）：多条流同时上传时帧可能很小，
                        // 每帧一次 TLS 记录加一次系统调用很浪费。AnyTLS 的填充方案只作用在前几次写入，
                        // 填充期间保持逐帧处理。
                        let mut batched = false;
                        while wire.len() < BATCH
                            // 按当前这一帧的写入序号判断：`writes` 已为它加过 1，用它会让第 stop−1 次写入
                            // 在队列恰有后续帧时跳过填充，是否填充取决于调度
                            && (!any || padding.lock().unwrap().stopped(first_writes))
                        {
                            match rx.try_recv() {
                                Ok(Command::Frame(kind, id, data)) => {
                                    encode(kind, id, &data, &mut wire);
                                    writes += 1;
                                    batched = true;
                                }
                                Ok(other) => {
                                    next = Some(other);
                                    break;
                                }
                                Err(_) => break,
                            }
                        }
                        let records = if any && !batched {
                            padding.lock().unwrap().encode(first_writes, wire)
                        } else {
                            Ok(vec![wire])
                        };
                        match records {
                            Err(e) => Err(e),
                            Ok(records) => {
                                async {
                                    for record in records {
                                        write.write_all(&record).await?;
                                    }
                                    write.flush().await
                                }
                                .await
                            }
                        }
                    }
                    Command::Flush(reply) => {
                        let r = write.flush().await;
                        let failed = r.is_err();
                        let _ = reply.send(r);
                        if failed {
                            break;
                        }
                        continue;
                    }
                };
                if result.is_err() {
                    break;
                }
            }
            failure.notify_one();
        });
        let controls = tx.clone();
        let read_driver = tokio::spawn(async move {
            let result: io::Result<()> = async {
                loop {
                    let mut h = [0; 8];
                    tokio::select! {r = read.read_exact(&mut h[..if any {7}else{8}]) => {r?;}, _ = read_failure.notified()=>return Err(err("session writer failed"))}
                    let (len,id,kind)=if any {
                        let len=u16::from_be_bytes(h[5..7].try_into().unwrap()) as usize;
                        let id=u32::from_be_bytes(h[1..5].try_into().unwrap());
                        // 数据 / waste 帧长度是 u16；32 KiB 只是某些实现的默认发送尺寸。
                        (len,id,if h[0]==3 {1}else {h[0]})
                    } else {
                        let len=u16::from_le_bytes(h[2..4].try_into().unwrap()) as usize;
                        let id=u32::from_le_bytes(h[4..].try_into().unwrap());
                        if h[0]!=1||!matches!(h[1],1..=3)||(h[1]!=2&&len!=0){return Err(err("invalid smux frame"));}
                        (len,id,h[1])
                    };
                    // 数据 / waste 帧长度是 u16，其余控制帧（设置、方案、告警……）很短。
                    // 控制帧超过 4096 或命令未知时只读掉并丢弃，不分配、不关闭会话（sing-anytls 对未知命令同样忽略）。
                    // 注意帧类型 1 在内部表示 FIN（线上命令 3）；线上命令 1（SYN）和 4（设置）只有服务端会收到，
                    // 这里按原始命令字判断，不能把它们当成 FIN。
                    let raw = h[0];
                    if any && !matches!(raw, 0 | 2) && (len > 4096 || !matches!(raw, 3 | 5..=10)) {
                        let mut left = len;
                        let mut sink = [0u8; 1024];
                        while left > 0 {
                            let n = left.min(sink.len());
                            tokio::select! {r=read.read_exact(&mut sink[..n])=>{r?;},_=read_failure.notified()=>return Err(err("session writer failed"))}
                            left -= n;
                        }
                        continue;
                    }
                    let mut data = vec![0;len];
                    tokio::select! {r=read.read_exact(&mut data)=>{r?;},_=read_failure.notified()=>return Err(err("session writer failed"))}
                    if any {
                        if kind==5 {return Err(err("AnyTLS server alert"));}
                        if kind==6 {
                            // 方案无效时保持原方案；不能因此关闭会话
                            if let Some(scheme) = super::any_padding::Scheme::parse(&data) { *read_padding.lock().unwrap() = scheme; }
                            continue;
                        }
                        if kind==8 {
                            // 心跳回应排在待发送队列后面；上传繁忙时队列满不能当作会话失败
                            tokio::select! {r = controls.send(Command::Frame(9,id,Bytes::new())) => {r.map_err(|_|err("AnyTLS session closed"))?;}, _ = read_failure.notified() => return Err(err("session writer failed"))}
                            continue;
                        }
                        if matches!(kind,0|9|10)||kind==7&&data.is_empty(){continue;}
                        if kind==7 {if let Some(r)=output.lock().unwrap().remove(&id){r.failed.store(true,Ordering::Release);}continue;}
                    }
                    if kind == 1 {
                        let reader = output.lock().unwrap().remove(&id);
                        if let Some(r) = reader {
                            if any {
                                r.peer_closed.closed.store(true, Ordering::Release);
                                r.peer_closed.writer.wake();
                            }
                            // FIN 排在已缓冲的数据之后，同样等待，不能因为队列满而丢掉流的结尾
                            let tx = r.tx.clone();
                            let mut sent = false;
                            let fin = async { sent = tx.send(Bytes::new()).await.is_ok() };
                            let stalled = deliver_or_stall(fin, id, &output, &read_failure).await?;
                            if stalled || !sent {
                                r.failed.store(true, Ordering::Release);
                                // 与数据停滞一样关闭流预算：唤醒等待者，信号量不必保留到会话结束
                                r.budget.close();
                            }
                        }
                    } else if kind == 2 && !data.is_empty() {
                        let reader = output.lock().unwrap().get(&id).map(|r| (r.tx.clone(), r.failed.clone(), r.budget.clone()));
                        let Some((tx, failed, budget)) = reader else { continue };
                        let n = data.len() as u32;
                        let deliver = async {
                            // 信号量关闭表示流已被丢弃，数据直接丢弃
                            let Ok(permit) = budget.acquire_many(n).await else { return };
                            permit.forget();
                            let _ = tx.send(data.into()).await;
                        };
                        if deliver_or_stall(deliver, id, &output, &read_failure).await? {
                            log::debug!("multiplex stream {id} stopped reading for {}s while other streams wait, closing it", STALL_TIMEOUT.as_secs());
                            failed.store(true, Ordering::Release);
                            budget.close();
                            output.lock().unwrap().remove(&id);
                            let _ = controls.try_send(Command::Frame(1, id, Bytes::new()));
                        }
                    }
                }
            }
            .await;
            let _ = result;
            let mut streams = output.lock().unwrap();
            for (_, r) in streams.drain() {
                r.failed.store(true, Ordering::Release);
            }
        });
        if any {
            let _ = tx.try_send(Command::Frame(
                4,
                0,
                Bytes::from_static(b"v=1\nclient=Oryn\npadding-md5=unknown"),
            ));
        }
        Self {
            any,
            tx,
            streams,
            next: AtomicU32::new(1),
            fin_keepers: Arc::new(Semaphore::new(MAX_FIN_KEEPERS)),
            read_abort: read_driver.abort_handle(),
            write_abort: write_driver.abort_handle(),
            read_driver: Driver(read_driver),
            write_driver: Driver(write_driver),
        }
    }
    pub(super) fn closed(&self) -> bool {
        self.read_driver.0.is_finished() || self.write_driver.0.is_finished()
    }
    pub(super) async fn open(&self) -> io::Result<BoxStream> {
        if self.closed() {
            return Err(err("smux session closed"));
        }
        // 先检查再推进：fetch_add 之后再判断会回绕，新流 ID 可能与存活流冲突、覆盖其 Reader
        let id = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| {
                (id <= u32::MAX - 2).then_some(id + 2)
            })
            .map_err(|_| err("smux stream ID exhausted"))?;
        let (tx, rx) = mpsc::channel(128);
        let budget = Arc::new(Semaphore::new(STREAM_BUDGET));
        let failed = Arc::new(AtomicBool::new(false));
        let peer_closed = Arc::new(PeerClosed::default());
        self.streams.lock().unwrap().insert(
            id,
            Reader {
                tx,
                failed: failed.clone(),
                budget: budget.clone(),
                peer_closed: peer_closed.clone(),
            },
        );
        let stream = SmuxStream {
            id,
            tx: PollSender::new(self.tx.clone()),
            raw: self.tx.clone(),
            rx,
            read: Bytes::new(),
            failed,
            budget,
            peer_closed,
            read_abort: self.read_abort.clone(),
            write_abort: self.write_abort.clone(),
            streams: self.streams.clone(),
            fin_keepers: self.fin_keepers.clone(),
            flush: None,
            closed: false,
            eof: false,
            any: self.any,
        };
        self.tx
            .send(Command::Frame(0, id, Bytes::new()))
            .await
            .map_err(|_| err("smux session closed"))?;
        Ok(Box::new(stream))
    }
}
struct SmuxStream {
    id: u32,
    tx: PollSender<Command>,
    raw: mpsc::Sender<Command>,
    rx: mpsc::Receiver<Bytes>,
    read: Bytes,
    failed: Arc<AtomicBool>,
    budget: Arc<Semaphore>,
    peer_closed: Arc<PeerClosed>,
    read_abort: tokio::task::AbortHandle,
    write_abort: tokio::task::AbortHandle,
    streams: Arc<StdMutex<HashMap<u32, Reader>>>,
    fin_keepers: Arc<Semaphore>,
    flush: Option<oneshot::Receiver<io::Result<()>>>,
    closed: bool,
    eof: bool,
    any: bool,
}
/// 丢弃一条未正常关闭的流时，等待写队列腾出位置发送 FIN 的最长时间。
const FIN_QUEUE_TIMEOUT: Duration = Duration::from_secs(10);
/// 独立于活跃流名额：取消 open / Drop 后，尚未退出的 FIN 任务仍占名额。
const MAX_FIN_KEEPERS: usize = 32;

impl Drop for SmuxStream {
    fn drop(&mut self) {
        // 唤醒可能正在等待这条流缓冲的读取任务
        self.budget.close();
        self.streams.lock().unwrap().remove(&self.id);
        if self.closed {
            return;
        }
        let fin = Command::Frame(1, self.id, Bytes::new());
        match self.raw.try_send(fin) {
            Ok(()) => {}
            // 写队列暂时满（承载在背压）：不能因为一条流被丢弃就关掉整个会话，
            // 共享会话上的其它流还在使用。放到后台等空位，超时仍送不出去才关闭承载。
            Err(mpsc::error::TrySendError::Full(fin)) => {
                // spawn 前获取名额，连尚未被调度的任务也计入上限。只有真正耗尽
                // 关闭登记预算才 fail closed，不能把普通单流背压当成会话失败。
                let Ok(permit) = self.fin_keepers.clone().try_acquire_owned() else {
                    abort_session(&self.read_abort, &self.write_abort, &self.streams);
                    return;
                };
                let (raw, streams) = (self.raw.clone(), self.streams.clone());
                let (read_abort, write_abort) = (self.read_abort.clone(), self.write_abort.clone());
                let waiter = async move {
                    // RAII 覆盖成功、超时、发送失败以及 runtime 取消（包括首次 poll 前）。
                    let _permit = permit;
                    if tokio::time::timeout(FIN_QUEUE_TIMEOUT, raw.send(fin))
                        .await
                        .map_or(true, |sent| sent.is_err())
                    {
                        abort_session(&read_abort, &write_abort, &streams);
                    }
                };
                match tokio::runtime::Handle::try_current() {
                    Ok(handle) => {
                        handle.spawn(waiter);
                    }
                    Err(_) => abort_session(&self.read_abort, &self.write_abort, &self.streams),
                }
            }
            // 写任务已经结束：会话本来就不可用
            Err(mpsc::error::TrySendError::Closed(_)) => {
                abort_session(&self.read_abort, &self.write_abort, &self.streams)
            }
        }
    }
}

/// FIN 无法送出时关闭整个承载，避免对端积累无法回收的流。
fn abort_session(
    read_abort: &tokio::task::AbortHandle,
    write_abort: &tokio::task::AbortHandle,
    streams: &StdMutex<HashMap<u32, Reader>>,
) {
    read_abort.abort();
    write_abort.abort();
    for (_, reader) in streams.lock().unwrap().drain() {
        reader.failed.store(true, Ordering::Release);
    }
}
impl AsyncRead for SmuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(err("smux stream or session failed")));
        }
        loop {
            if !self.read.is_empty() {
                let n = self.read.len().min(out.remaining());
                out.put_slice(&self.read[..n]);
                self.read.advance(n);
                self.budget.add_permits(n);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(self.rx.poll_recv(cx)) {
                Some(data) if data.is_empty() => self.eof = true,
                Some(data) => self.read = data,
                None => return Poll::Ready(Err(err("smux session closed"))),
            }
        }
    }
}
impl AsyncWrite for SmuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.peer_closed.writer.register(cx.waker());
        if self.closed
            || self.peer_closed.closed.load(Ordering::Acquire)
            || self.failed.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(err("smux write closed")));
        }
        // 取消过的 flush 必须先完成，避免下一次 flush 误用旧屏障的确认。
        if self.flush.is_some() {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.tx.poll_reserve(cx)).map_err(io::Error::other)?;
        // 不能把上限定在 16384 - 8 来凑一个 TLS 记录：调用方一次给 16384 字节，剩下的 8 字节会变成
        // 一个只有帧头加 8 字节的小帧，帧数翻倍（真机上 AnyTLS 上行因此掉了约 25%）。
        let n = data.len().min(16384);
        let id = self.id;
        self.tx
            .send_item(Command::Frame(2, id, Bytes::copy_from_slice(&data[..n])))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::future::Future;
        if self.flush.is_none() {
            ready!(self.tx.poll_reserve(cx)).map_err(io::Error::other)?;
            let (tx, rx) = oneshot::channel();
            self.tx
                .send_item(Command::Flush(tx))
                .map_err(io::Error::other)?;
            self.flush = Some(rx);
        }
        let result = ready!(Pin::new(self.flush.as_mut().unwrap()).poll(cx))
            .map_err(|_| err("smux session closed"))?;
        self.flush = None;
        Poll::Ready(result)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            if self.flush.is_some() {
                ready!(self.as_mut().poll_flush(cx))?;
            }
            ready!(self.tx.poll_reserve(cx)).map_err(io::Error::other)?;
            let id = self.id;
            self.tx
                .send_item(Command::Frame(1, id, Bytes::new()))
                .map_err(io::Error::other)?;
            self.closed = true;
            if self.any {
                // AnyTLS 的 FIN 关闭整条流：sing-anytls 服务端（v0.0.11 起）收到 FIN 后只在本地关闭，
                // 不会回 FIN，等对端的 EOF 会一直等下去。本端同样视为已关闭：读取到此为止。
                self.eof = true;
                // split 的另一个半部可能仍持有此流，不能等 Drop 才唤醒接收任务。
                self.budget.close();
                self.rx.close();
                self.read = Bytes::new();
                while self.rx.try_recv().is_ok() {}
                self.streams.lock().unwrap().remove(&self.id);
            }
        }
        self.poll_flush(cx)
    }
}

#[cfg(test)]
#[path = "smux_keeper_tests.rs"]
mod keeper_tests;

#[cfg(test)]
#[path = "smux_audit_tests.rs"]
mod audit_tests;

#[cfg(test)]
mod tests {
    use super::*;
    async fn frame(peer: &mut tokio::io::DuplexStream, id: u32, data: &[u8]) {
        let mut h = vec![1, 2];
        h.extend((data.len() as u16).to_le_bytes());
        h.extend(id.to_le_bytes());
        peer.write_all(&h).await.unwrap();
        peer.write_all(data).await.unwrap();
    }
    /// 调查共享读驱动的队头等待；测试构建使用 300 ms，而非生产 10 s。
    #[tokio::test]
    #[ignore = "performance survey; run alone with --nocapture"]
    async fn survey_slow_stream_delays_healthy_stream() {
        for stalled in [false, true] {
            let mut samples = Vec::new();
            for _ in 0..5 {
                let (carrier, mut peer) = tokio::io::duplex(256 * 1024);
                let session = Session::new(Box::new(carrier));
                let mut slow = session.open().await.unwrap();
                let mut fast = session.open().await.unwrap();
                let begin = std::time::Instant::now();
                if stalled {
                    for _ in 0..33 { frame(&mut peer, 1, &[1; 4096]).await; }
                }
                frame(&mut peer, 3, b"fast").await;
                let mut b = [0; 4];
                tokio::time::timeout(Duration::from_secs(2), fast.read_exact(&mut b)).await.unwrap().unwrap();
                assert_eq!(&b, b"fast");
                let elapsed = begin.elapsed();
                if stalled {
                    assert!(elapsed >= STALL_TIMEOUT, "shared read driver waited for isolation timeout");
                    assert!(slow.read(&mut b).await.is_err());
                }
                samples.push(elapsed.as_micros());
            }
            samples.sort_unstable();
            println!("smux_survey stalled={stalled} samples=5 median_us={} min_us={} max_us={} test_timeout_ms={} production_timeout_ms=10000", samples[2], samples[0], samples[4], STALL_TIMEOUT.as_millis());
        }
    }

    /// 不再读取的流：缓冲满后等待 `STALL_TIMEOUT`，再只关闭这条流，其他流继续工作。
    #[tokio::test]
    async fn stalled_stream_is_bounded_and_other_stream_survives() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (carrier, mut peer) = tokio::io::duplex(256 * 1024);
            let session = Session::new(Box::new(carrier));
            let mut slow = session.open().await.unwrap();
            let mut fast = session.open().await.unwrap();
            for _ in 0..33 {
                frame(&mut peer, 1, &[1; 4096]).await;
            }
            frame(&mut peer, 3, b"fast").await;
            let mut b = [0; 4];
            fast.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"fast");
            assert!(slow.read(&mut b).await.is_err());
            drop(peer);
            assert!(fast.read(&mut b).await.is_err());
        })
        .await
        .unwrap();
    }
    /// 读得慢的流（如测速时 lwIP 发送窗口满）超过 128 KiB 缓冲不能被关闭：
    /// 读取任务等待消费，数据完整，结尾的 FIN 也不会因为队列满而丢失。
    #[tokio::test]
    async fn slow_reader_gets_backpressure_instead_of_reset() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (carrier, mut peer) = tokio::io::duplex(64 * 1024);
            let session = Session::new_any(Box::new(carrier));
            let mut flow = session.open().await.unwrap();
            let total = 1024 * 1024;
            let writer = tokio::spawn(async move {
                // 跳过客户端发出的设置与 SYN 帧
                let mut sink = [0u8; 4096];
                for chunk in 0..total / 16384 {
                    let mut h = vec![2];
                    h.extend(1u32.to_be_bytes());
                    h.extend(16384u16.to_be_bytes());
                    peer.write_all(&h).await.unwrap();
                    peer.write_all(&vec![(chunk % 251) as u8; 16384])
                        .await
                        .unwrap();
                    let _ =
                        tokio::time::timeout(Duration::from_millis(1), peer.read(&mut sink)).await;
                }
                let mut fin = vec![3];
                fin.extend(1u32.to_be_bytes());
                fin.extend(0u16.to_be_bytes());
                peer.write_all(&fin).await.unwrap();
                peer
            });
            // 先让发送端填满缓冲，再读；等待短于 STALL_TIMEOUT
            tokio::time::sleep(STALL_TIMEOUT / 2).await;
            let mut got = Vec::new();
            let mut b = vec![0; 3000];
            loop {
                let n = flow.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&b[..n]);
            }
            assert_eq!(got.len(), total);
            for (i, chunk) in got.chunks(16384).enumerate() {
                assert!(chunk.iter().all(|&x| x == (i % 251) as u8));
            }
            drop(writer.await.unwrap());
        })
        .await
        .unwrap();
    }

    /// 会话里只有一条流时，应用长时间不读也不关闭它（与普通 TCP 一样等待），之后数据完整。
    #[tokio::test]
    async fn lone_stream_waits_past_stall_timeout() {
        let (carrier, mut peer) = tokio::io::duplex(256 * 1024);
        let session = Session::new(Box::new(carrier));
        let mut flow = session.open().await.unwrap();
        for _ in 0..40 {
            frame(&mut peer, 1, &[7; 4096]).await;
        }
        tokio::time::sleep(STALL_TIMEOUT * 3).await;
        let mut got = vec![0; 40 * 4096];
        flow.read_exact(&mut got).await.unwrap();
        assert!(got.iter().all(|&x| x == 7));
    }

    #[tokio::test]
    async fn fragmented_read_cancellation_preserves_bytes() {
        let (carrier, mut peer) = tokio::io::duplex(256);
        let session = Session::new(Box::new(carrier));
        let mut flow = session.open().await.unwrap();
        peer.write_all(&[1, 2, 4]).await.unwrap();
        let mut b = [0; 4];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), flow.read_exact(&mut b))
                .await
                .is_err()
        );
        peer.write_all(&[0, 1, 0, 0, 0]).await.unwrap();
        peer.write_all(b"data").await.unwrap();
        flow.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"data");
        assert_eq!(flow.write(&[]).await.unwrap(), 0);
    }

    /// AnyTLS 的 FIN 关闭整条流：新版 sing-anytls 服务端收到 FIN 只在本地关闭、不回 FIN，
    /// 本端发出 FIN 之后读取必须立刻结束，不能等对端的 EOF。smux 的 FIN 则是半关闭，继续读。
    #[tokio::test]
    async fn any_fin_closes_the_whole_stream_but_smux_fin_is_a_half_close() {
        let (carrier, mut peer) = tokio::io::duplex(4096);
        let session = Session::new_any(Box::new(carrier));
        let mut flow = session.open().await.unwrap();
        flow.shutdown().await.unwrap();
        let mut b = [0u8; 4];
        let got = tokio::time::timeout(Duration::from_secs(2), flow.read(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, 0);
        drop(peer.shutdown().await);
        // smux：写方向关闭之后仍能读到对端后续发来的数据
        let (carrier, mut peer) = tokio::io::duplex(4096);
        let session = Session::new(Box::new(carrier));
        let mut flow = session.open().await.unwrap();
        flow.shutdown().await.unwrap();
        frame(&mut peer, 1, b"late").await;
        flow.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"late");
    }
}
