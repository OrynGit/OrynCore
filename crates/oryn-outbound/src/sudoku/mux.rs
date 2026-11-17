// 帧格式移植自 MetaCubeX/mihomo transport/sudoku/multiplex/session.go
// @ 88dcbf7f1614a67c3b36b848ee3592dfa92ada36，GPL-3.0；原文件未单列版权声明。
// Oryn：32 条流、64 KiB 每流入队上限，满队列 RESET 慢流，不阻塞共享 reader。
#[cfg(test)]
#[path = "mux_lifecycle_tests.rs"]
mod lifecycle_tests;
#[cfg(test)]
#[path = "mux_tests.rs"]
mod tests;

use super::bad;
use crate::BoxStream;
use oryn_config::TargetAddr;
use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::{CancellationToken, PollSender};
struct Frame {
    kind: u8,
    id: u32,
    data: Vec<u8>,
}
enum Command {
    Frame(Frame),
    Flush(oneshot::Sender<()>),
}
enum Incoming {
    Data(Vec<u8>),
    Close,
}
struct Registration {
    send: mpsc::Sender<Incoming>,
    reset: CancellationToken,
    close_permit: mpsc::OwnedPermit<Command>,
}
pub struct Session {
    pub stop: Arc<CancellationToken>,
    send: mpsc::Sender<Command>,
    streams: Mutex<HashMap<u32, Registration>>,
    next: AtomicU32,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.stop.cancel();
        for task in self.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}
impl Session {
    pub fn new(stream: BoxStream, stop: Arc<CancellationToken>) -> Arc<Self> {
        // 最多 32 个活跃流各预留一个取消帧名额，其余容量用于普通命令。
        let (tx, mut rx) = mpsc::channel(64);
        let session = Arc::new(Self {
            stop: stop.clone(),
            send: tx,
            streams: Mutex::new(HashMap::new()),
            next: AtomicU32::new(1),
            tasks: Mutex::new(vec![]),
        });
        let (mut reader, mut writer) = tokio::io::split(stream);
        let cancelled = stop.clone();
        let write = tokio::spawn(async move {
            let work = async {
                let mut ticker = tokio::time::interval(Duration::from_secs(15));
                ticker.tick().await;
                loop {
                    let command = tokio::select! {command=rx.recv()=>match command{Some(c)=>c,None=>break},_=ticker.tick()=>Command::Frame(Frame{kind:2,id:0,data:vec![]})};
                    match command {
                        Command::Frame(f) => {
                            let mut head = [0; 9];
                            head[0] = f.kind;
                            head[1..5].copy_from_slice(&f.id.to_be_bytes());
                            head[5..].copy_from_slice(&(f.data.len() as u32).to_be_bytes());
                            writer.write_all(&head).await?;
                            writer.write_all(&f.data).await?;
                            writer.flush().await?;
                        }
                        Command::Flush(reply) => {
                            writer.flush().await?;
                            let _ = reply.send(());
                        }
                    }
                }
                Ok::<_, io::Error>(())
            };
            tokio::select! {_=cancelled.cancelled()=>{},_=work=>{}};
            cancelled.cancel();
        });
        let weak = Arc::downgrade(&session);
        let read = tokio::spawn(async move {
            let work = async {
                loop {
                    let mut head = [0; 9];
                    reader.read_exact(&mut head).await?;
                    let id = u32::from_be_bytes(head[1..5].try_into().unwrap());
                    let n = u32::from_be_bytes(head[5..].try_into().unwrap()) as usize;
                    if n > 256 * 1024 || !(1..=4).contains(&head[0]) {
                        return Err(bad("invalid Sudoku mux frame"));
                    }
                    let mut data = vec![0; n];
                    reader.read_exact(&mut data).await?;
                    let Some(s) = weak.upgrade() else {
                        break;
                    };
                    // RESET 不排在 DATA 队列后：锁存终态并唤醒两侧，即使调用者从未读。
                    if head[0] == 4 || head[0] == 1 {
                        if let Some(entry) = s.streams.lock().unwrap().remove(&id) {
                            entry.reset.cancel();
                        }
                        continue;
                    }
                    let mut streams = s.streams.lock().unwrap();
                    if let Some(entry) = streams.get(&id) {
                        let overflow = match head[0] {
                            2 => data.chunks(16 * 1024).any(|part| {
                                entry.send.try_send(Incoming::Data(part.to_vec())).is_err()
                            }),
                            3 => entry.send.try_send(Incoming::Close).is_err(),
                            _ => unreachable!(),
                        };
                        if overflow {
                            // DATA/CLOSE 均不能等待慢流；已接纳的部分也以 RESET 终态撤销。
                            // 与 Drop 共用唯一预留名额，同 FIFO 入队，不 spawn 关闭任务。
                            let entry = streams.remove(&id).unwrap();
                            entry.reset.cancel();
                            entry.close_permit.send(Command::Frame(Frame {
                                kind: 4,
                                id,
                                data: b"receive queue full".to_vec(),
                            }));
                        }
                    }
                }
                Ok::<_, io::Error>(())
            };
            tokio::select! {_=stop.cancelled()=>{},_=work=>{}};
            stop.cancel();
        });
        session.tasks.lock().unwrap().extend([read, write]);
        session
    }
    pub async fn open(self: &Arc<Self>, target: &TargetAddr) -> io::Result<BoxStream> {
        if self.stop.is_cancelled() {
            return Err(bad("Sudoku mux closed"));
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            self.stop.cancel();
            return Err(bad("Sudoku mux IDs exhausted"));
        }
        // Drop 不等待、不生成任务，也不因取消队列满而关闭共享会话。
        // permit.send 仍按实际发送时刻进入同一 FIFO，不能越过本流 OPEN/DATA。
        let close_permit = tokio::select! {
            _ = self.stop.cancelled() => return Err(bad("Sudoku mux closed")),
            p = self.send.clone().reserve_owned() => p.map_err(|_| bad("Sudoku mux writer closed"))?,
        };
        let reset = CancellationToken::new();
        let (tx, rx) = mpsc::channel(4);
        {
            // 检查与插入在同一把锁内，并发开流不会超过上限
            let mut streams = self.streams.lock().unwrap();
            if streams.len() >= 32 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Sudoku mux flow limit reached",
                ));
            }
            streams.insert(
                id,
                Registration {
                    send: tx,
                    reset: reset.clone(),
                    close_permit,
                },
            );
        }
        let mut stream = Stream {
            session: self.clone(),
            id,
            rx,
            send: PollSender::new(self.send.clone()),
            pending: vec![],
            offset: 0,
            read_closed: false,
            write_closed: false,
            flush: None,
            opened: false,
            shutdown_complete: false,
            reset: Box::pin(reset.cancelled_owned()),
            cancelled: Box::pin(self.stop.as_ref().clone().cancelled_owned()),
        };
        let mut data = vec![];
        oryn_protocol::socks5::encode_addr(target, &mut data)?;
        tokio::select! {_=self.stop.cancelled()=>return Err(bad("Sudoku mux closed")),r=self.send.send(Command::Frame(Frame{kind:1,id,data}))=>r.map_err(|_|bad("Sudoku mux writer closed"))?,}
        // OPEN 已入队：之后取消（包括 flush 期间）按中止处理，FIFO 发送 RESET。
        stream.opened = true;
        stream.flush().await?;
        Ok(Box::new(stream))
    }
}
struct Stream {
    session: Arc<Session>,
    id: u32,
    rx: mpsc::Receiver<Incoming>,
    send: PollSender<Command>,
    pending: Vec<u8>,
    offset: usize,
    read_closed: bool,
    write_closed: bool,
    flush: Option<oneshot::Receiver<()>>,
    opened: bool,
    shutdown_complete: bool,
    reset: Pin<Box<dyn Future<Output = ()> + Send>>,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
}
impl Drop for Stream {
    fn drop(&mut self) {
        let entry = self.session.streams.lock().unwrap().remove(&self.id);
        // 打开帧还没进写队列：服务端不知道这条流，直接撤销即可，不影响会话上的其他流
        // 成功 shutdown 已发送并 flush CLOSE；普通 Drop/取消仍是 RESET，不能冒充 EOF。
        if self.opened && !self.shutdown_complete {
            if let Some(entry) = entry {
                entry.close_permit.send(Command::Frame(Frame {
                    kind: 4,
                    id: self.id,
                    data: b"closed".to_vec(),
                }));
            }
        }
    }
}
impl Stream {
    fn active(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.reset.as_mut().poll(cx).is_ready() {
            Err(bad("Sudoku mux stream reset"))
        } else if self.cancelled.as_mut().poll(cx).is_ready() {
            Err(bad("Sudoku mux closed"))
        } else {
            Ok(())
        }
    }
    fn frame(&mut self, cx: &mut Context<'_>, kind: u8, data: Vec<u8>) -> Poll<io::Result<()>> {
        std::task::ready!(self.send.poll_reserve(cx))
            .map_err(|_| bad("Sudoku mux writer closed"))?;
        self.send
            .send_item(Command::Frame(Frame {
                kind,
                id: self.id,
                data,
            }))
            .map_err(|_| bad("Sudoku mux writer closed"))?;
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.active(cx)?;
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.offset < self.pending.len() {
                let n = out.remaining().min(self.pending.len() - self.offset);
                out.put_slice(&self.pending[self.offset..self.offset + n]);
                self.offset += n;
                return Poll::Ready(Ok(()));
            }
            if self.read_closed {
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.rx.poll_recv(cx)) {
                Some(Incoming::Data(data)) => {
                    self.pending = data;
                    self.offset = 0;
                }
                Some(Incoming::Close) => {
                    self.read_closed = true;
                }
                _ => return Poll::Ready(Err(bad("Sudoku mux stream reset"))),
            }
        }
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.active(cx)?;
        if self.write_closed {
            return Poll::Ready(Err(bad("Sudoku mux write closed")));
        }
        let n = buf.len().min(4096);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.frame(cx, 2, buf[..n].to_vec()))?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.active(cx)?;
        if self.flush.is_none() {
            std::task::ready!(self.send.poll_reserve(cx))
                .map_err(|_| bad("Sudoku mux writer closed"))?;
            let (tx, rx) = oneshot::channel();
            self.send
                .send_item(Command::Flush(tx))
                .map_err(|_| bad("Sudoku mux writer closed"))?;
            self.flush = Some(rx);
        }
        std::task::ready!(Pin::new(self.flush.as_mut().unwrap()).poll(cx))
            .map_err(|_| bad("Sudoku mux flush failed"))?;
        self.flush = None;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.active(cx)?;
        if !self.write_closed {
            std::task::ready!(self.frame(cx, 3, vec![]))?;
            self.write_closed = true;
        }
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        self.shutdown_complete = true;
        Poll::Ready(Ok(()))
    }
}
