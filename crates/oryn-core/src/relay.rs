//! TCP 双向转发：带计数、半关闭与空闲超时。

use std::cell::Cell;
use std::io;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::stats::{ConnGuard, Stats};

/// 每个方向的初始缓冲区大小。连接数多时这是主要内存开销之一，保持较小。
const BUF_SIZE: usize = 8 * 1024;
/// 批量传输时缓冲按需翻倍直到这个上限（一次读就把缓冲填满才算批量）；普通连接不会增长。
const BUF_MAX: usize = 64 * 1024;
/// 双向都在活动时的空闲超时。
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// 一个方向已结束（半关闭）后，另一方向的空闲超时。
const HALF_CLOSED_TIMEOUT: Duration = Duration::from_secs(60);
const CHECK_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
enum Dir {
    Up,
    Down,
}

fn read_side(dir: Dir) -> &'static str {
    match dir {
        Dir::Up => "read from app",
        Dir::Down => "read from remote",
    }
}

fn write_side(dir: Dir) -> &'static str {
    match dir {
        Dir::Up => "write to remote",
        Dir::Down => "write to app",
    }
}

/// 转发结束的原因，供调用方写入日志。
pub struct RelayEnd {
    pub reason: String,
    /// 从开始转发到收到远端第一个字节的时间；远端一直没发数据时为 None。
    pub first_down: Option<Duration>,
    /// 因读写错误或空闲超时而结束（不是双方正常关闭）。
    pub abnormal: bool,
}

/// 给 I/O 错误加上发生位置，便于区分是应用侧还是出站侧出了问题。
fn tag(what: &'static str) -> impl FnOnce(io::Error) -> io::Error {
    move |e| io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// `local` 是隧道侧（应用），`remote` 是出站侧。
pub async fn relay<L, R>(local: L, remote: R, conn: &ConnGuard, stats: &Stats) -> RelayEnd
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (lr, lw) = tokio::io::split(local);
    let (rr, rw) = tokio::io::split(remote);
    let started = Instant::now();
    let last = Cell::new(started);
    let first_down = Cell::new(None);

    let up = copy(lr, rw, Dir::Up, conn, stats, &last, &first_down);
    let down = copy(rr, lw, Dir::Down, conn, stats, &last, &first_down);
    let cancelled = conn.cancelled();
    tokio::pin!(up, down, cancelled);

    let mut up_done = false;
    let mut down_done = false;
    let mut ticker = tokio::time::interval(CHECK_INTERVAL);
    ticker.tick().await;
    loop {
        tokio::select! {
            r = &mut up, if !up_done => {
                up_done = true;
                if let Err(e) = r {
                    return RelayEnd { first_down: first_down.get().map(|t| t.duration_since(started)), reason: format!("upload (app to remote) failed: {e}"), abnormal: true };
                }
            }
            r = &mut down, if !down_done => {
                down_done = true;
                if let Err(e) = r {
                    return RelayEnd { first_down: first_down.get().map(|t| t.duration_since(started)), reason: format!("download (remote to app) failed: {e}"), abnormal: true };
                }
            }
            _ = &mut cancelled => {
                return RelayEnd { first_down: first_down.get().map(|t| t.duration_since(started)), reason: "closed by policy switch".to_string(), abnormal: false };
            }
            _ = ticker.tick() => {
                let limit = if up_done || down_done { HALF_CLOSED_TIMEOUT } else { IDLE_TIMEOUT };
                if last.get().elapsed() > limit {
                    let which = if up_done { "upload finished, download idle" } else if down_done { "download finished, upload idle" } else { "both directions idle" };
                    return RelayEnd { first_down: first_down.get().map(|t| t.duration_since(started)), reason: format!("idle timeout: {which}"), abnormal: true };
                }
            }
        }
        if up_done && down_done {
            return RelayEnd {
                first_down: first_down.get().map(|t| t.duration_since(started)),
                reason: "closed by both sides".into(),
                abnormal: false,
            };
        }
    }
}

async fn copy<Rd, Wr>(
    mut r: Rd,
    mut w: Wr,
    dir: Dir,
    conn: &ConnGuard,
    stats: &Stats,
    last: &Cell<Instant>,
    first_down: &Cell<Option<Instant>>,
) -> io::Result<()>
where
    Rd: AsyncRead + Unpin,
    Wr: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_SIZE];
    // 写出后不立刻 flush：读侧还有立即可读的数据就接着转发，读不到（要等待）之前再 flush。
    // 大块传输时 flush（lwIP 的 tcp_output、带缓冲出站的一条记录）不再每 8 KiB 一次；
    // 交互流量读侧马上 Pending，照样在等待前 flush，不增加延迟。
    let mut unflushed = false;
    loop {
        let ready = if unflushed {
            // `read` 可取消：未就绪时丢弃这次读取不会丢数据
            tokio::select! {
                biased;
                r = r.read(&mut buf) => Some(r),
                _ = std::future::ready(()) => None,
            }
        } else {
            None
        };
        let n = match ready {
            Some(result) => result,
            None => {
                // 读到数据后总会写出并重新置位，这里不必清除标记
                if unflushed {
                    w.flush().await.map_err(tag(write_side(dir)))?;
                }
                r.read(&mut buf).await
            }
        }
        .map_err(tag(read_side(dir)))?;
        if n > 0 && matches!(dir, Dir::Down) && first_down.get().is_none() {
            first_down.set(Some(Instant::now()));
        }
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        if n == buf.len() && buf.len() < BUF_MAX {
            buf.resize(buf.len() * 2, 0);
        }
        w.write_all(&buf[..n]).await.map_err(tag(write_side(dir)))?;
        unflushed = true;
        last.set(Instant::now());
        match dir {
            Dir::Up => {
                conn.add_up(n as u64);
                stats.add_up(n as u64);
            }
            Dir::Down => {
                conn.add_down(n as u64);
                stats.add_down(n as u64);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn one_small_request_flushes_buffered_outbound() {
        use crate::stats::ConnRegistry;
        use oryn_router::{FlowContext, Network};
        use std::rc::Rc;
        let (mut app, local) = tokio::io::duplex(1024);
        let (remote, mut peer) = tokio::io::duplex(1024);
        let remote = tokio::io::BufStream::new(remote);
        let registry = Rc::new(ConnRegistry::default());
        let flow = FlowContext::new(
            1,
            Network::Tcp,
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        );
        let guard = registry.register(&flow, vec!["P".into()], "MATCH".into());
        let stats = Stats::default();
        let io = async {
            app.write_all(b"ping").await.unwrap();
            let mut data = [0; 4];
            peer.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
            peer.write_all(b"pong").await.unwrap();
            app.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"pong");
            app.shutdown().await.unwrap();
            peer.shutdown().await.unwrap();
        };
        let (end, _) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(relay(local, remote, &guard, &stats), io)
        })
        .await
        .unwrap();
        assert_eq!(stats.upload.load(std::sync::atomic::Ordering::Relaxed), 4);
        assert!(!end.abnormal, "{}", end.reason);
    }

    #[tokio::test]
    async fn remote_failure_is_reported_with_its_side() {
        use crate::stats::ConnRegistry;
        use oryn_router::{FlowContext, Network};
        use std::rc::Rc;
        let (mut app, local) = tokio::io::duplex(1024);
        let (remote, peer) = tokio::io::duplex(1024);
        drop(peer); // 出站对端消失：向它写入必然失败
        let registry = Rc::new(ConnRegistry::default());
        let flow = FlowContext::new(
            1,
            Network::Tcp,
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        );
        let guard = registry.register(&flow, vec!["P".into()], "MATCH".into());
        let stats = Stats::default();
        app.write_all(b"ping").await.unwrap();
        let end =
            tokio::time::timeout(Duration::from_secs(1), relay(local, remote, &guard, &stats))
                .await
                .unwrap();
        assert!(end.abnormal);
        assert!(end.reason.contains("write to remote"), "{}", end.reason);
    }
}
