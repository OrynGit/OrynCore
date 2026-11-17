//! 合成吞吐端点（`198.18.0.4`）：隧道吞吐测量用的内存源 / 汇。
//!
//! 协议与 App 里的 BSD socket 压测一致：客户端先发 1 字节命令，`D` 表示客户端下载（本端无限输出），
//! 其余表示客户端上传（本端丢弃全部输入）。没有任何外部可达的内容，数据全部是内存里的填充字节。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub struct SyntheticStream {
    /// 客户端发来的第一个字节；收到之前读端不出数据。
    mode: Option<u8>,
    /// 客户端已关闭写方向（`shutdown`）；读端随后给 EOF。
    closed: bool,
    read_waker: Option<Waker>,
}

impl AsyncRead for SyntheticStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.mode == Some(b'D') {
            // 内容无所谓：只推进填充量，不额外写入
            let n = buf.remaining();
            buf.initialize_unfilled();
            buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        self.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for SyntheticStream {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.mode.is_none() && !buf.is_empty() {
            self.mode = Some(buf[0]);
            if let Some(waker) = self.read_waker.take() {
                waker.wake();
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn download_mode_streams_and_upload_mode_discards() {
        let mut down = SyntheticStream::default();
        down.write_all(b"D").await.unwrap();
        let mut buf = [0u8; 4096];
        assert_eq!(down.read(&mut buf).await.unwrap(), 4096);
        down.shutdown().await.unwrap();
        assert_eq!(down.read(&mut buf).await.unwrap(), 0);

        let mut up = SyntheticStream::default();
        up.write_all(b"U").await.unwrap();
        up.write_all(&[7u8; 100_000]).await.unwrap();
        // 上传模式没有输出，读端等到关闭才 EOF
        let pending = tokio::time::timeout(std::time::Duration::from_millis(30), up.read(&mut buf)).await;
        assert!(pending.is_err());
        up.shutdown().await.unwrap();
        assert_eq!(up.read(&mut buf).await.unwrap(), 0);
    }
}
