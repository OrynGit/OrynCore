//! QUIC 出站的并发 TCP 流名额：建流前占用，流被丢弃时归还。

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxStream;

#[derive(Clone, Default)]
pub(crate) struct Slots(Arc<AtomicUsize>);

/// 一个已占用的名额；丢弃即归还。
pub(crate) struct Slot(Arc<AtomicUsize>);

impl Slots {
    /// 未满则占用一个名额。
    pub(crate) fn acquire(&self, limit: usize) -> Option<Slot> {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < limit).then_some(used + 1)
            })
            .ok()
            .map(|_| Slot(self.0.clone()))
    }

    /// 当前占用的名额数。
    pub(crate) fn used(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 持有名额的流：流关闭（被丢弃）时归还名额。
pub(crate) struct Counted {
    inner: BoxStream,
    _slot: Slot,
}

impl Counted {
    pub(crate) fn boxed(inner: BoxStream, slot: Slot) -> BoxStream {
        Box::new(Self { inner, _slot: slot })
    }
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 持有底层传输保活句柄（如 QUIC 客户端或隧道实例）的流包装；
/// 配置重载替换出站后，已建立的连接仍能继续运行直到流结束。
#[allow(dead_code)]
pub(crate) struct HeldStream<K: Send + 'static> {
    inner: BoxStream,
    _keep: K,
}

impl<K: Send + Unpin + 'static> HeldStream<K> {
    #[allow(dead_code)]
    pub(crate) fn boxed(inner: BoxStream, keep: K) -> BoxStream {
        Box::new(Self { inner, _keep: keep })
    }
}

impl<K: Send + Unpin + 'static> AsyncRead for HeldStream<K> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<K: Send + Unpin + 'static> AsyncWrite for HeldStream<K> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_returned_when_streams_drop() {
        let slots = Slots::default();
        let held: Vec<_> = (0..3).map(|_| slots.acquire(3).unwrap()).collect();
        assert!(slots.acquire(3).is_none());
        let stream = Counted::boxed(
            Box::new(::tokio::io::duplex(1).0),
            slots.acquire(4).unwrap(),
        );
        assert_eq!(slots.used(), 4);
        drop(stream);
        drop(held);
        assert_eq!(slots.used(), 0);
        // 累计建流远超上限也不会被永久拒绝
        for _ in 0..100 {
            drop(slots.acquire(1).unwrap());
        }
    }
}
