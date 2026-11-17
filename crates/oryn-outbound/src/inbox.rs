//! 可在 `&self` 上等待的有界队列。满了就丢弃。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tokio::sync::Notify;

/// 会话收包队列的默认上限：包数与字节数同时限制（数据报最大约 64 KiB，只按包数限制会让内存没有上界）。
/// 太小会在读取方被调度延迟一两毫秒时丢包：40 Mbit/s 的下行洪泛里，8 个包的队列丢掉了 9–29%。
pub const SESSION_PACKETS: usize = 128;
pub const SESSION_BYTES: usize = 256 * 1024;

struct Queue<T> {
    items: VecDeque<(T, usize)>,
    bytes: usize,
}

pub struct Inbox<T> {
    queue: Mutex<Queue<T>>,
    notify: Notify,
    closed: AtomicBool,
    cap: usize,
    max_bytes: usize,
}

impl<T> Inbox<T> {
    #[cfg(test)]
    pub fn new(cap: usize) -> Self {
        Self::with_bytes(cap, usize::MAX)
    }

    /// 包数与字节数都有上限；`try_send_sized` 按调用方给的字节数计。
    pub fn with_bytes(cap: usize, max_bytes: usize) -> Self {
        Self {
            queue: Mutex::new(Queue {
                items: VecDeque::new(),
                bytes: 0,
            }),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
            cap,
            max_bytes,
        }
    }

    #[cfg(test)]
    pub fn try_send(&self, item: T) -> bool {
        self.try_send_sized(item, 0)
    }

    /// `bytes` 是这个包占用的字节数。超过包数或字节上限就丢弃（空队列时总是收下，保证大包不会永远进不来）。
    pub fn try_send_sized(&self, item: T, bytes: usize) -> bool {
        let mut queue = self.queue.lock().unwrap();
        if queue.items.len() >= self.cap
            || (!queue.items.is_empty() && queue.bytes.saturating_add(bytes) > self.max_bytes)
        {
            return false;
        }
        queue.bytes += bytes;
        queue.items.push_back((item, bytes));
        self.notify.notify_one();
        true
    }

    /// 关闭后队列里剩下的包仍可读完，之后 `recv` 返回 None。
    /// 底层连接断开时由读循环调用，否则会话会一直等到上层空闲超时。
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    pub async fn recv(&self) -> Option<T> {
        loop {
            {
                let mut queue = self.queue.lock().unwrap();
                if let Some((item, bytes)) = queue.items.pop_front() {
                    queue.bytes -= bytes;
                    return Some(item);
                }
            }
            if self.closed.load(Ordering::Acquire) {
                // 还有别的等待者时让它们也醒来
                self.notify.notify_one();
                return None;
            }
            self.notify.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn close_drains_queued_items_then_ends() {
        let inbox = Inbox::new(2);
        assert!(inbox.try_send(1));
        inbox.close();
        assert_eq!(inbox.recv().await, Some(1));
        assert_eq!(inbox.recv().await, None);
        assert_eq!(inbox.recv().await, None);
    }

    #[tokio::test]
    async fn close_wakes_a_waiting_receiver() {
        let inbox = std::sync::Arc::new(Inbox::<u8>::new(2));
        let waiter = {
            let inbox = inbox.clone();
            tokio::spawn(async move { inbox.recv().await })
        };
        tokio::task::yield_now().await;
        inbox.close();
        assert_eq!(waiter.await.unwrap(), None);
    }
}
