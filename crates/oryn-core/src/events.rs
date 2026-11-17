//! 面向用户的事件队列（策略组自动切换、资源更新结果）。
//!
//! Core 只负责产生事件；是否弹出系统通知、如何记录历史由 Extension 的 Swift 层决定
//! （Core 不碰 UI 与通知）。队列有上限，满载丢最旧的；同一事件在 [`DEDUP`] 内只记一次，
//! 避免失败重试反复刷屏。

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// 未被取走的事件上限。
const MAX_PENDING: usize = 64;
/// 记住最近事件的数量，用于去重。
const MAX_RECENT: usize = 32;
const DEDUP: Duration = Duration::from_secs(600);

struct State {
    pending: VecDeque<Value>,
    recent: VecDeque<(String, Instant)>,
}

static EVENTS: Mutex<State> = Mutex::new(State {
    pending: VecDeque::new(),
    recent: VecDeque::new(),
});

/// 记录一个事件。`kind` 为 `policy_group` 或 `resource`。
pub fn push(kind: &str, title: impl Into<String>, body: impl Into<String>) {
    let (title, body) = (title.into(), body.into());
    let key = format!("{kind}\u{0}{title}\u{0}{body}");
    let now = Instant::now();
    let mut s = EVENTS.lock().unwrap();
    s.recent.retain(|(_, at)| now.duration_since(*at) < DEDUP);
    if s.recent.iter().any(|(k, _)| *k == key) {
        return;
    }
    if s.recent.len() >= MAX_RECENT {
        s.recent.pop_front();
    }
    s.recent.push_back((key, now));
    if s.pending.len() >= MAX_PENDING {
        s.pending.pop_front();
    }
    s.pending
        .push_back(json!({ "kind": kind, "title": title, "body": body }));
}

/// 取走全部待处理事件。
pub fn drain() -> Vec<Value> {
    EVENTS.lock().unwrap().pending.drain(..).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_are_dropped_and_queue_is_bounded() {
        drain();
        push("resource", "Failed", "x");
        push("resource", "Failed", "x");
        assert_eq!(drain().len(), 1);
        for i in 0..200 {
            push("resource", "n", i.to_string());
        }
        assert_eq!(drain().len(), MAX_PENDING);
    }
}
