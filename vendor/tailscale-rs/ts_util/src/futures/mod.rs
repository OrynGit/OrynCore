// 来源：https://github.com/tailscale/tailscale-rs，ts_util/src/futures/mod.rs
// commit: f4781c480e8d1376aed89f737beefe7425e8b866；BSD-3-Clause；Copyright (c) 2026 Tailscale Inc & contributors.
// 完整许可：OrynCore/vendor/tailscale-rs/LICENSE。
//! Futures and async related utilities.

mod debounce;

pub use debounce::{Debounce, DebounceExt, DefaultFold};
#[cfg(feature = "tokio")]
pub use debounce::{TokioDebounce, TokioSleepFn};
