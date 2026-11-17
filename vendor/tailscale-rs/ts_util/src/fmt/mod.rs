// 来源：https://github.com/tailscale/tailscale-rs，ts_util/src/fmt/mod.rs
// commit: f4781c480e8d1376aed89f737beefe7425e8b866；BSD-3-Clause；Copyright (c) 2026 Tailscale Inc & contributors.
// 完整许可：OrynCore/vendor/tailscale-rs/LICENSE。
//! String formatting utilities.

mod hex;
mod iter;

pub use hex::{AsHexExt, Case as HexCase, HexIter, HexdumpIter, hex_fmt};
pub use iter::IterFmt;
