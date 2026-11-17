// 来源：https://github.com/tailscale/tailscale-rs，ts_util/src/lib.rs
// commit: f4781c480e8d1376aed89f737beefe7425e8b866；BSD-3-Clause；Copyright (c) 2026 Tailscale Inc & contributors.
// 完整许可：OrynCore/vendor/tailscale-rs/LICENSE。
#![doc = include_str!("../README.md")]
#![no_std]

// Before adding something to this crate, please see the note in the README. In short, does it
// REALLY need to go here?

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod fmt;
pub mod fn_;
#[cfg(feature = "futures")]
pub mod futures;
