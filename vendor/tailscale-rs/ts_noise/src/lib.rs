// 来源：https://github.com/tailscale/tailscale-rs，ts_noise/src/lib.rs
// commit: f4781c480e8d1376aed89f737beefe7425e8b866；BSD-3-Clause；Copyright (c) 2026 Tailscale Inc & contributors.
// 完整许可：OrynCore/vendor/tailscale-rs/LICENSE。
//! Implementation of the Noise protocol framework instantiations we require.
//!
//! For details on the Noise protocol framework, see <https://noiseprotocol.org/>

pub mod core;
pub mod ik;
pub mod ikpsk2;
mod messages;
