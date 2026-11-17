// 来源：https://github.com/tailscale/tailscale-rs，ts_control_noise/src/lib.rs
// commit: f4781c480e8d1376aed89f737beefe7425e8b866；BSD-3-Clause；Copyright (c) 2026 Tailscale Inc & contributors.
// 完整许可：OrynCore/vendor/tailscale-rs/LICENSE。
#![doc = include_str!("../README.md")]

mod codec;
mod error;
mod framed_io;
mod handshake;
mod messages;

pub use codec::{BiCodec, Codec, MAX_MESSAGE_SIZE, Rx, Tx};
pub use error::Error;
pub use handshake::Handshake;
pub use messages::{Header, Initiation, MessageType};
