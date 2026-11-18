//! WireGuard 客户端（可多个对端）。IP 包只存在于本 crate 内，对外只有字节流与数据报。

mod amnezia;
mod device;
mod dns;
mod engine;
mod frag;
pub mod resources;

pub use engine::{Endpoints, IoStream, Tunnel, UdpSession};
