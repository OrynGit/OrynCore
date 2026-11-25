//! Oryn Core：把 Netstack、DNS、Router、Outbound 组装成一个 Engine。
//!
//! 数据路径：`packet → Netstack → Flow → 嗅探 → Router → 策略组 → Outbound → relay`。

pub mod alloc;
#[cfg(test)]
mod hot_reload_tests;
#[cfg(test)]
mod reload_lifecycle_tests;
mod cache_compare;
#[cfg(test)]
mod connection_servers_tests;
mod admission;
mod android_package;
mod context;
mod download;
mod engine;
mod events;
mod geo;
mod health;
mod http;
mod ingest_selftest;
mod iperf;
mod local_ipv6;
mod local_proxy;
pub mod logging;
mod modules;
mod offload;
mod network_test;
mod options;
mod perf;
mod providers;
mod proxy_providers;
mod public_ip;
mod relay;
mod scripts;
mod selftest;
mod sniff;
mod synthetic;
mod stats;
mod tcp_flow;
mod utun_runtime;
#[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
mod utun_threads;
mod udp;
pub mod virtual_interface;

pub use engine::{
    run_command, Engine, EngineError, EngineHandle, OutputSink, INPUT_MAX_BATCH_BYTES,
    INPUT_MAX_BATCH_PACKETS, INPUT_MAX_PACKET_BYTES,
};
pub use options::{EngineOptions, NetworkOptions, ResourceProfile};

#[cfg(test)]
mod resource_profile_tests;

/// Core 版本号。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
