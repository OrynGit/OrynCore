//! Oryn 配置：类 mihomo 格式的 YAML，由 Core 直接解析。
//!
//! 流程：`YAML → parse → validate → resolve references → RuntimeConfig`。
//! 数据面只使用 [`RuntimeConfig`]。格式说明见 `docs/config.md`。

mod addr;
mod encryption;
pub mod links;
pub mod singbox;
pub use encryption::{EncryptionMode, EncryptionPadding, VlessEncryptionSpec};
mod cidr;
pub mod desktop;
pub mod domain;
mod mieru_pattern;
mod model;
mod smart;
pub use mieru_pattern::MieruTrafficPattern;
pub use smart::{smart_family_capable, smart_server, ServerStrategy, SmartSpec, SmartTuning};
mod parse;
mod yaml;

pub use addr::TargetAddr;
pub use cidr::IpCidr;
pub use domain::{
    glob_match, hostname_matches, listed_host_matches, normalize_domain, suffix_match,
    DomainPattern, ListedPort,
};
pub use model::*;
pub use parse::{
    parse_config, parse_config_with, parse_config_with_providers, parse_rule_body, parse_rule_item,
    proxy_provider_nodes, split_rule_line,
};
pub use parse::patch::{merge_config_patch, PatchSummary};

/// 配置错误，携带可展示给用户的说明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests;

/// Router / DNS 编译正则前用：`\d` / `\w` 换成 ASCII 类（见 `oryn_module::regex_ascii_classes`）。
pub use oryn_module::{compile_regex, regex_ascii_classes, CompactRegex};
pub use parse::modules::merge as merge_module_patches;
