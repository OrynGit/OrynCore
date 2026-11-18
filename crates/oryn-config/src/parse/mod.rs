//! 类 mihomo YAML → [`RuntimeConfig`]。
//!
//! 原则：Oryn 尚不支持的内容忽略并记录警告；真正的错误（如 YAML 语法错误、引用了不存在的名称）才返回错误。

mod dns;
mod groups;
mod mieru;
pub(crate) mod modules;
mod p3;
mod p4;
mod providers;
mod proxies;
mod proxy_providers;
mod rules;
mod sniffer;
mod sudoku_shadowquic;
mod tailscale;

use std::collections::{HashMap, HashSet};

use yaml_rust2::{Yaml, YamlLoader};

use crate::model::*;
use crate::yaml::{bool_of, get, int_of, str_of};
use crate::{ConfigError, DomainPattern, IpCidr};

pub use proxy_providers::content_nodes as proxy_provider_nodes;
pub use rules::{parse_rule_body, parse_rule_item, split_rule_line};

/// 解析过程中的共享状态。
#[derive(Default)]
pub(crate) struct Builder {
    pub outbounds: Vec<OutboundSpec>,
    pub names: HashMap<String, usize>,
    /// 因不支持而被忽略的代理 / 策略组名称。
    pub ignored: HashSet<String>,
    pub providers: Vec<ProviderSpec>,
    pub provider_names: HashMap<String, usize>,
    pub ignored_providers: HashSet<String>,
    pub warnings: Vec<String>,
    /// `dialer-proxy`：（出站下标，目标名称），等全部节点与策略组解析完再解析。
    pub pending_dialers: Vec<(usize, String)>,
    pub proxy_providers: Vec<ProxyProviderSpec>,
    pub proxy_provider_names: HashMap<String, usize>,
    /// 代理集合的下载出站名称，等策略组解析完再解析。
    pub pending_provider_via: Vec<(usize, Option<String>)>,
}

pub(crate) enum PolicyRef {
    Found(Policy),
    Ignored,
    Unknown,
}

impl Builder {
    pub fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// 解析策略名称（规则、策略组成员共用）。
    pub fn policy(&self, name: &str) -> PolicyRef {
        let upper = name.to_ascii_uppercase();
        if upper == "PASS" {
            return PolicyRef::Found(Policy::Pass);
        }
        let canonical = if upper == TAG_DIRECT || upper == "COMPATIBLE" {
            TAG_DIRECT
        } else if upper == TAG_REJECT || upper.starts_with("REJECT-") {
            TAG_REJECT
        } else {
            name
        };
        if let Some(&i) = self.names.get(canonical) {
            return PolicyRef::Found(Policy::Outbound(i));
        }
        if self.ignored.contains(name) {
            PolicyRef::Ignored
        } else {
            PolicyRef::Unknown
        }
    }

    pub fn push_outbound(&mut self, name: String, kind: OutboundKind) -> usize {
        let i = self.outbounds.len();
        self.names.insert(name.clone(), i);
        self.outbounds.push(OutboundSpec {
            name,
            kind,
            dialer: None,
        });
        i
    }
}

pub(crate) fn is_reserved(name: &str) -> bool {
    let u = name.to_ascii_uppercase();
    matches!(u.as_str(), "DIRECT" | "REJECT" | "PASS" | "COMPATIBLE") || u.starts_with("REJECT-")
}

/// 解析配置文本。代理集合只使用内联内容（`http` / `file` 集合为空）。
pub fn parse_config(text: &str) -> Result<RuntimeConfig, ConfigError> {
    parse_config_with(text, &|_| None)
}

/// 解析配置文本；`load` 按相对数据目录的路径返回代理集合的内容（`http` 的缓存或 `file` 的文件）。
pub fn parse_config_with(
    text: &str,
    load: &dyn Fn(&str) -> Option<String>,
) -> Result<RuntimeConfig, ConfigError> {
    let docs =
        YamlLoader::load_from_str(text).map_err(|e| ConfigError(format!("invalid YAML: {e}")))?;
    let root = docs.into_iter().next().unwrap_or(Yaml::Null);
    let root = match root {
        Yaml::Null => Yaml::Hash(Default::default()),
        h @ Yaml::Hash(_) => h,
        _ => {
            return Err(ConfigError(
                "the top level of the config must be a mapping".into(),
            ))
        }
    };

    let mut b = Builder::default();

    let mode = match str_of(&root, "mode") {
        Some(m) => Mode::parse(&m).unwrap_or_else(|| {
            b.warn(format!("unknown mode `{m}`, using rule"));
            Mode::Rule
        }),
        None => Mode::Rule,
    };
    let log_level = match str_of(&root, "log-level")
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("info") => "info",
        Some("silent") => "off",
        Some("error") => "error",
        Some("warning") | Some("warn") => "warn",
        Some("debug") => "debug",
        Some(other) => {
            b.warn(format!("unknown log-level `{other}`, using info"));
            "info"
        }
    }
    .to_string();

    proxies::parse(&root, &mut b)?;
    let config_proxies = b.outbounds.len();
    proxy_providers::parse(&root, &mut b, load)?;
    groups::parse(&root, &mut b, config_proxies)?;
    proxy_providers::resolve_via(&mut b);
    for key in ["sub-rules"] {
        if get(&root, key).is_some() {
            b.warn(format!("`{key}` is not supported and was ignored"));
        }
    }
    providers::parse(&root, &mut b)?;
    let rules = rules::parse(&root, &mut b)?;
    let hosts = parse_hosts(&root, &mut b);
    let dns = dns::parse(&root, &mut b)?;
    let sniffer = sniffer::parse(&root, &mut b);
    let module_specs = modules::parse(&root, &mut b);

    let geox = get(&root, "geox-url");
    let geoip = GeoIpSpec {
        url: geox
            .and_then(|g| str_of(g, "mmdb"))
            .unwrap_or_else(|| DEFAULT_MMDB_URL.to_string()),
        asn_url: geox
            .and_then(|g| str_of(g, "asn"))
            .filter(|s| !s.is_empty()),
        auto_update: bool_of(&root, "geo-auto-update").unwrap_or(false),
        interval_hours: int_of(&root, "geo-update-interval")
            .filter(|h| *h > 0)
            .unwrap_or(24) as u64,
    };

    Ok(RuntimeConfig {
        mode,
        log_level,
        outbounds: b.outbounds,
        rules,
        providers: b.providers,
        proxy_providers: b.proxy_providers,
        dns,
        hosts,
        sniffer,
        geoip,
        modules: module_specs,
        mitm: modules::mitm(&root),
        force_http_hosts: Vec::new(),
        raw_tcp_hosts: Vec::new(),
        warnings: b.warnings,
    })
}

fn parse_hosts(root: &Yaml, b: &mut Builder) -> Vec<HostEntry> {
    let mut out = Vec::new();
    let Some(hosts) = get(root, "hosts") else {
        return out;
    };
    // 每次查询按顺序匹配 hosts，条目数设上限，超出部分忽略并警告。
    const MAX_HOSTS: usize = 4096;
    for (key, value) in crate::yaml::entries(hosts) {
        if out.len() >= MAX_HOSTS {
            b.warn(format!(
                "hosts: more than {MAX_HOSTS} entries; the rest are ignored"
            ));
            break;
        }
        let Some(pattern) = DomainPattern::parse(&key) else {
            b.warn(format!("hosts: invalid domain `{key}`"));
            continue;
        };
        let values = crate::yaml::list_value(value);
        let ips: Vec<std::net::IpAddr> = values.iter().filter_map(|v| v.parse().ok()).collect();
        let value = if !ips.is_empty() && ips.len() == values.len() {
            HostValue::Ips(ips)
        } else if values.len() == 1 && ips.is_empty() {
            HostValue::Alias(crate::domain::normalize_domain(&values[0]))
        } else {
            b.warn(format!("hosts: invalid value for `{key}`"));
            continue;
        };
        out.push(HostEntry { pattern, value });
    }
    out
}

/// 端口列表：接受整数、`8000-9000`、以 `/` 或 `,` 分隔的多个值。
pub(crate) fn parse_ports(values: &[String]) -> Result<Vec<PortRange>, String> {
    let mut out = Vec::new();
    for v in values {
        for part in v.split(['/', ',']).map(str::trim).filter(|p| !p.is_empty()) {
            let parse = |p: &str| {
                p.trim()
                    .parse::<u16>()
                    .map_err(|_| format!("`{part}` is not a valid port"))
            };
            let (start, end) = match part.split_once('-') {
                Some((a, b)) => (parse(a)?, parse(b)?),
                None => {
                    let p = parse(part)?;
                    (p, p)
                }
            };
            if start > end {
                return Err(format!("port range `{part}` has start greater than end"));
            }
            out.push(PortRange { start, end });
        }
    }
    if out.is_empty() {
        return Err("empty port list".into());
    }
    Ok(out)
}

pub(crate) fn parse_cidrs(values: &[String], what: &str, b: &mut Builder) -> Vec<IpCidr> {
    let mut out = Vec::new();
    for v in values {
        match IpCidr::parse(v) {
            Some(c) => out.push(c),
            None => b.warn(format!("{what}: `{v}` is not a valid IP or CIDR")),
        }
    }
    out
}

/// 规则集缓存文件名：稳定的 FNV-1a 哈希。
pub(crate) fn fnv64(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// 相对路径检查：不允许绝对路径与 `..`。
pub(crate) fn safe_relative_path(p: &str) -> Option<String> {
    let p = p.trim().trim_start_matches("./");
    if p.is_empty() || p.starts_with('/') || p.split('/').any(|c| c == "..") {
        return None;
    }
    Some(p.to_string())
}
