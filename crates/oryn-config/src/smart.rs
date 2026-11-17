//! Smart 的编译配置；未实现的选项拒绝而非静默忽略。
use crate::{
    yaml::{bool_of, entries, get, list_of, str_of},
    ConfigError, OutboundKind, TransportSpec,
};
use yaml_rust2::Yaml;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServerStrategy {
    #[default]
    Adaptive,
    PreferV4,
    PreferV6,
    V4Only,
    V6Only,
}
#[derive(Debug, Clone)]
pub struct NamePreference {
    pub contains: Vec<String>,
    pub regex: Option<regex::Regex>,
    pub factor: f64,
}
/// 调度参数；默认值即设计初值，范围在解析时校验。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SmartTuning {
    pub half_life_secs: f64,
    pub prior_strength: f64,
    pub min_samples: f64,
    pub min_hold_secs: u64,
    pub idle_timeout_secs: u64,
    pub switch_margin: f64,
    pub switch_confirmations: u8,
    pub fallback_delay_ms: u64,
    pub max_attempts: u8,
    pub total_timeout_secs: u64,
    pub failure_window_secs: u64,
    pub consecutive_failures: u32,
    pub open_initial_secs: u64,
    pub open_max_secs: u64,
    /// 新会话探索比例；0 关闭。
    pub explore_ratio: f64,
    pub family_v4: f64,
    pub family_v6: f64,
    pub site_prior: bool,
}
impl Default for SmartTuning {
    fn default() -> Self {
        Self {
            half_life_secs: 600.0,
            prior_strength: 20.0,
            min_samples: 20.0,
            min_hold_secs: 120,
            idle_timeout_secs: 1800,
            switch_margin: 0.15,
            switch_confirmations: 3,
            fallback_delay_ms: 250,
            max_attempts: 4,
            total_timeout_secs: 10,
            failure_window_secs: 30,
            consecutive_failures: 3,
            open_initial_secs: 30,
            open_max_secs: 600,
            explore_ratio: 0.02,
            family_v4: 1.0,
            family_v6: 1.0,
            site_prior: false,
        }
    }
}
#[derive(Debug, Clone, Default)]
pub struct SmartSpec {
    pub tuning: SmartTuning,
    pub server_strategy: ServerStrategy,
    pub require_family_control: bool,
    pub preferences: Vec<NamePreference>,
    pub services: Vec<(String, Vec<String>)>,
}
impl SmartSpec {
    pub fn factor(&self, name: &str) -> f64 {
        let name = name.to_lowercase();
        self.preferences
            .iter()
            .find(|p| {
                p.contains.iter().any(|s| name.contains(s))
                    || p.regex.as_ref().is_some_and(|r| r.is_match(&name))
            })
            .map_or(1.0, |p| p.factor)
    }
}
/// 能按服务器地址族隔离物理拨号的节点：承载连接全部经 `Dialer` 建立的 TCP 路径。
///
/// Smart 为每个地址族重新构造一份出站（独立的拨号器、连接池与复用会话），因此 gRPC / h2 / XHTTP、
/// SS 插件、smux / yamux / h2mux 复用以及 AnyTLS / Snell / Mieru(TCP) / Naive(h2) / SSH / Sudoku / SSR
/// 的内部连接池天然按路径隔离。不满足条件的节点只做节点级调度（地址族为 unknown）：
/// - 链式节点（`dialer-proxy`）：服务器地址由上一跳解析，无法限定地址族；
/// - 承载是 UDP / QUIC 的协议与传输（Hysteria / Hysteria2 / TUIC / ShadowQuic / WireGuard / Tailscale、
///   mKCP / Mekya / V2Ray QUIC、Naive(h3)、Mieru(UDP)）：不经 `Dialer`，没有可观测的承载阶段。
pub fn smart_family_capable(kind: &OutboundKind, chained: bool) -> bool {
    if chained {
        return false;
    }
    match kind {
        OutboundKind::Http { .. }
        | OutboundKind::Socks5 { .. }
        | OutboundKind::Shadowsocks { .. }
        | OutboundKind::AnyTls(_)
        | OutboundKind::Snell(_)
        | OutboundKind::Ssh(_)
        | OutboundKind::Sudoku(_)
        | OutboundKind::Ssr(_) => true,
        OutboundKind::Naive(spec) => !spec.quic,
        OutboundKind::Mieru(spec) => !spec.transport_udp,
        OutboundKind::Trojan { stream, .. }
        | OutboundKind::Vless { stream, .. }
        | OutboundKind::Vmess { stream, .. } => matches!(
            stream.transport,
            TransportSpec::Tcp
                | TransportSpec::Ws(_)
                | TransportSpec::HttpUpgrade(_)
                | TransportSpec::Http(_)
                | TransportSpec::Grpc(_)
                | TransportSpec::H2(_)
                | TransportSpec::XHttp(_)
        ),
        _ => false,
    }
}

/// 节点配置的代理服务器地址（冷启动探针只连接它）。
pub fn smart_server(kind: &OutboundKind) -> Option<&crate::TargetAddr> {
    match kind {
        OutboundKind::Http { server, .. }
        | OutboundKind::Socks5 { server, .. }
        | OutboundKind::Shadowsocks { server, .. } => Some(server),
        OutboundKind::Trojan { stream, .. }
        | OutboundKind::Vless { stream, .. }
        | OutboundKind::Vmess { stream, .. } => Some(&stream.server),
        OutboundKind::AnyTls(spec) => Some(&spec.server),
        OutboundKind::Snell(spec) => Some(&spec.server),
        OutboundKind::Naive(spec) => Some(&spec.server),
        OutboundKind::Ssh(spec) => Some(&spec.server),
        OutboundKind::Sudoku(spec) => Some(&spec.server),
        OutboundKind::Ssr(spec) => Some(&spec.server),
        OutboundKind::Mieru(spec) => Some(&spec.server),
        _ => None,
    }
}
pub(crate) fn parse(y: Option<&Yaml>) -> Result<SmartSpec, ConfigError> {
    let mut spec = SmartSpec::default();
    let Some(y) = y else { return Ok(spec) };
    if !matches!(y, Yaml::Hash(_)) {
        return Err(ConfigError("smart must be a mapping".into()));
    }
    for (k, _) in entries(y) {
        if ![
            "server-ip",
            "require-family-control",
            "preferences",
            "services",
            "affinity",
            "dial",
            "health",
            "statistics",
            "exploration",
            "family-factors",
            "site-prior",
        ]
        .contains(&k.as_str())
        {
            return Err(ConfigError(format!("unsupported smart option: {k}")));
        }
    }
    spec.server_strategy = match str_of(y, "server-ip").as_deref() {
        None | Some("adaptive") => ServerStrategy::Adaptive,
        Some("prefer_ipv4") => ServerStrategy::PreferV4,
        Some("prefer_ipv6") => ServerStrategy::PreferV6,
        Some("ipv4_only") => ServerStrategy::V4Only,
        Some("ipv6_only") => ServerStrategy::V6Only,
        _ => return Err(ConfigError("invalid smart server-ip strategy".into())),
    };
    if get(y, "require-family-control").is_some() && bool_of(y, "require-family-control").is_none()
    {
        return Err(ConfigError(
            "smart require-family-control must be boolean".into(),
        ));
    }
    spec.require_family_control = bool_of(y, "require-family-control").unwrap_or(false);
    if let Some(rules) = get(y, "preferences") {
        let Yaml::Array(rules) = rules else {
            return Err(ConfigError("smart preferences must be a list".into()));
        };
        if rules.len() > 64 {
            return Err(ConfigError("smart permits at most 64 preferences".into()));
        }
        for rule in rules {
            for (k, _) in entries(rule) {
                if !["contains_any", "regex", "factor"].contains(&k.as_str()) {
                    return Err(ConfigError(format!(
                        "unsupported smart preference option: {k}"
                    )));
                }
            }
            let factor = str_of(rule, "factor")
                .and_then(|s| s.parse::<f64>().ok())
                .filter(|v| v.is_finite() && (0.1..=5.0).contains(v))
                .ok_or_else(|| ConfigError("smart factor must be in 0.1..=5.0".into()))?;
            let contains: Vec<_> = list_of(rule, "contains_any")
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect();
            let regex = str_of(rule, "regex")
                .map(|s| {
                    regex::RegexBuilder::new(&s)
                        .case_insensitive(true)
                        .size_limit(64 * 1024)
                        .build()
                        .map_err(|_| ConfigError("invalid smart preference regex".into()))
                })
                .transpose()?;
            if contains.is_empty() == regex.is_none() {
                return Err(ConfigError(
                    "smart preference needs exactly one of contains_any or regex".into(),
                ));
            }
            spec.preferences.push(NamePreference {
                contains,
                regex,
                factor,
            });
        }
    }
    if let Some(services) = get(y, "services") {
        let Yaml::Array(services) = services else {
            return Err(ConfigError("smart services must be a list".into()));
        };
        if services.len() > 64 {
            return Err(ConfigError("smart supports at most 64 services".into()));
        }
        for service in services {
            let id = str_of(service, "id")
                .filter(|s| s.len() <= 128)
                .ok_or_else(|| ConfigError("smart service needs an id".into()))?;
            let domains = list_of(service, "domains");
            if domains.is_empty() || domains.len() > 128 || domains.iter().any(|s| s.len() > 253) {
                return Err(ConfigError(
                    "smart service needs 1..128 domain patterns".into(),
                ));
            }
            spec.services
                .push((id, domains.into_iter().map(|d| d.to_lowercase()).collect()));
        }
    }
    parse_tuning(y, &mut spec.tuning)?;
    Ok(spec)
}

fn number(
    y: &Yaml,
    section: &str,
    key: &str,
    min: f64,
    max: f64,
) -> Result<Option<f64>, ConfigError> {
    let Some(v) = get(y, key) else {
        return Ok(None);
    };
    let n = match v {
        Yaml::Integer(i) => Some(*i as f64),
        Yaml::Real(r) => r.parse::<f64>().ok(),
        _ => None,
    };
    n.filter(|n| n.is_finite() && (min..=max).contains(n))
        .map(Some)
        .ok_or_else(|| {
            ConfigError(format!(
                "smart {section}.{key} must be a number in {min}..={max}"
            ))
        })
}
fn section<'a>(y: &'a Yaml, name: &str, allowed: &[&str]) -> Result<Option<&'a Yaml>, ConfigError> {
    let Some(v) = get(y, name) else {
        return Ok(None);
    };
    if !matches!(v, Yaml::Hash(_)) {
        return Err(ConfigError(format!("smart {name} must be a mapping")));
    }
    for (k, _) in entries(v) {
        if !allowed.contains(&k.as_str()) {
            return Err(ConfigError(format!("unsupported smart {name} option: {k}")));
        }
    }
    Ok(Some(v))
}
fn parse_tuning(y: &Yaml, t: &mut SmartTuning) -> Result<(), ConfigError> {
    if let Some(a) = section(
        y,
        "affinity",
        &[
            "min-hold",
            "idle-timeout",
            "switch-margin",
            "switch-confirmations",
        ],
    )? {
        if let Some(v) = number(a, "affinity", "min-hold", 0.0, 3600.0)? {
            t.min_hold_secs = v as u64;
        }
        if let Some(v) = number(a, "affinity", "idle-timeout", 60.0, 86400.0)? {
            t.idle_timeout_secs = v as u64;
        }
        if let Some(v) = number(a, "affinity", "switch-margin", 0.0, 1.0)? {
            t.switch_margin = v;
        }
        if let Some(v) = number(a, "affinity", "switch-confirmations", 1.0, 10.0)? {
            t.switch_confirmations = v as u8;
        }
    }
    if let Some(d) = section(
        y,
        "dial",
        &["fallback-delay", "max-attempts", "total-timeout"],
    )? {
        if let Some(v) = number(d, "dial", "fallback-delay", 50.0, 2000.0)? {
            t.fallback_delay_ms = v as u64;
        }
        if let Some(v) = number(d, "dial", "max-attempts", 1.0, 8.0)? {
            t.max_attempts = v as u8;
        }
        if let Some(v) = number(d, "dial", "total-timeout", 1.0, 60.0)? {
            t.total_timeout_secs = v as u64;
        }
    }
    if let Some(h) = section(
        y,
        "health",
        &[
            "failure-window",
            "consecutive-failures",
            "open-initial",
            "open-max",
        ],
    )? {
        if let Some(v) = number(h, "health", "failure-window", 5.0, 600.0)? {
            t.failure_window_secs = v as u64;
        }
        if let Some(v) = number(h, "health", "consecutive-failures", 1.0, 20.0)? {
            t.consecutive_failures = v as u32;
        }
        if let Some(v) = number(h, "health", "open-initial", 5.0, 600.0)? {
            t.open_initial_secs = v as u64;
        }
        if let Some(v) = number(h, "health", "open-max", 5.0, 3600.0)? {
            t.open_max_secs = v as u64;
        }
    }
    if let Some(s) = section(
        y,
        "statistics",
        &["half-life", "prior-strength", "min-effective-samples"],
    )? {
        if let Some(v) = number(s, "statistics", "half-life", 10.0, 86400.0)? {
            t.half_life_secs = v;
        }
        if let Some(v) = number(s, "statistics", "prior-strength", 1.0, 200.0)? {
            t.prior_strength = v;
        }
        if let Some(v) = number(s, "statistics", "min-effective-samples", 1.0, 1000.0)? {
            t.min_samples = v;
        }
    }
    if let Some(e) = section(y, "exploration", &["new-lease-ratio"])? {
        if let Some(v) = number(e, "exploration", "new-lease-ratio", 0.0, 0.2)? {
            t.explore_ratio = v;
        }
    }
    if let Some(f) = section(y, "family-factors", &["ipv4", "ipv6"])? {
        if let Some(v) = number(f, "family-factors", "ipv4", 0.1, 5.0)? {
            t.family_v4 = v;
        }
        if let Some(v) = number(f, "family-factors", "ipv6", 0.1, 5.0)? {
            t.family_v6 = v;
        }
    }
    if get(y, "site-prior").is_some() {
        t.site_prior = bool_of(y, "site-prior")
            .ok_or_else(|| ConfigError("smart site-prior must be boolean".into()))?;
    }
    if t.open_max_secs < t.open_initial_secs {
        return Err(ConfigError(
            "smart health.open-max must be >= open-initial".into(),
        ));
    }
    if t.idle_timeout_secs < t.min_hold_secs {
        return Err(ConfigError(
            "smart affinity.idle-timeout must be >= min-hold".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn options(text: &str) -> Result<SmartSpec, ConfigError> {
        let y = yaml_rust2::YamlLoader::load_from_str(text).unwrap();
        parse(y.first())
    }
    #[test]
    fn smart_preferences_first_match_and_validation() {
        let s=options("preferences:\n - contains_any: [备用]\n   factor: 0.7\n - regex: '(?i)iepl|iplc'\n   factor: 1.25\n - contains_any: [HK]\n   factor: 1.1").unwrap();
        assert_eq!(s.factor("备用 HK IEPL"), 0.7);
        assert_eq!(s.factor("HK iepl"), 1.25);
        assert_eq!(s.factor("hk BGP"), 1.1);
        assert_eq!(s.factor("Japan"), 1.0);
        for text in [
            "preferences: [{regex: '[', factor: 1}]",
            "preferences: [{contains_any: [x], factor: 0}]",
            "server-ip: invalid",
            "unknown: true",
            "preferences: [{regex: x, contains_any: [x], factor: 1}]",
        ] {
            assert!(options(text).is_err(), "{text}");
        }
    }
    #[test]
    fn smart_tuning_parse_and_reject() {
        let s = options("affinity: {min-hold: 60, switch-margin: 0.3}\ndial: {fallback-delay: 100, max-attempts: 2}\nhealth: {open-max: 120}\nstatistics: {half-life: 300}\nexploration: {new-lease-ratio: 0}\nfamily-factors: {ipv6: 1.05}").unwrap();
        let t = s.tuning;
        assert_eq!(
            (
                t.min_hold_secs,
                t.fallback_delay_ms,
                t.max_attempts,
                t.open_max_secs
            ),
            (60, 100, 2, 120)
        );
        assert_eq!(
            (
                t.half_life_secs,
                t.explore_ratio,
                t.family_v6,
                t.switch_margin
            ),
            (300.0, 0.0, 1.05, 0.3)
        );
        assert_eq!(options("{}").unwrap().tuning, SmartTuning::default());
        for text in [
            "affinity: {min-hold: -1}",
            "affinity: {unknown: 1}",
            "dial: {max-attempts: 99}",
            "health: {open-initial: 60, open-max: 30}",
            "affinity: {min-hold: 600, idle-timeout: 100}",
            "statistics: [1]",
            "exploration: {new-lease-ratio: 0.9}",
            "family-factors: {ipv6: 0}",
            "site-prior: maybe",
        ] {
            assert!(options(text).is_err(), "{text}");
        }
    }
    #[test]
    fn smart_strict_family_control_coverage() {
        let cfg = |proxy: &str| {
            crate::parse_config(&format!(
                "proxies:\n - {proxy}\nproxy-groups:\n - {{name: S, type: smart, proxies: [n], smart: {{require-family-control: true}}}}\nrules: [MATCH,S]"
            ))
        };
        for ok in [
            "{name: n, type: ss, server: a.example, port: 1, cipher: aes-128-gcm, password: p}",
            "{name: n, type: trojan, server: a.example, port: 443, password: p, network: ws, ws-opts: {path: /}}",
            "{name: n, type: trojan, server: a.example, port: 443, password: p}",
            // 承载全部经 Dialer 的连接池 / 复用协议：按路径各建一份，天然隔离。
            "{name: n, type: trojan, server: a.example, port: 443, password: p, network: grpc, grpc-opts: {grpc-service-name: g}}",
            "{name: n, type: trojan, server: a.example, port: 443, password: p, smux: {enabled: true}}",
            "{name: n, type: ss, server: a.example, port: 1, cipher: aes-128-gcm, password: p, plugin: obfs, plugin-opts: {mode: http}}",
            "{name: n, type: anytls, server: a.example, port: 443, password: p}",
            "{name: n, type: snell, server: a.example, port: 443, psk: secret, version: 4, reuse: true}",
            "{name: n, type: naive, server: a.example, port: 443, username: u, password: p}",
        ] {
            assert!(cfg(ok).is_ok(), "{ok}: {:?}", cfg(ok).err());
        }
        for bad in [
            // 承载是 UDP / QUIC，不经 Dialer。
            "{name: n, type: hysteria2, server: a.example, port: 443, password: p}",
            "{name: n, type: trojan, server: a.example, port: 443, password: p, network: kcp}",
            // 链式节点的服务器地址由上一跳解析。
            "{name: n, type: trojan, server: a.example, port: 443, password: p, dialer-proxy: hop}",
        ] {
            assert!(cfg(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn smart_empty_group_never_falls_back_to_direct() {
        assert!(crate::parse_config(
            "proxy-groups: [{name: Smart, type: smart, proxies: []}]\nrules: [MATCH,Smart]"
        )
        .is_err());
        assert!(crate::parse_config("proxy-groups: [{name: Smart, type: smart, proxies: [DIRECT], smart: {server-ip: ipv6_only}}]").is_err());
    }
}
