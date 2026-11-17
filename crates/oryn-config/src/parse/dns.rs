//! `dns` 段：引导 DNS、上游、代理域名服务器、转发规则等。

use std::net::IpAddr;

use yaml_rust2::Yaml;

use super::{parse_cidrs, split_rule_line, Builder, PolicyRef};
use crate::domain::normalize_domain;
use crate::model::*;
use crate::yaml::{bool_of, entries, get, list_of, list_value, str_of};
use crate::{ConfigError, DomainPattern, IpCidr};

/// 解析服务器地址（不含上游组名称）。`names` 用于解析 `#代理名称` 参数。
pub(crate) fn parse_server(s: &str, b: &Builder) -> Result<ServerSpec, String> {
    let raw = s.trim().to_string();
    let (main, params) = match raw.split_once('#') {
        Some((m, p)) => (m.trim(), p.trim()),
        None => (raw.as_str(), ""),
    };
    if let Some(name) = main
        .strip_prefix("tailscale://")
        .or_else(|| main.strip_prefix("ts://"))
    {
        if name.is_empty() || !params.is_empty() {
            return Err("Tailscale DNS requires an exact outbound name without parameters".into());
        }
        let i = *b
            .names
            .get(name)
            .ok_or_else(|| format!("unknown Tailscale DNS outbound {name}"))?;
        if !matches!(b.outbounds[i].kind, OutboundKind::Tailscale(_)) {
            return Err(format!("DNS outbound {name} is not Tailscale"));
        }
        return Ok(ServerSpec {
            raw: raw.clone(),
            proto: DnsProto::Tailscale,
            host: name.into(),
            port: 53,
            path: String::new(),
            via: DnsVia::Outbound(i),
            ecs: None,
            ecs_override: false,
            skip_cert_verify: false,
            disable_ipv4: false,
            disable_ipv6: false,
        });
    }
    let (proto, rest) = match main.split_once("://") {
        Some((scheme, rest)) => {
            let proto = match scheme.to_ascii_lowercase().as_str() {
                "udp" => DnsProto::Udp,
                "tcp" => DnsProto::Tcp,
                "tls" => DnsProto::Tls,
                "https" => DnsProto::Https,
                "h3" => DnsProto::H3,
                "quic" => DnsProto::Quic,
                other => return Err(format!("unsupported DNS scheme `{other}://`")),
            };
            (proto, rest)
        }
        None => {
            if main.eq_ignore_ascii_case("system") || main.eq_ignore_ascii_case("dhcp") {
                return Err(format!("`{main}` is not supported"));
            }
            (DnsProto::Udp, main)
        }
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = split_host_port(authority)?;
    if host.is_empty() {
        return Err(format!("`{raw}` has no host"));
    }
    let is_ip = host.parse::<IpAddr>().is_ok();
    if !is_ip && !host.contains('.') {
        return Err(format!("`{raw}` has an invalid host"));
    }
    let mut spec = ServerSpec {
        raw: raw.clone(),
        proto,
        host: host.to_ascii_lowercase(),
        port: port.unwrap_or_else(|| proto.default_port()),
        path: match proto {
            DnsProto::Https | DnsProto::H3 if path.is_empty() || path == "/" => "/dns-query".into(),
            DnsProto::Https | DnsProto::H3 => path.to_string(),
            _ => String::new(),
        },
        via: DnsVia::Default,
        ecs: None,
        ecs_override: false,
        skip_cert_verify: false,
        disable_ipv4: false,
        disable_ipv6: false,
    };
    for param in params.split('&').map(str::trim).filter(|p| !p.is_empty()) {
        let (key, value) = match param.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (param, None),
        };
        let truthy = value.is_none_or(|v| v.eq_ignore_ascii_case("true") || v == "1");
        match key.to_ascii_lowercase().as_str() {
            "ecs" => {
                spec.ecs = Some(
                    value
                        .and_then(IpCidr::parse)
                        .ok_or_else(|| format!("`{raw}`: invalid ecs"))?,
                );
            }
            "ecs-override" => spec.ecs_override = truthy,
            "skip-cert-verify" => spec.skip_cert_verify = truthy,
            "h3" => {
                if truthy && spec.proto == DnsProto::Https {
                    spec.proto = DnsProto::H3;
                }
            }
            "disable-ipv4" => spec.disable_ipv4 = truthy,
            "disable-ipv6" => spec.disable_ipv6 = truthy,
            _ if value.is_none() => {
                spec.via = if param.eq_ignore_ascii_case("RULES") {
                    DnsVia::Rules
                } else if param.eq_ignore_ascii_case(TAG_DIRECT) {
                    DnsVia::Direct
                } else {
                    match b.policy(param) {
                        PolicyRef::Found(Policy::Outbound(i)) => DnsVia::Outbound(i),
                        _ => return Err(format!("`{raw}`: unknown proxy `{param}`")),
                    }
                };
            }
            _ => {}
        }
    }
    Ok(spec)
}

fn split_host_port(authority: &str) -> Result<(String, Option<u16>), String> {
    let port = |p: &str| {
        p.parse::<u16>()
            .map_err(|_| format!("invalid port in `{authority}`"))
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("invalid address `{authority}`"))?;
        let p = match after.strip_prefix(':') {
            Some(p) => Some(port(p)?),
            None if after.is_empty() => None,
            None => return Err(format!("invalid address `{authority}`")),
        };
        return Ok((host.to_string(), p));
    }
    if authority.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok((authority.to_string(), None));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), Some(port(p)?))),
        None => Ok((authority.to_string(), None)),
    }
}

struct DnsBuilder<'a> {
    b: &'a mut Builder,
    upstreams: Vec<UpstreamGroup>,
}

impl DnsBuilder<'_> {
    fn group_index(&self, name: &str) -> Option<usize> {
        self.upstreams.iter().position(|g| g.name == name)
    }

    /// 服务器列表，允许写上游组名称（展开为组内服务器）。
    fn servers(&mut self, values: &[String], what: &str) -> Vec<ServerSpec> {
        let mut out = Vec::new();
        for v in values {
            if let Some(i) = self.group_index(v) {
                out.extend(self.upstreams[i].servers.iter().cloned());
                continue;
            }
            match parse_server(v, self.b) {
                Ok(s) => out.push(s),
                Err(e) => self.b.warn(format!("dns {what}: {e}; ignored")),
            }
        }
        out
    }

    fn target(&mut self, value: &str) -> Result<ForwardTarget, String> {
        if let Some(i) = self.group_index(value) {
            return Ok(ForwardTarget::Upstream(i));
        }
        match value.to_ascii_lowercase().as_str() {
            "bootstrap" => return Ok(ForwardTarget::Bootstrap),
            "reject" => return Ok(ForwardTarget::Reject),
            _ => {}
        }
        parse_server(value, self.b).map(|s| ForwardTarget::Servers(vec![s]))
    }
}

pub(super) fn parse(root: &Yaml, b: &mut Builder) -> Result<DnsSpec, ConfigError> {
    let empty = Yaml::Hash(Default::default());
    let d = get(root, "dns").unwrap_or(&empty);
    // 私域 DNS 错误不能被当成普通兼容警告后退到公网。
    fn validate(value: &Yaml, b: &Builder) -> Result<(), ConfigError> {
        match value {
            Yaml::String(s) if s.starts_with("tailscale://") || s.starts_with("ts://") => {
                parse_server(s, b).map_err(ConfigError)?;
            }
            Yaml::Array(items) => {
                let ts = items.iter().any(|v| {
                    v.as_str()
                        .is_some_and(|s| s.starts_with("tailscale://") || s.starts_with("ts://"))
                });
                if ts && items.len() != 1 {
                    return Err(ConfigError(
                        "Tailscale DNS cannot be mixed with fallback servers".into(),
                    ));
                }
                for item in items {
                    validate(item, b)?;
                }
            }
            Yaml::Hash(entries) => {
                for (_, v) in entries {
                    validate(v, b)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    validate(d, b)?;
    if list_of(d, "default-nameserver")
        .iter()
        .any(|s| s.starts_with("ts://") || s.starts_with("tailscale://"))
    {
        return Err(ConfigError(
            "Tailscale DNS cannot be used for bootstrap".into(),
        ));
    }
    let mut db = DnsBuilder {
        b,
        upstreams: Vec::new(),
    };

    // 命名上游组（Oryn 扩展）
    if let Some(ups) = get(d, "upstreams") {
        for (name, list) in entries(ups) {
            if name.eq_ignore_ascii_case("bootstrap") || name.eq_ignore_ascii_case("reject") {
                db.b.warn(format!(
                    "dns upstream group `{name}` uses a reserved name and was ignored"
                ));
                continue;
            }
            let servers = db.servers(&list_value(list), &format!("upstream `{name}`"));
            if servers.is_empty() {
                db.b.warn(format!(
                    "dns upstream group `{name}` has no usable servers and was ignored"
                ));
                continue;
            }
            db.upstreams.push(UpstreamGroup { name, servers });
        }
    }

    // 引导 DNS：支持 UDP / TCP / DoT / DoH / DoH3 / DoQ，但服务器必须是 IP 地址（否则要先解析引导 DNS 自己的域名），
    // 且不能指定经由哪个代理（引导查询总是直连）。
    let mut bootstrap = Vec::new();
    for v in list_of(d, "default-nameserver") {
        match parse_server(&v, db.b) {
            Ok(s) if s.host_ip().is_none() => db.b.warn(format!(
                "dns default-nameserver `{v}` must use an IP address, not a domain; ignored"
            )),
            Ok(s) if !matches!(s.via, DnsVia::Default) => db.b.warn(format!(
                "dns default-nameserver `{v}` cannot choose a proxy; ignored"
            )),
            Ok(s) => bootstrap.push(s),
            Err(e) => db.b.warn(format!("dns default-nameserver: {e}; ignored")),
        }
    }
    if bootstrap.is_empty() {
        bootstrap = DEFAULT_BOOTSTRAP
            .iter()
            .map(|s| parse_server(s, db.b).expect("default"))
            .collect();
    }

    let mut nameserver = db.servers(&list_of(d, "nameserver"), "nameserver");
    if nameserver.is_empty() {
        nameserver = DEFAULT_NAMESERVER
            .iter()
            .map(|s| parse_server(s, db.b).expect("default"))
            .collect();
    }
    let proxy_server = db.servers(
        &list_of(d, "proxy-server-nameserver"),
        "proxy-server-nameserver",
    );

    let mut forward = Vec::new();
    // nameserver-policy（mihomo 写法）
    if let Some(policy) = get(d, "nameserver-policy") {
        for (key, value) in entries(policy) {
            let values = list_value(value);
            let target = if values.len() == 1 {
                db.target(&values[0])
            } else {
                let servers = db.servers(&values, &format!("nameserver-policy `{key}`"));
                if servers.is_empty() {
                    Err("no usable servers".to_string())
                } else {
                    Ok(ForwardTarget::Servers(servers))
                }
            };
            let target = match target {
                Ok(t) => t,
                Err(e) => {
                    db.b.warn(format!("dns nameserver-policy `{key}`: {e}; ignored"));
                    continue;
                }
            };
            for matcher in policy_key(&key, db.b) {
                forward.push(ForwardRule {
                    matcher,
                    target: target.clone(),
                    text: format!("{key}: {}", values.join(", ")),
                });
            }
        }
    }
    // forward-rules（Oryn 扩展，Surge 风格）
    for line in list_of(d, "forward-rules") {
        match forward_rule(&line, &mut db) {
            Ok(Some(r)) => forward.push(r),
            Ok(None) => {}
            Err(e) => {
                db.b.warn(format!("dns forward rule `{line}`: {e}; ignored"))
            }
        }
    }

    let reject_response = match str_of(d, "reject-response")
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("refused") => RejectResponse::Refused,
        Some("nxdomain") => RejectResponse::NxDomain,
        Some(other) => {
            db.b.warn(format!(
                "dns reject-response `{other}` is unknown, using refused"
            ));
            RejectResponse::Refused
        }
    };
    let blocked_ips = parse_cidrs(&list_of(d, "blocked-ips"), "dns blocked-ips", db.b);
    let public_ip_url = str_of(d, "public-ip-url")
        .filter(|u| u.starts_with("http://") || u.starts_with("https://"));

    if bool_of(d, "enable") == Some(false) {
        db.b.warn("dns enable: false is not supported; Oryn always handles DNS");
    }
    let default_fake_range = IpCidr::parse("198.18.0.0/15").expect("default Fake-IP range");
    let fake_ip_range = match str_of(d, "fake-ip-range") {
        None => default_fake_range,
        Some(raw) => match IpCidr::parse(raw.trim()).filter(|c| valid_fake_ip_range(*c)) {
            // 包含隧道网段 198.18.0.0/24 时由地址池跳过该段，不算冲突。
            Some(cidr) => cidr.network(),
            None => {
                db.b.warn("dns fake-ip-range must be an IPv4 /8–/20 network outside reserved ranges; using the default range");
                default_fake_range
            }
        },
    };
    if let Some(mode) = str_of(d, "enhanced-mode") {
        if !mode.eq_ignore_ascii_case("fake-ip") {
            db.b.warn("dns enhanced-mode is not fake-ip; using fake-ip");
        }
    }
    if get(d, "fake-ip-range6").is_some() {
        db.b.warn("dns fake-ip-range6 is ignored");
    }
    let filter_values = if get(d, "fake-ip-filter").is_some() {
        list_of(d, "fake-ip-filter")
    } else {
        DEFAULT_FAKE_IP_FILTER
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    };
    let mut fake_ip_filter = Vec::new();
    for raw in filter_values {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        if let Some((kind, name)) = value.split_once(':') {
            if kind.eq_ignore_ascii_case("rule-set") {
                match db.b.provider_names.get(name.trim()) {
                    Some(&i) if db.b.providers[i].behavior != Behavior::IpCidr => {
                        fake_ip_filter.push(FakeIpFilter::RuleSet(i))
                    }
                    _ => {
                        db.b.warn("dns fake-ip-filter references an unusable rule provider")
                    }
                }
                continue;
            }
        }
        if value.to_ascii_lowercase().starts_with("geosite:") {
            db.b.warn("dns fake-ip-filter geosite is not supported");
        } else if value == "*" {
            fake_ip_filter.push(FakeIpFilter::Glob("*".into()));
        } else if let Some(rest) = value.strip_prefix("+.") {
            if rest.contains('*') {
                fake_ip_filter.push(FakeIpFilter::Glob(format!("*.{rest}")));
            } else if let Some(pattern) = DomainPattern::parse(value) {
                fake_ip_filter.push(FakeIpFilter::Domain(pattern));
            }
        } else if let Some(pattern) = DomainPattern::parse(value) {
            fake_ip_filter.push(FakeIpFilter::Domain(pattern));
        }
    }
    let fake_ip_filter_mode = match str_of(d, "fake-ip-filter-mode")
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("blacklist") => FakeIpFilterMode::Blacklist,
        Some("whitelist") => FakeIpFilterMode::Whitelist,
        Some("rule") => {
            db.b.warn("dns fake-ip-filter-mode rule is not supported; using blacklist");
            FakeIpFilterMode::Blacklist
        }
        Some(_) => {
            db.b.warn("dns fake-ip-filter-mode is unknown; using blacklist");
            FakeIpFilterMode::Blacklist
        }
    };
    for key in [
        "listen",
        "fallback",
        "fallback-filter",
        "direct-nameserver",
        "proxy-server-nameserver-policy",
        "prefer-h3",
        "use-system-hosts",
    ] {
        if get(d, key).is_some() {
            db.b.warn(format!("dns `{key}` is not supported and was ignored"));
        }
    }

    for servers in std::iter::once(&nameserver)
        .chain(std::iter::once(&proxy_server))
        .chain(db.upstreams.iter().map(|g| &g.servers))
        .chain(forward.iter().filter_map(|r| {
            if let ForwardTarget::Servers(s) = &r.target {
                Some(s)
            } else {
                None
            }
        }))
    {
        if servers.len() != 1 && servers.iter().any(|s| s.proto == DnsProto::Tailscale) {
            return Err(ConfigError(
                "Tailscale DNS cannot be mixed with fallback servers".into(),
            ));
        }
    }
    Ok(DnsSpec {
        bootstrap,
        nameserver,
        proxy_server,
        upstreams: db.upstreams,
        forward,
        use_hosts: bool_of(d, "use-hosts").unwrap_or(true),
        ipv6: bool_of(d, "ipv6").unwrap_or(true),
        respect_rules: bool_of(d, "respect-rules").unwrap_or(true),
        skip_cert_verify: bool_of(d, "skip-cert-verify").unwrap_or(false),
        blocked_ips,
        public_ip_url,
        reject_response,
        fake_ip_range,
        fake_ip_filter,
        fake_ip_filter_mode,
    })
}

/// `nameserver-policy` 的键：域名（mihomo 写法）、`rule-set:名称`，多个用逗号分隔。
fn policy_key(key: &str, b: &mut Builder) -> Vec<ForwardMatch> {
    let mut out = Vec::new();
    let (kind, rest) = match key.split_once(':') {
        Some((k, r)) if k.eq_ignore_ascii_case("rule-set") => ("rule-set", r),
        Some((k, _)) if k.eq_ignore_ascii_case("geosite") => {
            b.warn(format!(
                "dns nameserver-policy `{key}`: geosite is not supported; ignored"
            ));
            return out;
        }
        _ => ("domain", key),
    };
    for part in rest.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if kind == "rule-set" {
            match b.provider_names.get(part) {
                Some(&i) if b.providers[i].behavior != Behavior::IpCidr => {
                    out.push(ForwardMatch::RuleSet(i))
                }
                _ => b.warn(format!(
                    "dns nameserver-policy: unusable rule provider `{part}`; ignored"
                )),
            }
        } else {
            match DomainPattern::parse(part) {
                Some(p) => out.push(ForwardMatch::Pattern(p)),
                None => b.warn(format!(
                    "dns nameserver-policy: invalid domain `{part}`; ignored"
                )),
            }
        }
    }
    out
}

fn forward_rule(line: &str, db: &mut DnsBuilder) -> Result<Option<ForwardRule>, String> {
    let (ty, value, target) = split_rule_line(line).ok_or("malformed rule")?;
    let matcher = match ty.as_str() {
        "DOMAIN" => ForwardMatch::Domain(normalize_domain(&value)),
        "DOMAIN-SUFFIX" => {
            ForwardMatch::DomainSuffix(normalize_domain(value.trim_start_matches('.')))
        }
        "DOMAIN-KEYWORD" => ForwardMatch::DomainKeyword(value.to_ascii_lowercase()),
        "DOMAIN-WILDCARD" => ForwardMatch::DomainWildcard(value.to_ascii_lowercase()),
        "DOMAIN-REGEX" => {
            regex::Regex::new(&value).map_err(|_| format!("invalid regex `{value}`"))?;
            ForwardMatch::DomainRegex(value)
        }
        "RULE-SET" => match db.b.provider_names.get(&value) {
            Some(&i) if db.b.providers[i].behavior != Behavior::IpCidr => ForwardMatch::RuleSet(i),
            Some(_) => return Err(format!("rule provider `{value}` is an ipcidr set")),
            None => return Err(format!("unknown rule provider `{value}`")),
        },
        "SSID" => ForwardMatch::Ssid(value),
        "BSSID" => ForwardMatch::Bssid(value.to_ascii_lowercase()),
        "CELLULAR" => ForwardMatch::Cellular(value),
        "MATCH" | "FINAL" => ForwardMatch::Final,
        other => return Err(format!("unsupported type `{other}`")),
    };
    let target = db.target(&target)?;
    Ok(Some(ForwardRule {
        matcher,
        target,
        text: line.to_string(),
    }))
}

/// Fake-IP 地址池：IPv4、前缀 /8–/20，且不与本网络、回环、链路本地、组播及保留段重叠。
/// 前缀上限保证地址池至少 4096 个地址；下限避免把大段真实地址当成 Fake-IP。
pub(crate) fn valid_fake_ip_range(cidr: IpCidr) -> bool {
    if !cidr.is_ipv4() || !(8..=20).contains(&cidr.prefix()) {
        return false;
    }
    let Some((start, end)) = cidr.range_v4() else { return false };
    ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"].iter().all(|r| {
        let (rs, re) = IpCidr::parse(r).and_then(|c| c.range_v4()).expect("reserved range");
        end < rs || start > re
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn builder() -> Builder {
        let mut b = Builder {
            outbounds: Vec::new(),
            names: HashMap::new(),
            ignored: HashSet::new(),
            providers: Vec::new(),
            provider_names: HashMap::new(),
            ignored_providers: HashSet::new(),
            warnings: Vec::new(),
            pending_dialers: Vec::new(),
            ..Default::default()
        };
        b.push_outbound("Proxy".into(), OutboundKind::Direct);
        b.push_outbound(TAG_DIRECT.into(), OutboundKind::Direct);
        b
    }

    #[test]
    fn fake_ip_range_validation() {
        let ok = |s: &str| valid_fake_ip_range(IpCidr::parse(s).unwrap());
        for good in ["198.18.0.0/15", "198.18.0.0/20", "10.0.0.0/8", "172.20.0.0/16", "100.64.0.0/10", "28.0.0.0/8"] {
            assert!(ok(good), "{good}");
        }
        for bad in ["0.0.0.0/0", "8.0.0.0/7", "198.19.0.0/24", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/8", "240.0.0.0/8", "fd00::/8"] {
            assert!(!ok(bad), "{bad}");
        }
    }

    #[test]
    fn server_urls() {
        let b = builder();
        let s = parse_server("1.1.1.1", &b).unwrap();
        assert_eq!(
            (s.proto, s.host.as_str(), s.port),
            (DnsProto::Udp, "1.1.1.1", 53)
        );
        let s = parse_server("[2001:db8::1]:5353", &b).unwrap();
        assert_eq!(
            (s.proto, s.host.as_str(), s.port),
            (DnsProto::Udp, "2001:db8::1", 5353)
        );
        let s = parse_server("2001:db8::1", &b).unwrap();
        assert_eq!(s.port, 53);
        let s = parse_server("tls://dns.google", &b).unwrap();
        assert_eq!((s.proto, s.port), (DnsProto::Tls, 853));
        let s = parse_server("https://doh.pub", &b).unwrap();
        assert_eq!(
            (s.proto, s.port, s.path.as_str()),
            (DnsProto::Https, 443, "/dns-query")
        );
        let s = parse_server(
            "https://8.8.8.8/resolve?x=1#h3=true&ecs=1.2.3.0/24&ecs-override=true&Proxy",
            &b,
        )
        .unwrap();
        assert_eq!(s.proto, DnsProto::H3);
        assert_eq!(s.path, "/resolve?x=1");
        assert_eq!(s.ecs, IpCidr::parse("1.2.3.0/24"));
        assert!(s.ecs_override);
        assert_eq!(s.via, DnsVia::Outbound(0));
        let s = parse_server(
            "quic://dns.adguard-dns.com#skip-cert-verify&disable-ipv6&RULES",
            &b,
        )
        .unwrap();
        assert_eq!(
            (s.proto, s.port, s.skip_cert_verify, s.disable_ipv6, s.via),
            (DnsProto::Quic, 853, true, true, DnsVia::Rules)
        );
        assert_eq!(
            parse_server("tcp://1.1.1.1#DIRECT", &b).unwrap().via,
            DnsVia::Direct
        );
        assert!(parse_server("dhcp://en0", &b).is_err());
        assert!(parse_server("system", &b).is_err());
        assert!(parse_server("1.1.1.1#Nope", &b).is_err());
        assert!(parse_server("https://localhost/dns-query", &b).is_err());
    }
}

