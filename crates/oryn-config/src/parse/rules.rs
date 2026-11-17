//! 分流规则：`类型,值,策略[,选项]`，兼容 Surge 与 mihomo 写法。

use yaml_rust2::Yaml;

use super::{fnv64, parse_ports, Builder, PolicyRef};
use crate::domain::normalize_domain;
use crate::model::*;
use crate::yaml::{get, scalar};
use crate::{ConfigError, IpCidr};

/// 规则末尾可能出现的选项（均不影响 Oryn 的匹配）。
const OPTIONS: [&str; 6] = [
    "no-resolve",
    "src",
    "extended-matching",
    "dns-failed",
    "pre-matching",
    "no-track",
];

/// 拆分一行规则为（类型，值，策略）。`MATCH` / `FINAL` 的值为空。
///
/// 值中允许出现逗号（如 `DOMAIN-REGEX` 的 `{1,3}`）：策略总是去掉末尾选项后的最后一段。
pub fn split_rule_line(line: &str) -> Option<(String, String, String)> {
    let mut fields: Vec<&str> = line.split(',').map(str::trim).collect();
    let ty = fields.first()?.to_ascii_uppercase();
    if ty == "MATCH" || ty == "FINAL" {
        let policy = fields.get(1).filter(|p| !p.is_empty())?;
        return Some((ty, String::new(), policy.to_string()));
    }
    while fields.len() > 3 && OPTIONS.contains(&fields.last()?.to_ascii_lowercase().as_str()) {
        fields.pop();
    }
    if fields.len() < 3 {
        return None;
    }
    let policy = fields.pop()?.to_string();
    let value = fields[1..].join(",");
    if value.is_empty() || policy.is_empty() {
        return None;
    }
    Some((ty, value, policy))
}

/// 策略之后的选项（小写），即 `split_rule_line` 去掉的部分。
pub(super) fn rule_options(line: &str) -> Vec<String> {
    let mut fields: Vec<&str> = line.split(',').map(str::trim).collect();
    let mut out = Vec::new();
    while fields.len() > 3 {
        let last = fields[fields.len() - 1].to_ascii_lowercase();
        if !OPTIONS.contains(&last.as_str()) {
            break;
        }
        out.push(last);
        fields.pop();
    }
    out
}

/// 逻辑规则允许的最大嵌套层数。
const MAX_LOGIC_DEPTH: usize = 8;

/// 规则主体里的 `RULE-SET` / `DOMAIN-SET`：主规则按名称或地址找到规则集；
/// `Ok(None)` 表示此处不支持规则集（`classical` 规则集内）。
type SetLookup<'a> = dyn FnMut(&str, &str) -> Result<Option<usize>, String> + 'a;

fn no_sets(_: &str, _: &str) -> Result<Option<usize>, String> {
    Ok(None)
}

/// 解析不带策略的规则主体（分流规则与 `classical` 规则集共用）。
///
/// 返回 `Ok(None)` 表示该类型 Oryn 暂不支持；`RULE-SET` / `DOMAIN-SET` 由调用方处理。
pub fn parse_rule_body(ty: &str, value: &str) -> Result<Option<RuleKind>, String> {
    parse_body(ty, value, &mut no_sets, 0)
}

/// `classical` 规则集的一行：`类型,值[,选项…]`，没有策略。返回规则与是否 `no-resolve`。
pub fn parse_rule_item(line: &str) -> Result<Option<(RuleKind, bool)>, String> {
    Ok(parse_item(line, &mut no_sets, 0)?.map(|s| (s.kind, s.no_resolve)))
}

/// `类型,值[,选项…]`：逻辑规则的子规则与 `classical` 规则集的一行。
///
/// 与 mihomo 一致，值只取第一段（逻辑规则取到最后一个右括号），其后只认选项，其余内容忽略。
fn parse_item(line: &str, sets: &mut SetLookup, depth: usize) -> Result<Option<SubRule>, String> {
    let (ty, rest) = line.split_once(',').ok_or("malformed rule")?;
    let ty = ty.trim().to_ascii_uppercase();
    let split = if matches!(ty.as_str(), "AND" | "OR" | "NOT") {
        rest.rfind(')').map_or(rest.len(), |i| i + 1)
    } else {
        rest.find(',').unwrap_or(rest.len())
    };
    let (value, tail) = rest.split_at(split);
    let options: Vec<String> = tail
        .split(',')
        .map(|o| o.trim().to_ascii_lowercase())
        .filter(|o| OPTIONS.contains(&o.as_str()))
        .collect();
    let Some(kind) = parse_body(&ty, value, sets, depth)? else {
        return Ok(None);
    };
    Ok(Some(SubRule {
        kind: with_options(kind, &ty, &options)?,
        no_resolve: options.iter().any(|o| o == "no-resolve"),
    }))
}

/// 末尾的 `src` 让 IP / 规则集类规则改用源地址匹配；其它类型不认识它，宁可跳过也不按目的地址误判。
fn with_options(kind: RuleKind, ty: &str, options: &[String]) -> Result<RuleKind, String> {
    if !options.iter().any(|o| o == "src") {
        return Ok(kind);
    }
    match kind {
        RuleKind::IpCidr(_) | RuleKind::GeoIp(_) | RuleKind::IpAsn(_) | RuleKind::RuleSet(_) => {
            Ok(RuleKind::Src(Box::new(kind)))
        }
        RuleKind::Src(_) => Ok(kind),
        _ => Err(format!("option `src` is not supported for {ty}")),
    }
}

/// `((类型,值),(类型,值))`：最外层括号内按括号深度拆出各子规则。
fn parse_logic(
    ty: &str,
    value: &str,
    sets: &mut SetLookup,
    depth: usize,
) -> Result<RuleKind, String> {
    if depth >= MAX_LOGIC_DEPTH {
        return Err("logic rules are nested too deeply".into());
    }
    let inner = value
        .trim()
        .strip_prefix('(')
        .and_then(|v| v.strip_suffix(')'))
        .ok_or_else(|| format!("{ty} payload must be wrapped in parentheses"))?;
    let mut items = Vec::new();
    let (mut level, mut start) = (0usize, 0usize);
    for (i, c) in inner.char_indices() {
        match c {
            '(' => {
                if level == 0 {
                    start = i + 1;
                }
                level += 1;
            }
            ')' => {
                level = level.checked_sub(1).ok_or("unbalanced parentheses")?;
                if level == 0 {
                    items.push(&inner[start..i]);
                }
            }
            ',' | ' ' if level == 0 => {}
            _ if level == 0 => return Err(format!("unexpected `{c}` in {ty} payload")),
            _ => {}
        }
    }
    if level != 0 {
        return Err("unbalanced parentheses".into());
    }
    let op = match ty {
        "AND" => LogicOp::And,
        "OR" => LogicOp::Or,
        _ => LogicOp::Not,
    };
    match (op, items.len()) {
        (_, 0) => return Err(format!("{ty} has no sub-rules")),
        (LogicOp::Not, n) if n != 1 => return Err("NOT takes exactly one sub-rule".into()),
        _ => {}
    }
    let mut subs = Vec::with_capacity(items.len());
    for item in items {
        let t = item
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        if t == "MATCH" || t == "FINAL" {
            return Err(format!("{t} cannot be a sub-rule"));
        }
        match parse_item(item, sets, depth + 1)? {
            Some(s) => subs.push(s),
            None => return Err(format!("unsupported sub-rule type `{t}`")),
        }
    }
    Ok(RuleKind::Logic(op, subs))
}

fn parse_body(
    ty: &str,
    value: &str,
    sets: &mut SetLookup,
    depth: usize,
) -> Result<Option<RuleKind>, String> {
    let value = value.trim();
    let base = match ty {
        "SRC-IP-CIDR" => Some("IP-CIDR"),
        "SRC-PORT" => Some("DST-PORT"),
        "SRC-GEOIP" => Some("GEOIP"),
        "SRC-IP-ASN" => Some("IP-ASN"),
        _ => None,
    };
    if let Some(base) = base {
        return Ok(parse_body(base, value, sets, depth)?.map(|k| RuleKind::Src(Box::new(k))));
    }
    let kind = match ty {
        "AND" | "OR" | "NOT" => parse_logic(ty, value, sets, depth)?,
        "RULE-SET" | "DOMAIN-SET" => match sets(ty, value)? {
            Some(i) => RuleKind::RuleSet(i),
            None => return Ok(None),
        },
        "DOMAIN" => RuleKind::Domain(normalize_domain(value)),
        "DOMAIN-SUFFIX" => RuleKind::DomainSuffix(normalize_domain(value.trim_start_matches('.'))),
        "DOMAIN-KEYWORD" => RuleKind::DomainKeyword(value.to_ascii_lowercase()),
        "DOMAIN-WILDCARD" => RuleKind::DomainWildcard(value.to_ascii_lowercase()),
        "DOMAIN-REGEX" => {
            regex::Regex::new(value).map_err(|_| format!("invalid regex `{value}`"))?;
            RuleKind::DomainRegex(value.to_string())
        }
        "IP-CIDR" | "IP-CIDR6" => RuleKind::IpCidr(
            IpCidr::parse(value).ok_or_else(|| format!("`{value}` is not a valid CIDR"))?,
        ),
        "GEOIP" => RuleKind::GeoIp(value.to_ascii_uppercase()),
        "IP-ASN" => {
            let digits = value
                .strip_prefix("AS")
                .or_else(|| value.strip_prefix("as"))
                .unwrap_or(value);
            RuleKind::IpAsn(
                digits
                    .parse()
                    .map_err(|_| format!("`{value}` is not a valid ASN"))?,
            )
        }
        "DST-PORT" => RuleKind::DstPort(parse_ports(&[value.to_string()])?),
        "NETWORK" => match value.to_ascii_lowercase().as_str() {
            "tcp" => RuleKind::Network(NetworkKind::Tcp),
            "udp" => RuleKind::Network(NetworkKind::Udp),
            _ => return Err(format!("unknown network `{value}`")),
        },
        "PROTOCOL" => RuleKind::Protocol(match value.to_ascii_uppercase().as_str() {
            "TCP" => ProtocolKind::Tcp,
            "UDP" => ProtocolKind::Udp,
            "HTTP" => ProtocolKind::Http,
            "HTTPS" => ProtocolKind::Https,
            "QUIC" => ProtocolKind::Quic,
            _ => return Err(format!("unsupported protocol `{value}`")),
        }),
        "USER-AGENT" => RuleKind::UserAgent(value.to_string()),
        "URL-REGEX" => {
            regex::Regex::new(value).map_err(|_| format!("invalid regex `{value}`"))?;
            RuleKind::UrlRegex(value.to_string())
        }
        // 只在 Android 上编译进规则表。其它平台在 `parse` 里记一条说明后跳过。
        "PROCESS-NAME" if cfg!(target_os = "android") => {
            if value.is_empty() || value.contains('\n') {
                return Err(format!("invalid Android package `{value}`"));
            }
            RuleKind::ProcessName(value.to_string())
        }
        _ => return Ok(None),
    };
    if matches!(&kind, RuleKind::Domain(v) | RuleKind::DomainSuffix(v) | RuleKind::DomainKeyword(v) | RuleKind::DomainWildcard(v) | RuleKind::UserAgent(v) if v.is_empty())
    {
        return Err("empty value".into());
    }
    Ok(Some(kind))
}

pub(super) fn parse(root: &Yaml, b: &mut Builder) -> Result<Vec<RuleSpec>, ConfigError> {
    let mut rules = Vec::new();
    let lines: Vec<String> = match get(root, "rules") {
        Some(Yaml::Array(a)) => a.iter().filter_map(scalar).collect(),
        _ => Vec::new(),
    };
    let mut unsupported: std::collections::BTreeMap<String, usize> = Default::default();
    let mut android_packages = 0usize;
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((ty, value, policy_name)) = split_rule_line(line) else {
            b.warn(format!("rule `{line}` is malformed and was ignored"));
            continue;
        };
        let options = rule_options(line);
        let no_resolve = options.iter().any(|o| o == "no-resolve");
        let policy = match b.policy(&policy_name) {
            PolicyRef::Found(p) => p,
            PolicyRef::Ignored => {
                b.warn(format!(
                    "rule `{line}` refers to an ignored proxy or group and was skipped"
                ));
                continue;
            }
            PolicyRef::Unknown => {
                return Err(ConfigError(format!(
                    "rule `{line}` refers to unknown policy `{policy_name}`"
                )));
            }
        };
        if ty == "PROCESS-NAME" && !cfg!(target_os = "android") {
            android_packages += 1;
            continue;
        }
        let kind = match ty.as_str() {
            "MATCH" | "FINAL" => RuleKind::Final,
            "RULE-SET" | "DOMAIN-SET" => match rule_set(&ty, &value, b) {
                Some(i) => match with_options(RuleKind::RuleSet(i), &ty, &options) {
                    Ok(k) => k,
                    Err(e) => {
                        b.warn(format!("rule `{line}`: {e}; ignored"));
                        continue;
                    }
                },
                None => continue,
            },
            _ => match parse_body(
                &ty,
                &value,
                &mut |t: &str, v: &str| {
                    rule_set(t, v, b)
                        .map(Some)
                        .ok_or_else(|| format!("rule set `{v}` is unavailable"))
                },
                0,
            )
            .and_then(|k| k.map(|k| with_options(k, &ty, &options)).transpose())
            {
                Ok(Some(k)) => k,
                Ok(None) => {
                    *unsupported.entry(ty).or_default() += 1;
                    continue;
                }
                Err(e) => {
                    b.warn(format!("rule `{line}`: {e}; ignored"));
                    continue;
                }
            },
        };
        let is_final = matches!(kind, RuleKind::Final);
        if is_final && policy == Policy::Pass {
            b.warn(format!("rule `{line}`: MATCH cannot use PASS; ignored"));
            continue;
        }
        rules.push(RuleSpec {
            kind,
            policy,
            no_resolve,
            text: line.to_string(),
        });
        if is_final {
            break;
        }
    }
    if android_packages > 0 {
        b.warn(format!(
            "ignored {android_packages} PROCESS-NAME rules: Android package routing is not supported on iOS"
        ));
    }
    if !unsupported.is_empty() {
        let detail: Vec<String> = unsupported
            .iter()
            .map(|(t, n)| format!("{t}: {n}"))
            .collect();
        b.warn(format!(
            "ignored rules with unsupported types ({})",
            detail.join(", ")
        ));
    }
    if !matches!(rules.last().map(|r| &r.kind), Some(RuleKind::Final)) {
        let direct = b.names[TAG_DIRECT];
        rules.push(RuleSpec {
            kind: RuleKind::Final,
            policy: Policy::Outbound(direct),
            no_resolve: false,
            text: "MATCH,DIRECT".into(),
        });
    }
    Ok(rules)
}

/// `RULE-SET,名称` 引用 rule-providers；`RULE-SET,https://…` / `DOMAIN-SET,https://…` 为 Surge 写法，自动生成规则集。
fn rule_set(ty: &str, value: &str, b: &mut Builder) -> Option<usize> {
    let is_url = value.starts_with("http://") || value.starts_with("https://");
    if !is_url {
        if ty == "DOMAIN-SET" {
            b.warn(format!("DOMAIN-SET `{value}` must be a URL; ignored"));
            return None;
        }
        if let Some(&i) = b.provider_names.get(value) {
            return Some(i);
        }
        if b.ignored_providers.contains(value) {
            b.warn(format!(
                "rule refers to ignored rule provider `{value}` and was skipped"
            ));
        } else {
            b.warn(format!(
                "rule refers to unknown rule provider `{value}` and was skipped"
            ));
        }
        return None;
    }
    let key = format!("{ty}:{value}");
    if let Some(&i) = b.provider_names.get(&key) {
        return Some(i);
    }
    let (behavior, style, ext) = if ty == "DOMAIN-SET" {
        (Behavior::Domain, DomainStyle::Surge, "txt")
    } else {
        (Behavior::Classical, DomainStyle::Mihomo, "list")
    };
    let i = b.providers.len();
    b.providers.push(ProviderSpec {
        name: key.clone(),
        source: ProviderSource::Http {
            url: value.to_string(),
            interval_secs: Some(86400),
            via: ProviderVia::Rules,
            size_limit: 0,
            cache_path: format!("providers/{}.{ext}", fnv64(value)),
        },
        behavior,
        format: ProviderFormat::Text,
        domain_style: style,
    });
    b.provider_names.insert(key, i);
    Some(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_lines() {
        assert_eq!(
            split_rule_line("DOMAIN-SUFFIX, google.com ,Proxy"),
            Some(("DOMAIN-SUFFIX".into(), "google.com".into(), "Proxy".into()))
        );
        assert_eq!(
            split_rule_line("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"),
            Some(("IP-CIDR".into(), "10.0.0.0/8".into(), "DIRECT".into()))
        );
        assert_eq!(
            split_rule_line("DOMAIN-REGEX,^a{1,3}\\.com$,Proxy"),
            Some((
                "DOMAIN-REGEX".into(),
                "^a{1,3}\\.com$".into(),
                "Proxy".into()
            ))
        );
        assert_eq!(
            split_rule_line("match,Proxy"),
            Some(("MATCH".into(), String::new(), "Proxy".into()))
        );
        assert_eq!(
            split_rule_line("FINAL,DIRECT,dns-failed"),
            Some(("FINAL".into(), String::new(), "DIRECT".into()))
        );
        assert_eq!(split_rule_line("DOMAIN,a.com"), None);
    }

    #[test]
    fn bodies() {
        assert!(
            matches!(parse_rule_body("DST-PORT", "80/443/8000-9000"), Ok(Some(RuleKind::DstPort(p))) if p.len() == 3)
        );
        assert!(
            matches!(parse_rule_body("GEOIP", "cn"), Ok(Some(RuleKind::GeoIp(c))) if c == "CN")
        );
        assert!(matches!(
            parse_rule_body("IP-ASN", "4134"),
            Ok(Some(RuleKind::IpAsn(4134)))
        ));
        assert!(matches!(
            parse_rule_body("IP-ASN", "AS4837"),
            Ok(Some(RuleKind::IpAsn(4837)))
        ));
        assert!(parse_rule_body("IP-ASN", "x").is_err());
        assert!(
            matches!(parse_rule_body("DOMAIN-SUFFIX", ".Apple.com"), Ok(Some(RuleKind::DomainSuffix(d))) if d == "apple.com")
        );
        assert!(parse_rule_body("DOMAIN-REGEX", "(").is_err());
        assert!(matches!(parse_rule_body("PROCESS-NAME", "curl"), Ok(None)));
        assert!(parse_rule_body("NETWORK", "icmp").is_err());
    }

    #[test]
    fn logic_and_src() {
        let and = parse_rule_body(
            "AND",
            "((DOMAIN,a.com),(NETWORK,UDP),(IP-CIDR,1.0.0.0/8,no-resolve))",
        );
        let Ok(Some(RuleKind::Logic(LogicOp::And, subs))) = and else {
            panic!("{and:?}")
        };
        assert_eq!(subs.len(), 3);
        assert!(subs[2].no_resolve && !subs[0].no_resolve);
        // 嵌套、NOT、空格
        let nested = parse_rule_body(
            "OR",
            "( (NOT,((DST-PORT,443))) , (AND,((SRC-IP-CIDR,192.168.0.0/16),(GEOIP,CN))) )",
        );
        let Ok(Some(RuleKind::Logic(LogicOp::Or, subs))) = nested else {
            panic!("{nested:?}")
        };
        assert!(matches!(&subs[0].kind, RuleKind::Logic(LogicOp::Not, n) if n.len() == 1));
        assert!(
            matches!(&subs[1].kind, RuleKind::Logic(LogicOp::And, a) if matches!(&a[0].kind, RuleKind::Src(k) if matches!(**k, RuleKind::IpCidr(_))))
        );
        assert!(parse_rule_body("NOT", "((DOMAIN,a),(DOMAIN,b))").is_err());
        assert!(parse_rule_body("AND", "(DOMAIN,a)").is_err());
        assert!(parse_rule_body("AND", "((DOMAIN,a),(PROCESS-NAME,x))").is_err());
        assert!(parse_rule_body("AND", "((DOMAIN,a),(MATCH,))").is_err());
        assert!(parse_rule_body("AND", "((DOMAIN,a)").is_err());
        assert!(parse_rule_body("AND", "((RULE-SET,x))").is_err());
        let deep = format!("{}(DOMAIN,a){}", "(NOT,(".repeat(9), "))".repeat(9));
        assert!(parse_rule_body("NOT", &format!("({deep})")).is_err());

        assert!(
            matches!(parse_rule_body("SRC-PORT", "5000"), Ok(Some(RuleKind::Src(k))) if matches!(*k, RuleKind::DstPort(_)))
        );
        assert!(
            matches!(parse_rule_body("SRC-IP-ASN", "AS1"), Ok(Some(RuleKind::Src(k))) if matches!(*k, RuleKind::IpAsn(1)))
        );
        assert!(matches!(
            parse_rule_item("IP-CIDR,10.0.0.0/8,src"),
            Ok(Some((RuleKind::Src(_), false)))
        ));
        assert!(matches!(
            parse_rule_item("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"),
            Ok(Some((RuleKind::IpCidr(_), true)))
        ));
        assert!(parse_rule_item("DOMAIN,a.com,src").is_err());
        assert!(matches!(
            parse_rule_item("AND,((DOMAIN,a.com),(NETWORK,TCP))"),
            Ok(Some((RuleKind::Logic(LogicOp::And, _), false)))
        ));
    }

    #[test]
    fn rule_lines_with_logic_and_src() {
        let yaml = r#"
proxies: [{name: P, type: socks5, server: 1.2.3.4, port: 1080}]
rule-providers:
  lan: {type: inline, behavior: ipcidr, payload: ['192.168.0.0/16']}
rules:
  - AND,((NETWORK,UDP),(DST-PORT,443),(IP-CIDR,1.0.0.0/8,no-resolve)),REJECT
  - OR,((RULE-SET,lan),(DOMAIN,a.com)),DIRECT
  - RULE-SET,lan,P,src
  - IP-CIDR,10.0.0.0/8,DIRECT,src,no-resolve
  - DOMAIN,b.com,P,src
  - AND,((DOMAIN,c.com),(RULE-SET,missing)),P
  - MATCH,P
"#;
        let c = crate::parse_config(yaml).unwrap();
        assert_eq!(c.rules.len(), 5, "{:?}", c.warnings);
        // 子规则的 no-resolve 不算整条规则的选项
        assert!(
            matches!(c.rules[0].kind, RuleKind::Logic(LogicOp::And, _)) && !c.rules[0].no_resolve
        );
        assert!(
            matches!(&c.rules[1].kind, RuleKind::Logic(LogicOp::Or, s) if matches!(s[0].kind, RuleKind::RuleSet(0)))
        );
        assert!(
            matches!(&c.rules[2].kind, RuleKind::Src(k) if matches!(**k, RuleKind::RuleSet(0)))
        );
        assert!(matches!(&c.rules[3].kind, RuleKind::Src(k) if matches!(**k, RuleKind::IpCidr(_))));
        assert!(c
            .warnings
            .iter()
            .any(|w| w.contains("b.com") && w.contains("src")));
        assert!(c.warnings.iter().any(|w| w.contains("missing")));
    }
}
