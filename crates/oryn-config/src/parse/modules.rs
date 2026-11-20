use super::Builder;
use crate::model::ModuleSpec;
use crate::yaml::{bool_of, get, int_of, list_value, scalar, str_of};
use oryn_module::{parse as parse_module, ModuleFormat};
use yaml_rust2::Yaml;

pub fn parse(root: &Yaml, b: &mut Builder) -> Vec<ModuleSpec> {
    let Some(value) = get(root, "modules") else {
        return Vec::new();
    };
    let items = match value {
        Yaml::Array(items) => items,
        _ => {
            b.warn("modules must be an array");
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    if items.len() > 64 {
        b.warn("module count exceeds 64; extra modules ignored");
    }
    for (index, item) in items.iter().take(64).enumerate() {
        let mut url = str_of(item, "url");
        let inline_text = str_of(item, "inline");
        if url.is_none() && inline_text.is_none() {
            b.warn(format!("modules[{index}] requires url or inline"));
            continue;
        }
        let format = str_of(item, "format").and_then(|v| match v.to_ascii_lowercase().as_str() {
            "surge" => Some(ModuleFormat::Surge),
            "loon" => Some(ModuleFormat::Loon),
            "auto" => None,
            other => {
                b.warn(format!("modules[{index}] unknown format {other}"));
                None
            }
        });
        // Script-Hub 的本机转换地址只在其模块拦截时可用；Oryn 直接读取原始模块。
        let mut format = format;
        if let Some((source, hint)) = url.as_deref().and_then(oryn_module::script_hub_source) {
            url = Some(source);
            format = format.or(hint);
        }
        let enabled = bool_of(item, "enabled").unwrap_or(true);
        let update_interval = int_of(item, "update-interval")
            .filter(|v| *v > 0)
            .unwrap_or(86_400) as u64;
        // Egern 配置把模块参数写作 `compat_arguments`。
        let has_arguments =
            matches!(item, Yaml::Hash(h) if h.contains_key(&Yaml::String("arguments".into())));
        let arguments = map_values(
            item,
            if has_arguments {
                "arguments"
            } else {
                "compat_arguments"
            },
        );
        let policy_map = map_values(item, "policy-map");
        let env = map_values(item, "env").into_iter().collect();
        let inline = inline_text.and_then(|text| {
            let actual = format.unwrap_or_else(|| oryn_module::detect_format(&text));
            let text = match oryn_module::bind(&text, actual, &arguments) {
                Ok(bound) => {
                    for w in bound.warnings {
                        b.warn(format!("modules[{index}] argument binding: {w}"));
                    }
                    bound.text
                }
                Err(e) => {
                    b.warn(format!("modules[{index}] argument binding: {e}"));
                    return None;
                }
            };
            match parse_module(&text, Some(actual)) {
                Ok(ir) => Some(ir),
                Err(e) => {
                    b.warn(format!("modules[{index}] inline parse failed: {e}"));
                    None
                }
            }
        });
        out.push(ModuleSpec {
            url,
            format,
            enabled,
            update_interval,
            arguments,
            policy_map,
            env,
            inline,
            resources: Default::default(),
        });
    }
    out
}

/// 模块规则的策略：先查 `policy-map`，再查主配置里的策略组 / 节点 / 内置策略；
/// 主配置没有的 `PROXY` 落到 `policy-map` 的 PROXY（默认 GLOBAL）。找不到时只跳过该条规则。
/// 第二个返回值表示用了 PROXY → GLOBAL 的默认回退，调用方据此提示用户。
fn module_policy(b: &Builder, spec: &ModuleSpec, name: &str) -> Option<(String, bool)> {
    let found = |p: &str| matches!(b.policy(p), super::PolicyRef::Found(_));
    if let Some(p) = mapped_policy(spec, name).filter(|p| found(p)) {
        return Some((p, false));
    }
    if found(name) {
        return Some((name.to_owned(), false));
    }
    if !name.eq_ignore_ascii_case("PROXY") {
        return None;
    }
    match mapped_policy(spec, "PROXY") {
        Some(p) => found(&p).then_some((p, false)),
        None => found(crate::model::TAG_GLOBAL).then(|| (crate::model::TAG_GLOBAL.into(), true)),
    }
}

/// `policy-map` 里给出的映射（没有映射时为 None）。
fn mapped_policy(spec: &ModuleSpec, name: &str) -> Option<String> {
    spec.policy_map
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// `%INSERT%` / `%APPEND%` 前缀的主机列表。整行前缀作用于所有项，单项前缀只作用于该项；
/// 返回（整行是否带前缀，`(是否插到前面, 主机)` 列表）。
fn prefixed_hosts(value: &str) -> (bool, Vec<(bool, String)>) {
    fn strip(v: &str) -> (Option<bool>, &str) {
        if let Some(v) = v.strip_prefix("%INSERT%") {
            (Some(true), v)
        } else if let Some(v) = v.strip_prefix("%APPEND%") {
            (Some(false), v)
        } else {
            (None, v)
        }
    }
    let (line, rest) = strip(value.trim());
    let hosts = rest
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|item| {
            let (own, host) = strip(item);
            (own.or(line).unwrap_or(false), host.trim().to_owned())
        })
        .filter(|(_, h)| !h.is_empty())
        .collect();
    (line.is_some(), hosts)
}

/// 按 `prefixed_hosts` 的结果插到列表前面或追加到后面，保持各自的相对顺序，跳过已有项。
fn merge_hosts(target: &mut Vec<String>, hosts: Vec<(bool, String)>) {
    let mut front = vec![];
    for (insert, host) in hosts {
        if target.contains(&host) || front.contains(&host) {
            continue;
        }
        if insert {
            front.push(host);
        } else {
            target.push(host);
        }
    }
    target.splice(0..0, front);
}

/// 规则策略经 `policy-map` 映射后的名字（没有映射时原样）。
fn effective_policy(spec: &ModuleSpec, name: &str) -> String {
    mapped_policy(spec, name).unwrap_or_else(|| name.to_owned())
}

fn module_label(spec: &ModuleSpec) -> String {
    spec.url
        .clone()
        .or_else(|| spec.inline.as_ref().and_then(|m| m.meta.name.clone()))
        .unwrap_or_else(|| "inline".into())
}

fn map_values(root: &Yaml, key: &str) -> Vec<(String, String)> {
    let Some(value) = get(root, key) else {
        return Vec::new();
    };
    match value {
        Yaml::Hash(_) => crate::yaml::entries(value)
            .into_iter()
            .filter_map(|(k, v)| scalar(v).map(|s| (k, s)))
            .collect(),
        Yaml::Array(_) => list_value(value)
            .into_iter()
            .filter_map(|item| {
                item.split_once('=')
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
            .collect(),
        _ => Vec::new(),
    }
}

pub fn mitm(root: &Yaml) -> crate::MitmSpec {
    let Some(m) = get(root, "mitm") else {
        return Default::default();
    };
    crate::MitmSpec {
        enabled: bool_of(m, "enabled").unwrap_or(false),
        hostnames: crate::yaml::list_of(m, "hostnames"),
        http2: bool_of(m, "http2").unwrap_or(true),
        auto_quic_block: bool_of(m, "auto-quic-block").unwrap_or(true),
        skip_server_cert_verify: bool_of(m, "skip-server-cert-verify").unwrap_or(false),
    }
}

/// 模块规则仍交给同一个配置编译器，不能在 HTTP 数据面新增策略中心。
pub fn merge(config: &mut crate::RuntimeConfig) -> Result<(), crate::ConfigError> {
    use super::rules;
    use crate::{Policy, RuleKind};
    let mut b = Builder {
        outbounds: config.outbounds.clone(),
        names: config
            .outbounds
            .iter()
            .enumerate()
            .map(|(i, o)| (o.name.clone(), i))
            .collect(),
        ignored: Default::default(),
        providers: config.providers.clone(),
        provider_names: config
            .providers
            .iter()
            .enumerate()
            .map(|(i, p)| (p.name.clone(), i))
            .collect(),
        ignored_providers: Default::default(),
        warnings: vec![],
        pending_dialers: vec![],
        ..Default::default()
    };
    let mut surge = vec![];
    let mut loon = vec![];
    for spec in &config.modules {
        if !spec.enabled {
            continue;
        }
        let Some(m) = &spec.inline else { continue };
        config.warnings.extend(m.warnings.clone());
        let label = module_label(spec);
        let mut lines = vec![];
        let mut dropped_final = false;
        let mut proxy_fallback = false;
        for line in &m.rules {
            let Some((ty, v, policy)) = rules::split_rule_line(line) else {
                b.warn(format!("malformed module rule `{line}`"));
                continue;
            };
            // 模块不能改写主配置的兜底规则。
            if ty == "MATCH" || ty == "FINAL" {
                dropped_final = true;
                continue;
            }
            // URL-REGEX 的拒绝规则由 HTTP 检查编译为 reject 重写：它能看到每个请求（含 MITM），
            // Router 只看到明文连接的第一个请求。`policy-map` 把策略映射成拒绝时同样如此。
            if ty == "URL-REGEX"
                && oryn_module::reject_status(&effective_policy(spec, &policy)).is_some()
            {
                continue;
            }
            let Some((policy, fallback)) = module_policy(&b, spec, &policy) else {
                b.warn(format!(
                    "module rule `{line}` refers to unknown policy `{policy}`; skipped"
                ));
                continue;
            };
            proxy_fallback |= fallback;
            // 只有 no-resolve 与 src 影响匹配，其余选项与原规则解析一致地丢弃。
            let options = rules::rule_options(line)
                .into_iter()
                .rev()
                .filter(|o| o == "no-resolve" || o == "src")
                .map(|o| format!(",{o}"))
                .collect::<String>();
            lines.push(Yaml::String(format!("{ty},{v},{policy}{options}")));
        }
        if dropped_final {
            b.warn(format!(
                "module {label}: MATCH/FINAL rule ignored; the main config's final rule applies"
            ));
        }
        if proxy_fallback {
            b.warn(format!(
                "module {label}: policy PROXY is not defined; its rules use GLOBAL (set policy-map PROXY to choose)"
            ));
        }
        let mut root = yaml_rust2::yaml::Hash::new();
        root.insert(Yaml::String("rules".into()), Yaml::Array(lines));
        let added = rules::parse(&Yaml::Hash(root), &mut b)?;
        let dest = if m.format == ModuleFormat::Surge {
            &mut surge
        } else {
            &mut loon
        };
        dest.extend(
            added
                .into_iter()
                .filter(|r| !matches!(r.kind, RuleKind::Final)),
        );
        for line in &m.mitm {
            let Some((k, value)) = line.split_once('=') else {
                continue;
            };
            if k.trim().eq_ignore_ascii_case("hostname") {
                let (_, hosts) = prefixed_hosts(value);
                let hosts = hosts
                    .into_iter()
                    .filter(|(_, h)| {
                        let valid = !h.contains(['%', ' ', '/']);
                        if !valid {
                            b.warn(format!(
                                "module {label}: invalid MITM hostname `{h}` ignored"
                            ));
                        }
                        valid
                    })
                    .collect();
                merge_hosts(&mut config.mitm.hostnames, hosts);
            } else {
                b.warn(format!(
                    "module MITM field {} cannot override device CA/settings",
                    k.trim()
                ));
            }
        }
        for line in &m.general {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if key.eq_ignore_ascii_case("always-real-ip") {
                let (prefixed, hosts) = prefixed_hosts(value);
                if !prefixed {
                    b.warn(format!(
                        "module General {key} without %APPEND%/%INSERT% is appended instead of replacing the list"
                    ));
                }
                let mut front = Vec::new();
                for (insert, raw) in hosts {
                    let host = raw.trim();
                    let entry = if host == "*" {
                        Some(crate::FakeIpFilter::Glob("*".into()))
                    } else if let Some(rest) = host.strip_prefix("+.") {
                        if rest.contains('*') {
                            Some(crate::FakeIpFilter::Glob(format!("*.{rest}")))
                        } else {
                            crate::DomainPattern::parse(host).map(crate::FakeIpFilter::Domain)
                        }
                    } else {
                        crate::DomainPattern::parse(host).map(crate::FakeIpFilter::Domain)
                    };
                    let Some(entry) = entry else {
                        b.warn(format!(
                            "module {label}: invalid always-real-ip pattern `{host}` ignored"
                        ));
                        continue;
                    };
                    if config.dns.fake_ip_filter.contains(&entry) || front.contains(&entry) {
                        continue;
                    }
                    if insert {
                        front.push(entry);
                    } else {
                        config.dns.fake_ip_filter.push(entry);
                    }
                }
                config.dns.fake_ip_filter.splice(0..0, front);
                continue;
            }
            let target = match key {
                "force-http-engine-hosts" => &mut config.force_http_hosts,
                "always-raw-tcp-hosts" => &mut config.raw_tcp_hosts,
                _ => {
                    b.warn(format!("unsupported module General field {key}"));
                    continue;
                }
            };
            let (prefixed, hosts) = prefixed_hosts(value);
            // 不带前缀时也按追加处理：整体覆盖会让后加载的模块静默清掉主配置与其他模块的
            // 列表，结果依赖模块顺序。重复项去掉。
            if !prefixed {
                b.warn(format!(
                    "module General {key} without %APPEND%/%INSERT% is appended instead of replacing the list"
                ));
            }
            merge_hosts(target, hosts);
        }
        for line in &m.hosts {
            if let Some((k, v)) = line.split_once('=') {
                let Some(p) = crate::DomainPattern::parse(k.trim()) else {
                    b.warn(format!(
                        "module {label}: invalid Host pattern `{}` ignored",
                        k.trim()
                    ));
                    continue;
                };
                let trimmed = v.trim();
                if let Some(rest) = trimmed
                    .strip_prefix("server:")
                    .or_else(|| trimmed.strip_prefix("SERVER:"))
                    .or_else(|| {
                        trimmed
                            .get(..7)
                            .filter(|p| p.eq_ignore_ascii_case("server:"))
                            .map(|_| &trimmed[7..])
                    })
                {
                    let rest = rest.trim();
                    if rest.eq_ignore_ascii_case("system") {
                        config.dns.forward.insert(
                            0,
                            crate::ForwardRule {
                                matcher: crate::ForwardMatch::Pattern(p),
                                target: crate::ForwardTarget::Bootstrap,
                                text: line.clone(),
                            },
                        );
                    } else {
                        let mut servers = Vec::new();
                        for raw in rest.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                            match super::dns::parse_server(raw, &b) {
                                Ok(server) => servers.push(server),
                                Err(e) => b.warn(format!(
                                    "module {label}: invalid Host DNS server `{raw}`: {e}"
                                )),
                            }
                        }
                        if !servers.is_empty() {
                            config.dns.forward.insert(
                                0,
                                crate::ForwardRule {
                                    matcher: crate::ForwardMatch::Pattern(p),
                                    target: crate::ForwardTarget::Servers(servers),
                                    text: line.clone(),
                                },
                            );
                        }
                    }
                    continue;
                }
                {
                    let ips = v
                        .split(',')
                        .filter_map(|x| match x.trim().parse() {
                            Ok(ip) => Some(ip),
                            Err(_) => {
                                b.warn(format!(
                                    "module {label}: invalid Host IP `{}` ignored",
                                    x.trim()
                                ));
                                None
                            }
                        })
                        .collect::<Vec<_>>();
                    if !ips.is_empty() {
                        config.hosts.insert(
                            0,
                            crate::HostEntry {
                                pattern: p,
                                value: crate::HostValue::Ips(ips),
                            },
                        );
                    } else {
                        b.warn(format!(
                            "module Host value {v} requires DNS script or server mapping"
                        ));
                    }
                }
            }
        }
    }
    let final_pos = config
        .rules
        .iter()
        .position(|r| matches!(r.kind, RuleKind::Final))
        .unwrap_or(config.rules.len());
    config.rules.splice(final_pos..final_pos, loon);
    config.rules.splice(0..0, surge);
    config.providers = b.providers;
    config.warnings.extend(b.warnings);
    // 拒绝动作的 HTTP 内容由 Inspector 处理；Flow 层继续只有 Outbound。
    let _ = Policy::Pass;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_always_real_ip_and_host_server_merge_into_dns() {
        let yaml = r#"
dns:
  enable: true
  enhanced-mode: fake-ip
modules:
  - inline: |
      [General]
      always-real-ip = %APPEND% *.real.test, exact.test
      [Host]
      corp.test = server:1.1.1.1
      sys.test = server:system
"#;
        let mut cfg = crate::parse_config(yaml).unwrap();
        super::merge(&mut cfg).unwrap();
        assert!(cfg.dns.fake_ip_filter.iter().any(|f| matches!(f, crate::FakeIpFilter::Domain(p) if p.matches("a.real.test"))));
        assert!(cfg.dns.fake_ip_filter.iter().any(|f| matches!(f, crate::FakeIpFilter::Domain(p) if p.matches("exact.test"))));
        assert!(cfg.dns.forward.iter().any(|r| matches!(&r.target, crate::ForwardTarget::Servers(s) if s[0].host == "1.1.1.1")));
        assert!(cfg.dns.forward.iter().any(|r| matches!(&r.target, crate::ForwardTarget::Bootstrap)));
    }
}
