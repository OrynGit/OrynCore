//! 代理集合（`proxy-providers`）：内容为 mihomo 格式的 YAML（`proxies` 列表），
//! 节点在解析配置时展开为普通出站，之后由策略组的 `use` / `include-all*` 引用。

use yaml_rust2::{Yaml, YamlLoader};

use super::{fnv64, safe_relative_path, Builder, PolicyRef};
use crate::model::*;
use crate::yaml::{bool_of, entries, get, int_of, str_of};
use crate::ConfigError;

/// 单个集合的节点上限，防止异常内容耗尽内存。
pub const MAX_PROVIDER_PROXIES: usize = 10_000;
/// 单个集合最多记录的逐节点警告，其余合并为一条。
const MAX_NODE_WARNINGS: usize = 5;

pub(super) fn parse(
    root: &Yaml,
    b: &mut Builder,
    load: &dyn Fn(&str) -> Option<String>,
) -> Result<(), ConfigError> {
    let Some(map) = get(root, "proxy-providers") else {
        return Ok(());
    };
    for (name, p) in entries(map) {
        if b.proxy_provider_names.contains_key(&name) {
            return Err(ConfigError(format!("duplicate proxy provider `{name}`")));
        }
        let ty = str_of(p, "type").unwrap_or_default().to_ascii_lowercase();
        let source = match ty.as_str() {
            "http" => {
                let url = str_of(p, "url").ok_or_else(|| {
                    ConfigError(format!("proxy provider `{name}` is missing `url`"))
                })?;
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err(ConfigError(format!(
                        "proxy provider `{name}`: `url` must be http:// or https://"
                    )));
                }
                let cache_path = match str_of(p, "path") {
                    Some(path) => safe_relative_path(&path).ok_or_else(|| {
                        ConfigError(format!("proxy provider `{name}`: `path` must be a relative path inside the data directory"))
                    })?,
                    None => format!("providers/proxy-{}.yaml", fnv64(&format!("{name}\n{url}"))),
                };
                let mut headers = Vec::new();
                if let Some(h) = get(p, "header") {
                    for (key, value) in entries(h) {
                        if let Some(first) = crate::yaml::list_value(value).into_iter().next() {
                            if key.bytes().all(|c| c.is_ascii_graphic() && c != b':')
                                && !first.bytes().any(|c| c == b'\r' || c == b'\n')
                            {
                                headers.push((key, first));
                            }
                        }
                    }
                }
                ProxyProviderSource::Http {
                    url,
                    interval_secs: int_of(p, "interval").filter(|v| *v > 0).map(|v| v as u64),
                    via: ProviderVia::Rules,
                    size_limit: int_of(p, "size-limit").filter(|v| *v > 0).unwrap_or(0) as u64,
                    cache_path,
                    headers,
                }
            }
            "file" => {
                let path = str_of(p, "path")
                    .and_then(|p| safe_relative_path(&p))
                    .ok_or_else(|| {
                        ConfigError(format!("proxy provider `{name}` needs a relative `path`"))
                    })?;
                ProxyProviderSource::File { path }
            }
            "inline" => ProxyProviderSource::Inline,
            other => {
                b.warn(format!(
                    "proxy provider `{name}`: unknown type `{other}`; ignored"
                ));
                continue;
            }
        };
        let health = get(p, "health-check")
            .filter(|h| bool_of(h, "enable").unwrap_or(false))
            .map(|h| HealthSpec {
                url: str_of(h, "url").unwrap_or_else(|| DEFAULT_TEST_URL.to_string()),
                interval_secs: int_of(h, "interval").filter(|v| *v > 0).unwrap_or(300) as u64,
                timeout_ms: int_of(h, "timeout").filter(|v| *v > 0).unwrap_or(5000) as u64,
                lazy: bool_of(h, "lazy").unwrap_or(true),
            });
        let index = b.proxy_providers.len();
        b.proxy_providers.push(ProxyProviderSpec {
            name: name.clone(),
            source,
            members: Vec::new(),
            health,
            loaded: false,
            error: None,
        });
        b.proxy_provider_names.insert(name.clone(), index);
        b.pending_provider_via.push((index, str_of(p, "proxy")));

        // 内容：内联节点，或数据目录里的文件 / 缓存
        let nodes = match &b.proxy_providers[index].source {
            ProxyProviderSource::Inline => Some(Ok(Content {
                nodes: match get(p, "payload") {
                    Some(Yaml::Array(a)) => a.clone(),
                    _ => Vec::new(),
                },
                warnings: Vec::new(),
            })),
            _ => {
                let path = b.proxy_providers[index]
                    .file_path()
                    .unwrap_or_default()
                    .to_string();
                load(&path).map(|text| content(&text))
            }
        };
        match nodes {
            None => {}
            Some(Err(e)) => {
                b.warn(format!("proxy provider `{name}`: {e}"));
                b.proxy_providers[index].error = Some(e);
                b.proxy_providers[index].loaded = true;
            }
            Some(Ok(content)) => {
                b.proxy_providers[index].loaded = true;
                for w in content.warnings.iter().take(MAX_NODE_WARNINGS) {
                    b.warn(format!("proxy provider `{name}`: {w}"));
                }
                if content.warnings.len() > MAX_NODE_WARNINGS {
                    b.warn(format!(
                        "proxy provider `{name}`: {} more entries were skipped",
                        content.warnings.len() - MAX_NODE_WARNINGS
                    ));
                }
                add_nodes(p, &name, index, content.nodes, b);
            }
        }
    }
    Ok(())
}

/// 解析集合内容：mihomo YAML 的 `proxies` 列表、sing-box 配置的 `outbounds`，或分享链接订阅（逐行或整段 Base64）。
pub fn content_nodes(text: &str) -> Result<Vec<Yaml>, String> {
    content(text).map(|c| c.nodes)
}

pub struct Content {
    pub nodes: Vec<Yaml>,
    /// 链接订阅中被跳过的链接及原因。
    pub warnings: Vec<String>,
}

pub fn content(text: &str) -> Result<Content, String> {
    if let Ok(docs) = YamlLoader::load_from_str(text) {
        if let Some(Yaml::Array(a)) = docs
            .into_iter()
            .next()
            .as_ref()
            .and_then(|r| get(r, "proxies"))
        {
            return Ok(Content {
                nodes: a.clone(),
                warnings: Vec::new(),
            });
        }
    }
    match crate::singbox::parse_outbounds(text).or_else(|| crate::links::parse_subscription(text)) {
        Some(p) => Ok(Content {
            nodes: p.nodes,
            warnings: p.warnings,
        }),
        None => {
            Err("content is neither a mihomo `proxies` list, a sing-box configuration nor a share-link subscription".into())
        }
    }
}

fn regex(p: &Yaml, key: &str, provider: &str, b: &mut Builder) -> Option<regex::Regex> {
    let pattern = str_of(p, key)?;
    match regex::Regex::new(&pattern) {
        Ok(r) => Some(r),
        Err(_) => {
            b.warn(format!(
                "proxy provider `{provider}`: invalid `{key}` regex"
            ));
            None
        }
    }
}

/// 过滤、改写并把节点注册为出站。单个节点有错时跳过并警告，不影响整个配置。
fn add_nodes(p: &Yaml, provider: &str, index: usize, list: Vec<Yaml>, b: &mut Builder) {
    let filter = regex(p, "filter", provider, b);
    let exclude = regex(p, "exclude-filter", provider, b);
    let exclude_types: Vec<String> = str_of(p, "exclude-type")
        .map(|s| {
            s.split('|')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let ov = get(p, "override");
    // 前后缀保留空白（`[A] ` 之类很常见），不能用会去掉首尾空白的 str_of
    let raw = |key: &str| -> String {
        ov.and_then(|o| get(o, key))
            .and_then(crate::yaml::scalar)
            .unwrap_or_default()
    };
    let prefix = raw("additional-prefix");
    let suffix = raw("additional-suffix");
    let mut renames: Vec<(regex::Regex, String)> = Vec::new();
    if let Some(Yaml::Array(rules)) = ov.and_then(|o| get(o, "proxy-name")) {
        for r in rules {
            if let Some(pattern) = str_of(r, "pattern") {
                match regex::Regex::new(&pattern) {
                    Ok(re) => renames.push((re, str_of(r, "target").unwrap_or_default())),
                    Err(_) => b.warn(format!(
                        "proxy provider `{provider}`: invalid override proxy-name pattern"
                    )),
                }
            }
        }
    }
    // override 里的其它键直接写入每个节点
    let extra: Vec<(Yaml, Yaml)> = match ov {
        Some(Yaml::Hash(h)) => h
            .iter()
            .filter(|(k, _)| {
                !matches!(
                    k.as_str(),
                    Some("additional-prefix" | "additional-suffix" | "proxy-name")
                )
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        _ => Vec::new(),
    };

    if list.len() > MAX_PROVIDER_PROXIES {
        b.warn(format!(
            "proxy provider `{provider}`: only the first {MAX_PROVIDER_PROXIES} of {} proxies are used",
            list.len()
        ));
    }
    let mut node_warnings: Vec<String> = Vec::new();
    for node in list.into_iter().take(MAX_PROVIDER_PROXIES) {
        let Yaml::Hash(mut h) = node else {
            node_warnings.push("an entry is not a mapping".into());
            continue;
        };
        let Some(original) = h
            .get(&Yaml::String("name".into()))
            .and_then(crate::yaml::scalar)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        else {
            node_warnings.push("an entry has no name".into());
            continue;
        };
        if filter.as_ref().is_some_and(|r| !r.is_match(&original))
            || exclude.as_ref().is_some_and(|r| r.is_match(&original))
        {
            continue;
        }
        let ty = h
            .get(&Yaml::String("type".into()))
            .and_then(crate::yaml::scalar)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if exclude_types.contains(&ty) {
            continue;
        }
        let mut name = original.clone();
        for (re, target) in &renames {
            name = re.replace_all(&name, target.as_str()).into_owned();
        }
        name = format!("{prefix}{name}{suffix}");
        // 与配置里的节点、策略组或其它集合重名时加上集合名
        if b.names.contains_key(&name) || b.ignored.contains(&name) || super::is_reserved(&name) {
            let candidate = format!("{name} ({provider})");
            if b.names.contains_key(&candidate) || b.ignored.contains(&candidate) {
                node_warnings.push(format!("duplicate name `{name}` skipped"));
                continue;
            }
            name = candidate;
        }
        h.insert(Yaml::String("name".into()), Yaml::String(name.clone()));
        for (k, v) in &extra {
            h.insert(k.clone(), v.clone());
        }
        let mut wrapper = yaml_rust2::yaml::Hash::new();
        wrapper.insert(
            Yaml::String("proxies".into()),
            Yaml::Array(vec![Yaml::Hash(h)]),
        );
        let warnings_before = b.warnings.len();
        let result = super::proxies::parse(&Yaml::Hash(wrapper), b);
        node_warnings.extend(b.warnings.drain(warnings_before..));
        match result {
            Ok(()) => {
                if let Some(&i) = b.names.get(&name) {
                    b.proxy_providers[index].members.push(i);
                }
            }
            Err(e) => node_warnings.push(format!("proxy `{name}` skipped: {e}")),
        }
    }
    let total = node_warnings.len();
    for w in node_warnings.into_iter().take(MAX_NODE_WARNINGS) {
        b.warn(format!("proxy provider `{provider}`: {w}"));
    }
    if total > MAX_NODE_WARNINGS {
        b.warn(format!(
            "proxy provider `{provider}`: {} more warnings",
            total - MAX_NODE_WARNINGS
        ));
    }
}

/// 解析下载出站：没写 `proxy` 时遵循分流规则；写了就用指定的出站（`DIRECT` 为直连）。
/// 找不到时用 DIRECT 并警告。
pub(super) fn resolve_via(b: &mut Builder) {
    let direct = b.names[TAG_DIRECT];
    for (index, via) in std::mem::take(&mut b.pending_provider_via) {
        let Some(name) = via else { continue };
        let resolved = match b.policy(&name) {
            PolicyRef::Found(Policy::Outbound(i)) => i,
            _ => {
                let provider = b.proxy_providers[index].name.clone();
                b.warn(format!(
                    "proxy provider `{provider}`: unknown proxy `{name}`, downloading via DIRECT"
                ));
                direct
            }
        };
        if let ProxyProviderSource::Http { via, .. } = &mut b.proxy_providers[index].source {
            *via = ProviderVia::Outbound(resolved);
        }
    }
}
