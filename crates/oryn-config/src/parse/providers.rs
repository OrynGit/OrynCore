use yaml_rust2::Yaml;

use super::{fnv64, safe_relative_path, Builder, PolicyRef};
use crate::model::*;
use crate::yaml::{entries, get, int_of, list_of, str_of};
use crate::ConfigError;

pub(super) fn parse(root: &Yaml, b: &mut Builder) -> Result<(), ConfigError> {
    let Some(map) = get(root, "rule-providers") else {
        return Ok(());
    };
    for (name, p) in entries(map) {
        let behavior = match str_of(p, "behavior")
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("domain") => Behavior::Domain,
            Some("ipcidr") => Behavior::IpCidr,
            Some("classical") => Behavior::Classical,
            other => {
                b.warn(format!(
                    "rule provider `{name}`: unknown behavior `{}`; ignored",
                    other.unwrap_or("")
                ));
                b.ignored_providers.insert(name);
                continue;
            }
        };
        let format = match str_of(p, "format")
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("yaml") => ProviderFormat::Yaml,
            Some("text") => ProviderFormat::Text,
            Some("mrs") => {
                b.warn(format!(
                    "rule provider `{name}`: the mrs format is not supported; ignored"
                ));
                b.ignored_providers.insert(name);
                continue;
            }
            Some(other) => {
                b.warn(format!(
                    "rule provider `{name}`: unknown format `{other}`; ignored"
                ));
                b.ignored_providers.insert(name);
                continue;
            }
        };
        let ty = str_of(p, "type").unwrap_or_default().to_ascii_lowercase();
        let source = match ty.as_str() {
            "http" => {
                let Some(url) = str_of(p, "url") else {
                    return Err(ConfigError(format!(
                        "rule provider `{name}` is missing `url`"
                    )));
                };
                let cache_path = match str_of(p, "path") {
                    Some(path) => safe_relative_path(&path).ok_or_else(|| {
                        ConfigError(format!("rule provider `{name}`: `path` must be a relative path inside the data directory"))
                    })?,
                    None => {
                        let ext = if format == ProviderFormat::Yaml { "yaml" } else { "txt" };
                        format!("providers/{}.{ext}", fnv64(&url))
                    }
                };
                // 没写 `proxy` 时遵循分流规则（与代理集合一致）；写了就用指定的出站。
                let via = match str_of(p, "proxy") {
                    None => ProviderVia::Rules,
                    Some(proxy) => match b.policy(&proxy) {
                        PolicyRef::Found(Policy::Outbound(i)) => ProviderVia::Outbound(i),
                        _ => {
                            b.warn(format!("rule provider `{name}`: unknown proxy `{proxy}`, downloading via DIRECT"));
                            ProviderVia::Outbound(b.names[TAG_DIRECT])
                        }
                    },
                };
                ProviderSource::Http {
                    url,
                    interval_secs: int_of(p, "interval").filter(|v| *v > 0).map(|v| v as u64),
                    via,
                    size_limit: int_of(p, "size-limit").filter(|v| *v > 0).unwrap_or(0) as u64,
                    cache_path,
                }
            }
            "file" => {
                let path = str_of(p, "path")
                    .and_then(|p| safe_relative_path(&p))
                    .ok_or_else(|| {
                        ConfigError(format!("rule provider `{name}` needs a relative `path`"))
                    })?;
                ProviderSource::File { path }
            }
            "inline" => ProviderSource::Inline {
                payload: list_of(p, "payload"),
            },
            other => {
                b.warn(format!(
                    "rule provider `{name}`: unknown type `{other}`; ignored"
                ));
                b.ignored_providers.insert(name);
                continue;
            }
        };
        let i = b.providers.len();
        b.providers.push(ProviderSpec {
            name: name.clone(),
            source,
            behavior,
            format,
            domain_style: DomainStyle::Mihomo,
        });
        b.provider_names.insert(name, i);
    }
    Ok(())
}
