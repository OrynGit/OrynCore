//! 部分配置热更新的 YAML 补丁合并与白名单校验。

use yaml_rust2::{yaml::Hash, Yaml, YamlEmitter, YamlLoader};

use crate::ConfigError;

/// 部分配置补丁影响的摘要。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchSummary {
    pub touched_sections: Vec<String>,
    pub touches_modules_or_mitm: bool,
    pub touched_proxy_providers: Vec<String>,
    pub replaced_proxy_providers: bool,
    pub touches_dns: bool,
}

const ALLOWED_SECTIONS: &[&str] = &[
    "mode",
    "log-level",
    "proxies",
    "proxy-providers",
    "proxy-groups",
    "rule-providers",
    "rules",
    "dns",
    "hosts",
    "sniffer",
    "geox-url",
    "geo-auto-update",
    "geo-update-interval",
    "modules",
    "mitm",
];

const HOST_SECTIONS: &[&str] = &[
    "tun",
    "port",
    "socks-port",
    "mixed-port",
    "redir-port",
    "tproxy-port",
    "allow-lan",
    "bind-address",
    "routing-mark",
    "interface-name",
    "external-controller",
    "secret",
];

const MAP_SECTIONS: &[&str] = &[
    "proxy-providers",
    "rule-providers",
    "hosts",
    "geox-url",
    "dns",
    "sniffer",
    "mitm",
];

fn parse_top_mapping(text: &str, empty_ok: bool, label: &str) -> Result<Hash, ConfigError> {
    let docs = YamlLoader::load_from_str(text)
        .map_err(|e| ConfigError(format!("invalid {label} YAML: {e}")))?;
    let root = docs.into_iter().next().unwrap_or(Yaml::Null);
    match root {
        Yaml::Null if empty_ok => Ok(Hash::new()),
        Yaml::Hash(h) => {
            if !empty_ok && h.is_empty() {
                return Err(ConfigError(format!("{label} cannot be empty")));
            }
            Ok(h)
        }
        _ => Err(ConfigError(format!(
            "the top level of {label} must be a mapping"
        ))),
    }
}

/// 将 `patch_yaml` 中的允许配置段合并到 `base_yaml` 中。
pub fn merge_config_patch(
    base_yaml: &str,
    patch_yaml: &str,
    merge_maps: bool,
) -> Result<(String, PatchSummary), ConfigError> {
    let mut base = parse_top_mapping(base_yaml, true, "base config")?;
    let patch = parse_top_mapping(patch_yaml, false, "patch")?;

    let mut validated: Vec<(String, Yaml)> = Vec::with_capacity(patch.len());
    for (k, v) in patch {
        let Yaml::String(key) = k else {
            return Err(ConfigError("patch section names must be strings".into()));
        };
        if HOST_SECTIONS.contains(&key.as_str()) {
            return Err(ConfigError(format!(
                "section `{key}` cannot be hot-patched; use apply_settings or restart"
            )));
        }
        if !ALLOWED_SECTIONS.contains(&key.as_str()) {
            return Err(ConfigError(format!("unsupported patch section `{key}`")));
        }
        if merge_maps && MAP_SECTIONS.contains(&key.as_str()) && !v.is_null() && !matches!(v, Yaml::Hash(_)) {
            return Err(ConfigError(format!("section `{key}` must be a mapping")));
        }
        validated.push((key, v));
    }

    let mut summary = PatchSummary::default();
    for (key, value) in validated {
        summary.touched_sections.push(key.clone());
        if matches!(key.as_str(), "modules" | "mitm") {
            summary.touches_modules_or_mitm = true;
        }
        if matches!(key.as_str(), "dns" | "hosts") {
            summary.touches_dns = true;
        }
        let top_key = Yaml::String(key.clone());
        if value.is_null() {
            base.remove(&top_key);
            if key == "proxy-providers" {
                summary.replaced_proxy_providers = true;
            }
            continue;
        }
        if merge_maps && MAP_SECTIONS.contains(&key.as_str()) {
            let Yaml::Hash(patch_map) = value else {
                unreachable!("validated mapping section");
            };
            let target = match base.get_mut(&top_key) {
                Some(Yaml::Hash(existing)) => existing,
                _ => {
                    base.insert(top_key.clone(), Yaml::Hash(Hash::new()));
                    let Some(Yaml::Hash(inserted)) = base.get_mut(&top_key) else {
                        unreachable!();
                    };
                    inserted
                }
            };
            for (sub_k, sub_v) in patch_map {
                if key == "proxy-providers" {
                    if let Some(name) = crate::yaml::scalar(&sub_k) {
                        if !summary.touched_proxy_providers.contains(&name) {
                            summary.touched_proxy_providers.push(name);
                        }
                    }
                }
                if sub_v.is_null() {
                    target.remove(&sub_k);
                } else {
                    target.insert(sub_k, sub_v);
                }
            }
        } else {
            if key == "proxy-providers" {
                summary.replaced_proxy_providers = true;
            }
            base.insert(top_key, value);
        }
    }

    if base.is_empty() {
        return Ok(("{}\n".to_string(), summary));
    }
    let mut out = String::new();
    let mut emitter = YamlEmitter::new(&mut out);
    emitter
        .dump(&Yaml::Hash(base))
        .map_err(|e| ConfigError(format!("failed to serialize patched config: {e}")))?;
    out.push('\n');
    Ok((out, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_config;

    #[test]
    fn merge_maps_updates_and_deletes_subkeys_and_roundtrips() {
        let base = r#"
mode: rule
rule-providers:
  a: {type: inline, behavior: domain, payload: ['+.a.test']}
  b: {type: inline, behavior: domain, payload: ['+.b.test']}
proxy-providers:
  p1: {type: inline, payload: [{name: n1, type: socks5, server: 127.0.0.1, port: 1080}]}
  p2: {type: inline, payload: [{name: n2, type: socks5, server: 127.0.0.1, port: 1081}]}
proxy-groups:
  - {name: G, type: select, use: [p1]}
rules:
  - RULE-SET,a,G
  - MATCH,DIRECT
modules:
  - format: surge
    inline: |
      #!name=multiline
      [Rule]
      DOMAIN,m.test,REJECT
"#;
        let patch = r#"
rule-providers:
  b: null
  c: {type: inline, behavior: domain, payload: ['+.c.test']}
proxy-providers:
  p2: null
rules:
  - RULE-SET,c,G
  - MATCH,DIRECT
"#;
        let (merged, summary) = merge_config_patch(base, patch, true).unwrap();
        assert_eq!(summary.touched_sections, ["rule-providers", "proxy-providers", "rules"]);
        assert!(!summary.touches_modules_or_mitm);
        assert!(!summary.replaced_proxy_providers);
        assert_eq!(summary.touched_proxy_providers, ["p2"]);
        let parsed = parse_config(&merged).unwrap();
        assert_eq!(parsed.providers.len(), 2);
        assert!(parsed.providers.iter().any(|p| p.name == "a"));
        assert!(parsed.providers.iter().any(|p| p.name == "c"));
        assert!(!parsed.providers.iter().any(|p| p.name == "b"));
        assert_eq!(parsed.proxy_providers.len(), 1);
        assert_eq!(parsed.proxy_providers[0].name, "p1");
        assert_eq!(parsed.modules.len(), 1);
        assert!(parsed.modules[0].inline.as_ref().unwrap().rules.len() == 1);
    }

    #[test]
    fn replace_mode_deletions_and_rejections() {
        let base = "mode: rule\nhosts:\n  a.test: 1.1.1.1\nrules:\n  - MATCH,DIRECT\n";
        let (merged, summary) = merge_config_patch(
            base,
            "hosts:\n  b.test: 2.2.2.2\nmode: global\n",
            false,
        )
        .unwrap();
        assert_eq!(summary.touched_sections, ["hosts", "mode"]);
        assert!(summary.touches_dns);
        let parsed = parse_config(&merged).unwrap();
        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(parsed.mode, crate::Mode::Global);

        // 顶层 null 删除整段
        let (cleared, _) = merge_config_patch(&merged, "hosts: null\n", true).unwrap();
        assert!(parse_config(&cleared).unwrap().hosts.is_empty());

        // 清空所有可删键也能输出合法空映射
        let (empty, _) = merge_config_patch("mode: rule\n", "mode: null\n", true).unwrap();
        assert!(parse_config(&empty).is_ok());

        // 拒绝宿主段、未知段、非映射、无效 YAML
        assert!(merge_config_patch(base, "tun: {enable: true}", true)
            .unwrap_err()
            .0
            .contains("cannot be hot-patched"));
        assert!(merge_config_patch(base, "port: 7890", true).is_err());
        assert!(merge_config_patch(base, "unknown-key: 1", true).is_err());
        assert!(merge_config_patch(base, "dns: [1, 2]", true).is_err());
        assert!(merge_config_patch(base, "{}", true).is_err());
        assert!(merge_config_patch(base, "not: [valid", true).is_err());
    }
}
