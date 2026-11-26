//! Egern YAML 模块解析与参数绑定，转换为统一的 [`ModuleIR`]（Surge 方言）。
use crate::{ArgumentDef, Bound, ModuleFormat, ModuleIR, ModuleSource, ParseError, RewriteRule, ScriptDecl, MAX_MODULE_BYTES};
use std::collections::{BTreeMap, BTreeSet};
use yaml_rust2::{Yaml, YamlLoader};

const TOP_LEVEL_KEYS: &[&str] = &[
    "name",
    "description",
    "author",
    "homepage",
    "icon",
    "open_url",
    "compat_arguments",
    "compat_arguments_desc",
    "mitm",
    "rules",
    "rule_sets",
    "body_rewrites",
    "url_rewrites",
    "header_rewrites",
    "map_locals",
    "scriptings",
    "dns",
    "hosts",
    "dns_rewrites",
];

/// 判断文本是否为 Egern YAML 模块（与 Surge / Loon INI 区分）。
pub fn is_egern_yaml(text: &str) -> bool {
    let text = text.trim_start_matches('\u{feff}');
    // 含 `#!` 元数据头或标准 Surge/Loon INI section 的按 INI 解析。
    for raw in text.lines() {
        let s = raw.trim();
        if s.starts_with("#!") {
            return false;
        }
        if let Some(sec) = s.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let lower = sec.trim().to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "general"
                    | "rule"
                    | "host"
                    | "mitm"
                    | "script"
                    | "rewrite"
                    | "url rewrite"
                    | "header rewrite"
                    | "body rewrite"
                    | "map local"
                    | "argument"
            ) {
                return false;
            }
        }
    }
    let Some(first) = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
    else {
        return false;
    };
    if first == "---" {
        return true;
    }
    first.split_once(':').is_some_and(|(key, value)| {
        let key = key.trim();
        TOP_LEVEL_KEYS.contains(&key) && (value.is_empty() || value.starts_with(char::is_whitespace))
    })
}

/// 把未加引号的 YAML 占位符 `key: {{{arg}}}` 临时包成字符串，供未绑定模板解析 `compat_arguments`。
fn quote_bare_placeholders(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 32);
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || !line.contains("{{{") {
            out.push_str(line);
            continue;
        }
        let body = line.trim_end_matches(['\r', '\n']);
        let eol = &line[body.len()..];
        if let Some((prefix, raw_val)) = body.split_once(':') {
            let ws_len = raw_val.len() - raw_val.trim_start().len();
            let val = raw_val[ws_len..].trim_end();
            if val.starts_with("{{{") && val.ends_with("}}}") {
                out.push_str(prefix);
                out.push(':');
                out.push_str(&raw_val[..ws_len]);
                out.push('"');
                out.push_str(val);
                out.push('"');
                out.push_str(eol);
                continue;
            }
        }
        out.push_str(line);
    }
    out
}

fn load_yaml(text: &str) -> Result<Yaml, ParseError> {
    let clean = text.trim_start_matches('\u{feff}');
    let docs = match YamlLoader::load_from_str(clean) {
        Ok(docs) => docs,
        Err(first_err) if clean.contains("{{{") => {
            YamlLoader::load_from_str(&quote_bare_placeholders(clean))
                .map_err(|_| ParseError(format!("invalid Egern YAML module: {first_err}")))?
        }
        Err(e) => return Err(ParseError(format!("invalid Egern YAML module: {e}"))),
    };
    docs.into_iter()
        .next()
        .ok_or_else(|| ParseError("empty Egern YAML module".into()))
}

fn get<'a>(node: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    match node {
        Yaml::Hash(map) => map.get(&Yaml::String(key.into())),
        _ => None,
    }
}

fn scalar_str(node: &Yaml) -> Option<String> {
    match node {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Real(r) => Some(r.clone()),
        Yaml::Boolean(b) => Some(if *b { "true" } else { "false" }.into()),
        _ => None,
    }
}

fn str_of(node: &Yaml, key: &str) -> Option<String> {
    get(node, key).and_then(scalar_str)
}

fn bool_of(node: &Yaml, key: &str) -> Option<bool> {
    match get(node, key)? {
        Yaml::Boolean(b) => Some(*b),
        Yaml::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn double_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `[Body Rewrite]` 里的正则项不走 `unquote`，需要避免空格/制表符与前导引号破坏分词。
fn safe_body_regex(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    for (i, c) in pattern.chars().enumerate() {
        match c {
            ' ' => out.push_str("\\x20"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '"' if i == 0 => out.push_str("\\x22"),
            '\'' if i == 0 => out.push_str("\\x27"),
            '`' if i == 0 => out.push_str("\\x60"),
            c => out.push(c),
        }
    }
    out
}

/// 去掉 YAML 注释（仅引号外且前置空白的 `#`）。
fn strip_yaml_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escape = false;
    let mut prev_space = true;
    for (i, c) in line.char_indices() {
        if let Some(q) = quote {
            if escape {
                escape = false;
            } else if c == '\\' && q == '"' {
                escape = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        if matches!(c, '"' | '\'') {
            quote = Some(c);
            prev_space = false;
            continue;
        }
        if prev_space && c == '#' {
            return line[..i].trim_end();
        }
        prev_space = c.is_whitespace();
    }
    line
}

pub fn bind_yaml(text: &str, args: &[(String, String)]) -> Result<Bound, ParseError> {
    let ir = parse_yaml(text, "module")?;
    let mut warnings = Vec::new();
    for (k, _) in args {
        if !ir.arguments.iter().any(|a| &a.name == k) {
            warnings.push(format!("argument {k} is not declared by the module; ignored"));
        }
    }
    let values: BTreeMap<_, _> = ir
        .arguments
        .iter()
        .map(|a| {
            let v = args
                .iter()
                .find(|(k, _)| k == &a.name)
                .map(|(_, v)| v.clone())
                .or_else(|| a.default.clone());
            (a.name.clone(), v)
        })
        .collect();
    let mut out = String::with_capacity(text.len());
    let mut empty = BTreeSet::new();
    let mut skip_block_indent: Option<usize> = None;
    for line in text.split_inclusive('\n') {
        let trimmed_start = line.trim_start();
        let indent = line.len() - trimmed_start.len();
        if let Some(base) = skip_block_indent {
            if !trimmed_start.is_empty() && !trimmed_start.starts_with('#') && indent <= base {
                skip_block_indent = None;
            } else {
                out.push_str(line);
                continue;
            }
        }
        if trimmed_start.starts_with('#') {
            out.push_str(line);
            continue;
        }
        if let Some((k, v)) = trimmed_start.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if matches!(k, "compat_arguments_desc" | "description")
                && (v.starts_with('|') || v.starts_with('>'))
            {
                skip_block_indent = Some(indent);
                out.push_str(line);
                continue;
            }
        }
        let body = line.trim_end_matches(['\r', '\n']);
        let active = strip_yaml_comment(body);
        let suffix = &line[active.len()..];
        let mut rest = active;
        while let Some(i) = rest.find("{{{") {
            out.push_str(&rest[..i]);
            rest = &rest[i + 3..];
            let Some(end) = rest.find("}}}") else {
                return Err(ParseError("unterminated module argument".into()));
            };
            let name = &rest[..end];
            let Some(value) = values.get(name) else {
                return Err(ParseError(format!("undeclared argument {name}")));
            };
            let value = match value {
                Some(v) => v.as_str(),
                None => {
                    if empty.insert(name.to_owned()) {
                        warnings.push(format!(
                            "argument {name} has no value or default; replaced with empty text"
                        ));
                    }
                    ""
                }
            };
            if value.contains(['\r', '\n']) {
                return Err(ParseError("argument must not contain line breaks".into()));
            }
            out.push_str(value);
            rest = &rest[end + 3..];
        }
        out.push_str(rest);
        out.push_str(suffix);
    }
    if out.len() > MAX_MODULE_BYTES {
        return Err(ParseError("expanded module too large".into()));
    }
    Ok(Bound { text: out, warnings })
}

pub fn parse_yaml(text: &str, name: &str) -> Result<ModuleIR, ParseError> {
    let root = load_yaml(text)?;
    let Yaml::Hash(top) = &root else {
        return Err(ParseError("Egern YAML module root must be a mapping".into()));
    };
    let mut out = ModuleIR {
        format: ModuleFormat::Surge,
        meta: Default::default(),
        arguments: Vec::new(),
        general: Vec::new(),
        rules: Vec::new(),
        hosts: Vec::new(),
        rewrites: Vec::new(),
        scripts: Vec::new(),
        mitm: Vec::new(),
        raw_sections: Default::default(),
        warnings: Vec::new(),
    };
    let src = |line: usize| ModuleSource {
        name: name.into(),
        line,
    };

    out.meta.name = str_of(&root, "name");
    out.meta.description = str_of(&root, "description");
    out.meta.author = str_of(&root, "author");
    out.meta.homepage = str_of(&root, "homepage");
    out.meta.icon = str_of(&root, "icon");
    out.meta.arguments_desc = str_of(&root, "compat_arguments_desc");
    for (k, v) in top {
        if let (Some(ks), Some(vs)) = (scalar_str(k), scalar_str(v)) {
            out.meta.raw.insert(ks.to_ascii_lowercase(), vs);
        }
    }

    // compat_arguments
    if let Some(Yaml::Hash(args_map)) = get(&root, "compat_arguments") {
        for (idx, (k, v)) in args_map.iter().enumerate() {
            let Some(arg_name) = scalar_str(k) else {
                continue;
            };
            let is_bool = matches!(v, Yaml::Boolean(_));
            let default = scalar_str(v);
            out.arguments.push(ArgumentDef {
                name: arg_name.clone(),
                kind: if is_bool { "switch" } else { "input" }.into(),
                default: default.clone(),
                options: Vec::new(),
                typed: None,
                tag: None,
                desc: None,
                raw: format!("{arg_name}:{}", default.as_deref().unwrap_or("")),
                source: src(idx + 1),
            });
        }
    }

    // mitm
    if let Some(mitm) = get(&root, "mitm") {
        let mut hosts = Vec::new();
        if let Some(hostnames) = get(mitm, "hostnames") {
            match hostnames {
                Yaml::Array(items) => {
                    for h in items {
                        if let Some(s) = scalar_str(h) {
                            let s = s.trim();
                            if !s.is_empty() {
                                hosts.push(s.to_owned());
                            }
                        }
                    }
                }
                Yaml::Hash(_) => {
                    if let Some(Yaml::Array(inc)) = get(hostnames, "includes") {
                        for h in inc {
                            if let Some(s) = scalar_str(h) {
                                let s = s.trim();
                                if !s.is_empty() {
                                    hosts.push(s.to_owned());
                                }
                            }
                        }
                    }
                    if let Some(Yaml::Array(exc)) = get(hostnames, "excludes") {
                        for h in exc {
                            if let Some(s) = scalar_str(h) {
                                let s = s.trim();
                                if !s.is_empty() {
                                    hosts.push(if s.starts_with('-') {
                                        s.to_owned()
                                    } else {
                                        format!("-{s}")
                                    });
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if !hosts.is_empty() {
            out.mitm.push(format!("hostname = %APPEND% {}", hosts.join(", ")));
        }
    }

    // hosts
    if let Some(Yaml::Hash(hosts_map)) = get(&root, "hosts") {
        for (k, v) in hosts_map {
            if let (Some(domain), Some(val)) = (scalar_str(k), scalar_str(v)) {
                out.hosts.push(format!("{domain} = {val}"));
            }
        }
    }

    // rules
    if let Some(Yaml::Array(rules)) = get(&root, "rules") {
        for item in rules {
            match item {
                Yaml::String(line) => {
                    let line = line.trim();
                    if !line.is_empty() {
                        out.rules.push(line.to_owned());
                    }
                }
                Yaml::Hash(map) => {
                    for (k, v) in map {
                        let Some(rule_kind) = scalar_str(k) else {
                            continue;
                        };
                        if let Some(line) = egern_rule(&rule_kind, v) {
                            out.rules.push(line);
                        } else {
                            out.warnings.push(format!(
                                "{name}: unsupported Egern rule type `{rule_kind}` ignored"
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // body_rewrites
    if let Some(Yaml::Array(items)) = get(&root, "body_rewrites") {
        for (idx, item) in items.iter().enumerate() {
            let Yaml::Hash(map) = item else { continue };
            for (k, v) in map {
                let Some(kind) = scalar_str(k) else { continue };
                let Some(pattern) = str_of(v, "match") else {
                    out.warnings.push(format!("{name}: body_rewrites[{idx}] missing match"));
                    continue;
                };
                match kind.as_str() {
                    "response_regex" | "request_regex" => {
                        let Some(find) = str_of(v, "find") else {
                            out.warnings.push(format!("{name}: body_rewrites[{idx}] missing find"));
                            continue;
                        };
                        let replace = str_of(v, "replace").unwrap_or_default();
                        let stage = if kind.starts_with("response") {
                            "http-response"
                        } else {
                            "http-request"
                        };
                        out.rewrites.push(RewriteRule {
                            section: "body rewrite".into(),
                            text: format!(
                                "{stage} {pattern} {} {}",
                                safe_body_regex(&find),
                                double_quote(&replace)
                            ),
                            source: src(idx + 1),
                        });
                    }
                    "response_jq" | "request_jq" => {
                        let Some(filter) = str_of(v, "filter").or_else(|| str_of(v, "jq")) else {
                            out.warnings.push(format!("{name}: body_rewrites[{idx}] missing filter"));
                            continue;
                        };
                        let stage = if kind.starts_with("response") {
                            "http-response-jq"
                        } else {
                            "http-request-jq"
                        };
                        out.rewrites.push(RewriteRule {
                            section: "body rewrite".into(),
                            text: format!("{stage} {pattern} {}", double_quote(&filter)),
                            source: src(idx + 1),
                        });
                    }
                    other => {
                        out.warnings.push(format!(
                            "{name}: unsupported Egern body_rewrites kind `{other}` ignored"
                        ));
                    }
                }
            }
        }
    }

    // url_rewrites
    if let Some(Yaml::Array(items)) = get(&root, "url_rewrites") {
        for (idx, item) in items.iter().enumerate() {
            let Some((pattern, location, action)) = egern_url_rewrite(item) else {
                out.warnings.push(format!("{name}: url_rewrites[{idx}] unsupported format ignored"));
                continue;
            };
            out.rewrites.push(RewriteRule {
                section: "url rewrite".into(),
                text: format!("{pattern} {} {action}", double_quote(&location)),
                source: src(idx + 1),
            });
        }
    }

    // header_rewrites
    if let Some(Yaml::Array(items)) = get(&root, "header_rewrites") {
        for (idx, item) in items.iter().enumerate() {
            let Yaml::Hash(map) = item else { continue };
            for (k, v) in map {
                let Some(kind) = scalar_str(k) else { continue };
                let Some(pattern) = str_of(v, "match") else {
                    continue;
                };
                let Some(hdr_name) = str_of(v, "name") else {
                    continue;
                };
                let (stage, op, has_val) = match kind.as_str() {
                    "request_add" => ("http-request", "header-add", true),
                    "request_replace" => ("http-request", "header-replace", true),
                    "request_delete" => ("http-request", "header-del", false),
                    "response_add" => ("http-response", "header-add", true),
                    "response_replace" => ("http-response", "header-replace", true),
                    "response_delete" => ("http-response", "header-del", false),
                    _ => continue,
                };
                let text = if has_val {
                    let val = str_of(v, "value").unwrap_or_default();
                    format!("{stage} {pattern} {op} {hdr_name} {}", double_quote(&val))
                } else {
                    format!("{stage} {pattern} {op} {hdr_name}")
                };
                out.rewrites.push(RewriteRule {
                    section: "header rewrite".into(),
                    text,
                    source: src(idx + 1),
                });
            }
        }
    }

    // map_locals
    if let Some(Yaml::Array(items)) = get(&root, "map_locals") {
        for (idx, item) in items.iter().enumerate() {
            let Some(pattern) = str_of(item, "match") else {
                continue;
            };
            let mut parts = vec![pattern];
            if let Some(status) = str_of(item, "status_code").or_else(|| str_of(item, "status")) {
                parts.push(format!("status-code={status}"));
            }
            if let Some(b64) = str_of(item, "body_base64") {
                parts.push("data-type=base64".into());
                parts.push(format!("data={}", double_quote(&b64)));
            } else if let Some(body) = str_of(item, "body") {
                parts.push("data-type=text".into());
                parts.push(format!("data={}", double_quote(&body)));
            } else if let Some(file) = str_of(item, "file") {
                parts.push("data-type=file".into());
                parts.push(format!("data={}", double_quote(&file)));
            } else {
                parts.push("data-type=text".into());
                parts.push("data=\"\"".into());
            }
            if let Some(Yaml::Hash(hdrs)) = get(item, "headers") {
                let pairs: Vec<String> = hdrs
                    .iter()
                    .filter_map(|(k, v)| Some(format!("{}: {}", scalar_str(k)?, scalar_str(v)?)))
                    .collect();
                if !pairs.is_empty() {
                    parts.push(format!("header={}", double_quote(&pairs.join("|"))));
                }
            }
            out.rewrites.push(RewriteRule {
                section: "map local".into(),
                text: parts.join(" "),
                source: src(idx + 1),
            });
        }
    }

    // scriptings
    if let Some(Yaml::Array(items)) = get(&root, "scriptings") {
        for (idx, item) in items.iter().enumerate() {
            let Yaml::Hash(map) = item else { continue };
            for (k, v) in map {
                let Some(kind) = scalar_str(k) else { continue };
                let Some(decl) = egern_script(&kind, v, idx + 1, name) else {
                    out.warnings.push(format!(
                        "{name}: unsupported or incomplete Egern script kind `{kind}` ignored"
                    ));
                    continue;
                };
                out.scripts.push(decl);
            }
        }
    }

    // 保留无法识别的非空顶层节告警（忽略已知元数据与空 dns: {}）。
    for (k, v) in top {
        let Some(key) = scalar_str(k) else { continue };
        if matches!(
            key.as_str(),
            "name"
                | "description"
                | "author"
                | "homepage"
                | "icon"
                | "open_url"
                | "compat_arguments"
                | "compat_arguments_desc"
                | "mitm"
                | "rules"
                | "hosts"
                | "body_rewrites"
                | "url_rewrites"
                | "header_rewrites"
                | "map_locals"
                | "scriptings"
        ) {
            continue;
        }
        if key == "dns" && matches!(v, Yaml::Hash(h) if h.is_empty()) {
            continue;
        }
        out.warnings
            .push(format!("{name}: unsupported Egern field `{key}` ignored"));
    }

    Ok(out)
}

fn egern_rule(kind: &str, v: &Yaml) -> Option<String> {
    let policy = str_of(v, "policy")?;
    if kind == "default" {
        return Some(format!("FINAL,{policy}"));
    }
    let matched = str_of(v, "match")?;
    let ty = match kind {
        "domain" => "DOMAIN",
        "domain_suffix" => "DOMAIN-SUFFIX",
        "domain_keyword" => "DOMAIN-KEYWORD",
        "domain_regex" => "DOMAIN-REGEX",
        "url_regex" => "URL-REGEX",
        "ip_cidr" => "IP-CIDR",
        "ip_cidr6" => "IP-CIDR6",
        "geoip" => "GEOIP",
        "asn" => "IP-ASN",
        "dest_port" => "DST-PORT",
        "src_ip_cidr" => "SRC-IP-CIDR",
        "protocol" => "PROTOCOL",
        "user_agent" => "USER-AGENT",
        _ => return None,
    };
    let no_resolve = if bool_of(v, "no_resolve") == Some(true) {
        ",no-resolve"
    } else {
        ""
    };
    Some(format!("{ty},{matched},{policy}{no_resolve}"))
}

fn egern_url_rewrite(item: &Yaml) -> Option<(String, String, String)> {
    let target = if let Yaml::Hash(map) = item {
        if map.len() == 1 {
            let (k, v) = map.iter().next()?;
            if matches!(v, Yaml::Hash(_)) {
                let kind = scalar_str(k)?;
                let pattern = str_of(v, "match")?;
                let location = str_of(v, "location").unwrap_or_else(|| "-".into());
                let action = match kind.as_str() {
                    "redirect" => str_of(v, "status").unwrap_or_else(|| "302".into()),
                    "header" | "url_rewrite" => {
                        str_of(v, "type").or_else(|| str_of(v, "status")).unwrap_or_else(|| "header".into())
                    }
                    "reject" => "reject".into(),
                    other if other.starts_with("reject") => other.replace('_', "-"),
                    _ => return None,
                };
                return Some((pattern, location, action));
            }
        }
        item
    } else {
        return None;
    };
    let pattern = str_of(target, "match")?;
    let location = str_of(target, "location").unwrap_or_else(|| "-".into());
    let action = str_of(target, "type")
        .or_else(|| str_of(target, "action"))
        .or_else(|| str_of(target, "status"))
        .unwrap_or_else(|| {
            if location == "-" {
                "reject".into()
            } else {
                "302".into()
            }
        })
        .to_ascii_lowercase()
        .replace('_', "-");
    Some((pattern, location, action))
}

fn egern_script(kind: &str, v: &Yaml, line: usize, module_name: &str) -> Option<ScriptDecl> {
    let script_type = match kind {
        "http_request" => "http-request",
        "http_response" => "http-response",
        "schedule" => "cron",
        "generic" => "generic",
        "network_changed" => "event",
        _ => return None,
    };
    let script_url = str_of(v, "script_url").or_else(|| str_of(v, "script_path"))?;
    let script_name = str_of(v, "name").unwrap_or_else(|| format!("script-{line}"));
    let mut opts = vec![
        format!("type={script_type}"),
        format!("script-path={}", double_quote(&script_url)),
    ];
    if let Some(pattern) = str_of(v, "match") {
        opts.push(format!("pattern={}", double_quote(&pattern)));
    }
    if script_type == "cron" {
        let cron = str_of(v, "cron")?;
        opts.push(format!("cronexp={}", double_quote(&cron)));
    }
    if kind == "network_changed" {
        opts.push("event-name=network-changed".into());
    }
    if bool_of(v, "body_required") == Some(true) {
        opts.push("requires-body=true".into());
    }
    if bool_of(v, "binary_body") == Some(true) {
        opts.push("binary-body-mode=true".into());
    }
    if let Some(max_size) = str_of(v, "max_size") {
        opts.push(format!("max-size={max_size}"));
    }
    if let Some(timeout) = str_of(v, "timeout") {
        opts.push(format!("timeout={timeout}"));
    }
    if bool_of(v, "disabled") == Some(true) || bool_of(v, "enabled") == Some(false) {
        opts.push("enable=false".into());
    }
    if let Some(arg) = extract_compat_argument(v) {
        opts.push(format!("argument={}", double_quote(&arg)));
    }
    Some(ScriptDecl {
        text: format!("{script_name} = {}", opts.join(", ")),
        source: ModuleSource {
            name: module_name.into(),
            line,
        },
    })
}

fn extract_compat_argument(v: &Yaml) -> Option<String> {
    for container in ["arguments", "env"] {
        if let Some(node) = get(v, container) {
            if let Some(s) = scalar_str(node) {
                return Some(s);
            }
            if let Some(compat) = str_of(node, "_compat.$argument") {
                return Some(compat);
            }
        }
    }
    str_of(v, "argument")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_egern_yaml_body_rewrites_scripts_rules_and_mitm() {
        let yaml = r#"
name: Demo Egern Module
description: Sample description
compat_arguments:
  region: CN
  sync_disabled: false
compat_arguments_desc: |
  region: Country code
scriptings:
  - http_request:
      name: Demo.req
      match: ^https?:\/\/api\.example\.com\/v1\/test
      script_url: https://cdn.example.com/req.js
      body_required: true
      binary_body: true
      timeout: 30
      env:
        _compat.$argument: region="{{{region}}}"
  - schedule:
      name: Demo.cron
      disabled: {{{sync_disabled}}}
      cron: "0 8 * * *"
      script_url: https://cdn.example.com/cron.js
      arguments:
        _compat.$argument: "flag={{{region}}}"
body_rewrites:
  - response_regex:
      match: ^https://web\.example\.com/
      find: foo bar
      replace: baz
  - response_jq:
      match: ^https://api\.example\.com/feed
      filter: 'del(.ad)'
rules:
  - domain_suffix:
      match: example.com
      policy: DIRECT
mitm:
  hostnames:
    includes:
      - api.example.com
    excludes:
      - skip.example.com
"#;
        assert!(is_egern_yaml(yaml));
        let bound = crate::bind(yaml, ModuleFormat::Surge, &[("region".into(), "SG".into())]).unwrap();
        let ir = crate::parse_named(&bound.text, None, "demo.yaml").unwrap();
        assert_eq!(ir.meta.name.as_deref(), Some("Demo Egern Module"));
        assert_eq!(ir.arguments.len(), 2);
        assert_eq!(ir.rules, vec!["DOMAIN-SUFFIX,example.com,DIRECT"]);
        assert_eq!(ir.mitm, vec!["hostname = %APPEND% api.example.com, -skip.example.com"]);
        assert_eq!(ir.rewrites.len(), 2);
        assert!(ir.rewrites[0].text.contains(r"foo\x20bar"));
        assert!(ir.rewrites[1].text.contains("http-response-jq"));
        assert_eq!(ir.scripts.len(), 2);
        assert!(ir.scripts[0].text.contains(r#"argument="region=\"SG\"""#));
        assert!(ir.scripts[0].text.contains("requires-body=true"));
        assert!(ir.scripts[0].text.contains("binary-body-mode=true"));
        assert!(!ir.scripts[1].text.contains("enable=false"));
    }
}
