//! Surge/Loon 文本输入。保留来源顺序、方言和参数；不执行网络请求或脚本。
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const MAX_MODULE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_LINES: usize = 32768;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleFormat {
    Surge,
    Loon,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleSource {
    pub name: String,
    pub line: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ModuleMeta {
    pub name: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub homepage: Option<String>,
    pub icon: Option<String>,
    pub system: Option<String>,
    pub system_version: Option<String>,
    pub core_requirement: Option<String>,
    pub module_type: Option<String>,
    pub arguments_desc: Option<String>,
    pub raw: BTreeMap<String, String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgumentDef {
    pub name: String,
    pub kind: String,
    pub default: Option<String>,
    pub options: Vec<String>,
    pub typed: Option<String>,
    /// Loon `tag=` 显示名与 `desc=` 说明，只用于界面展示。
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub desc: Option<String>,
    pub raw: String,
    pub source: ModuleSource,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteRule {
    pub section: String,
    pub text: String,
    pub source: ModuleSource,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptDecl {
    pub text: String,
    pub source: ModuleSource,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleIR {
    pub format: ModuleFormat,
    pub meta: ModuleMeta,
    pub arguments: Vec<ArgumentDef>,
    pub general: Vec<String>,
    pub rules: Vec<String>,
    pub hosts: Vec<String>,
    pub rewrites: Vec<RewriteRule>,
    pub scripts: Vec<ScriptDecl>,
    pub mitm: Vec<String>,
    pub raw_sections: BTreeMap<String, Vec<String>>,
    pub warnings: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);
impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ParseError {}
pub fn detect_format(text: &str) -> ModuleFormat {
    // 转换仓库会保留 Loon 元数据，实际 section 比版本注释更可靠。
    if text.lines().any(|s| {
        matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "[body rewrite]" | "[header rewrite]" | "[map local]"
        )
    }) {
        return ModuleFormat::Surge;
    }
    if text.lines().any(|s| {
        let s = s.trim();
        s.eq_ignore_ascii_case("[rewrite]")
            || s.eq_ignore_ascii_case("[argument]")
            || s.starts_with("#!loon_version")
    }) {
        ModuleFormat::Loon
    } else {
        ModuleFormat::Surge
    }
}
pub fn parse(text: &str, format: Option<ModuleFormat>) -> Result<ModuleIR, ParseError> {
    parse_named(text, format, "module")
}
pub fn parse_named(
    text: &str,
    format: Option<ModuleFormat>,
    name: &str,
) -> Result<ModuleIR, ParseError> {
    if text.len() > MAX_MODULE_BYTES || text.lines().count() > MAX_LINES {
        return Err(ParseError("module exceeds size or line limit".into()));
    }
    let mut out = ModuleIR {
        format: format.unwrap_or_else(|| detect_format(text)),
        meta: Default::default(),
        arguments: vec![],
        general: vec![],
        rules: vec![],
        hosts: vec![],
        rewrites: vec![],
        scripts: vec![],
        mitm: vec![],
        raw_sections: Default::default(),
        warnings: vec![],
    };
    let mut section = String::new();
    for (i, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = line.trim();
        let source = ModuleSource {
            name: name.into(),
            line: i + 1,
        };
        if let Some(meta) = line.strip_prefix("#!") {
            parse_meta(meta, &mut out.meta);
            continue;
        }
        let line = without_comment(line);
        if line.is_empty() || line.starts_with(['#', ';']) || line.starts_with("//") {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s.trim().to_ascii_lowercase();
            continue;
        }
        match section.as_str() {
            "argument" => match argument(line, source.clone()) {
                Ok(v) => out.arguments.push(v),
                Err(e) => out.warnings.push(format!("{name}:{}: invalid argument declaration: {e}", i + 1)),
            },
            "general" => out.general.push(line.into()),
            "rule" => out.rules.push(line.into()),
            "host" => out.hosts.push(line.into()),
            "mitm" => out.mitm.push(line.into()),
            "script" => out.scripts.push(ScriptDecl {
                text: line.into(),
                source,
            }),
            "url rewrite" | "header rewrite" | "body rewrite" | "map local" | "rewrite" => {
                out.rewrites.push(RewriteRule {
                    section: section.clone(),
                    text: line.into(),
                    source,
                })
            }
            _ => {
                out.raw_sections
                    .entry(section.clone())
                    .or_default()
                    .push(line.into());
            }
        }
    }
    for section in out.raw_sections.keys() {
        out.warnings
            .push(format!("{name}: unsupported section [{section}]"));
    }
    if out.format == ModuleFormat::Surge {
        let meta_line = text
            .lines()
            .position(|l| {
                l.trim()
                    .strip_prefix("#!")
                    .and_then(|m| m.split_once('='))
                    .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("arguments"))
            })
            .map_or(1, |i| i + 1);
        if let Some(args) = out.meta.raw.get("arguments") {
            for item in split_top(args, ',')? {
                let (key, value) = item
                    .split_once(':')
                    .map_or((item, None), |(k, v)| (k, Some(v)));
                // `key:"a,b"` 的引号只用于保护逗号，替换进 `"{{{key}}}"` 时不能再带一层引号。
                let default = value.map(|v| unquote(v.trim())).transpose()?;
                out.arguments.push(ArgumentDef {
                    name: key.trim().into(),
                    kind: "input".into(),
                    default,
                    options: vec![],
                    typed: None,
                    tag: None,
                    desc: None,
                    raw: item.into(),
                    source: ModuleSource {
                        name: name.into(),
                        line: meta_line,
                    },
                });
            }
        }
    }
    Ok(out)
}
fn parse_meta(line: &str, out: &mut ModuleMeta) {
    let Some((k, v)) = line.split_once('=') else {
        return;
    };
    let k = k.trim().to_ascii_lowercase();
    let v = v.trim().to_owned();
    out.raw.insert(k.clone(), v.clone());
    match k.as_str() {
        "name" => out.name = Some(v),
        "desc" => out.description = Some(v),
        "author" => out.author = Some(v),
        "homepage" => out.homepage = Some(v),
        "icon" => out.icon = Some(v),
        "system" => out.system = Some(v),
        "system_version" => out.system_version = Some(v),
        "requirement" => out.core_requirement = Some(v),
        "type" => out.module_type = Some(v),
        "arguments-desc" => out.arguments_desc = Some(v),
        _ => {}
    }
}
fn argument(line: &str, source: ModuleSource) -> Result<ArgumentDef, ParseError> {
    let (name, raw) = line
        .split_once('=')
        .ok_or_else(|| ParseError("argument needs =".into()))?;
    let parts = split_top(raw, ',')?;
    let kind = parts.first().copied()
        .ok_or_else(|| ParseError("argument declaration is empty".into()))?;
    if name.trim().is_empty() {
        return Err(ParseError("argument name is empty".into()));
    }
    if !matches!(kind, "input" | "select" | "switch") {
        return Err(ParseError(format!("unknown argument type {kind}")));
    }
    let mut options = vec![];
    let mut typed = None;
    let mut tag = None;
    let mut desc = None;
    for p in &parts[1..] {
        if let Some(v) = p.strip_prefix("type=") {
            typed = Some(v.trim().to_ascii_lowercase())
        } else if let Some(v) = p.strip_prefix("tag=") {
            tag = Some(unquote(v)?)
        } else if let Some(v) = p.strip_prefix("desc=") {
            desc = Some(unquote(v)?)
        } else if p.starts_with(['"', '\'']) || !is_attribute(p) {
            // 引号里的值（如带查询串的 URL）可以含 `=`；只有 `标识符=` 形式才是属性。
            options.push(unquote(p)?);
        }
    }
    let value_type = typed.as_deref().unwrap_or(if kind == "switch" { "boolean" } else { "string" });
    if !matches!(value_type, "string" | "number" | "boolean") {
        return Err(ParseError(format!("unknown argument value type {value_type}")));
    }
    if (kind == "switch") != (value_type == "boolean") {
        return Err(ParseError(format!("argument control {kind} cannot use type {value_type}")));
    }
    for value in &options {
        let valid = match value_type {
            "number" => value.parse::<f64>().is_ok_and(|n| n.is_finite()),
            "boolean" => matches!(value.as_str(), "true" | "false"),
            _ => true,
        };
        if !valid {
            return Err(ParseError(format!("argument value does not match type {value_type}")));
        }
    }
    let default = options
        .first()
        .cloned()
        .or_else(|| (kind == "switch").then(|| "false".into()));
    Ok(ArgumentDef {
        name: name.trim().into(),
        kind: kind.into(),
        default,
        options,
        typed,
        tag,
        desc,
        raw: raw.into(),
        source,
    })
}
/// `key=value` 形式的参数属性（`type=` / `tag=` / `desc=` 以及以后可能出现的同类键）。
fn is_attribute(p: &str) -> bool {
    p.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    })
}
/// 按最外层分隔符切分，字符串、数组和括号内的分隔符保持原样。
/// 拆开 Script-Hub 转换地址 `http://script.hub/file/_start_/<原地址>/_end_/<文件名>?type=…`，
/// 返回原地址和由 `type` 推出的格式。Oryn 自己解析 Surge / Loon，不需要转换服务。
pub fn script_hub_source(url: &str) -> Option<(String, Option<ModuleFormat>)> {
    let lower = url.get(..19)?.to_ascii_lowercase();
    let rest = if lower.starts_with("http://script.hub/") {
        &url[18..]
    } else if lower == "https://script.hub/" {
        &url[19..]
    } else {
        return None;
    };
    let (inner, tail) = rest.strip_prefix("file/_start_/")?.split_once("/_end_/")?;
    if !inner.starts_with("https://") && !inner.starts_with("http://") {
        return None;
    }
    let format = tail
        .split_once('?')
        .map_or("", |(_, q)| q)
        .split('&')
        .find_map(|kv| kv.strip_prefix("type="))
        .and_then(|t| match t {
            "loon-plugin" => Some(ModuleFormat::Loon),
            "surge-module" => Some(ModuleFormat::Surge),
            _ => None,
        });
    Some((inner.to_owned(), format))
}

/// 规则与模块用的正则引擎（`regex-automata` 的 meta 引擎）。
pub type CompactRegex = regex_automata::meta::Regex;

/// 模块引用的脚本 / 数据文件（路径 → 内容）。内容用 `Arc` 共享：编译出的脚本直接引用同一块
/// 内存，配置 `clone()` 也不复制。
pub type Resources = BTreeMap<String, std::sync::Arc<[u8]>>;

/// 编译规则 / 模块正则：`\d` / `\w` 按 ASCII（[`regex_ascii_classes`]），并关闭 onepass DFA。
///
/// meta 引擎对锚定（`^` 开头）的正则默认额外建一张 onepass DFA，`(?i)` 的普通 URL 正则单条
/// 就有 100 KiB 以上，而模块里的 URL 正则几乎都是锚定的；关闭后约 15 KiB，判断是否命中仍走
/// 懒 DFA，捕获组改由回溯器 / PikeVM 计算（URL 很短，差别可忽略）。`regex::Regex` 不提供这个开关。
pub fn compile_regex(pattern: &str) -> Result<CompactRegex, Box<regex_automata::meta::BuildError>> {
    regex_automata::meta::Builder::new()
        .configure(regex_automata::meta::Config::new().onepass(false))
        .build(&regex_ascii_classes(pattern))
        .map_err(Box::new)
}

/// 把正则里的 `\d` / `\D` / `\w` / `\W` 换成 ASCII 字符类。
///
/// 模块（JavaScript 语义）与 Clash（Go RE2）里这几个类本来就只匹配 ASCII；Rust `regex` 默认按
/// Unicode 处理，Unicode `\w` 有几百个区间，`\w{32}` 这类写法单条就编出 1.7 MiB 的自动机
/// （实测 37 个常见去广告模块合计约 20 MiB），在 Extension 的内存预算里放不下。
/// 字符类内的 `\D` / `\W` 无法展开为区间，保持原样。没有需要替换的内容时不分配。
pub fn regex_ascii_classes(pattern: &str) -> std::borrow::Cow<'_, str> {
    if !pattern.contains(['\\']) {
        return pattern.into();
    }
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut changed = false;
    let mut chars = pattern.chars().peekable();
    // 字符类内（`[...]`）；`class_start` 表示刚进入，此时的 `]` 是字面量。
    let mut in_class = false;
    let mut class_start = false;
    while let Some(c) = chars.next() {
        if c == '\\' {
            let Some(n) = chars.next() else {
                out.push(c);
                break;
            };
            let replacement = match (in_class, n) {
                (false, 'd') => Some("[0-9]"),
                (false, 'D') => Some("[^0-9]"),
                (false, 'w') => Some("[0-9A-Za-z_]"),
                (false, 'W') => Some("[^0-9A-Za-z_]"),
                (true, 'd') => Some("0-9"),
                (true, 'w') => Some("0-9A-Za-z_"),
                _ => None,
            };
            match replacement {
                Some(r) => {
                    out.push_str(r);
                    changed = true;
                }
                None => {
                    out.push(c);
                    out.push(n);
                }
            }
            class_start = false;
            continue;
        }
        out.push(c);
        if in_class {
            if c == '^' && class_start && out.ends_with("[^") {
                continue;
            }
            if c == ']' && !class_start {
                in_class = false;
            }
            class_start = false;
        } else if c == '[' {
            in_class = true;
            class_start = true;
        }
    }
    if changed {
        out.into()
    } else {
        pattern.into()
    }
}

/// 规则策略为拒绝类时，返回 HTTP 检查用的状态码与空响应种类（`""` / `drop` / `dict` / `array` / `img`）。
pub fn reject_status(policy: &str) -> Option<(u16, &'static str)> {
    match policy.trim().to_ascii_uppercase().as_str() {
        "REJECT" | "REJECT-NO-DROP" => Some((404, "")),
        "REJECT-DROP" => Some((0, "drop")),
        "REJECT-200" => Some((200, "")),
        "REJECT-TINYGIF" | "REJECT-IMG" => Some((200, "img")),
        "REJECT-DICT" => Some((200, "dict")),
        "REJECT-ARRAY" => Some((200, "array")),
        _ => None,
    }
}

pub fn split_top(text: &str, separator: char) -> Result<Vec<&str>, ParseError> {
    let mut quote = None;
    let mut escape = false;
    let mut depth = 0usize;
    let mut start = 0;
    let mut out = vec![];
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if let Some(q) = quote {
            if q == '`' {
                if c == q {
                    if chars.peek().is_some_and(|(_, c)| *c == q) {
                        chars.next();
                    } else {
                        quote = None;
                    }
                }
            } else if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        if matches!(c, '\'' | '"' | '`') {
            quote = Some(c);
            continue;
        }
        if matches!(c, '(' | '[' | '{') {
            depth += 1;
        } else if matches!(c, ')' | ']' | '}') {
            depth = depth.saturating_sub(1);
        }
        if depth == 0 && (c == separator || separator == ' ' && c.is_whitespace()) {
            let s = text[start..i].trim();
            if !s.is_empty() {
                out.push(s)
            }
            start = i + c.len_utf8();
        }
    }
    if quote.is_some() {
        return Err(ParseError("unterminated quoted value".into()));
    }
    if !text[start..].trim().is_empty() {
        out.push(text[start..].trim())
    }
    Ok(out)
}
pub fn unquote(text: &str) -> Result<String, ParseError> {
    if text.len() >= 2 && text.starts_with('\'') && text.ends_with('\'') {
        return Ok(text[1..text.len() - 1].to_string());
    }
    if text.len() >= 2 && text.starts_with('`') && text.ends_with('`') {
        return Ok(text[1..text.len() - 1].replace("``", "`"));
    }
    if text.len() >= 2
        && (text.starts_with('"') && text.ends_with('"')
            || text.starts_with('\'') && text.ends_with('\''))
    {
        let delim = text.as_bytes()[0] as char;
        let mut out = String::new();
        let mut chars = text[1..text.len() - 1].chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            let n = chars
                .next()
                .ok_or_else(|| ParseError("trailing string escape".into()))?;
            match n {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '\\' => out.push('\\'),
                x if x == delim => out.push(x),
                x => {
                    out.push('\\');
                    out.push(x);
                }
            }
        }
        return Ok(out);
    }
    Ok(text.to_owned())
}
/// 参数替换结果；`warnings` 是不影响加载、但用户应当知道的问题。
#[derive(Debug, Clone)]
pub struct Bound {
    pub text: String,
    pub warnings: Vec<String>,
}
/// Surge 参数按文本契约只替换一次；禁止参数注入新 section 或新行。
pub fn bind_surge(text: &str, args: &[(String, String)]) -> Result<String, ParseError> {
    bind(text, ModuleFormat::Surge, args).map(|b| b.text)
}
/// 按模块声明的参数替换 `{{{name}}}`。Surge 中未声明的占位符是错误；Loon 插件（社区转换器
/// 生成的 `{{{key}}}`）只替换 `[Argument]` 声明过的名字，其余原样保留并告警。
pub fn bind(
    text: &str,
    format: ModuleFormat,
    args: &[(String, String)],
) -> Result<Bound, ParseError> {
    let ir = parse(text, Some(format))?;
    if let Some(warning) = ir.warnings.iter().find(|w| w.contains("invalid argument declaration:")) {
        return Err(ParseError(warning.clone()));
    }
    let mut warnings = vec![];
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
    let mut out = String::new();
    let mut empty = std::collections::BTreeSet::new();
    // 与解析器使用同一注释边界；保留注释和换行，但不展开其中的示例。
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with(['#', ';']) || trimmed.starts_with("//") {
            out.push_str(line);
            continue;
        }
        let active = without_comment(line.trim_end_matches(['\r', '\n']));
        let suffix = &line[active.len()..];
        let mut rest = active;
        while let Some(i) = rest.find("{{{") {
            out.push_str(&rest[..i]);
            rest = &rest[i + 3..];
            let Some(end) = rest.find("}}}") else {
                return Err(ParseError("unterminated module argument".into()));
            };
            let name = &rest[..end];
            let value = match values.get(name) {
                Some(v) => v,
                None if format == ModuleFormat::Loon => {
                    warnings.push(format!("placeholder {{{{{{{name}}}}}}} has no [Argument]; left as is"));
                    out.push_str("{{{");
                    out.push_str(name);
                    out.push_str("}}}");
                    rest = &rest[end + 3..];
                    continue;
                }
                None => return Err(ParseError(format!("undeclared argument {name}"))),
            };
            let value = match value {
                Some(v) => v.as_str(),
                None => {
                    if empty.insert(name.to_owned()) {
                        warnings.push(format!("argument {name} has no value or default; replaced with empty text"));
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

/// Surge 的行尾注释必须在引号外且之前有空白；URL 中的 // 不会被截断。
fn without_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escape = false;
    let mut prev_space = false;
    for (i, c) in line.char_indices() {
        if let Some(q) = quote {
            if escape {
                escape = false
            } else if c == '\\' && q != '`' {
                escape = true
            } else if c == q {
                quote = None
            }
            continue;
        }
        if matches!(c, '"' | '\'' | '`') {
            quote = Some(c);
            continue;
        }
        if prev_space && (c == '#' || c == ';' || line[i..].starts_with("//")) {
            return line[..i].trim_end();
        }
        prev_space = c.is_whitespace();
    }
    line
}

pub mod requirements;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn argument_declarations_are_checked() {
        for declaration in ["p =", "p = input,abc,type=unknown", "p = input,true,type=number",
            "p = switch,123,type=boolean", "p = switch,true,type=string", "p = input,NaN,type=number"] {
            let text = format!("[Argument]\n{declaration}\n");
            let ir = parse(&text, Some(ModuleFormat::Loon)).unwrap();
            assert!(ir.arguments.is_empty(), "{declaration}");
            assert!(ir.warnings[0].contains("module:2: invalid argument declaration:"));
            assert!(bind(&text, ModuleFormat::Loon, &[]).is_err());
        }
        let ir = parse("[Argument]\np = input,12,type=NUMBER\nb = switch,true,type=BoOlEaN\ns = select,a,b,type=STRING\n", None).unwrap();
        assert!(ir.warnings.is_empty());
        assert_eq!(ir.arguments[0].typed.as_deref(), Some("number"));
        assert_eq!(ir.arguments[1].typed.as_deref(), Some("boolean"));
        assert_eq!(ir.arguments[2].typed.as_deref(), Some("string"));
    }

    #[test]
    fn comment_placeholders_are_not_bound() {
        let text = "#!desc={{{unused}}}\n# {{{unterminated\n; {{{unused}}}\n// {{{unused}}}\n[Rule]\nDOMAIN,a.test,{{{p}}} # {{{unused}}}\n";
        let text = format!("#!arguments=p:DIRECT\n{text}");
        let bound = bind_surge(&text, &[]).unwrap();
        assert!(bound.contains("DOMAIN,a.test,DIRECT # {{{unused}}}"));
        assert!(bound.contains("# {{{unterminated"));
        assert!(bind_surge("[Rule]\nDOMAIN,a.test,{{{missing}}}\n", &[]).is_err());
    }

    #[test]
    fn loon_argument_tag_and_desc() {
        let ir = parse(
            "#!name=Weather\n[Argument]\nsource = select,\"ColorfulClouds\",\"WeatherKit\",tag=[天气]数据源,desc=使用选定的数据源\nlog = switch,true,tag=日志\n",
            None,
        )
        .unwrap();
        assert_eq!(ir.format, ModuleFormat::Loon);
        let a = &ir.arguments[0];
        assert_eq!(a.options, ["ColorfulClouds", "WeatherKit"]);
        assert_eq!(a.default.as_deref(), Some("ColorfulClouds"));
        assert_eq!(a.tag.as_deref(), Some("[天气]数据源"));
        assert_eq!(a.desc.as_deref(), Some("使用选定的数据源"));
        assert_eq!(ir.arguments[1].default.as_deref(), Some("true"));
        assert_eq!(ir.arguments[1].desc, None);
    }

    #[test]
    fn loon_select_options_may_contain_equals() {
        let ir = parse(
            "#!loon_version=3.2.4\n[Argument]\nep = select,\"https://a.test/?k=v\",\"b\",tag=Endpoint\n",
            None,
        )
        .unwrap();
        let a = &ir.arguments[0];
        assert_eq!(a.options, ["https://a.test/?k=v", "b"]);
        assert_eq!(a.default.as_deref(), Some("https://a.test/?k=v"));
        assert_eq!(a.tag.as_deref(), Some("Endpoint"));
    }

    #[test]
    fn regex_perl_classes_become_ascii() {
        let t = |p: &str| regex_ascii_classes(p).into_owned();
        assert_eq!(t(r"^http:\/\/\w{32}\.a\.com"), r"^http:\/\/[0-9A-Za-z_]{32}\.a\.com");
        assert_eq!(t(r"id=\d+&x=\D"), r"id=[0-9]+&x=[^0-9]");
        assert_eq!(t(r"[\w.-]+\W"), r"[0-9A-Za-z_.-]+[^0-9A-Za-z_]");
        assert_eq!(t(r"[\d]"), "[0-9]");
        // 转义的反斜杠、字符类里的 `]` 与 `^`、其他转义保持原样
        assert_eq!(t(r"a\\w"), r"a\\w");
        assert_eq!(t(r"[]\w]\s\."), r"[]0-9A-Za-z_]\s\.");
        assert_eq!(t(r"[^\w]"), r"[^0-9A-Za-z_]");
        assert_eq!(t(r"[\W]"), r"[\W]");
        assert!(matches!(regex_ascii_classes(r"^https://a\.com/"), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn script_hub_urls_unwrap_to_source() {
        assert_eq!(
            script_hub_source("http://script.hub/file/_start_/https://a.test/x/Y.plugin/_end_/Y.sgmodule?type=loon-plugin&target=surge-module&del=true"),
            Some(("https://a.test/x/Y.plugin".into(), Some(ModuleFormat::Loon)))
        );
        assert_eq!(
            script_hub_source("http://script.hub/file/_start_/https://a.test/中文.sgmodule/_end_/中文.sgmodule?type=surge-module"),
            Some(("https://a.test/中文.sgmodule".into(), Some(ModuleFormat::Surge)))
        );
        assert_eq!(script_hub_source("https://a.test/file/_start_/x/_end_/y"), None);
    }

    #[test]
    fn surge_quoted_argument_defaults_are_unquoted() {
        let text = "#!name = Quoted\n#!arguments = Tab:\"1,2\",Switch:true,Policy:PROXY\n[Script]\ns = type=http-request, pattern=^https://a.test, script-path=s.js, argument=Tab=\"{{{Tab}}}\"&Switch=\"{{{Switch}}}\"\n[Rule]\nDOMAIN,a.test,{{{Policy}}}\n";
        let ir = parse(text, None).unwrap();
        assert_eq!(ir.meta.name.as_deref(), Some("Quoted"));
        assert_eq!(ir.arguments[0].default.as_deref(), Some("1,2"));
        let bound = bind_surge(text, &[("Policy".into(), "Media".into())]).unwrap();
        assert_eq!(parse(text, None).unwrap().arguments[0].source.line, 2);
        assert!(bound.contains("argument=Tab=\"1,2\"&Switch=\"true\""));
        assert!(bound.contains("DOMAIN,a.test,Media"));
    }

    #[test]
    fn loon_placeholders_bind_declared_arguments() {
        let text = "#!name=L\n[Argument]\npolicy = select,\"DIRECT\",\"PROXY\",tag=策略\n[Rule]\nDOMAIN,a.test,{{{policy}}}\nDOMAIN,b.test,{{{other}}}\n";
        let b = bind(text, ModuleFormat::Loon, &[("policy".into(), "PROXY".into()), ("nope".into(), "x".into())]).unwrap();
        assert!(b.text.contains("DOMAIN,a.test,PROXY"));
        assert!(b.text.contains("DOMAIN,b.test,{{{other}}}"));
        assert_eq!(b.warnings.len(), 2, "{:?}", b.warnings);
    }
    #[test]
    fn surge_argument_without_value_warns() {
        let text = "#!name=S\n#!arguments=P\n[Rule]\nDOMAIN,a.test,{{{P}}}\n";
        let b = bind(text, ModuleFormat::Surge, &[]).unwrap();
        assert!(b.text.contains("DOMAIN,a.test,\n"));
        assert_eq!(b.warnings.len(), 1);
    }
}
