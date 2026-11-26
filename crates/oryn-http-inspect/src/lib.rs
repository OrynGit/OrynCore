//! 按消息执行重写，HTTP/1 与 HTTP/2 共用；方言决定匹配、动作顺序和脚本互斥。
mod compile;
mod json_path;
mod syntax;
pub use compile::{
    compile_module, compile_module_with_limits, compile_module_with_policies, Resources,
};
use oryn_module::ModuleFormat;
use serde_json::Value;
use std::{borrow::Cow, collections::BTreeMap, io, io::Read, rc::Rc};

pub const DEFAULT_SCRIPT_TIMEOUT: u64 = 10;
pub const DEFAULT_HTTP_SCRIPT_MAX_TIMEOUT: u64 = 60;
pub const DEFAULT_BG_SCRIPT_MAX_TIMEOUT: u64 = 300;
pub const MAX_BODY: usize = 4 * 1024 * 1024;
pub const DESKTOP_MAX_BODY: usize = 8 * 1024 * 1024;

/// 脚本与 HTTP 检查的资源限额（默认按受限/移动扩展档构造，桌面档可通过 `compile_module_with_limits` 放宽）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InspectLimits {
    pub default_timeout: u64,
    pub http_max_timeout: u64,
    pub bg_max_timeout: u64,
    pub max_body: usize,
}

impl Default for InspectLimits {
    fn default() -> Self {
        Self {
            default_timeout: DEFAULT_SCRIPT_TIMEOUT,
            http_max_timeout: DEFAULT_HTTP_SCRIPT_MAX_TIMEOUT,
            bg_max_timeout: DEFAULT_BG_SCRIPT_MAX_TIMEOUT,
            max_body: MAX_BODY,
        }
    }
}
pub fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
/// 模块写法合法、但当前运行时不提供该能力；调用方跳过该行而不是拒绝整个模块。
pub fn unsupported(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, e.to_string())
}
/// 模块正则。能被 `regex-syntax` 解析的走 meta 引擎（关闭 onepass，见
/// `oryn_module::compile_regex`）；前后查找、反向引用等才交给 `fancy-regex`。
///
/// 按需编译：加载时只校验语法，第一次可能命中时才编译并缓存。`^` 锚定的正则（模块里几乎
/// 都是 `^https:\/\/主机\/…`）先比对开头的字面量前缀，对不上就一定不命中，不必编译；
/// 用户不访问的 App 的规则因此不占内存（一个常见的 37 模块组合约 970 条正则，全部编译约 14 MiB）。
#[derive(Clone, Debug, PartialEq, Eq)]
enum Prefix {
    Exact { text: String, ci: bool },
    /// 匹配 `http://<rest>` 或 `https://<rest>`（对应常见的 `^https?://...`）。
    HttpOrHttps { rest: String, ci: bool },
}

impl Prefix {
    fn matches(&self, s: &str) -> bool {
        match self {
            Self::Exact { text, ci } => {
                let Some(head) = s.as_bytes().get(..text.len()) else {
                    return false;
                };
                if *ci {
                    head.eq_ignore_ascii_case(text.as_bytes())
                } else {
                    head == text.as_bytes()
                }
            }
            Self::HttpOrHttps { rest, ci } => {
                let bytes = s.as_bytes();
                let tail = if *ci {
                    if bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(b"https://") {
                        &bytes[8..]
                    } else if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"http://") {
                        &bytes[7..]
                    } else {
                        return false;
                    }
                } else if let Some(t) = bytes.strip_prefix(b"https://") {
                    t
                } else if let Some(t) = bytes.strip_prefix(b"http://") {
                    t
                } else {
                    return false;
                };
                let Some(head) = tail.get(..rest.len()) else {
                    return false;
                };
                if *ci {
                    head.eq_ignore_ascii_case(rest.as_bytes())
                } else {
                    head == rest.as_bytes()
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Prefilter {
    prefix: Option<Prefix>,
    needle: Option<(Box<str>, bool)>,
    exact_host: Option<Box<str>>,
}

#[derive(Clone, Debug)]
pub struct Pattern {
    source: std::sync::Arc<str>,
    /// 打包到堆上的预过滤信息（前缀、必现子串、精确主机名），保持 `Pattern` 自身紧凑。
    prefilter: Option<Box<Prefilter>>,
    engine: std::sync::OnceLock<Engine>,
    /// 包括整体匹配组0；加载时记录，不为索引校验再次编译。
    capture_count: usize,
}
#[derive(Clone, Debug)]
enum Engine {
    Meta(oryn_module::CompactRegex),
    Fancy(fancy_regex::Regex),
}
impl Engine {
    fn build(s: &str) -> io::Result<Self> {
        if let Ok(re) = oryn_module::compile_regex(s) {
            return Ok(Self::Meta(re));
        }
        Ok(Self::Fancy(
            fancy_regex::RegexBuilder::new(s)
                .backtrack_limit(100_000)
                .build()
                .map_err(invalid)?,
        ))
    }
}
fn has_top_level_alternation(rest: &str) -> bool {
    let (mut depth, mut class, mut escape) = (0i32, false, false);
    for c in rest.chars() {
        match c {
            _ if escape => escape = false,
            '\\' => escape = true,
            '[' if !class => class = true,
            ']' if class => class = false,
            '(' if !class => depth += 1,
            ')' if !class => depth -= 1,
            '|' if !class && depth == 0 => return true,
            _ => {}
        }
    }
    false
}
/// 从正则切片开头提取连续的 ASCII 字面量与转义标点，并返回未消费的剩余切片。
fn literal_run(rest: &str) -> (String, &str) {
    let mut out = String::new();
    let mut i = 0usize;
    let bytes = rest.as_bytes();
    while i < bytes.len() {
        let (lit, next_i) = match bytes[i] {
            b'\\' => {
                if i + 1 < bytes.len() && bytes[i + 1].is_ascii_punctuation() {
                    (bytes[i + 1] as char, i + 2)
                } else {
                    break;
                }
            }
            b'.' | b'[' | b'(' | b')' | b'*' | b'+' | b'?' | b'{' | b'|' | b'$' | b'^' => break,
            b if b.is_ascii() => (b as char, i + 1),
            _ => break,
        };
        match bytes.get(next_i) {
            // 量词让这个字符变成可选：不计入前缀，剩余切片停在该字符之前。
            Some(b'?' | b'*' | b'{') => break,
            Some(b'+') => {
                out.push(lit);
                i = next_i;
                break;
            }
            _ => {
                out.push(lit);
                i = next_i;
            }
        }
    }
    (out, &rest[i..])
}
/// 锚定正则开头必然出现的字面量（只处理 ASCII 字面量与转义的标点）。
#[cfg(test)]
fn literal_prefix(pattern: &str) -> Option<String> {
    let rest = pattern.strip_prefix('^')?;
    if has_top_level_alternation(rest) {
        return None;
    }
    let (out, _) = literal_run(rest);
    (!out.is_empty()).then_some(out)
}
fn strip_optional_https_scheme(rest: &str, ci: bool) -> Option<&str> {
    for pat in ["https?://", r"https?:\/\/"] {
        if rest.len() >= pat.len() {
            let head = &rest.as_bytes()[..pat.len()];
            let matched = if ci {
                head.eq_ignore_ascii_case(pat.as_bytes())
            } else {
                head == pat.as_bytes()
            };
            if matched {
                return Some(&rest[pat.len()..]);
            }
        }
    }
    None
}
fn extract_exact_host(after_scheme: &str, tail: &str) -> Option<String> {
    let host = if let Some(pos) = after_scheme.find(['/', ':', '?', '#']) {
        &after_scheme[..pos]
    } else if tail == "$" {
        after_scheme
    } else {
        return None;
    };
    if host.is_empty()
        || host
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'@' | b'[' | b']'))
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}
fn extract_prefix(pattern: &str, ci: bool) -> (Option<Prefix>, Option<String>) {
    let Some(rest) = pattern.strip_prefix('^') else {
        return (None, None);
    };
    if has_top_level_alternation(rest) {
        return (None, None);
    }
    if let Some(after_scheme) = strip_optional_https_scheme(rest, ci) {
        let (lit, tail) = literal_run(after_scheme);
        if !lit.is_empty() {
            let host = extract_exact_host(&lit, tail);
            return (Some(Prefix::HttpOrHttps { rest: lit, ci }), host);
        }
    }
    let (lit, tail) = literal_run(rest);
    if lit.is_empty() {
        return (None, None);
    }
    let host = if lit.len() >= 8 && lit.as_bytes()[..8].eq_ignore_ascii_case(b"https://") {
        extract_exact_host(&lit[8..], tail)
    } else if lit.len() >= 7 && lit.as_bytes()[..7].eq_ignore_ascii_case(b"http://") {
        extract_exact_host(&lit[7..], tail)
    } else {
        None
    };
    (Some(Prefix::Exact { text: lit, ci }), host)
}
/// 从 HTTP(S) URL 提取小写主机名（不分配，除非含大写字母）。
fn url_host_lower(url: &str) -> Option<Cow<'_, str>> {
    let bytes = url.as_bytes();
    let after = if bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(b"https://") {
        &url[8..]
    } else if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"http://") {
        &url[7..]
    } else {
        return None;
    };
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..authority_end];
    let host_port = match authority.rsplit_once('@') {
        Some((_, hp)) => hp,
        None => authority,
    };
    if host_port.is_empty() || host_port.starts_with('[') {
        return None;
    }
    let host = match host_port.split_once(':') {
        Some((h, _)) => h,
        None => host_port,
    };
    if host.is_empty() {
        return None;
    }
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        Some(Cow::Owned(host.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(host))
    }
}
/// 从无顶层 `|` 的正则中提取括号深度 0、字符类外、非可选的最长 ASCII 字面量子串。
/// 仅在不含内联标志（如 `(?i)`）时启用，确保不漏匹配。
fn required_literal_needle(pattern: &str) -> Option<String> {
    if has_top_level_alternation(pattern) {
        return None;
    }
    let bytes = pattern.as_bytes();
    let mut best = String::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut in_class = false;
    let mut i = 0usize;

    let flush = |cur: &mut String, best: &mut String| {
        if cur.len() > best.len() {
            best.clear();
            best.push_str(cur);
        }
        cur.clear();
    };

    while i < bytes.len() {
        let b = bytes[i];
        if in_class {
            if b == b'\\' {
                i += 2;
            } else {
                if b == b']' {
                    in_class = false;
                }
                i += 1;
            }
            continue;
        }
        if depth > 0 {
            match b {
                b'\\' => i += 2,
                b'[' => {
                    in_class = true;
                    i += 1;
                }
                b'(' => {
                    if bytes.get(i + 1) == Some(&b'?') {
                        match bytes.get(i + 2) {
                            Some(b':' | b'=' | b'!' | b'<') => {}
                            _ => return None,
                        }
                    }
                    depth += 1;
                    i += 1;
                }
                b')' => {
                    depth -= 1;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        match b {
            b'[' => {
                flush(&mut cur, &mut best);
                in_class = true;
                i += 1;
            }
            b'(' => {
                flush(&mut cur, &mut best);
                if bytes.get(i + 1) == Some(&b'?') {
                    match bytes.get(i + 2) {
                        Some(b':' | b'=' | b'!' | b'<') => {}
                        _ => return None,
                    }
                }
                depth += 1;
                i += 1;
            }
            b')' => return None,
            b'{' => {
                flush(&mut cur, &mut best);
                let rel_end = bytes[i + 1..].iter().position(|&c| c == b'}')?;
                i += rel_end + 2;
            }
            b'.' | b'*' | b'+' | b'?' | b'^' | b'$' | b'|' => {
                flush(&mut cur, &mut best);
                i += 1;
            }
            b'\\' => {
                let Some(&next) = bytes.get(i + 1) else {
                    break;
                };
                if next.is_ascii_punctuation() {
                    let after = i + 2;
                    match bytes.get(after) {
                        Some(b'?' | b'*') => {
                            flush(&mut cur, &mut best);
                            i = after + 1;
                        }
                        Some(b'{') => {
                            flush(&mut cur, &mut best);
                            let rel_end = bytes[after + 1..].iter().position(|&c| c == b'}')?;
                            i = after + rel_end + 2;
                        }
                        Some(b'+') => {
                            cur.push(next as char);
                            flush(&mut cur, &mut best);
                            i = after + 1;
                        }
                        _ => {
                            cur.push(next as char);
                            i = after;
                        }
                    }
                } else if matches!(
                    next,
                    b'd' | b'D'
                        | b'w'
                        | b'W'
                        | b's'
                        | b'S'
                        | b'b'
                        | b'B'
                        | b'A'
                        | b'z'
                        | b'Z'
                        | b'n'
                        | b'r'
                        | b't'
                        | b'f'
                        | b'v'
                ) {
                    flush(&mut cur, &mut best);
                    i += 2;
                } else {
                    // 遇到 \x / \u / \p / 反向引用等复杂转义，停止继续扫描，仅保留此前已确认的最长字面量。
                    flush(&mut cur, &mut best);
                    break;
                }
            }
            c if c.is_ascii() => {
                let after = i + 1;
                match bytes.get(after) {
                    Some(b'?' | b'*') => {
                        flush(&mut cur, &mut best);
                        i = after + 1;
                    }
                    Some(b'{') => {
                        flush(&mut cur, &mut best);
                        let rel_end = bytes[after + 1..].iter().position(|&c| c == b'}')?;
                        i = after + rel_end + 2;
                    }
                    Some(b'+') => {
                        cur.push(c as char);
                        flush(&mut cur, &mut best);
                        i = after + 1;
                    }
                    _ => {
                        cur.push(c as char);
                        i = after;
                    }
                }
            }
            _ => {
                flush(&mut cur, &mut best);
                i += 1;
            }
        }
    }
    flush(&mut cur, &mut best);
    if best.len() < 4
        || best.eq_ignore_ascii_case("http")
        || best.eq_ignore_ascii_case("https")
        || best.eq_ignore_ascii_case("http://")
        || best.eq_ignore_ascii_case("https://")
    {
        return None;
    }
    Some(best)
}
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    let first = needle[0].to_ascii_lowercase();
    let end = haystack.len() - needle.len();
    for i in 0..=end {
        if haystack[i].to_ascii_lowercase() == first
            && haystack[i..i + needle.len()].eq_ignore_ascii_case(needle)
        {
            return true;
        }
    }
    false
}
impl Pattern {
    pub fn new(s: &str, flags: &str) -> io::Result<Self> {
        if s.len() > 16384 || flags.chars().any(|c| !"ims".contains(c)) {
            return Err(invalid("invalid regex length or flags"));
        }
        // 模块正则是 JavaScript 语义：`\d` / `\w` 只匹配 ASCII，也避免 Unicode 类编出巨大的自动机。
        let ascii = oryn_module::regex_ascii_classes(s);
        let ci = flags.contains('i');
        let (prefix, exact_host) = if flags.contains('m') {
            (None, None)
        } else {
            extract_prefix(&ascii, ci)
        };
        // 对未抽出精确主机的规则（如子域通配、未锚定正则），再提取必现字面量子串作为预过滤，
        // 避免首条不相关请求即编译所有通配 DFA。
        let needle = if exact_host.is_none() {
            required_literal_needle(&ascii)
                .filter(|n| match &prefix {
                    Some(Prefix::Exact { text, .. }) => !text.contains(n.as_str()),
                    Some(Prefix::HttpOrHttps { rest, .. }) => !rest.contains(n.as_str()),
                    None => true,
                })
                .map(|n| (n.into_boxed_str(), ci))
        } else {
            None
        };
        let prefilter = if prefix.is_some() || needle.is_some() || exact_host.is_some() {
            Some(Box::new(Prefilter {
                prefix,
                needle,
                exact_host: exact_host.map(String::into_boxed_str),
            }))
        } else {
            None
        };
        let source: std::sync::Arc<str> = if flags.is_empty() {
            ascii.into()
        } else {
            format!("(?{flags}){ascii}").into()
        };
        // 校验语法；有前缀或必现子串时先丢掉编译结果，等真正可能命中时再编译。
        let engine = Engine::build(&source)?;
        let capture_count = match &engine {
            Engine::Meta(re) => re.captures_len(),
            Engine::Fancy(re) => re.captures_len(),
        };
        let cell = std::sync::OnceLock::new();
        if prefilter.is_none() {
            let _ = cell.set(engine);
        }
        Ok(Self {
            source,
            prefilter,
            engine: cell,
            capture_count,
        })
    }
    pub(crate) fn capture_count(&self) -> usize {
        self.capture_count
    }
    pub(crate) fn exact_host(&self) -> Option<&str> {
        self.prefilter.as_deref()?.exact_host.as_deref()
    }
    /// 前缀或必现子串对不上时为 None（一定不命中），否则返回（必要时现编译的）引擎。
    fn engine_for(&self, s: &str) -> Option<&Engine> {
        if let Some(pf) = self.prefilter.as_deref() {
            if let Some(p) = &pf.prefix {
                if !p.matches(s) {
                    return None;
                }
            }
            if let Some((needle, ci)) = &pf.needle {
                let ok = if *ci {
                    contains_ascii_ci(s.as_bytes(), needle.as_bytes())
                } else {
                    s.contains(needle.as_ref())
                };
                if !ok {
                    return None;
                }
            }
        }
        Some(self.engine.get_or_init(|| {
            Engine::build(&self.source).expect("pattern validated when loaded")
        }))
    }
    pub fn matches(&self, s: &str) -> bool {
        match self.engine_for(s) {
            None => false,
            Some(Engine::Meta(re)) => re.is_match(s),
            Some(Engine::Fancy(re)) => re.is_match(s).unwrap_or(false),
        }
    }
    /// 各捕获组的文本（组 0 为整体匹配）；不匹配时为 None。
    fn captures<'a>(&self, s: &'a str) -> Option<Vec<Option<&'a str>>> {
        match self.engine_for(s)? {
            Engine::Meta(re) => {
                let mut caps = re.create_captures();
                re.captures(s, &mut caps);
                caps.is_match().then(|| {
                    (0..caps.group_len())
                        .map(|i| caps.get_group(i).map(|span| &s[span]))
                        .collect()
                })
            }
            Engine::Fancy(re) => {
                let c = re.captures(s).ok()??;
                Some((0..c.len()).map(|i| c.get(i).map(|m| m.as_str())).collect())
            }
        }
    }
    fn replace_bounded(&self, s: &str, r: &str, all: bool, max_body: usize) -> io::Result<String> {
        let mut out = String::new();
        let mut end = 0;
        // 输出超限即报错；只替换第一处时返回 false 结束循环。
        let next = |out: &String| -> io::Result<bool> {
            if out.len() > max_body {
                return Err(invalid("rewrite output exceeds limit"));
            }
            Ok(all)
        };
        let Some(engine) = self.engine_for(s) else {
            return Ok(s.to_owned());
        };
        match engine {
            Engine::Meta(re) => {
                for caps in re.captures_iter(s) {
                    let m = caps.get_match().expect("captures_iter yields matches");
                    out.push_str(&s[end..m.start()]);
                    caps.interpolate_string_into(s, r, &mut out);
                    end = m.end();
                    if !next(&out)? {
                        break;
                    }
                }
            }
            Engine::Fancy(re) => {
                for cap in re.captures_iter(s) {
                    let cap = cap.map_err(invalid)?;
                    let m = cap.get(0).unwrap();
                    out.push_str(&s[end..m.start()]);
                    cap.expand(r, &mut out);
                    end = m.end();
                    if !next(&out)? {
                        break;
                    }
                }
            }
        }
        out.push_str(&s[end..]);
        if out.len() > max_body {
            return Err(invalid("rewrite output exceeds limit"));
        }
        Ok(out)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub url: String,
    pub method: String,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl Message {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn delete_header(&mut self, name: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }
    pub fn set_header(&mut self, name: &str, value: String) {
        self.delete_header(name);
        self.headers.push((name.into(), value));
    }
    fn length(&mut self) {
        self.delete_header("Transfer-Encoding");
        self.set_header("Content-Length", self.body.len().to_string());
    }
    pub fn response(&self, status: u16, body: Vec<u8>, content_type: &str) -> Self {
        Self {
            url: self.url.clone(),
            method: self.method.clone(),
            status: Some(status),
            headers: vec![
                ("Content-Type".into(), content_type.into()),
                ("Content-Length".into(), body.len().to_string()),
            ],
            body,
        }
    }
}
#[derive(Clone, Debug)]
pub enum Expr {
    Literal(Value),
    Variable(String),
    Template(String),
    /// 加载时切分，参数文本和转义美元符号不再被运行时二次展开。
    BoundTemplate(Vec<TemplatePart>),
    Regex(Pattern),
    Array(Vec<Expr>),
}
#[derive(Clone, Debug, PartialEq)]
pub enum TemplatePart {
    Literal(String),
    Variable(String),
}

pub(crate) fn bound_template(source: Vec<TemplatePart>, args: &BTreeMap<String, Value>) -> Expr {
    let mut parts = Vec::new();
    let mut literal = String::new();
    for part in source {
        match part {
            TemplatePart::Literal(s) => literal.push_str(&s),
            TemplatePart::Variable(name) => {
                if let Some(v) = args.get(&name) { literal.push_str(&string(v.clone())); }
                else {
                    if !literal.is_empty() { parts.push(TemplatePart::Literal(std::mem::take(&mut literal))); }
                    parts.push(TemplatePart::Variable(name));
                }
            }
        }
    }
    if parts.is_empty() { return Expr::Literal(Value::String(literal)); }
    if !literal.is_empty() { parts.push(TemplatePart::Literal(literal)); }
    Expr::BoundTemplate(parts)
}

#[derive(Clone, Debug)]
pub enum Condition {
    Always,
    Eq(Expr, Expr),
    Match(Expr, Pattern, Option<String>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}
#[derive(Clone, Debug)]
pub enum Action {
    HeaderAdd(String, Expr),
    HeaderSet(String, Expr),
    HeaderReplace(String, Expr),
    HeaderDelete(String),
    HeaderRegex(String, Pattern, Expr),
    Url(Pattern, Expr),
    Redirect(u16, Pattern, Expr),
    Reject(u16, String),
    RejectText(u16, String),
    Mock {
        status: Option<u16>,
        body: Vec<u8>,
        content_type: String,
        headers: Vec<(String, String)>,
    },
    BodyRegex(Pattern, Expr),
    JsonAdd(String, Expr),
    JsonReplace(String, Expr),
    JsonDelete(String),
    Jq(Rc<oryn_jq::Program>),
}
impl Action {
    pub fn needs_body(&self) -> bool {
        matches!(
            self,
            Self::BodyRegex(..)
                | Self::JsonAdd(..)
                | Self::JsonReplace(..)
                | Self::JsonDelete(..)
                | Self::Jq(..)
                | Self::Mock { status: None, .. }
        )
    }
}
#[derive(Clone, Debug)]
pub struct CompiledRule {
    pub condition: Condition,
    pub actions: Vec<Action>,
    pub dialect: ModuleFormat,
    pub source: String,
}
#[derive(Debug, Default)]
struct RuleIndex {
    by_host: std::collections::HashMap<String, Vec<usize>>,
    fallback: Vec<usize>,
}

impl RuleIndex {
    fn build<'a>(conditions: impl Iterator<Item = &'a Condition>) -> Self {
        let mut by_host: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();
        let mut fallback = Vec::new();
        for (idx, cond) in conditions.enumerate() {
            if let Some(host) = condition_exact_host(cond) {
                by_host.entry(host.to_owned()).or_default().push(idx);
            } else {
                fallback.push(idx);
            }
        }
        Self { by_host, fallback }
    }

    fn host_indices(&self, url: &str) -> &[usize] {
        if self.by_host.is_empty() {
            return &[];
        }
        match url_host_lower(url) {
            Some(host) => self.by_host.get(host.as_ref()).map_or(&[], Vec::as_slice),
            None => &[],
        }
    }
}

#[derive(Debug)]
struct PlanIndex {
    lens: (usize, usize, usize),
    request: RuleIndex,
    response: RuleIndex,
    scripts: RuleIndex,
}

fn condition_exact_host(c: &Condition) -> Option<&str> {
    match c {
        Condition::Match(Expr::Variable(v), p, _) if v == "url" => p.exact_host(),
        Condition::And(a, b) => condition_exact_host(a).or_else(|| condition_exact_host(b)),
        _ => None,
    }
}

fn expr_reads_response_header(e: &Expr) -> bool {
    match e {
        Expr::Variable(n) => n.starts_with("response.header["),
        Expr::Template(s) => s.contains("response.header["),
        Expr::BoundTemplate(parts) => parts.iter().any(|p| {
            matches!(p, TemplatePart::Variable(n) if n.starts_with("response.header["))
        }),
        Expr::Array(xs) => xs.iter().any(expr_reads_response_header),
        _ => false,
    }
}

fn condition_reads_response_header(c: &Condition) -> bool {
    match c {
        Condition::Always => false,
        Condition::Eq(a, b) => expr_reads_response_header(a) || expr_reads_response_header(b),
        Condition::Match(e, _, _) => expr_reads_response_header(e),
        Condition::And(a, b) | Condition::Or(a, b) => {
            condition_reads_response_header(a) || condition_reads_response_header(b)
        }
    }
}

pub struct Plan {
    pub request: Vec<CompiledRule>,
    pub response: Vec<CompiledRule>,
    pub scripts: Vec<ScriptRule>,
    /// 单条消息正文改写上限（由模块编译传入，默认 [`MAX_BODY`]）。
    pub max_body: usize,
    /// 被跳过的行，由加载方并入配置警告。
    pub warnings: Vec<String>,
    /// 延迟按精确主机名建立的候选下标索引，避免每条请求线性扫描全部规则。
    index: std::cell::RefCell<Option<Box<PlanIndex>>>,
}

impl Clone for Plan {
    fn clone(&self) -> Self {
        Self {
            request: self.request.clone(),
            response: self.response.clone(),
            scripts: self.scripts.clone(),
            max_body: self.max_body,
            warnings: self.warnings.clone(),
            index: std::cell::RefCell::new(None),
        }
    }
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plan")
            .field("request", &self.request)
            .field("response", &self.response)
            .field("scripts", &self.scripts)
            .field("max_body", &self.max_body)
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            request: Vec::new(),
            response: Vec::new(),
            scripts: Vec::new(),
            max_body: MAX_BODY,
            warnings: Vec::new(),
            index: std::cell::RefCell::new(None),
        }
    }
}
/// 脚本源码：模块资源本身（已校验为 UTF-8），不另存一份字符串。
#[derive(Clone)]
pub struct ScriptCode(std::sync::Arc<[u8]>);
impl ScriptCode {
    pub fn new(bytes: std::sync::Arc<[u8]>) -> io::Result<Self> {
        std::str::from_utf8(&bytes).map_err(invalid)?;
        Ok(Self(bytes))
    }
    pub fn as_str(&self) -> &str {
        // new() 已校验；这里的检查是线性的，只在交给脚本引擎时调用一次。
        std::str::from_utf8(&self.0).expect("script code validated as UTF-8")
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl From<&str> for ScriptCode {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().into())
    }
}
impl std::fmt::Debug for ScriptCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ScriptCode({} bytes)", self.0.len())
    }
}
#[derive(Clone, Debug)]
pub struct ScriptRule {
    pub enabled: bool,
    pub event: Option<String>,
    pub cron: Option<String>,
    pub name: String,
    pub kind: String,
    pub condition: Condition,
    pub source: String,
    /// 脚本源码，与模块资源共享同一块内存；交给 worker 线程时也不复制。
    pub code: ScriptCode,
    pub argument: Value,
    /// 所属模块的环境变量（`ctx.env`），编译后由加载方填入并跨脚本共享。
    pub env: std::sync::Arc<std::collections::BTreeMap<String, String>>,
    pub requires_body: bool,
    pub binary: bool,
    pub full_headers: bool,
    pub timeout: u64,
    pub max_size: usize,
    pub dialect: ModuleFormat,
}

#[cfg(test)]
mod jq_sharing_bounds_tests {
    use super::*;

    #[test]
    fn candidate_limits_keep_execution_and_existing_hits() {
        for (entries, bytes) in [(1, usize::MAX), (usize::MAX, 1), (0, 0)] {
            let mut plan = Plan::default();
            let actions = [".", ". + 1", ".", ". + 1"].into_iter()
                .map(|s| Action::Jq(Rc::new(oryn_jq::Program::compile(s).unwrap())))
                .collect();
            plan.response.push(CompiledRule {
                condition: Condition::Always, actions,
                dialect: ModuleFormat::Loon, source: String::new(),
            });
            plan.share_jq_programs_bounded(entries, bytes);
            let ps: Vec<_> = plan.response[0].actions.iter().map(|a| {
                let Action::Jq(p) = a else { unreachable!() }; p
            }).collect();
            assert_eq!(Rc::ptr_eq(ps[0], ps[2]), entries != 0);
            assert!(!Rc::ptr_eq(ps[1], ps[3]));
            for (p, expected) in ps.iter().zip([0, 1, 0, 1]) {
                assert_eq!(p.run(&Value::from(0)).unwrap(), Value::from(expected));
            }
        }
    }
}

impl Plan {
    /// 按指定单正文上限构造空计划（供外部 crate 使用）。
    pub fn with_max_body(max_body: usize) -> Self {
        Self {
            max_body,
            ..Self::default()
        }
    }

    fn ensure_index(&self) -> std::cell::Ref<'_, PlanIndex> {
        let lens = (self.request.len(), self.response.len(), self.scripts.len());
        let needs_build = self
            .index
            .borrow()
            .as_ref()
            .is_none_or(|idx| idx.lens != lens);
        if needs_build {
            let built = Box::new(PlanIndex {
                lens,
                request: RuleIndex::build(self.request.iter().map(|r| &r.condition)),
                response: RuleIndex::build(self.response.iter().map(|r| &r.condition)),
                scripts: RuleIndex::build(self.scripts.iter().map(|s| &s.condition)),
            });
            *self.index.borrow_mut() = Some(built);
        }
        std::cell::Ref::map(self.index.borrow(), |opt| {
            opt.as_deref().expect("PlanIndex initialized")
        })
    }

    /// 仅在加载完成后共享同源码 jq；每条声明仍由编译器独立验证。
    /// 临时索引借读已有源码，无源码副本；超限的新候选照常独立执行。
    pub fn share_jq_programs(&mut self) {
        self.share_jq_programs_bounded(256, 1024 * 1024);
    }

    fn share_jq_programs_bounded(&mut self, max_entries: usize, max_source_bytes: usize) {
        // key 持有 Rc 保证借读有效，排序/查找只看源码，不看指针。
        struct Source(Rc<oryn_jq::Program>);
        impl std::borrow::Borrow<str> for Source {
            fn borrow(&self) -> &str { self.0.source() }
        }
        impl PartialEq for Source {
            fn eq(&self, other: &Self) -> bool { self.0.source() == other.0.source() }
        }
        impl Eq for Source {}
        impl PartialOrd for Source {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for Source {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.0.source().cmp(other.0.source())
            }
        }
        // 排序仅借读不可变 source；Program 的 OnceCell 只改变编译产物，不参与键比较。
        #[allow(clippy::mutable_key_type)]
        let mut programs: BTreeMap<Source, ()> = BTreeMap::new();
        let mut source_bytes = 0;
        for rule in self.request.iter_mut().chain(&mut self.response) {
            for action in &mut rule.actions {
                let Action::Jq(program) = action else { continue };
                if let Some((shared, ())) = programs.get_key_value(program.source()) {
                    *program = Rc::clone(&shared.0);
                } else if programs.len() < max_entries
                    && program.source().len() <= max_source_bytes - source_bytes
                {
                    source_bytes += program.source().len();
                    programs.insert(Source(Rc::clone(program)), ());
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.request.is_empty() && self.response.is_empty() && self.scripts.is_empty()
    }

    pub fn has_response_body_scripts(&self) -> bool {
        self.scripts
            .iter()
            .any(|s| s.enabled && s.kind == "http-response" && s.requires_body)
    }
    pub fn from_modules(modules: &[oryn_module::ModuleIR], warnings: &mut Vec<String>) -> Self {
        let mut plan = Self::default();
        for m in modules {
            match compile_module(m, &BTreeMap::new(), &Resources::new()) {
                Ok(p) => {
                    plan.request.extend(p.request);
                    plan.response.extend(p.response);
                    plan.scripts.extend(p.scripts);
                    warnings.extend(p.warnings)
                }
                Err(e) => warnings.push(e.to_string()),
            }
        }
        plan.share_jq_programs();
        plan
    }
    /// Surge依次选择全部命中；Loon在同一HTTP阶段仅取首条完整命中。
    /// 混合方言时两者各自保留其语义，返回顺序仍是模块声明顺序。
    pub fn scripts(&self, m: &Message, request: Option<&Message>) -> Vec<&ScriptRule> {
        let kind = if m.status.is_some() {
            "http-response"
        } else {
            "http-request"
        };
        let index = self.ensure_index();
        let host_slice = index.scripts.host_indices(&m.url);
        let fallback = index.scripts.fallback.as_slice();
        let (mut hi, mut fi) = (0usize, 0usize);
        let mut loon_selected = false;
        let mut out = Vec::new();
        let mut caps = BTreeMap::new();
        loop {
            let idx = match (host_slice.get(hi).copied(), fallback.get(fi).copied()) {
                (Some(h), Some(f)) if h < f => {
                    hi += 1;
                    h
                }
                (Some(_), Some(f)) => {
                    fi += 1;
                    f
                }
                (Some(h), None) => {
                    hi += 1;
                    h
                }
                (None, Some(f)) => {
                    fi += 1;
                    f
                }
                (None, None) => break,
            };
            let s = &self.scripts[idx];
            if !s.enabled || s.kind != kind || (s.dialect == ModuleFormat::Loon && loon_selected) {
                continue;
            }
            caps.clear();
            if !evaluate(&s.condition, m, request, &mut caps) {
                continue;
            }
            if s.dialect == ModuleFormat::Loon {
                loon_selected = true;
            }
            out.push(s);
        }
        out
    }
    pub fn apply_request(&self, m: &mut Message) -> io::Result<Option<Message>> {
        self.execute(false, m, None, true)
    }
    pub fn apply_response(&self, m: &mut Message, request: &Message) -> io::Result<()> {
        self.execute(true, m, Some(request), true)?;
        Ok(())
    }
    pub fn apply_request_headers(&self, m: &mut Message) -> io::Result<Option<Message>> {
        self.execute(false, m, None, false)
    }
    pub fn apply_response_headers(&self, m: &mut Message, request: &Message) -> io::Result<()> {
        self.execute(true, m, Some(request), false)?;
        Ok(())
    }
    /// 预演本消息命中的非正文动作以决定是否缓冲；实际消息的动作仅执行一次。
    /// 响应脚本仍按原始响应选取。
    pub fn needs_body_after_rewrite(&self, m: &Message, request: Option<&Message>) -> bool {
        // 预演只在首条命中的非正文改写发生时延迟克隆 header 快照；未命中时零分配。
        // 未命中的其他主机规则不能令普通大上传返回413。
        let is_response = m.status.is_some();
        let rules = if is_response {
            &self.response
        } else {
            &self.request
        };
        let mut preview: Option<Message> = None;
        let mut url_rewritten = false;
        {
            let index = self.ensure_index();
            let rule_index = if is_response {
                &index.response
            } else {
                &index.request
            };
            let mut host_slice = rule_index.host_indices(&m.url);
            let fallback = rule_index.fallback.as_slice();
            let (mut hi, mut fi) = (0usize, 0usize);
            let mut captures = BTreeMap::new();
            loop {
                let rule_idx = match (host_slice.get(hi).copied(), fallback.get(fi).copied()) {
                    (Some(h), Some(f)) if h < f => {
                        hi += 1;
                        h
                    }
                    (Some(_), Some(f)) => {
                        fi += 1;
                        f
                    }
                    (Some(h), None) => {
                        hi += 1;
                        h
                    }
                    (None, Some(f)) => {
                        fi += 1;
                        f
                    }
                    (None, None) => break,
                };
                let rule = &rules[rule_idx];
                captures.clear();
                let current = preview.as_ref().unwrap_or(m);
                if !evaluate(&rule.condition, current, request, &mut captures) {
                    continue;
                }
                for action in &rule.actions {
                    if action.needs_body() {
                        return true;
                    }
                    if rule.dialect == ModuleFormat::Surge
                        && url_rewritten
                        && matches!(action, Action::Url(..))
                    {
                        continue;
                    }
                    let msg = preview.get_or_insert_with(|| Message {
                        url: m.url.clone(),
                        method: m.method.clone(),
                        status: m.status,
                        headers: m.headers.clone(),
                        body: Vec::new(),
                    });
                    match perform(action, msg, request, &captures, self.max_body) {
                        Ok(Some(_)) => return false,
                        Ok(None) => {
                            if matches!(action, Action::Url(..)) {
                                url_rewritten = true;
                                host_slice = rule_index.host_indices(&msg.url);
                                hi = host_slice.partition_point(|&i| i <= rule_idx);
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        let script_message = if is_response {
            m
        } else {
            preview.as_ref().unwrap_or(m)
        };
        self.scripts(script_message, request)
            .iter()
            .any(|s| s.requires_body)
    }
    /// 返回是否命中过正文规则（包括执行失败/资源不足），用于Loon互斥，不表示正文已改变。
    pub fn apply_request_with_effects(&self, m: &mut Message) -> io::Result<(Option<Message>, bool)> {
        let mut body_matched = false;
        let response = self.execute_inner(false, m, None, true, &mut body_matched)?;
        Ok((response, body_matched))
    }
    pub fn apply_response_with_effects(
        &self,
        m: &mut Message,
        request: &Message,
        body_available: bool,
    ) -> io::Result<bool> {
        let mut body_matched = false;
        self.execute_inner(true, m, Some(request), body_available, &mut body_matched)?;
        Ok(body_matched)
    }
    pub fn body_rewrite_matches(&self, m: &Message, request: Option<&Message>) -> bool {
        let is_response = m.status.is_some();
        let rules = if is_response {
            &self.response
        } else {
            &self.request
        };
        let index = self.ensure_index();
        let rule_index = if is_response {
            &index.response
        } else {
            &index.request
        };
        let host_slice = rule_index.host_indices(&m.url);
        let fallback = rule_index.fallback.as_slice();
        let (mut hi, mut fi) = (0usize, 0usize);
        let mut caps = BTreeMap::new();
        loop {
            let idx = match (host_slice.get(hi).copied(), fallback.get(fi).copied()) {
                (Some(h), Some(f)) if h < f => {
                    hi += 1;
                    h
                }
                (Some(_), Some(f)) => {
                    fi += 1;
                    f
                }
                (Some(h), None) => {
                    hi += 1;
                    h
                }
                (None, Some(f)) => {
                    fi += 1;
                    f
                }
                (None, None) => return false,
            };
            let r = &rules[idx];
            if r.actions.iter().any(Action::needs_body) {
                caps.clear();
                if evaluate(&r.condition, m, request, &mut caps) {
                    return true;
                }
            }
        }
    }
    pub fn needs_body(&self, m: &Message, request: Option<&Message>) -> bool {
        self.body_rewrite_matches(m, request)
            || self.scripts(m, request).iter().any(|s| s.requires_body)
    }
    fn execute(
        &self,
        is_response: bool,
        m: &mut Message,
        request: Option<&Message>,
        body_available: bool,
    ) -> io::Result<Option<Message>> {
        self.execute_inner(is_response, m, request, body_available, &mut false)
    }
    fn execute_inner(
        &self,
        is_response: bool,
        m: &mut Message,
        request: Option<&Message>,
        body_available: bool,
        body_matched: &mut bool,
    ) -> io::Result<Option<Message>> {
        let rules = if is_response {
            &self.response
        } else {
            &self.request
        };
        let index = self.ensure_index();
        let rule_index = if is_response {
            &index.response
        } else {
            &index.request
        };
        let mut host_slice = rule_index.host_indices(&m.url);
        let fallback = rule_index.fallback.as_slice();
        let (mut hi, mut fi) = (0usize, 0usize);
        let mut url_rewritten = false;
        let started = std::time::Instant::now();
        let mut captures = BTreeMap::new();
        // 连续的 JsonAdd/JsonReplace/JsonDelete 复用同一份解析后的 JSON DOM，
        // 避免单条规则链或相邻规则对大 JSON 反复解析与序列化。
        let mut pending_json: Option<(Value, bool)> = None;
        let mut pending_source = "";

        fn flush_json(
            m: &mut Message,
            pending: &mut Option<(Value, bool)>,
            max_body: usize,
            source: &str,
        ) {
            let Some((json, dirty)) = pending.take() else {
                return;
            };
            if !dirty {
                return;
            }
            match serde_json::to_vec(&json).map_err(invalid) {
                Ok(output) if output.len() <= max_body => {
                    m.body = output;
                    m.delete_header("Content-Encoding");
                    m.delete_header("ETag");
                    m.delete_header("Content-MD5");
                    m.length();
                }
                Ok(_) => log::warn!("{source}: rewrite skipped: rewritten body exceeds limit"),
                Err(e) => log::warn!("{source}: rewrite skipped: {e}"),
            }
        }

        loop {
            let rule_idx = match (host_slice.get(hi).copied(), fallback.get(fi).copied()) {
                (Some(h), Some(f)) if h < f => {
                    hi += 1;
                    h
                }
                (Some(_), Some(f)) => {
                    fi += 1;
                    f
                }
                (Some(h), None) => {
                    hi += 1;
                    h
                }
                (None, Some(f)) => {
                    fi += 1;
                    f
                }
                (None, None) => break,
            };
            let rule = &rules[rule_idx];
            if started.elapsed() > std::time::Duration::from_millis(500) {
                let skipped = rules.len() - rule_idx;
                log::warn!(
                    "HTTP rewrite execution budget (500 ms) exceeded on {}; {skipped} remaining rules skipped, starting at {}",
                    m.url,
                    rule.source
                );
                break;
            }
            if pending_json.is_some() && condition_reads_response_header(&rule.condition) {
                flush_json(m, &mut pending_json, self.max_body, pending_source);
            }
            captures.clear();
            if !evaluate(&rule.condition, m, request, &mut captures) {
                continue;
            }
            *body_matched |= rule
                .actions
                .iter()
                .any(|a| a.needs_body() || matches!(a, Action::Mock { status: None, .. }));
            if let Some(mock) = rule.actions.iter().find(|a| {
                matches!(
                    a,
                    Action::Mock {
                        status: Some(_),
                        ..
                    }
                )
            }) {
                flush_json(m, &mut pending_json, self.max_body, pending_source);
                if let Some(mut response) = perform(mock, m, request, &captures, self.max_body)? {
                    for a in &rule.actions {
                        if !matches!(a, Action::Mock { .. }) {
                            if let Err(e) =
                                perform(a, &mut response, Some(m), &captures, self.max_body)
                            {
                                log::warn!("{}: rewrite action skipped: {e}", rule.source);
                            }
                        }
                    }
                    return Ok(Some(response));
                }
            }
            for action in &rule.actions {
                if !body_available && action.needs_body() {
                    continue;
                }
                if rule.dialect == ModuleFormat::Surge
                    && url_rewritten
                    && matches!(action, Action::Url(..))
                {
                    continue;
                }
                match action {
                    Action::JsonAdd(path, expr)
                    | Action::JsonReplace(path, expr) => {
                        if pending_json.is_some() && expr_reads_response_header(expr) {
                            flush_json(m, &mut pending_json, self.max_body, pending_source);
                        }
                        if let Err(e) = require_captures(expr, &captures) {
                            log::warn!("{}: rewrite skipped: {e}", rule.source);
                            continue;
                        }
                        if pending_json.is_none() {
                            if m.body.len() > self.max_body {
                                log::warn!("{}: rewrite skipped: body exceeds rewrite limit", rule.source);
                                continue;
                            }
                            let parsed = decode_body_cow(m, self.max_body)
                                .and_then(|raw| serde_json::from_slice::<Value>(&raw).map_err(invalid));
                            match parsed {
                                Ok(v) => pending_json = Some((v, false)),
                                Err(e) => {
                                    log::warn!("{}: rewrite skipped: {e}", rule.source);
                                    continue;
                                }
                            }
                        }
                        let val = value(expr, m, request, &captures);
                        let (json, dirty) = pending_json.as_mut().unwrap();
                        match json_path::set(json, path, val, matches!(action, Action::JsonAdd(..))) {
                            Ok(()) => {
                                *dirty = true;
                                pending_source = &rule.source;
                            }
                            Err(e) => log::warn!("{}: rewrite skipped: {e}", rule.source),
                        }
                    }
                    Action::JsonDelete(path) => {
                        if pending_json.is_none() {
                            if m.body.len() > self.max_body {
                                log::warn!("{}: rewrite skipped: body exceeds rewrite limit", rule.source);
                                continue;
                            }
                            let parsed = decode_body_cow(m, self.max_body)
                                .and_then(|raw| serde_json::from_slice::<Value>(&raw).map_err(invalid));
                            match parsed {
                                Ok(v) => pending_json = Some((v, false)),
                                Err(e) => {
                                    log::warn!("{}: rewrite skipped: {e}", rule.source);
                                    continue;
                                }
                            }
                        }
                        let (json, dirty) = pending_json.as_mut().unwrap();
                        match json_path::delete(json, path) {
                            Ok(()) => {
                                *dirty = true;
                                pending_source = &rule.source;
                            }
                            Err(e) => log::warn!("{}: rewrite skipped: {e}", rule.source),
                        }
                    }
                    _ => {
                        flush_json(m, &mut pending_json, self.max_body, pending_source);
                        match perform(action, m, request, &captures, self.max_body) {
                            Ok(Some(response)) => return Ok(Some(response)),
                            Ok(None) => {
                                if matches!(action, Action::Url(..)) {
                                    url_rewritten = true;
                                    host_slice = rule_index.host_indices(&m.url);
                                    hi = host_slice.partition_point(|&i| i <= rule_idx);
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                                return Err(e);
                            }
                            Err(e) => log::warn!("{}: rewrite skipped: {e}", rule.source),
                        }
                    }
                }
            }
        }
        flush_json(m, &mut pending_json, self.max_body, pending_source);
        Ok(None)
    }
}
fn string(v: Value) -> String {
    match v {
        Value::String(s) => s,
        Value::Null => String::new(),
        x => x.to_string(),
    }
}
fn capture_value<'a>(name: &str, captures: &'a BTreeMap<String, String>) -> Option<&'a String> {
    captures.get(name).or_else(|| {
        let (base, index) = name.rsplit_once('.')?;
        if index.len() > 1 && index.starts_with('0') && index.bytes().all(|c| c.is_ascii_digit()) {
            captures.get(&format!("{base}.{}", index.parse::<usize>().ok()?))
        } else { None }
    })
}
fn value(
    e: &Expr,
    m: &Message,
    request: Option<&Message>,
    captures: &BTreeMap<String, String>,
) -> Value {
    match e {
        Expr::Literal(v) => v.clone(),
        Expr::Array(xs) => {
            Value::Array(xs.iter().map(|v| value(v, m, request, captures)).collect())
        }
        Expr::Regex(_) => Value::Null,
        Expr::BoundTemplate(parts) => {
            let mut out = String::new();
            for part in parts {
                match part {
                    TemplatePart::Literal(s) => out.push_str(s),
                    TemplatePart::Variable(name) => out.push_str(&string(value(&Expr::Variable(name.clone()), m, request, captures))),
                }
            }
            Value::String(out)
        }
        Expr::Variable(name) => {
            if let Some(v) = capture_value(name, captures) {
                return Value::String(v.clone());
            }
            let req = request.unwrap_or(m);
            match name.as_str() {
                "url" => m.url.clone().into(),
                "request.method" => req.method.clone().into(),
                "response.status" => m.status.map(Value::from).unwrap_or(Value::Null),
                _ => {
                    let (msg, rest) = if let Some(n) = name.strip_prefix("request.header[") {
                        (req, n)
                    } else if let Some(n) = name.strip_prefix("response.header[") {
                        (m, n)
                    } else {
                        return Value::Null;
                    };
                    let key = rest.trim_end_matches(']').trim_matches(['\'', '"']);
                    msg.header(key)
                        .map(|v| Value::String(v.into()))
                        .unwrap_or(Value::Null)
                }
            }
        }
        Expr::Template(s) => {
            let mut out = String::new();
            let mut rest = s.as_str();
            while let Some(i) = rest.find("${ ".trim_end()) {
                out.push_str(&rest[..i]);
                rest = &rest[i + 2..];
                if let Some(j) = rest.find('}') {
                    out.push_str(&string(value(
                        &Expr::Variable(rest[..j].into()),
                        m,
                        request,
                        captures,
                    )));
                    rest = &rest[j + 1..]
                } else {
                    break;
                }
            }
            out.push_str(rest);
            Value::String(out)
        }
    }
}
/// 只有命名捕获缺值属于错误；缺失HTTP头仍合法求值为null。
fn require_captures(e: &Expr, caps: &BTreeMap<String, String>) -> io::Result<()> {
    let check = |name: &str| {
        if let Some((_, index)) = name.rsplit_once('.') {
            if !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()) && capture_value(name, caps).is_none() {
                return Err(invalid(format!("capture {name} did not participate in this match")));
            }
        }
        Ok(())
    };
    match e {
        Expr::Variable(name) => check(name),
        Expr::BoundTemplate(parts) => {
            for part in parts { if let TemplatePart::Variable(name) = part { check(name)?; } }
            Ok(())
        }
        Expr::Template(s) => {
            let mut rest = s.as_str();
            while let Some(i) = rest.find("${") {
                rest = &rest[i + 2..];
                let Some(end) = rest.find('}') else { break };
                check(&rest[..end])?;
                rest = &rest[end + 1..];
            }
            Ok(())
        }
        Expr::Array(a) => { for e in a { require_captures(e, caps)?; } Ok(()) },
        _ => Ok(()),
    }
}

/// 常见字符串表达式（`url`、`request.method`、请求/响应头、字面量）零拷贝求值，
/// 避免每条规则匹配都克隆整条 `m.url`。
fn eval_str<'a>(
    e: &'a Expr,
    m: &'a Message,
    req: Option<&'a Message>,
    caps: &'a BTreeMap<String, String>,
) -> Option<Cow<'a, str>> {
    match e {
        Expr::Literal(Value::String(s)) => Some(Cow::Borrowed(s.as_str())),
        Expr::Literal(_) | Expr::Array(_) | Expr::Regex(_) => None,
        Expr::Variable(name) => {
            if let Some(v) = capture_value(name, caps) {
                return Some(Cow::Borrowed(v.as_str()));
            }
            let r = req.unwrap_or(m);
            match name.as_str() {
                "url" => Some(Cow::Borrowed(m.url.as_str())),
                "request.method" => Some(Cow::Borrowed(r.method.as_str())),
                "response.status" => None,
                _ => {
                    let (msg, rest) = if let Some(n) = name.strip_prefix("request.header[") {
                        (r, n)
                    } else {
                        let n = name.strip_prefix("response.header[")?;
                        (m, n)
                    };
                    let key = rest.trim_end_matches(']').trim_matches(['\'', '"']);
                    msg.header(key).map(Cow::Borrowed)
                }
            }
        }
        Expr::BoundTemplate(_) | Expr::Template(_) => match value(e, m, req, caps) {
            Value::String(s) => Some(Cow::Owned(s)),
            _ => None,
        },
    }
}

fn evaluate(
    c: &Condition,
    m: &Message,
    req: Option<&Message>,
    caps: &mut BTreeMap<String, String>,
) -> bool {
    match c {
        Condition::Always => true,
        Condition::Eq(a, b) => {
            if require_captures(a, caps).is_err() || require_captures(b, caps).is_err() {
                return false;
            }
            if let (Some(sa), Some(sb)) = (eval_str(a, m, req, caps), eval_str(b, m, req, caps)) {
                return sa.as_ref() == sb.as_ref();
            }
            value(a, m, req, caps) == value(b, m, req, caps)
        }
        Condition::And(a, b) => evaluate(a, m, req, caps) && evaluate(b, m, req, caps),
        Condition::Or(a, b) => {
            let saved = caps.clone();
            if evaluate(a, m, req, caps) {
                true
            } else {
                *caps = saved;
                evaluate(b, m, req, caps)
            }
        }
        Condition::Match(e, p, name) => {
            if require_captures(e, caps).is_err() {
                return false;
            }
            let Some(s) = eval_str(e, m, req, caps) else {
                return false;
            };
            // 不需要命名捕获时只判断是否命中，比取捕获组便宜得多（每个请求都要过全部条件）。
            let Some(name) = name else {
                return p.matches(s.as_ref());
            };
            let Some(groups) = p.captures(s.as_ref()) else {
                return false;
            };
            let owned: Vec<(usize, String)> = groups
                .into_iter()
                .enumerate()
                .filter_map(|(i, g)| g.map(|g| (i, g.to_owned())))
                .collect();
            drop(s);
            for (i, g) in owned {
                caps.insert(format!("{name}.{i}"), g);
            }
            true
        }
    }
}
fn perform(
    a: &Action,
    m: &mut Message,
    req: Option<&Message>,
    caps: &BTreeMap<String, String>,
    max_body: usize,
) -> io::Result<Option<Message>> {
    // 在修改消息前验证；可选组没参与时仅此动作失败，前后动作仍保留。
    match a {
        Action::HeaderAdd(_, e) | Action::HeaderSet(_, e) | Action::HeaderReplace(_, e)
        | Action::HeaderRegex(_, _, e) | Action::Url(_, e) | Action::Redirect(_, _, e)
        | Action::BodyRegex(_, e) | Action::JsonAdd(_, e) | Action::JsonReplace(_, e) => require_captures(e, caps)?,
        _ => {},
    }
    let eval = |e| value(e, m, req, caps);
    let text = |e| string(eval(e));
    match a {
        Action::HeaderAdd(k, v) | Action::HeaderSet(k, v) | Action::HeaderReplace(k, v) => {
            let v = text(v);
            check_header(k, &v)?;
            if m.headers.len() >= 128
                || m.headers
                    .iter()
                    .map(|(k, v)| k.len() + v.len())
                    .sum::<usize>()
                    .saturating_add(k.len() + v.len())
                    > 32768
            {
                return Err(invalid("rewritten headers exceed limit"));
            }
            if matches!(a, Action::HeaderAdd(..)) {
                m.headers.push((k.clone(), v))
            } else if !matches!(a, Action::HeaderReplace(..)) || m.header(k).is_some() {
                m.set_header(k, v)
            }
        }
        Action::HeaderDelete(k) => {
            check_header(k, "")?;
            m.delete_header(k)
        }
        Action::HeaderRegex(k, p, r) => {
            check_header(k, "")?;
            // 与 Surge 一致逐行处理同名头（多条 Set-Cookie 各自改写），保留顺序与条数。
            let replacement = text(r);
            let mut updated = m.headers.clone();
            for (name, value) in updated.iter_mut() {
                if name.eq_ignore_ascii_case(k) {
                    let v = p.replace_bounded(value, &replacement, true, max_body)?;
                    check_header(k, &v)?;
                    *value = v;
                }
            }
            if updated.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() > 32768 {
                return Err(invalid("rewritten headers exceed limit"));
            }
            m.headers = updated;
        }
        Action::Url(p, v) => {
            let url = p.replace_bounded(&m.url, &text(v), false, max_body)?;
            let u: http::Uri = url.parse().map_err(invalid)?;
            if !matches!(u.scheme_str(), Some("http" | "https" | "ws")) {
                return Err(invalid("invalid rewritten URL scheme"));
            }
            let authority = u
                .authority()
                .ok_or_else(|| invalid("rewritten URL has no authority"))?
                .as_str()
                .to_owned();
            m.url = url;
            m.set_header("Host", authority);
        }
        Action::Redirect(status, p, v) => {
            let location = p.replace_bounded(&m.url, &text(v), false, max_body)?;
            check_header("Location", &location)?;
            let mut r = m.response(*status, vec![], "text/plain");
            r.set_header("Location", location);
            return Ok(Some(r));
        }
        Action::RejectText(status, body) => {
            return Ok(Some(m.response(*status, body.as_bytes().to_vec(), "text/plain")));
        }
        Action::Reject(s, kind) => {
            if kind == "drop" {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "rejected with REJECT-DROP",
                ));
            }
            let (body, ct) = match kind.as_str() {
                "dict" => (b"{}".to_vec(), "application/json"),
                "array" => (b"[]".to_vec(), "application/json"),
                "img" => (
                    base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
                    )
                    .map_err(invalid)?,
                    "image/gif",
                ),
                // Loon 的 reject-video：空正文但类型为视频，播放器按「无内容」处理而不是解析失败。
                "video" => (vec![], "video/mp4"),
                _ => (vec![], "text/plain"),
            };
            return Ok(Some(m.response(*s, body, ct)));
        }
        Action::Mock {
            status,
            body,
            content_type,
            headers,
        } => {
            // 模块写明的头覆盖 data-type 推出的默认类型，避免 text/plain 和
            // application/json 同时出现、客户端只认第一个。
            if let Some(s) = status {
                let mut r = m.response(*s, body.clone(), content_type);
                for (k, v) in headers {
                    r.set_header(k, v.clone());
                }
                r.set_header("Content-Length", body.len().to_string());
                return Ok(Some(r));
            }
            m.body = body.clone();
            m.set_header("Content-Type", content_type.clone());
            for (k, v) in headers {
                m.set_header(k, v.clone());
            }
            m.delete_header("Content-Encoding");
            m.length()
        }
        _ => {
            if m.body.len() > max_body {
                return Err(invalid("body exceeds rewrite limit"));
            }
            let original = decode_body_cow(m, max_body)?;
            let output = match a {
                Action::BodyRegex(p, r) => p
                    .replace_bounded(
                        std::str::from_utf8(&original).map_err(invalid)?,
                        &text(r),
                        true,
                        max_body,
                    )?
                    .into_bytes(),
                Action::Jq(program) => program.run_bytes(&original, max_body).map_err(invalid)?,
                Action::JsonAdd(path, v) | Action::JsonReplace(path, v) => {
                    let mut json = serde_json::from_slice(&original).map_err(invalid)?;
                    json_path::set(&mut json, path, eval(v), matches!(a, Action::JsonAdd(..)))?;
                    serde_json::to_vec(&json).map_err(invalid)?
                }
                Action::JsonDelete(path) => {
                    let mut json = serde_json::from_slice(&original).map_err(invalid)?;
                    json_path::delete(&mut json, path)?;
                    serde_json::to_vec(&json).map_err(invalid)?
                }
                _ => unreachable!(),
            };
            if output.len() > max_body {
                return Err(invalid("rewritten body exceeds limit"));
            }
            m.body = output;
            m.delete_header("Content-Encoding");
            m.delete_header("ETag");
            m.delete_header("Content-MD5");
            m.length();
        }
    }
    Ok(None)
}
fn check_header(k: &str, v: &str) -> io::Result<()> {
    if k.len().saturating_add(v.len()) > 32768 {
        return Err(invalid("header exceeds limit"));
    }
    if k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("transfer-encoding") {
        return Err(invalid("header rewrite cannot change framing"));
    }
    http::header::HeaderName::from_bytes(k.as_bytes()).map_err(invalid)?;
    http::header::HeaderValue::from_str(v).map_err(invalid)?;
    Ok(())
}
/// 按需零拷贝读取正文；未压缩（`identity` 或无 `Content-Encoding`）时直接借用原切片。
pub fn decode_body_cow<'a>(m: &'a Message, max_body: usize) -> io::Result<Cow<'a, [u8]>> {
    let encoding = m
        .header("Content-Encoding")
        .unwrap_or("identity")
        .to_ascii_lowercase();
    if encoding == "identity" {
        if m.body.len() > max_body {
            return Err(invalid("decompressed body exceeds limit"));
        }
        return Ok(Cow::Borrowed(&m.body));
    }
    let mut reader: Box<dyn Read + '_> = match encoding.as_str() {
        "gzip" => Box::new(flate2::read::GzDecoder::new(m.body.as_slice())),
        "deflate" => Box::new(flate2::read::ZlibDecoder::new(m.body.as_slice())),
        "br" => Box::new(brotli::Decompressor::new(m.body.as_slice(), 4096)),
        _ => return Err(invalid("unsupported content encoding")),
    };
    let mut out = vec![];
    reader
        .by_ref()
        .take((max_body + 1) as u64)
        .read_to_end(&mut out)?;
    if out.len() > max_body {
        return Err(invalid("decompressed body exceeds limit"));
    }
    Ok(Cow::Owned(out))
}

pub fn decode_body(m: &Message) -> io::Result<Vec<u8>> {
    decode_body_cow(m, MAX_BODY).map(Cow::into_owned)
}

#[cfg(test)]
mod pattern_tests {
    use super::*;
    /// 只测加载和首次命中的重复构建成本，不保留所有引擎作为优化。
    #[test]
    #[ignore = "manual Pattern cold-path measurement"]
    fn completion_pattern_cold_cost() {
        use std::{hint::black_box, time::Instant};
        for (source, input) in [
            (r"^https://api\.example/(\w+)", "https://api.example/item"),
            (r"^https://api\.example/(?!ad)(\w+)", "https://api.example/item"),
        ] {
            let mut load = Vec::new();
            let mut first = Vec::new();
            let mut warm = Vec::new();
            for _ in 0..101 {
                let start = Instant::now();
                let pattern = Pattern::new(black_box(source), "").unwrap();
                load.push(start.elapsed().as_nanos());
                assert!(pattern.engine.get().is_none());
                let start = Instant::now();
                assert!(black_box(&pattern).matches(black_box(input)));
                first.push(start.elapsed().as_nanos());
                let start = Instant::now();
                for _ in 0..100 { assert!(black_box(&pattern).matches(black_box(input))); }
                warm.push(start.elapsed().as_nanos() / 100);
            }
            load.sort_unstable(); first.sort_unstable(); warm.sort_unstable();
            println!("pattern={source} load_ns={} first_ns={} warm_ns={}", load[50], first[50], warm[50]);
        }
    }

    #[test]
    fn completion_pattern_validation_and_unicode_boundary() {
        // 语法可解析不等于自动机构建成功；不能以 syntax-only 校验代替 build。
        assert!(Pattern::new(r"^a{1000000000}", "").is_err());
        assert!(Pattern::new(r"^a(?=", "").is_err());
        assert!(Pattern::new("^ok", "x").is_err());
        assert!(Pattern::new(&"a".repeat(16385), "").is_err());
        // 前缀按字节取片段，非 UTF-8 边界不能 panic；不扩大为 Unicode case folding。
        let p = Pattern::new("^abc", "i").unwrap();
        assert!(!p.matches("abé"));
        assert!(p.engine.get().is_none());
        let p = Pattern::new("^k", "i").unwrap();
        assert!(!p.matches("K"));
        assert!(p.engine.get().is_none());
        assert!(p.matches("K"));
        let p = Pattern::new("^é", "").unwrap();
        assert!(p.matches("é"));
    }

    #[test]
    fn literal_prefixes() {
        let p = |s: &str| literal_prefix(s);
        assert_eq!(p(r"^https:\/\/api\.a\.com\/x"), Some("https://api.a.com/x".into()));
        assert_eq!(p(r"^https?:\/\/a"), Some("http".into()));
        assert_eq!(p(r"^http:\/\/a+b"), Some("http://a".into()));
        assert_eq!(p(r"^https:\/\/(a|b)\.com"), Some("https://".into()));
        assert_eq!(p(r"^https:\/\/a\.com|^http:\/\/b"), None);
        assert_eq!(p(r"https:\/\/a"), None);
        assert_eq!(p(r"^[0-9]"), None);
        assert_eq!(p(r"^https:\/\/a\d"), Some("https://a".into()));
    }
    #[test]
    fn lazy_patterns_match_like_eager_ones() {
        let cases = [
            (r"^https:\/\/api\.a\.com\/x", "i", "HTTPS://API.a.com/x?1", true),
            (r"^https:\/\/api\.a\.com\/x", "", "HTTPS://API.a.com/x?1", false),
            (r"^https?:\/\/a\.com\/(\w+)", "", "http://a.com/abc", true),
            (r"^https:\/\/a\.com", "", "https://b.com/", false),
            (r"^https:\/\/a\.com", "m", "x\nhttps://a.com", true),
            (r"^https:\/\/a\.com\/(?!ad)", "", "https://a.com/ok", true),
            (r"^https:\/\/a\.com\/(?!ad)", "", "https://a.com/ad", false),
        ];
        for (re, flags, url, want) in cases {
            let p = Pattern::new(re, flags).unwrap();
            assert_eq!(p.matches(url), want, "{re} {flags} {url}");
        }
        // 前缀不符时不编译
        let p = Pattern::new(r"^https:\/\/a\.com\/", "i").unwrap();
        assert!(!p.matches("https://b.com/"));
        assert!(p.engine.get().is_none());
        assert!(p.matches("https://A.com/"));
        assert!(p.engine.get().is_some());
        // 语法错误在加载时报出
        assert!(Pattern::new(r"^https:\/\/(a", "").is_err());
        // 替换：前缀不符原样返回
        let p = Pattern::new(r"^http:\/\/a\.com\/(\d+)", "").unwrap();
        assert_eq!(p.replace_bounded("http://a.com/42", "https://b.com/$1", false, MAX_BODY).unwrap(), "https://b.com/42");
        assert_eq!(p.replace_bounded("http://c.com/42", "x", false, MAX_BODY).unwrap(), "http://c.com/42");
    }

    #[test]
    fn https_optional_prefix_stays_lazy_and_matches_both_schemes() {
        let p = Pattern::new(r"^https?://api\.example\.com/v1/ad$", "").unwrap();
        assert_eq!(p.exact_host(), Some("api.example.com"));
        // 其它主机不编译正则
        assert!(!p.matches("https://other.example.com/v1/ad"));
        assert!(!p.matches("http://other.example.com/v1/ad"));
        assert!(p.engine.get().is_none(), "unmatched host must not compile DFA");
        // 同主机 http / https 均正常命中
        assert!(p.matches("http://api.example.com/v1/ad"));
        assert!(p.matches("https://api.example.com/v1/ad"));
        assert!(!p.matches("https://api.example.com/v1/other"));

        // 未终结的主机前缀不能进入精确主机索引（避免漏匹配 api.example.com.cn）。
        let open = Pattern::new(r"^https?://api\.example\.com", "").unwrap();
        assert_eq!(open.exact_host(), None);
        assert!(open.matches("https://api.example.com.cn/x"));

        // 子域通配规则通过必现字面量子串预过滤，不相关请求不编译 DFA。
        let wild = Pattern::new(r"^https://[^/]+\.wild0\.example/ad$", "").unwrap();
        assert_eq!(wild.exact_host(), None);
        assert!(!wild.matches("https://unmatched.example/home"));
        assert!(
            wild.engine.get().is_none(),
            "wildcard rule must stay lazy on unmatched URL"
        );
        assert!(wild.matches("https://sub.wild0.example/ad"));
        assert!(wild.engine.get().is_some());

        // 含内联 (?i) 或量化器 {1,3} 不得误抽出不可靠子串导致漏匹配。
        let inline_ci = Pattern::new(r"(?i)^https://[^/]+\.MiXeD\.example/ad$", "").unwrap();
        assert!(inline_ci.matches("https://a.mixed.example/ad"));
        let braced = Pattern::new(r"^https://a\.example/x{1,3}y$", "").unwrap();
        assert!(braced.matches("https://a.example/xy"));
    }

    #[test]
    fn host_index_preserves_declaration_order_wildcards_and_url_rewrites() {
        let text = "\
[Rewrite]
^https://a\\.example/go$ url-302-skip
^https://a\\.example/start$ header-add X-Step 1
^https://[^/]+\\.example/start$ header-add X-Step 2
^https://a\\.example/start$ header-add X-Step 3
^https://a\\.example/jump$ https://b.example/land 307
";
        // 直接用 Plan 构造含精确主机、通配和 URL 重写换主机的顺序测试。
        let _ = text;
        let mut plan = Plan::default();
        plan.request.push(CompiledRule {
            condition: Condition::Match(
                Expr::Variable("url".into()),
                Pattern::new(r"^https://a\.example/step$", "").unwrap(),
                None,
            ),
            actions: vec![Action::HeaderAdd("X-Trace".into(), Expr::Literal("1".into()))],
            dialect: ModuleFormat::Loon,
            source: "r1".into(),
        });
        plan.request.push(CompiledRule {
            condition: Condition::Match(
                Expr::Variable("url".into()),
                Pattern::new(r"^https://[^/]+\.example/step$", "").unwrap(),
                None,
            ),
            actions: vec![Action::HeaderAdd("X-Trace".into(), Expr::Literal("2".into()))],
            dialect: ModuleFormat::Loon,
            source: "r2".into(),
        });
        plan.request.push(CompiledRule {
            condition: Condition::Match(
                Expr::Variable("url".into()),
                Pattern::new(r"^https://a\.example/step$", "").unwrap(),
                None,
            ),
            actions: vec![Action::Url(
                Pattern::new(r"^https://a\.example/step$", "").unwrap(),
                Expr::Literal("https://b.example/after".into()),
            )],
            dialect: ModuleFormat::Loon,
            source: "r3".into(),
        });
        plan.request.push(CompiledRule {
            condition: Condition::Match(
                Expr::Variable("url".into()),
                Pattern::new(r"^https://b\.example/after$", "").unwrap(),
                None,
            ),
            actions: vec![Action::HeaderAdd("X-Trace".into(), Expr::Literal("4".into()))],
            dialect: ModuleFormat::Loon,
            source: "r4".into(),
        });

        let mut req = Message {
            url: "https://a.example/step".into(),
            method: "GET".into(),
            status: None,
            headers: vec![("Host".into(), "a.example".into())],
            body: Vec::new(),
        };
        plan.apply_request(&mut req).unwrap();
        let trace: Vec<&str> = req
            .headers
            .iter()
            .filter(|(k, _)| k == "X-Trace")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(trace, vec!["1", "2", "4"]);
        assert_eq!(req.url, "https://b.example/after");
    }

    #[test]
    fn chained_json_actions_and_two_mib_jq_succeed() {
        let ir = oryn_module::parse(
            "[Rewrite]\n\
             ^https://chain\\.example/api$ response-body-json-del a0 a1 a2\n\
             ^https://chain\\.example/api$ response-body-json-add clean true\n\
             ^https://jq\\.example/feed$ response-body-json-jq 'del(.ad) | .items |= map(select(.is_ad != true))'\n",
            Some(ModuleFormat::Loon),
        )
        .unwrap();
        let plan = compile_module(&ir, &BTreeMap::new(), &Resources::new()).unwrap();

        let req = Message {
            url: "https://chain.example/api".into(),
            method: "GET".into(),
            status: None,
            headers: vec![],
            body: vec![],
        };
        let mut resp = Message {
            url: req.url.clone(),
            method: "GET".into(),
            status: Some(200),
            headers: vec![("ETag".into(), "\"v1\"".into())],
            body: br#"{"a0":1,"a1":2,"a2":3,"keep":4}"#.to_vec(),
        };
        plan.apply_response(&mut resp, &req).unwrap();
        let v: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v, serde_json::json!({"keep": 4, "clean": true}));
        assert!(resp.header("ETag").is_none());

        // 2 MiB JSON 正文经 jq 改写应成功（不再被旧的 1 MiB 硬编码截断）。
        let pad = "x".repeat(220);
        let mut big = String::from(r#"{"ad":true,"items":["#);
        for i in 0..8_000usize {
            if i > 0 {
                big.push(',');
            }
            big.push_str(&format!(
                r#"{{"id":{i},"is_ad":{},"s":"{pad}"}}"#,
                i % 4 == 0
            ));
        }
        big.push_str("]}");
        assert!(big.len() > 2_000_000);
        let jq_req = Message {
            url: "https://jq.example/feed".into(),
            method: "GET".into(),
            status: None,
            headers: vec![],
            body: vec![],
        };
        let mut jq_resp = Message {
            url: jq_req.url.clone(),
            method: "GET".into(),
            status: Some(200),
            headers: vec![],
            body: big.into_bytes(),
        };
        plan.apply_response(&mut jq_resp, &jq_req).unwrap();
        let out: Value = serde_json::from_slice(&jq_resp.body).unwrap();
        assert!(out.get("ad").is_none());
        assert_eq!(out["items"].as_array().unwrap().len(), 6_000);
    }
}
