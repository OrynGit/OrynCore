//! 按消息执行重写，HTTP/1 与 HTTP/2 共用；方言决定匹配、动作顺序和脚本互斥。
mod compile;
mod json_path;
mod syntax;
pub use compile::{compile_module, compile_module_with_policies, Resources};
use oryn_module::ModuleFormat;
use serde_json::Value;
use std::{collections::BTreeMap, io, io::Read, rc::Rc};

pub const MAX_BODY: usize = 1024 * 1024;
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
#[derive(Clone, Debug)]
pub struct Pattern {
    source: std::sync::Arc<str>,
    /// 字面量前缀与是否忽略 ASCII 大小写；None 表示无法提取（未锚定、多行模式、顶层 `|` 等）。
    prefix: Option<(String, bool)>,
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
/// 锚定正则开头必然出现的字面量（只处理 ASCII 字面量与转义的标点）。
fn literal_prefix(pattern: &str) -> Option<String> {
    let rest = pattern.strip_prefix('^')?;
    // 顶层 `|` 让 `^` 只约束第一个分支。
    let (mut depth, mut class, mut escape) = (0i32, false, false);
    for c in rest.chars() {
        match c {
            _ if escape => escape = false,
            '\\' => escape = true,
            '[' if !class => class = true,
            ']' if class => class = false,
            '(' if !class => depth += 1,
            ')' if !class => depth -= 1,
            '|' if !class && depth == 0 => return None,
            _ => {}
        }
    }
    let mut out = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        let lit = match c {
            '\\' => match chars.next() {
                Some(n) if n.is_ascii_punctuation() => n,
                _ => break,
            },
            '.' | '[' | '(' | ')' | '*' | '+' | '?' | '{' | '|' | '$' | '^' => break,
            c if c.is_ascii() => c,
            _ => break,
        };
        match chars.peek() {
            // 量词让这个字符变成可选：不计入前缀。
            Some('?' | '*' | '{') => break,
            Some('+') => {
                out.push(lit);
                break;
            }
            _ => out.push(lit),
        }
    }
    (!out.is_empty()).then_some(out)
}
impl Pattern {
    pub fn new(s: &str, flags: &str) -> io::Result<Self> {
        if s.len() > 16384 || flags.chars().any(|c| !"ims".contains(c)) {
            return Err(invalid("invalid regex length or flags"));
        }
        // 模块正则是 JavaScript 语义：`\d` / `\w` 只匹配 ASCII，也避免 Unicode 类编出巨大的自动机。
        let ascii = oryn_module::regex_ascii_classes(s);
        let prefix = if flags.contains('m') {
            None
        } else {
            literal_prefix(&ascii).map(|p| (p, flags.contains('i')))
        };
        let source: std::sync::Arc<str> = if flags.is_empty() {
            ascii.into()
        } else {
            format!("(?{flags}){ascii}").into()
        };
        // 校验语法；有前缀时先丢掉编译结果，等真正可能命中时再编译。
        let engine = Engine::build(&source)?;
        let capture_count = match &engine {
            Engine::Meta(re) => re.captures_len(),
            Engine::Fancy(re) => re.captures_len(),
        };
        let cell = std::sync::OnceLock::new();
        if prefix.is_none() {
            let _ = cell.set(engine);
        }
        Ok(Self {
            source,
            prefix,
            engine: cell,
            capture_count,
        })
    }
    pub(crate) fn capture_count(&self) -> usize { self.capture_count }
    /// 前缀对不上时为 None（一定不命中），否则返回（必要时现编译的）引擎。
    fn engine_for(&self, s: &str) -> Option<&Engine> {
        if let Some((p, ci)) = &self.prefix {
            let head = s.as_bytes().get(..p.len())?;
            let ok = if *ci {
                head.eq_ignore_ascii_case(p.as_bytes())
            } else {
                head == p.as_bytes()
            };
            if !ok {
                return None;
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
    fn replace(&self, s: &str, r: &str, all: bool) -> io::Result<String> {
        let mut out = String::new();
        let mut end = 0;
        // 输出超限即报错；只替换第一处时返回 false 结束循环。
        let next = |out: &String| -> io::Result<bool> {
            if out.len() > MAX_BODY {
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
        if out.len() > MAX_BODY {
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
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub request: Vec<CompiledRule>,
    pub response: Vec<CompiledRule>,
    pub scripts: Vec<ScriptRule>,
    /// 被跳过的行，由加载方并入配置警告。
    pub warnings: Vec<String>,
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
    /// 所属模块的环境变量（`ctx.env`），编译后由加载方填入。
    pub env: std::collections::BTreeMap<String, String>,
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
        let mut loon_selected = false;
        self.scripts
            .iter()
            .filter(|s| {
                if !s.enabled || s.kind != kind || (s.dialect == ModuleFormat::Loon && loon_selected) {
                    return false;
                }
                if !evaluate(&s.condition, m, request, &mut BTreeMap::new()) { return false; }
                if s.dialect == ModuleFormat::Loon { loon_selected = true; }
                true
            })
            .collect()
    }
    pub fn apply_request(&self, m: &mut Message) -> io::Result<Option<Message>> {
        self.execute(&self.request, m, None, true)
    }
    pub fn apply_response(&self, m: &mut Message, request: &Message) -> io::Result<()> {
        self.execute(&self.response, m, Some(request), true)?;
        Ok(())
    }
    pub fn apply_request_headers(&self, m: &mut Message) -> io::Result<Option<Message>> {
        self.execute(&self.request, m, None, false)
    }
    pub fn apply_response_headers(&self, m: &mut Message, request: &Message) -> io::Result<()> {
        self.execute(&self.response, m, Some(request), false)?;
        Ok(())
    }
    /// 预演本消息命中的非正文动作以决定是否缓冲；实际消息的动作仅执行一次。
    /// 响应脚本仍按原始响应选取。
    pub fn needs_body_after_rewrite(&self, m: &Message, request: Option<&Message>) -> bool {
        // 预演只操作独立header快照，无IO/脚本，不重放到实际Message。
        // 未命中的其他主机规则不能令普通大上传返回413。
        let rules = if m.status.is_some() { &self.response } else { &self.request };
        let mut preview = Message { url: m.url.clone(), method: m.method.clone(),
            status: m.status, headers: m.headers.clone(), body: Vec::new() };
        let mut url_rewritten = false;
        for rule in rules {
            let mut captures = BTreeMap::new();
            if !evaluate(&rule.condition, &preview, request, &mut captures) { continue; }
            for action in &rule.actions {
                if action.needs_body() { return true; }
                if rule.dialect == ModuleFormat::Surge && url_rewritten && matches!(action, Action::Url(..)) { continue; }
                match perform(action, &mut preview, request, &captures) {
                    Ok(Some(_)) => return false,
                    Ok(None) => { if matches!(action, Action::Url(..)) { url_rewritten = true; } },
                    Err(_) => {},
                }
            }
        }
        let script_message = if m.status.is_some() { m } else { &preview };
        self.scripts(script_message, request).iter().any(|s| s.requires_body)
    }
    /// 返回是否命中过正文规则（包括执行失败/资源不足），用于Loon互斥，不表示正文已改变。
    pub fn apply_request_with_effects(&self, m: &mut Message) -> io::Result<(Option<Message>, bool)> {
        let mut body_matched = false;
        let response = self.execute_inner(&self.request, m, None, true, &mut body_matched)?;
        Ok((response, body_matched))
    }
    pub fn apply_response_with_effects(&self, m: &mut Message, request: &Message, body_available: bool) -> io::Result<bool> {
        let mut body_matched = false;
        self.execute_inner(&self.response, m, Some(request), body_available, &mut body_matched)?;
        Ok(body_matched)
    }
    pub fn body_rewrite_matches(&self, m: &Message, request: Option<&Message>) -> bool {
        let rules = if m.status.is_some() {
            &self.response
        } else {
            &self.request
        };
        rules.iter().any(|r| {
            r.actions.iter().any(Action::needs_body)
                && evaluate(&r.condition, m, request, &mut BTreeMap::new())
        })
    }
    pub fn needs_body(&self, m: &Message, request: Option<&Message>) -> bool {
        let rules = if m.status.is_some() {
            &self.response
        } else {
            &self.request
        };
        rules.iter().any(|r| {
            r.actions.iter().any(Action::needs_body)
                && evaluate(&r.condition, m, request, &mut BTreeMap::new())
        }) || self.scripts(m, request).iter().any(|s| s.requires_body)
    }
    fn execute(
        &self,
        rules: &[CompiledRule],
        m: &mut Message,
        request: Option<&Message>,
        body_available: bool,
    ) -> io::Result<Option<Message>> {
        self.execute_inner(rules, m, request, body_available, &mut false)
    }
    fn execute_inner(
        &self, rules: &[CompiledRule], m: &mut Message, request: Option<&Message>,
        body_available: bool, body_matched: &mut bool,
    ) -> io::Result<Option<Message>> {
        let mut url_rewritten = false;
        let started = std::time::Instant::now();
        for rule in rules {
            if started.elapsed() > std::time::Duration::from_millis(250) {
                let skipped = rules.len() - rules.iter().position(|r| std::ptr::eq(r, rule)).unwrap_or(0);
                log::warn!(
                    "HTTP rewrite execution budget (250 ms) exceeded on {}; {skipped} remaining rules skipped, starting at {}",
                    m.url,
                    rule.source
                );
                break;
            }
            let mut captures = BTreeMap::new();
            if !evaluate(&rule.condition, m, request, &mut captures) {
                continue;
            }
            *body_matched |= rule.actions.iter().any(|a| a.needs_body() || matches!(a, Action::Mock { status: None, .. }));
            if let Some(mock) = rule.actions.iter().find(|a| {
                matches!(
                    a,
                    Action::Mock {
                        status: Some(_),
                        ..
                    }
                )
            }) {
                if let Some(mut response) = perform(mock, m, request, &captures)? {
                    for a in &rule.actions {
                        if !matches!(a, Action::Mock { .. }) {
                            if let Err(e) = perform(a, &mut response, Some(m), &captures) {
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
                match perform(action, m, request, &captures) {
                    Ok(Some(response)) => return Ok(Some(response)),
                    Ok(None) => {
                        if matches!(action, Action::Url(..)) {
                            url_rewritten = true
                        }
                    }
                    Err(e) => log::warn!("{}: rewrite skipped: {e}", rule.source),
                }
            }
        }
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

fn evaluate(
    c: &Condition,
    m: &Message,
    req: Option<&Message>,
    caps: &mut BTreeMap<String, String>,
) -> bool {
    match c {
        Condition::Always => true,
        Condition::Eq(a, b) => require_captures(a, caps).is_ok() && require_captures(b, caps).is_ok()
            && value(a, m, req, caps) == value(b, m, req, caps),
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
            if require_captures(e, caps).is_err() { return false; }
            let v = value(e, m, req, caps);
            let Some(s) = v.as_str() else { return false };
            // 不需要命名捕获时只判断是否命中，比取捕获组便宜得多（每个请求都要过全部条件）。
            let Some(name) = name else {
                return p.matches(s);
            };
            let Some(groups) = p.captures(s) else {
                return false;
            };
            for (i, g) in groups.into_iter().enumerate() {
                if let Some(g) = g {
                    caps.insert(format!("{name}.{i}"), g.into());
                }
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
                    let v = p.replace(value, &replacement, true)?;
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
            let url = p.replace(&m.url, &text(v), false)?;
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
            let location = p.replace(&m.url, &text(v), false)?;
            check_header("Location", &location)?;
            let mut r = m.response(*status, vec![], "text/plain");
            r.set_header("Location", location);
            return Ok(Some(r));
        }
        Action::RejectText(status, body) => {
            return Ok(Some(m.response(*status, body.as_bytes().to_vec(), "text/plain")));
        }
        Action::Reject(s, kind) => {
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
            if m.body.len() > MAX_BODY {
                return Err(invalid("body exceeds rewrite limit"));
            }
            let original = decode_body(m)?;
            let output = match a {
                Action::BodyRegex(p, r) => p
                    .replace(
                        std::str::from_utf8(&original).map_err(invalid)?,
                        &text(r),
                        true,
                    )?
                    .into_bytes(),
                Action::Jq(program) => {
                    let input = serde_json::from_slice(&original).map_err(invalid)?;
                    serde_json::to_vec(&program.run(&input).map_err(invalid)?).map_err(invalid)?
                }
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
            if output.len() > MAX_BODY {
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
pub fn decode_body(m: &Message) -> io::Result<Vec<u8>> {
    let mut reader: Box<dyn Read + '_> = match m
        .header("Content-Encoding")
        .unwrap_or("identity")
        .to_ascii_lowercase()
        .as_str()
    {
        "identity" => Box::new(m.body.as_slice()),
        "gzip" => Box::new(flate2::read::GzDecoder::new(m.body.as_slice())),
        "deflate" => Box::new(flate2::read::ZlibDecoder::new(m.body.as_slice())),
        "br" => Box::new(brotli::Decompressor::new(m.body.as_slice(), 4096)),
        _ => return Err(invalid("unsupported content encoding")),
    };
    let mut out = vec![];
    reader
        .by_ref()
        .take((MAX_BODY + 1) as u64)
        .read_to_end(&mut out)?;
    if out.len() > MAX_BODY {
        return Err(invalid("decompressed body exceeds limit"));
    }
    Ok(out)
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
        assert_eq!(p.replace("http://a.com/42", "https://b.com/$1", false).unwrap(), "https://b.com/42");
        assert_eq!(p.replace("http://c.com/42", "x", false).unwrap(), "http://c.com/42");
    }
}
