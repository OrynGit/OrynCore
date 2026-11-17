//! 分享链接订阅：把 `ss://`、`vmess://` 等链接（逐行，或整段 Base64）转换成 mihomo 风格的节点，
//! 之后与 YAML 里的节点走同一个解析器。支持的写法与 App 的 `ProxyLinks` 一致；带有无法表示的
//! 参数的链接整条跳过并给出原因，不静默丢字段。

use std::collections::{HashMap, HashSet};

use base64::Engine;
use yaml_rust2::yaml::Hash;
use yaml_rust2::Yaml;

/// 一次最多处理的链接数，防止异常内容耗尽内存。
pub(crate) const MAX_LINKS: usize = 20_000;

const SCHEMES: [&str; 14] = [
    "ss",
    "ssr",
    "snell",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "hy2",
    "tuic",
    "anytls",
    "socks",
    "socks5",
    "http",
    "https",
];

pub struct Parsed {
    pub nodes: Vec<Yaml>,
    pub warnings: Vec<String>,
}

fn scheme_of(line: &str) -> Option<String> {
    let (scheme, _) = line.split_once("://")?;
    let s = scheme.to_ascii_lowercase();
    SCHEMES.contains(&s.as_str()).then_some(s)
}

/// 订阅内容是链接（逐行或整段 Base64）时返回节点；不是链接时返回 `None`。
pub fn parse_subscription(text: &str) -> Option<Parsed> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let direct = trimmed.lines().any(|l| scheme_of(l.trim()).is_some());
    let owned;
    let body = if direct {
        trimmed
    } else {
        let decoded = decode_base64(trimmed)?;
        owned = String::from_utf8(decoded).ok()?;
        if !owned.lines().any(|l| scheme_of(l.trim()).is_some()) {
            return None;
        }
        owned.as_str()
    };
    let mut nodes = Vec::new();
    let mut warnings = Vec::new();
    for (n, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if nodes.len() + warnings.len() >= MAX_LINKS {
            warnings.push(format!("only the first {MAX_LINKS} links are used"));
            break;
        }
        let preview: String = line.chars().take(40).collect();
        match parse_link(line) {
            Ok(node) => nodes.push(node),
            Err(e) => warnings.push(format!("link {} ({preview}…): {e}", n + 1)),
        }
    }
    Some(Parsed { nodes, warnings })
}

// MARK: 工具

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // 非法 UTF-8 时原样返回，而不是丢掉整段
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 宽松的 Base64：标准 / URL-safe 字母表混用、缺失或多余的 `=`、夹杂空白、百分号编码的 `=`。
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut s = text.trim().to_string();
    if s.contains('%') {
        s = percent_decode(&s);
    }
    let mut s: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    while s.ends_with('=') {
        s.pop();
    }
    if s.len() % 4 == 1 {
        return None;
    }
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s)
        .ok()
}

fn st(s: impl Into<String>) -> Yaml {
    Yaml::String(s.into())
}

fn set(h: &mut Hash, key: &str, value: Yaml) {
    h.insert(st(key), value);
}

fn set_str(h: &mut Hash, key: &str, value: impl Into<String>) {
    set(h, key, st(value));
}

fn list(items: impl IntoIterator<Item = String>) -> Yaml {
    Yaml::Array(items.into_iter().map(Yaml::String).collect())
}

fn csv(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

struct Parts {
    userinfo: Option<String>,
    host: String,
    port: Option<u16>,
    raw_port: Option<String>,
    path: String,
    query: Query,
    fragment: Option<String>,
}

fn split(rest: &str) -> Result<Parts, String> {
    let mut body = rest.to_string();
    let mut fragment = None;
    if let Some(i) = body.rfind('#') {
        fragment = Some(percent_decode(&body[i + 1..]));
        body.truncate(i);
    }
    let mut query_text = String::new();
    if let Some(i) = body.find('?') {
        query_text = body[i + 1..].to_string();
        body.truncate(i);
    }
    let (authority, path) = match body.find('/') {
        Some(i) => (body[..i].to_string(), body[i..].to_string()),
        None => (body.clone(), String::new()),
    };
    let (userinfo, authority) = match authority.rfind('@') {
        Some(i) => (
            Some(authority[..i].to_string()),
            authority[i + 1..].to_string(),
        ),
        None => (None, authority),
    };
    let (host, raw_port) = if let Some(stripped) = authority.strip_prefix('[') {
        let close = stripped.find(']').ok_or("invalid address")?;
        let host = stripped[..close].to_string();
        let after = &stripped[close + 1..];
        (host, after.strip_prefix(':').map(String::from))
    } else if let Some(i) = authority.rfind(':') {
        (
            authority[..i].to_string(),
            Some(authority[i + 1..].to_string()),
        )
    } else {
        (authority.clone(), None)
    };
    let port = raw_port.as_deref().and_then(|p| p.parse::<u16>().ok());
    Ok(Parts {
        userinfo,
        host,
        port,
        raw_port,
        path,
        query: Query::new(&query_text),
        fragment,
    })
}

/// 查询参数。读过的键被记下，剩下的未知键用来拒绝带有无法表示字段的链接。
struct Query {
    items: HashMap<String, String>,
    order: Vec<String>,
    used: HashSet<String>,
}

/// 各客户端常带的提示类参数，忽略不影响连接语义。
const HARMLESS: [&str; 9] = [
    "tfo",
    "fast-open",
    "fastopen",
    "mptcp",
    "ecn",
    "remarks",
    "remark",
    "name",
    "group",
];

impl Query {
    fn new(text: &str) -> Query {
        let mut items = HashMap::new();
        let mut order = Vec::new();
        for pair in text.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(k);
            let value = percent_decode(&v.replace('+', "%20"));
            if !items.contains_key(&key) {
                order.push(key.clone());
            }
            items.insert(key, value);
        }
        Query {
            items,
            order,
            used: HashSet::new(),
        }
    }

    fn get(&mut self, key: &str) -> Option<String> {
        self.used.insert(key.to_string());
        self.items.get(key).filter(|v| !v.is_empty()).cloned()
    }

    fn flag(&mut self, key: &str) -> bool {
        matches!(
            self.get(key).map(|v| v.to_ascii_lowercase()).as_deref(),
            Some("1" | "true")
        )
    }

    fn ignore(&mut self, keys: &[&str]) {
        for k in keys {
            self.used.insert((*k).to_string());
        }
    }

    /// 显式写出的 `udp=0|1` 覆盖协议默认值。
    fn udp(&mut self, node: &mut Hash) {
        match self.get("udp").map(|v| v.to_ascii_lowercase()).as_deref() {
            Some("0" | "false") => set(node, "udp", Yaml::Boolean(false)),
            Some("1" | "true") => set(node, "udp", Yaml::Boolean(true)),
            _ => {}
        }
    }

    fn finish(&self) -> Result<(), String> {
        for key in &self.order {
            if !self.used.contains(key)
                && !HARMLESS.contains(&key.to_ascii_lowercase().as_str())
                && !self.items.get(key).is_none_or(String::is_empty)
            {
                return Err(format!("unsupported parameter `{key}`"));
            }
        }
        Ok(())
    }
}

fn require_port(parts: &Parts) -> Result<u16, String> {
    if parts.host.is_empty() {
        return Err("missing server address".into());
    }
    parts
        .port
        .filter(|p| *p > 0)
        .ok_or_else(|| "the port must be between 1 and 65535".into())
}

fn node_name(parts: &Parts, kind: &str) -> String {
    let n = parts
        .fragment
        .clone()
        .unwrap_or_default()
        .trim()
        .to_string();
    if n.is_empty() {
        format!("{kind} {}", parts.host)
    } else {
        n
    }
}

fn userinfo(parts: &Parts) -> Option<String> {
    parts.userinfo.as_deref().map(percent_decode)
}

fn base(name: String, ty: &str, host: &str, port: u16) -> Hash {
    let mut h = Hash::new();
    set_str(&mut h, "name", name);
    set_str(&mut h, "type", ty);
    set_str(&mut h, "server", host);
    set(&mut h, "port", Yaml::Integer(port as i64));
    set(&mut h, "udp", Yaml::Boolean(true));
    h
}

/// TLS 字段。`sni_key`：vless / vmess 用 `servername`，其它用 `sni`。
fn apply_tls(h: &mut Hash, q: &mut Query, sni_key: &str, with_tls_flag: bool) {
    if with_tls_flag {
        set(h, "tls", Yaml::Boolean(true));
    }
    if let Some(sni) = q
        .get("sni")
        .or_else(|| q.get("peer"))
        .or_else(|| q.get("servername"))
    {
        set_str(h, sni_key, sni);
    }
    if q.flag("allowInsecure")
        || q.flag("insecure")
        || q.flag("allow_insecure")
        || q.flag("skip-cert-verify")
    {
        set(h, "skip-cert-verify", Yaml::Boolean(true));
    }
    if let Some(alpn) = q.get("alpn") {
        set(h, "alpn", list(csv(&alpn)));
    }
    if let Some(fp) = q.get("fp").or_else(|| q.get("fingerprint")) {
        if fp != "none" {
            set_str(h, "client-fingerprint", fp.to_ascii_lowercase());
        }
    }
    if let Some(pin) = q.get("pinSHA256") {
        set_str(h, "fingerprint", pin);
    }
}

fn first_csv(text: &str) -> String {
    text.split(',').next().unwrap_or("/").to_string()
}

/// V2Ray 系链接的传输层字段。
fn apply_transport(
    h: &mut Hash,
    ty: &str,
    host: Option<String>,
    path: Option<String>,
    service: Option<String>,
    header_type: Option<String>,
    mode: Option<String>,
) -> Result<(), String> {
    let header = header_type
        .unwrap_or_else(|| "none".into())
        .to_ascii_lowercase();
    let host_h = |key: &str, value: &str| {
        let mut m = Hash::new();
        m.insert(st(key), st(value));
        Yaml::Hash(m)
    };
    match ty.to_ascii_lowercase().as_str() {
        "" | "tcp" | "raw" => {
            if header == "http" {
                set_str(h, "network", "http");
                let mut opts = Hash::new();
                set_str(&mut opts, "method", "GET");
                set(
                    &mut opts,
                    "path",
                    list([first_csv(&path.unwrap_or_else(|| "/".into()))]),
                );
                if let Some(host) = host.filter(|s| !s.is_empty()) {
                    let mut headers = Hash::new();
                    set(&mut headers, "Host", list(csv(&host)));
                    set(&mut opts, "headers", Yaml::Hash(headers));
                }
                set(h, "http-opts", Yaml::Hash(opts));
            } else if header != "none" {
                return Err(format!("unsupported header type `{header}`"));
            }
        }
        net @ ("ws" | "httpupgrade") => {
            set_str(h, "network", "ws");
            let mut opts = Hash::new();
            set_str(&mut opts, "path", path.unwrap_or_else(|| "/".into()));
            if let Some(host) = host.filter(|s| !s.is_empty()) {
                set(&mut opts, "headers", host_h("Host", &host));
            }
            if net == "httpupgrade" {
                set(&mut opts, "v2ray-http-upgrade", Yaml::Boolean(true));
            }
            set(h, "ws-opts", Yaml::Hash(opts));
        }
        "grpc" => {
            if let Some(mode) = mode {
                if mode != "gun" && mode != "auto" {
                    return Err(format!("unsupported gRPC mode `{mode}`"));
                }
            }
            set_str(h, "network", "grpc");
            let mut opts = Hash::new();
            set_str(
                &mut opts,
                "grpc-service-name",
                service.or(path).unwrap_or_else(|| "Tun".into()),
            );
            set(h, "grpc-opts", Yaml::Hash(opts));
        }
        "h2" | "http" => {
            set_str(h, "network", "h2");
            let mut opts = Hash::new();
            if let Some(host) = host.filter(|s| !s.is_empty()) {
                set(&mut opts, "host", list(csv(&host)));
            }
            set_str(
                &mut opts,
                "path",
                first_csv(&path.unwrap_or_else(|| "/".into())),
            );
            set(h, "h2-opts", Yaml::Hash(opts));
        }
        "xhttp" => {
            set_str(h, "network", "xhttp");
            let mut opts = Hash::new();
            set_str(&mut opts, "method", "POST");
            set_str(&mut opts, "path", path.unwrap_or_else(|| "/".into()));
            set_str(&mut opts, "mode", "auto");
            if let Some(host) = host.filter(|s| !s.is_empty()) {
                let mut headers = Hash::new();
                set(&mut headers, "Host", list(csv(&host)));
                set(&mut opts, "headers", Yaml::Hash(headers));
            }
            set(h, "xhttp-opts", Yaml::Hash(opts));
        }
        "kcp" => set_str(h, "network", "mkcp"),
        "quic" => {
            if host
                .as_deref()
                .is_some_and(|s| !s.is_empty() && s != "none")
            {
                return Err("QUIC header encryption is not supported".into());
            }
            if header != "none" {
                return Err(format!("unsupported header type `{header}`"));
            }
            set_str(h, "network", "quic");
        }
        other => return Err(format!("unsupported transport `{other}`")),
    }
    Ok(())
}

// MARK: 入口

fn parse_link(link: &str) -> Result<Yaml, String> {
    let (scheme, rest) = link.split_once("://").ok_or("not a share link")?;
    let scheme = scheme.to_ascii_lowercase();
    let node = match scheme.as_str() {
        "ss" => shadowsocks(rest)?,
        "ssr" => shadowsocks_r(rest)?,
        "snell" => snell(rest)?,
        "vmess" => vmess(rest)?,
        "vless" => vless(rest)?,
        "trojan" => trojan(rest)?,
        "hysteria2" | "hy2" => hysteria2(rest)?,
        "tuic" => tuic(rest)?,
        "anytls" => anytls(rest)?,
        "socks" | "socks5" => socks(rest)?,
        "http" | "https" => http(rest, scheme == "https")?,
        other => return Err(format!("unsupported link type `{other}`")),
    };
    Ok(Yaml::Hash(node))
}

const SS_ALIASES: [(&str, &str); 7] = [
    ("chacha20-poly1305", "chacha20-ietf-poly1305"),
    ("aead_chacha20_poly1305", "chacha20-ietf-poly1305"),
    ("xchacha20-poly1305", "xchacha20-ietf-poly1305"),
    ("aead_xchacha20_poly1305", "xchacha20-ietf-poly1305"),
    ("aead_aes_128_gcm", "aes-128-gcm"),
    ("aead_aes_192_gcm", "aes-192-gcm"),
    ("aead_aes_256_gcm", "aes-256-gcm"),
];

/// SIP002（`base64url(method:password)@host:port/?plugin=…#name` 或明文）与整段 Base64 的旧写法。
fn shadowsocks(rest: &str) -> Result<Hash, String> {
    let invalid = || "invalid Shadowsocks link".to_string();
    let mut body = rest.trim().to_string();
    let mut fragment = None;
    if let Some(i) = body.find('#') {
        fragment = Some(percent_decode(&body[i + 1..]));
        body.truncate(i);
    }
    let mut query_text = String::new();
    if let Some(i) = body.find('?') {
        query_text = body[i + 1..].to_string();
        body.truncate(i);
    }
    while body.ends_with('/') {
        body.pop();
    }
    let (mut info, host_port) = if let Some(at) = body.rfind('@') {
        (body[..at].to_string(), body[at + 1..].to_string())
    } else {
        let text =
            String::from_utf8(decode_base64(&body).ok_or_else(invalid)?).map_err(|_| invalid())?;
        let mut text = text;
        if let Some(q) = text.find('?') {
            let inner = text[q + 1..].to_string();
            query_text = if query_text.is_empty() {
                inner
            } else {
                format!("{query_text}&{inner}")
            };
            text.truncate(q);
        }
        while text.ends_with('/') {
            text.pop();
        }
        let at = text.rfind('@').ok_or_else(invalid)?;
        (text[..at].to_string(), text[at + 1..].to_string())
    };
    info = percent_decode(&info);
    if !info.contains(':') {
        let text =
            String::from_utf8(decode_base64(&info).ok_or_else(invalid)?).map_err(|_| invalid())?;
        if !text.contains(':') {
            return Err(invalid());
        }
        info = text;
    }
    let (method, password) = info.split_once(':').ok_or_else(invalid)?;
    let mut method = method.trim().to_ascii_lowercase();
    if let Some((_, to)) = SS_ALIASES.iter().find(|(from, _)| *from == method) {
        method = (*to).to_string();
    }
    let query_part = if query_text.is_empty() {
        String::new()
    } else {
        format!("?{query_text}")
    };
    let mut parts = split(&format!("{host_port}{query_part}"))?;
    parts.fragment = fragment;
    let port = require_port(&parts)?;
    let mut h = base(node_name(&parts, "Shadowsocks"), "ss", &parts.host, port);
    set_str(&mut h, "cipher", method);
    set_str(&mut h, "password", password);
    let mut q = parts.query;
    if let Some(plugin) = q.get("plugin") {
        ss_plugin(&mut h, &plugin)?;
    }
    if q.flag("uot") || q.flag("udp-over-tcp") {
        set(&mut h, "udp-over-tcp", Yaml::Boolean(true));
        let version = q
            .get("uot-version")
            .or_else(|| q.get("udp-over-tcp-version"))
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(1);
        set(&mut h, "udp-over-tcp-version", Yaml::Integer(version));
    }
    q.udp(&mut h);
    q.ignore(&[
        "type",
        "group",
        "uot-version",
        "udp-over-tcp-version",
        "udp-relay",
        "shadow-tls",
    ]);
    q.finish()?;
    Ok(h)
}

pub(crate) fn ss_plugin(h: &mut Hash, text: &str) -> Result<(), String> {
    let mut pieces = text.split(';').filter(|s| !s.is_empty());
    let Some(name) = pieces.next() else {
        return Ok(());
    };
    let mut options: HashMap<String, String> = HashMap::new();
    for item in pieces {
        match item.split_once('=') {
            Some((k, v)) => options.insert(k.to_string(), v.to_string()),
            None => options.insert(item.to_string(), String::new()),
        };
    }
    let known = |allowed: &[&str]| -> Result<(), String> {
        match options.keys().find(|k| !allowed.contains(&k.as_str())) {
            Some(k) => Err(format!("unsupported plugin option `{k}`")),
            None => Ok(()),
        }
    };
    let mut opts = Hash::new();
    match name {
        "obfs-local" | "simple-obfs" | "obfs" => {
            let mode = options
                .get("obfs")
                .or_else(|| options.get("mode"))
                .cloned()
                .unwrap_or_else(|| "http".into());
            if mode != "http" && mode != "tls" {
                return Err(format!("unsupported obfs mode `{mode}`"));
            }
            known(&["obfs", "mode", "obfs-host", "host", "obfs-uri", "fast-open"])?;
            set_str(h, "plugin", "obfs");
            set_str(&mut opts, "mode", mode);
            set_str(
                &mut opts,
                "host",
                options
                    .get("obfs-host")
                    .or_else(|| options.get("host"))
                    .cloned()
                    .unwrap_or_default(),
            );
        }
        "v2ray-plugin" => {
            let mode = options
                .get("mode")
                .cloned()
                .unwrap_or_else(|| "websocket".into());
            if mode != "websocket" {
                return Err(format!("unsupported v2ray-plugin mode `{mode}`"));
            }
            known(&["mode", "tls", "host", "path", "mux", "fast-open"])?;
            set_str(h, "plugin", "v2ray-plugin");
            set_str(&mut opts, "mode", "websocket");
            set(&mut opts, "tls", Yaml::Boolean(options.contains_key("tls")));
            if let Some(host) = options.get("host").filter(|s| !s.is_empty()) {
                set_str(&mut opts, "host", host.clone());
            }
            set_str(
                &mut opts,
                "path",
                options.get("path").cloned().unwrap_or_else(|| "/".into()),
            );
            set(
                &mut opts,
                "mux",
                Yaml::Boolean(options.get("mux").is_none_or(|m| m != "0")),
            );
        }
        "shadow-tls" => {
            known(&["host", "password", "version", "alpn"])?;
            set_str(h, "plugin", "shadow-tls");
            set_str(
                &mut opts,
                "host",
                options.get("host").cloned().unwrap_or_default(),
            );
            set_str(
                &mut opts,
                "password",
                options.get("password").cloned().unwrap_or_default(),
            );
            set(
                &mut opts,
                "version",
                Yaml::Integer(
                    options
                        .get("version")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(3),
                ),
            );
            if let Some(alpn) = options.get("alpn") {
                set(&mut opts, "alpn", list(csv(alpn)));
            }
        }
        other => return Err(format!("unsupported plugin `{other}`")),
    }
    set(h, "plugin-opts", Yaml::Hash(opts));
    Ok(())
}

/// `server:port:protocol:method:obfs:base64(password)/?obfsparam=…&protoparam=…`
fn shadowsocks_r(rest: &str) -> Result<Hash, String> {
    let invalid = || "invalid ShadowsocksR link".to_string();
    let mut body = rest.to_string();
    let mut fragment = None;
    if let Some(i) = body.rfind('#') {
        fragment = Some(percent_decode(&body[i + 1..]));
        body.truncate(i);
    }
    let (main, query) = match body.find("/?") {
        Some(i) => (body[..i].to_string(), Some(body[i + 2..].to_string())),
        None => (body.clone(), None),
    };
    let main =
        String::from_utf8(decode_base64(&main).ok_or_else(invalid)?).map_err(|_| invalid())?;
    let fields: Vec<&str> = main.splitn(6, ':').collect();
    if fields.len() != 6 {
        return Err(invalid());
    }
    let port: u16 = fields[1].parse().map_err(|_| invalid())?;
    let password =
        String::from_utf8(decode_base64(fields[5]).ok_or_else(invalid)?).map_err(|_| invalid())?;
    if fields[0].is_empty() || port == 0 || password.is_empty() {
        return Err(invalid());
    }
    let name = fragment
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("ShadowsocksR {}", fields[0]));
    let mut h = base(name, "ssr", fields[0], port);
    set_str(&mut h, "cipher", fields[3]);
    set_str(&mut h, "password", password);
    set_str(&mut h, "protocol", fields[2]);
    set_str(&mut h, "obfs", fields[4]);
    if let Some(query) = query {
        let mut q = Query::new(&query);
        for (key, out) in [
            ("obfsparam", "obfs-param"),
            ("protoparam", "protocol-param"),
        ] {
            if let Some(text) = q
                .get(key)
                .and_then(|v| decode_base64(&v))
                .and_then(|b| String::from_utf8(b).ok())
            {
                set_str(&mut h, out, text);
            }
        }
        q.ignore(&["remarks", "group"]);
        q.finish()?;
    }
    Ok(h)
}

fn snell(rest: &str) -> Result<Hash, String> {
    let mut parts = split(rest)?;
    let port = require_port(&parts)?;
    let psk = parts
        .query
        .get("psk")
        .or_else(|| userinfo(&parts))
        .filter(|s| !s.is_empty())
        .ok_or("missing psk")?;
    let mut h = base(node_name(&parts, "Snell"), "snell", &parts.host, port);
    set_str(&mut h, "psk", psk);
    let q = &mut parts.query;
    let version: i64 = q.get("version").and_then(|v| v.parse().ok()).unwrap_or(4);
    if ![4, 5, 6].contains(&version) {
        return Err("unsupported Snell version".into());
    }
    set(&mut h, "version", Yaml::Integer(version));
    if let Some(mode) = q.get("mode").filter(|m| m != "default") {
        set_str(&mut h, "mode", mode);
    }
    let obfs = q.get("obfs").unwrap_or_else(|| "none".into());
    if obfs != "none" {
        let mut opts = Hash::new();
        set_str(&mut opts, "mode", obfs);
        if let Some(host) = q.get("obfs-host").or_else(|| q.get("host")) {
            set_str(&mut opts, "host", host);
        }
        set(&mut h, "obfs-opts", Yaml::Hash(opts));
    }
    // 链接显式写了 reuse 才写出（缺省开启，由配置解析决定）
    if q.get("reuse").is_some() {
        set(&mut h, "reuse", Yaml::Boolean(q.flag("reuse")));
    }
    q.ignore(&[
        "psk",
        "version",
        "mode",
        "obfs",
        "obfs-host",
        "host",
        "reuse",
        "remarks",
    ]);
    q.finish()?;
    Ok(h)
}

fn json_text(object: &serde_json::Value, key: &str) -> Option<String> {
    match object.get(key)? {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn vmess(rest: &str) -> Result<Hash, String> {
    let invalid = || "invalid VMess link".to_string();
    let mut body = rest.to_string();
    if let Some(i) = body.rfind('#') {
        body.truncate(i);
    }
    let data = decode_base64(&percent_decode(&body)).ok_or_else(invalid)?;
    let object: serde_json::Value = serde_json::from_slice(&data).map_err(|_| invalid())?;
    let host = json_text(&object, "add").ok_or_else(invalid)?;
    let port: u16 = json_text(&object, "port")
        .and_then(|p| p.parse().ok())
        .filter(|p| *p > 0)
        .ok_or_else(invalid)?;
    let name = json_text(&object, "ps").unwrap_or_else(|| format!("VMess {host}"));
    let mut h = base(name, "vmess", &host, port);
    set_str(&mut h, "uuid", json_text(&object, "id").unwrap_or_default());
    set(
        &mut h,
        "alterId",
        Yaml::Integer(
            json_text(&object, "aid")
                .and_then(|a| a.parse().ok())
                .unwrap_or(0),
        ),
    );
    let cipher = json_text(&object, "scy").unwrap_or_else(|| "auto".into());
    if ![
        "auto",
        "aes-128-gcm",
        "chacha20-poly1305",
        "none",
        "zero",
        "aes-128-cfb",
    ]
    .contains(&cipher.as_str())
    {
        return Err(format!("unsupported cipher `{cipher}`"));
    }
    set_str(&mut h, "cipher", cipher);
    let net = json_text(&object, "net")
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase();
    let host_header = json_text(&object, "host");
    let path = json_text(&object, "path");
    apply_transport(
        &mut h,
        &net,
        host_header.clone(),
        path.clone(),
        if net == "grpc" { path } else { None },
        json_text(&object, "type"),
        None,
    )?;
    if json_text(&object, "tls").is_some_and(|t| t.eq_ignore_ascii_case("tls")) {
        set(&mut h, "tls", Yaml::Boolean(true));
        let sni = json_text(&object, "sni").or_else(|| {
            matches!(net.as_str(), "ws" | "h2" | "httpupgrade")
                .then(|| host_header.clone())
                .flatten()
        });
        if let Some(sni) = sni {
            set_str(&mut h, "servername", sni);
        }
        if let Some(alpn) = json_text(&object, "alpn") {
            set(&mut h, "alpn", list(csv(&alpn)));
        }
        if let Some(fp) = json_text(&object, "fp").filter(|f| f != "none") {
            set_str(&mut h, "client-fingerprint", fp.to_ascii_lowercase());
        }
        if json_text(&object, "allowInsecure").is_some_and(|a| a == "1" || a == "true") {
            set(&mut h, "skip-cert-verify", Yaml::Boolean(true));
        }
    }
    let known = [
        "v",
        "ps",
        "add",
        "port",
        "id",
        "aid",
        "scy",
        "net",
        "type",
        "host",
        "path",
        "tls",
        "sni",
        "alpn",
        "fp",
        "allowInsecure",
        "insecure",
        "mode",
        "authority",
    ];
    if let Some(map) = object.as_object() {
        if let Some(extra) = map
            .keys()
            .find(|k| !known.contains(&k.as_str()) && json_text(&object, k).is_some())
        {
            return Err(format!("unsupported parameter `{extra}`"));
        }
    }
    Ok(h)
}

fn reality(h: &mut Hash, q: &mut Query) {
    let mut opts = Hash::new();
    set_str(&mut opts, "public-key", q.get("pbk").unwrap_or_default());
    set_str(&mut opts, "short-id", q.get("sid").unwrap_or_default());
    set(h, "reality-opts", Yaml::Hash(opts));
    if !h.contains_key(&st("client-fingerprint")) {
        set_str(h, "client-fingerprint", "chrome");
    }
    q.ignore(&["spx"]);
}

fn transport_from_query(h: &mut Hash, q: &mut Query) -> Result<(), String> {
    let ty = q.get("type").unwrap_or_else(|| "tcp".into());
    let (host, path, service, header, mode) = (
        q.get("host"),
        q.get("path"),
        q.get("serviceName"),
        q.get("headerType"),
        q.get("mode"),
    );
    apply_transport(h, &ty, host, path, service, header, mode)
}

fn vless(rest: &str) -> Result<Hash, String> {
    let mut parts = split(rest)?;
    let port = require_port(&parts)?;
    let uuid = userinfo(&parts)
        .filter(|s| !s.is_empty())
        .ok_or("missing UUID")?;
    let mut h = base(node_name(&parts, "VLESS"), "vless", &parts.host, port);
    set_str(&mut h, "uuid", uuid);
    let q = &mut parts.query;
    if let Some(enc) = q.get("encryption").filter(|e| e != "none") {
        set_str(&mut h, "encryption", enc);
    }
    if let Some(flow) = q.get("flow") {
        if flow != "xtls-rprx-vision" {
            return Err(format!("VLESS flow `{flow}` is not supported"));
        }
        set_str(&mut h, "flow", flow);
    }
    match q
        .get("security")
        .unwrap_or_else(|| "none".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "none" => {}
        "tls" => apply_tls(&mut h, q, "servername", true),
        "reality" => {
            apply_tls(&mut h, q, "servername", true);
            reality(&mut h, q);
        }
        other => return Err(format!("unsupported security `{other}`")),
    }
    transport_from_query(&mut h, q)?;
    if let Some(enc) = q.get("packetEncoding").filter(|e| e != "none") {
        set_str(&mut h, "packet-encoding", enc);
    }
    q.udp(&mut h);
    q.ignore(&[
        "allowInsecure",
        "insecure",
        "authority",
        "extra",
        "fp",
        "alpn",
        "sni",
        "peer",
    ]);
    q.finish()?;
    // ws / h2 / httpupgrade 且没有 sni 时用 Host 作为 SNI
    if h.contains_key(&st("tls")) && !h.contains_key(&st("servername")) {
        let host = h
            .get(&st("ws-opts"))
            .and_then(|o| match o {
                Yaml::Hash(o) => o.get(&st("headers")),
                _ => None,
            })
            .and_then(|hd| match hd {
                Yaml::Hash(hd) => hd
                    .get(&st("Host"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                _ => None,
            });
        if let Some(host) = host {
            set_str(&mut h, "servername", host);
        }
    }
    Ok(h)
}

fn trojan(rest: &str) -> Result<Hash, String> {
    let mut parts = split(rest)?;
    let port = require_port(&parts)?;
    let password = userinfo(&parts)
        .filter(|s| !s.is_empty())
        .ok_or("missing password")?;
    let mut h = base(node_name(&parts, "Trojan"), "trojan", &parts.host, port);
    set_str(&mut h, "password", password);
    let q = &mut parts.query;
    match q
        .get("security")
        .unwrap_or_else(|| "tls".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "tls" => apply_tls(&mut h, q, "sni", false),
        "reality" => {
            apply_tls(&mut h, q, "sni", false);
            reality(&mut h, q);
        }
        other => return Err(format!("unsupported security `{other}`")),
    }
    if let Some(flow) = q.get("flow") {
        return Err(format!("Trojan flow `{flow}` is not supported"));
    }
    transport_from_query(&mut h, q)?;
    q.udp(&mut h);
    q.ignore(&[
        "allowInsecure",
        "authority",
        "encryption",
        "sni",
        "peer",
        "alpn",
        "fp",
    ]);
    q.finish()?;
    Ok(h)
}

fn hysteria2(rest: &str) -> Result<Hash, String> {
    let mut parts = split(rest)?;
    let mut ports = String::new();
    // 端口位置可以是 `443,20000-30000`
    if parts.port.is_none() {
        if let Some(raw) = parts
            .raw_port
            .clone()
            .filter(|r| r.contains(',') || r.contains('-'))
        {
            ports = raw.clone();
            parts.port = raw.split([',', '-']).next().and_then(|p| p.parse().ok());
        }
    }
    let port = require_port(&parts)?;
    let mut h = base(
        node_name(&parts, "Hysteria2"),
        "hysteria2",
        &parts.host,
        port,
    );
    set_str(&mut h, "password", userinfo(&parts).unwrap_or_default());
    let q = &mut parts.query;
    apply_tls(&mut h, q, "sni", false);
    if let Some(obfs) = q.get("obfs") {
        if obfs != "salamander" {
            return Err(format!("unsupported obfuscation `{obfs}`"));
        }
        set_str(&mut h, "obfs", "salamander");
        set_str(
            &mut h,
            "obfs-password",
            q.get("obfs-password").unwrap_or_default(),
        );
    }
    if let Some(mport) = q.get("mport").or_else(|| q.get("ports")) {
        ports = mport;
    }
    if !ports.is_empty() {
        set_str(&mut h, "ports", ports);
    }
    if let Some(up) = q.get("up") {
        set_str(&mut h, "up", up);
    }
    if let Some(down) = q.get("down") {
        set_str(&mut h, "down", down);
    }
    q.udp(&mut h);
    q.ignore(&[
        "insecure",
        "allowInsecure",
        "sni",
        "alpn",
        "pinSHA256",
        "obfs-password",
        "name",
    ]);
    q.finish()?;
    Ok(h)
}

fn tuic(rest: &str) -> Result<Hash, String> {
    let mut parts = split(rest)?;
    let port = require_port(&parts)?;
    let info = userinfo(&parts).ok_or("invalid TUIC link")?;
    let (uuid, password) = info.split_once(':').ok_or("invalid TUIC link")?;
    let mut h = base(node_name(&parts, "TUIC"), "tuic", &parts.host, port);
    set_str(&mut h, "uuid", uuid);
    set_str(&mut h, "password", password);
    let q = &mut parts.query;
    apply_tls(&mut h, q, "sni", false);
    if let Some(cc) = q
        .get("congestion_control")
        .or_else(|| q.get("congestion-controller"))
    {
        set_str(&mut h, "congestion-controller", cc);
    }
    if let Some(mode) = q.get("udp_relay_mode").or_else(|| q.get("udp-relay-mode")) {
        set_str(&mut h, "udp-relay-mode", mode);
    }
    if q.flag("disable_sni") || q.flag("disable-sni") {
        set(&mut h, "disable-sni", Yaml::Boolean(true));
    }
    q.udp(&mut h);
    q.ignore(&[
        "sni",
        "alpn",
        "allow_insecure",
        "allowInsecure",
        "insecure",
        "udp_over_stream",
        "heartbeat",
        "zero_rtt_handshake",
        "reduce_rtt",
        "congestion_control",
    ]);
    q.finish()?;
    Ok(h)
}

fn anytls(rest: &str) -> Result<Hash, String> {
    let mut parts = split(rest)?;
    let port = require_port(&parts)?;
    let password = userinfo(&parts)
        .filter(|s| !s.is_empty())
        .ok_or("missing password")?;
    let mut h = base(node_name(&parts, "AnyTLS"), "anytls", &parts.host, port);
    set_str(&mut h, "password", password);
    let q = &mut parts.query;
    apply_tls(&mut h, q, "sni", false);
    q.udp(&mut h);
    q.ignore(&["insecure", "allowInsecure", "sni", "alpn", "fp"]);
    q.finish()?;
    Ok(h)
}

fn credentials(h: &mut Hash, info: Option<String>) {
    if let Some((user, pass)) = info.as_deref().and_then(|i| i.split_once(':')) {
        set_str(h, "username", user);
        set_str(h, "password", pass);
    }
}

fn socks(rest: &str) -> Result<Hash, String> {
    let mut parts = split(rest)?;
    if let Some(info) = parts.userinfo.clone().filter(|i| !i.contains(':')) {
        if let Some(text) =
            decode_base64(&percent_decode(&info)).and_then(|b| String::from_utf8(b).ok())
        {
            if text.contains(':') {
                parts.userinfo = Some(text);
            }
        }
    }
    let port = require_port(&parts)?;
    let mut h = base(node_name(&parts, "SOCKS5"), "socks5", &parts.host, port);
    credentials(&mut h, userinfo(&parts));
    parts.query.ignore(&["remarks", "udp"]);
    parts.query.finish()?;
    Ok(h)
}

fn http(rest: &str, tls: bool) -> Result<Hash, String> {
    let mut parts = split(rest)?;
    let port = require_port(&parts)?;
    let mut h = base(node_name(&parts, "HTTP"), "http", &parts.host, port);
    h.remove(&st("udp"));
    credentials(&mut h, userinfo(&parts));
    if tls {
        apply_tls(&mut h, &mut parts.query, "sni", true);
    }
    parts
        .query
        .ignore(&["remarks", "sni", "allowInsecure", "insecure"]);
    parts.query.finish()?;
    let _ = &parts.path;
    Ok(h)
}
