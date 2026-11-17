//! sing-box 订阅：把 JSON 里的 `outbounds`（以及 1.11 起放在 `endpoints` 里的 WireGuard）转换成
//! mihomo 风格的节点，之后与 YAML 里的节点走同一个解析器。只取节点；`route`、`dns`、`selector` 等不转换。
//! 与分享链接一致：带有无法表示的字段的出站整条跳过并给出原因，不静默丢字段。
//! App 的 `OrynImport/SingBoxOutbounds.swift` 是同一套规则，两边需同步。见 docs/plan-singbox-subscription.md。

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};
use yaml_rust2::yaml::Hash;
use yaml_rust2::Yaml;

use crate::links::{ss_plugin, Parsed, MAX_LINKS};

/// 不是节点的出站类型，静默跳过。
const NOT_NODES: [&str; 5] = ["direct", "block", "dns", "selector", "urltest"];

/// 拨号相关、与连接语义无关的字段，忽略。
const DIAL_FIELDS: [&str; 21] = [
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "bind_address_no_port",
    "routing_mark",
    "reuse_addr",
    "netns",
    "connect_timeout",
    "tcp_fast_open",
    "tcp_multi_path",
    "udp_fragment",
    "domain_strategy",
    "domain_resolver",
    "fallback_delay",
    "network_strategy",
    "network_type",
    "fallback_network_type",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "protect_path",
];

/// 内容是 sing-box 配置（或出站数组）时返回节点；不是时返回 `None`。
pub fn parse_outbounds(text: &str) -> Option<Parsed> {
    let trimmed = text.trim();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return None;
    }
    let root: Value = serde_json::from_str(trimmed).ok()?;
    let items: Vec<&Value> = match &root {
        Value::Object(o) => {
            let outbounds = o.get("outbounds").and_then(Value::as_array);
            let endpoints = o.get("endpoints").and_then(Value::as_array);
            if outbounds.is_none() && endpoints.is_none() {
                return None;
            }
            outbounds.into_iter().chain(endpoints).flatten().collect()
        }
        Value::Array(a) => {
            if a.is_empty()
                || !a
                    .iter()
                    .all(|v| v.get("type").is_some_and(Value::is_string))
            {
                return None;
            }
            a.iter().collect()
        }
        _ => return None,
    };
    let by_tag: HashMap<&str, &Map<String, Value>> = items
        .iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            Some((o.get("tag")?.as_str()?, o))
        })
        .collect();
    // 被 Shadowsocks 经 detour 引用的 shadowtls 合并进该节点，不单独成为节点
    let consumed: HashSet<&str> = items
        .iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            if o.get("type")?.as_str()? != "shadowsocks" {
                return None;
            }
            let detour = o.get("detour")?.as_str()?;
            (type_of(by_tag.get(detour)?) == "shadowtls").then_some(detour)
        })
        .collect();

    let mut nodes = Vec::new();
    let mut warnings = Vec::new();
    for (n, item) in items.iter().enumerate() {
        let Some(o) = item.as_object() else {
            warnings.push(format!("outbound {}: not an object", n + 1));
            continue;
        };
        let ty = type_of(o);
        let tag = o.get("tag").and_then(Value::as_str).unwrap_or("");
        if NOT_NODES.contains(&ty) || (ty == "shadowtls" && consumed.contains(tag)) {
            continue;
        }
        if nodes.len() + warnings.len() >= MAX_LINKS {
            warnings.push(format!("only the first {MAX_LINKS} outbounds are used"));
            break;
        }
        match outbound(o, &by_tag) {
            Ok(h) => nodes.push(Yaml::Hash(h)),
            Err(e) if tag.is_empty() => warnings.push(format!("outbound {}: {e}", n + 1)),
            Err(e) => warnings.push(format!("outbound `{tag}`: {e}")),
        }
    }
    Some(Parsed { nodes, warnings })
}

fn type_of(o: &Map<String, Value>) -> &str {
    o.get("type").and_then(Value::as_str).unwrap_or("")
}

// MARK: 工具

/// 一个 JSON 对象。读过的键被记下，剩下的未知键用来拒绝带有无法表示字段的出站。
struct Obj<'a> {
    map: &'a Map<String, Value>,
    used: HashSet<&'a str>,
    /// 报错时键名的前缀，如 `tls.`。
    prefix: &'static str,
}

impl<'a> Obj<'a> {
    fn new(map: &'a Map<String, Value>, prefix: &'static str) -> Self {
        Obj {
            map,
            used: HashSet::new(),
            prefix,
        }
    }

    fn child(value: &'a Value, prefix: &'static str) -> Result<Self, String> {
        value
            .as_object()
            .map(|m| Obj::new(m, prefix))
            .ok_or_else(|| format!("`{}` is not an object", prefix.trim_end_matches('.')))
    }

    fn get(&mut self, key: &'a str) -> Option<&'a Value> {
        self.used.insert(key);
        self.map.get(key).filter(|v| !v.is_null())
    }

    fn str(&mut self, key: &'a str) -> Option<String> {
        match self.get(key)? {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }

    fn bool(&mut self, key: &'a str) -> Option<bool> {
        self.get(key)?.as_bool()
    }

    fn int(&mut self, key: &'a str) -> Option<i64> {
        match self.get(key)? {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    /// 字符串或字符串数组。
    fn strings(&mut self, key: &'a str) -> Vec<String> {
        match self.get(key) {
            Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Go 风格的时长（`30s`、`1m30s`、`500ms`）或秒数，返回毫秒。
    fn duration_ms(&mut self, key: &'a str) -> Result<Option<u64>, String> {
        let Some(v) = self.get(key) else {
            return Ok(None);
        };
        let ms = match v {
            Value::Number(n) => n.as_u64().map(|s| s.saturating_mul(1000)),
            Value::String(s) => parse_duration_ms(s),
            _ => None,
        };
        ms.map(Some)
            .ok_or_else(|| format!("invalid `{}{key}`", self.prefix))
    }

    fn ignore(&mut self, keys: &[&'a str]) {
        self.used.extend(keys.iter().copied());
    }

    fn finish(&self) -> Result<(), String> {
        match self
            .map
            .iter()
            .find(|(k, v)| !v.is_null() && !self.used.contains(k.as_str()))
        {
            Some((k, _)) => Err(format!("unsupported field `{}{k}`", self.prefix)),
            None => Ok(()),
        }
    }
}

fn parse_duration_ms(text: &str) -> Option<u64> {
    let s = text.trim();
    if let Ok(secs) = s.parse::<u64>() {
        return Some(secs.saturating_mul(1000));
    }
    let mut total = 0f64;
    let mut rest = s;
    while !rest.is_empty() {
        let split = rest.find(|c: char| !c.is_ascii_digit() && c != '.')?;
        let num: f64 = rest[..split].parse().ok()?;
        rest = &rest[split..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let factor = match &rest[..unit_len] {
            "ms" => 1.0,
            "s" => 1000.0,
            "m" => 60_000.0,
            "h" => 3_600_000.0,
            _ => return None,
        };
        total += num * factor;
        rest = &rest[unit_len..];
    }
    (total.is_finite() && total >= 0.0).then_some(total as u64)
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

fn mbps(n: i64) -> Yaml {
    st(format!("{n} Mbps"))
}

/// `["20000:30000", "443"]` → `20000-30000,443`
fn port_ranges(ranges: &[String]) -> String {
    ranges
        .iter()
        .map(|r| r.replace(':', "-"))
        .collect::<Vec<_>>()
        .join(",")
}

// MARK: 出站

fn mihomo_type(ty: &str) -> Option<&'static str> {
    Some(match ty {
        "shadowsocks" => "ss",
        "socks" => "socks5",
        "http" => "http",
        "vmess" => "vmess",
        "vless" => "vless",
        "trojan" => "trojan",
        "hysteria" => "hysteria",
        "hysteria2" => "hysteria2",
        "tuic" => "tuic",
        "anytls" => "anytls",
        "naive" => "naive",
        "ssh" => "ssh",
        "snell" => "snell",
        "wireguard" => "wireguard",
        _ => return None,
    })
}

fn outbound(
    o: &Map<String, Value>,
    by_tag: &HashMap<&str, &Map<String, Value>>,
) -> Result<Hash, String> {
    let mut f = Obj::new(o, "");
    let ty = f.str("type").unwrap_or_default();
    let Some(kind) = mihomo_type(&ty) else {
        return Err(format!("the `{ty}` type is not supported"));
    };
    let tag = f.str("tag");
    f.ignore(&DIAL_FIELDS);
    if kind == "wireguard" {
        return wireguard(f, tag);
    }

    let server = f.str("server").ok_or("missing server")?;
    // Hysteria 系的 server_ports 与 server_port 互斥（sing-box 的规定）；有端口段时只写 `ports`
    let ranges = if kind.starts_with("hysteria") {
        f.strings("server_ports")
    } else {
        Vec::new()
    };
    let port = f.int("server_port");
    if ranges.is_empty() && !port.is_some_and(|p| (1..=65535).contains(&p)) {
        return Err("the port must be between 1 and 65535".into());
    }
    let udp = match f.str("network").as_deref() {
        None | Some("") => true,
        Some("tcp") => false,
        Some(other) => return Err(format!("network `{other}` is not supported")),
    };

    let mut h = Hash::new();
    set_str(
        &mut h,
        "name",
        tag.unwrap_or_else(|| format!("{ty} {server}")),
    );
    set_str(&mut h, "type", kind);
    set_str(&mut h, "server", server);
    if ranges.is_empty() {
        set(&mut h, "port", Yaml::Integer(port.unwrap_or(0)));
    }
    if !matches!(kind, "http" | "ssh") {
        set(&mut h, "udp", Yaml::Boolean(udp));
    }
    let mut detour = f.str("detour");

    match kind {
        "ss" => {
            set_str(&mut h, "cipher", f.str("method").ok_or("missing method")?);
            set_str(
                &mut h,
                "password",
                f.str("password").ok_or("missing password")?,
            );
            if let Some(plugin) = f.str("plugin") {
                let opts = f.str("plugin_opts").unwrap_or_default();
                ss_plugin(&mut h, &format!("{plugin};{opts}"))?;
            }
            match f.get("udp_over_tcp") {
                Some(Value::Bool(true)) => set(&mut h, "udp-over-tcp", Yaml::Boolean(true)),
                Some(Value::Object(m)) => {
                    let mut u = Obj::new(m, "udp_over_tcp.");
                    if u.bool("enabled") == Some(true) {
                        set(&mut h, "udp-over-tcp", Yaml::Boolean(true));
                        if let Some(v) = u.int("version") {
                            set(&mut h, "udp-over-tcp-version", Yaml::Integer(v));
                        }
                    }
                    u.ignore(&["version"]);
                    u.finish()?;
                }
                _ => {}
            }
            multiplex(&mut f, &mut h)?;
            if let Some(stls) = detour
                .as_deref()
                .and_then(|d| by_tag.get(d))
                .filter(|m| type_of(m) == "shadowtls")
            {
                if h.contains_key(&st("plugin")) {
                    return Err("a plugin cannot be combined with a shadowtls detour".into());
                }
                detour = shadow_tls(stls, &mut h)?;
            }
        }
        "vmess" => {
            set_str(&mut h, "uuid", f.str("uuid").ok_or("missing uuid")?);
            set_str(
                &mut h,
                "cipher",
                f.str("security").unwrap_or_else(|| "auto".into()),
            );
            set(
                &mut h,
                "alterId",
                Yaml::Integer(f.int("alter_id").unwrap_or(0)),
            );
            if f.bool("global_padding") == Some(true) {
                set(&mut h, "global-padding", Yaml::Boolean(true));
            }
            if f.bool("authenticated_length") == Some(true) {
                set(&mut h, "authenticated-length", Yaml::Boolean(true));
            }
            packet_encoding(&mut f, &mut h)?;
            let tls = tls(&mut f, &mut h, "servername", true, false)?;
            transport(&mut f, &mut h, tls)?;
            multiplex(&mut f, &mut h)?;
        }
        "vless" => {
            set_str(&mut h, "uuid", f.str("uuid").ok_or("missing uuid")?);
            if let Some(flow) = f.str("flow") {
                set_str(&mut h, "flow", flow);
            }
            packet_encoding(&mut f, &mut h)?;
            let tls = tls(&mut f, &mut h, "servername", true, false)?;
            transport(&mut f, &mut h, tls)?;
            multiplex(&mut f, &mut h)?;
        }
        "trojan" => {
            set_str(
                &mut h,
                "password",
                f.str("password").ok_or("missing password")?,
            );
            tls(&mut f, &mut h, "sni", false, true)?;
            transport(&mut f, &mut h, true)?;
            multiplex(&mut f, &mut h)?;
        }
        "hysteria2" => {
            if let Some(password) = f.str("password") {
                set_str(&mut h, "password", password);
            }
            hysteria_common(&mut f, &mut h, &ranges)?;
            if let Some(v) = f.get("obfs") {
                let mut o = Obj::child(v, "obfs.")?;
                if let Some(ty) = o.str("type") {
                    set_str(&mut h, "obfs", ty);
                    set_str(
                        &mut h,
                        "obfs-password",
                        o.str("password").unwrap_or_default(),
                    );
                }
                o.ignore(&["password"]);
                o.finish()?;
            }
            f.ignore(&["brutal_debug"]);
            tls(&mut f, &mut h, "sni", false, true)?;
        }
        "hysteria" => {
            hysteria_common(&mut f, &mut h, &ranges)?;
            for (from, to) in [("up", "up"), ("down", "down")] {
                if let Some(v) = f.str(from) {
                    set_str(&mut h, to, v);
                }
            }
            if let Some(obfs) = f.str("obfs") {
                set_str(&mut h, "obfs", obfs);
            }
            if let Some(auth) = f.str("auth") {
                set_str(&mut h, "auth", auth);
            }
            if let Some(auth) = f.str("auth_str") {
                set_str(&mut h, "auth-str", auth);
            }
            for (from, to) in [
                ("recv_window_conn", "recv-window-conn"),
                ("recv_window", "recv-window"),
            ] {
                if let Some(v) = f.int(from) {
                    set(&mut h, to, Yaml::Integer(v));
                }
            }
            f.ignore(&["disable_mtu_discovery"]);
            tls(&mut f, &mut h, "sni", false, true)?;
        }
        "tuic" => {
            set_str(&mut h, "uuid", f.str("uuid").ok_or("missing uuid")?);
            if let Some(password) = f.str("password") {
                set_str(&mut h, "password", password);
            }
            if let Some(cc) = f.str("congestion_control") {
                set_str(&mut h, "congestion-controller", cc);
            }
            if let Some(mode) = f.str("udp_relay_mode") {
                set_str(&mut h, "udp-relay-mode", mode);
            }
            if f.bool("udp_over_stream") == Some(true) {
                set(&mut h, "udp-over-stream", Yaml::Boolean(true));
            }
            if f.bool("zero_rtt_handshake") == Some(true) {
                set(&mut h, "reduce-rtt", Yaml::Boolean(true));
            }
            if let Some(ms) = f.duration_ms("heartbeat")? {
                set(&mut h, "heartbeat-interval", Yaml::Integer(ms as i64));
            }
            tls(&mut f, &mut h, "sni", false, true)?;
        }
        "anytls" => {
            set_str(
                &mut h,
                "password",
                f.str("password").ok_or("missing password")?,
            );
            for (from, to) in [
                ("idle_session_check_interval", "idle-session-check-interval"),
                ("idle_session_timeout", "idle-session-timeout"),
            ] {
                if let Some(ms) = f.duration_ms(from)? {
                    set(&mut h, to, Yaml::Integer((ms / 1000) as i64));
                }
            }
            if let Some(n) = f.int("min_idle_session") {
                set(&mut h, "min-idle-session", Yaml::Integer(n));
            }
            tls(&mut f, &mut h, "sni", false, true)?;
        }
        "socks5" => {
            if let Some(v) = f.str("version").filter(|v| v != "5") {
                return Err(format!("SOCKS version {v} is not supported"));
            }
            credentials(&mut f, &mut h, "username");
            let uot = match f.get("udp_over_tcp") {
                Some(Value::Bool(b)) => *b,
                Some(Value::Object(m)) => m.get("enabled").and_then(Value::as_bool) == Some(true),
                _ => false,
            };
            if uot {
                return Err("SOCKS UDP over TCP is not supported".into());
            }
        }
        "http" => {
            credentials(&mut f, &mut h, "username");
            if let Some(path) = f.str("path").filter(|p| p != "/") {
                return Err(format!("the HTTP proxy path `{path}` is not supported"));
            }
            headers(&mut f, &mut h, "headers", "headers")?;
            tls(&mut f, &mut h, "sni", true, false)?;
        }
        "naive" => {
            credentials(&mut f, &mut h, "username");
            headers(&mut f, &mut h, "extra_headers", "headers")?;
            // naive 的 UDP 只能经 UoT
            set(&mut h, "udp", Yaml::Boolean(false));
            match f.get("udp_over_tcp") {
                Some(Value::Bool(true)) => set(&mut h, "udp", Yaml::Boolean(udp)),
                Some(Value::Object(m)) => {
                    let mut u = Obj::new(m, "udp_over_tcp.");
                    if u.bool("enabled") == Some(true) {
                        set(&mut h, "udp", Yaml::Boolean(udp));
                        if let Some(v) = u.int("version") {
                            set(&mut h, "udp-over-tcp-version", Yaml::Integer(v));
                        }
                    }
                    u.ignore(&["version"]);
                    u.finish()?;
                }
                _ => {}
            }
            if f.bool("quic") == Some(true) {
                set(&mut h, "quic", Yaml::Boolean(true));
            }
            f.ignore(&["insecure_concurrency", "quic_congestion_control"]);
            tls(&mut f, &mut h, "sni", false, true)?;
        }
        "ssh" => {
            credentials(&mut f, &mut h, "user");
            let key = f.strings("private_key");
            if !key.is_empty() {
                set_str(&mut h, "private-key", key.join("\n"));
            }
            if let Some(p) = f.str("private_key_passphrase") {
                set_str(&mut h, "private-key-passphrase", p);
            }
            for (from, to) in [
                ("host_key", "host-key"),
                ("host_key_algorithms", "host-key-algorithms"),
            ] {
                let items = f.strings(from);
                if !items.is_empty() {
                    set(&mut h, to, list(items));
                }
            }
            f.ignore(&["client_version"]);
        }
        // 上游 sing-box 没有 Snell；这是 ob-sb 等分支的写法（v4–v6，`obfs_mode` / `obfs_host` 只用于 v4 / v5）
        "snell" => {
            set_str(&mut h, "psk", f.str("psk").ok_or("missing psk")?);
            if let Some(v) = f.int("version") {
                set(&mut h, "version", Yaml::Integer(v));
            }
            if let Some(mode) = f.str("obfs_mode").filter(|m| m != "none") {
                let mut opts = Hash::new();
                set_str(&mut opts, "mode", mode);
                if let Some(host) = f.str("obfs_host") {
                    set_str(&mut opts, "host", host);
                }
                set(&mut h, "obfs-opts", Yaml::Hash(opts));
            }
            f.ignore(&["obfs_host"]);
            if let Some(mode) = f.str("mode").filter(|m| m != "default") {
                set_str(&mut h, "mode", mode);
            }
            if let Some(reuse) = f.bool("reuse") {
                set(&mut h, "reuse", Yaml::Boolean(reuse));
            }
            if f.str("userkey").is_some() {
                return Err("Snell userkey is not supported".into());
            }
        }
        _ => unreachable!("mapped above"),
    }
    if let Some(d) = detour {
        set_str(&mut h, "dialer-proxy", d);
    }
    f.finish()?;
    Ok(h)
}

/// `username` / `password`。sing-box 的 SSH 用户名键是 `user`。
fn credentials(f: &mut Obj, h: &mut Hash, user_key: &'static str) {
    if let Some(user) = f.str(user_key) {
        set_str(h, "username", user);
    }
    if let Some(password) = f.str("password") {
        set_str(h, "password", password);
    }
}

fn packet_encoding(f: &mut Obj, h: &mut Hash) -> Result<(), String> {
    match f.str("packet_encoding").as_deref() {
        None => Ok(()),
        Some(e @ ("xudp" | "packetaddr")) => {
            set_str(h, "packet-encoding", e);
            Ok(())
        }
        Some(other) => Err(format!("packet_encoding `{other}` is not supported")),
    }
}

/// 请求头：值可以是字符串或数组（取第一个）。
fn headers<'a>(f: &mut Obj<'a>, h: &mut Hash, from: &'a str, to: &str) -> Result<(), String> {
    let Some(v) = f.get(from) else {
        return Ok(());
    };
    let map = v
        .as_object()
        .ok_or_else(|| format!("`{from}` is not an object"))?;
    let mut out = Hash::new();
    for (k, v) in map {
        let value = match v {
            Value::String(s) => s.clone(),
            Value::Array(a) => a.iter().find_map(Value::as_str).unwrap_or("").to_string(),
            _ => return Err(format!("invalid header `{k}`")),
        };
        set_str(&mut out, k, value);
    }
    if !out.is_empty() {
        set(h, to, Yaml::Hash(out));
    }
    Ok(())
}

/// Hysteria / Hysteria2 共有的端口跳跃与带宽字段。
fn hysteria_common(f: &mut Obj, h: &mut Hash, ranges: &[String]) -> Result<(), String> {
    if !ranges.is_empty() {
        set_str(h, "ports", port_ranges(ranges));
    }
    if let Some(ms) = f.duration_ms("hop_interval")? {
        set(h, "hop-interval", Yaml::Integer((ms / 1000).max(1) as i64));
    }
    if let Some(n) = f.int("up_mbps") {
        set(h, "up", mbps(n));
    }
    if let Some(n) = f.int("down_mbps") {
        set(h, "down", mbps(n));
    }
    Ok(())
}

/// TLS 字段，返回是否启用。`sni_key`：vless / vmess 用 `servername`，其它用 `sni`；
/// `flag` 为真时写出 `tls: true`；`required` 为真时没有启用 TLS 即报错。
fn tls(
    f: &mut Obj,
    h: &mut Hash,
    sni_key: &str,
    flag: bool,
    required: bool,
) -> Result<bool, String> {
    let enabled = match f.get("tls") {
        Some(v) => {
            let mut t = Obj::child(v, "tls.")?;
            if t.bool("enabled") == Some(true) {
                tls_fields(&mut t, h, sni_key, flag)?;
                true
            } else {
                false
            }
        }
        None => false,
    };
    if required && !enabled {
        return Err("TLS must be enabled".into());
    }
    Ok(enabled)
}

fn tls_fields(t: &mut Obj, h: &mut Hash, sni_key: &str, flag: bool) -> Result<(), String> {
    if flag {
        set(h, "tls", Yaml::Boolean(true));
    }
    if let Some(sni) = t.str("server_name") {
        set_str(h, sni_key, sni);
    }
    if t.bool("insecure") == Some(true) {
        set(h, "skip-cert-verify", Yaml::Boolean(true));
    }
    let alpn = t.strings("alpn");
    if !alpn.is_empty() {
        set(h, "alpn", list(alpn));
    }
    if t.bool("disable_sni") == Some(true) {
        if h.get(&st("type")) != Some(&st("tuic")) {
            return Err("`tls.disable_sni` is not supported".into());
        }
        set(h, "disable-sni", Yaml::Boolean(true));
    }
    // 版本与密码套件由 Oryn 的 TLS 栈决定；分片是抗审查的可选行为
    t.ignore(&[
        "min_version",
        "max_version",
        "cipher_suites",
        "curve_preferences",
        "fragment",
        "fragment_fallback_delay",
        "record_fragment",
    ]);
    if let Some(v) = t.get("utls") {
        let mut u = Obj::child(v, "tls.utls.")?;
        if u.bool("enabled") == Some(true) {
            let fp = u.str("fingerprint").unwrap_or_else(|| "chrome".into());
            set_str(h, "client-fingerprint", fp.to_ascii_lowercase());
        }
        u.ignore(&["fingerprint"]);
        u.finish()?;
    }
    if let Some(v) = t.get("reality") {
        let mut r = Obj::child(v, "tls.reality.")?;
        if r.bool("enabled") == Some(true) {
            let mut opts = Hash::new();
            set_str(
                &mut opts,
                "public-key",
                r.str("public_key")
                    .ok_or("missing tls.reality.public_key")?,
            );
            if let Some(id) = r.str("short_id") {
                set_str(&mut opts, "short-id", id);
            }
            set(h, "reality-opts", Yaml::Hash(opts));
        }
        r.ignore(&["public_key", "short_id"]);
        r.finish()?;
    }
    if let Some(v) = t.get("ech") {
        let mut e = Obj::child(v, "tls.ech.")?;
        if e.bool("enabled") == Some(true) {
            // PEM：去掉 BEGIN / END 行，剩下的是 ECHConfigList 的 Base64
            let config: String = e
                .strings("config")
                .iter()
                .flat_map(|s| s.lines())
                .map(str::trim)
                .filter(|l| !l.starts_with("-----"))
                .collect();
            if config.is_empty() {
                return Err("`tls.ech` needs an inline config".into());
            }
            let mut opts = Hash::new();
            set(&mut opts, "enable", Yaml::Boolean(true));
            set_str(&mut opts, "config", config);
            set(h, "ech-opts", Yaml::Hash(opts));
        }
        e.ignore(&[
            "config",
            "pq_signature_schemes_enabled",
            "dynamic_record_sizing_disabled",
        ]);
        e.finish()?;
    }
    t.finish()
}

/// V2Ray 传输层。`tls`：外层是否启用 TLS（`http` 传输需要）。
fn transport(f: &mut Obj, h: &mut Hash, tls: bool) -> Result<(), String> {
    let Some(v) = f.get("transport") else {
        return Ok(());
    };
    let mut t = Obj::child(v, "transport.")?;
    let ty = t.str("type").unwrap_or_default();
    match ty.as_str() {
        "ws" | "httpupgrade" => {
            set_str(h, "network", "ws");
            let mut opts = Hash::new();
            set_str(
                &mut opts,
                "path",
                t.str("path").unwrap_or_else(|| "/".into()),
            );
            let mut hdrs = Hash::new();
            headers(&mut t, &mut hdrs, "headers", "headers")?;
            if let Some(host) = t.str("host").filter(|_| ty == "httpupgrade") {
                let mut map = match hdrs.remove(&st("headers")) {
                    Some(Yaml::Hash(m)) => m,
                    _ => Hash::new(),
                };
                set_str(&mut map, "Host", host);
                set(&mut hdrs, "headers", Yaml::Hash(map));
            }
            if let Some(v) = hdrs.remove(&st("headers")) {
                set(&mut opts, "headers", v);
            }
            if ty == "ws" {
                if let Some(n) = t.int("max_early_data").filter(|n| *n > 0) {
                    set(&mut opts, "max-early-data", Yaml::Integer(n));
                }
                if let Some(name) = t.str("early_data_header_name") {
                    set_str(&mut opts, "early-data-header-name", name);
                }
            } else {
                set(&mut opts, "v2ray-http-upgrade", Yaml::Boolean(true));
            }
            set(h, "ws-opts", Yaml::Hash(opts));
        }
        "grpc" => {
            set_str(h, "network", "grpc");
            let mut opts = Hash::new();
            set_str(
                &mut opts,
                "grpc-service-name",
                t.str("service_name").unwrap_or_default(),
            );
            set(h, "grpc-opts", Yaml::Hash(opts));
            t.ignore(&["idle_timeout", "ping_timeout", "permit_without_stream"]);
        }
        "http" => {
            if !tls {
                return Err("the http transport without TLS is not supported".into());
            }
            set_str(h, "network", "h2");
            let mut opts = Hash::new();
            let hosts = t.strings("host");
            if !hosts.is_empty() {
                set(&mut opts, "host", list(hosts));
            }
            set_str(
                &mut opts,
                "path",
                t.str("path").unwrap_or_else(|| "/".into()),
            );
            set(h, "h2-opts", Yaml::Hash(opts));
            t.ignore(&["idle_timeout", "ping_timeout"]);
        }
        "quic" => set_str(h, "network", "quic"),
        other => return Err(format!("the `{other}` transport is not supported")),
    }
    t.finish()
}

fn multiplex(f: &mut Obj, h: &mut Hash) -> Result<(), String> {
    let Some(v) = f.get("multiplex") else {
        return Ok(());
    };
    let mut m = Obj::child(v, "multiplex.")?;
    m.ignore(&[
        "protocol",
        "max_connections",
        "min_streams",
        "max_streams",
        "padding",
        "brutal",
    ]);
    if m.bool("enabled") != Some(true) {
        return m.finish();
    }
    let mut opts = Hash::new();
    set(&mut opts, "enabled", Yaml::Boolean(true));
    // sing-box 的缺省协议是 h2mux，mihomo 的缺省是 smux
    set_str(
        &mut opts,
        "protocol",
        m.str("protocol").unwrap_or_else(|| "h2mux".into()),
    );
    for (from, to) in [
        ("max_connections", "max-connections"),
        ("min_streams", "min-streams"),
        ("max_streams", "max-streams"),
    ] {
        if let Some(n) = m.int(from).filter(|n| *n > 0) {
            set(&mut opts, to, Yaml::Integer(n));
        }
    }
    if m.bool("padding") == Some(true) {
        set(&mut opts, "padding", Yaml::Boolean(true));
    }
    if let Some(v) = m.get("brutal") {
        let mut b = Obj::child(v, "multiplex.brutal.")?;
        b.ignore(&["up_mbps", "down_mbps"]);
        if b.bool("enabled") == Some(true) {
            let mut brutal = Hash::new();
            set(&mut brutal, "enabled", Yaml::Boolean(true));
            set(&mut brutal, "up", mbps(b.int("up_mbps").unwrap_or(0)));
            set(&mut brutal, "down", mbps(b.int("down_mbps").unwrap_or(0)));
            set(&mut opts, "brutal-opts", Yaml::Hash(brutal));
        }
        b.finish()?;
    }
    set(h, "smux", Yaml::Hash(opts));
    m.finish()
}

/// 把 Shadowsocks 经 detour 引用的 shadowtls 出站合并为 `plugin: shadow-tls`：
/// 服务器与端口换成 shadowtls 的，返回 shadowtls 自己的 detour。
fn shadow_tls(o: &Map<String, Value>, h: &mut Hash) -> Result<Option<String>, String> {
    let mut s = Obj::new(o, "shadowtls.");
    s.ignore(&["type", "tag"]);
    s.ignore(&DIAL_FIELDS);
    let server = s.str("server").ok_or("missing shadowtls server")?;
    let port = s
        .int("server_port")
        .filter(|p| (1..=65535).contains(p))
        .ok_or("invalid shadowtls port")?;
    set_str(h, "server", server);
    set(h, "port", Yaml::Integer(port));
    let mut opts = Hash::new();
    let mut tls_on = false;
    if let Some(v) = s.get("tls") {
        let mut t = Obj::child(v, "shadowtls.tls.")?;
        tls_on = t.bool("enabled") == Some(true);
        if let Some(host) = t.str("server_name") {
            set_str(&mut opts, "host", host);
        }
        if t.bool("insecure") == Some(true) {
            set(&mut opts, "skip-cert-verify", Yaml::Boolean(true));
        }
        let alpn = t.strings("alpn");
        if !alpn.is_empty() {
            set(&mut opts, "alpn", list(alpn));
        }
        // Oryn 的 ShadowTLS 插件不使用浏览器指纹（mihomo 的 client-fingerprint 在这里也被忽略）
        t.ignore(&["utls", "min_version", "max_version"]);
        t.finish()?;
    }
    if !tls_on {
        return Err("shadowtls requires TLS".into());
    }
    if let Some(password) = s.str("password") {
        set_str(&mut opts, "password", password);
    }
    set(
        &mut opts,
        "version",
        Yaml::Integer(s.int("version").unwrap_or(1)),
    );
    set_str(h, "plugin", "shadow-tls");
    set(h, "plugin-opts", Yaml::Hash(opts));
    let detour = s.str("detour");
    s.finish()?;
    Ok(detour)
}

/// WireGuard：旧的出站写法（`local_address`、`peer_public_key`）与 1.11 起的端点写法（`address`、`peers`）。
fn wireguard(mut f: Obj, tag: Option<String>) -> Result<Hash, String> {
    f.ignore(&[
        "system_interface",
        "interface_name",
        "name",
        "workers",
        "gso",
        "listen_port",
        "udp_timeout",
    ]);
    if f.map.get("system").and_then(Value::as_bool) == Some(true)
        || f.map.get("system_interface").and_then(Value::as_bool) == Some(true)
    {
        return Err("system WireGuard interfaces are not supported".into());
    }
    f.ignore(&["system"]);
    let mut addresses = f.strings("address");
    addresses.extend(f.strings("local_address"));
    let private_key = f.str("private_key").ok_or("missing private_key")?;

    // 对端：端点写法的 peers，或旧写法顶层的单个对端
    let mut peers: Vec<Hash> = Vec::new();
    if let Some(v) = f.get("peers") {
        let list_v = v.as_array().ok_or("`peers` is not an array")?;
        for p in list_v {
            let mut po = Obj::child(p, "peers.")?;
            let mut peer = Hash::new();
            set_str(
                &mut peer,
                "server",
                po.str("address")
                    .or_else(|| po.str("server"))
                    .ok_or("missing peer address")?,
            );
            let port = po
                .int("port")
                .or_else(|| po.int("server_port"))
                .unwrap_or(0);
            if !(1..=65535).contains(&port) {
                return Err("the peer port must be between 1 and 65535".into());
            }
            set(&mut peer, "port", Yaml::Integer(port));
            set_str(
                &mut peer,
                "public-key",
                po.str("public_key").ok_or("missing peer public_key")?,
            );
            if let Some(psk) = po.str("pre_shared_key") {
                set_str(&mut peer, "pre-shared-key", psk);
            }
            let allowed = po.strings("allowed_ips");
            set(
                &mut peer,
                "allowed-ips",
                list(if allowed.is_empty() {
                    default_allowed()
                } else {
                    allowed
                }),
            );
            if let Some(r) = po.get("reserved") {
                set(&mut peer, "reserved", reserved(r)?);
            }
            if let Some(k) = po.int("persistent_keepalive_interval") {
                set(&mut peer, "persistent-keepalive", Yaml::Integer(k));
            }
            po.finish()?;
            peers.push(peer);
        }
    }
    if peers.is_empty() {
        let mut peer = Hash::new();
        set_str(
            &mut peer,
            "server",
            f.str("server").ok_or("missing server")?,
        );
        let port = f.int("server_port").unwrap_or(0);
        if !(1..=65535).contains(&port) {
            return Err("the port must be between 1 and 65535".into());
        }
        set(&mut peer, "port", Yaml::Integer(port));
        set_str(
            &mut peer,
            "public-key",
            f.str("peer_public_key").ok_or("missing peer_public_key")?,
        );
        if let Some(psk) = f.str("pre_shared_key") {
            set_str(&mut peer, "pre-shared-key", psk);
        }
        set(&mut peer, "allowed-ips", list(default_allowed()));
        if let Some(r) = f.get("reserved") {
            set(&mut peer, "reserved", reserved(r)?);
        }
        peers.push(peer);
    } else {
        f.ignore(&[
            "server",
            "server_port",
            "peer_public_key",
            "pre_shared_key",
            "reserved",
        ]);
    }

    let first_server = peers[0]
        .get(&st("server"))
        .and_then(Yaml::as_str)
        .unwrap_or("")
        .to_string();
    let mut h = Hash::new();
    set_str(
        &mut h,
        "name",
        tag.unwrap_or_else(|| format!("wireguard {first_server}")),
    );
    set_str(&mut h, "type", "wireguard");
    // 每个地址族取第一个地址
    if let Some(v4) = addresses.iter().find(|a| !a.contains(':')) {
        set_str(&mut h, "ip", v4.clone());
    }
    if let Some(v6) = addresses.iter().find(|a| a.contains(':')) {
        set_str(&mut h, "ipv6", v6.clone());
    }
    set_str(&mut h, "private-key", private_key);
    if let Some(mtu) = f.int("mtu") {
        set(&mut h, "mtu", Yaml::Integer(mtu));
    }
    set(&mut h, "udp", Yaml::Boolean(true));
    // keepalive 在 Oryn 里是接口级字段，取第一个对端的
    if let Some(k) = peers[0].remove(&st("persistent-keepalive")) {
        set(&mut h, "persistent-keepalive", k);
    }
    for p in peers.iter_mut().skip(1) {
        p.remove(&st("persistent-keepalive"));
    }
    if peers.len() == 1 {
        for (k, v) in peers.pop().expect("one peer") {
            h.insert(k, v);
        }
    } else {
        set(
            &mut h,
            "peers",
            Yaml::Array(peers.into_iter().map(Yaml::Hash).collect()),
        );
    }
    if let Some(d) = f.str("detour") {
        set_str(&mut h, "dialer-proxy", d);
    }
    f.finish()?;
    Ok(h)
}

fn default_allowed() -> Vec<String> {
    vec!["0.0.0.0/0".into(), "::/0".into()]
}

fn reserved(v: &Value) -> Result<Yaml, String> {
    match v {
        Value::Array(a) => Ok(Yaml::Array(
            a.iter()
                .map(|n| n.as_i64().map(Yaml::Integer).ok_or("invalid reserved"))
                .collect::<Result<_, _>>()?,
        )),
        Value::String(s) => Ok(st(s.clone())),
        _ => Err("invalid reserved".into()),
    }
}
