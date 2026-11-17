//! 配置语义参考 mihomo adapter/outbound/{sudoku,shadowquic}.go @ 88dcbf7f1614a67c3b36b848ee3592dfa92ada36。
use super::{
    proxies::{error, password_value, server, tls},
    Builder,
};
use crate::{
    model::*,
    yaml::{bool_of, get, int_of, list_of, str_of},
    ConfigError,
};
use yaml_rust2::Yaml;
fn text(p: &Yaml, k: &str) -> String {
    str_of(p, k).unwrap_or_default()
}
fn bounded(
    p: &Yaml,
    name: &str,
    key: &str,
    default: i64,
    min: i64,
    max: i64,
) -> Result<i64, ConfigError> {
    match get(p, key) {
        None => Ok(default),
        Some(_) => int_of(p, key)
            .filter(|v| (min..=max).contains(v))
            .ok_or_else(|| error(name, &format!("invalid {key}"))),
    }
}
pub(super) fn sudoku(p: &Yaml, name: &str, b: &mut Builder) -> Result<OutboundKind, ConfigError> {
    for field in [
        "http-mask",
        "http-mask-tls",
        "enable-pure-downlink",
        "udp",
        "skip-cert-verify",
    ] {
        if get(p, field).is_some() && bool_of(p, field).is_none() {
            return Err(error(name, &format!("invalid {field}")));
        }
    }
    for field in [
        "aead-method",
        "table-type",
        "custom-table",
        "http-mask-mode",
        "http-mask-host",
        "path-root",
        "multiplex",
        "http-mask-multiplex",
    ] {
        if get(p, field).is_some() && str_of(p, field).is_none() {
            return Err(error(name, &format!("invalid {field}")));
        }
    }
    if let Some(value) = get(p, "custom-tables") {
        let values = value
            .as_vec()
            .ok_or_else(|| error(name, "custom-tables must be a list"))?;
        if values.len() > 8 || values.iter().any(|v| !matches!(v, Yaml::String(_))) {
            return Err(error(name, "invalid custom-tables"));
        }
    }
    for (field, _) in crate::yaml::entries(p) {
        if ![
            "name",
            "type",
            "server",
            "port",
            "key",
            "aead-method",
            "padding-min",
            "padding-max",
            "table-type",
            "custom-table",
            "custom-tables",
            "enable-pure-downlink",
            "http-mask",
            "http-mask-mode",
            "http-mask-tls",
            "http-mask-host",
            "http-mask-multiplex",
            "httpmask",
            "path-root",
            "multiplex",
            "udp",
            "dialer-proxy",
            "skip-cert-verify",
            "fingerprint",
            "alpn",
        ]
        .contains(&field.as_str())
        {
            b.warn(format!(
                "proxy {name}: ignored unsupported Sudoku option {field}"
            ));
        }
    }
    let key = text(p, "key");
    if key.is_empty() || key.len() > 1024 {
        return Err(error(name, "Sudoku key must be 1–1024 bytes"));
    }
    let aead = str_of(p, "aead-method").unwrap_or_else(|| "chacha20-poly1305".into());
    if !["chacha20-poly1305", "aes-128-gcm", "none"].contains(&aead.as_str()) {
        return Err(error(name, "invalid Sudoku aead-method"));
    }
    let mut min = bounded(p, name, "padding-min", 10, 0, 100)? as u8;
    let mut max = bounded(p, name, "padding-max", 30, 0, 100)? as u8;
    if get(p, "padding-min").is_none() && max < min {
        min = max;
    }
    if get(p, "padding-max").is_none() && min > max {
        max = min;
    }
    if min > max {
        return Err(error(name, "padding-min exceeds padding-max"));
    }
    let table_type = match text(p, "table-type").to_ascii_lowercase().as_str() {
        "" | "entropy" | "prefer_entropy" => "prefer_entropy",
        "ascii" | "prefer_ascii" => "prefer_ascii",
        "up_ascii_down_entropy" => "up_ascii_down_entropy",
        "up_entropy_down_ascii" => "up_entropy_down_ascii",
        _ => return Err(error(name, "invalid Sudoku table-type")),
    }
    .to_string();
    let mut tables = list_of(p, "custom-tables");
    if tables.is_empty() {
        tables.push(text(p, "custom-table"));
    }
    if tables.len() > 8 {
        return Err(error(name, "Sudoku supports at most 8 custom tables"));
    }
    for table in &mut tables {
        *table = table.trim().to_ascii_lowercase();
        let cleaned = table.replace(' ', "");
        if !table.is_empty()
            && (cleaned.len() != 8
                || cleaned.bytes().filter(|c| *c == b'x').count() != 2
                || cleaned.bytes().filter(|c| *c == b'p').count() != 2
                || cleaned.bytes().filter(|c| *c == b'v').count() != 4)
        {
            return Err(error(name, "invalid Sudoku custom table"));
        }
    }
    let mut disabled = !bool_of(p, "http-mask").unwrap_or(true);
    let mut mode = str_of(p, "http-mask-mode").unwrap_or_else(|| "legacy".into());
    let mut https = bool_of(p, "http-mask-tls").unwrap_or(false);
    let mut host = text(p, "http-mask-host");
    let mut root = text(p, "path-root");
    let mut multiplex = str_of(p, "multiplex").unwrap_or_else(|| "off".into());
    if !text(p, "http-mask-multiplex").is_empty() {
        multiplex = text(p, "http-mask-multiplex");
    }
    if let Some(h) = get(p, "httpmask") {
        if h.as_hash().is_none() {
            return Err(error(name, "httpmask must be a mapping"));
        }
        for field in ["disable", "tls"] {
            if get(h, field).is_some() && bool_of(h, field).is_none() {
                return Err(error(name, &format!("invalid httpmask.{field}")));
            }
        }
        disabled = bool_of(h, "disable").unwrap_or(false);
        https = bool_of(h, "tls").unwrap_or(false);
        host = text(h, "host");
        if !text(h, "mode").is_empty() {
            mode = text(h, "mode");
        }
        if !text(h, "path-root").is_empty() {
            root = text(h, "path-root");
        }
        if !text(h, "multiplex").is_empty() {
            multiplex = text(h, "multiplex");
        }
    }
    mode = mode.trim().to_ascii_lowercase();
    multiplex = multiplex.trim().to_ascii_lowercase();
    if !root.trim().is_empty() && root.trim().trim_matches('/').is_empty() {
        return Err(error(name, "invalid Sudoku path-root"));
    }
    root = root.trim().trim_matches('/').to_string();
    if !["legacy", "stream", "poll", "auto", "ws"].contains(&mode.as_str()) {
        return Err(error(name, "invalid Sudoku http-mask-mode"));
    }
    if !["off", "auto", "on"].contains(&multiplex.as_str()) {
        return Err(error(name, "invalid Sudoku multiplex"));
    }
    if root.len() > 64
        || !root
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err(error(name, "invalid Sudoku path-root"));
    }
    if host.len() > 300
        || host
            .bytes()
            .any(|c| c <= 32 || c == 127 || c == b'/' || c == b'\\')
    {
        return Err(error(name, "invalid Sudoku http-mask-host"));
    }
    if bool_of(p, "udp") == Some(false) {
        b.warn(format!(
            "proxy {name}: Sudoku always supports UDP; ignored udp: false"
        ));
    }
    let tls_spec = if https && !disabled && mode != "legacy" {
        // HTTPMask 只采用文档列出的 TLS 字段；已警告忽略的指纹/Reality/ECH 不得意外生效。
        let mut options = yaml_rust2::yaml::Hash::new();
        for field in ["alpn", "fingerprint", "skip-cert-verify"] {
            if let Some(value) = get(p, field) {
                options.insert(Yaml::String(field.into()), value.clone());
            }
        }
        let mut spec = tls(&Yaml::Hash(options), name, true)?.unwrap();
        if spec.alpn.iter().any(|v| v != "http/1.1") {
            return Err(error(name, "Sudoku HTTP mask requires HTTP/1.1 ALPN"));
        }
        spec.alpn = vec!["http/1.1".into()];
        Some(spec)
    } else {
        None
    };
    Ok(OutboundKind::Sudoku(SudokuSpec {
        server: server(p, name)?,
        key,
        aead,
        padding_min: min,
        padding_max: max,
        table_type,
        tables,
        pure_downlink: bool_of(p, "enable-pure-downlink").unwrap_or(true),
        http_disabled: disabled,
        http_mode: mode,
        http_tls: https,
        http_host: host,
        path_root: root,
        multiplex,
        tls: tls_spec,
    }))
}
pub(super) fn shadowquic(
    p: &Yaml,
    name: &str,
    b: &mut Builder,
) -> Result<OutboundKind, ConfigError> {
    for (field, _) in crate::yaml::entries(p) {
        if ![
            "name",
            "type",
            "server",
            "port",
            "username",
            "password",
            "sni",
            "alpn",
            "quic-versions",
            "udp-over-stream",
            "zero-rtt",
            "keep-alive-interval",
            "congestion-controller",
            "cwnd",
            "bbr-profile",
            "recv-window-conn",
            "recv-window",
            "max-open-streams",
            "max-datagram-frame-size",
            "disable-mtu-discovery",
            "up",
            "down",
            "udp",
            "dialer-proxy",
        ]
        .contains(&field.as_str())
        {
            b.warn(format!(
                "proxy {name}: ignored unsupported ShadowQUIC option {field}"
            ));
        }
    }
    for field in ["quic-versions", "alpn"] {
        if let Some(value) = get(p, field) {
            let values = value
                .as_vec()
                .ok_or_else(|| error(name, &format!("{field} must be a list")))?;
            if values
                .iter()
                .any(|v| !matches!(v, Yaml::String(_) | Yaml::Integer(_)))
            {
                return Err(error(name, &format!("invalid {field}")));
            }
        }
    }
    if !cfg!(feature = "quic") {
        return Err(error(name, "ShadowQUIC requires the quic build feature"));
    }
    for field in [
        "udp-over-stream",
        "zero-rtt",
        "disable-mtu-discovery",
        "udp",
    ] {
        if get(p, field).is_some() && bool_of(p, field).is_none() {
            return Err(error(name, &format!("invalid {field}")));
        }
    }
    if bool_of(p, "udp") == Some(false) {
        b.warn(format!(
            "proxy {name}: ShadowQUIC always supports UDP; ignored udp: false"
        ));
    }
    let username = get(p, "username")
        .and_then(crate::yaml::scalar)
        .unwrap_or_default();
    let password = password_value(p).unwrap_or_default();
    if username.len() > 1024 || password.len() > 1024 {
        return Err(error(name, "ShadowQUIC credentials exceed 1024 bytes"));
    }
    let mut versions = list_of(p, "quic-versions");
    if versions.is_empty() {
        versions.push("v1".into());
    }
    let mut v1 = false;
    let mut v2 = false;
    for v in versions {
        match v.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "v1" | "1" | "rfc9000" | "rfc-9000" => v1 = true,
            "v2" | "2" | "rfc9369" | "rfc-9369" => v2 = true,
            _ => return Err(error(name, "invalid QUIC version")),
        }
    }
    if !v1 {
        return Err(error(
            name,
            "ShadowQUIC QUIC v2 is unsupported by quinn/rustls; v1 is required",
        ));
    }
    if v2 {
        b.warn(format!(
            "proxy {name}: ShadowQUIC QUIC v2 is unsupported by quinn/rustls; ignoring v2 and using v1"
        ));
    }
    let mut alpn = list_of(p, "alpn");
    if alpn.is_empty() {
        alpn.push("h3".into());
    }
    if alpn.len() > 8 || alpn.iter().any(|s| s.is_empty() || s.len() > 255) {
        return Err(error(name, "invalid ShadowQUIC ALPN"));
    }
    let congestion = str_of(p, "congestion-controller")
        .unwrap_or_else(|| "cubic".into())
        .to_ascii_lowercase();
    if !["bbr", "cubic", "new_reno", "newreno"].contains(&congestion.as_str()) {
        return Err(error(name, "invalid ShadowQUIC congestion-controller"));
    }
    let profile = text(p, "bbr-profile");
    if !["", "standard", "conservative", "aggressive"].contains(&profile.as_str()) {
        return Err(error(name, "invalid ShadowQUIC bbr-profile"));
    }
    if !profile.is_empty() && profile != "standard" {
        b.warn(format!(
            "proxy {name}: BBR profile {profile} is unsupported; using standard BBR"
        ));
    }
    let clamp = |value: i64, limit: i64, b: &mut Builder, field: &str| {
        if value > limit {
            b.warn(format!(
                "proxy {name}: {field} capped at {limit} for Extension memory budget"
            ));
        }
        value.min(limit) as u32
    };
    let sw = bounded(p, name, "recv-window-conn", 0, 0, 64 * 1024 * 1024)?;
    let rw = bounded(p, name, "recv-window", 0, 0, 64 * 1024 * 1024)?;
    let sw = clamp(
        if sw == 0 { 65536 } else { sw },
        262144,
        b,
        "recv-window-conn",
    );
    let rw = clamp(if rw == 0 { 524288 } else { rw }, 1048576, b, "recv-window");
    let streams = bounded(p, name, "max-open-streams", 32, 1, 65535)?;
    let streams = clamp(streams, 32, b, "max-open-streams") as usize;
    let sni = str_of(p, "sni").unwrap_or_else(|| text(p, "server"));
    if sni.is_empty() || sni.len() > 253 || sni.bytes().any(|v| v <= 32 || v == 127) {
        return Err(error(name, "invalid ShadowQUIC SNI"));
    }
    let rate = |key: &str| -> Result<u64, ConfigError> {
        let value = text(p, key);
        if value.is_empty() {
            return Ok(0);
        }
        let value = value.to_ascii_lowercase().replace(' ', "");
        let (num, mult) = if let Some(n) = value.strip_suffix("gbps") {
            (n, 1e9)
        } else if let Some(n) = value.strip_suffix("mbps") {
            (n, 1e6)
        } else if let Some(n) = value.strip_suffix("kbps") {
            (n, 1e3)
        } else if let Some(n) = value.strip_suffix("bps") {
            (n, 1.0)
        } else {
            (value.as_str(), 1e6)
        };
        let n = num
            .parse::<f64>()
            .map_err(|_| error(name, "invalid ShadowQUIC bandwidth"))?;
        if !n.is_finite() || n < 0.0 || n * mult > 1e11 {
            return Err(error(name, "invalid ShadowQUIC bandwidth"));
        }
        Ok((n * mult / 8.0) as u64)
    };
    Ok(OutboundKind::ShadowQuic(ShadowQuicSpec {
        server: server(p, name)?,
        username,
        password,
        sni,
        alpn,
        udp_over_stream: bool_of(p, "udp-over-stream").unwrap_or(false),
        zero_rtt: bool_of(p, "zero-rtt").unwrap_or(false),
        keep_alive_ms: bounded(p, name, "keep-alive-interval", 0, 0, 60000)? as u64,
        congestion,
        cwnd: bounded(p, name, "cwnd", 32, 1, 256)? as u32,
        stream_window: sw,
        receive_window: rw,
        max_streams: streams,
        max_datagram: bounded(p, name, "max-datagram-frame-size", 1400, 64, 1400)? as usize,
        disable_mtu_discovery: bool_of(p, "disable-mtu-discovery").unwrap_or(false),
        up_bps: rate("up")?,
        down_bps: rate("down")?,
    }))
}

#[cfg(test)]
mod tests {
    use crate::{parse_config, OutboundKind};
    #[test]
    fn sudoku_defaults_alias_priority_and_bounds() {
        let yaml="proxies: [{name: P, type: sudoku, server: proxy.test, port: 443, key: secret, padding-max: 5, multiplex: off, http-mask-multiplex: auto, http-mask: false, httpmask: {mode: ws, multiplex: on}, custom-table: invalid, custom-tables: [xpxvvpvv]}]";
        let cfg = parse_config(yaml).unwrap();
        let OutboundKind::Sudoku(s) = &cfg.outbounds[cfg.outbound_index("P").unwrap()].kind else {
            panic!()
        };
        assert_eq!((s.padding_min, s.padding_max), (5, 5));
        assert_eq!(s.multiplex, "on");
        assert!(!s.http_disabled);
        assert_eq!(s.http_mode, "ws");
        assert_eq!(s.tables, ["xpxvvpvv"]);
        let cfg=parse_config("proxies: [{name: P,type: sudoku,server: proxy.test,port: 443,key: secret,http-mask-mode: ws,http-mask-tls: true,client-fingerprint: invalid,reality-opts: {}}]").unwrap();
        let OutboundKind::Sudoku(s) = &cfg.outbounds[cfg.outbound_index("P").unwrap()].kind else {
            panic!()
        };
        assert!(s.tls.as_ref().unwrap().client_fingerprint.is_none());
        assert!(s.tls.as_ref().unwrap().reality.is_none());
        assert!(cfg.warnings.len() >= 2);
        for field in [
            "padding-min: -1",
            "padding-max: 101",
            "aead-method: wrong",
            "table-type: wrong",
            "custom-table: xxx",
            "custom-tables: [false]",
            "http-mask: wrong",
            "httpmask: {tls: wrong}",
            "path-root: a/b",
            "multiplex: wrong",
        ] {
            let text=format!("proxies: [{{name: P,type: sudoku,server: proxy.test,port: 443,key: secret,{field}}}]");
            assert!(parse_config(&text).is_err(), "{field}");
        }
    }
    #[test]
    fn shadowquic_version_and_resource_bounds() {
        let cfg=parse_config("proxies: [{name: P,type: shadowquic,server: proxy.test,port: 443,quic-versions: [v2]}]").unwrap();
        assert!(cfg.outbound_index("P").is_none());
        assert!(cfg
            .warnings
            .iter()
            .any(|w| w.contains("QUIC v2 is unsupported by quinn/rustls")));
        if !cfg!(feature = "quic") {
            return;
        }
        let cfg=parse_config("proxies: [{name: P,type: shadowquic,server: proxy.test,port: 443,quic-versions: [v2, v1],recv-window: 8388608,max-open-streams: 1024}]").unwrap();
        let OutboundKind::ShadowQuic(s) = &cfg.outbounds[cfg.outbound_index("P").unwrap()].kind
        else {
            panic!()
        };
        assert_eq!((s.receive_window, s.max_streams), (1048576, 32));
        assert!(cfg
            .warnings
            .iter()
            .any(|w| w.contains("ignoring v2 and using v1")));
        for field in [
            "quic-versions: [bad]",
            "cwnd: 0",
            "max-datagram-frame-size: 1401",
            "up: nan",
            "zero-rtt: wrong",
            "congestion-controller: bad",
        ] {
            let text = format!(
                "proxies: [{{name: P,type: shadowquic,server: proxy.test,port: 443,{field}}}]"
            );
            assert!(parse_config(&text).is_err(), "{field}");
        }
    }
}
