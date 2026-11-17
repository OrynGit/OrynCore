//! 0.8.x 新增的出站类型：ShadowsocksR、Snell 等。

use yaml_rust2::Yaml;

use super::proxies::{error, password_value, server};
use super::Builder;
use crate::model::*;
use crate::yaml::{bool_of, get, int_of, list_of, str_of};
use crate::ConfigError;

fn plain_param(s: &str) -> bool {
    s.len() <= 1024 && !s.bytes().any(|c| c < 32 || c == 127)
}

/// `None` 表示节点被忽略（已给出警告）。
pub(super) fn parse(
    ty: &str,
    p: &Yaml,
    name: &str,
    b: &mut Builder,
) -> Result<Option<OutboundKind>, ConfigError> {
    match ty {
        "sudoku" => super::sudoku_shadowquic::sudoku(p, name, b).map(Some),
        "shadowquic" => super::sudoku_shadowquic::shadowquic(p, name, b).map(Some),
        "mieru" => super::mieru::parse(p, name, b).map(Some),
        "ssr" => ssr(p, name).map(Some),
        "snell" => snell(p, name, b),
        "naive" => naive(p, name, b).map(Some),
        "ssh" => ssh(p, name, b).map(Some),
        _ => unreachable!(),
    }
}

/// mihomo 的 SSH 写法。`private-key` 只接受内联文本：Extension 里没有用户可读的文件路径。
fn ssh(p: &Yaml, name: &str, b: &mut Builder) -> Result<OutboundKind, ConfigError> {
    let server = server(p, name)?;
    let username = str_of(p, "username")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error(name, "missing username"))?;
    let password = password_value(p).filter(|s| !s.is_empty());
    let private_key = str_of(p, "private-key").filter(|s| !s.is_empty());
    if let Some(key) = &private_key {
        if !key.contains("PRIVATE KEY") && !key.trim_start().starts_with("PuTTY-User-Key-File-") {
            return Err(error(
                name,
                "ssh private-key must be the key text, not a file path",
            ));
        }
    }
    if password.is_none() && private_key.is_none() {
        return Err(error(name, "ssh needs a password or private-key"));
    }
    let host_keys = list_of(p, "host-key");
    for key in &host_keys {
        let mut fields = key.split_whitespace();
        if fields.next().is_none() || fields.next().is_none() || key.len() > 16 * 1024 {
            return Err(error(name, "invalid ssh host-key"));
        }
    }
    let host_key_algorithms = list_of(p, "host-key-algorithms");
    if host_key_algorithms.len() > 32
        || host_key_algorithms
            .iter()
            .any(|a| a.is_empty() || a.len() > 128)
    {
        return Err(error(name, "invalid ssh host-key-algorithms"));
    }
    let mode = match get(p, "oryn-ssh-udp") {
        None => None,
        Some(Yaml::String(s)) => match s.as_str() {
            "off" => None,
            "badvpn" => Some(SshUdpMode::BadVpn),
            "tun2proxy" => Some(SshUdpMode::Tun2Proxy),
            _ => return Err(error(name, "oryn-ssh-udp must be off, badvpn or tun2proxy")),
        },
        _ => return Err(error(name, "oryn-ssh-udp must be a string")),
    };
    let gateway = match get(p, "oryn-ssh-udp-server") {
        None => "127.0.0.1:7300".parse().expect("default gateway"),
        Some(Yaml::String(s)) if !s.contains('%') => s
            .parse::<std::net::SocketAddr>()
            .map_err(|_| error(name, "oryn-ssh-udp-server must be an IP:port"))?,
        _ => return Err(error(name, "oryn-ssh-udp-server must be an IP:port string")),
    };
    if gateway.port() == 0 {
        return Err(error(name, "oryn-ssh-udp-server port must be 1 to 65535"));
    }
    if get(p, "udp").is_some() {
        b.warn(format!(
            "proxy {name}: SSH ignores udp; use oryn-ssh-udp to opt into a UDP gateway"
        ));
    }
    Ok(OutboundKind::Ssh(SshSpec {
        server,
        username,
        password,
        private_key,
        private_key_passphrase: str_of(p, "private-key-passphrase").filter(|s| !s.is_empty()),
        host_keys,
        host_key_algorithms,
        udp_gateway: mode.map(|mode| SshUdpSpec {
            mode,
            server: gateway,
        }),
    }))
}

/// NaïveProxy（Oryn 扩展，字段对应 sing-box 的 naive 出站）：`username`、`password`、TLS 字段、
/// `headers`（附加首部）、`udp`（经 UoT，`udp-over-tcp-version` 缺省 2）和
/// `quic: true`（HTTP/3）。HTTP/3 不会静默退回 HTTP/2。
fn naive(p: &Yaml, name: &str, b: &mut Builder) -> Result<OutboundKind, ConfigError> {
    let server = server(p, name)?;
    let username = str_of(p, "username").unwrap_or_default();
    let password = password_value(p).unwrap_or_default();
    if username.contains(':') || username.len() > 255 || password.len() > 255 {
        return Err(error(name, "invalid naive username or password"));
    }
    if get(p, "quic").is_some() && bool_of(p, "quic").is_none() {
        return Err(error(name, "invalid naive quic"));
    }
    let quic = bool_of(p, "quic").unwrap_or(false);
    for field in ["insecure-concurrency", "concurrency"] {
        if get(p, field).is_some() {
            b.warn(format!("proxy {name}: ignored unsupported {field}"));
        }
    }
    let mut tls = super::proxies::tls(p, name, true)?.expect("required TLS");
    if tls.reality.is_some() {
        return Err(error(name, "naive cannot use Reality"));
    }
    if quic && tls.client_fingerprint.is_some() {
        return Err(error(
            name,
            "naive HTTP/3 does not support browser client-fingerprint",
        ));
    }
    if quic && tls.ech.is_some() {
        return Err(error(name, "naive HTTP/3 does not support ECH"));
    }
    // Naïve 的承载由 ALPN 明确选择，避免 quic 配置失败时静默回落到 h2。
    tls.alpn = vec![if quic { "h3" } else { "h2" }.into()];
    let headers = super::proxies::transport_headers(p, name)?;
    let uot = if bool_of(p, "udp").unwrap_or(false) {
        match get(p, "udp-over-tcp-version") {
            None => Some(2),
            Some(_) => match int_of(p, "udp-over-tcp-version") {
                Some(v @ 1..=2) => Some(v as u8),
                _ => return Err(error(name, "udp-over-tcp-version must be 1 or 2")),
            },
        }
    } else {
        None
    };
    Ok(OutboundKind::Naive(NaiveSpec {
        server,
        username,
        password,
        tls,
        quic,
        headers,
        uot,
    }))
}

/// mihomo 的 Snell 写法：`psk`、`version`、`obfs-opts`（`mode: http / tls`、`host`）、`reuse`、`udp`；
/// Oryn 扩展 `version: 6` 与 v6 的 `mode`（default / unshaped / unsafe-raw，与 sing-box 相同）。
/// 与 mihomo 一样，版本缺省为 1、5 按 4 处理；v1–v3 没有可用的对端，节点被忽略。
fn snell(p: &Yaml, name: &str, b: &mut Builder) -> Result<Option<OutboundKind>, ConfigError> {
    let version = match get(p, "version") {
        None => 1,
        Some(_) => int_of(p, "version").ok_or_else(|| error(name, "invalid snell version"))?,
    };
    let version = match version {
        1..=3 => {
            b.warn(format!(
                "proxy {name}: snell version {version} is unsupported and was ignored"
            ));
            return Ok(None);
        }
        4 | 5 => version as u8,
        6 => 6,
        _ => return Err(error(name, "invalid snell version")),
    };
    let server = server(p, name)?;
    let psk = str_of(p, "psk")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error(name, "missing psk"))?;
    if psk.len() > 1024 {
        return Err(error(name, "snell psk is too long"));
    }
    let mut obfs = None;
    if let Some(opts) = get(p, "obfs-opts") {
        let mode = str_of(opts, "mode")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let host = str_of(opts, "host").unwrap_or_default();
        match mode.as_str() {
            "" | "none" => {}
            "http" | "tls" if matches!(version, 4 | 5) => {
                obfs = Some(ObfsSpec {
                    tls: mode == "tls",
                    host,
                })
            }
            "http" | "tls" => b.warn(format!(
                "proxy {name}: ignored obfs-opts; snell v6 has no obfs"
            )),
            _ => {
                b.warn(format!(
                    "proxy {name}: snell obfs mode {mode} is unsupported and was ignored"
                ));
                return Ok(None);
            }
        }
    }
    let mode = match str_of(p, "mode")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "default" => SnellMode::Default,
        "unshaped" => SnellMode::Unshaped,
        "unsafe-raw" => SnellMode::UnsafeRaw,
        _ => return Err(error(name, "invalid snell mode")),
    };
    if matches!(version, 4 | 5) && get(p, "mode").is_some() {
        b.warn(format!(
            "proxy {name}: ignored mode; it only applies to snell v6"
        ));
    }
    if str_of(p, "client-fingerprint").is_some() {
        b.warn(format!(
            "proxy {name}: ignored unsupported client-fingerprint"
        ));
    }
    Ok(Some(OutboundKind::Snell(SnellSpec {
        server,
        psk,
        version,
        obfs,
        mode,
        // 缺省开启连接复用（与 mihomo 的缺省 false 不同）：复用省掉每个请求的 TCP 握手，
        // 并且不会因测速等并发场景一次新建几十条连接而触发云服务器按新建连接速率的限速。
        reuse: bool_of(p, "reuse").unwrap_or(true),
        udp: bool_of(p, "udp").unwrap_or(false),
    })))
}

fn ssr(p: &Yaml, name: &str) -> Result<OutboundKind, ConfigError> {
    let server = server(p, name)?;
    let cipher = str_of(p, "cipher").ok_or_else(|| error(name, "missing cipher"))?;
    if cipher != "none" && !SS_STREAM_CIPHERS.contains(&cipher.as_str()) {
        return Err(error(name, "ShadowsocksR needs a stream cipher or none"));
    }
    let password = password_value(p).ok_or_else(|| error(name, "missing password"))?;
    let protocol = str_of(p, "protocol").unwrap_or_else(|| "origin".into());
    if !SSR_PROTOCOLS.contains(&protocol.as_str()) {
        return Err(error(name, "unsupported ShadowsocksR protocol"));
    }
    let obfs = str_of(p, "obfs").unwrap_or_else(|| "plain".into());
    if !SSR_OBFS.contains(&obfs.as_str()) {
        return Err(error(name, "unsupported ShadowsocksR obfs"));
    }
    let protocol_param = str_of(p, "protocol-param").unwrap_or_default();
    let obfs_param = str_of(p, "obfs-param").unwrap_or_default();
    if !plain_param(&protocol_param) || !plain_param(&obfs_param) {
        return Err(error(
            name,
            "invalid ShadowsocksR protocol-param or obfs-param",
        ));
    }
    Ok(OutboundKind::Ssr(SsrSpec {
        server,
        cipher,
        password,
        protocol,
        protocol_param,
        obfs,
        obfs_param,
        udp: bool_of(p, "udp").unwrap_or(false),
    }))
}
