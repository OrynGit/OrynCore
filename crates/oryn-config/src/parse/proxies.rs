use std::collections::BTreeMap;

use base64::Engine;
use yaml_rust2::Yaml;

use super::{is_reserved, Builder};
use crate::model::*;
use crate::yaml::{bool_of, entries, get, int_of, list_of, str_of};
use crate::{ConfigError, TargetAddr};

pub(super) fn parse(root: &Yaml, b: &mut Builder) -> Result<(), ConfigError> {
    let Some(Yaml::Array(list)) = get(root, "proxies") else {
        return Ok(());
    };
    let mut ignored_types: BTreeMap<String, usize> = BTreeMap::new();
    for (i, p) in list.iter().enumerate() {
        let name = str_of(p, "name")
            .ok_or_else(|| ConfigError(format!("proxies[{i}] is missing name")))?;
        if is_reserved(&name) || name.eq_ignore_ascii_case(TAG_GLOBAL) {
            b.warn(format!("proxy {name} uses a reserved name and was ignored"));
            continue;
        }
        if b.names.contains_key(&name) || b.ignored.contains(&name) {
            return Err(ConfigError(format!("duplicate proxy name {name}")));
        }
        let ty = str_of(p, "type").unwrap_or_default().to_ascii_lowercase();
        if ty == "tailscale" {
            let spec = super::tailscale::parse(p, &name, b)?;
            if spec.enabled
                && b.outbounds
                    .iter()
                    .any(|o| matches!(&o.kind, OutboundKind::Tailscale(t) if t.enabled))
            {
                return Err(ConfigError(
                    "only one active Tailscale identity is supported".into(),
                ));
            }
            let index = b.push_outbound(name.clone(), OutboundKind::Tailscale(spec));
            register_dialer(p, &name, index, b)?;
            continue;
        }
        if ty == "shadowquic" {
            let versions = list_of(p, "quic-versions");
            let only_v2 = !versions.is_empty()
                && versions.iter().all(|v| {
                    matches!(
                        v.trim().to_ascii_lowercase().replace('_', "-").as_str(),
                        "v2" | "2" | "rfc9369" | "rfc-9369"
                    )
                });
            if only_v2 {
                // quinn-proto 0.11 + rustls currently expose only QUIC v1 and
                // draft-v1 Initial/Retry key material. Do not silently send a
                // v1 packet for a node that explicitly requires RFC 9369.
                b.warn(format!(
                    "proxy {name}: ShadowQUIC QUIC v2 is unsupported by quinn/rustls; node was ignored"
                ));
                b.ignored.insert(name);
                continue;
            }
            if !super::p3::compiled("quic") {
                b.warn(format!(
                    "proxy {name}: ShadowQUIC requires compiled QUIC v1 support; node was ignored"
                ));
                b.ignored.insert(name);
                continue;
            }
        }
        if matches!(
            ty.as_str(),
            "ssr" | "snell" | "naive" | "ssh" | "mieru" | "sudoku" | "shadowquic"
        ) {
            match super::p4::parse(&ty, p, &name, b)? {
                Some(kind) => {
                    let index = b.push_outbound(name.clone(), kind);
                    register_dialer(p, &name, index, b)?;
                }
                None => {
                    b.ignored.insert(name);
                }
            }
            continue;
        }
        if matches!(ty.as_str(), "hysteria2" | "hysteria" | "tuic" | "wireguard") {
            if !super::p3::compiled(&ty) {
                b.warn(format!(
                    "proxy {name}: {ty} is not compiled in and was ignored"
                ));
                b.ignored.insert(name);
                continue;
            }
            match super::p3::parse(&ty, p, &name, b)? {
                Some(kind) => {
                    let index = b.push_outbound(name.clone(), kind);
                    register_dialer(p, &name, index, b)?;
                }
                None => {
                    b.ignored.insert(name);
                }
            }
            continue;
        }
        if !matches!(
            ty.as_str(),
            "socks5" | "http" | "ss" | "trojan" | "vless" | "vmess" | "anytls"
        ) {
            *ignored_types
                .entry(if ty.is_empty() { "unknown".into() } else { ty })
                .or_default() += 1;
            b.ignored.insert(name);
            continue;
        }
        if ty == "ss" {
            if get(p, "reality-opts").is_some() {
                b.warn(format!(
                    "proxy {name}: Shadowsocks cannot use Reality and was ignored"
                ));
                b.ignored.insert(name);
                continue;
            }
            if str_of(p, "client-fingerprint").is_some() {
                b.warn(format!(
                    "proxy {name}: ignored client-fingerprint without a TLS transport"
                ));
            }
        }
        let network = str_of(p, "network")
            .unwrap_or_else(|| "tcp".into())
            .to_ascii_lowercase();
        let network = if network == "mkcp" {
            "kcp".into()
        } else {
            network
        };
        if network == "kcp" && ty != "vmess" {
            b.warn(format!("proxy {name}: mKCP is mihomo-compatible only for VMess; using it for {ty} is an Oryn extension"));
        }
        if network == "mekya" && ty != "vmess" {
            b.warn(format!("proxy {name}: Mekya is mihomo-compatible only for VMess; using it for {ty} is an Oryn extension"));
        }
        let http_upgrade = network == "ws"
            && get(p, "ws-opts")
                .and_then(|opts| get(opts, "v2ray-http-upgrade"))
                .and_then(crate::yaml::scalar)
                .and_then(|v| v.parse::<bool>().ok())
                .unwrap_or(false);
        let flow = str_of(p, "flow").filter(|f| !f.is_empty());
        let vless_encryption = if ty == "vless" {
            crate::VlessEncryptionSpec::parse(&str_of(p, "encryption").unwrap_or_default())?
        } else {
            if get(p, "encryption").is_some() {
                b.warn(format!(
                    "proxy {name}: ignored encryption on non-VLESS proxy"
                ));
            }
            None
        };
        let skip = if flow.is_some()
            && (ty != "vless" || flow.as_deref() != Some("xtls-rprx-vision"))
        {
            Some("flow")
        } else if str_of(p, "plugin").is_some()
            && !(ty == "ss"
                && matches!(
                    str_of(p, "plugin").as_deref(),
                    Some("shadow-tls" | "obfs" | "simple-obfs" | "v2ray-plugin" | "gost-plugin")
                ))
        {
            Some("plugin")
        } else if network != "tcp"
            && !(matches!(
                network.as_str(),
                "ws" | "grpc" | "h2" | "http" | "xhttp" | "kcp" | "mekya" | "quic"
            ) && matches!(ty.as_str(), "trojan" | "vless" | "vmess"))
        {
            Some("network")
        } else if network == "quic" && !super::p3::compiled("quic") {
            b.warn(format!(
                "proxy {name}: network quic is not compiled in and was ignored"
            ));
            b.ignored.insert(name);
            continue;
        } else {
            None
        };
        if let Some(field) = skip {
            b.warn(format!(
                "proxy {name} has unsupported {field} and was ignored"
            ));
            b.ignored.insert(name);
            continue;
        }
        for field in ["udp-over-tcp", "udp-over-tcp-version"] {
            if ty != "ss" && get(p, field).is_some() {
                b.warn(format!("proxy {name}: ignored unsupported {field}"));
            }
        }
        // Older mihomo profiles occasionally carry an incomplete, disabled
        // gRPC entry. Keep the established skip-and-warn behavior for that
        // shape while fully validating entries that provide a server.
        if network == "grpc" && get(p, "server").is_none() {
            b.warn(format!(
                "proxy {name} has unsupported network grpc or is missing server and was ignored"
            ));
            b.ignored.insert(name);
            continue;
        }
        for field in ["smux", "packet-encoding"] {
            let supported = if field == "smux" {
                matches!(ty.as_str(), "ss" | "trojan" | "vless" | "vmess")
            } else {
                matches!(ty.as_str(), "vless" | "vmess")
            };
            if !supported && get(p, field).is_some() {
                b.warn(format!("proxy {name}: ignored unsupported {field}"));
            }
        }
        let server = server(p, &name)?;
        let udp = bool_of(p, "udp").unwrap_or(false);
        let kind = match ty.as_str() {
            "socks5" | "http" => {
                let auth = str_of(p, "username").map(|username| ProxyAuth {
                    username,
                    password: password_value(p).unwrap_or_default(),
                });
                let tls = tls(p, &name, false)?;
                if ty == "socks5" {
                    OutboundKind::Socks5 {
                        server,
                        auth,
                        udp,
                        tls,
                    }
                } else {
                    OutboundKind::Http { server, auth, tls }
                }
            }
            "ss" => {
                let cipher = str_of(p, "cipher").ok_or_else(|| error(&name, "missing cipher"))?;
                let password = required_password(p, &name)?;
                validate_ss(&cipher, &password).map_err(|e| error(&name, &e))?;
                let plugin = ss_plugin(p, &name, &server)?;
                let uot = if bool_of(p, "udp-over-tcp").unwrap_or(false) {
                    let version = match get(p, "udp-over-tcp-version") {
                        None => 1,
                        Some(_) => int_of(p, "udp-over-tcp-version").unwrap_or(0),
                    };
                    if !(1..=2).contains(&version) {
                        return Err(error(&name, "udp-over-tcp-version must be 1 or 2"));
                    }
                    Some(version as u8)
                } else {
                    None
                };
                OutboundKind::Shadowsocks {
                    server,
                    cipher,
                    password,
                    udp,
                    mux: mux(p, &name, b)?,
                    plugin,
                    uot,
                }
            }
            "anytls" => {
                let limit =
                    |key: &str, default: i64, min: i64, max: i64| -> Result<i64, ConfigError> {
                        let n =
                            match get(p, key) {
                                None => default,
                                Some(v) => crate::yaml::scalar(v)
                                    .and_then(|s| s.parse::<i64>().ok())
                                    .ok_or_else(|| error(&name, "invalid AnyTLS session option"))?,
                            };
                        if !(min..=max).contains(&n) {
                            return Err(error(&name, "invalid AnyTLS session option"));
                        }
                        Ok(n)
                    };
                OutboundKind::AnyTls(AnyTlsSpec {
                    server,
                    password: required_password(p, &name)?,
                    tls: tls(p, &name, true)?.unwrap(),
                    idle_check_secs: limit("idle-session-check-interval", 30, 1, 3600)? as u64,
                    idle_timeout_secs: limit("idle-session-timeout", 30, 1, 3600)? as u64,
                    min_idle_sessions: limit("min-idle-session", 0, 0, 4)? as usize,
                    udp,
                })
            }
            "trojan" | "vless" | "vmess" => {
                let security = tls(p, &name, ty == "trojan")?
                    .map(SecuritySpec::Tls)
                    .unwrap_or(SecuritySpec::None);
                let transport = match network.as_str() {
                    "tcp" => TransportSpec::Tcp,
                    "ws" if http_upgrade => {
                        TransportSpec::HttpUpgrade(http_upgrade_spec(p, &name)?)
                    }
                    "ws" => TransportSpec::Ws(ws(p, &name)?),
                    "grpc" => TransportSpec::Grpc(grpc(p, &name)?),
                    "h2" => TransportSpec::H2(h2_spec(p, &name)?),
                    "http" => TransportSpec::Http(http_spec(p, &name)?),
                    "xhttp" => TransportSpec::XHttp(xhttp_spec(p, &name)?),
                    "kcp" => TransportSpec::Kcp(kcp_spec(p, &name)?),
                    "mekya" => TransportSpec::Mekya(mekya_spec(p, &name)?),
                    "quic" => TransportSpec::Quic,
                    _ => unreachable!(),
                };
                let stream = StreamProxySpec {
                    server,
                    udp,
                    security,
                    transport,
                    mux: mux(p, &name, b)?,
                    packet_encoding: match str_of(p, "packet-encoding").as_deref() {
                        None | Some("") => PacketEncoding::Default,
                        Some("packetaddr") if ty != "trojan" => PacketEncoding::PacketAddr,
                        Some("xudp") if ty != "trojan" => PacketEncoding::Xudp,
                        _ => return Err(error(&name, "unsupported packet-encoding")),
                    },
                    vision: flow.is_some(),
                    vless_encryption: if ty == "vless" {
                        vless_encryption
                    } else {
                        None
                    },
                };
                if stream.vision {
                    // Vision 需要直接控制外层 TLS 记录：只能是 TCP 传输上的 TLS / Reality
                    if !matches!(stream.transport, TransportSpec::Tcp) || stream.tls().is_none() {
                        return Err(error(
                            &name,
                            "VLESS Vision requires TCP transport with TLS or Reality",
                        ));
                    }
                }
                if stream.vless_encryption.is_some() && stream.vision {
                    return Err(error(
                        &name,
                        "VLESS Encryption cannot be combined with Vision",
                    ));
                }
                if matches!(
                    stream.transport,
                    TransportSpec::Ws(_) | TransportSpec::HttpUpgrade(_)
                ) && matches!(&stream.security, SecuritySpec::Tls(t) if t.alpn.iter().any(|a| a != "http/1.1"))
                {
                    return Err(error(&name, "WebSocket requires HTTP/1.1 ALPN"));
                }
                if matches!(stream.transport, TransportSpec::Grpc(_)) {
                    let tls = match &stream.security {
                        SecuritySpec::Tls(t) => t,
                        _ => return Err(error(&name, "gRPC requires TLS")),
                    };
                    if tls.alpn.iter().any(|a| a != "h2") {
                        return Err(error(&name, "gRPC requires h2 ALPN"));
                    }
                }
                if matches!(stream.transport, TransportSpec::H2(_)) {
                    let tls = match &stream.security {
                        SecuritySpec::Tls(t) => t,
                        _ => return Err(error(&name, "HTTP/2 transport requires TLS")),
                    };
                    if tls.alpn.iter().any(|a| a != "h2") {
                        return Err(error(&name, "HTTP/2 transport requires h2 ALPN"));
                    }
                }
                if matches!(stream.transport, TransportSpec::Http(_)) {
                    if let SecuritySpec::Tls(tls) = &stream.security {
                        if tls.alpn.iter().any(|a| a != "http/1.1") {
                            return Err(error(&name, "HTTP transport requires HTTP/1.1 ALPN"));
                        }
                    }
                }
                if matches!(stream.transport, TransportSpec::XHttp(_))
                    && matches!(&stream.security, SecuritySpec::Tls(t) if t.alpn.iter().any(|a| a != "h2"))
                {
                    return Err(error(&name, "XHTTP currently requires h2 ALPN"));
                }
                if matches!(stream.transport, TransportSpec::Kcp(_))
                    && !matches!(stream.security, SecuritySpec::None)
                {
                    return Err(error(
                        &name,
                        "mKCP does not support an additional TLS layer",
                    ));
                }
                if matches!(stream.transport, TransportSpec::Mekya(_)) {
                    if let SecuritySpec::Tls(tls) = &stream.security {
                        if tls.alpn.iter().any(|a| a != "h2" && a != "http/1.1") {
                            return Err(error(&name, "Mekya requires h2 or HTTP/1.1 ALPN"));
                        }
                    }
                }
                if matches!(stream.transport, TransportSpec::Quic) {
                    let tls = match &stream.security {
                        SecuritySpec::Tls(t) => t,
                        _ => return Err(error(&name, "QUIC transport requires TLS")),
                    };
                    if tls.alpn.iter().any(|a| a != "h3") {
                        return Err(error(&name, "QUIC transport requires h3 ALPN"));
                    }
                    if tls.reality.is_some() {
                        return Err(error(&name, "QUIC transport cannot use Reality"));
                    }
                    if tls.ech.is_some() {
                        return Err(error(&name, "QUIC transport does not support ECH"));
                    }
                }
                if ty == "trojan" {
                    OutboundKind::Trojan {
                        stream,
                        password: required_password(p, &name)?,
                    }
                } else {
                    let text = str_of(p, "uuid").ok_or_else(|| error(&name, "missing uuid"))?;
                    let uuid = parse_uuid(&text).ok_or_else(|| error(&name, "invalid uuid"))?;
                    if ty == "vless" {
                        OutboundKind::Vless { stream, uuid }
                    } else {
                        let alter_id = match get(p, "alterId") {
                            None => 0,
                            Some(v) => crate::yaml::scalar(v)
                                .and_then(|s| s.parse::<u16>().ok())
                                .ok_or_else(|| error(&name, "invalid alterId"))?,
                        };
                        let cipher = str_of(p, "cipher").unwrap_or_else(|| "auto".into());
                        if !matches!(
                            cipher.as_str(),
                            "auto"
                                | "aes-128-gcm"
                                | "chacha20-poly1305"
                                | "none"
                                | "zero"
                                | "aes-128-cfb"
                        ) {
                            return Err(error(&name, "unsupported VMess cipher"));
                        }
                        OutboundKind::Vmess {
                            stream,
                            protocol: VmessSpec {
                                uuid,
                                alter_id,
                                cipher,
                                global_padding: bool_of(p, "global-padding").unwrap_or(false),
                                authenticated_length: bool_of(p, "authenticated-length")
                                    .unwrap_or(false),
                            },
                        }
                    }
                }
            }
            _ => unreachable!(),
        };
        let index = b.push_outbound(name.clone(), kind);
        register_dialer(p, &name, index, b)?;
    }
    if !ignored_types.is_empty() {
        let detail: Vec<String> = ignored_types
            .iter()
            .map(|(t, n)| format!("{t}: {n}"))
            .collect();
        b.warn(format!(
            "ignored proxies with unsupported types ({})",
            detail.join(", ")
        ));
    }
    Ok(())
}

pub(super) fn error(name: &str, reason: &str) -> ConfigError {
    ConfigError(format!("proxy {name}: {reason}"))
}

pub(super) fn server(p: &Yaml, name: &str) -> Result<TargetAddr, ConfigError> {
    let host = str_of(p, "server").ok_or_else(|| error(name, "missing server"))?;
    let port = int_of(p, "port")
        .filter(|p| (1..=65535).contains(p))
        .ok_or_else(|| error(name, "invalid port"))? as u16;
    Ok(TargetAddr::from_host(&host, port))
}

// 密码不做 trim，空格是认证材料的一部分。
pub(super) fn password_value(p: &Yaml) -> Option<String> {
    get(p, "password").and_then(crate::yaml::scalar)
}
fn required_password(p: &Yaml, name: &str) -> Result<String, ConfigError> {
    password_value(p)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error(name, "missing password"))
}

pub(super) fn tls(p: &Yaml, name: &str, required: bool) -> Result<Option<TlsSpec>, ConfigError> {
    if !required && !bool_of(p, "tls").unwrap_or(false) {
        if get(p, "reality-opts").is_some()
            || str_of(p, "client-fingerprint").is_some()
            || ech_enabled(p)
        {
            return Err(error(
                name,
                "client-fingerprint, ECH and Reality require TLS",
            ));
        }
        return Ok(None);
    }
    let alpn = list_of(p, "alpn");
    if alpn.len() > 16 || alpn.iter().any(|a| a.len() > 255) {
        return Err(error(name, "invalid ALPN"));
    }
    let fingerprint = match str_of(p, "fingerprint") {
        Some(s) => Some(
            hex::<32>(&s.replace(':', ""))
                .ok_or_else(|| error(name, "invalid SHA-256 fingerprint"))?,
        ),
        None => None,
    };
    let mut client_fingerprint = str_of(p, "client-fingerprint").map(|s| s.to_ascii_lowercase());
    if client_fingerprint
        .as_ref()
        .is_some_and(|s| !CLIENT_FINGERPRINTS.contains(&s.as_str()))
    {
        return Err(error(name, "unsupported client-fingerprint"));
    }
    let ech = parse_ech(p, name)?;
    if ech.is_some() && fingerprint.is_some() {
        return Err(error(
            name,
            "ECH cannot be combined with a certificate fingerprint",
        ));
    }
    if ech.is_some() && client_fingerprint.is_some() {
        return Err(error(
            name,
            "ECH cannot be combined with a browser client-fingerprint",
        ));
    }
    let reality = if let Some(opts) = get(p, "reality-opts") {
        let key =
            str_of(opts, "public-key").ok_or_else(|| error(name, "Reality requires public-key"))?;
        if key.len() != 43 && !(key.len() == 44 && key.ends_with('=')) {
            return Err(error(name, "invalid Reality public-key length"));
        }
        let public_key: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key.trim_end_matches('='))
            .map_err(|_| error(name, "invalid Reality public-key Base64"))?
            .try_into()
            .map_err(|_| error(name, "Reality public-key must be 32 bytes"))?;
        if public_key == [0; 32] {
            return Err(error(name, "invalid Reality low-order public-key"));
        }
        // YAML 数字会丢失前导零；身份材料必须保留原始十六进制文本。
        let short = match get(opts, "short-id") {
            None => String::new(),
            Some(Yaml::String(s)) => s.trim().to_string(),
            Some(_) => {
                return Err(error(
                    name,
                    "Reality short-id must be a quoted hexadecimal string",
                ))
            }
        };
        if short.len() > 16
            || !short.len().is_multiple_of(2)
            || !short.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(error(name, "invalid Reality short-id"));
        }
        let mut short_id = [0; 8];
        for (i, b) in short_id.iter_mut().take(short.len() / 2).enumerate() {
            *b = u8::from_str_radix(&short[i * 2..i * 2 + 2], 16)
                .map_err(|_| error(name, "invalid Reality short-id"))?;
        }
        if client_fingerprint.is_none() {
            client_fingerprint = Some("chrome".into());
        }
        if client_fingerprint.as_deref() == Some("android") {
            return Err(error(
                name,
                "Android 11 fingerprint is TLS 1.2 and cannot use Reality",
            ));
        }
        if fingerprint.is_some() {
            return Err(error(name, "Reality cannot use a certificate fingerprint"));
        }
        Some(RealitySpec {
            public_key,
            short_id,
        })
    } else {
        None
    };
    let sni = str_of(p, "sni").or_else(|| str_of(p, "servername"));
    if reality.is_some() {
        let fallback = str_of(p, "server");
        let host = sni
            .as_ref()
            .or(fallback.as_ref())
            .ok_or_else(|| error(name, "Reality requires SNI"))?;
        if host.parse::<std::net::IpAddr>().is_ok()
            || host.len() > 253
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(error(name, "Reality requires a DNS server name"));
        }
    }
    Ok(Some(TlsSpec {
        sni,
        skip_cert_verify: bool_of(p, "skip-cert-verify").unwrap_or(false),
        alpn,
        fingerprint,
        client_fingerprint,
        reality,
        ech,
    }))
}

fn ech_enabled(p: &Yaml) -> bool {
    bool_of(p, "ech").unwrap_or(false)
        || get(p, "ech-opts").is_some()
        || str_of(p, "ech-config").is_some()
}

/// 解析 mihomo / sing-box 常见的 ECH 配置写法。配置值是 DNS HTTPS 记录中的
/// ECHConfigList Base64，不在连接时访问 DNS，保证数据面只使用 RuntimeConfig。
fn parse_ech(p: &Yaml, name: &str) -> Result<Option<EchSpec>, ConfigError> {
    if !ech_enabled(p) {
        return Ok(None);
    }
    let opts = get(p, "ech-opts");
    let encoded = str_of(p, "ech-config")
        .or_else(|| opts.and_then(|o| str_of(o, "config")))
        .or_else(|| opts.and_then(|o| str_of(o, "ech")))
        .ok_or_else(|| {
            error(
                name,
                "ECH requires a Base64 config list in ech-config or ech-opts.config",
            )
        })?;
    let encoded = encoded.trim();
    if encoded.len() > 64 * 1024 {
        return Err(error(name, "ECH config list is too large"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|_| error(name, "invalid ECH config Base64"))?;
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(error(
            name,
            "ECH config list must be between 1 and 16384 bytes",
        ));
    }
    Ok(Some(EchSpec { config: bytes }))
}

pub(super) fn hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.is_ascii() {
        return None;
    }
    let mut out = [0; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub(super) fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    if s.len() == 36 && [8, 13, 18, 23].iter().any(|&i| s.as_bytes()[i] != b'-') {
        return None;
    }
    if s.len() != 36 && s.len() != 32 {
        return None;
    }
    hex(&s.replace('-', ""))
}

fn validate_ss(cipher: &str, password: &str) -> Result<(), String> {
    if crate::SS_AEAD_CIPHERS.contains(&cipher) || crate::SS_STREAM_CIPHERS.contains(&cipher) {
        return Ok(());
    }
    let key_len = match cipher {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        _ => return Err("unsupported Shadowsocks cipher".into()),
    };
    let keys: Vec<_> = password.split(':').collect();
    if keys.len() > 8 || (cipher.contains("chacha20") && keys.len() != 1) {
        return Err("invalid SS2022 key chain".into());
    }
    for key in keys {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|_| "invalid SS2022 Base64 key")?;
        if bytes.len() != key_len {
            return Err(format!("SS2022 key must decode to {key_len} bytes"));
        }
    }
    Ok(())
}

fn valid_header_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_~|".contains(&c))
}

fn ws(p: &Yaml, name: &str) -> Result<WsSpec, ConfigError> {
    let empty = Yaml::Null;
    let opts = get(p, "ws-opts").unwrap_or(&empty);
    let mut path = str_of(opts, "path").unwrap_or_else(|| "/".into());
    // mihomo 常见写法 /ws?ed=2048 等价于 max-early-data，并移除 ed 参数。
    let mut query_early = None;
    if let Some((base, query)) = path.split_once('?') {
        let mut kept = Vec::new();
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("ed=") {
                query_early = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| error(name, "invalid WS ed query"))?,
                );
            } else {
                kept.push(pair);
            }
        }
        path = if kept.is_empty() {
            base.to_string()
        } else {
            format!("{base}?{}", kept.join("&"))
        };
    }
    let max = match get(opts, "max-early-data") {
        Some(v) => crate::yaml::scalar(v)
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| error(name, "invalid WS max-early-data"))?,
        None => query_early.unwrap_or(0),
    };
    let early_data_header =
        str_of(opts, "early-data-header-name").unwrap_or_else(|| "Sec-WebSocket-Protocol".into());
    let headers = get(opts, "headers")
        .map(entries)
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| {
            Ok((
                k,
                crate::yaml::scalar(v).ok_or_else(|| error(name, "invalid WS header value"))?,
            ))
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;
    if !path.starts_with('/')
        || path.len() > 4096
        || path.bytes().any(|c| c <= 32 || c == 127)
        || path.contains('#')
    {
        return Err(error(name, "invalid WS path"));
    }
    let reserved = |s: &str| {
        matches!(
            s.to_ascii_lowercase().as_str(),
            "host"
                | "connection"
                | "upgrade"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "sec-websocket-accept"
        )
    };
    if !(0..=4096).contains(&max)
        || !valid_header_name(&early_data_header)
        || reserved(&early_data_header)
    {
        return Err(error(name, "invalid WS early data options"));
    }
    if headers.len() > 32
        || headers
            .iter()
            .map(|(k, v)| k.len() + v.len() + 4)
            .sum::<usize>()
            > 8192
        || headers.iter().any(|(k, v)| {
            !valid_header_name(k)
                || v.len() > 4096
                || v.bytes().any(|c| c < 32 || c == 127)
                || (reserved(k) && !k.eq_ignore_ascii_case("host"))
        })
    {
        return Err(error(name, "invalid or reserved WS header"));
    }
    Ok(WsSpec {
        path,
        headers,
        max_early_data: max as usize,
        early_data_header,
    })
}

pub(super) fn transport_headers(
    opts: &Yaml,
    name: &str,
) -> Result<Vec<(String, String)>, ConfigError> {
    let headers = get(opts, "headers")
        .map(entries)
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| {
            if !valid_header_name(&k)
                || matches!(
                    k.to_ascii_lowercase().as_str(),
                    "connection" | "upgrade" | "content-length" | "transfer-encoding"
                )
            {
                return Err(error(name, "invalid HTTP header name"));
            }
            let value =
                crate::yaml::scalar(v).ok_or_else(|| error(name, "invalid HTTP header value"))?;
            if value.len() > 4096 || value.bytes().any(|c| c < 32 || c == 127) {
                return Err(error(name, "invalid HTTP header value"));
            }
            Ok((k, value))
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;
    if headers.len() > 32
        || headers
            .iter()
            .map(|(k, v)| k.len() + v.len() + 4)
            .sum::<usize>()
            > 8192
    {
        return Err(error(name, "too many HTTP headers"));
    }
    Ok(headers)
}

fn http_upgrade_spec(p: &Yaml, name: &str) -> Result<HttpUpgradeSpec, ConfigError> {
    let empty = Yaml::Null;
    let opts = get(p, "ws-opts").unwrap_or(&empty);
    let path = str_of(opts, "path").unwrap_or_else(|| "/".into());
    if !path.starts_with('/')
        || path.len() > 4096
        || path.bytes().any(|c| c <= 32 || c == 127)
        || path.contains('#')
    {
        return Err(error(name, "invalid HTTPUpgrade path"));
    }
    Ok(HttpUpgradeSpec {
        path,
        headers: transport_headers(opts, name)?,
    })
}

fn grpc(p: &Yaml, name: &str) -> Result<GrpcSpec, ConfigError> {
    let empty = Yaml::Null;
    let opts = get(p, "grpc-opts").unwrap_or(&empty);
    let service_name = str_of(opts, "grpc-service-name")
        .or_else(|| str_of(p, "grpc-service-name"))
        .ok_or_else(|| error(name, "gRPC requires grpc-service-name"))?;
    if service_name.is_empty()
        || service_name.len() > 255
        || service_name
            .bytes()
            .any(|c| c <= 32 || c == 127 || !c.is_ascii_alphanumeric() && !b"-_.".contains(&c))
    {
        return Err(error(name, "invalid gRPC service name"));
    }
    Ok(GrpcSpec { service_name })
}

fn mux(p: &Yaml, name: &str, b: &mut Builder) -> Result<Option<MuxSpec>, ConfigError> {
    let Some(opts) = get(p, "smux") else {
        return Ok(None);
    };
    if !bool_of(opts, "enabled").unwrap_or(false) {
        return Ok(None);
    }
    let protocol = match str_of(opts, "protocol").as_deref() {
        None | Some("smux") => MuxProtocol::Smux,
        Some("yamux") => MuxProtocol::Yamux,
        Some("h2mux") => MuxProtocol::H2Mux,
        _ => return Err(error(name, "unsupported mux protocol")),
    };
    let number = |key: &str, default: i64, max: i64| -> Result<usize, ConfigError> {
        let n = match get(opts, key) {
            None => default,
            Some(v) => crate::yaml::scalar(v)
                .and_then(|s| s.parse::<i64>().ok())
                .ok_or_else(|| error(name, "invalid mux limit"))?,
        };
        if !(1..=max).contains(&n) {
            return Err(error(name, "invalid mux limit"));
        }
        Ok(n as usize)
    };
    let max_connections = number("max-connections", 4, 16)?;
    let max_streams = number("max-streams", 32, 64)?;
    let min_streams = number("min-streams", 4, max_streams as i64)?;
    if max_connections * max_streams > 128 {
        return Err(error(name, "mux total capacity exceeds 128 streams"));
    }
    if get(opts, "statistic").is_some() {
        b.warn(format!("proxy {name}: ignored unsupported smux.statistic"));
    }
    let brutal = match get(opts, "brutal-opts") {
        Some(brutal) if bool_of(brutal, "enabled").unwrap_or(false) => {
            let mbps = |key: &str| -> Result<u32, ConfigError> {
                let text = str_of(brutal, key)
                    .ok_or_else(|| error(name, "brutal-opts needs up and down"))?;
                let number = text.split_whitespace().next().unwrap_or("");
                let n: u32 = number
                    .parse()
                    .map_err(|_| error(name, "invalid brutal-opts bandwidth"))?;
                if !(1..=10_000).contains(&n) {
                    return Err(error(name, "brutal-opts bandwidth must be 1 to 10000 Mbps"));
                }
                Ok(n)
            };
            Some(BrutalSpec {
                up_mbps: mbps("up")?,
                down_mbps: mbps("down")?,
            })
        }
        _ => None,
    };
    Ok(Some(MuxSpec {
        brutal,
        protocol,
        max_connections,
        min_streams,
        max_streams,
        padding: bool_of(opts, "padding").unwrap_or(false),
        only_tcp: bool_of(opts, "only-tcp").unwrap_or(false),
    }))
}

/// `dialer-proxy`：目标在所有节点和策略组解析完之后才能确定，先记下名称。
fn register_dialer(p: &Yaml, name: &str, index: usize, b: &mut Builder) -> Result<(), ConfigError> {
    if let Some(target) = str_of(p, "dialer-proxy") {
        if target == name {
            return Err(error(name, "dialer-proxy cannot refer to itself"));
        }
        b.pending_dialers.push((index, target));
    }
    Ok(())
}

fn host_list(opts: &Yaml, key: &str, name: &str) -> Result<Vec<String>, ConfigError> {
    let hosts = list_of(opts, key);
    if hosts.len() > 8
        || hosts
            .iter()
            .any(|h| h.len() > 253 || h.bytes().any(|c| c <= 32 || c == 127))
    {
        return Err(error(name, "invalid host list"));
    }
    Ok(hosts)
}

fn plain_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 1024
        && !path.bytes().any(|c| c <= 32 || c == 127)
        && !path.contains('#')
}

fn h2_spec(p: &Yaml, name: &str) -> Result<H2Spec, ConfigError> {
    let empty = Yaml::Null;
    let opts = get(p, "h2-opts").unwrap_or(&empty);
    let path = str_of(opts, "path").unwrap_or_else(|| "/".into());
    if !plain_path(&path) {
        return Err(error(name, "invalid HTTP/2 path"));
    }
    Ok(H2Spec {
        hosts: host_list(opts, "host", name)?,
        path,
    })
}

fn http_spec(p: &Yaml, name: &str) -> Result<HttpSpec, ConfigError> {
    let empty = Yaml::Null;
    let opts = get(p, "http-opts").unwrap_or(&empty);
    let method = str_of(opts, "method").unwrap_or_else(|| "GET".into());
    if method.is_empty() || method.len() > 16 || !method.bytes().all(|c| c.is_ascii_alphabetic()) {
        return Err(error(name, "invalid HTTP method"));
    }
    // mihomo 的 path 是候选列表；这里取第一个
    let paths = list_of(opts, "path");
    if paths.len() > 8 {
        return Err(error(name, "too many HTTP paths"));
    }
    let path = paths.into_iter().next().unwrap_or_else(|| "/".into());
    if !plain_path(&path) {
        return Err(error(name, "invalid HTTP path"));
    }
    let mut hosts = Vec::new();
    let mut headers = Vec::new();
    if let Some(h) = get(opts, "headers") {
        for (key, value) in entries(h) {
            if !valid_header_name(&key)
                || matches!(
                    key.to_ascii_lowercase().as_str(),
                    "connection" | "upgrade" | "content-length" | "transfer-encoding"
                )
            {
                return Err(error(name, "invalid HTTP header name"));
            }
            let values = crate::yaml::list_value(value);
            if values
                .iter()
                .any(|v| v.len() > 1024 || v.bytes().any(|c| c < 32 || c == 127))
            {
                return Err(error(name, "invalid HTTP header value"));
            }
            if key.eq_ignore_ascii_case("host") {
                if values.len() > 8 {
                    return Err(error(name, "invalid host list"));
                }
                hosts = values;
            } else if let Some(first) = values.into_iter().next() {
                headers.push((key, first));
            }
        }
    }
    if headers.len() > 16 {
        return Err(error(name, "too many HTTP headers"));
    }
    Ok(HttpSpec {
        method,
        path,
        headers,
        hosts,
    })
}

fn first_yaml<'a>(node: &'a Yaml, keys: &[&str]) -> Option<&'a Yaml> {
    keys.iter().find_map(|key| get(node, key))
}
type XHttpHeaders = (Vec<String>, Vec<(String, String)>);

fn xhttp_spec(p: &Yaml, name: &str) -> Result<XHttpSpec, ConfigError> {
    let empty = Yaml::Null;
    let opts = get(p, "xhttp-opts").unwrap_or(&empty);
    let str_any = |node: &Yaml, keys: &[&str]| -> Option<String> {
        keys.iter().find_map(|key| str_of(node, key))
    };
    let bool_any = |node: &Yaml, keys: &[&str]| -> Option<bool> {
        keys.iter().find_map(|key| bool_of(node, key))
    };
    let path = str_any(opts, &["path"]).unwrap_or_else(|| "/".into());
    if !plain_path(&path) {
        return Err(error(name, "invalid XHTTP path"));
    }
    let method = str_any(opts, &["method"]).unwrap_or_else(|| "POST".into());
    if method.is_empty() || method.len() > 16 || !method.bytes().all(|c| c.is_ascii_alphabetic()) {
        return Err(error(name, "invalid XHTTP method"));
    }
    let mode = str_any(opts, &["mode"])
        .unwrap_or_else(|| "auto".into())
        .to_ascii_lowercase();
    if !matches!(
        mode.as_str(),
        "auto" | "stream-one" | "stream-up" | "packet-up"
    ) {
        return Err(error(name, "invalid XHTTP mode"));
    }
    let parse_headers = |node: &Yaml| -> Result<XHttpHeaders, ConfigError> {
        let mut hosts = Vec::new();
        let mut headers = Vec::new();
        if let Some(h) = first_yaml(node, &["headers"]) {
            for (key, value) in entries(h) {
                if !valid_header_name(&key)
                    || key.eq_ignore_ascii_case("connection")
                    || key.eq_ignore_ascii_case("content-length")
                {
                    return Err(error(name, "invalid XHTTP header name"));
                }
                let values = crate::yaml::list_value(value);
                if values
                    .iter()
                    .any(|v| v.len() > 1024 || v.bytes().any(|c| c < 32 || c == 127))
                {
                    return Err(error(name, "invalid XHTTP header value"));
                }
                if key.eq_ignore_ascii_case("host") {
                    hosts = values;
                } else if let Some(first) = values.into_iter().next() {
                    headers.push((key, first));
                }
            }
        }
        if let Some(h) = first_yaml(node, &["host"]) {
            hosts = crate::yaml::list_value(h);
        }
        if hosts.len() > 8
            || hosts
                .iter()
                .any(|v| v.len() > 253 || v.bytes().any(|c| c <= 32 || c == 127))
            || headers.len() > 32
        {
            return Err(error(name, "invalid XHTTP host or headers"));
        }
        Ok((hosts, headers))
    };
    let (hosts, headers) = parse_headers(opts)?;
    let text_opt = |key: &str, default: &str| -> Result<String, ConfigError> {
        if get(opts, key).is_some() && str_of(opts, key).is_none() {
            return Err(error(name, "invalid XHTTP option"));
        }
        let value = str_of(opts, key).unwrap_or_else(|| default.into());
        if value.is_empty() || value.len() > 64 || value.bytes().any(|c| c < 0x21 || c == 0x7f) {
            return Err(error(name, "invalid XHTTP option"));
        }
        Ok(value)
    };
    let placement = |key: &str, default: &str| -> Result<String, ConfigError> {
        let value = text_opt(key, default)?.to_ascii_lowercase();
        if !matches!(value.as_str(), "header" | "cookie" | "body" | "auto") {
            return Err(error(name, "unsupported XHTTP uplink data placement"));
        }
        Ok(value)
    };
    // Session and sequence metadata are request path/query/header/cookie
    // fields in mihomo. `body` is reserved for packet payload placement and
    // must be rejected instead of being silently ignored.
    let meta_placement = |key: &str, default: &str| -> Result<String, ConfigError> {
        let value = text_opt(key, default)?.to_ascii_lowercase();
        if !matches!(value.as_str(), "path" | "query" | "header" | "cookie") {
            return Err(error(name, "invalid XHTTP metadata placement"));
        }
        Ok(value)
    };
    let bounded = |key: &str, default: i64, min: i64, max: i64| -> Result<usize, ConfigError> {
        let value = match get(opts, key) {
            None => default,
            Some(v) => crate::yaml::scalar(v)
                .and_then(|s| s.parse::<i64>().ok())
                .ok_or_else(|| error(name, "invalid XHTTP size option"))?,
        };
        if !(min..=max).contains(&value) {
            return Err(error(name, "invalid XHTTP size option"));
        }
        Ok(value as usize)
    };
    let range_max =
        |node: &Yaml, keys: &[&str], default: &str, limit: usize| -> Result<usize, ConfigError> {
            let text = first_yaml(node, keys)
                .and_then(crate::yaml::scalar)
                .unwrap_or_else(|| default.to_string());
            let mut parts = text.trim().split('-');
            let first = parts
                .next()
                .and_then(|v| v.trim().parse::<usize>().ok())
                .ok_or_else(|| error(name, "invalid XHTTP range"))?;
            let last = match parts.next() {
                None => first,
                Some(v) if parts.next().is_none() => v
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| error(name, "invalid XHTTP range"))?,
                _ => return Err(error(name, "invalid XHTTP range")),
            };
            if last < first || last > limit {
                return Err(error(name, "invalid XHTTP range"));
            }
            Ok(last)
        };
    let no_grpc_header = bool_any(opts, &["no-grpc-header", "noGRPCHeader"]).unwrap_or(false);
    if first_yaml(opts, &["no-grpc-header", "noGRPCHeader"]).is_some()
        && bool_any(opts, &["no-grpc-header", "noGRPCHeader"]).is_none()
    {
        return Err(error(name, "invalid XHTTP no-grpc-header"));
    }
    let uplink_http_method = text_opt("uplink-http-method", &method)?;
    let uplink_data_placement = placement("uplink-data-placement", "body")?;
    let uplink_data_key = text_opt("uplink-data-key", "data")?;
    let session_placement = meta_placement("session-placement", "path")?;
    let session_key = text_opt(
        "session-key",
        if session_placement == "header" {
            "X-Session"
        } else {
            "x_session"
        },
    )?;
    let seq_placement = meta_placement("seq-placement", "path")?;
    let seq_key = text_opt(
        "seq-key",
        if seq_placement == "header" {
            "X-Seq"
        } else {
            "x_seq"
        },
    )?;
    let valid_cookie_name = |value: &str| {
        !value.is_empty()
            && value.bytes().all(|c| {
                c > 0x20
                    && c < 0x7f
                    && !matches!(
                        c,
                        b'(' | b')'
                            | b'<'
                            | b'>'
                            | b'@'
                            | b','
                            | b';'
                            | b':'
                            | b'\\'
                            | b'"'
                            | b'/'
                            | b'['
                            | b']'
                            | b'?'
                            | b'='
                            | b'{'
                            | b'}'
                    )
            })
    };
    if session_placement == "body"
        || seq_placement == "body"
        || (session_placement == "header" && !valid_header_name(&session_key))
        || (seq_placement == "header" && !valid_header_name(&seq_key))
        || (session_placement == "cookie" && !valid_cookie_name(&session_key))
        || (seq_placement == "cookie" && !valid_cookie_name(&seq_key))
    {
        return Err(error(name, "invalid XHTTP session or sequence placement"));
    }
    if (uplink_data_placement == "header" && !valid_header_name(&format!("{}-0", uplink_data_key)))
        || (uplink_data_placement == "cookie"
            && !valid_cookie_name(&format!("{}_0", uplink_data_key)))
    {
        return Err(error(name, "invalid XHTTP uplink data key"));
    }
    let uplink_chunk_size = bounded("uplink-chunk-size", 16 * 1024, 64, 64 * 1024)?;
    // body 方式上传时一块就是一条 POST；默认 64 KiB，配合在途流水线不被往返时延限制（见 docs/protocols/xhttp.md）
    let sc_max_each_post_bytes = bounded("sc-max-each-post-bytes", 64 * 1024, 256, 1024 * 1024)?;
    let sc_min_posts_interval_ms =
        range_max(opts, &["sc-min-posts-interval-ms"], "0", 60_000)? as u64;
    let padding_text = first_yaml(opts, &["x-padding-bytes", "xPaddingBytes"])
        .and_then(crate::yaml::scalar)
        .unwrap_or_else(|| "100-1000".into());
    let mut pp = padding_text.trim().split('-');
    let padding_min = pp
        .next()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .ok_or_else(|| error(name, "invalid XHTTP padding range"))?;
    let padding_max = match pp.next() {
        None => padding_min,
        Some(v) if pp.next().is_none() => v
            .trim()
            .parse::<usize>()
            .map_err(|_| error(name, "invalid XHTTP padding range"))?,
        _ => return Err(error(name, "invalid XHTTP padding range")),
    };
    if padding_max < padding_min || padding_max > 64 * 1024 {
        return Err(error(name, "invalid XHTTP padding range"));
    }
    let obfs_mode = bool_any(opts, &["x-padding-obfs-mode", "xPaddingObfsMode"]).unwrap_or(false);
    if first_yaml(opts, &["x-padding-obfs-mode", "xPaddingObfsMode"]).is_some()
        && bool_any(opts, &["x-padding-obfs-mode", "xPaddingObfsMode"]).is_none()
    {
        return Err(error(name, "invalid XHTTP padding obfs mode"));
    }
    let padding_key =
        str_any(opts, &["x-padding-key", "xPaddingKey"]).unwrap_or_else(|| "x_padding".into());
    let padding_header =
        str_any(opts, &["x-padding-header", "xPaddingHeader"]).unwrap_or_else(|| "Referer".into());
    if !valid_header_name(&padding_header)
        || !valid_header_name(&padding_key)
        || padding_key.len() > 64
        || padding_key.bytes().any(|c| c <= 32 || c == 127)
    {
        return Err(error(name, "invalid XHTTP padding header or key"));
    }
    let padding_placement = str_any(opts, &["x-padding-placement", "xPaddingPlacement"])
        .unwrap_or_else(|| "queryInHeader".into());
    let padding_placement = match padding_placement.to_ascii_lowercase().as_str() {
        "queryinheader" => "queryinheader",
        "cookie" => "cookie",
        "header" => "header",
        "query" => "query",
        _ => return Err(error(name, "invalid XHTTP padding placement")),
    }
    .to_string();
    let padding_method = str_any(opts, &["x-padding-method", "xPaddingMethod"])
        .unwrap_or_else(|| "repeat-x".into())
        .to_ascii_lowercase();
    if !matches!(padding_method.as_str(), "repeat-x" | "tokenish") {
        return Err(error(name, "invalid XHTTP padding method"));
    }
    let has_download = first_yaml(opts, &["download-settings", "downloadSettings"]).is_some();
    let reuse = parse_xhttp_reuse(opts, name)?;
    if mode == "stream-one" && has_download {
        return Err(error(name, "XHTTP stream-one cannot use download-settings"));
    }
    let session_table = str_any(opts, &["session-table", "sessionTable"]).unwrap_or_default();
    if session_table.len() > 128
        || session_table
            .bytes()
            .any(|c| !c.is_ascii() || c <= 0x20 || c == 0x7f)
    {
        return Err(error(name, "invalid XHTTP session table"));
    }
    let session_length = range_max(opts, &["session-length", "sessionLength"], "16", 128)?;
    let sc_max_buffered_posts = range_max(
        opts,
        &["sc-max-buffered-posts", "scMaxBufferedPosts"],
        "16",
        1024,
    )?;
    let mut spec = XHttpSpec {
        hosts,
        path,
        method,
        mode,
        headers,
        no_grpc_header,
        uplink_http_method,
        uplink_data_placement,
        uplink_data_key,
        uplink_chunk_size,
        session_placement,
        session_key,
        seq_placement,
        seq_key,
        sc_max_each_post_bytes,
        sc_min_posts_interval_ms,
        padding: XHttpPaddingSpec {
            min: padding_min,
            max: padding_max,
            obfs_mode,
            key: padding_key,
            header: padding_header,
            placement: padding_placement,
            method: padding_method,
        },
        download: None,
        reuse,
        session_table,
        session_length,
        sc_max_buffered_posts,
    };
    spec.download = parse_xhttp_download(p, opts, name, &spec)?;
    if spec.mode == "auto" && get(p, "reality-opts").is_some() {
        spec.mode = if has_download {
            "stream-up"
        } else {
            "stream-one"
        }
        .into();
    }
    Ok(spec)
}

fn parse_xhttp_download(
    p: &Yaml,
    opts: &Yaml,
    name: &str,
    parent: &XHttpSpec,
) -> Result<Option<XHttpDownloadSpec>, ConfigError> {
    let Some(download) = first_yaml(opts, &["download-settings", "downloadSettings"]) else {
        return Ok(None);
    };
    let Yaml::Hash(fields) = download else {
        return Err(error(name, "invalid XHTTP download-settings"));
    };
    let mut endpoint = p.clone();
    let Yaml::Hash(ref mut endpoint_fields) = endpoint else {
        unreachable!()
    };
    // sni / servername 是别名，下载端显式覆盖任一项时不能被上行别名遮蔽。
    if get(download, "servername").is_some() || get(download, "sni").is_some() {
        endpoint_fields.remove(&Yaml::String("sni".into()));
        endpoint_fields.remove(&Yaml::String("servername".into()));
    }
    let mut transport = parent.clone();
    // 未提供的字段继承上行；显式空 headers 必须清空，而不是与上行拼接。
    let mut request = opts.clone();
    if !matches!(request, Yaml::Hash(_)) {
        request = Yaml::Hash(Default::default());
    }
    let Yaml::Hash(ref mut request_fields) = request else {
        unreachable!()
    };
    request_fields.remove(&Yaml::String("download-settings".into()));
    request_fields.remove(&Yaml::String("downloadSettings".into()));
    for (key, value) in fields {
        let Some(key_str) = key.as_str() else {
            return Err(error(name, "invalid XHTTP download key"));
        };
        match key_str {
            "host" | "path" | "headers" | "reuse-settings" | "reuseSettings" => {
                request_fields.insert(key.clone(), value.clone());
            }
            "server" | "port" | "tls" | "alpn" | "servername" | "sni" | "skip-cert-verify"
            | "fingerprint" | "client-fingerprint" | "reality-opts" | "ech-opts" => {
                endpoint_fields.insert(key.clone(), value.clone());
            }
            _ => {
                return Err(error(
                    name,
                    &format!("unsupported XHTTP download-settings field: {key_str}"),
                ))
            }
        }
    }
    if get(download, "tls").is_some() && bool_of(download, "tls").is_none() {
        return Err(error(name, "invalid XHTTP download TLS flag"));
    }
    let server = server(&endpoint, name)?;
    let required = bool_of(download, "tls").unwrap_or_else(|| {
        str_of(p, "type").as_deref() == Some("trojan") || bool_of(p, "tls").unwrap_or(false)
    });
    let security = tls(&endpoint, name, required)?
        .map(SecuritySpec::Tls)
        .unwrap_or(SecuritySpec::None);
    if matches!(&security, SecuritySpec::Tls(t) if t.alpn.iter().any(|a| a != "h2")) {
        return Err(error(name, "XHTTP download requires h2 ALPN"));
    }
    // 复用同一请求参数解析器，但先移除下载配置以保证递归深度为一层。
    if let Yaml::Hash(ref mut endpoint_fields) = endpoint {
        endpoint_fields.insert(Yaml::String("xhttp-opts".into()), request);
    }
    let parsed = xhttp_spec(&endpoint, name)?;
    transport.hosts = parsed.hosts;
    transport.path = parsed.path;
    transport.headers = parsed.headers;
    transport.reuse = parsed.reuse;
    if transport.hosts.is_empty() {
        let host = match &security {
            SecuritySpec::Tls(t) if t.sni.is_some() => t.sni.clone().unwrap(),
            _ => match &server {
                TargetAddr::Domain(d, _) => d.clone(),
                TargetAddr::Ip(a) => a.ip().to_string(),
            },
        };
        transport.hosts = vec![if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host
        }];
    }
    Ok(Some(XHttpDownloadSpec {
        server,
        security,
        hosts: transport.hosts.clone(),
        path: transport.path.clone(),
        headers: transport.headers.clone(),
        transport: Box::new(transport),
    }))
}

fn parse_xhttp_reuse(opts: &Yaml, name: &str) -> Result<XHttpReuseSpec, ConfigError> {
    let Some(reuse) = ["reuse-settings", "reuseSettings", "xmux"]
        .iter()
        .find_map(|key| get(opts, key))
    else {
        return Ok(XHttpReuseSpec::default());
    };
    if !matches!(reuse, Yaml::Hash(_)) {
        return Err(error(name, "invalid XHTTP reuse-settings"));
    }
    let range = |keys: &[&str], limit: usize| -> Result<(usize, usize), ConfigError> {
        let text = keys
            .iter()
            .find_map(|key| get(reuse, key))
            .and_then(crate::yaml::scalar);
        let Some(text) = text else { return Ok((0, 0)) };
        let mut parts = text.trim().split('-');
        let first = parts
            .next()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .ok_or_else(|| error(name, "invalid XHTTP reuse range"))?;
        let last = match parts.next() {
            None => first,
            Some(v) if parts.next().is_none() => v
                .trim()
                .parse::<usize>()
                .map_err(|_| error(name, "invalid XHTTP reuse range"))?,
            _ => return Err(error(name, "invalid XHTTP reuse range")),
        };
        if last < first || last > limit {
            return Err(error(name, "invalid XHTTP reuse range"));
        }
        Ok((first, last))
    };
    for (key, _) in entries(reuse) {
        if ![
            "max-concurrency",
            "maxConcurrency",
            "max-connections",
            "maxConnections",
            "c-max-reuse-times",
            "cMaxReuseTimes",
            "h-max-request-times",
            "hMaxRequestTimes",
            "h-max-reusable-secs",
            "hMaxReusableSecs",
        ]
        .contains(&key.as_str())
        {
            return Err(error(
                name,
                &format!("unsupported XHTTP reuse-settings field: {key}"),
            ));
        }
    }
    let (min_max_concurrency, max_concurrency) =
        range(&["max-concurrency", "maxConcurrency"], 128)?;
    let (min_max_connections, max_connections) = range(&["max-connections", "maxConnections"], 32)?;
    let (min_max_reuse_times, max_reuse_times) =
        range(&["c-max-reuse-times", "cMaxReuseTimes"], 100_000)?;
    let (min_max_request_times, max_request_times) =
        range(&["h-max-request-times", "hMaxRequestTimes"], 100_000)?;
    let (min_max_reusable_secs, max_reusable_secs) =
        range(&["h-max-reusable-secs", "hMaxReusableSecs"], 86_400)?;
    Ok(XHttpReuseSpec {
        min_max_concurrency,
        max_concurrency,
        min_max_connections,
        max_connections,
        min_max_reuse_times,
        max_reuse_times,
        min_max_request_times,
        max_request_times,
        min_max_reusable_secs: min_max_reusable_secs as u64,
        max_reusable_secs: max_reusable_secs as u64,
    })
}

fn kcp_spec(p: &Yaml, name: &str) -> Result<KcpSpec, ConfigError> {
    let empty = Yaml::Null;
    let opts = first_yaml(p, &["mkcp-opts", "kcp-opts"]).unwrap_or(&empty);
    kcp_spec_opts(opts, name)
}

fn kcp_spec_opts(opts: &Yaml, name: &str) -> Result<KcpSpec, ConfigError> {
    let number = |key: &str, default: i64, min: i64, max: i64| -> Result<i64, ConfigError> {
        let v = get(opts, key)
            .and_then(crate::yaml::scalar)
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(default);
        if !(min..=max).contains(&v) {
            return Err(error(name, "invalid mKCP option"));
        }
        Ok(v)
    };
    let header = str_of(opts, "header")
        .unwrap_or_else(|| "none".into())
        .to_ascii_lowercase();
    if !matches!(
        header.as_str(),
        "none" | "srtp" | "utp" | "wechat" | "wechat-video" | "dtls" | "wireguard"
    ) {
        return Err(error(name, "unsupported mKCP header type"));
    }
    let header = if header == "wechat" {
        "wechat-video".into()
    } else {
        header
    };
    let seed = get(opts, "seed")
        .and_then(crate::yaml::scalar)
        .filter(|s| !s.is_empty());
    if seed.as_ref().is_some_and(|s| s.len() > 1024) {
        return Err(error(name, "mKCP seed is too long"));
    }
    let read_buffer_key = if get(opts, "read-buffer").is_some() {
        "read-buffer"
    } else {
        "read-buffer-size"
    };
    let write_buffer_key = if get(opts, "write-buffer").is_some() {
        "write-buffer"
    } else {
        "write-buffer-size"
    };
    Ok(KcpSpec {
        mtu: number("mtu", 1350, 576, 1500)? as u16,
        tti: number("tti", 50, 10, 500)? as u16,
        uplink_capacity: number("uplink-capacity", 5, 1, 100_000)? as u32,
        downlink_capacity: number("downlink-capacity", 20, 1, 100_000)? as u32,
        congestion: bool_of(opts, "congestion").unwrap_or(false),
        read_buffer_size: number(
            read_buffer_key,
            2 * 1024 * 1024,
            16 * 1024,
            16 * 1024 * 1024,
        )? as usize,
        write_buffer_size: number(
            write_buffer_key,
            2 * 1024 * 1024,
            16 * 1024,
            16 * 1024 * 1024,
        )? as usize,
        header,
        seed,
    })
}

fn mekya_spec(p: &Yaml, name: &str) -> Result<MekyaSpec, ConfigError> {
    let empty = Yaml::Null;
    let opts = get(p, "mekya-opts").unwrap_or(&empty);
    let url = str_of(opts, "url").unwrap_or_else(|| {
        // URL is completed by the outbound with the configured server when
        // omitted, matching mihomo's https://<server> default.
        String::new()
    });
    if url.len() > 2048 || (url.is_empty() && get(opts, "url").is_some()) {
        return Err(error(name, "invalid Mekya URL"));
    }
    let bounded = |key: &str, default: i64, min: i64, max: i64| -> Result<i64, ConfigError> {
        let v = match get(opts, key) {
            None => default,
            Some(v) => crate::yaml::scalar(v)
                .and_then(|s| s.parse::<i64>().ok())
                .ok_or_else(|| error(name, "invalid Mekya option"))?,
        };
        if !(min..=max).contains(&v) {
            return Err(error(name, "invalid Mekya option"));
        }
        Ok(v)
    };
    let kcp = kcp_spec_opts(get(opts, "kcp").unwrap_or(opts), name)?;
    let max_request_size = bounded(
        "max-request-size",
        64 * 1024,
        i64::from(kcp.mtu) + 2,
        1024 * 1024,
    )? as usize;
    Ok(MekyaSpec {
        url,
        h2_pool_size: bounded("h2-pool-size", 1, 1, 8)? as usize,
        max_write_delay_ms: bounded("max-write-delay", 0, 0, 60_000)? as u64,
        max_request_size,
        polling_interval_initial_ms: bounded("polling-interval-initial", 50, 1, 60_000)? as u64,
        max_write_size: bounded("max-write-size", 64 * 1024, 256, 1024 * 1024)? as usize,
        max_write_duration_ms: bounded("max-write-duration-ms", 50, 1, 60_000)? as u64,
        max_simultaneous_write_connections: bounded("max-simultaneous-write-connection", 4, 1, 32)?
            as usize,
        packet_writing_buffer: bounded("packet-writing-buffer", 256, 16, 4096)? as usize,
        kcp,
    })
}

/// Shadowsocks 的 SIP003 插件。
fn ss_plugin(p: &Yaml, name: &str, server: &TargetAddr) -> Result<SsPlugin, ConfigError> {
    let Some(plugin) = str_of(p, "plugin") else {
        return Ok(SsPlugin::None);
    };
    let empty = Yaml::Null;
    let opts = get(p, "plugin-opts").unwrap_or(&empty);
    match plugin.as_str() {
        "shadow-tls" => {
            if get(p, "plugin-opts").is_none() {
                return Err(error(name, "missing ShadowTLS plugin-opts"));
            }
            let version = int_of(opts, "version").unwrap_or(0);
            if !(1..=3).contains(&version) {
                return Err(error(name, "ShadowTLS version must be 1, 2 or 3"));
            }
            let host =
                str_of(opts, "host").ok_or_else(|| error(name, "ShadowTLS requires host"))?;
            let password = if version == 1 {
                password_value(opts).unwrap_or_default()
            } else {
                required_password(opts, name)?
            };
            let alpn = list_of(opts, "alpn");
            if host.len() > 253
                || host.is_empty()
                || alpn.len() > 16
                || alpn.iter().any(|s| s.len() > 255)
            {
                return Err(error(name, "invalid ShadowTLS host or ALPN"));
            }
            Ok(SsPlugin::ShadowTls(ShadowTlsSpec {
                version: version as u8,
                host,
                password,
                alpn,
                // mihomo 把它放在 plugin-opts 里；与 v2ray-plugin 一样也接受代理顶层的写法
                skip_cert_verify: bool_of(opts, "skip-cert-verify")
                    .or_else(|| bool_of(p, "skip-cert-verify"))
                    .unwrap_or(false),
            }))
        }
        "obfs" | "simple-obfs" => {
            let mode = str_of(opts, "mode").unwrap_or_else(|| "http".into());
            let tls = match mode.as_str() {
                "http" => false,
                "tls" => true,
                _ => return Err(error(name, "obfs mode must be http or tls")),
            };
            // 与 sing-box 一致，host 缺省时使用 bing.com
            let host = str_of(opts, "host").unwrap_or_else(|| "bing.com".into());
            if host.len() > 253 || host.bytes().any(|c| c <= 32 || c == 127) {
                return Err(error(name, "invalid obfs host"));
            }
            Ok(SsPlugin::Obfs(ObfsSpec { tls, host }))
        }
        "v2ray-plugin" | "gost-plugin" => {
            let mode = str_of(opts, "mode").unwrap_or_else(|| "websocket".into());
            if mode != "websocket" {
                return Err(error(name, "only websocket plugin mode is supported"));
            }
            if bool_of(opts, "v2ray-http-upgrade").unwrap_or(false) {
                return Err(error(name, "v2ray-plugin HTTPUpgrade is not supported"));
            }
            let host = str_of(opts, "host").unwrap_or_default();
            let path = str_of(opts, "path").unwrap_or_else(|| "/".into());
            if host.len() > 253 || host.bytes().any(|c| c <= 32 || c == 127) || !plain_path(&path) {
                return Err(error(name, "invalid v2ray-plugin host or path"));
            }
            let headers = transport_headers(opts, name)?;
            let tls = if bool_of(opts, "tls").unwrap_or(false) {
                let fingerprint = match str_of(opts, "fingerprint") {
                    Some(s) => Some(
                        hex::<32>(&s.replace(':', ""))
                            .ok_or_else(|| error(name, "invalid SHA-256 fingerprint"))?,
                    ),
                    None => None,
                };
                Some(TlsSpec {
                    sni: Some(if host.is_empty() {
                        match server {
                            TargetAddr::Domain(d, _) => d.clone(),
                            TargetAddr::Ip(a) => a.ip().to_string(),
                        }
                    } else {
                        host.clone()
                    }),
                    skip_cert_verify: bool_of(opts, "skip-cert-verify")
                        .or_else(|| bool_of(p, "skip-cert-verify"))
                        .unwrap_or(false),
                    alpn: vec!["http/1.1".into()],
                    fingerprint,
                    client_fingerprint: None,
                    reality: None,
                    ech: None,
                })
            } else {
                None
            };
            // 两个插件默认都开启复用：v2ray-plugin 是 Mux.Cool，gost-plugin 是 smux（与 mihomo 相同）
            let mux = bool_of(opts, "mux").unwrap_or(true);
            let spec = V2RayPluginSpec {
                tls,
                host,
                path,
                headers,
                mux,
            };
            Ok(if plugin == "gost-plugin" {
                SsPlugin::Gost(spec)
            } else {
                SsPlugin::V2Ray(spec)
            })
        }
        _ => Err(error(name, "unsupported Shadowsocks plugin")),
    }
}
