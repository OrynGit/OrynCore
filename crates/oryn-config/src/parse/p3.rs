//! Hysteria2、TUIC v5、WireGuard 的配置解析。
//!
//! feature 关闭时调用方不会进入 [`parse`]，只发出「未编译」警告。

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::Engine;
use yaml_rust2::Yaml;

use super::proxies::{error, hex, parse_uuid, password_value};
use super::Builder;
use crate::model::*;
use crate::yaml::{bool_of, get, int_of, list_of, scalar, str_of};
use crate::{ConfigError, IpCidr, TargetAddr};

pub(super) fn compiled(ty: &str) -> bool {
    (cfg!(feature = "hysteria2") && matches!(ty, "hysteria2" | "hysteria"))
        || (cfg!(feature = "tuic") && ty == "tuic")
        || (cfg!(feature = "wireguard") && ty == "wireguard")
        || (cfg!(feature = "quic") && ty == "quic")
}

pub(super) fn parse(
    ty: &str,
    p: &Yaml,
    name: &str,
    b: &mut Builder,
) -> Result<Option<OutboundKind>, ConfigError> {
    match ty {
        "hysteria2" => hysteria2(p, name, b),
        "hysteria" => hysteria(p, name, b),
        "tuic" => tuic(p, name, b),
        "wireguard" => wireguard(p, name, b),
        _ => Ok(None),
    }
}

fn warn_ignored(b: &mut Builder, name: &str, field: &str) {
    b.warn(format!("proxy {name}: ignored unsupported {field}"));
}

fn hysteria2(p: &Yaml, name: &str, b: &mut Builder) -> Result<Option<OutboundKind>, ConfigError> {
    if get(p, "bbr-profile").is_some() {
        warn_ignored(b, name, "bbr-profile");
    }
    let obfs = str_of(p, "obfs").map(|s| s.to_ascii_lowercase());
    let realm = realm(p, name, b)?;
    if obfs.is_some() && !matches!(obfs.as_deref(), Some("salamander" | "gecko")) {
        return Err(error(name, "unsupported hysteria2 obfuscation"));
    }
    let gecko = if obfs.as_deref() == Some("gecko") {
        let size = |key: &str, default: i64| -> Result<u16, ConfigError> {
            match get(p, key) {
                None => Ok(default as u16),
                Some(_) => int_of(p, key)
                    .filter(|n| (0..=2048).contains(n))
                    .map(|n| n as u16)
                    .ok_or_else(|| error(name, "invalid gecko packet size")),
            }
        };
        let (min, max) = (
            size("obfs-min-packet-size", 512)?,
            size("obfs-max-packet-size", 1200)?,
        );
        if min > max {
            return Err(error(name, "gecko minimum packet size exceeds the maximum"));
        }
        Some((min, max))
    } else {
        for field in ["obfs-min-packet-size", "obfs-max-packet-size"] {
            if get(p, field).is_some() {
                warn_ignored(b, name, field);
            }
        }
        None
    };
    let (server, ports) = match &realm {
        // 走会合服务器时对端地址由打洞决定；server / port 可以不写，TLS 名称退回会合服务器的主机名
        Some(realm) if str_of(p, "server").is_none() => {
            (TargetAddr::Domain(realm.host.clone(), 443), None)
        }
        Some(_) if get(p, "port").is_none() && get(p, "ports").is_none() => (
            TargetAddr::from_host(&str_of(p, "server").unwrap_or_default(), 443),
            None,
        ),
        _ => server_and_ports(p, name, b)?,
    };
    if realm.is_some() && ports.is_some() {
        return Err(error(name, "realm and port hopping are mutually exclusive"));
    }
    let password = password_value(p).unwrap_or_default();
    if password.is_empty() {
        b.warn(format!("proxy {name}: hysteria2 password is empty"));
    }
    let obfs_password = if obfs.is_some() {
        let pw = password_value_key(p, "obfs-password").unwrap_or_default();
        if pw.len() < 4 {
            return Err(error(name, "invalid salamander password"));
        }
        Some(pw)
    } else {
        if get(p, "obfs-password").is_some() {
            warn_ignored(b, name, "obfs-password");
        }
        None
    };
    let up_bps = bandwidth(p, name, "up")?;
    let down_bps = bandwidth(p, name, "down")?;
    let (hop_min_secs, hop_max_secs) = hop_interval(p, name, b)?;
    Ok(Some(OutboundKind::Hysteria2(Hysteria2Spec {
        server,
        ports,
        password,
        up_bps,
        down_bps,
        obfs_password,
        gecko,
        tls: quic_tls(p, name, b)?,
        hop_min_secs,
        hop_max_secs,
        udp: bool_of(p, "udp").unwrap_or(false),
        realm,
    })))
}

/// mihomo 的 `realm-opts`（`enable: true` 才生效）。证书双向认证与 `name-cert-verify` 不支持。
fn realm(p: &Yaml, name: &str, b: &mut Builder) -> Result<Option<RealmSpec>, ConfigError> {
    if get(p, "realm").is_some() {
        warn_ignored(b, name, "realm (use realm-opts)");
    }
    let Some(opts) = get(p, "realm-opts") else {
        return Ok(None);
    };
    if !bool_of(opts, "enable").unwrap_or(false) {
        return Ok(None);
    }
    for field in ["certificate", "private-key", "name-cert-verify", "alpn"] {
        if get(opts, field).is_some() {
            warn_ignored(b, name, &format!("realm-opts.{field}"));
        }
    }
    let url = str_of(opts, "server-url").ok_or_else(|| error(name, "missing realm server-url"))?;
    let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(error(name, "realm server-url must be http or https"));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
        None => (rest, ""),
    };
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, tail) = inner
            .split_once(']')
            .ok_or_else(|| error(name, "invalid realm server-url"))?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port
                .parse::<u16>()
                .map_err(|_| error(name, "invalid realm server-url"))?,
            None if tail.is_empty() => default_port,
            None => return Err(error(name, "invalid realm server-url")),
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (
                host.to_string(),
                port.parse::<u16>()
                    .map_err(|_| error(name, "invalid realm server-url"))?,
            ),
            None => (authority.to_string(), default_port),
        }
    };
    if host.is_empty()
        || port == 0
        || path.contains(['?', '#'])
        || path.chars().any(|c| c.is_control() || c == ' ')
    {
        return Err(error(name, "invalid realm server-url"));
    }
    let realm_id = str_of(opts, "realm-id").unwrap_or_default();
    // 与会合服务的 realm 名称规则一致
    let valid_id = realm_id.len() <= 64
        && realm_id
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && realm_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !valid_id {
        return Err(error(name, "invalid realm-id"));
    }
    let token = str_of(opts, "token").unwrap_or_default();
    if token.chars().any(|c| c.is_control()) || token.len() > 1024 {
        return Err(error(name, "invalid realm token"));
    }
    let mut stun_servers = Vec::new();
    for item in list_of(opts, "stun-servers") {
        let item = item.trim();
        let parsed = if let Some(inner) = item.strip_prefix('[') {
            match inner.split_once(']') {
                Some((host, "")) => Some(TargetAddr::from_host(host, 3478)),
                Some((host, tail)) => tail
                    .strip_prefix(':')
                    .and_then(|port| port.parse::<u16>().ok())
                    .map(|port| TargetAddr::from_host(host, port)),
                None => None,
            }
        } else if item.matches(':').count() > 1 {
            // 不带括号的 IPv6
            item.parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| TargetAddr::Ip(SocketAddr::new(ip, 3478)))
        } else {
            match item.rsplit_once(':') {
                Some((host, port)) => port
                    .parse::<u16>()
                    .ok()
                    .map(|port| TargetAddr::from_host(host, port)),
                None => Some(TargetAddr::from_host(item, 3478)),
            }
        };
        match parsed {
            Some(addr) if !item.is_empty() && addr.port() != 0 => stun_servers.push(addr),
            _ => return Err(error(name, "invalid realm stun-servers")),
        }
    }
    if stun_servers.is_empty() {
        return Err(error(name, "realm requires stun-servers"));
    }
    if stun_servers.len() > REALM_MAX_STUN_SERVERS {
        b.warn(format!(
            "proxy {name}: only the first {REALM_MAX_STUN_SERVERS} realm stun-servers are used"
        ));
        stun_servers.truncate(REALM_MAX_STUN_SERVERS);
    }
    let fingerprint = match str_of(opts, "fingerprint") {
        Some(s) => Some(
            hex::<32>(&s.replace(':', ""))
                .ok_or_else(|| error(name, "invalid realm SHA-256 fingerprint"))?,
        ),
        None => None,
    };
    Ok(Some(RealmSpec {
        tls,
        host: host.to_ascii_lowercase(),
        port,
        path: path.to_string(),
        token,
        realm_id,
        stun_servers,
        sni: str_of(opts, "sni").filter(|s| !s.is_empty()),
        skip_cert_verify: bool_of(opts, "skip-cert-verify").unwrap_or(false),
        fingerprint,
    }))
}

/// Hysteria v1：控制流认证、XPlus 混淆、Brutal（两个方向的带宽必填）。
fn hysteria(p: &Yaml, name: &str, b: &mut Builder) -> Result<Option<OutboundKind>, ConfigError> {
    let protocol = str_of(p, "protocol")
        .or_else(|| str_of(p, "obfs-protocol"))
        .unwrap_or_else(|| "udp".into())
        .to_ascii_lowercase();
    if !matches!(
        protocol.as_str(),
        "udp" | "wechat-video" | "wechat" | "faketcp"
    ) {
        return Err(error(name, "invalid hysteria protocol"));
    }
    if protocol == "faketcp" {
        // FakeTCP 需要原始套接字与防火墙规则（参考实现仅 Linux），Oryn 没有实现；
        // 配置照常加载，经该节点的连接在运行时失败，不退回 UDP
        b.warn(format!(
            "proxy {name}: hysteria protocol faketcp is not implemented; connections through this proxy will fail"
        ));
    }
    if protocol == "wechat" {
        b.warn(format!(
            "proxy {name}: hysteria protocol wechat is accepted as wechat-video"
        ));
    }
    if get(p, "protocol").is_some()
        && get(p, "obfs-protocol").is_some()
        && str_of(p, "protocol").map(|v| v.to_ascii_lowercase())
            != str_of(p, "obfs-protocol").map(|v| v.to_ascii_lowercase())
    {
        return Err(error(name, "protocol and obfs-protocol disagree"));
    }
    for field in [
        "recv-window-conn",
        "recv-window",
        "disable_mtu_discovery",
        "fast-open",
    ] {
        if get(p, field).is_some() {
            warn_ignored(b, name, field);
        }
    }
    let (server, ports) = server_and_ports(p, name, b)?;
    let auth = if let Some(text) = password_value_key(p, "auth-str") {
        text.into_bytes()
    } else if let Some(text) = password_value_key(p, "auth") {
        base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|_| error(name, "invalid hysteria auth"))?
    } else {
        Vec::new()
    };
    if auth.len() > 1024 {
        return Err(error(name, "hysteria auth is too long"));
    }
    // up / down 可以带单位，也可以用 up-speed / down-speed（Mbps）
    let speed = |key: &str, legacy: &str| -> Result<u64, ConfigError> {
        let value = match bandwidth(p, name, key)? {
            Some(v) => v,
            None => match get(p, legacy) {
                Some(_) => int_of(p, legacy)
                    .filter(|n| (1..=1000).contains(n))
                    .map(|n| n as u64 * 125_000)
                    .ok_or_else(|| error(name, "invalid hysteria speed"))?,
                None => return Err(error(name, "hysteria requires up and down")),
            },
        };
        // 协议最小 16384 字节/秒
        if value < 16_384 {
            return Err(error(name, "hysteria speed is too low"));
        }
        Ok(value)
    };
    let up_bps = speed("up", "up-speed")?;
    let down_bps = speed("down", "down-speed")?;
    let obfs = password_value_key(p, "obfs").filter(|s| !s.is_empty());
    let (hop_min_secs, hop_max_secs) = hop_interval(p, name, b)?;
    Ok(Some(OutboundKind::Hysteria(HysteriaSpec {
        server,
        protocol: if protocol == "wechat" {
            "wechat-video".into()
        } else {
            protocol
        },
        ports,
        auth,
        up_bps,
        down_bps,
        obfs,
        tls: quic_tls_alpn(p, name, b, "hysteria", false)?,
        hop_min_secs,
        hop_max_secs,
        udp: bool_of(p, "udp").unwrap_or(false),
    })))
}

fn tuic(p: &Yaml, name: &str, b: &mut Builder) -> Result<Option<OutboundKind>, ConfigError> {
    let has_uuid = str_of(p, "uuid").is_some();
    let has_token = str_of(p, "token").is_some();
    if has_token && !has_uuid {
        b.warn(format!(
            "proxy {name}: TUIC v4 is unsupported and was ignored"
        ));
        return Ok(None);
    }
    if has_token {
        warn_ignored(b, name, "token");
    }
    for field in [
        "bbr-profile",
        "bbr_meta_v1",
        "cwnd",
        "fast-open",
        "request-timeout",
        "ip",
        "name-cert-verify",
    ] {
        if get(p, field).is_some() {
            warn_ignored(b, name, field);
        }
    }
    // 与 mihomo 一致：版本缺省（或 0）为旧版 1，只接受 1 和 2
    let udp_over_stream = if bool_of(p, "udp-over-stream").unwrap_or(false) {
        match get(p, "udp-over-stream-version").map(|_| int_of(p, "udp-over-stream-version")) {
            None | Some(Some(0)) | Some(Some(1)) => Some(1),
            Some(Some(2)) => Some(2),
            Some(_) => return Err(error(name, "invalid udp-over-stream-version")),
        }
    } else {
        None
    };
    let uuid_text = str_of(p, "uuid").ok_or_else(|| error(name, "missing uuid"))?;
    let uuid = parse_uuid(&uuid_text).ok_or_else(|| error(name, "invalid uuid"))?;
    let password = password_value(p).ok_or_else(|| error(name, "missing password"))?;
    let udp_relay = match str_of(p, "udp-relay-mode")
        .unwrap_or_else(|| "native".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "native" => UdpRelayMode::Native,
        "quic" => UdpRelayMode::Quic,
        _ => return Err(error(name, "invalid udp-relay-mode")),
    };
    let congestion = match str_of(p, "congestion-controller")
        // 未写时用 BBR：千兆有线下 TUIC 默认 Cubic 比 BBR 慢一半（见 Oryn_dev/docs/oryncore/performance/throughput-report-2026-10-13.md）；
        // 显式写 cubic / new_reno 的仍照配置。
        .unwrap_or_else(|| "bbr".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "cubic" => QuicCongestion::Cubic,
        "bbr" => QuicCongestion::Bbr,
        "new_reno" => QuicCongestion::NewReno,
        "bbr_meta_v1" | "bbr_meta_v2" => {
            warn_ignored(b, name, "congestion-controller");
            QuicCongestion::Bbr
        }
        _ => return Err(error(name, "invalid congestion-controller")),
    };
    let heartbeat_ms = match get(p, "heartbeat-interval") {
        None => 10_000,
        Some(_) => {
            let n = int_of(p, "heartbeat-interval").unwrap_or(-1);
            if n == 0 {
                10_000
            } else if (1000..=60_000).contains(&n) {
                n as u64
            } else {
                return Err(error(name, "invalid heartbeat-interval"));
            }
        }
    };
    let max_udp_packet = match get(p, "max-udp-relay-packet-size") {
        None => 1500,
        Some(_) => {
            let n = int_of(p, "max-udp-relay-packet-size").unwrap_or(-1);
            if !(1..=2048).contains(&n) {
                return Err(error(name, "invalid max-udp-relay-packet-size"));
            }
            n as usize
        }
    };
    let mut max_streams = 128usize;
    if get(p, "max-open-streams").is_some() {
        let n = int_of(p, "max-open-streams").unwrap_or(-1);
        if n < 1 {
            return Err(error(name, "invalid max-open-streams"));
        }
        if n > 128 {
            b.warn(format!("proxy {name}: max-open-streams is clamped to 128"));
            max_streams = 128;
        } else {
            max_streams = n as usize;
        }
    }
    Ok(Some(OutboundKind::Tuic(TuicSpec {
        server: super::proxies::server(p, name)?,
        uuid,
        password,
        udp_relay,
        congestion,
        heartbeat_ms,
        tls: quic_tls(p, name, b)?,
        disable_sni: bool_of(p, "disable-sni").unwrap_or(false),
        max_udp_packet,
        max_streams,
        udp: bool_of(p, "udp").unwrap_or(false),
        udp_over_stream,
        reduce_rtt: bool_of(p, "reduce-rtt").unwrap_or(false),
    })))
}

const MAX_WG_PEERS: usize = 8;

fn wireguard(p: &Yaml, name: &str, b: &mut Builder) -> Result<Option<OutboundKind>, ConfigError> {
    if get(p, "amnezia-wg-option").is_some() && get(p, "amneziawg").is_some() {
        return Err(error(name, "use either amnezia-wg-option or amneziawg"));
    }
    // 对端：没有 `peers` 时用顶层字段；有 `peers` 时顶层的对端字段被忽略并警告
    let peer_nodes: Vec<&Yaml> = match get(p, "peers") {
        None => vec![p],
        Some(Yaml::Array(list)) if !list.is_empty() && list.len() <= MAX_WG_PEERS => {
            if get(p, "server").is_some()
                || get(p, "public-key").is_some()
                || get(p, "port").is_some()
            {
                b.warn(format!(
                    "proxy {name}: ignored top-level WireGuard peer fields because peers is set"
                ));
            }
            list.iter().collect()
        }
        Some(_) => {
            b.warn(format!(
                "proxy {name}: peers must list 1 to {MAX_WG_PEERS} peers and was ignored"
            ));
            return Ok(None);
        }
    };
    let private_key =
        wg_key(p, name, "private-key", true)?.ok_or_else(|| error(name, "missing private-key"))?;
    let mut peers = Vec::new();
    for peer in &peer_nodes {
        let public_key = wg_key(peer, name, "public-key", true)?
            .ok_or_else(|| error(name, "missing public-key"))?;
        let preshared_key = wg_key(peer, name, "pre-shared-key", false)?;
        let endpoint = super::proxies::server(peer, name)?;
        let allowed_text = list_of(peer, "allowed-ips");
        if allowed_text.is_empty() {
            b.warn(format!(
                "proxy {name}: wireguard requires allowed-ips and was ignored"
            ));
            return Ok(None);
        }
        let mut allowed_ips = Vec::new();
        for item in &allowed_text {
            let cidr = IpCidr::parse(item).ok_or_else(|| error(name, "invalid allowed-ips"))?;
            allowed_ips.push(cidr);
        }
        peers.push(WireGuardPeerSpec {
            endpoint,
            public_key,
            preshared_key,
            allowed_ips,
            reserved: reserved(peer, name)?,
            keepalive_secs: None,
        });
    }
    let address_v4 = iface_addr(p, name, "ip", true)?;
    let address_v6 = iface_addr(p, name, "ipv6", false)?;
    if address_v4.is_none() && address_v6.is_none() {
        b.warn(format!(
            "proxy {name}: wireguard requires ip or ipv6 and was ignored"
        ));
        return Ok(None);
    }
    let address_v4 = address_v4.map(|(ip, prefix)| match ip {
        std::net::IpAddr::V4(v4) => (v4, prefix),
        std::net::IpAddr::V6(_) => unreachable!("ip field is IPv4"),
    });
    let address_v6 = address_v6.map(|(ip, prefix)| match ip {
        std::net::IpAddr::V6(v6) => (v6, prefix),
        std::net::IpAddr::V4(_) => unreachable!("ipv6 field is IPv6"),
    });
    let mtu = match get(p, "mtu") {
        None => 1280,
        Some(_) => {
            let n = int_of(p, "mtu").unwrap_or(-1);
            if !(1280..=1420).contains(&n) {
                return Err(error(name, "invalid mtu"));
            }
            n as u16
        }
    };
    let keepalive_secs = match get(p, "persistent-keepalive") {
        None => 0,
        Some(_) => {
            let n = int_of(p, "persistent-keepalive").unwrap_or(-1);
            if !(0..=65535).contains(&n) {
                return Err(error(name, "invalid persistent-keepalive"));
            }
            let mut n = n as u16;
            if (1..10).contains(&n) {
                b.warn(format!(
                    "proxy {name}: persistent-keepalive is clamped to 10 seconds"
                ));
                n = 10;
            }
            n
        }
    };
    let remote_dns = bool_of(p, "remote-dns-resolve").unwrap_or(false);
    let dns = if remote_dns {
        let list = list_of(p, "dns");
        if list.is_empty() || list.len() > 4 {
            return Err(error(
                name,
                "remote-dns-resolve requires 1 to 4 dns servers",
            ));
        }
        list.iter()
            .map(|s| parse_dns_server(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| error(name, "invalid dns server"))?
    } else {
        if get(p, "dns").is_some() {
            warn_ignored(b, name, "dns");
        }
        Vec::new()
    };
    let refresh_secs = match get(p, "refresh-server-ip-interval") {
        None => None,
        Some(_) => {
            let n = int_of(p, "refresh-server-ip-interval").unwrap_or(-1);
            if n == 0 {
                None
            } else if (10..=86_400).contains(&n) {
                Some(n as u64)
            } else {
                return Err(error(
                    name,
                    "refresh-server-ip-interval must be 0 or 10 to 86400",
                ));
            }
        }
    };
    let tcp_buffers = wg_tcp_buffers(p, name)?;
    Ok(Some(OutboundKind::WireGuard(WireGuardSpec {
        peers,
        private_key,
        address_v4,
        address_v6,
        mtu,
        keepalive_secs,
        udp: bool_of(p, "udp").unwrap_or(false),
        remote_dns,
        dns,
        amnezia: amnezia(p, name, b)?,
        refresh_secs,
        tcp_buffers,
    })))
}

/// `tcp-rx-buffer` / `tcp-tx-buffer`（每连接上限）/ `tcp-buffer-budget`（合计）：Oryn 扩展，字节。超出范围时整份配置失败。
fn wg_tcp_buffers(p: &Yaml, name: &str) -> Result<WireGuardTcpBuffers, ConfigError> {
    type B = WireGuardTcpBuffers;
    let size = |key: &str, default: usize, min: usize, max: usize| -> Result<usize, ConfigError> {
        match get(p, key) {
            None => Ok(default),
            Some(_) => match int_of(p, key) {
                Some(n) if n >= min as i64 && n <= max as i64 => Ok(n as usize),
                _ => Err(error(
                    name,
                    &format!("{key} must be an integer from {min} to {max}"),
                )),
            },
        }
    };
    let rx = size("tcp-rx-buffer", B::RX_DEFAULT, B::RX_MIN, B::BUFFER_MAX)?;
    let tx = size("tcp-tx-buffer", B::TX_DEFAULT, B::TX_MIN, B::BUFFER_MAX)?;
    let default_budget = B::default_budget(rx, tx);
    let budget = size("tcp-buffer-budget", default_budget, rx + tx, B::BUDGET_MAX)?;
    Ok(B { rx, tx, budget })
}

/// AmneziaWG 1.0 的 `jc/jmin/jmax/s1/s2/h1..h4`。1.5 / 2.0 的 `i1`–`i5` 等字段忽略并警告。
fn amnezia(p: &Yaml, name: &str, b: &mut Builder) -> Result<Option<AmneziaSpec>, ConfigError> {
    let Some(opts) = get(p, "amnezia-wg-option").or_else(|| get(p, "amneziawg")) else {
        return Ok(None);
    };
    for key in [
        "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime", "s3", "s4",
    ] {
        if get(opts, key).is_some() {
            b.warn(format!(
                "proxy {name}: ignored AmneziaWG 1.5/2.0 option {key}"
            ));
        }
    }
    let number = |key: &str, default: i64, min: i64, max: i64| -> Result<i64, ConfigError> {
        let n = match get(opts, key) {
            None => default,
            Some(_) => int_of(opts, key).ok_or_else(|| error(name, "invalid AmneziaWG option"))?,
        };
        if !(min..=max).contains(&n) {
            return Err(error(name, "invalid AmneziaWG option"));
        }
        Ok(n)
    };
    let jc = number("jc", 4, 0, 128)?;
    let jmin = number("jmin", 40, 0, 1280)?;
    let jmax = number("jmax", 70, 0, 1280)?;
    let s1 = number("s1", 0, 0, 1280)?;
    let s2 = number("s2", 0, 0, 1280)?;
    let h = [
        number("h1", 1, 1, u32::MAX as i64)? as u32,
        number("h2", 2, 1, u32::MAX as i64)? as u32,
        number("h3", 3, 1, u32::MAX as i64)? as u32,
        number("h4", 4, 1, u32::MAX as i64)? as u32,
    ];
    if jmin > jmax || s1 + 56 == s2 {
        return Err(error(name, "invalid AmneziaWG option"));
    }
    let mut distinct = h.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() != 4 {
        return Err(error(name, "AmneziaWG header values must be different"));
    }
    Ok(Some(AmneziaSpec {
        jc: jc as u8,
        jmin: jmin as u16,
        jmax: jmax as u16,
        s1: s1 as u16,
        s2: s2 as u16,
        h: [h[0], h[1], h[2], h[3]],
    }))
}

fn server_and_ports(
    p: &Yaml,
    name: &str,
    b: &mut Builder,
) -> Result<(TargetAddr, Option<PortSet>), ConfigError> {
    let host = str_of(p, "server").ok_or_else(|| error(name, "missing server"))?;
    if let Some(text) = str_of(p, "ports") {
        if get(p, "port").is_some() {
            b.warn(format!("proxy {name}: ignored port because ports is set"));
        }
        let set = parse_ports(&text).map_err(|_| error(name, "invalid ports"))?;
        let stable = set.ranges[0].0;
        return Ok((TargetAddr::from_host(&host, stable), Some(set)));
    }
    Ok((super::proxies::server(p, name)?, None))
}

fn parse_ports(text: &str) -> Result<PortSet, ()> {
    let mut ranges = Vec::new();
    let mut count: u32 = 0;
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (start, end) = if let Some((a, b)) = part.split_once('-') {
            (parse_port(a)?, parse_port(b)?)
        } else {
            let port = parse_port(part)?;
            (port, port)
        };
        if start == 0 || end == 0 || start > end {
            return Err(());
        }
        count = count.checked_add(u32::from(end - start) + 1).ok_or(())?;
        ranges.push((start, end));
    }
    if ranges.is_empty() {
        return Err(());
    }
    Ok(PortSet { ranges, count })
}

fn parse_port(text: &str) -> Result<u16, ()> {
    let n: u32 = text.trim().parse().map_err(|_| ())?;
    u16::try_from(n).map_err(|_| ())
}

fn hop_interval(p: &Yaml, name: &str, b: &mut Builder) -> Result<(u64, u64), ConfigError> {
    let Some(raw) = get(p, "hop-interval").and_then(scalar) else {
        return Ok((30, 30));
    };
    let raw = raw.trim();
    if raw.contains(',') {
        return Err(error(name, "invalid hop-interval"));
    }
    let (min, max) = if let Some((a, btxt)) = raw.split_once('-') {
        let min: u64 = a
            .trim()
            .parse()
            .map_err(|_| error(name, "invalid hop-interval"))?;
        let max: u64 = btxt
            .trim()
            .parse()
            .map_err(|_| error(name, "invalid hop-interval"))?;
        if min == 0 || max == 0 || min > max {
            return Err(error(name, "invalid hop-interval"));
        }
        (min, max)
    } else {
        let n: u64 = raw
            .parse()
            .map_err(|_| error(name, "invalid hop-interval"))?;
        if n == 0 {
            return Err(error(name, "invalid hop-interval"));
        }
        (n, n)
    };
    let mut min = min;
    let mut max = max;
    if min < 5 {
        b.warn(format!(
            "proxy {name}: hop-interval is clamped to 5 seconds"
        ));
        min = 5;
        if max < 5 {
            max = 5;
        }
    }
    Ok((min, max))
}

fn bandwidth(p: &Yaml, name: &str, key: &str) -> Result<Option<u64>, ConfigError> {
    let Some(raw) = get(p, key).and_then(scalar) else {
        return Ok(None);
    };
    let bits = parse_bps(raw.trim()).map_err(|_| error(name, "invalid bandwidth"))?;
    if bits == 0 {
        return Ok(None);
    }
    if bits > 1_000_000_000 {
        return Err(error(name, "bandwidth exceeds 1000 Mbps"));
    }
    Ok(Some(bits / 8))
}

fn parse_bps(raw: &str) -> Result<u64, ()> {
    let s = raw
        .split_whitespace()
        .collect::<String>()
        .to_ascii_lowercase();
    let split = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
    if split == 0 {
        return Err(());
    }
    let num: f64 = s[..split].parse().map_err(|_| ())?;
    if !num.is_finite() || num < 0.0 {
        return Err(());
    }
    let unit = s[split..].trim_end_matches("/s");
    let mult = match unit {
        "" | "mbps" => 1_000_000.0,
        "bps" => 1.0,
        "kbps" => 1_000.0,
        "gbps" => 1_000_000_000.0,
        _ => return Err(()),
    };
    Ok((num * mult) as u64)
}

fn quic_tls(p: &Yaml, name: &str, b: &mut Builder) -> Result<TlsSpec, ConfigError> {
    quic_tls_alpn(p, name, b, "h3", true)
}

/// `default_alpn` 是 alpn 未写时的取值；`require_default` 时列表里必须含有它。
fn quic_tls_alpn(
    p: &Yaml,
    name: &str,
    b: &mut Builder,
    default_alpn: &str,
    require_default: bool,
) -> Result<TlsSpec, ConfigError> {
    if get(p, "reality-opts").is_some() {
        warn_ignored(b, name, "reality-opts");
    }
    if str_of(p, "client-fingerprint").is_some() {
        warn_ignored(b, name, "client-fingerprint");
    }
    let mut alpn = list_of(p, "alpn");
    if alpn.is_empty() {
        alpn.push(default_alpn.into());
    }
    if alpn.len() > 16
        || alpn.iter().any(|a| a.is_empty() || a.len() > 255)
        || (require_default && !alpn.iter().any(|a| a == default_alpn))
    {
        return Err(error(name, "invalid ALPN"));
    }
    let fingerprint = match str_of(p, "fingerprint") {
        Some(s) => Some(
            hex::<32>(&s.replace(':', ""))
                .ok_or_else(|| error(name, "invalid SHA-256 fingerprint"))?,
        ),
        None => None,
    };
    Ok(TlsSpec {
        sni: str_of(p, "sni").or_else(|| str_of(p, "servername")),
        skip_cert_verify: bool_of(p, "skip-cert-verify").unwrap_or(false),
        alpn,
        fingerprint,
        client_fingerprint: None,
        reality: None,
        ech: None,
    })
}

fn password_value_key(p: &Yaml, key: &str) -> Option<String> {
    get(p, key).and_then(scalar)
}

fn wg_key(
    p: &Yaml,
    name: &str,
    key: &str,
    required: bool,
) -> Result<Option<[u8; 32]>, ConfigError> {
    let Some(text) = get(p, key).and_then(scalar) else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| error(name, "invalid wireguard key"))?;
    if bytes.len() != 32 {
        return Err(error(name, "invalid wireguard key"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    if !required && key == "pre-shared-key" && bytes.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    Ok(Some(out))
}

fn iface_addr(
    p: &Yaml,
    name: &str,
    key: &str,
    v4: bool,
) -> Result<Option<(std::net::IpAddr, u8)>, ConfigError> {
    let Some(text) = str_of(p, key) else {
        return Ok(None);
    };
    let (addr, prefix) = if let Some((ip, pref)) = text.split_once('/') {
        let prefix: u8 = pref
            .parse()
            .map_err(|_| error(name, "invalid interface address"))?;
        (ip, Some(prefix))
    } else {
        (text.as_str(), None)
    };
    if v4 {
        let ip: Ipv4Addr = addr
            .parse()
            .map_err(|_| error(name, "invalid interface address"))?;
        let prefix = prefix.unwrap_or(32);
        if prefix > 32 {
            return Err(error(name, "invalid interface address"));
        }
        Ok(Some((ip.into(), prefix)))
    } else {
        let ip: Ipv6Addr = addr
            .parse()
            .map_err(|_| error(name, "invalid interface address"))?;
        let prefix = prefix.unwrap_or(128);
        if prefix > 128 {
            return Err(error(name, "invalid interface address"));
        }
        Ok(Some((ip.into(), prefix)))
    }
}

fn reserved(p: &Yaml, name: &str) -> Result<[u8; 3], ConfigError> {
    let Some(value) = get(p, "reserved") else {
        return Ok([0, 0, 0]);
    };
    let items = match value {
        Yaml::Array(_) => list_of(p, "reserved"),
        Yaml::String(s) if s.contains(',') => s
            .split(',')
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect(),
        Yaml::String(s) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .map_err(|_| error(name, "invalid reserved"))?;
            if bytes.len() != 3 {
                return Err(error(name, "invalid reserved"));
            }
            return Ok([bytes[0], bytes[1], bytes[2]]);
        }
        _ => return Err(error(name, "invalid reserved")),
    };
    if items.len() != 3 {
        return Err(error(name, "invalid reserved"));
    }
    let mut out = [0u8; 3];
    for (i, item) in items.iter().enumerate() {
        let n: u16 = item.parse().map_err(|_| error(name, "invalid reserved"))?;
        if n > 255 {
            return Err(error(name, "invalid reserved"));
        }
        out[i] = n as u8;
    }
    Ok(out)
}

fn parse_dns_server(text: &str) -> Result<SocketAddr, ()> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = text.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(())
}

#[cfg(test)]
mod tests {
    use super::parse_bps;

    #[test]
    fn bandwidth_units() {
        assert_eq!(parse_bps("30").unwrap(), 30_000_000);
        assert_eq!(parse_bps("30 Mbps").unwrap(), 30_000_000);
        assert_eq!(parse_bps("8 kbps").unwrap(), 8_000);
        assert_eq!(parse_bps("1000bps").unwrap(), 1000);
        assert!(parse_bps("1001 Mbps").unwrap() > 1_000_000_000);
        assert!(parse_bps("fast").is_err());
    }
}
