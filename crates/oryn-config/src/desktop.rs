//! 桌面独立核心 `oryn` 专用的宿主设置：mihomo `tun:` 段的子集，以及顶层 `routing-mark`、
//! `interface-name`、`port`、`socks-port`、`allow-lan`。
//!
//! 只由 `oryn` 命令行调用；[`crate::parse_config`] 不读这些键，App 宿主（iOS / Android /
//! macOS App）因此忽略整个 `tun:` 段，由平台层建隧道。支持的键与取值见
//! Oryn_dev/docs/oryncore/plans/plan-desktop-tun-bare-core.md「第 2 期支持的 `tun:` 子集」。
//! 表外的键忽略并警告；已支持键的非法值返回错误。

use std::net::IpAddr;

use yaml_rust2::{Yaml, YamlLoader};

use crate::yaml::{entries, get, list_value, scalar};
use crate::{ConfigError, IpCidr};

/// `iproute2-table-index` 的默认值。
pub const DEFAULT_TABLE_INDEX: u32 = 2022;
/// `iproute2-rule-index` 的默认值。
pub const DEFAULT_RULE_INDEX: u32 = 9000;
/// `auto-route` 时未写 `routing-mark` 的默认标记。
pub const DEFAULT_ROUTING_MARK: u32 = 2022;
/// `mtu` 的默认值。
pub const DEFAULT_TUN_MTU: u16 = 9000;
/// 默认隧道地址：落在 198.18.0.0/24 内，Fake-IP 池跳过这一段；198.18.0.2 是内置 DNS。
pub const DEFAULT_INET4_ADDRESS: &str = "198.18.0.1/30";

/// 每类地址 / 网段列表的上限，防止配置写出成千上万条路由与规则。
const MAX_LIST: usize = 256;

/// `oryn` 宿主设置。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesktopSettings {
    /// `tun.enable` 为 true 时才有值。
    pub tun: Option<TunSettings>,
    /// 顶层 `routing-mark`：出站套接字的 `SO_MARK`。
    pub routing_mark: Option<u32>,
    /// 顶层 `interface-name`：直连固定绑定的接口。
    pub interface_name: Option<String>,
    /// 顶层 `port`：本地 HTTP 代理端口。
    pub http_port: Option<u16>,
    /// 顶层 `socks-port`：本地 SOCKS5 代理端口。
    pub socks_port: Option<u16>,
    /// 顶层 `allow-lan`：本地代理接受外部连接。
    pub allow_lan: Option<bool>,
    pub warnings: Vec<String>,
}

impl DesktopSettings {
    /// 实际使用的路由标记：显式设置优先，`auto-route` 时默认 [`DEFAULT_ROUTING_MARK`]。
    pub fn effective_routing_mark(&self) -> Option<u32> {
        self.routing_mark.or_else(|| {
            self.tun
                .as_ref()
                .filter(|t| t.auto_route)
                .map(|_| DEFAULT_ROUTING_MARK)
        })
    }
}

/// `tun:` 段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunSettings {
    /// 接口名；`None` 时由宿主取平台默认（Linux `oryn0`）。
    pub device: Option<String>,
    pub mtu: u16,
    pub inet4_address: Vec<IpCidr>,
    pub inet6_address: Vec<IpCidr>,
    pub auto_route: bool,
    pub table_index: u32,
    pub rule_index: u32,
    /// 进入隧道的网段；为空表示全部（`0.0.0.0/0`，有 IPv6 地址时另加 `::/0`）。
    pub route_address: Vec<IpCidr>,
    pub route_exclude_address: Vec<IpCidr>,
    pub auto_detect_interface: bool,
    pub dns_hijack: Vec<DnsHijack>,
}

/// 一条 `dns-hijack`：`[tcp://|udp://]<any|IP>:<port>`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHijack {
    pub tcp: bool,
    pub udp: bool,
    /// `None` 表示 `any`。
    pub ip: Option<IpAddr>,
    pub port: u16,
}

impl DnsHijack {
    pub fn matches(&self, tcp: bool, ip: IpAddr, port: u16) -> bool {
        port == self.port
            && if tcp { self.tcp } else { self.udp }
            && self.ip.is_none_or(|want| want == ip || canonical(ip) == want)
    }
}

/// IPv4 映射的 IPv6 地址按 IPv4 比较。
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// 解析一条 mihomo 写法的 `dns-hijack`。
pub fn parse_dns_hijack(text: &str) -> Result<DnsHijack, String> {
    let raw = text.trim();
    let invalid = || format!("invalid dns-hijack `{raw}`");
    let lower = raw.to_ascii_lowercase();
    let (tcp, udp, rest) = if let Some(r) = lower.strip_prefix("tcp://") {
        (true, false, r)
    } else if let Some(r) = lower.strip_prefix("udp://") {
        (false, true, r)
    } else if lower.contains("://") {
        return Err(invalid());
    } else {
        (true, true, lower.as_str())
    };
    // `any:53`、`1.2.3.4:53`、`[::1]:53`；只写主机时端口为 53
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (h, tail) = inner.split_once(']').ok_or_else(invalid)?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p,
            None if tail.is_empty() => "53",
            None => return Err(invalid()),
        };
        (h, port)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, p),
            Some(_) => (rest, "53"),
            None => (rest, "53"),
        }
    };
    let port: u16 = port.parse().ok().filter(|p| *p != 0).ok_or_else(invalid)?;
    let ip = match host {
        "any" | "" | "0.0.0.0" | "::" => None,
        h => Some(h.parse::<IpAddr>().map_err(|_| invalid())?),
    };
    Ok(DnsHijack { tcp, udp, ip: ip.map(canonical), port })
}

/// 解析配置文本中的宿主设置。YAML 语法错误与已支持键的非法值返回错误。
pub fn parse_desktop(text: &str) -> Result<DesktopSettings, ConfigError> {
    let docs =
        YamlLoader::load_from_str(text).map_err(|e| ConfigError(format!("invalid YAML: {e}")))?;
    let root = docs.into_iter().next().unwrap_or(Yaml::Null);
    let mut out = DesktopSettings::default();
    if root.is_null() {
        return Ok(out);
    }
    if !matches!(root, Yaml::Hash(_)) {
        return Err(ConfigError("the top level of the config must be a mapping".into()));
    }
    out.routing_mark = opt_u32(&root, "routing-mark")?.filter(|m| *m != 0);
    out.interface_name = get(&root, "interface-name")
        .map(|v| interface_name(v, "interface-name"))
        .transpose()?;
    out.http_port = opt_port(&root, "port")?;
    out.socks_port = opt_port(&root, "socks-port")?;
    out.allow_lan = opt_bool(&root, "allow-lan")?;
    if get(&root, "mixed-port").is_some() {
        out.warnings.push(
            "`mixed-port` is not supported; use `port` (HTTP) and `socks-port` (SOCKS5)".into(),
        );
    }
    if let Some(tun) = get(&root, "tun") {
        if !matches!(tun, Yaml::Hash(_)) {
            return Err(ConfigError("`tun` must be a mapping".into()));
        }
        if opt_bool(tun, "enable")?.unwrap_or(false) {
            out.tun = Some(parse_tun(tun, &mut out.warnings)?);
        }
    }
    Ok(out)
}

fn parse_tun(tun: &Yaml, warnings: &mut Vec<String>) -> Result<TunSettings, ConfigError> {
    let mut settings = TunSettings {
        device: None,
        mtu: DEFAULT_TUN_MTU,
        inet4_address: Vec::new(),
        inet6_address: Vec::new(),
        auto_route: false,
        table_index: DEFAULT_TABLE_INDEX,
        rule_index: DEFAULT_RULE_INDEX,
        route_address: Vec::new(),
        route_exclude_address: Vec::new(),
        auto_detect_interface: false,
        dns_hijack: Vec::new(),
    };
    for (key, value) in entries(tun) {
        let k = key.as_str();
        if value.is_null() {
            continue;
        }
        match k {
            "enable" => {}
            "stack" => match scalar(value).map(|s| s.trim().to_ascii_lowercase()).as_deref() {
                Some("system" | "gvisor" | "mixed" | "lwip") => warnings.push(format!(
                    "tun.stack `{}` is ignored; Oryn always uses its own lwIP netstack",
                    scalar(value).unwrap_or_default().trim()
                )),
                _ => return Err(ConfigError("tun.stack must be system, gvisor or mixed".into())),
            },
            "device" => settings.device = Some(interface_name(value, "tun.device")?),
            "mtu" => {
                let mtu = int(value, "tun.mtu")?;
                if !(1280..=65535).contains(&mtu) {
                    return Err(ConfigError("tun.mtu must be between 1280 and 65535".into()));
                }
                settings.mtu = mtu as u16;
            }
            "inet4-address" | "inet6-address" => {
                let v6 = k == "inet6-address";
                let list = cidrs(value, k)?;
                if list.iter().any(|c| c.is_ipv4() == v6) {
                    return Err(ConfigError(format!("tun.{k}: wrong address family")));
                }
                if v6 {
                    settings.inet6_address = list;
                } else {
                    settings.inet4_address = list;
                }
            }
            "auto-route" => settings.auto_route = boolean(value, "tun.auto-route")?,
            "auto-detect-interface" => {
                settings.auto_detect_interface = boolean(value, "tun.auto-detect-interface")?
            }
            "iproute2-table-index" => {
                let t = u32_value(value, k)?;
                // 0 未指定，253..=255 为内核的 default / main / local 表
                if t == 0 || (253..=255).contains(&t) {
                    return Err(ConfigError("tun.iproute2-table-index must not be 0 or 253-255".into()));
                }
                settings.table_index = t;
            }
            "iproute2-rule-index" => {
                let p = u32_value(value, k)?;
                // 需要 P..=P+2 三个优先级，且不能占用 main（32766）/ default（32767）
                if p == 0 || p > 32763 {
                    return Err(ConfigError("tun.iproute2-rule-index must be between 1 and 32763".into()));
                }
                settings.rule_index = p;
            }
            "route-address" | "inet4-route-address" | "inet6-route-address" => {
                settings.route_address.extend(cidrs(value, k)?)
            }
            "route-exclude-address" | "inet4-route-exclude-address" | "inet6-route-exclude-address" => {
                settings.route_exclude_address.extend(cidrs(value, k)?)
            }
            "dns-hijack" => {
                for item in bounded(list_value(value), k)? {
                    settings
                        .dns_hijack
                        .push(parse_dns_hijack(&item).map_err(|e| ConfigError(format!("tun: {e}")))?);
                }
            }
            "strict-route" | "auto-redirect" | "gso" | "gso-max-size" | "endpoint-independent-nat"
            | "udp-timeout" | "file-descriptor" | "include-interface" | "exclude-interface"
            | "include-uid" | "include-uid-range" | "exclude-uid" | "exclude-uid-range"
            | "include-android-user" | "include-package" | "exclude-package" | "route-address-set"
            | "route-exclude-address-set" | "auto-redirect-input-mark" | "auto-redirect-output-mark" => {
                warnings.push(format!("tun.{k} is not supported yet and was ignored"))
            }
            other => warnings.push(format!("tun.{other} is not supported and was ignored")),
        }
    }
    for list in [&settings.route_address, &settings.route_exclude_address] {
        if list.len() > MAX_LIST {
            return Err(ConfigError(format!("tun: more than {MAX_LIST} route entries")));
        }
    }
    if settings.inet4_address.is_empty() {
        settings.inet4_address.push(IpCidr::parse(DEFAULT_INET4_ADDRESS).expect("valid default"));
    }
    Ok(settings)
}

fn bounded(list: Vec<String>, key: &str) -> Result<Vec<String>, ConfigError> {
    if list.len() > MAX_LIST {
        return Err(ConfigError(format!("tun.{key}: more than {MAX_LIST} entries")));
    }
    Ok(list)
}

fn cidrs(value: &Yaml, key: &str) -> Result<Vec<IpCidr>, ConfigError> {
    bounded(list_value(value), key)?
        .iter()
        .map(|s| {
            IpCidr::parse(s).ok_or_else(|| ConfigError(format!("tun.{key}: `{s}` is not a valid IP or CIDR")))
        })
        .collect()
}

fn interface_name(value: &Yaml, key: &str) -> Result<String, ConfigError> {
    let name = scalar(value).map(|s| s.trim().to_string()).unwrap_or_default();
    // Linux IFNAMSIZ 为 16（含结尾 NUL）
    let valid = !name.is_empty()
        && name.len() < 16
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && name != "."
        && name != "..";
    if !valid {
        return Err(ConfigError(format!("{key}: invalid interface name `{name}`")));
    }
    Ok(name)
}

fn int(value: &Yaml, key: &str) -> Result<i64, ConfigError> {
    match value {
        Yaml::Integer(i) => Some(*i),
        Yaml::String(s) => s.trim().parse().ok(),
        _ => None,
    }
    .ok_or_else(|| ConfigError(format!("{key} must be an integer")))
}

fn u32_value(value: &Yaml, key: &str) -> Result<u32, ConfigError> {
    u32::try_from(int(value, key)?).map_err(|_| ConfigError(format!("{key} is out of range")))
}

fn boolean(value: &Yaml, key: &str) -> Result<bool, ConfigError> {
    match value {
        Yaml::Boolean(b) => Some(*b),
        Yaml::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" => Some(true),
            "false" | "no" | "off" => Some(false),
            _ => None,
        },
        _ => None,
    }
    .ok_or_else(|| ConfigError(format!("{key} must be true or false")))
}

fn opt_bool(y: &Yaml, key: &str) -> Result<Option<bool>, ConfigError> {
    get(y, key).map(|v| boolean(v, key)).transpose()
}

fn opt_u32(y: &Yaml, key: &str) -> Result<Option<u32>, ConfigError> {
    get(y, key).map(|v| u32_value(v, key)).transpose()
}

fn opt_port(y: &Yaml, key: &str) -> Result<Option<u16>, ConfigError> {
    get(y, key)
        .map(|v| {
            let p = int(v, key)?;
            u16::try_from(p)
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| ConfigError(format!("{key} must be between 1 and 65535")))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_config_without_tun_has_no_desktop_settings() {
        let s = parse_desktop("mode: rule\nrules: ['MATCH,DIRECT']\n").unwrap();
        assert_eq!(s, DesktopSettings::default());
        assert_eq!(s.effective_routing_mark(), None);
        // tun 关闭时不解析内容，也不报错
        let s = parse_desktop("tun:\n  enable: false\n  mtu: 1\n").unwrap();
        assert!(s.tun.is_none() && s.warnings.is_empty());
    }

    #[test]
    fn parses_tun_subset_with_defaults() {
        let s = parse_desktop(
            "port: 7890\nsocks-port: 7891\nallow-lan: true\nmixed-port: 7892\ninterface-name: eth0\n\
             tun:\n  enable: true\n  stack: gvisor\n  auto-route: true\n  auto-detect-interface: true\n\
             \x20 dns-hijack: [any:53, 'tcp://8.8.8.8:53']\n  route-exclude-address: [192.168.0.0/16]\n\
             \x20 strict-route: true\n  bogus: 1\n",
        )
        .unwrap();
        let tun = s.tun.as_ref().unwrap();
        assert_eq!((tun.mtu, tun.table_index, tun.rule_index), (9000, 2022, 9000));
        assert_eq!(tun.inet4_address, vec![IpCidr::parse("198.18.0.1/30").unwrap()]);
        assert!(tun.auto_route && tun.auto_detect_interface && tun.device.is_none());
        assert_eq!(tun.route_exclude_address.len(), 1);
        assert_eq!(tun.dns_hijack.len(), 2);
        assert_eq!((s.http_port, s.socks_port, s.allow_lan), (Some(7890), Some(7891), Some(true)));
        assert_eq!(s.interface_name.as_deref(), Some("eth0"));
        assert_eq!(s.effective_routing_mark(), Some(2022));
        // stack、mixed-port、strict-route、未知键各一条警告
        assert_eq!(s.warnings.len(), 4, "{:?}", s.warnings);
    }

    #[test]
    fn invalid_supported_values_fail() {
        for bad in [
            "tun: {enable: true, mtu: 100}",
            "tun: {enable: true, stack: foo}",
            "tun: {enable: true, device: 'a/b'}",
            "tun: {enable: true, device: 'abcdefghijklmnopq'}",
            "tun: {enable: true, inet4-address: 'fd00::1/64'}",
            "tun: {enable: true, auto-route: maybe}",
            "tun: {enable: true, dns-hijack: ['quic://any:53']}",
            "tun: {enable: true, iproute2-table-index: 254}",
            "tun: {enable: true, route-address: [nope]}",
            "tun: {enable: maybe}",
            "routing-mark: -1",
            "port: 70000",
        ] {
            assert!(parse_desktop(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn explicit_routing_mark_wins() {
        let s = parse_desktop("routing-mark: 6666\ntun: {enable: true, auto-route: true}").unwrap();
        assert_eq!(s.effective_routing_mark(), Some(6666));
    }

    #[test]
    fn dns_hijack_forms() {
        let any = parse_dns_hijack("any:53").unwrap();
        assert!(any.matches(true, "1.1.1.1".parse().unwrap(), 53));
        assert!(any.matches(false, "::1".parse().unwrap(), 53));
        assert!(!any.matches(false, "1.1.1.1".parse().unwrap(), 5353));
        let tcp = parse_dns_hijack("tcp://8.8.8.8:53").unwrap();
        assert!(tcp.matches(true, "8.8.8.8".parse().unwrap(), 53));
        assert!(tcp.matches(true, "::ffff:8.8.8.8".parse().unwrap(), 53));
        assert!(!tcp.matches(false, "8.8.8.8".parse().unwrap(), 53));
        assert!(!tcp.matches(true, "8.8.4.4".parse().unwrap(), 53));
        let v6 = parse_dns_hijack("udp://[2001:db8::1]:5353").unwrap();
        assert!(v6.matches(false, "2001:db8::1".parse().unwrap(), 5353));
        assert_eq!(parse_dns_hijack("1.1.1.1").unwrap().port, 53);
        for bad in ["any:0", "any:x", "foo:53", "http://any:53", "[::1"] {
            assert!(parse_dns_hijack(bad).is_err(), "{bad}");
        }
    }
}
