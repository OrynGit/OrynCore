//! 创建 Engine 时由 PacketTunnel 传入的运行参数（JSON）。与配置文件无关的内容都在这里。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use oryn_config::Mode;
use oryn_dns::{NetworkInfo, NetworkKind};
use serde::Deserialize;

/// 创建时固定的资源政策；桌面额度只能由 macOS 宿主显式选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProfile {
    #[serde(rename = "constrained")]
    Constrained,
    #[cfg(target_os = "ios")]
    #[serde(rename = "mobile_plus")]
    MobilePlus,
    #[cfg(target_os = "macos")]
    #[serde(rename = "desktop_high")]
    DesktopHigh,
}

// The default is intentionally platform-specific: iOS uses MobilePlus while macOS
// must remain constrained unless the host explicitly selects desktop_high.
#[allow(clippy::derivable_impls)]
impl Default for ResourceProfile {
    fn default() -> Self {
        #[cfg(target_os = "macos")]
        { Self::Constrained }
        #[cfg(target_os = "ios")]
        { Self::MobilePlus }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        { Self::Constrained }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ResourceLimits {
    pub active: Option<usize>,
    pub establishing: usize,
    /// establishing 的初始软上限（不超过 `establishing`，可由 `admission_tune` 调整）。
    pub establishing_soft: usize,
    pub dns: usize,
    pub http_connections: Option<usize>,
    pub http_transactions: Option<usize>,
    pub http_upstream_establish: usize,
    pub udp_sessions: usize,
    pub http_bodies: usize,
}

impl ResourceProfile {
    pub(crate) fn limits(self) -> ResourceLimits {
        let (active, establishing, http, udp_sessions) = match self {
            Self::Constrained => (Some(64), 8, Some(32), 512),
            #[cfg(target_os = "ios")]
            Self::MobilePlus => (Some(640), 64, Some(256), 512),
            #[cfg(target_os = "macos")]
            Self::DesktopHigh => (None, 48, None, 2048),
        };
        ResourceLimits {
            active,
            establishing,
            establishing_soft: match self {
                #[cfg(target_os = "ios")]
                Self::MobilePlus => 32,
                _ => establishing,
            },
            dns: 4,
            http_connections: http,
            http_transactions: http,
            http_upstream_establish: match self {
                #[cfg(target_os = "ios")]
                Self::MobilePlus => 32,
                _ => establishing,
            },
            udp_sessions,
            http_bodies: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EngineOptions {
    pub resource_profile: ResourceProfile,
    /// 规则集、GEOIP 数据库等的缓存目录；为空时不缓存到磁盘。
    pub data_dir: Option<PathBuf>,
    pub inspection_config: Option<String>,
    pub maxmind: Option<MaxMindOptions>,
    pub system_version: String,
    /// 隧道内 DNS 服务器地址（与 NEDNSSettings 一致）。
    pub dns_address: Ipv4Addr,
    pub mtu: u16,
    /// select 策略组的已保存选择。
    pub selections: HashMap<String, String>,
    /// 界面上选择的模式，覆盖配置文件中的 `mode`。
    pub mode: Option<String>,
    pub network: NetworkOptions,
    /// 本机设置覆盖策略组健康检查的代理测试地址。
    pub proxy_test_url: Option<String>,
    /// 由 App 保存的直连 / UDP 测试地址，供后续诊断命令使用。
    pub direct_test_url: Option<String>,
    pub udp_test_url: Option<String>,
    pub close_connections_on_policy_switch: bool,
    /// QUIC 全局策略：`default`、`always` 或 `never`。
    pub block_quic: String,
    /// 本机应用目标的 IPv6 设置，不控制代理节点连接。
    pub ipv6_support: bool,
    pub prefer_ipv6: bool,
    /// 所有节点域名的本地解析偏好，与应用目标设置独立。
    pub proxy_prefer_ipv6: bool,
    pub real_ip_domains: Vec<String>,
    pub local_proxy: LocalProxyOptions,
    pub virtual_interface: crate::virtual_interface::VirtualInterfaceOptions,
    /// App 开启诊断日志时指定的级别，覆盖配置文件里的 `log-level`。
    pub log_level: Option<String>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions {
            resource_profile: ResourceProfile::default(),
            data_dir: None,
            inspection_config: None,
            maxmind: None,
            system_version: "16.0".into(),
            dns_address: Ipv4Addr::new(198, 18, 0, 2),
            mtu: 1500,
            selections: HashMap::new(),
            mode: None,
            network: NetworkOptions::default(),
            proxy_test_url: None,
            direct_test_url: None,
            udp_test_url: None,
            close_connections_on_policy_switch: true,
            block_quic: "default".into(),
            ipv6_support: true,
            prefer_ipv6: false,
            proxy_prefer_ipv6: false,
            real_ip_domains: Vec::new(),
            local_proxy: LocalProxyOptions::default(),
            virtual_interface: Default::default(),
            log_level: None,
        }
    }
}

impl EngineOptions {
    pub fn parse(json: &[u8]) -> Result<EngineOptions, String> {
        if json.iter().all(u8::is_ascii_whitespace) {
            return Ok(EngineOptions::default());
        }
        let mut options: Self =
            serde_json::from_slice(json).map_err(|e| format!("invalid engine options: {e}"))?;
        if let Some(maxmind) = &options.maxmind {
            maxmind.validate()?;
        }
        options.real_ip_domains = oryn_dns::normalize_real_ip_domains(&options.real_ip_domains)?;
        Ok(options)
    }

    pub fn mode(&self) -> Option<Mode> {
        self.mode.as_deref().and_then(Mode::parse)
    }
}

/// App 的全局数据库设置，覆盖订阅，统一每周更新。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MaxMindOptions {
    pub geoip_db_url: String,
    pub asn_db_url: String,
}

impl MaxMindOptions {
    pub fn validate(&self) -> Result<(), String> {
        for value in [&self.geoip_db_url, &self.asn_db_url] {
            if value.len() > 4096 || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err("invalid MaxMind database URL".into());
            }
            let parsed = url::Url::parse(value).map_err(|_| "invalid MaxMind database URL")?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
                || parsed.port() == Some(0)
            {
                return Err("invalid MaxMind database URL".into());
            }
            oryn_http::Url::parse(value).map_err(|_| "invalid MaxMind database URL")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LocalProxyOptions {
    pub enabled: bool,
    pub http_port: u16,
    pub socks_port: u16,
    pub allow_external: bool,
}

impl Default for LocalProxyOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            http_port: 3080,
            socks_port: 3090,
            allow_external: false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NetworkOptions {
    /// `wifi` / `cellular` / `wired` / `other`
    pub kind: Option<String>,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    /// 蜂窝无线制式，如 `LTE`、`NR`。
    pub radio: Option<String>,
    /// 物理网络是否支持 IPv6；旧版 App 不传时为未知。
    pub ipv6: Option<bool>,
    /// 出站套接字绑定的物理接口名（macOS TUN 模式，如 `en0`）；不传时不绑定。
    pub interface: Option<String>,
}

impl NetworkOptions {
    /// 应用出站绑定接口。只有平台层传了接口名才改动，iOS 与系统代理模式保持不绑定。
    pub fn apply_interface(&self) {
        if let Some(name) = &self.interface {
            let index = oryn_udp::iface::set_bound_interface(Some(name));
            if index == 0 {
                log::warn!("outbound interface {name} not found; sockets are not bound");
            } else {
                log::info!("outbound sockets bound to {name} (index {index})");
            }
        }
    }

    pub fn to_info(&self) -> NetworkInfo {
        let kind = match self.kind.as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("wifi") => NetworkKind::Wifi,
            Some("cellular") => NetworkKind::Cellular,
            Some("wired") => NetworkKind::Wired,
            Some("other") => NetworkKind::Other,
            _ => NetworkKind::Unknown,
        };
        NetworkInfo {
            kind,
            ssid: self.ssid.clone().filter(|s| !s.is_empty()),
            bssid: self
                .bssid
                .clone()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_ascii_lowercase()),
            radio: self.radio.clone().filter(|s| !s.is_empty()),
            ipv6: self.ipv6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_options() {
        let o = EngineOptions::parse(b"").unwrap();
        assert_eq!(o.mtu, 1500);
        let o = EngineOptions::parse(
            br#"{"data_dir":"/tmp/x","selections":{"Proxy":"Tokyo"},"mode":"global","network":{"kind":"cellular","radio":"NR","ipv6":false}}"#,
        )
        .unwrap();
        assert_eq!(o.selections["Proxy"], "Tokyo");
        assert_eq!(o.mode(), Some(Mode::Global));
        let info = o.network.to_info();
        assert_eq!(
            (info.kind, info.radio.as_deref()),
            (NetworkKind::Cellular, Some("NR"))
        );
        assert_eq!(info.ipv6, Some(false));
        assert!(EngineOptions::parse(b"{bad").is_err());
    }
}
