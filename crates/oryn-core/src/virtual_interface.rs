//! 本机虚拟接口配置：只在启动/重载时编译，不在包路径解析文本。
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use oryn_config::IpCidr;
use serde::{Deserialize, Serialize};

pub const TUNNEL_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// 本机自回环地址：经隧道到此地址的 TCP 不走规则与代理，由 Core 直连 `127.0.0.1` 同端口。
/// 位于隧道内部 /24（App 侧已保护，不作 Fake-IP），供主 App 经完整隧道路径连接本机服务（如 iPerf3 服务端）。
pub const SELF_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 3);
/// 合成吞吐端点：经隧道到此地址的 TCP 由 Core 在内存里充当源 / 汇，不碰本机 socket（见 `synthetic.rs`）。
/// 用来单独量出隧道自身的吞吐上限——`SELF_V4` 的 127.0.0.1 一跳里，内核会在 Core 线程的 `read` / `write` 里替 App 里的
/// 服务端做 TCP 处理，那部分 CPU 是测量设施的成本，真实代理流量里不存在。仅供开发测量，不接收任何外部数据。
pub const SYNTHETIC_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 4);

/// 隧道接口所在的 /24。这段地址不在公网，也不应被当成可拨号的 Fake-IP。
pub fn is_tunnel_subnet(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return false,
        },
    };
    let octets = v4.octets();
    octets[0] == 198 && octets[1] == 18 && octets[2] == 0
}
const MAX_ROUTES: usize = 512;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RouteMode {
    #[default]
    All,
    Specified,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct VirtualInterfaceOptions {
    pub loopback_addresses: Vec<Ipv4Addr>,
    pub route_mode: RouteMode,
    pub included_routes: Vec<String>,
    pub excluded_routes: Vec<String>,
    pub include_all_networks: bool,
    pub include_local_network: bool,
    /// 平台报告的本机地址与广播地址，用于阻止占用。
    pub local_addresses: Vec<Ipv4Addr>,
}

impl Default for VirtualInterfaceOptions {
    fn default() -> Self {
        Self {
            loopback_addresses: Vec::new(),
            route_mode: RouteMode::All,
            included_routes: Vec::new(),
            excluded_routes: Vec::new(),
            include_all_networks: false,
            include_local_network: true,
            local_addresses: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VirtualInterfacePlan {
    pub included: Vec<String>,
    pub excluded: Vec<String>,
    pub required: Vec<String>,
}

fn parse(value: &str) -> Result<IpCidr, String> {
    if value.len() > 64
        || value.contains('%')
        || value
            .split_once('/')
            .is_some_and(|(_, p)| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("invalid virtual interface route: {value}"));
    }
    let cidr =
        IpCidr::parse(value).ok_or_else(|| format!("invalid virtual interface route: {value}"))?;
    if matches!(cidr.addr(), IpAddr::V6(a) if a.to_ipv4_mapped().is_some()) {
        return Err(format!("IPv4-mapped IPv6 route is not supported: {value}"));
    }
    Ok(cidr.network())
}

fn covers(a: IpCidr, b: IpCidr) -> bool {
    a.is_ipv4() == b.is_ipv4() && a.prefix() <= b.prefix() && a.contains(b.addr())
}
fn overlaps(a: IpCidr, b: IpCidr) -> bool {
    covers(a, b) || covers(b, a)
}

fn simplify(mut routes: Vec<IpCidr>) -> Vec<IpCidr> {
    routes.sort_by_key(|r| (r.prefix(), r.addr()));
    let mut result = Vec::new();
    for route in routes {
        if !result.iter().any(|r| covers(*r, route)) {
            result.push(route);
        }
    }
    result.sort_by_key(|r| (r.addr(), r.prefix()));
    result
}

/// 按前缀二分减去排除网段，临时结果同样有上限。
fn subtract_one(route: IpCidr, excluded: IpCidr, out: &mut Vec<IpCidr>) -> Result<(), String> {
    if covers(excluded, route) {
        return Ok(());
    }
    if !overlaps(route, excluded) {
        if out.len() >= MAX_ROUTES {
            return Err("too many effective virtual interface routes (maximum 512)".into());
        }
        out.push(route);
        return Ok(());
    }
    let prefix = route.prefix() + 1;
    let (left, right) = match route.addr() {
        IpAddr::V4(a) => (
            IpAddr::V4(a),
            IpAddr::V4(Ipv4Addr::from(u32::from(a) | (1 << (32 - prefix)))),
        ),
        IpAddr::V6(a) => (
            IpAddr::V6(a),
            IpAddr::V6(Ipv6Addr::from(u128::from(a) | (1 << (128 - prefix)))),
        ),
    };
    for addr in [left, right] {
        subtract_one(
            IpCidr::parse(&format!("{addr}/{prefix}")).unwrap(),
            excluded,
            out,
        )?;
    }
    Ok(())
}
fn subtract(mut routes: Vec<IpCidr>, exclusions: &[IpCidr]) -> Result<Vec<IpCidr>, String> {
    for excluded in exclusions {
        let mut next = Vec::new();
        for route in routes {
            subtract_one(route, *excluded, &mut next)?;
        }
        routes = next;
    }
    Ok(simplify(routes))
}
fn strings(routes: Vec<IpCidr>) -> Vec<String> {
    routes.iter().map(ToString::to_string).collect()
}

impl VirtualInterfaceOptions {
    pub fn compile(&self, fake_ip: IpCidr, dns: Ipv4Addr) -> Result<VirtualInterfacePlan, String> {
        if self.loopback_addresses.len() > 16
            || self.included_routes.len() > 128
            || self.excluded_routes.len() > 128
            || self.local_addresses.len() > 128
        {
            return Err("virtual interface setting exceeds its entry limit".into());
        }
        if self.include_all_networks
            && (self.route_mode != RouteMode::All || !self.excluded_routes.is_empty())
        {
            return Err(
                "Include All Networks requires All Traffic with no custom excluded routes".into(),
            );
        }
        let included = self
            .included_routes
            .iter()
            .map(|s| parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let excluded = simplify(
            self.excluded_routes
                .iter()
                .map(|s| parse(s))
                .collect::<Result<Vec<_>, _>>()?,
        );
        if self.route_mode == RouteMode::Specified && included.is_empty() {
            return Err("Specified Networks requires at least one included route".into());
        }
        if self.route_mode == RouteMode::Specified {
            for i in &included {
                if excluded.iter().any(|e| covers(*e, *i)) {
                    return Err(format!(
                        "included route {i} is covered by an excluded route; split the exclusion"
                    ));
                }
            }
        }
        let mut required = vec![
            parse("198.18.0.0/24")?,
            parse("fd00:6f72:796e::/64")?,
            fake_ip.network(),
            parse(&dns.to_string())?,
        ];
        let private = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "fc00::/7",
            "fe80::/10",
        ]
        .map(|s| parse(s).unwrap());
        let system_excludes = if self.include_all_networks && !self.include_local_network {
            private.to_vec()
        } else {
            Vec::new()
        };
        for (index, address) in self.loopback_addresses.iter().enumerate() {
            let ip = IpAddr::V4(*address);
            let octets = address.octets();
            if octets[0] == 0
                || octets[0] == 127
                || octets[0] >= 224
                || address.is_link_local()
                || self.local_addresses.contains(address)
                || required.iter().any(|r| r.contains(ip))
                || self.loopback_addresses[..index].contains(address)
            {
                return Err(format!(
                    "invalid or conflicting loopback address: {address}"
                ));
            }
            if system_excludes.iter().any(|r| r.contains(ip)) {
                return Err(format!(
                    "loopback address {address} conflicts with Exclude Local Networks"
                ));
            }
            required.push(parse(&address.to_string())?);
        }
        required = simplify(required);
        for e in &excluded {
            if let Some(r) = required.iter().find(|r| overlaps(*e, **r)) {
                return Err(format!(
                    "excluded route {e} conflicts with required route {r}"
                ));
            }
        }
        // 系统私网例外扣除内部网段；用户排除冲突则在上面明确拒绝。
        let mut effective_excluded = excluded;
        effective_excluded.extend(subtract(system_excludes, &required)?);
        let effective_excluded = simplify(effective_excluded);
        let mut effective_included = match self.route_mode {
            RouteMode::All => vec![parse("0.0.0.0/0")?, parse("::/0")?],
            RouteMode::Specified => included,
        };
        effective_included.extend(required.iter().copied());
        let effective_included = subtract(simplify(effective_included), &effective_excluded)?;
        if effective_included.len() + effective_excluded.len() > MAX_ROUTES {
            return Err("too many effective virtual interface routes (maximum 512)".into());
        }
        Ok(VirtualInterfacePlan {
            included: strings(effective_included),
            excluded: strings(effective_excluded),
            required: strings(required),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan(o: &VirtualInterfaceOptions) -> Result<VirtualInterfacePlan, String> {
        o.compile(
            parse("198.18.0.0/15").unwrap(),
            Ipv4Addr::new(198, 18, 0, 2),
        )
    }
    fn contains(routes: &[String], ip: &str) -> bool {
        routes
            .iter()
            .any(|r| parse(r).unwrap().contains(ip.parse().unwrap()))
    }
    #[test]
    fn vif_defaults_and_custom_dual_stack() {
        let mut o = VirtualInterfaceOptions::default();
        assert_eq!(plan(&o).unwrap().included, ["0.0.0.0/0", "::/0"]);
        o.route_mode = RouteMode::Specified;
        assert!(plan(&o).is_err());
        o.included_routes = vec!["10.1.2.3/8".into(), "2001:db8::/32".into()];
        o.excluded_routes = vec!["10.1.0.0/16".into(), "2001:db8:1::/48".into()];
        let p = plan(&o).unwrap();
        for ip in ["10.2.0.1", "2001:db8:2::1", "198.19.1.1", "198.18.0.2"] {
            assert!(contains(&p.included, ip));
        }
        for ip in ["10.1.2.3", "2001:db8:1::1", "8.8.8.8", "2606:4700::1"] {
            assert!(!contains(&p.included, ip));
        }
        o.included_routes.push("10.1.2.0/24".into());
        assert!(plan(&o).is_err());
    }
    #[test]
    fn vif_protects_dynamic_ranges_aliases_and_system_options() {
        let mut o = VirtualInterfaceOptions {
            loopback_addresses: vec!["10.7.0.1".parse().unwrap()],
            ..Default::default()
        };
        assert!(plan(&o).unwrap().required.contains(&"10.7.0.1/32".into()));
        assert!(o.compile(parse("10.7.0.0/20").unwrap(), TUNNEL_V4).is_err());
        o.excluded_routes.push("10.0.0.0/8".into());
        assert!(plan(&o).is_err());
        o.excluded_routes.clear();
        o.include_all_networks = true;
        o.include_local_network = false;
        assert!(plan(&o).is_err());
        o.loopback_addresses.clear();
        let p = plan(&o).unwrap();
        assert!(contains(&p.included, "fd00:6f72:796e::1"));
        assert!(!contains(&p.excluded, "fd00:6f72:796e::1"));
        assert!(contains(&p.excluded, "fd12::1"));
        o.route_mode = RouteMode::Specified;
        assert!(plan(&o).is_err());
    }
    #[test]
    fn vif_invalid_and_bounded_inputs() {
        for address in [
            "0.1.2.3",
            "127.0.0.2",
            "169.254.1.2",
            "224.0.0.1",
            "198.18.0.1",
            "198.19.1.1",
        ] {
            let o = VirtualInterfaceOptions {
                loopback_addresses: vec![address.parse().unwrap()],
                ..Default::default()
            };
            assert!(plan(&o).is_err(), "{address}");
        }
        let mut o = VirtualInterfaceOptions::default();
        for route in [
            "host.test",
            "::1%lo0",
            "1.2.3.4/33",
            "::/129",
            "::ffff:1.2.3.4",
            "10.0.0.0/+8",
        ] {
            o.included_routes = vec![route.into()];
            assert!(plan(&o).is_err(), "{route}");
        }
        o.included_routes = vec!["1.2.3.4".into(); 129];
        assert!(plan(&o).is_err());
        o.included_routes.clear();
        o.excluded_routes = (1..128).map(|n| format!("2001:{n:x}::1/128")).collect();
        assert!(plan(&o).unwrap_err().contains("512"));
    }
}
