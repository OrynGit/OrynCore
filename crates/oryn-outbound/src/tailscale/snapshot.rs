//! 有界 netmap 快照。全量优先于增量，撤销、过期、DNS 更新采用同一代数据。
use super::err;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use ts_keys::NodePublicKey;
/// 对端上限。原先 32，稍大的 tailnet 即整份 netmap 被拒（OrynCore#43）；每个对端只占一份
/// WireGuard 会话与少量路由状态，256 仍在 Extension 预算内。快照总大小另有上限。
pub const MAX_PEERS: usize = 256;
/// 快照（对端、本机、DNS、DERP、过滤器的原始 JSON）总大小上限。
const MAX_SNAPSHOT: usize = 768 * 1024;
const MAX_ROUTES_PER_PEER: usize = 64;
const MAX_ENDPOINTS_PER_PEER: usize = 16;
const MAX_FILTER_RULES: usize = 256;
type DnsRouteMap = BTreeMap<String, Vec<std::net::SocketAddr>>;
type DnsConfigParts = (
    Vec<std::net::SocketAddr>,
    DnsRouteMap,
    Vec<std::net::SocketAddr>,
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub id: i64,
    pub key: [u8; 32],
    pub name: String,
    pub ips: Vec<IpAddr>,
    pub derp: u16,
    pub expiry: Option<i64>,
    /// Primary subnet routes selected by the control plane. Host addresses are
    /// kept separately in `ips`; this list is only enabled when accept-routes
    /// is set on the outbound.
    pub routes: Vec<oryn_config::IpCidr>,
    pub endpoints: Vec<std::net::SocketAddr>,
    pub online: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AclRule {
    pub src: Vec<oryn_config::IpCidr>,
    pub dst: Vec<(oryn_config::IpCidr, u16, u16)>,
    pub protocols: Vec<u8>,
}
/// 一次 netmap 更新带来的变化。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    None,
    /// 只有对端上下线、DNS 记录与解析器变化：替换快照即可，隧道与既有 Flow 保留。
    Soft,
    /// 对端密钥 / 地址 / 路由 / 端点 / DERP、本机地址、授权、过期、ACL 变化：换代重建隧道。
    Hard,
}

#[derive(Default, Clone)]
pub struct Snapshot {
    raw: BTreeMap<i64, Value>,
    own: Value,
    dns: Value,
    derp: Value,
    filters: BTreeMap<String, Value>,
    pub peers: Vec<Peer>,
    pub own_ips: Vec<IpAddr>,
    pub records: BTreeMap<String, Vec<IpAddr>>,
    pub regions: BTreeMap<u16, url::Url>,
    pub region_nodes: BTreeMap<u16, Vec<url::Url>>,
    /// DERP 节点的 `CertName`：证书期望名称，或 `sha256-raw:<hex>` 固定自签证书（自建 derper）。
    pub derp_certs: BTreeMap<url::Url, String>,
    /// 声明 `InsecureForTests: true` 的 DERP 节点（含非 127.0.0.1 自建测试/内网节点）。
    pub derp_insecure: std::collections::BTreeSet<url::Url>,
    /// DERPMap 给出的显式节点 IP（当 `HostName` 无 DNS 或作 SNI 虚拟名时作为拨号回退）。
    pub derp_ips: BTreeMap<url::Url, Vec<IpAddr>>,
    pub dns_resolvers: Vec<std::net::SocketAddr>,
    pub dns_routes: BTreeMap<String, Vec<std::net::SocketAddr>>,
    pub dns_fallback: Vec<std::net::SocketAddr>,
    pub expiry: Option<i64>,
    pub authorized: bool,
    pub acl: Vec<AclRule>,
    pub generation: u64,
}
fn expiry(node: &Value) -> io::Result<Option<i64>> {
    let Some(text) = node["KeyExpiry"].as_str() else {
        return Ok(None);
    };
    if text.starts_with("0001-") {
        return Ok(None);
    }
    Ok(Some(
        chrono::DateTime::parse_from_rfc3339(text)
            .map_err(io::Error::other)?
            .timestamp(),
    ))
}
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn ips(node: &Value) -> io::Result<Vec<IpAddr>> {
    let addresses = node["Addresses"]
        .as_array()
        .ok_or_else(|| err("Tailscale node has no addresses"))?;
    if addresses.is_empty() || addresses.len() > 4 {
        return Err(err("invalid Tailscale node addresses"));
    }
    addresses
        .iter()
        .map(|v| {
            let value = v.as_str().ok_or_else(|| err("invalid Tailscale address"))?;
            let cidr = oryn_config::IpCidr::parse(value)
                .ok_or_else(|| err("invalid Tailscale address prefix"))?;
            let ip: IpAddr = value
                .split('/')
                .next()
                .unwrap_or("")
                .parse()
                .map_err(io::Error::other)?;
            if cidr.prefix() != if ip.is_ipv4() { 32 } else { 128 } {
                return Err(err("peer address must be a host prefix"));
            }
            Ok(ip)
        })
        .collect()
}
fn cidr_list(node: &Value, key: &str) -> io::Result<Vec<oryn_config::IpCidr>> {
    let Some(values) = node[key].as_array() else {
        return Ok(Vec::new());
    };
    if values.len() > MAX_ROUTES_PER_PEER {
        return Err(err("Tailscale route count exceeds limit"));
    }
    values
        .iter()
        .map(|value| {
            let text = value
                .as_str()
                .ok_or_else(|| err("invalid Tailscale route"))?;
            oryn_config::IpCidr::parse(text).ok_or_else(|| err("invalid Tailscale route prefix"))
        })
        .collect()
}
fn endpoints(node: &Value) -> io::Result<Vec<std::net::SocketAddr>> {
    let Some(values) = node["Endpoints"].as_array() else {
        return Ok(Vec::new());
    };
    if values.len() > MAX_ENDPOINTS_PER_PEER {
        return Err(err("Tailscale endpoint count exceeds limit"));
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| err("invalid Tailscale endpoint"))?
                .parse()
                .map_err(io::Error::other)
        })
        .collect()
}
fn selector(text: &str) -> io::Result<Vec<oryn_config::IpCidr>> {
    let text = text.trim();
    if text == "*" {
        return Ok([
            oryn_config::IpCidr::parse("0.0.0.0/0"),
            oryn_config::IpCidr::parse("::/0"),
        ]
        .into_iter()
        .flatten()
        .collect());
    }
    // tailcfg FilterRule.SrcIPs / NetPortRange.IP 允许「两个 IP 以连字符相连的闭区间」，
    // headscale 用 netipx.IPSet.Strings() 生成的正是这种形式（OrynCore#38）
    if let Some((start, end)) = text.split_once('-') {
        let start: IpAddr = start.trim().parse().map_err(|_| err("invalid filter IP range"))?;
        let end: IpAddr = end.trim().parse().map_err(|_| err("invalid filter IP range"))?;
        return range_cidrs(start, end);
    }
    if text.contains('/') {
        return Ok(vec![
            oryn_config::IpCidr::parse(text).ok_or_else(|| err("invalid filter CIDR"))?
        ]);
    }
    let ip: IpAddr = text.parse().map_err(|_| err("invalid filter IP"))?;
    Ok(vec![oryn_config::IpCidr::parse(&format!(
        "{ip}/{}",
        if ip.is_ipv4() { 32 } else { 128 }
    ))
    .ok_or_else(|| err("invalid filter IP"))?])
}
/// 闭区间 [start, end] 拆成最少的前缀块。
fn range_cidrs(start: IpAddr, end: IpAddr) -> io::Result<Vec<oryn_config::IpCidr>> {
    let (bits, lo, hi) = match (start, end) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (32u32, u128::from(u32::from(a)), u128::from(u32::from(b))),
        (IpAddr::V6(a), IpAddr::V6(b)) => (128u32, u128::from(a), u128::from(b)),
        _ => return Err(err("filter IP range mixes address families")),
    };
    if lo > hi {
        return Err(err("invalid filter IP range order"));
    }
    let span = |size: u32| if size >= 128 { u128::MAX } else { (1u128 << size) - 1 };
    let mut out = Vec::new();
    let mut cur = lo;
    loop {
        // 以 cur 为起点、不越过 hi 的最大对齐块
        let mut size = if cur == 0 { bits } else { cur.trailing_zeros().min(bits) };
        while size > 0 && cur.checked_add(span(size)).is_none_or(|last| last > hi) {
            size -= 1;
        }
        let ip = if bits == 32 {
            IpAddr::from(std::net::Ipv4Addr::from(cur as u32))
        } else {
            IpAddr::from(std::net::Ipv6Addr::from(cur))
        };
        out.push(
            oryn_config::IpCidr::parse(&format!("{ip}/{}", bits - size))
                .ok_or_else(|| err("invalid filter IP range"))?,
        );
        if out.len() > MAX_FILTER_RULES {
            return Err(err("filter IP range is too fragmented"));
        }
        let last = cur + span(size);
        if last >= hi {
            return Ok(out);
        }
        cur = last + 1;
    }
}
fn selectors(value: &Value) -> io::Result<Vec<oryn_config::IpCidr>> {
    let Some(values) = value.as_array() else {
        return Err(err("Tailscale filter source is not an array"));
    };
    if values.is_empty() || values.len() > MAX_FILTER_RULES {
        return Err(err("invalid Tailscale filter source count"));
    }
    let mut out = Vec::new();
    for value in values {
        let text = value.as_str().ok_or_else(|| err("invalid filter source"))?;
        if text.starts_with("cap:") {
            return Err(err("Tailscale capability filter sources are not supported"));
        }
        out.extend(selector(text)?);
    }
    Ok(out)
}
fn compile_acl(filters: &BTreeMap<String, Value>) -> io::Result<Vec<AclRule>> {
    let mut out = Vec::new();
    for value in filters.values() {
        let rules = value
            .as_array()
            .ok_or_else(|| err("invalid Tailscale packet filter"))?;
        if out.len() + rules.len() > MAX_FILTER_RULES {
            return Err(err("Tailscale packet filter count exceeds limit"));
        }
        for rule in rules {
            // 过滤器只描述谁可以连入本节点（tailscale filter.RunIn；RunOut 恒放行），本核心不接受入站，
            // 所以单条规则无法解析时跳过并记录，不能让整份 netmap 失败（OrynCore#38 / #39）
            match compile_rule(rule) {
                Ok(Some(rule)) => out.push(rule),
                Ok(None) => {}
                Err(error) => log::warn!("tailscale: skipping packet filter rule: {error}"),
            }
        }
    }
    Ok(out)
}
fn compile_rule(rule: &Value) -> io::Result<Option<AclRule>> {
    {
        {
            let src = selectors(&rule["SrcIPs"])?;
            let protocols = match rule["IPProto"].as_array() {
                None => Vec::new(),
                Some(values) => values
                    .iter()
                    .map(|value| {
                        let n = value
                            .as_i64()
                            .ok_or_else(|| err("invalid Tailscale protocol"))?;
                        u8::try_from(n).map_err(|_| err("invalid Tailscale protocol"))
                    })
                    .collect::<io::Result<Vec<_>>>()?,
            };
            let Some(ports) = rule["DstPorts"].as_array() else {
                // CapGrant is an application capability, not a network
                // allow rule. Preserve the conservative network boundary by
                // skipping it instead of turning it into allow-all.
                if rule["CapGrant"].as_array().is_some_and(|v| !v.is_empty()) {
                    return Ok(None);
                }
                return Err(err("Tailscale filter has no destination ports"));
            };
            if ports.is_empty() {
                return Err(err("Tailscale filter destination is empty"));
            }
            let mut dst = Vec::with_capacity(ports.len());
            for port in ports {
                let cidrs = selector(port["IP"].as_str().unwrap_or(""))?;
                let first = port["Ports"]["First"]
                    .as_u64()
                    .and_then(|n| u16::try_from(n).ok())
                    .ok_or_else(|| err("invalid Tailscale destination port"))?;
                let last = port["Ports"]["Last"]
                    .as_u64()
                    .and_then(|n| u16::try_from(n).ok())
                    .ok_or_else(|| err("invalid Tailscale destination port"))?;
                if first > last {
                    return Err(err("invalid Tailscale destination port range"));
                }
                for cidr in cidrs {
                    dst.push((cidr, first, last));
                }
            }
            Ok(Some(AclRule {
                src,
                dst,
                protocols,
            }))
        }
    }
}
fn dns_servers(value: &Value, key: &str) -> io::Result<Vec<std::net::SocketAddr>> {
    let Some(values) = value[key].as_array() else {
        return Ok(Vec::new());
    };
    if values.len() > 8 {
        return Err(err("too many Tailscale DNS resolvers"));
    }
    let mut out = Vec::new();
    for resolver in values {
        let addr = resolver["Addr"].as_str().unwrap_or("");
        let parsed = addr
            .parse::<std::net::SocketAddr>()
            .or_else(|_| {
                addr.parse::<IpAddr>()
                    .map(|ip| std::net::SocketAddr::new(ip, 53))
            })
            .map_err(|_| err("Tailscale DNS resolver must use an IP address"))?;
        out.push(parsed);
    }
    Ok(out)
}
fn parse_dns(value: &Value) -> io::Result<DnsConfigParts> {
    let defaults = dns_servers(value, "Resolvers")?;
    let fallback = dns_servers(value, "FallbackResolvers")?;
    let mut routes = BTreeMap::new();
    if let Some(map) = value["Routes"].as_object() {
        if map.len() > 64 {
            return Err(err("too many Tailscale DNS routes"));
        }
        for (name, resolvers) in map {
            let suffix = name.trim_end_matches('.').to_ascii_lowercase();
            if suffix.is_empty()
                || suffix.len() > 253
                || suffix.bytes().any(|c| c <= 32 || c >= 127)
            {
                return Err(err("invalid Tailscale DNS route suffix"));
            }
            routes.insert(
                suffix,
                dns_servers(&json!({"Resolvers": resolvers}), "Resolvers")?,
            );
        }
    }
    Ok((defaults, routes, fallback))
}
fn name(node: &Value) -> io::Result<String> {
    let name = node["Name"]
        .as_str()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if name.len() > 253 || name.bytes().any(|c| c <= 32 || c >= 127) {
        return Err(err("invalid MagicDNS name"));
    }
    Ok(name)
}
impl Snapshot {
    pub fn valid(&self) -> bool {
        self.authorized && self.expiry.is_none_or(|e| e > now())
    }
    pub fn peer(&self, ip: IpAddr) -> bool {
        self.peers
            .iter()
            .any(|p| p.ips.contains(&ip) && p.expiry.is_none_or(|e| e > now()))
    }
    pub fn subnet(&self, ip: IpAddr) -> bool {
        self.peers.iter().any(|p| {
            p.routes
                .iter()
                .any(|route| route.prefix() != 0 && route.contains(ip))
                && p.expiry.is_none_or(|e| e > now())
        })
    }
    /// 入站判定（tailscale filter.RunIn 语义）：`source` 能否连到本节点的 `destination:port`。
    /// 本核心不监听入站，出站一律放行（RunOut 恒 Accept），目前只有测试使用。
    #[cfg(test)]
    pub fn admits(&self, source: IpAddr, destination: IpAddr, port: u16, protocol: u8) -> bool {
        self.acl.iter().any(|rule| {
            rule.src.iter().any(|cidr| cidr.contains(source))
                && (rule.protocols.is_empty() || rule.protocols.contains(&protocol))
                && rule.dst.iter().any(|(cidr, first, last)| {
                    cidr.contains(destination) && port >= *first && port <= *last
                })
        })
    }
    pub fn magic_domain(&self, name: &str) -> bool {
        self.dns["Domains"].as_array().is_some_and(|domains| {
            domains.iter().filter_map(Value::as_str).any(|domain| {
                let suffix = domain.trim_end_matches('.').to_ascii_lowercase();
                name == suffix || name.ends_with(&format!(".{suffix}"))
            })
        })
    }
    /// 影响 WireGuard 配置、DERP 或授权的部分（对端的 `online` 不算）。
    #[allow(clippy::type_complexity)]
    fn hard_state(
        &self,
    ) -> (
        Vec<Peer>,
        Vec<IpAddr>,
        BTreeMap<u16, url::Url>,
        BTreeMap<u16, Vec<url::Url>>,
        BTreeMap<url::Url, String>,
        std::collections::BTreeSet<url::Url>,
        BTreeMap<url::Url, Vec<IpAddr>>,
        Option<i64>,
        bool,
    ) {
        let peers = self
            .peers
            .iter()
            .cloned()
            .map(|mut p| {
                p.online = true;
                p
            })
            .collect();
        (
            peers,
            self.own_ips.clone(),
            self.regions.clone(),
            self.region_nodes.clone(),
            self.derp_certs.clone(),
            self.derp_insecure.clone(),
            self.derp_ips.clone(),
            self.expiry,
            self.authorized,
        )
    }
    #[allow(clippy::type_complexity)]
    fn soft_state(
        &self,
    ) -> (
        Vec<bool>,
        BTreeMap<String, Vec<IpAddr>>,
        Vec<std::net::SocketAddr>,
        DnsRouteMap,
        Vec<std::net::SocketAddr>,
        BTreeMap<String, Value>,
        Vec<AclRule>,
    ) {
        (
            self.peers.iter().map(|p| p.online).collect(),
            self.records.clone(),
            self.dns_resolvers.clone(),
            self.dns_routes.clone(),
            self.dns_fallback.clone(),
            // 过滤器只影响入站判定，不改变隧道与出站，变化不必换代
            self.filters.clone(),
            self.acl.clone(),
        )
    }
    /// 与另一份快照相比，切换过去需要的变化级别。
    pub fn change_from(&self, other: &Snapshot) -> Change {
        if self.hard_state() != other.hard_state() {
            Change::Hard
        } else if self.soft_state() != other.soft_state() {
            Change::Soft
        } else {
            Change::None
        }
    }
    pub fn apply(&mut self, value: Value) -> io::Result<Change> {
        if value["KeepAlive"].as_bool() == Some(true) {
            return Ok(Change::None);
        }
        let before = self.clone();
        if value["TKAInfo"].is_object() && value["TKAInfo"]["Disabled"].as_bool() != Some(true) {
            return Err(err("Tailnet Lock is not supported"));
        }
        if value["Node"].is_object() {
            self.own = value["Node"].clone();
        }
        if let Some(full) = value["Peers"].as_array() {
            if full.len() > MAX_PEERS {
                return Err(err(&format!("Tailscale peer count exceeds {MAX_PEERS}")));
            }
            self.raw.clear();
            for node in full {
                let id = node["ID"].as_i64().ok_or_else(|| err("missing peer ID"))?;
                self.raw.insert(id, node.clone());
            }
        } else {
            if let Some(removed) = value["PeersRemoved"].as_array() {
                for id in removed {
                    if let Some(id) = id.as_i64() {
                        self.raw.remove(&id);
                    }
                }
            }
            if let Some(changed) = value["PeersChanged"].as_array() {
                for node in changed {
                    let id = node["ID"].as_i64().ok_or_else(|| err("missing peer ID"))?;
                    self.raw.insert(id, node.clone());
                }
            }
            if let Some(patches) = value["PeersChangedPatch"].as_array() {
                for patch in patches {
                    let id = patch["NodeID"]
                        .as_i64()
                        .ok_or_else(|| err("invalid peer patch ID"))?;
                    if let Some(node) = self.raw.get_mut(&id).and_then(Value::as_object_mut) {
                        for (key, value) in
                            patch.as_object().ok_or_else(|| err("invalid peer patch"))?
                        {
                            if key == "DERPRegion" {
                                // PeerChange 的字段名与完整 Node 不同；0 表示没有变化。
                                if value.as_u64().is_some_and(|region| region != 0) {
                                    node.insert("HomeDERP".into(), value.clone());
                                }
                            } else if key != "NodeID" && !value.is_null() {
                                // Go PeerChange 的可选指针/slice/map 为 nil 表示不更新；
                                // 例如 null KeyExpiry 不能撤销旧到期约束，[] Endpoints 才是清空。
                                node.insert(key.clone(), value.clone());
                            }
                        }
                    }
                }
            }
            if let Some(changes) = value["OnlineChange"].as_object() {
                for (id, online) in changes {
                    if let Ok(id) = id.parse::<i64>() {
                        if let Some(node) = self.raw.get_mut(&id) {
                            node["Online"] = online.clone();
                        }
                    }
                }
            }
        }
        if self.raw.len() > MAX_PEERS {
            return Err(err(&format!("Tailscale peer count exceeds {MAX_PEERS}")));
        }
        if value["DNSConfig"].is_object() {
            self.dns = value["DNSConfig"].clone();
            let (resolvers, routes, fallback) = parse_dns(&self.dns)?;
            self.dns_resolvers = resolvers;
            self.dns_routes = routes;
            self.dns_fallback = fallback;
        }
        if value["DERPMap"].is_object() {
            let mut next = value["DERPMap"].clone();
            // 与固定版控制端语义一致：省略/null 沿用旧值，显式空 map 则清空。
            if next["Regions"].is_null() {
                next["Regions"] = self.derp["Regions"].clone();
                next["OmitDefaultRegions"] = self.derp["OmitDefaultRegions"].clone();
            }
            if next["HomeParams"].is_null() {
                next["HomeParams"] = self.derp["HomeParams"].clone();
            } else if next["HomeParams"].is_object() && next["HomeParams"]["RegionScore"].is_null()
            {
                next["HomeParams"]["RegionScore"] = self.derp["HomeParams"]["RegionScore"].clone();
            }
            self.derp = next;
        }
        if let Some(filter) = value.get("PacketFilter").filter(|v| !v.is_null()) {
            self.filters.clear();
            self.filters.insert("base".into(), filter.clone());
        }
        if let Some(updates) = value["PacketFilters"].as_object() {
            if updates.get("*").is_some_and(Value::is_null) {
                self.filters.clear();
            }
            for (key, filter) in updates {
                if key == "*" {
                    continue;
                }
                if filter.is_null() {
                    self.filters.remove(key);
                } else {
                    self.filters.insert(key.clone(), filter.clone());
                }
            }
        }
        if self.filters.len() > 64
            || serde_json::to_vec(&(&self.raw, &self.own, &self.dns, &self.derp, &self.filters))
                .map_err(io::Error::other)?
                .len()
                > MAX_SNAPSHOT
        {
            return Err(err("Tailscale snapshot exceeds size limit"));
        }
        self.acl = compile_acl(&self.filters)?;
        self.authorized = self.own["MachineAuthorized"].as_bool() == Some(true)
            && self.own["Expired"].as_bool() != Some(true);
        self.expiry = expiry(&self.own)?;
        self.own_ips = ips(&self.own)?;
        // 本后端只发起连接，无监听端口。空过滤器在官方语义下是「无人可以连入」，不影响出站（OrynCore#39）。
        self.peers.clear();
        self.records.clear();
        self.regions.clear();
        self.region_nodes.clear();
        self.derp_certs.clear();
        self.derp_insecure.clear();
        self.derp_ips.clear();
        let own_name = name(&self.own)?;
        if !own_name.is_empty() {
            self.records.insert(own_name, self.own_ips.clone());
        }
        for (&id, node) in &self.raw {
            // 不看对端的 MachineAuthorized：它是旧字段，headscale 只给本机置位；未获准入的机器
            // 控制面根本不会下发（OrynCore#40）。IsJailed 只限制对端发起连接，连向它仍允许。
            if node["Expired"].as_bool() == Some(true) {
                continue;
            }
            let expires = expiry(node)?;
            if expires.is_some_and(|e| e <= now()) {
                continue;
            }
            if node["KeySignature"].as_str().is_some_and(|s| !s.is_empty()) {
                return Err(err("signed tailnet node requires unsupported Tailnet Lock"));
            }
            let key: NodePublicKey = node["Key"]
                .as_str()
                .ok_or_else(|| err("missing node key"))?
                .parse()
                .map_err(io::Error::other)?;
            let ip = ips(node)?;
            let mut routes = cidr_list(node, "PrimaryRoutes")?;
            let allowed = cidr_list(node, "AllowedIPs")?;
            if node.get("PrimaryRoutes").is_none() {
                routes = allowed.clone();
            }
            // 控制面可能将 exit 默认路由仅放在 AllowedIPs。
            for route in allowed.into_iter().filter(|route| route.prefix() == 0) {
                if !routes.contains(&route) {
                    routes.push(route);
                }
            }
            // A node's address prefixes are not subnet routes. They are added
            // by the WireGuard adapter from `ips` below.
            routes.retain(|route| {
                !ip.iter().any(|address| {
                    route.prefix() == if address.is_ipv4() { 32 } else { 128 }
                        && route.contains(*address)
                })
            });
            let endpoints = endpoints(node)?;
            let name = name(node)?;
            let region = node["HomeDERP"]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .filter(|n| *n != 0)
                .or_else(|| {
                    node["DERP"]
                        .as_str()
                        .and_then(|s| s.rsplit(':').next()?.parse().ok())
                })
                .unwrap_or(0);
            if !name.is_empty() {
                self.records.insert(name.clone(), ip.clone());
            }
            if region != 0 {
                self.peers.push(Peer {
                    id,
                    key: *key.to_crypto_box().as_bytes(),
                    name,
                    ips: ip,
                    derp: region,
                    expiry: expires,
                    routes,
                    endpoints,
                    online: node["Online"].as_bool().unwrap_or(true),
                });
            }
        }
        // 短名仅从控制面实际搜索域派生，不猜全部 ts.net。
        if let Some(domains) = self.dns["Domains"].as_array() {
            if domains.len() > 16 {
                return Err(err("too many MagicDNS search domains"));
            }
            for domain in domains.iter().filter_map(Value::as_str) {
                let suffix = format!(".{}", domain.trim_end_matches('.').to_ascii_lowercase());
                let additions: Vec<_> = self
                    .records
                    .iter()
                    .filter_map(|(n, ips)| {
                        n.strip_suffix(&suffix)
                            .filter(|s| !s.contains('.'))
                            .map(|short| (short.to_string(), ips.clone()))
                    })
                    .collect();
                for (n, ips) in additions {
                    self.records.entry(n).or_insert(ips);
                }
            }
        }
        if let Some(extra) = self.dns["ExtraRecords"].as_array() {
            if extra.len() > 64 {
                return Err(err("too many MagicDNS extra records"));
            }
            for record in extra {
                if matches!(record["Type"].as_str(), Some("A" | "AAAA")) {
                    let n = record["Name"]
                        .as_str()
                        .unwrap_or("")
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    if n.is_empty() || n.len() > 253 {
                        return Err(err("invalid extra DNS record name"));
                    }
                    let ip = record["Value"]
                        .as_str()
                        .unwrap_or("")
                        .parse::<IpAddr>()
                        .map_err(io::Error::other)?;
                    let entry = self.records.entry(n).or_default();
                    if entry.len() >= 4 {
                        return Err(err("too many addresses for DNS record"));
                    }
                    entry.push(ip);
                }
            }
        }
        if let Some(regions) = self.derp["Regions"].as_object() {
            if regions.len() > 128 {
                return Err(err("too many DERP regions"));
            }
            for (id, region) in regions {
                let id = id.parse::<u16>().map_err(io::Error::other)?;
                if let Some(nodes) = region["Nodes"].as_array() {
                    let mut urls = Vec::new();
                    for node in nodes {
                        if node["STUNOnly"].as_bool() == Some(true) {
                            continue;
                        }
                        let host = node["HostName"].as_str().unwrap_or("");
                        let port = node["DERPPort"].as_u64().filter(|n| *n != 0).unwrap_or(443);
                        if host.is_empty() || host.len() > 253 || port > 65535 {
                            return Err(err("invalid DERP server"));
                        }
                        let insecure = node["InsecureForTests"].as_bool() == Some(true);
                        // 本机 loopback 测试对端允许明文；非 127.0.0.1 节点走 HTTPS 并记录 InsecureForTests，
                        // 与官方 derphttp_client 一致（OrynCore#43）。
                        let scheme = if host == "127.0.0.1" && insecure {
                            "http"
                        } else {
                            "https"
                        };
                        let url: url::Url = format!("{scheme}://{host}:{port}/derp")
                            .parse()
                            .map_err(io::Error::other)?;
                        if insecure {
                            self.derp_insecure.insert(url.clone());
                        }
                        if let Some(cert) = node["CertName"].as_str().filter(|c| !c.is_empty()) {
                            if cert.len() > 253 + 11 {
                                return Err(err("invalid DERP certificate name"));
                            }
                            self.derp_certs.insert(url.clone(), cert.to_string());
                        }
                        let host_ip = host.parse::<IpAddr>().ok();
                        let fallback_ips: Vec<IpAddr> = ["IPv4", "IPv6"]
                            .iter()
                            .filter_map(|k| node[*k].as_str())
                            .filter(|v| !v.is_empty() && *v != "none")
                            .filter_map(|v| v.parse::<IpAddr>().ok())
                            .filter(|ip| Some(*ip) != host_ip)
                            .collect();
                        if !fallback_ips.is_empty() {
                            self.derp_ips.insert(url.clone(), fallback_ips);
                        }
                        urls.push(url);
                    }
                    if let Some(first) = urls.first().cloned() {
                        self.regions.insert(id, first);
                        self.region_nodes.insert(id, urls);
                    }
                }
            }
        }
        // 只有硬变化换代：既有 Flow 以 generation 判断身份 / 路由 / 授权是否仍然有效
        let change = self.change_from(&before);
        if change == Change::Hard {
            self.generation = self.generation.wrapping_add(1);
        }
        Ok(change)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn node(id: i64, name: &str) -> Value {
        json!({"ID":id,"Name":name,"Key":ts_keys::NodeKeyPair::random().public.to_string(),"MachineAuthorized":true,"Addresses":[format!("100.64.0.{id}/32")],"HomeDERP":1})
    }
    #[test]
    fn peer_derp_region_patch_updates_compiled_route_and_zero_is_noop() {
        let mut s = Snapshot::default();
        s.apply(json!({"Node":node(1,"own.test"),"Peers":[node(2,"peer.test")]}))
            .unwrap();
        assert_eq!(s.peers[0].derp, 1);
        let generation = s.generation;
        assert_eq!(
            s.apply(json!({"PeersChangedPatch":[{"NodeID":2,"DERPRegion":7}]}))
                .unwrap(),
            Change::Hard
        );
        assert_eq!(s.peers[0].derp, 7);
        assert_eq!(s.generation, generation + 1);
        assert_eq!(s.raw[&2]["HomeDERP"], 7);
        assert_eq!(
            s.apply(json!({"PeersChangedPatch":[{"NodeID":2,"DERPRegion":0}]}))
                .unwrap(),
            Change::None
        );
        assert_eq!(s.peers[0].derp, 7);
    }

    #[test]
    fn nullable_peer_patch_does_not_remove_key_expiry_or_endpoints() {
        let mut s = Snapshot::default();
        let mut peer = node(2, "peer.test");
        peer["KeyExpiry"] = json!("2099-01-01T00:00:00Z");
        peer["Endpoints"] = json!(["192.0.2.1:1234"]);
        s.apply(json!({"Node":node(1,"own.test"),"Peers":[peer]}))
            .unwrap();
        let before = s.peers[0].clone();
        assert_eq!(s.apply(json!({"PeersChangedPatch":[{"NodeID":2,"KeyExpiry":null,"Endpoints":null,"Key":null}]})).unwrap(), Change::None);
        assert_eq!(s.peers[0].expiry, before.expiry);
        assert_eq!(s.peers[0].endpoints, before.endpoints);
        assert_eq!(
            s.apply(json!({"PeersChangedPatch":[{"NodeID":2,"Endpoints":[]}]}))
                .unwrap(),
            Change::Hard
        );
        assert!(s.peers[0].endpoints.is_empty());
    }

    #[test]
    fn partial_derp_map_keeps_omitted_fields_but_empty_regions_clear() {
        let mut s = Snapshot::default();
        s.apply(json!({"Node":node(1,"own.test"),"DERPMap":{
            "Regions":{"1":{"Nodes":[{"HostName":"derp.example"}]}},
            "OmitDefaultRegions":true,"HomeParams":{"RegionScore":{"1":0.5}}
        }}))
        .unwrap();
        let generation = s.generation;
        assert!(s.regions.contains_key(&1));
        s.apply(json!({"DERPMap":{"HomeParams":{}}})).unwrap();
        assert!(
            s.regions.contains_key(&1),
            "partial update must retain DERP endpoints"
        );
        assert_eq!(s.derp["HomeParams"]["RegionScore"]["1"], 0.5);
        assert_eq!(s.derp["OmitDefaultRegions"], true);
        assert_eq!(s.generation, generation);
        s.apply(json!({"DERPMap":{"Regions":null,"HomeParams":null}}))
            .unwrap();
        assert!(s.regions.contains_key(&1));
        assert_eq!(s.derp["HomeParams"]["RegionScore"]["1"], 0.5);
        s.apply(json!({"DERPMap":{"Regions":{}}})).unwrap();
        assert!(
            s.regions.is_empty(),
            "explicit empty map must replace old regions"
        );
        assert_eq!(s.derp["HomeParams"]["RegionScore"]["1"], 0.5);
        assert_eq!(s.generation, generation + 1);
    }

    #[test]
    fn full_delta_dns_and_authorization() {
        let mut s = Snapshot::default();
        let peer = node(2, "peer.example.ts.net.");
        s.apply(json!({"Node":node(1,"oryn.example.ts.net."),"Peers":[peer],"PacketFilter":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}],"DNSConfig":{"Domains":["example.ts.net"]}})).unwrap();
        assert!(s.valid());
        assert!(s.records.contains_key("peer"));
        s.apply(json!({"PeersRemoved":[2]})).unwrap();
        assert!(s.peers.is_empty());
        assert!(!s.records.contains_key("peer"));
        assert!(s.valid());
        // 空过滤器只表示「无人可以连入」，不使本机失去授权（OrynCore#39）
        s.apply(json!({"PacketFilter":[]})).unwrap();
        assert!(s.valid());
    }
    #[test]
    fn online_and_dns_changes_are_soft_routes_and_acl_are_hard() {
        let mut s = Snapshot::default();
        let allow_all =
            json!([{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]);
        assert_eq!(
            s.apply(json!({"Node":node(1,"oryn.example.ts.net."),"Peers":[node(2,"peer.example.ts.net.")],"PacketFilter":allow_all})).unwrap(),
            Change::Hard
        );
        let generation = s.generation;
        // 对端上下线与 DNS 配置变化只是软变化，不换代
        assert_eq!(
            s.apply(json!({"OnlineChange":{"2":false}})).unwrap(),
            Change::Soft
        );
        assert_eq!(
            s.apply(json!({"DNSConfig":{"Resolvers":[{"Addr":"100.64.0.2"}]}}))
                .unwrap(),
            Change::Soft
        );
        assert_eq!(s.apply(json!({"KeepAlive":true})).unwrap(), Change::None);
        assert_eq!(s.generation, generation);
        // 过滤器只影响入站判定：软变化；对端集合变化换代
        assert_eq!(s.apply(json!({"PacketFilter":[]})).unwrap(), Change::Soft);
        assert_eq!(s.apply(json!({"PeersRemoved":[2]})).unwrap(), Change::Hard);
        assert_eq!(s.generation, generation + 1);
    }
    #[test]
    fn oversized_and_tailnet_lock_rejected() {
        let mut s = Snapshot::default();
        assert!(s.apply(json!({"Peers":vec![node(2,"peer");MAX_PEERS + 1]})).is_err());
        assert!(s.apply(json!({"TKAInfo":{"Disabled":false}})).is_err());
    }
    #[test]
    fn subnet_routes_and_packet_filter_are_compiled() {
        let mut s = Snapshot::default();
        let mut peer = node(2, "router.example.ts.net.");
        peer["AllowedIPs"] = json!(["100.64.0.2/32", "10.20.0.0/24"]);
        peer["PrimaryRoutes"] = json!(["10.20.0.0/24"]);
        s.apply(json!({
            "Node": node(1, "oryn.example.ts.net."),
            "Peers": [peer],
            "PacketFilter": [{"SrcIPs":["100.64.0.1/32"],"IPProto":[6],"DstPorts":[{"IP":"10.20.0.0/24","Ports":{"First":80,"Last":80}}]}]
        })).unwrap();
        assert!(s.subnet("10.20.0.8".parse().unwrap()));
        let me = "100.64.0.1".parse().unwrap();
        assert!(s.admits(me, "10.20.0.8".parse().unwrap(), 80, 6));
        assert!(!s.admits(me, "10.20.0.8".parse().unwrap(), 81, 6));
        assert!(!s.admits(me, "10.20.0.8".parse().unwrap(), 80, 17));
    }
    #[test]
    fn exit_defaults_survive_host_filter_and_require_exit_selection() {
        let mut s = Snapshot::default();
        let mut peer = node(2, "exit.example.ts.net.");
        peer["PrimaryRoutes"] = json!(["10.20.0.0/24"]);
        peer["AllowedIPs"] = json!(["100.64.0.2/32", "10.20.0.0/24", "0.0.0.0/0"]);
        s.apply(json!({
            "Node": node(1, "oryn.example.ts.net."), "Peers": [peer],
            "PacketFilter": [{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]
        })).unwrap();
        assert!(!s.subnet("8.8.8.8".parse().unwrap()));
        assert!(s.subnet("10.20.0.8".parse().unwrap()));
        let peer = &s.peers[0];
        let ordinary = super::super::derp::wire_peer(peer, 0, true, false);
        assert!(!ordinary.allowed_ips.iter().any(|route| route.prefix() == 0));
        let exit = super::super::derp::wire_peer(peer, 0, true, true);
        assert!(exit.allowed_ips.iter().any(|route| route.prefix() == 0));
        assert!(!exit
            .allowed_ips
            .iter()
            .any(|route| route.contains("2001:4860:4860::8888".parse().unwrap())));
        assert_eq!(
            super::super::select_exit(&s, Some("auto:any")).unwrap(),
            Some(0)
        );
    }
    #[test]
    fn split_dns_routes_are_bounded_and_parsed() {
        let mut s = Snapshot::default();
        s.apply(json!({
            "Node": node(1, "oryn.example.ts.net."),
            "Peers": [node(2, "peer.example.ts.net.")],
            "PacketFilter": [{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}],
            "DNSConfig": {
                "Resolvers": [{"Addr":"100.64.0.2"}],
                "FallbackResolvers": [{"Addr":"100.64.0.3:5353"}],
                "Routes": {"corp.example": [{"Addr":"100.64.0.4"}], "magic.example": []}
            }
        })).unwrap();
        assert_eq!(s.dns_resolvers[0], "100.64.0.2:53".parse().unwrap());
        assert_eq!(s.dns_fallback[0], "100.64.0.3:5353".parse().unwrap());
        assert_eq!(
            s.dns_routes["corp.example"][0],
            "100.64.0.4:53".parse().unwrap()
        );
        assert!(s.dns_routes["magic.example"].is_empty());
    }
    /// headscale 的缺省策略：SrcIPs / DstPorts 用 netipx 区间（OrynCore#38）
    #[test]
    fn headscale_ip_ranges_compile() {
        let mut s = Snapshot::default();
        s.apply(json!({
            "Node": node(1, "oryn.example.ts.net."),
            "Peers": [node(2, "peer.example.ts.net.")],
            "PacketFilter": [{
                "SrcIPs": ["100.64.0.0-100.127.255.255", "fd7a:115c:a1e0::-fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff"],
                "DstPorts": [{"IP":"100.64.0.1-100.64.0.10","Ports":{"First":0,"Last":65535}}]
            }]
        }))
        .unwrap();
        assert_eq!(s.acl.len(), 1);
        let src: Vec<String> = s.acl[0].src.iter().map(|c| format!("{c:?}")).collect();
        assert_eq!(s.acl[0].src.len(), 2, "{src:?}");
        assert!(s.admits("100.100.1.2".parse().unwrap(), "100.64.0.10".parse().unwrap(), 22, 6));
        assert!(!s.admits("100.128.0.1".parse().unwrap(), "100.64.0.1".parse().unwrap(), 22, 6));
        assert!(!s.admits("100.64.0.5".parse().unwrap(), "100.64.0.11".parse().unwrap(), 22, 6));
        assert!(s.admits("fd7a:115c:a1e0::9".parse().unwrap(), "100.64.0.1".parse().unwrap(), 22, 6));
    }
    #[test]
    fn ranges_split_into_minimal_prefixes() {
        let r = |a: &str, b: &str| {
            range_cidrs(a.parse().unwrap(), b.parse().unwrap())
                .unwrap()
                .iter()
                .map(|c| format!("{}/{}", c.addr(), c.prefix()))
                .collect::<Vec<_>>()
        };
        assert_eq!(r("100.64.0.0", "100.127.255.255"), ["100.64.0.0/10"]);
        assert_eq!(r("10.0.0.1", "10.0.0.6"), ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]);
        assert_eq!(r("0.0.0.0", "255.255.255.255"), ["0.0.0.0/0"]);
        assert_eq!(r("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), ["::/0"]);
        assert_eq!(r("10.0.0.7", "10.0.0.7"), ["10.0.0.7/32"]);
        assert!(range_cidrs("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap()).is_err());
        assert!(range_cidrs("10.0.0.1".parse().unwrap(), "::1".parse().unwrap()).is_err());
    }
    /// 无法解析的过滤规则只跳过该条，不让整份 netmap 失败（OrynCore#38）
    #[test]
    fn bad_filter_rule_is_skipped_not_fatal() {
        let mut s = Snapshot::default();
        s.apply(json!({
            "Node": node(1, "oryn.example.ts.net."),
            "Peers": [node(2, "peer.example.ts.net.")],
            "PacketFilter": [
                {"SrcIPs":["cap:example.com/cap"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]},
                {"SrcIPs":["not-an-ip"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]},
                {"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":22,"Last":22}}]}
            ]
        }))
        .unwrap();
        assert!(s.valid());
        assert_eq!(s.acl.len(), 1);
        assert_eq!(s.peers.len(), 1);
    }
    /// headscale 只给本机置 MachineAuthorized；对端没有该字段也要保留。IsJailed 只限制对端发起连接（OrynCore#40）
    #[test]
    fn peers_without_machine_authorized_or_jailed_are_kept() {
        let mut s = Snapshot::default();
        let mut plain = node(2, "plain.example.ts.net.");
        plain.as_object_mut().unwrap().remove("MachineAuthorized");
        let mut jailed = node(3, "jailed.example.ts.net.");
        jailed["IsJailed"] = json!(true);
        let mut expired = node(4, "expired.example.ts.net.");
        expired["Expired"] = json!(true);
        s.apply(json!({"Node": node(1, "oryn.example.ts.net."), "Peers": [plain, jailed, expired]}))
            .unwrap();
        let names: Vec<_> = s.peers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["plain.example.ts.net", "jailed.example.ts.net"]);
        assert!(s.valid(), "no PacketFilter must not make the node unauthorized");
        assert!(s.peer("100.64.0.2".parse().unwrap()));
    }
    /// 自建 derper 的 CertName（含 sha256-raw 固定自签证书）进入快照，直连对端开保活（OrynCore#43）
    #[test]
    fn derp_cert_name_and_direct_keepalive() {
        let mut s = Snapshot::default();
        let mut direct = node(2, "direct.example.ts.net.");
        direct["Endpoints"] = json!(["192.0.2.1:41641"]);
        let hash = "ab".repeat(32);
        s.apply(json!({
            "Node": node(1, "oryn.example.ts.net."),
            "Peers": [direct, node(3, "relay.example.ts.net.")],
            "DERPMap": {"Regions": {"900": {"Nodes": [
                {"HostName": "203.0.113.9", "DERPPort": 8443, "CertName": format!("sha256-raw:{hash}")}
            ]}}}
        }))
        .unwrap();
        let url = &s.region_nodes[&900][0];
        assert_eq!(url.as_str(), "https://203.0.113.9:8443/derp");
        assert_eq!(s.derp_certs[url], format!("sha256-raw:{hash}"));
        let generation = s.generation;
        s.apply(json!({"DERPMap": {"Regions": {"900": {"Nodes": [
            {"HostName": "203.0.113.9", "DERPPort": 8443, "CertName": "derp.example"}
        ]}}}}))
        .unwrap();
        assert_eq!(s.generation, generation + 1, "certificate change rebuilds DERP");
        let wire = |i: usize| super::super::derp::wire_peer(&s.peers[i], i, false, false);
        assert_eq!(wire(0).keepalive_secs, Some(25));
        assert_eq!(wire(1).keepalive_secs, None);

        // 非 127.0.0.1 节点开启 InsecureForTests 与 IPv4/IPv6 回退应被记录且变更时触发硬切换（OrynCore#43）
        let gen2 = s.generation;
        s.apply(json!({"DERPMap": {"Regions": {"999": {"Nodes": [
            {"HostName": "derp-999", "IPv4": "172.18.0.9", "IPv6": "none", "DERPPort": 8443, "InsecureForTests": true}
        ]}}}}))
        .unwrap();
        assert_eq!(s.generation, gen2 + 1);
        let derp_999 = &s.region_nodes[&999][0];
        assert_eq!(derp_999.as_str(), "https://derp-999:8443/derp");
        assert!(s.derp_insecure.contains(derp_999));
        assert_eq!(
            s.derp_ips[derp_999],
            vec!["172.18.0.9".parse::<IpAddr>().unwrap()]
        );
    }
}
