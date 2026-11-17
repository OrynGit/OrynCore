//! 规则集：`domain` / `ipcidr` / `classical` 三种行为，`text` / `yaml` 两种格式。

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use oryn_config::{
    glob_match, normalize_domain, parse_rule_item, compile_regex, Behavior, CompactRegex, DomainPattern, DomainStyle, IpCidr,
    NetworkKind, PortRange, ProviderFormat, ProviderSpec, RuleKind,
};

use crate::geoip::GeoIp;
use crate::matcher::{Env, Matcher};
use crate::sets::{DomainSet, DomainSetBuilder, IpSet};
use crate::{FlowContext, Network};

#[derive(Debug)]
pub enum RuleSet {
    Domain(DomainSet),
    IpCidr(IpSet),
    Classical(Box<ClassicalSet>),
}

/// `classical` 规则集按类型归并，大部分规则走集合查找而不是逐条匹配。
#[derive(Debug, Default)]
pub struct ClassicalSet {
    domains: DomainSet,
    keywords: Vec<String>,
    wildcards: Vec<String>,
    regexes: Vec<CompactRegex>,
    ips: IpSet,
    geoip: Vec<String>,
    /// 已排序去重，二分查找。
    asns: Vec<u32>,
    ports: Vec<PortRange>,
    networks: Vec<NetworkKind>,
    /// 逻辑规则与源地址规则，逐条匹配。
    others: Vec<Matcher>,
}

impl ClassicalSet {
    fn matches_domain(&self, d: &str) -> bool {
        self.domains.contains(d)
            || self.keywords.iter().any(|k| d.contains(k.as_str()))
            || self.wildcards.iter().any(|w| glob_match(w, d))
            || self.regexes.iter().any(|r| r.is_match(d))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ParseStats {
    pub loaded: usize,
    pub ignored: usize,
}

impl RuleSet {
    pub fn len(&self) -> usize {
        match self {
            RuleSet::Domain(d) => d.len(),
            RuleSet::IpCidr(i) => i.len(),
            RuleSet::Classical(c) => {
                c.domains.len()
                    + c.keywords.len()
                    + c.wildcards.len()
                    + c.regexes.len()
                    + c.ips.len()
                    + c.geoip.len()
                    + c.asns.len()
                    + c.ports.len()
                    + c.networks.len()
                    + c.others.len()
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 连接是否命中。`asn` 是 ASN 数据库，只有含 `IP-ASN` 的规则集会查询。
    pub fn matches_flow(&self, ctx: &FlowContext, geo: &GeoIp, asn: &GeoIp) -> bool {
        self.matches_at(ctx, ctx.destination, geo, asn, true)
    }

    /// 以 `dst` 作为匹配地址（`src` 规则传入源地址），域名与网络类型仍取自 `ctx`。
    /// `use_ip` 为假时（Fake-IP 且 `no-resolve`）目的地址不是真实 IP，只匹配域名、端口等非 IP 条目。
    pub(crate) fn matches_at(
        &self,
        ctx: &FlowContext,
        dst: SocketAddr,
        geo: &GeoIp,
        asn: &GeoIp,
        use_ip: bool,
    ) -> bool {
        let ip = dst.ip();
        match self {
            RuleSet::Domain(d) => ctx.domain.as_deref().is_some_and(|x| d.contains(x)),
            RuleSet::IpCidr(s) => use_ip && s.contains(ip),
            RuleSet::Classical(c) => {
                ctx.domain.as_deref().is_some_and(|d| c.matches_domain(d))
                    || use_ip && c.ips.contains(ip)
                    || use_ip && geo.matches_any(c.geoip.iter().map(String::as_str), ip)
                    || (use_ip
                        && !c.asns.is_empty()
                        && asn
                            .asn(ip)
                            .is_some_and(|n| c.asns.binary_search(&n).is_ok()))
                    || c.ports.iter().any(|p| p.contains(dst.port()))
                    || c.networks.iter().any(|n| {
                        matches!(
                            (n, ctx.network),
                            (NetworkKind::Tcp, Network::Tcp) | (NetworkKind::Udp, Network::Udp)
                        )
                    })
                    || (!c.others.is_empty() && {
                        let env = Env {
                            geoip: geo,
                            asn,
                            rule_sets: None,
                        };
                        // 规则集内的 no-resolve 由引用它的 RULE-SET 决定。
                        c.others
                            .iter()
                            .any(|m| m.eval(&env, ctx, dst, !use_ip, !use_ip))
                    })
            }
        }
    }

    /// 是否包含取决于首包的规则（`PROTOCOL,HTTP`、`USER-AGENT` 等）。
    pub(crate) fn needs_payload(&self) -> bool {
        matches!(self, RuleSet::Classical(c) if c.others.iter().any(|m| m.needs_payload(None)))
    }

    /// Fake-IP Flow 匹配本集合前是否需要真实目的 IP：纯域名集合（常见的广告 / 分流清单）不需要。
    pub(crate) fn needs_ip(&self) -> bool {
        match self {
            RuleSet::Domain(_) => false,
            RuleSet::IpCidr(_) => true,
            RuleSet::Classical(c) => {
                !c.ips.is_empty()
                    || !c.geoip.is_empty()
                    || !c.asns.is_empty()
                    || c.others.iter().any(|m| m.needs_ip(false))
            }
        }
    }

    /// 是否包含需要 GEOIP / ASN 数据库的规则（`GEOIP,LAN` 除外）。
    pub fn uses_geoip(&self) -> bool {
        matches!(self, RuleSet::Classical(c) if !c.asns.is_empty()
            || c.geoip.iter().any(|g| g != "LAN")
            || c.others.iter().any(Matcher::uses_geo_db))
    }

    /// 只按域名判断（DNS 转发规则使用）。`ipcidr` 规则集总是不命中。
    pub fn matches_domain(&self, domain: &str) -> bool {
        match self {
            RuleSet::Domain(d) => d.contains(domain),
            RuleSet::IpCidr(_) => false,
            RuleSet::Classical(c) => c.matches_domain(domain),
        }
    }

    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match self {
            RuleSet::IpCidr(s) => s.contains(ip),
            RuleSet::Classical(c) => c.ips.contains(ip),
            RuleSet::Domain(_) => false,
        }
    }
}

/// 解析规则集内容。
pub fn parse_rule_set(
    content: &str,
    behavior: Behavior,
    format: ProviderFormat,
    style: DomainStyle,
) -> (RuleSet, ParseStats) {
    let lines = match format {
        ProviderFormat::Text => text_lines(content),
        ProviderFormat::Yaml => yaml_payload(content),
    };
    build(lines.iter().map(String::as_str), behavior, style)
}

/// 由 `inline` 规则集的 payload 构建。
pub fn build_inline(payload: &[String], behavior: Behavior) -> (RuleSet, ParseStats) {
    build(
        payload.iter().map(String::as_str),
        behavior,
        DomainStyle::Mihomo,
    )
}

fn build<'a>(
    lines: impl Iterator<Item = &'a str>,
    behavior: Behavior,
    style: DomainStyle,
) -> (RuleSet, ParseStats) {
    let mut stats = ParseStats::default();
    match behavior {
        Behavior::Domain => {
            let mut b = DomainSetBuilder::default();
            for l in lines {
                let p = match style {
                    DomainStyle::Mihomo => DomainPattern::parse(l),
                    DomainStyle::Surge => DomainPattern::parse_surge(l),
                };
                match p {
                    Some(p) => {
                        b.add(p);
                        stats.loaded += 1;
                    }
                    None => stats.ignored += 1,
                }
            }
            (RuleSet::Domain(b.build()), stats)
        }
        Behavior::IpCidr => {
            let mut cidrs = Vec::new();
            for l in lines {
                match IpCidr::parse(l.split(',').next().unwrap_or("").trim()) {
                    Some(c) => {
                        cidrs.push(c);
                        stats.loaded += 1;
                    }
                    None => stats.ignored += 1,
                }
            }
            (RuleSet::IpCidr(IpSet::build(&cidrs)), stats)
        }
        Behavior::Classical => {
            let mut domains = DomainSetBuilder::default();
            let mut cidrs = Vec::new();
            let mut c = ClassicalSet::default();
            for l in lines {
                match parse_rule_item(l) {
                    Ok(Some((kind, _))) => {
                        stats.loaded += 1;
                        match kind {
                            RuleKind::Domain(d) => domains.add(DomainPattern::Exact(d)),
                            RuleKind::DomainSuffix(d) => domains.add(DomainPattern::Suffix(d)),
                            RuleKind::DomainKeyword(k) => c.keywords.push(k),
                            RuleKind::DomainWildcard(w) => c.wildcards.push(w),
                            RuleKind::DomainRegex(r) => match compile_regex(&r) {
                                Ok(r) => c.regexes.push(r),
                                Err(_) => stats.ignored += 1,
                            },
                            RuleKind::IpCidr(cidr) => cidrs.push(cidr),
                            RuleKind::GeoIp(code) => c.geoip.push(code),
                            RuleKind::IpAsn(n) => c.asns.push(n),
                            RuleKind::DstPort(p) => c.ports.extend(p),
                            RuleKind::Network(n) => c.networks.push(n),
                            RuleKind::Logic(..)
                            | RuleKind::Src(_)
                            | RuleKind::Protocol(_)
                            | RuleKind::UserAgent(_)
                            | RuleKind::UrlRegex(_)
                            | RuleKind::ProcessName(_) => c.others.push(Matcher::compile(&kind)),
                            RuleKind::RuleSet(_) | RuleKind::Final => stats.ignored += 1,
                        }
                    }
                    _ => stats.ignored += 1,
                }
            }
            c.domains = domains.build();
            c.ips = IpSet::build(&cidrs);
            c.asns.sort_unstable();
            c.asns.dedup();
            (RuleSet::Classical(Box::new(c)), stats)
        }
    }
}

fn is_comment(l: &str) -> bool {
    l.is_empty() || l.starts_with('#') || l.starts_with("//") || l.starts_with(';')
}

fn text_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !is_comment(l))
        .map(str::to_string)
        .collect()
}

/// 读取 YAML 的 `payload` 列表。常见的简单写法（`payload:` 后逐行 `- 项`）直接按行解析，
/// 避免为大文件构建完整的 YAML 树；其它写法交给 YAML 解析器。
fn yaml_payload(content: &str) -> Vec<String> {
    if let Some(v) = simple_payload(content) {
        return v;
    }
    let Ok(docs) = yaml_rust2::YamlLoader::load_from_str(content) else {
        return Vec::new();
    };
    let Some(doc) = docs.first() else {
        return Vec::new();
    };
    match &doc["payload"] {
        yaml_rust2::Yaml::Array(a) => a
            .iter()
            .filter_map(|y| match y {
                yaml_rust2::Yaml::String(s) | yaml_rust2::Yaml::Real(s) => {
                    Some(s.trim().to_string())
                }
                yaml_rust2::Yaml::Integer(i) => Some(i.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn simple_payload(content: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut in_payload = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !in_payload {
            if line == "payload:" {
                in_payload = true;
                continue;
            }
            return None;
        }
        let item = line.strip_prefix('-')?.trim();
        // 行尾注释（引号外的 ` #`）
        let item = match (item.starts_with(['\'', '"']), item.find(" #")) {
            (false, Some(i)) => item[..i].trim(),
            _ => item,
        };
        let item = if item.len() >= 2
            && ((item.starts_with('\'') && item.ends_with('\''))
                || (item.starts_with('"') && item.ends_with('"')))
        {
            &item[1..item.len() - 1]
        } else if item.starts_with(['\'', '"', '[', '{', '&', '*', '!', '|', '>']) {
            return None;
        } else {
            item
        };
        if !item.is_empty() {
            out.push(item.to_string());
        }
    }
    in_payload.then_some(out)
}

#[derive(Debug, Clone, Default)]
pub struct SlotInfo {
    pub count: usize,
    pub updated: Option<SystemTime>,
    pub error: Option<String>,
}

/// 一个规则集的运行时槽位：内容可在后台更新后原子替换。
#[derive(Debug)]
pub struct RuleSetSlot {
    pub name: String,
    pub behavior: Behavior,
    data: RwLock<Option<Arc<RuleSet>>>,
    info: Mutex<SlotInfo>,
}

impl RuleSetSlot {
    pub fn get(&self) -> Option<Arc<RuleSet>> {
        self.data.read().unwrap().clone()
    }

    pub fn set(&self, set: RuleSet, updated: SystemTime) {
        let count = set.len();
        *self.data.write().unwrap() = Some(Arc::new(set));
        let mut info = self.info.lock().unwrap();
        info.count = count;
        info.updated = Some(updated);
        info.error = None;
    }

    pub fn set_error(&self, error: String) {
        self.info.lock().unwrap().error = Some(error);
    }

    pub fn info(&self) -> SlotInfo {
        self.info.lock().unwrap().clone()
    }
}

/// 全部规则集，下标与 `RuntimeConfig::providers` 一致。
#[derive(Debug, Default)]
pub struct RuleSetStore {
    slots: Vec<Arc<RuleSetSlot>>,
}

impl RuleSetStore {
    pub fn new(providers: &[ProviderSpec]) -> RuleSetStore {
        RuleSetStore {
            slots: providers
                .iter()
                .map(|p| {
                    Arc::new(RuleSetSlot {
                        name: p.name.clone(),
                        behavior: p.behavior,
                        data: RwLock::new(None),
                        info: Mutex::new(SlotInfo::default()),
                    })
                })
                .collect(),
        }
    }

    pub fn slot(&self, i: usize) -> Option<&Arc<RuleSetSlot>> {
        self.slots.get(i)
    }

    pub fn slots(&self) -> &[Arc<RuleSetSlot>] {
        &self.slots
    }

    pub fn matches_domain(&self, i: usize, domain: &str) -> bool {
        self.slot(i)
            .and_then(|s| s.get())
            .is_some_and(|s| s.matches_domain(&normalize_domain(domain)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classical_logic_and_src() {
        let (set, stats) = build_inline(
            &[
                "AND,((NETWORK,UDP),(DST-PORT,443))".to_string(),
                "SRC-IP-CIDR,10.9.0.0/16".to_string(),
                "IP-CIDR,8.8.8.0/24,src".to_string(),
                "DOMAIN-SUFFIX,x.com,DIRECT".to_string(),
                "AND,((DOMAIN,a),(PROCESS-NAME,b))".to_string(),
            ],
            Behavior::Classical,
        );
        assert_eq!((stats.loaded, stats.ignored), (4, 1));
        let geo = GeoIp::default();
        assert!(set.matches_flow(&flow("1.1.1.1:443", None, Network::Udp), &geo, &geo));
        assert!(!set.matches_flow(&flow("1.1.1.1:443", None, Network::Tcp), &geo, &geo));
        assert!(set.matches_flow(
            &flow("1.1.1.1:443", Some("a.x.com"), Network::Tcp),
            &geo,
            &geo
        ));
        // 源地址是 10.0.0.2，目的地址落在 src 段内也不命中
        assert!(!set.matches_flow(&flow("10.9.1.1:443", None, Network::Tcp), &geo, &geo));
        let mut c = flow("1.1.1.1:443", None, Network::Tcp);
        c.source = "10.9.3.3:5000".parse().unwrap();
        assert!(set.matches_flow(&c, &geo, &geo));
        c.source = "8.8.8.8:5000".parse().unwrap();
        assert!(set.matches_flow(&c, &geo, &geo));
    }

    fn flow(dst: &str, domain: Option<&str>, network: Network) -> FlowContext {
        let mut c = FlowContext::new(
            1,
            network,
            "10.0.0.2:5000".parse().unwrap(),
            dst.parse().unwrap(),
        );
        if let Some(d) = domain {
            c.set_domain(d.into(), crate::DomainSource::DnsMapping);
        }
        c
    }

    #[test]
    fn domain_text_and_yaml() {
        let text = "# comment\n+.google.com\n\n.sub.example\nexact.example\n*.one.example\n+.\n";
        let (set, stats) = parse_rule_set(
            text,
            Behavior::Domain,
            ProviderFormat::Text,
            DomainStyle::Mihomo,
        );
        assert_eq!(
            stats,
            ParseStats {
                loaded: 4,
                ignored: 1
            }
        );
        for d in [
            "google.com",
            "mail.google.com",
            "a.sub.example",
            "exact.example",
            "x.one.example",
        ] {
            assert!(set.matches_domain(d), "{d}");
        }
        assert!(!set.matches_domain("sub.example") && !set.matches_domain("a.exact.example"));

        let yaml =
            "payload:\n  - '+.google.com'\n  - \"exact.example\" \n  - plain.example # 注释\n";
        let (set, stats) = parse_rule_set(
            yaml,
            Behavior::Domain,
            ProviderFormat::Yaml,
            DomainStyle::Mihomo,
        );
        assert_eq!(stats.loaded, 3);
        assert!(set.matches_domain("a.google.com") && set.matches_domain("plain.example"));

        // 复杂 YAML 回退到完整解析器
        let yaml = "payload: ['+.flow.example', exact.example]\n";
        let (set, _) = parse_rule_set(
            yaml,
            Behavior::Domain,
            ProviderFormat::Yaml,
            DomainStyle::Mihomo,
        );
        assert!(set.matches_domain("a.flow.example"));
    }

    #[test]
    fn surge_domain_set() {
        let (set, _) = parse_rule_set(
            ".apple.com\nicloud.com\n",
            Behavior::Domain,
            ProviderFormat::Text,
            DomainStyle::Surge,
        );
        assert!(set.matches_domain("apple.com") && set.matches_domain("www.apple.com"));
        assert!(set.matches_domain("icloud.com") && !set.matches_domain("www.icloud.com"));
    }

    #[test]
    fn ipcidr_and_classical() {
        let (set, stats) = parse_rule_set(
            "10.0.0.0/8\n2001:db8::/32\nbad\n",
            Behavior::IpCidr,
            ProviderFormat::Text,
            DomainStyle::Mihomo,
        );
        assert_eq!(
            stats,
            ParseStats {
                loaded: 2,
                ignored: 1
            }
        );
        assert!(
            set.matches_ip("10.1.1.1".parse().unwrap())
                && !set.matches_ip("11.0.0.1".parse().unwrap())
        );
        assert!(!set.matches_domain("a.com"));

        let text = "DOMAIN-SUFFIX,google.com\nDOMAIN,exact.example\nDOMAIN-KEYWORD,youtube\nDOMAIN-WILDCARD,*.w.example\n\
                    DOMAIN-REGEX,^ad\\d+\\.\nIP-CIDR,17.0.0.0/8,no-resolve\nDST-PORT,5222\nNETWORK,udp\nGEOIP,LAN\nPROCESS-NAME,x\nUSER-AGENT,y*\nSCRIPT,z\n";
        let (set, stats) = parse_rule_set(
            text,
            Behavior::Classical,
            ProviderFormat::Text,
            DomainStyle::Mihomo,
        );
        assert_eq!(
            stats,
            ParseStats {
                loaded: 10,
                ignored: 2
            }
        );
        assert!(set.needs_payload());
        let geo = GeoIp::default();
        assert!(set.matches_flow(
            &flow("1.1.1.1:443", Some("www.google.com"), Network::Tcp),
            &geo,
            &geo
        ));
        assert!(set.matches_flow(
            &flow("1.1.1.1:443", Some("m.youtube.com"), Network::Tcp),
            &geo,
            &geo
        ));
        assert!(set.matches_flow(
            &flow("1.1.1.1:443", Some("a.b.w.example"), Network::Tcp),
            &geo,
            &geo
        ));
        assert!(set.matches_flow(
            &flow("1.1.1.1:443", Some("ad12.example"), Network::Tcp),
            &geo,
            &geo
        ));
        assert!(set.matches_flow(&flow("17.1.2.3:443", None, Network::Tcp), &geo, &geo));
        assert!(set.matches_flow(&flow("1.1.1.1:5222", None, Network::Tcp), &geo, &geo));
        assert!(set.matches_flow(&flow("1.1.1.1:443", None, Network::Udp), &geo, &geo));
        assert!(set.matches_flow(&flow("192.168.1.1:443", None, Network::Tcp), &geo, &geo));
        assert!(!set.matches_flow(
            &flow("1.1.1.1:443", Some("other.example"), Network::Tcp),
            &geo,
            &geo
        ));
        assert!(set.matches_domain("exact.example") && !set.matches_domain("x.exact.example"));
    }

    #[test]
    fn ip_asn() {
        struct Asn;
        impl crate::GeoLookup for Asn {
            fn country(&self, _: IpAddr) -> Option<String> {
                None
            }
            fn asn(&self, ip: IpAddr) -> Option<u32> {
                (ip == "114.114.114.114".parse::<IpAddr>().unwrap()).then_some(4134)
            }
        }
        // 与 GetSomeFries 的 ASN.China.yaml 相同的写法：注释掉的条目夹在 payload 中间。
        let text =
            "payload:\n  - IP-ASN,4837\n#   - IP-ASN,7720\n  - IP-ASN,4134\n  - IP-ASN,AS4134\n";
        let (set, stats) = parse_rule_set(
            text,
            Behavior::Classical,
            ProviderFormat::Yaml,
            DomainStyle::Mihomo,
        );
        assert_eq!(
            stats,
            ParseStats {
                loaded: 3,
                ignored: 0
            }
        );
        assert!(set.uses_geoip());
        let geo = GeoIp::default();
        let asn = GeoIp::default();
        let cn = flow("114.114.114.114:53", None, Network::Udp);
        assert!(!set.matches_flow(&cn, &geo, &asn));
        asn.set(Some(Arc::new(Asn)));
        assert!(set.matches_flow(&cn, &geo, &asn));
        assert!(!set.matches_flow(&flow("1.1.1.1:53", None, Network::Udp), &geo, &asn));
    }

    #[test]
    fn store() {
        let providers = oryn_config::parse_config(
            "rule-providers:\n  a: {type: inline, behavior: domain, payload: ['+.a.com']}\n",
        )
        .unwrap()
        .providers;
        let store = RuleSetStore::new(&providers);
        assert!(!store.matches_domain(0, "a.com"), "未加载时不命中");
        let (set, _) = build_inline(&["+.a.com".to_string()], Behavior::Domain);
        store.slot(0).unwrap().set(set, SystemTime::now());
        assert!(store.matches_domain(0, "X.A.COM."));
        assert_eq!(store.slot(0).unwrap().info().count, 1);
    }
}
