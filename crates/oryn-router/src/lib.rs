//! Flow 上下文与规则引擎。
//!
//! 一个 Flow 只调用一次 [`Router::route`]，结果存为 [`RouteDecision`]，后续数据不再匹配。

pub mod geoip;
mod matcher;
pub mod ruleset;
pub mod sets;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use oryn_config::{glob_match, suffix_match, Mode, Policy, RuntimeConfig};

use matcher::{Env, Matcher};

pub use geoip::{is_lan, GeoIp, GeoLookup, Mmdb};
pub use ruleset::{
    build_inline, parse_rule_set, ParseStats, RuleSet, RuleSetSlot, RuleSetStore, SlotInfo,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        }
    }
}

/// 域名的来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainSource {
    None,
    /// DNS 解析结果的反查。
    DnsMapping,
    /// 从首包中嗅探。
    Sniffed,
    /// Fake-IP 地址池的权威映射。
    FakeIp,
    /// DNS 查询本身携带的域名。
    DnsQuery,
    /// 由本地 HTTP / SOCKS 入站明确携带的域名。
    Explicit,
}

impl DomainSource {
    pub fn as_str(self) -> &'static str {
        match self {
            DomainSource::None => "none",
            DomainSource::DnsMapping => "dns",
            DomainSource::Sniffed => "sniffed",
            DomainSource::FakeIp => "fake-ip",
            DomainSource::DnsQuery => "query",
            DomainSource::Explicit => "explicit",
        }
    }
}

/// 路由前从首包读到的明文 HTTP 请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestInfo {
    /// `http://主机[:端口]/路径`。
    pub url: String,
    pub user_agent: Option<String>,
}

/// 一个 TCP 连接、UDP 会话或 DNS 查询的上下文。
#[derive(Debug, Clone)]
pub struct FlowContext {
    pub is_quic: bool,
    /// TCP 首包是 TLS 记录（`PROTOCOL,HTTPS`）。
    pub is_tls: bool,
    /// 明文 HTTP 的第一个请求（`URL-REGEX` / `USER-AGENT` / `PROTOCOL,HTTP`）。
    pub http: Option<HttpRequestInfo>,
    pub id: u64,
    pub network: Network,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    /// 小写、无末尾点。
    pub domain: Option<String>,
    pub domain_source: DomainSource,
    /// Android 应用包名。其它平台保持为空，`PROCESS-NAME` 规则因此不会命中。
    pub package: Option<String>,
    pub started_at: SystemTime,
    pub route: Option<RouteDecision>,
}

impl FlowContext {
    pub fn new(id: u64, network: Network, source: SocketAddr, destination: SocketAddr) -> Self {
        FlowContext {
            is_quic: false,
            is_tls: false,
            http: None,
            id,
            network,
            source,
            destination,
            domain: None,
            domain_source: DomainSource::None,
            package: None,
            started_at: SystemTime::now(),
            route: None,
        }
    }

    pub fn set_domain(&mut self, domain: String, source: DomainSource) {
        self.domain = Some(oryn_config::normalize_domain(&domain));
        self.domain_source = source;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteDecision {
    /// `RuntimeConfig::outbounds` 的下标。
    pub outbound: usize,
    /// 命中的规则下标；Global / Direct 模式下为 `None`。
    pub rule: Option<usize>,
}

struct CompiledRule {
    matcher: Matcher,
    policy: Policy,
    no_resolve: bool,
    text: String,
}

pub struct Router {
    outbound_count: usize,
    mitm: oryn_config::MitmSpec,
    reject: usize,
    rules: Vec<CompiledRule>,
    /// 是否有规则要看首包（`PROTOCOL,HTTP` 等）。
    payload_rules: bool,
    mode: AtomicU8,
    ipv6_support: AtomicBool,
    direct: usize,
    global: usize,
    rule_sets: Arc<RuleSetStore>,
    geoip: Arc<GeoIp>,
    asn: Arc<GeoIp>,
}

fn mode_code(m: Mode) -> u8 {
    match m {
        Mode::Rule => 0,
        Mode::Global => 1,
        Mode::Direct => 2,
    }
}

impl Router {
    pub fn new(config: &RuntimeConfig, rule_sets: Arc<RuleSetStore>, geoip: Arc<GeoIp>) -> Self {
        let rules = config
            .rules
            .iter()
            .map(|r| CompiledRule {
                matcher: Matcher::compile(&r.kind),
                policy: r.policy,
                no_resolve: r.no_resolve,
                text: r.text.clone(),
            })
            .collect::<Vec<CompiledRule>>();
        let payload_rules = rules
            .iter()
            .any(|r| r.matcher.needs_payload(Some(&rule_sets)));
        Router {
            outbound_count: config.outbounds.len(),
            payload_rules,
            mitm: config.mitm.clone(),
            reject: config
                .outbound_index("REJECT")
                .unwrap_or(config.direct_index()),
            rules,
            mode: AtomicU8::new(mode_code(config.mode)),
            ipv6_support: AtomicBool::new(true),
            direct: config.direct_index(),
            global: config.global_index(),
            rule_sets,
            geoip,
            asn: Arc::new(GeoIp::default()),
        }
    }

    /// `IP-ASN` 规则使用的 ASN 数据库；未设置时这些规则不命中。
    pub fn with_asn(mut self, asn: Arc<GeoIp>) -> Self {
        self.asn = asn;
        self
    }

    pub fn mode(&self) -> Mode {
        match self.mode.load(Ordering::Relaxed) {
            1 => Mode::Global,
            2 => Mode::Direct,
            _ => Mode::Rule,
        }
    }

    pub fn set_mode(&self, mode: Mode) {
        self.mode.store(mode_code(mode), Ordering::Relaxed);
    }

    pub fn set_ipv6_support(&self, enabled: bool) {
        self.ipv6_support.store(enabled, Ordering::Relaxed);
    }

    fn blocks_ipv6(&self, ctx: &FlowContext) -> bool {
        // DNS 服务器连接独立于应用目标开关；IPv4-mapped 地址仍视为 IPv4。
        !self.ipv6_support.load(Ordering::Relaxed)
            && ctx.domain_source != DomainSource::DnsQuery
            && matches!(ctx.destination.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none())
    }

    pub fn rule_sets(&self) -> &Arc<RuleSetStore> {
        &self.rule_sets
    }

    pub fn geoip(&self) -> &Arc<GeoIp> {
        &self.geoip
    }

    /// 用户主动发起的诊断 Flow 使用显式出站，不改变普通流量的规则或运行模式。
    /// 同一个 Flow 已有决定时保持不变；调用者须使用当前配置的下标。
    pub fn route_explicit(&self, ctx: &mut FlowContext, outbound: usize) -> Option<RouteDecision> {
        if outbound >= self.outbound_count {
            return None;
        }
        let outbound = if self.blocks_ipv6(ctx) {
            self.reject
        } else {
            outbound
        };
        Some(*ctx.route.get_or_insert(RouteDecision {
            outbound,
            rule: None,
        }))
    }

    /// first-match；`PASS` 继续匹配下一条。编译阶段保证最后一条是 FINAL。
    pub fn route(&self, ctx: &FlowContext) -> RouteDecision {
        if self.blocks_ipv6(ctx) {
            return RouteDecision {
                outbound: self.reject,
                rule: None,
            };
        }
        if self.mitm.auto_quic_block
            && ctx.is_quic
            && ctx
                .domain
                .as_deref()
                .is_some_and(|d| self.mitm.matches(d, ctx.destination.port()))
        {
            return RouteDecision {
                outbound: self.reject,
                rule: Some(self.rules.len()),
            };
        }
        match self.mode() {
            Mode::Direct => {
                return RouteDecision {
                    outbound: self.direct,
                    rule: None,
                }
            }
            Mode::Global => {
                return RouteDecision {
                    outbound: self.global,
                    rule: None,
                }
            }
            Mode::Rule => {}
        }
        for (i, rule) in self.rules.iter().enumerate() {
            if self.matches(rule, ctx) {
                match rule.policy {
                    Policy::Pass => continue,
                    Policy::Outbound(o) => {
                        return RouteDecision {
                            outbound: o,
                            rule: Some(i),
                        }
                    }
                }
            }
        }
        RouteDecision {
            outbound: self.direct,
            rule: None,
        }
    }

    pub fn rule_text(&self, rule: Option<usize>) -> String {
        if rule == Some(self.rules.len()) {
            return "MITM,QUIC,REJECT".into();
        }
        match rule {
            Some(i) => self.rules.get(i).map_or(String::new(), |r| r.text.clone()),
            None => match self.mode() {
                Mode::Global => "Global mode".into(),
                Mode::Direct => "Direct mode".into(),
                Mode::Rule => "MATCH,DIRECT".into(),
            },
        }
    }

    /// Fake-IP Flow 在进入 IP / GEOIP / IP 规则集前是否需要一次真实解析。
    /// 域名规则已经决定策略时不解析，避免代理域名泄漏到本地 DNS。
    pub fn needs_ip_resolution(&self, ctx: &FlowContext) -> bool {
        if self.mode() != Mode::Rule {
            return false;
        }
        for rule in &self.rules {
            match &rule.matcher {
                Matcher::Domain(d) if ctx.domain.as_deref() == Some(d) => {
                    if rule.policy != Policy::Pass {
                        return false;
                    }
                }
                Matcher::DomainSuffix(s)
                    if ctx.domain.as_deref().is_some_and(|d| suffix_match(d, s)) =>
                {
                    if rule.policy != Policy::Pass {
                        return false;
                    }
                }
                Matcher::DomainKeyword(k)
                    if ctx.domain.as_deref().is_some_and(|d| d.contains(k)) =>
                {
                    if rule.policy != Policy::Pass {
                        return false;
                    }
                }
                Matcher::DomainWildcard(w)
                    if ctx.domain.as_deref().is_some_and(|d| glob_match(w, d)) =>
                {
                    if rule.policy != Policy::Pass {
                        return false;
                    }
                }
                Matcher::DomainRegex(r)
                    if ctx
                        .domain
                        .as_deref()
                        .is_some_and(|d| r.as_ref().is_some_and(|r| r.is_match(d))) =>
                {
                    if rule.policy != Policy::Pass {
                        return false;
                    }
                }
                Matcher::IpCidr(_) | Matcher::GeoIp(_) | Matcher::IpAsn(_) if !rule.no_resolve => {
                    return true
                }
                // 规则集按内容判断：含 IP 类条目才需要解析；纯域名集合现在就能判断。
                // 尚未加载的集合不命中任何连接，也不需要解析。
                Matcher::RuleSet(i) => {
                    let set = self.rule_sets.slot(*i).and_then(|s| s.get());
                    if !rule.no_resolve && set.as_ref().is_some_and(|s| s.needs_ip()) {
                        return true;
                    }
                    if rule.policy != Policy::Pass && self.matches(rule, ctx) {
                        return false;
                    }
                }
                // 逻辑规则：含需要真实 IP 的子规则就先解析；否则现在就能判断，命中即决定策略。
                Matcher::Logic(..) => {
                    if rule.matcher.needs_ip(rule.no_resolve) {
                        return true;
                    }
                    if rule.policy != Policy::Pass && self.matches(rule, ctx) {
                        return false;
                    }
                }
                Matcher::Final => return false,
                _ => {}
            }
        }
        false
    }

    /// 路由前是否要先读首包（TCP 首批数据 / UDP 首个数据报）填入 `is_tls`、`http`、`is_quic`。
    /// 在第一条需要首包的规则之前已有规则决定策略时不读，避免服务器先说话的协议白等。
    pub fn needs_payload(&self, ctx: &FlowContext) -> bool {
        if !self.payload_rules || self.mode() != Mode::Rule {
            return false;
        }
        for rule in &self.rules {
            if rule.matcher.needs_payload(Some(&self.rule_sets)) {
                return true;
            }
            if rule.policy != Policy::Pass && self.matches(rule, ctx) {
                return false;
            }
        }
        false
    }

    fn matches(&self, rule: &CompiledRule, ctx: &FlowContext) -> bool {
        let env = Env {
            geoip: &self.geoip,
            asn: &self.asn,
            rule_sets: Some(&self.rule_sets),
        };
        let fake = ctx.domain_source == DomainSource::FakeIp;
        rule.matcher
            .eval(&env, ctx, ctx.destination, rule.no_resolve, fake)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryn_config::parse_config;

    struct Fake;
    impl GeoLookup for Fake {
        fn country(&self, ip: std::net::IpAddr) -> Option<String> {
            ip.to_string().starts_with("114.").then(|| "CN".into())
        }
    }

    fn setup() -> (Router, RuntimeConfig) {
        let yaml = r#"
proxies: [{name: P, type: socks5, server: 1.2.3.4, port: 1080}]
rule-providers:
  cn: {type: inline, behavior: domain, payload: ['+.cn-site.example']}
rules:
  - DOMAIN,exact.com,REJECT
  - DOMAIN-SUFFIX,google.com,P
  - DOMAIN-KEYWORD,ads,REJECT
  - DOMAIN-WILDCARD,img?.cdn.*,DIRECT
  - DOMAIN-REGEX,^v\d+\.video\.,P
  - NETWORK,udp,PASS
  - IP-CIDR,91.108.0.0/16,P
  - IP-CIDR6,2001:b28::/32,P
  - GEOIP,CN,DIRECT
  - GEOIP,LAN,DIRECT
  - RULE-SET,cn,DIRECT
  - DST-PORT,22/6000-7000,P
  - MATCH,P
"#;
        let cfg = parse_config(yaml).unwrap();
        let store = Arc::new(RuleSetStore::new(&cfg.providers));
        let (set, _) = build_inline(
            &["+.cn-site.example".to_string()],
            oryn_config::Behavior::Domain,
        );
        store.slot(0).unwrap().set(set, SystemTime::now());
        let geo = Arc::new(GeoIp::default());
        geo.set(Some(Arc::new(Fake)));
        (Router::new(&cfg, store, geo), cfg)
    }

    #[test]
    fn ipv6_support_blocks_targets_in_all_modes_but_not_dns_servers() {
        let (router, cfg) = setup();
        router.set_ipv6_support(false);
        let reject = cfg.outbound_index("REJECT").unwrap();
        for mode in [Mode::Rule, Mode::Global, Mode::Direct] {
            router.set_mode(mode);
            for network in [Network::Tcp, Network::Udp] {
                let mut flow = ctx("[2001:db8::1]:443", None, network);
                assert_eq!(router.route(&flow).outbound, reject);
                assert_eq!(
                    router
                        .route_explicit(&mut flow, cfg.direct_index())
                        .unwrap()
                        .outbound,
                    reject
                );
            }
        }
        router.set_mode(Mode::Direct);
        let mut dns = ctx("[2001:db8::53]:53", None, Network::Udp);
        dns.set_domain("example.com".into(), DomainSource::DnsQuery);
        assert_eq!(router.route(&dns).outbound, cfg.direct_index());
        assert_eq!(
            router
                .route(&ctx("[::ffff:192.0.2.1]:443", None, Network::Tcp))
                .outbound,
            cfg.direct_index()
        );
        let mut existing = ctx("[2001:db8::1]:443", None, Network::Tcp);
        router.set_ipv6_support(true);
        let decision = router.route_explicit(&mut existing, cfg.direct_index());
        router.set_ipv6_support(false);
        assert_eq!(router.route_explicit(&mut existing, reject), decision);
    }

    fn ctx(dst: &str, domain: Option<&str>, network: Network) -> FlowContext {
        let mut c = FlowContext::new(
            1,
            network,
            "10.0.0.2:5000".parse().unwrap(),
            dst.parse().unwrap(),
        );
        if let Some(d) = domain {
            c.set_domain(d.into(), DomainSource::DnsMapping);
        }
        c
    }

    fn tag(r: &Router, cfg: &RuntimeConfig, c: &FlowContext) -> String {
        cfg.outbounds[r.route(c).outbound].name.clone()
    }

    #[test]
    fn logic_and_src_rules() {
        let yaml = r#"
proxies: [{name: P, type: socks5, server: 1.2.3.4, port: 1080}]
rule-providers:
  lan: {type: inline, behavior: ipcidr, payload: ['10.0.0.0/8']}
rules:
  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT
  - NOT,((OR,((DOMAIN-SUFFIX,a.com),(IP-CIDR,9.0.0.0/8)))),DIRECT
  - SRC-PORT,5001,REJECT
  - RULE-SET,lan,P,src
  - MATCH,DIRECT
"#;
        let cfg = parse_config(yaml).unwrap();
        let store = Arc::new(RuleSetStore::new(&cfg.providers));
        let (set, _) = build_inline(&["10.0.0.0/8".to_string()], oryn_config::Behavior::IpCidr);
        store.slot(0).unwrap().set(set, SystemTime::now());
        let r = Router::new(&cfg, store, Arc::new(GeoIp::default()));
        let t = |c: &FlowContext| tag(&r, &cfg, c);
        assert_eq!(t(&ctx("1.1.1.1:443", None, Network::Udp)), "REJECT");
        assert_eq!(t(&ctx("1.1.1.1:80", None, Network::Udp)), "DIRECT");
        // NOT(OR(...))：命中 a.com 或 9/8 时不命中，交给后面的规则；源地址 10.0.0.2 命中 src 规则集
        assert_eq!(t(&ctx("1.1.1.1:443", Some("x.a.com"), Network::Tcp)), "P");
        assert_eq!(t(&ctx("9.9.9.9:443", None, Network::Tcp)), "P");
        let mut c = ctx("9.9.9.9:443", None, Network::Tcp);
        c.source = "172.16.0.1:5001".parse().unwrap();
        assert_eq!(t(&c), "REJECT");
        c.source = "172.16.0.1:5000".parse().unwrap();
        assert_eq!(t(&c), "DIRECT");
    }

    #[test]
    fn logic_with_fake_ip() {
        let yaml = r#"
proxies: [{name: P, type: socks5, server: 1.2.3.4, port: 1080}]
rules:
  - AND,((DOMAIN,a.com),(DST-PORT,443)),P
  - AND,((DOMAIN,b.com),(IP-CIDR,198.18.0.0/16,no-resolve)),REJECT
  - AND,((DOMAIN,c.com),(IP-CIDR,9.0.0.0/8)),REJECT
  - MATCH,DIRECT
"#;
        let cfg = parse_config(yaml).unwrap();
        let store = Arc::new(RuleSetStore::new(&cfg.providers));
        let r = Router::new(&cfg, store, Arc::new(GeoIp::default()));
        let fake = |d: &str| {
            let mut c = ctx("198.18.0.5:443", None, Network::Tcp);
            c.set_domain(d.into(), DomainSource::FakeIp);
            c
        };
        // 只用域名与端口就能决定，不解析
        assert!(!r.needs_ip_resolution(&fake("a.com")));
        assert_eq!(tag(&r, &cfg, &fake("a.com")), "P");
        // no-resolve 的 IP 子规则在 Fake-IP 下不命中，也不触发解析
        assert_eq!(tag(&r, &cfg, &fake("b.com")), "DIRECT");
        // 含需要解析的 IP 子规则
        assert!(r.needs_ip_resolution(&fake("c.com")));
    }

    #[test]
    fn rule_sets_with_fake_ip() {
        let yaml = r#"
proxies: [{name: P, type: socks5, server: 1.2.3.4, port: 1080}]
rule-providers:
  ads: {type: inline, behavior: domain, payload: ['+.ads.test']}
  mixed: {type: inline, behavior: classical, payload: ['DOMAIN-SUFFIX,m.test', 'IP-CIDR,9.0.0.0/8']}
  cn: {type: inline, behavior: ipcidr, payload: ['114.0.0.0/8']}
rules:
  - RULE-SET,ads,REJECT
  - RULE-SET,mixed,P,no-resolve
  - RULE-SET,cn,DIRECT
  - MATCH,P
"#;
        let cfg = parse_config(yaml).unwrap();
        let store = Arc::new(RuleSetStore::new(&cfg.providers));
        for (i, p) in cfg.providers.iter().enumerate() {
            let oryn_config::ProviderSource::Inline { payload } = &p.source else {
                unreachable!()
            };
            let (set, _) = build_inline(payload, p.behavior);
            store.slot(i).unwrap().set(set, SystemTime::now());
        }
        let r = Router::new(&cfg, store, Arc::new(GeoIp::default()));
        let fake = |d: &str| {
            let mut c = ctx("198.18.0.5:443", None, Network::Tcp);
            c.set_domain(d.into(), DomainSource::FakeIp);
            c
        };
        // 纯域名规则集命中即决定，不解析
        assert!(!r.needs_ip_resolution(&fake("x.ads.test")));
        assert_eq!(tag(&r, &cfg, &fake("x.ads.test")), "REJECT");
        // no-resolve 的规则集仍按域名命中，只是不用 Fake-IP 匹配 IP 条目
        assert!(!r.needs_ip_resolution(&fake("a.m.test")));
        assert_eq!(tag(&r, &cfg, &fake("a.m.test")), "P");
        // 后面的 IP 规则集需要真实地址
        assert!(r.needs_ip_resolution(&fake("other.test")));
    }

    #[test]
    fn first_match_semantics() {
        let (r, cfg) = setup();
        let t = |dst: &str, d: Option<&str>| tag(&r, &cfg, &ctx(dst, d, Network::Tcp));
        assert_eq!(t("1.1.1.1:443", Some("exact.com")), "REJECT");
        assert_eq!(t("1.1.1.1:443", Some("sub.exact.com")), "P");
        assert_eq!(t("1.1.1.1:443", Some("WWW.Google.com.")), "P");
        assert_eq!(t("1.1.1.1:443", Some("myads.net")), "REJECT");
        assert_eq!(t("1.1.1.1:443", Some("img1.cdn.example")), "DIRECT");
        assert_eq!(t("1.1.1.1:443", Some("v12.video.example")), "P");
        assert_eq!(t("91.108.4.1:443", None), "P");
        assert_eq!(t("[2001:b28:f23d::a]:443", None), "P");
        assert_eq!(t("114.114.114.114:53", None), "DIRECT");
        assert_eq!(t("192.168.1.1:80", None), "DIRECT");
        assert_eq!(t("8.8.8.8:443", Some("a.cn-site.example")), "DIRECT");
        assert_eq!(t("8.8.8.8:6500", None), "P");
        assert_eq!(t("8.8.8.8:443", None), "P");
        assert_eq!(
            r.rule_text(r.route(&ctx("8.8.8.8:443", None, Network::Tcp)).rule),
            "MATCH,P"
        );
        // PASS：UDP 流量跳过 NETWORK 规则，继续匹配
        assert_eq!(
            tag(&r, &cfg, &ctx("114.1.1.1:443", None, Network::Udp)),
            "DIRECT"
        );
    }

    #[test]
    fn modes() {
        let (r, cfg) = setup();
        let c = ctx("1.1.1.1:443", Some("exact.com"), Network::Tcp);
        r.set_mode(Mode::Global);
        assert_eq!(tag(&r, &cfg, &c), "GLOBAL");
        assert_eq!(r.route(&c).rule, None);
        r.set_mode(Mode::Direct);
        assert_eq!(tag(&r, &cfg, &c), "DIRECT");
        r.set_mode(Mode::Rule);
        assert_eq!(tag(&r, &cfg, &c), "REJECT");
    }

    #[test]
    fn payload_rules_use_first_bytes() {
        let yaml = r#"
proxies: [{name: P, type: socks5, server: 1.2.3.4, port: 1080}]
rules:
  - DOMAIN,early.test,P
  - AND,((URL-REGEX,^http:\/\/119\.29\.29\.90\/d\?),(USER-AGENT,%E5%98%80*)),DIRECT
  - AND,((DOMAIN-SUFFIX,spotify.com),(PROTOCOL,QUIC)),REJECT
  - PROTOCOL,HTTPS,DIRECT
  - MATCH,P
"#;
        let cfg = parse_config(yaml).unwrap();
        let r = Router::new(
            &cfg,
            Arc::new(RuleSetStore::new(&cfg.providers)),
            Arc::new(GeoIp::default()),
        );
        // 前面的域名规则已决定策略：不读首包
        assert!(!r.needs_payload(&ctx("1.1.1.1:443", Some("early.test"), Network::Tcp)));

        let mut c = ctx("119.29.29.90:80", None, Network::Tcp);
        assert!(r.needs_payload(&c));
        assert_eq!(tag(&r, &cfg, &c), "P");
        c.http = Some(HttpRequestInfo {
            url: "http://119.29.29.90/d?dn=a.test".into(),
            user_agent: Some("%E5%98%80%E5%97%92 1.0".into()),
        });
        assert_eq!(tag(&r, &cfg, &c), "DIRECT");

        let mut q = ctx("1.1.1.1:443", Some("audio.spotify.com"), Network::Udp);
        assert_eq!(tag(&r, &cfg, &q), "P");
        q.is_quic = true;
        assert_eq!(tag(&r, &cfg, &q), "REJECT");

        let mut t = ctx("1.1.1.1:443", None, Network::Tcp);
        t.is_tls = true;
        assert_eq!(tag(&r, &cfg, &t), "DIRECT");
    }
}
