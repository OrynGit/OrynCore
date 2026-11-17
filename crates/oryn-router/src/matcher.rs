//! 编译后的单条规则：主规则与 `classical` 规则集里的逻辑 / 源地址规则共用。

use std::net::SocketAddr;

use oryn_config::{
    compile_regex, glob_match, suffix_match, CompactRegex, IpCidr, LogicOp, NetworkKind, PortRange,
    ProtocolKind, RuleKind,
};

use crate::geoip::GeoIp;
use crate::ruleset::RuleSetStore;
use crate::{FlowContext, Network};

/// 匹配时用到的数据库与规则集；`classical` 规则集内没有规则集可引用。
pub(crate) struct Env<'a> {
    pub geoip: &'a GeoIp,
    pub asn: &'a GeoIp,
    pub rule_sets: Option<&'a RuleSetStore>,
}

#[derive(Debug)]
pub(crate) enum Matcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainWildcard(String),
    DomainRegex(Option<CompactRegex>),
    IpCidr(IpCidr),
    GeoIp(String),
    IpAsn(u32),
    DstPort(Vec<PortRange>),
    Network(NetworkKind),
    Protocol(ProtocolKind),
    UserAgent(String),
    UrlRegex(Option<CompactRegex>),
    RuleSet(usize),
    Logic(LogicOp, Vec<(Matcher, bool)>),
    Src(Box<Matcher>),
    ProcessName(String),
    Final,
}

impl Matcher {
    pub fn compile(kind: &RuleKind) -> Matcher {
        match kind {
            RuleKind::Domain(d) => Matcher::Domain(d.clone()),
            RuleKind::DomainSuffix(d) => Matcher::DomainSuffix(d.clone()),
            RuleKind::DomainKeyword(k) => Matcher::DomainKeyword(k.clone()),
            RuleKind::DomainWildcard(w) => Matcher::DomainWildcard(w.clone()),
            RuleKind::DomainRegex(r) => {
                Matcher::DomainRegex(compile_regex(r).ok())
            }
            RuleKind::IpCidr(c) => Matcher::IpCidr(*c),
            RuleKind::GeoIp(c) => Matcher::GeoIp(c.clone()),
            RuleKind::IpAsn(n) => Matcher::IpAsn(*n),
            RuleKind::DstPort(p) => Matcher::DstPort(p.clone()),
            RuleKind::Network(n) => Matcher::Network(*n),
            RuleKind::Protocol(p) => Matcher::Protocol(*p),
            RuleKind::UserAgent(u) => Matcher::UserAgent(u.clone()),
            RuleKind::UrlRegex(r) => {
                Matcher::UrlRegex(compile_regex(r).ok())
            }
            RuleKind::RuleSet(i) => Matcher::RuleSet(*i),
            RuleKind::Logic(op, subs) => Matcher::Logic(
                *op,
                subs.iter()
                    .map(|s| (Matcher::compile(&s.kind), s.no_resolve))
                    .collect(),
            ),
            RuleKind::Src(k) => Matcher::Src(Box::new(Matcher::compile(k))),
            RuleKind::ProcessName(name) => Matcher::ProcessName(name.clone()),
            RuleKind::Final => Matcher::Final,
        }
    }

    /// 按目的 IP 匹配的规则（Fake-IP 下 `no-resolve` 时直接不命中）。
    pub fn is_ip(&self) -> bool {
        matches!(
            self,
            Matcher::IpCidr(_) | Matcher::GeoIp(_) | Matcher::IpAsn(_) | Matcher::RuleSet(_)
        )
    }

    /// Fake-IP Flow 匹配本条前是否需要真实解析目的地址。源地址规则不需要。
    pub fn needs_ip(&self, no_resolve: bool) -> bool {
        match self {
            Matcher::Logic(_, subs) => subs.iter().any(|(m, nr)| m.needs_ip(*nr)),
            m => m.is_ip() && !no_resolve,
        }
    }

    /// `dst` 是参与匹配的地址：通常是目的地址，`Src` 内为源地址。
    /// `fake` 为 Fake-IP Flow 且 `dst` 是目的地址时为真，此时带 `no-resolve` 的 IP 类规则不命中。
    pub fn eval(
        &self,
        env: &Env,
        ctx: &FlowContext,
        dst: SocketAddr,
        no_resolve: bool,
        fake: bool,
    ) -> bool {
        // 规则集可能同时含域名与 IP 条目：no-resolve 只关掉其中的 IP 部分，见下面的 RuleSet 分支。
        if fake && no_resolve && self.is_ip() && !matches!(self, Matcher::RuleSet(_)) {
            return false;
        }
        let domain = ctx.domain.as_deref();
        match self {
            Matcher::Domain(d) => domain == Some(d.as_str()),
            Matcher::DomainSuffix(s) => domain.is_some_and(|d| suffix_match(d, s)),
            Matcher::DomainKeyword(k) => domain.is_some_and(|d| d.contains(k.as_str())),
            Matcher::DomainWildcard(w) => domain.is_some_and(|d| glob_match(w, d)),
            Matcher::DomainRegex(r) => {
                domain.is_some_and(|d| r.as_ref().is_some_and(|r| r.is_match(d)))
            }
            // 未指定地址（0.0.0.0 / ::）表示「还不知道 IP」（DNS 查询、脚本请求等按域名构造的
            // 上下文），IP 类规则不应据此命中。
            Matcher::IpCidr(c) => !dst.ip().is_unspecified() && c.contains(dst.ip()),
            Matcher::GeoIp(code) => !dst.ip().is_unspecified() && env.geoip.matches(code, dst.ip()),
            Matcher::IpAsn(n) => !dst.ip().is_unspecified() && env.asn.asn(dst.ip()) == Some(*n),
            Matcher::DstPort(ports) => ports.iter().any(|p| p.contains(dst.port())),
            Matcher::Network(n) => matches!(
                (n, ctx.network),
                (NetworkKind::Tcp, Network::Tcp) | (NetworkKind::Udp, Network::Udp)
            ),
            Matcher::Protocol(p) => match p {
                ProtocolKind::Tcp => ctx.network == Network::Tcp,
                ProtocolKind::Udp => ctx.network == Network::Udp,
                ProtocolKind::Http => ctx.network == Network::Tcp && ctx.http.is_some(),
                ProtocolKind::Https => ctx.network == Network::Tcp && ctx.is_tls,
                ProtocolKind::Quic => ctx.network == Network::Udp && ctx.is_quic,
            },
            Matcher::UserAgent(p) => ctx
                .http
                .as_ref()
                .and_then(|h| h.user_agent.as_deref())
                .is_some_and(|ua| glob_match(p, ua)),
            Matcher::UrlRegex(r) => ctx
                .http
                .as_ref()
                .is_some_and(|h| r.as_ref().is_some_and(|r| r.is_match(&h.url))),
            Matcher::ProcessName(name) => ctx.package.as_deref() == Some(name.as_str()),
            Matcher::RuleSet(i) => env
                .rule_sets
                .and_then(|s| s.slot(*i))
                .and_then(|s| s.get())
                .is_some_and(|set| {
                    set.matches_at(ctx, dst, env.geoip, env.asn, !(fake && no_resolve))
                }),
            Matcher::Logic(op, subs) => {
                let mut each = subs.iter().map(|(m, nr)| m.eval(env, ctx, dst, *nr, fake));
                match op {
                    LogicOp::And => each.all(|x| x),
                    LogicOp::Or => each.any(|x| x),
                    LogicOp::Not => !each.next().unwrap_or(false),
                }
            }
            Matcher::Src(m) => m.eval(env, ctx, ctx.source, false, false),
            Matcher::Final => true,
        }
    }

    /// 匹配结果是否取决于首包（TLS / HTTP 请求 / QUIC）。规则集看其中的规则。
    pub fn needs_payload(&self, rule_sets: Option<&RuleSetStore>) -> bool {
        match self {
            Matcher::Protocol(p) => {
                matches!(
                    p,
                    ProtocolKind::Http | ProtocolKind::Https | ProtocolKind::Quic
                )
            }
            Matcher::UserAgent(_) | Matcher::UrlRegex(_) => true,
            Matcher::Logic(_, subs) => subs.iter().any(|(m, _)| m.needs_payload(rule_sets)),
            Matcher::RuleSet(i) => rule_sets
                .and_then(|s| s.slot(*i))
                .and_then(|s| s.get())
                .is_some_and(|set| set.needs_payload()),
            _ => false,
        }
    }

    /// 是否需要 GEOIP / ASN 数据库（`GEOIP,LAN` 除外）。
    pub fn uses_geo_db(&self) -> bool {
        match self {
            Matcher::GeoIp(c) => c != "LAN",
            Matcher::IpAsn(_) => true,
            Matcher::Logic(_, subs) => subs.iter().any(|(m, _)| m.uses_geo_db()),
            Matcher::Src(m) => m.uses_geo_db(),
            _ => false,
        }
    }
}
