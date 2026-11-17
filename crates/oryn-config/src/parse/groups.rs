use std::collections::BTreeMap;

use yaml_rust2::Yaml;

use super::{is_reserved, Builder, PolicyRef};
use crate::model::*;
use crate::yaml::{bool_of, get, int_of, list_of, str_of};
use crate::ConfigError;

struct Pending {
    index: usize,
    name: String,
    members: Vec<String>,
    /// `use`：引用的代理集合。
    providers: Vec<String>,
    include_proxies: bool,
    include_providers: bool,
    filter: Option<regex::Regex>,
    exclude: Option<regex::Regex>,
    /// Oryn 扩展 `flatten`：成员里的策略组之后紧跟它包含的全部节点。
    flatten: bool,
}

/// `config_proxies`：配置里 `proxies` 的节点数（下标 0..config_proxies）；其后是代理集合的节点。
pub(super) fn parse(
    root: &Yaml,
    b: &mut Builder,
    config_proxies: usize,
) -> Result<(), ConfigError> {
    let mut pending = Vec::new();
    let mut ignored_types: BTreeMap<String, usize> = BTreeMap::new();

    if let Some(Yaml::Array(list)) = get(root, "proxy-groups") {
        // 第一遍：登记名称，允许成员前向引用
        for (i, g) in list.iter().enumerate() {
            let name = str_of(g, "name")
                .ok_or_else(|| ConfigError(format!("proxy-groups[{i}] is missing `name`")))?;
            if is_reserved(&name) {
                b.warn(format!(
                    "proxy group `{name}` uses a reserved name and was ignored"
                ));
                continue;
            }
            if b.names.contains_key(&name) || b.ignored.contains(&name) {
                return Err(ConfigError(format!(
                    "duplicate proxy or group name `{name}`"
                )));
            }
            let ty = str_of(g, "type").unwrap_or_default().to_ascii_lowercase();
            let health = HealthSpec {
                url: str_of(g, "url").unwrap_or_else(|| DEFAULT_TEST_URL.to_string()),
                interval_secs: int_of(g, "interval").filter(|v| *v > 0).unwrap_or(300) as u64,
                timeout_ms: int_of(g, "timeout").filter(|v| *v > 0).unwrap_or(5000) as u64,
                lazy: bool_of(g, "lazy").unwrap_or(true),
            };
            let kind = match ty.as_str() {
                "smart" => GroupKind::Smart,
                "select" => GroupKind::Select,
                "url-test" => GroupKind::UrlTest {
                    tolerance_ms: int_of(g, "tolerance").filter(|v| *v >= 0).unwrap_or(50) as u32,
                },
                "fallback" => GroupKind::Fallback,
                "load-balance" => {
                    let strategy = match str_of(g, "strategy")
                        .map(|s| s.to_ascii_lowercase())
                        .as_deref()
                    {
                        None | Some("consistent-hashing") => LbStrategy::ConsistentHashing,
                        Some("round-robin") => LbStrategy::RoundRobin,
                        Some("sticky-sessions") => LbStrategy::StickySessions,
                        Some(other) => {
                            b.warn(format!("group `{name}`: unknown strategy `{other}`, using consistent-hashing"));
                            LbStrategy::ConsistentHashing
                        }
                    };
                    GroupKind::LoadBalance(strategy)
                }
                _ => {
                    *ignored_types
                        .entry(if ty.is_empty() { "unknown".into() } else { ty })
                        .or_default() += 1;
                    b.ignored.insert(name);
                    continue;
                }
            };
            let regex = |key: &str, b: &mut Builder| -> Option<regex::Regex> {
                let pat = str_of(g, key)?;
                match regex::Regex::new(&pat) {
                    Ok(r) => Some(r),
                    Err(_) => {
                        b.warn(format!("group `{name}`: invalid `{key}` regex"));
                        None
                    }
                }
            };
            let filter = regex("filter", b);
            let exclude = regex("exclude-filter", b);
            let index = b.push_outbound(
                name.clone(),
                OutboundKind::Group(GroupSpec {
                    smart: crate::smart::parse(get(g, "smart"))?,
                    kind,
                    members: Vec::new(),
                    health,
                    disable_udp: bool_of(g, "disable-udp").unwrap_or(false),
                }),
            );
            let include_all = bool_of(g, "include-all").unwrap_or(false);
            pending.push(Pending {
                index,
                name,
                members: list_of(g, "proxies"),
                providers: list_of(g, "use"),
                include_proxies: include_all || bool_of(g, "include-all-proxies").unwrap_or(false),
                include_providers: include_all
                    || bool_of(g, "include-all-providers").unwrap_or(false),
                filter,
                exclude,
                flatten: bool_of(g, "flatten").unwrap_or(false),
            });
        }
    }
    if !ignored_types.is_empty() {
        let detail: Vec<String> = ignored_types
            .iter()
            .map(|(t, n)| format!("{t}: {n}"))
            .collect();
        b.warn(format!(
            "ignored proxy groups with unsupported types ({})",
            detail.join(", ")
        ));
    }

    // 内置策略
    let user_global = b.names.get(TAG_GLOBAL).copied();
    let global = match user_global {
        Some(i) => i,
        None => b.push_outbound(
            TAG_GLOBAL.into(),
            OutboundKind::Group(GroupSpec {
                smart: crate::SmartSpec::default(),
                kind: GroupKind::Select,
                members: Vec::new(),
                health: HealthSpec::default(),
                disable_udp: false,
            }),
        ),
    };
    let direct = b.push_outbound(TAG_DIRECT.into(), OutboundKind::Direct);
    let reject = b.push_outbound(TAG_REJECT.into(), OutboundKind::Reject);

    // 第二遍：解析成员
    for p in &pending {
        let mut members = Vec::new();
        for m in &p.members {
            match b.policy(m) {
                PolicyRef::Found(Policy::Outbound(i)) => {
                    if !members.contains(&i) {
                        members.push(i);
                    }
                }
                PolicyRef::Found(Policy::Pass) => {
                    b.warn(format!("group `{}`: PASS cannot be a member", p.name));
                }
                PolicyRef::Ignored => {}
                PolicyRef::Unknown => {
                    return Err(ConfigError(format!(
                        "group `{}` refers to unknown proxy or group `{m}`",
                        p.name
                    )));
                }
            }
        }
        // `use` 与 `include-all*` 带来的节点经过 filter / exclude-filter；`proxies` 里明确写的成员不过滤
        let mut candidates: Vec<usize> = Vec::new();
        if p.include_proxies {
            candidates.extend(0..config_proxies);
        }
        for provider in &p.providers {
            let Some(&pi) = b.proxy_provider_names.get(provider) else {
                return Err(ConfigError(format!(
                    "group `{}` uses unknown proxy provider `{provider}`",
                    p.name
                )));
            };
            candidates.extend(b.proxy_providers[pi].members.iter().copied());
        }
        if p.include_providers {
            for provider in &b.proxy_providers {
                candidates.extend(provider.members.iter().copied());
            }
        }
        for i in candidates {
            let name = &b.outbounds[i].name;
            let keep = p.filter.as_ref().is_none_or(|r| r.is_match(name))
                && !p.exclude.as_ref().is_some_and(|r| r.is_match(name));
            if keep && !members.contains(&i) {
                members.push(i);
            }
        }
        if members.is_empty()
            && matches!(&b.outbounds[p.index].kind, OutboundKind::Group(g) if g.kind == GroupKind::Smart)
        {
            return Err(ConfigError(format!(
                "smart group {} has no usable members",
                p.name
            )));
        }
        if members.is_empty() {
            b.warn(format!(
                "group `{}` has no usable members and behaves as DIRECT",
                p.name
            ));
            members.push(direct);
        }
        if let OutboundKind::Group(g) = &mut b.outbounds[p.index].kind {
            g.members = members;
        }
    }

    flatten(b, &pending);

    if user_global.is_none() {
        // 内置 GLOBAL：全部代理与策略组，外加 DIRECT、REJECT
        let mut members: Vec<usize> = (0..b.outbounds.len())
            .filter(|&i| i != global && i != direct && i != reject)
            .collect();
        members.push(direct);
        members.push(reject);
        if let OutboundKind::Group(g) = &mut b.outbounds[global].kind {
            g.members = members;
        }
    }

    resolve_dialers(b)?;
    check_cycles(b)?;
    for outbound in &b.outbounds {
        if let OutboundKind::Group(g) = &outbound.kind {
            if g.kind != GroupKind::Smart {
                continue;
            }
            if g.members.len() > 1024 {
                return Err(ConfigError("Smart supports at most 1024 members".into()));
            }
            for &i in &g.members {
                let member = &b.outbounds[i];
                if matches!(member.kind, OutboundKind::Group(_)) {
                    return Err(ConfigError(format!(
                        "smart group {} requires leaf members",
                        outbound.name
                    )));
                }
                if (g.smart.require_family_control
                    || matches!(
                        g.smart.server_strategy,
                        crate::ServerStrategy::V4Only | crate::ServerStrategy::V6Only
                    ))
                    && !crate::smart_family_capable(&member.kind, member.dialer.is_some())
                {
                    return Err(ConfigError(format!(
                        "smart: {} does not support strict server family control",
                        member.name
                    )));
                }
            }
        }
    }
    Ok(())
}

/// 展平：成员里每个策略组之后，紧跟该组（递归）包含的全部节点；已出现过的不重复。
/// 只加入节点，不加入 DIRECT / REJECT 与策略组本身。在全部策略组的成员解析完之后进行，
/// 使用展平前的成员，结果与策略组的书写顺序无关。
fn flatten(b: &mut Builder, pending: &[Pending]) {
    fn members(b: &Builder, i: usize) -> Option<&Vec<usize>> {
        match &b.outbounds[i].kind {
            OutboundKind::Group(g) => Some(&g.members),
            _ => None,
        }
    }
    fn leaves(b: &Builder, i: usize, seen: &mut Vec<usize>, out: &mut Vec<usize>) {
        if seen.contains(&i) {
            return;
        }
        seen.push(i);
        let Some(list) = members(b, i) else { return };
        for &m in list {
            match &b.outbounds[m].kind {
                OutboundKind::Group(_) => leaves(b, m, seen, out),
                OutboundKind::Direct | OutboundKind::Reject => {}
                _ => {
                    if !out.contains(&m) {
                        out.push(m);
                    }
                }
            }
        }
    }
    let mut results: Vec<(usize, Vec<usize>)> = Vec::new();
    for p in pending.iter().filter(|p| p.flatten) {
        let Some(original) = members(b, p.index) else {
            continue;
        };
        let mut out: Vec<usize> = Vec::new();
        for &m in original {
            if !out.contains(&m) {
                out.push(m);
            }
            if members(b, m).is_some() {
                let mut found = Vec::new();
                leaves(b, m, &mut vec![p.index], &mut found);
                for leaf in found {
                    if !out.contains(&leaf) && !original.contains(&leaf) {
                        out.push(leaf);
                    }
                }
            }
        }
        results.push((p.index, out));
    }
    for (index, list) in results {
        if let OutboundKind::Group(g) = &mut b.outbounds[index].kind {
            g.members = list;
        }
    }
}

/// 把 `dialer-proxy` 的名称解析成下标。目标被忽略（不支持）时节点改为 REJECT，
/// 不能悄悄退回直连，那会让本该经由链路的流量直接出去。
fn resolve_dialers(b: &mut Builder) -> Result<(), ConfigError> {
    for (index, target) in std::mem::take(&mut b.pending_dialers) {
        let own = b.outbounds[index].name.clone();
        match b.policy(&target) {
            PolicyRef::Found(Policy::Outbound(i)) => b.outbounds[index].dialer = Some(i),
            PolicyRef::Found(Policy::Pass) | PolicyRef::Unknown => {
                return Err(ConfigError(format!(
                    "proxy {own}: dialer-proxy refers to unknown proxy or group `{target}`"
                )));
            }
            PolicyRef::Ignored => {
                b.warn(format!(
                    "proxy {own}: dialer-proxy target `{target}` was ignored, so this proxy now rejects traffic"
                ));
                b.outbounds[index].kind = OutboundKind::Reject;
            }
        }
    }
    Ok(())
}

fn check_cycles(b: &Builder) -> Result<(), ConfigError> {
    // 0 = 未访问，1 = 访问中，2 = 完成
    fn visit(i: usize, b: &Builder, state: &mut Vec<u8>) -> Result<(), ConfigError> {
        match state[i] {
            1 => {
                return Err(ConfigError(format!(
                    "`{}` is part of a reference cycle (proxy groups and dialer-proxy)",
                    b.outbounds[i].name
                )))
            }
            2 => return Ok(()),
            _ => {}
        }
        state[i] = 1;
        if let OutboundKind::Group(g) = &b.outbounds[i].kind {
            for &m in &g.members {
                visit(m, b, state)?;
            }
        }
        if let Some(d) = b.outbounds[i].dialer {
            visit(d, b, state)?;
        }
        state[i] = 2;
        Ok(())
    }
    let mut state = vec![0u8; b.outbounds.len()];
    for i in 0..b.outbounds.len() {
        visit(i, b, &mut state)?;
    }
    Ok(())
}
