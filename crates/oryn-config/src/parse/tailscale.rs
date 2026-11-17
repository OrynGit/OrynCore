//! mihomo Tailscale 字段。高级路由和出口选项在运行时按 netmap 原子快照应用。
use super::Builder;
use crate::model::TailscaleSpec;
use crate::yaml::{bool_of, get, str_of};
use crate::ConfigError;
use yaml_rust2::Yaml;

pub(super) fn parse(p: &Yaml, name: &str, b: &mut Builder) -> Result<TailscaleSpec, ConfigError> {
    let fail = |reason: &str| ConfigError(format!("proxy {name}: {reason}"));
    for key in [
        "oryn-tailscale-enabled",
        "ephemeral",
        "udp",
        "accept-routes",
        "exit-node-allow-lan-access",
    ] {
        if get(p, key).is_some() && bool_of(p, key).is_none() {
            return Err(fail(&format!("{key} must be boolean")));
        }
    }
    let enabled = bool_of(p, "oryn-tailscale-enabled").unwrap_or(false);
    let state_dir = str_of(p, "state-dir").unwrap_or_else(|| "tailscale".into());
    if state_dir.is_empty()
        || state_dir.len() > 128
        || state_dir.starts_with('/')
        || state_dir.contains('\\')
        || state_dir.split('/').any(|s| {
            s.is_empty()
                || s == "."
                || s == ".."
                || !s
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        })
    {
        return Err(fail("state-dir must be a safe relative state namespace"));
    }
    let control_url = str_of(p, "control-url")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://controlplane.tailscale.com".into());
    if control_url.len() > 2048
        || (!control_url.starts_with("https://") && !control_url.starts_with("http://127.0.0.1:"))
        || control_url.bytes().any(|c| c <= 32 || c == 127)
    {
        return Err(fail(
            "control-url requires HTTPS (loopback HTTP is allowed for local testing)",
        ));
    }
    let spec = TailscaleSpec {
        enabled,
        hostname: str_of(p, "hostname").filter(|s| !s.is_empty()),
        auth_key: str_of(p, "auth-key").filter(|s| !s.is_empty()),
        control_url,
        state_dir,
        ephemeral: bool_of(p, "ephemeral").unwrap_or(false),
        udp: bool_of(p, "udp").unwrap_or(false),
        accept_routes: bool_of(p, "accept-routes"),
        exit_node: str_of(p, "exit-node").filter(|s| !s.is_empty()),
        exit_node_allow_lan_access: bool_of(p, "exit-node-allow-lan-access"),
    };
    if spec
        .hostname
        .as_ref()
        .is_some_and(|h| h.len() > 63 || !h.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
    {
        return Err(fail("invalid Tailscale hostname"));
    }
    if spec.auth_key.as_ref().is_some_and(|s| s.len() > 4096) {
        return Err(fail("auth-key exceeds size limit"));
    }
    if spec
        .exit_node
        .as_ref()
        .is_some_and(|s| s.len() > 253 || s.bytes().any(|c| c <= 32 || c == 127))
    {
        return Err(fail(
            "exit-node must be an IP address, node name, or auto:any",
        ));
    }
    for key in ["oryn-tailscale-auto-route", "oryn-tailscale-low-power"] {
        if get(p, key).is_some() {
            return Err(fail(&format!("{key} is not implemented")));
        }
    }
    for key in ["interface-name", "routing-mark", "ip-version"] {
        if get(p, key).is_some() {
            b.warn(format!(
                "proxy {name}: {key} is not supported by Tailscale and was ignored"
            ));
        }
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use crate::{parse_config, DnsProto, ForwardTarget, OutboundKind};
    #[test]
    fn tailscale_defaults_and_dns_binding() {
        let c=parse_config("proxies: [{name: 'My Tailnet',type: tailscale}]\ndns: {nameserver-policy: {'+.test.ts.net': 'ts://My Tailnet'}}\nrules: ['MATCH,My Tailnet']").unwrap();
        let spec = c.outbounds.iter().find(|o| o.name == "My Tailnet").unwrap();
        let OutboundKind::Tailscale(t) = &spec.kind else {
            panic!()
        };
        assert!(!t.enabled && !t.udp && !t.ephemeral);
        assert_eq!(t.accept_routes, None);
        assert_eq!(t.state_dir, "tailscale");
        let ForwardTarget::Servers(servers) = &c.dns.forward[0].target else {
            panic!()
        };
        assert_eq!(servers[0].proto, DnsProto::Tailscale);
    }
    #[test]
    fn tailscale_rejects_unsafe_or_silent_fallback_configuration() {
        for field in [
            "state-dir: ../escape",
            "state-dir: /tmp/state",
            "oryn-tailscale-enabled: invalid",
        ] {
            assert!(
                parse_config(&format!("proxies: [{{name: T,type: tailscale,{field}}}]")).is_err(),
                "{field}"
            );
        }
        for field in [
            "oryn-tailscale-enabled: true, accept-routes: true",
            "oryn-tailscale-enabled: true, exit-node: auto:any",
            "oryn-tailscale-enabled: true, exit-node-allow-lan-access: false",
        ] {
            assert!(
                parse_config(&format!("proxies: [{{name: T,type: tailscale,{field}}}]")).is_ok(),
                "{field}"
            );
        }
        for dns in [
            "nameserver: ['ts://Unknown']",
            "nameserver: ['ts://T', '8.8.8.8']",
            "default-nameserver: ['ts://T']",
        ] {
            assert!(
                parse_config(&format!(
                    "proxies: [{{name: T,type: tailscale}}]\ndns: {{{dns}}}"
                ))
                .is_err(),
                "{dns}"
            );
        }
    }

    #[test]
    fn swift_tailscale_fixture_preserves_mihomo_defaults() {
        let config = crate::parse_config(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../Tests/Fixtures/tailscale-profile.yaml"
        )))
        .unwrap();
        let node = config
            .outbounds
            .iter()
            .find(|o| o.name == "Tailnet")
            .unwrap();
        let crate::OutboundKind::Tailscale(spec) = &node.kind else {
            panic!("wrong outbound kind")
        };
        assert!(!spec.enabled && !spec.udp && !spec.ephemeral);
        assert_eq!(spec.hostname.as_deref(), Some("oryn"));
        assert_eq!(spec.auth_key.as_deref(), Some("tskey-auth-fixture"));
        assert_eq!(spec.accept_routes, None);
    }

    #[test]
    fn tailscale_advanced_routes_and_exit_options_are_compiled() {
        let config = parse_config(
            "proxies: [{name: T,type: tailscale,accept-routes: true,exit-node: '100.64.0.1',exit-node-allow-lan-access: true}]",
        )
        .unwrap();
        let OutboundKind::Tailscale(spec) = &config.outbounds[0].kind else {
            panic!("wrong outbound kind")
        };
        assert_eq!(spec.accept_routes, Some(true));
        assert_eq!(spec.exit_node.as_deref(), Some("100.64.0.1"));
        assert_eq!(spec.exit_node_allow_lan_access, Some(true));
        let enabled = parse_config(
            "proxies: [{name: T,type: tailscale,oryn-tailscale-enabled: true,accept-routes: true}]",
        );
        assert!(
            enabled.is_ok(),
            "advanced Tailscale routes must be accepted"
        );
    }

    #[test]
    fn tailscale_split_dns_policy_is_bound_without_public_fallback() {
        let config = parse_config(
            "proxies: [{name: T,type: tailscale}]\ndns:\n  nameserver: ['9.9.9.9']\n  nameserver-policy:\n    '+.corp.ts.net': 'tailscale://T'\n    '+.public.test': '9.9.9.9'",
        )
        .unwrap();
        assert_eq!(config.dns.forward.len(), 2);
        assert!(config.dns.forward.iter().any(|f| {
            matches!(&f.target, ForwardTarget::Servers(servers) if servers.iter().any(|s| s.proto == DnsProto::Tailscale))
        }));
    }
}
