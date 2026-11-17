use yaml_rust2::Yaml;

use super::{parse_cidrs, parse_ports, Builder};
use crate::model::*;
use crate::yaml::{bool_of, entries, get, list_of, list_value};
use crate::DomainPattern;

fn default_ports(proto: &str) -> Vec<PortRange> {
    match proto {
        "HTTP" => vec![
            PortRange { start: 80, end: 80 },
            PortRange {
                start: 8080,
                end: 8880,
            },
        ],
        _ => vec![
            PortRange {
                start: 443,
                end: 443,
            },
            PortRange {
                start: 8443,
                end: 8443,
            },
        ],
    }
}

pub(super) fn parse(root: &Yaml, b: &mut Builder) -> SnifferSpec {
    let s = get(root, "sniffer");
    let enable = s.and_then(|s| bool_of(s, "enable")).unwrap_or(false);
    let override_all = s
        .and_then(|s| bool_of(s, "override-destination"))
        .unwrap_or(false);

    let proto = |name: &str, b: &mut Builder| -> SniffProto {
        let sniff = s.and_then(|s| get(s, "sniff"));
        let Some(sniff) = sniff else {
            return SniffProto {
                enabled: true,
                ports: default_ports(name),
                override_destination: override_all,
            };
        };
        let entry = entries(sniff)
            .into_iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v);
        let Some(entry) = entry else {
            return SniffProto {
                enabled: false,
                ports: Vec::new(),
                override_destination: false,
            };
        };
        let ports = match get(entry, "ports").map(list_value) {
            Some(v) if !v.is_empty() => parse_ports(&v).unwrap_or_else(|e| {
                b.warn(format!("sniffer {name}: {e}; using default ports"));
                default_ports(name)
            }),
            _ => default_ports(name),
        };
        SniffProto {
            enabled: true,
            ports,
            override_destination: bool_of(entry, "override-destination").unwrap_or(override_all),
        }
    };
    let http = proto("HTTP", b);
    let tls = proto("TLS", b);
    let quic = proto("QUIC", b);

    let patterns = |key: &str| -> Vec<DomainPattern> {
        s.map(|s| list_of(s, key))
            .unwrap_or_default()
            .iter()
            .filter_map(|d| DomainPattern::parse(d))
            .collect()
    };
    let force_domain = patterns("force-domain");
    let skip_domain = patterns("skip-domain");
    let skip_src = parse_cidrs(
        &s.map(|s| list_of(s, "skip-src-address"))
            .unwrap_or_default(),
        "sniffer skip-src-address",
        b,
    );
    let skip_dst = parse_cidrs(
        &s.map(|s| list_of(s, "skip-dst-address"))
            .unwrap_or_default(),
        "sniffer skip-dst-address",
        b,
    );
    if s.is_some_and(|s| get(s, "sniffing").is_some()) {
        b.warn("sniffer: the legacy `sniffing` list is not supported; use `sniff`");
    }

    SnifferSpec {
        enable,
        force_dns_mapping: s
            .and_then(|s| bool_of(s, "force-dns-mapping"))
            .unwrap_or(true),
        parse_pure_ip: s.and_then(|s| bool_of(s, "parse-pure-ip")).unwrap_or(true),
        http,
        tls,
        quic,
        force_domain,
        skip_domain,
        skip_src,
        skip_dst,
    }
}
