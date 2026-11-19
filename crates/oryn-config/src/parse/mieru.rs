//! 字段语义参考 mihomo adapter/outbound/mieru.go @ 88dcbf7f1614a67c3b36b848ee3592dfa92ada36。
use super::proxies::{error, password_value};
use crate::{
    model::*,
    yaml::{bool_of, get, int_of, str_of},
    ConfigError,
};
use yaml_rust2::Yaml;

pub(super) fn parse(
    p: &Yaml,
    name: &str,
    b: &mut super::Builder,
) -> Result<OutboundKind, ConfigError> {
    for (field, _) in crate::yaml::entries(p) {
        if ![
            "name",
            "type",
            "server",
            "port",
            "port-range",
            "transport",
            "username",
            "password",
            "udp",
            "multiplexing",
            "handshake-mode",
            "traffic-pattern",
            "dialer-proxy",
        ]
        .contains(&field.as_str())
        {
            b.warn(format!(
                "proxy {name}: ignored unsupported Mieru option {field}"
            ));
        }
    }
    for field in ["multiplexing", "handshake-mode", "traffic-pattern"] {
        if get(p, field).is_some() && str_of(p, field).is_none() {
            return Err(error(name, &format!("invalid {field}")));
        }
    }
    if get(p, "udp").is_some() && bool_of(p, "udp").is_none() {
        return Err(error(name, "invalid udp"));
    }
    let required = |key| {
        str_of(p, key)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| error(name, &format!("missing {key}")))
    };
    let host = required("server")?;
    let username = get(p, "username")
        .and_then(crate::yaml::scalar)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error(name, "missing username"))?;
    let password = password_value(p)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error(name, "missing password"))?;
    if username.len() > 1024 || password.len() > 1024 {
        return Err(error(name, "Mieru credentials exceed 1024 bytes"));
    }
    let (begin, end) = match (get(p, "port"), get(p, "port-range")) {
        (Some(_), None) => {
            let n = int_of(p, "port")
                .filter(|v| (1..=65535).contains(v))
                .ok_or_else(|| error(name, "invalid port"))? as u16;
            (n, n)
        }
        (None, Some(_)) => {
            let range = required("port-range")?;
            let (a, b) = range
                .split_once('-')
                .ok_or_else(|| error(name, "invalid port-range"))?;
            let a = a
                .parse::<u16>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| error(name, "invalid port-range"))?;
            let b = b
                .parse::<u16>()
                .ok()
                .filter(|n| *n >= a)
                .ok_or_else(|| error(name, "invalid port-range"))?;
            (a, b)
        }
        _ => {
            return Err(error(
                name,
                "exactly one of port and port-range must be set",
            ))
        }
    };
    // mihomo 生态的配置惯用小写枚举（`transport: tcp`），三个枚举字段都按大小写不敏感处理。
    let upper = |key| str_of(p, key).unwrap_or_default().to_ascii_uppercase();
    let transport_udp = match required("transport")?.to_ascii_uppercase().as_str() {
        "TCP" => false,
        "UDP" => true,
        _ => return Err(error(name, "Mieru transport must be TCP or UDP")),
    };
    let multiplexing = match upper("multiplexing").as_str() {
        "" | "MULTIPLEXING_DEFAULT" | "MULTIPLEXING_LOW" => 4,
        "MULTIPLEXING_OFF" => 1,
        "MULTIPLEXING_MIDDLE" => 8,
        "MULTIPLEXING_HIGH" => 16,
        _ => return Err(error(name, "invalid Mieru multiplexing")),
    };
    let no_wait = match upper("handshake-mode").as_str() {
        "" | "HANDSHAKE_DEFAULT" | "HANDSHAKE_STANDARD" => false,
        "HANDSHAKE_NO_WAIT" => true,
        _ => return Err(error(name, "invalid Mieru handshake-mode")),
    };
    let traffic_pattern =
        crate::MieruTrafficPattern::parse(&str_of(p, "traffic-pattern").unwrap_or_default())?;
    Ok(OutboundKind::Mieru(MieruSpec {
        server: crate::TargetAddr::from_host(&host, begin),
        port_end: end,
        transport_udp,
        username,
        password,
        udp: bool_of(p, "udp").unwrap_or(false),
        multiplexing,
        no_wait,
        traffic_pattern,
    }))
}

#[cfg(test)]
mod tests {
    use crate::{parse_config, OutboundKind};
    #[test]
    fn mieru_options_are_validated_before_building() {
        let base="proxies:\n- {name: M, type: mieru, server: proxy.test, username: user, password: secret, transport: TCP";
        let parse = |fields: &str| parse_config(&format!("{base}{fields}}}\nrules: ['MATCH,M']"));
        for fields in [
            ", port: 443",
            ", port-range: 1-65535",
            ", port-range: 443-443, transport: UDP",
        ] {
            // 不使用重复 YAML key；第三种在下面另测。
            if fields.contains("transport") {
                continue;
            }
            let c = parse(fields).unwrap();
            assert!(matches!(
                c.outbounds[c.outbound_index("M").unwrap()].kind,
                OutboundKind::Mieru(_)
            ));
        }
        for fields in [
            "",
            ", port: 0",
            ", port: 65536",
            ", port: 443, port-range: 1-2",
            ", port-range: 3-2",
            ", port-range: 1-2-3",
            ", port-range: 0-2",
            ", port: 443, multiplexing: wrong",
            ", port: 443, handshake-mode: wrong",
            ", port: 443, traffic-pattern: '!'",
            ", port: 443, traffic-pattern: MgII/w==",
        ] {
            assert!(parse(fields).is_err(), "{fields}");
        }
    }

    #[test]
    fn mieru_enums_are_case_insensitive() {
        let parse = |fields: &str| {
            let c = parse_config(&format!(
                "proxies:\n- {{name: M, type: mieru, server: proxy.test, port: 443, username: user, password: secret{fields}}}\nrules: ['MATCH,M']"
            ))
            .unwrap();
            match &c.outbounds[c.outbound_index("M").unwrap()].kind {
                OutboundKind::Mieru(spec) => spec.clone(),
                _ => unreachable!(),
            }
        };
        assert!(!parse(", transport: tcp").transport_udp);
        assert!(parse(", transport: udp").transport_udp);
        assert!(parse(", transport: Udp").transport_udp);
        let s = parse(", transport: tcp, multiplexing: multiplexing_high, handshake-mode: handshake_no_wait");
        assert_eq!((s.multiplexing, s.no_wait), (16, true));
        let s = parse(", transport: TCP, multiplexing: MULTIPLEXING_OFF, handshake-mode: HANDSHAKE_STANDARD");
        assert_eq!((s.multiplexing, s.no_wait), (1, false));
    }
}
