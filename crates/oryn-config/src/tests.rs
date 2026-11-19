use crate::*;

const SAMPLE: &str = r#"
mode: rule
log-level: warning
mixed-port: 7890            # 与 iOS 无关的字段直接忽略
geox-url:
  mmdb: https://example.com/country.mmdb
geo-auto-update: true
geo-update-interval: 12

hosts:
  'router.lan': 192.168.1.1
  '+.test.dev': [127.0.0.1, "::1"]
  'alias.example': www.example.com

proxies:
  - name: Tokyo
    type: socks5
    server: tokyo.example.com
    port: 1080
    username: u
    password: p
    udp: true
  - name: Office
    type: http
    server: 10.0.0.1
    port: 8080
    tls: true
    skip-cert-verify: true
  - name: SS-HK
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: x
  - {name: VM, type: hysteria2, server: a.com, port: 443}

proxy-groups:
  - name: Proxy
    type: select
    proxies: [Auto, Tokyo, SS-HK, DIRECT]
  - name: Auto
    type: url-test
    proxies: [Tokyo, Office]
    url: https://cp.cloudflare.com/generate_204
    interval: 120
    tolerance: 80
  - name: LB
    type: load-balance
    strategy: round-robin
    include-all: true
    filter: "^T"
  - name: OnlySS
    type: fallback
    proxies: [SS-HK]
  - name: Chain
    type: relay
    proxies: [Tokyo, Office]

rule-providers:
  cn:
    type: http
    behavior: domain
    format: text
    url: https://example.com/cn.txt
    interval: 86400
    proxy: Proxy
  lan:
    type: inline
    behavior: ipcidr
    payload: [10.0.0.0/8, 192.168.0.0/16]
  local:
    type: file
    behavior: classical
    path: ./rules/local.yaml
  fast:
    type: http
    behavior: domain
    format: mrs
    url: https://example.com/fast.mrs

rules:
  - DOMAIN,ad.example,REJECT
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-KEYWORD,youtube,Proxy
  - DOMAIN-WILDCARD,*.cdn.example,DIRECT
  - DOMAIN-REGEX,^img\d{1,3}\.example\.com$,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR6,2001:db8::/32,Proxy
  - GEOIP,cn,DIRECT
  - GEOIP,LAN,DIRECT
  - DST-PORT,22/8000-9000,Proxy
  - NETWORK,udp,PASS
  - RULE-SET,cn,DIRECT
  - RULE-SET,lan,DIRECT
  - RULE-SET,fast,DIRECT
  - RULE-SET,https://example.com/surge.list,Proxy
  - DOMAIN-SET,https://example.com/ads.txt,REJECT-TINYGIF
  - PROCESS-NAME,curl,DIRECT
  - AND,((DOMAIN,a.com),(NETWORK,UDP)),DIRECT
  - DOMAIN,hk.example,SS-HK
  - MATCH,Proxy
  - DOMAIN,after-final.example,DIRECT

sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443, 8443]
    HTTP:
      ports: [80, "8080-8880"]
      override-destination: true
  skip-domain: ['Mijia Cloud', '+.apple.com']

dns:
  enable: true
  enhanced-mode: fake-ip
  default-nameserver: [119.29.29.29, tls://1.1.1.1, tcp://223.5.5.5, tls://dns.example.com]
  nameserver: [Domestic-DNS, 8.8.8.8]
  proxy-server-nameserver: [tls://223.5.5.5]
  upstreams:
    Domestic-DNS:
      - https://doh.pub/dns-query
      - tls://223.5.5.5
    bootstrap: [1.1.1.1]
  nameserver-policy:
    '+.google.com,+.youtube.com': 8.8.8.8
    'rule-set:cn': Domestic-DNS
    'geosite:cn': 223.5.5.5
  forward-rules:
    - DOMAIN-SUFFIX,chaoxing.com,119.29.29.29
    - DOMAIN-REGEX,^ad\..*,reject
    - SSID,Home*,Domestic-DNS
    - CELLULAR,NR,bootstrap
    - RULE-SET,local,Domestic-DNS
    - RULE-SET,lan,Domestic-DNS
    - MATCH,Domestic-DNS
  respect-rules: false
  ipv6: false
  skip-cert-verify: true
  blocked-ips: [0.0.0.0, 10.0.0.0/8, bogus]
  public-ip-url: https://ifconfig.me/ip
  reject-response: nxdomain
"#;

#[test]
fn parses_full_sample() {
    let c = parse_config(SAMPLE).unwrap();
    assert_eq!(c.mode, Mode::Rule);
    assert_eq!(c.log_level, "warn");
    assert_eq!(c.geoip.url, "https://example.com/country.mmdb");
    assert!(c.geoip.auto_update);
    assert_eq!(c.geoip.interval_hours, 12);

    // 代理：SS 已支持，hysteria2 仍被忽略
    let names: Vec<&str> = c.outbounds.iter().map(|o| o.name.as_str()).collect();
    #[cfg(not(feature = "hysteria2"))]
    assert_eq!(
        names,
        [
            "Tokyo", "Office", "SS-HK", "Proxy", "Auto", "LB", "OnlySS", "GLOBAL", "DIRECT",
            "REJECT"
        ]
    );
    #[cfg(feature = "hysteria2")]
    assert_eq!(
        names,
        [
            "Tokyo", "Office", "SS-HK", "VM", "Proxy", "Auto", "LB", "OnlySS", "GLOBAL", "DIRECT",
            "REJECT"
        ]
    );
    match &c.outbounds[0].kind {
        OutboundKind::Socks5 {
            server,
            auth,
            udp,
            tls,
        } => {
            assert_eq!(
                server,
                &TargetAddr::Domain("tokyo.example.com".into(), 1080)
            );
            assert_eq!(auth.as_ref().unwrap().password, "p");
            assert!(*udp && tls.is_none());
        }
        k => panic!("{k:?}"),
    }
    assert!(
        matches!(&c.outbounds[1].kind, OutboundKind::Http { tls: Some(t), .. } if t.skip_cert_verify)
    );

    let idx = |n: &str| c.outbound_index(n).unwrap();
    let group = |n: &str| match &c.outbounds[idx(n)].kind {
        OutboundKind::Group(g) => g.clone(),
        k => panic!("{k:?}"),
    };
    // Proxy 包含新协议节点
    assert_eq!(
        group("Proxy").members,
        vec![idx("Auto"), idx("Tokyo"), idx("SS-HK"), idx("DIRECT")]
    );
    let auto = group("Auto");
    assert_eq!(auto.kind, GroupKind::UrlTest { tolerance_ms: 80 });
    assert_eq!(auto.health.url, "https://cp.cloudflare.com/generate_204");
    assert_eq!(auto.health.interval_secs, 120);
    let lb = group("LB");
    assert_eq!(lb.kind, GroupKind::LoadBalance(LbStrategy::RoundRobin));
    assert_eq!(lb.members, vec![idx("Tokyo")]);
    // 单独的 SS 策略组
    assert_eq!(group("OnlySS").members, vec![idx("SS-HK")]);
    // 内置 GLOBAL：全部代理与策略组 + DIRECT + REJECT
    let global = group("GLOBAL");
    assert_eq!(global.kind, GroupKind::Select);
    // 样例里的 Hysteria2 节点只在 feature 打开时进入 GLOBAL
    let global_members = if cfg!(feature = "hysteria2") { 10 } else { 9 };
    assert_eq!(global.members.len(), global_members);

    // 规则集：mrs 被忽略，Surge URL 自动生成
    let providers: Vec<&str> = c.providers.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        providers,
        [
            "cn",
            "lan",
            "local",
            "RULE-SET:https://example.com/surge.list",
            "DOMAIN-SET:https://example.com/ads.txt"
        ]
    );
    match &c.providers[0].source {
        ProviderSource::Http {
            via,
            interval_secs,
            cache_path,
            ..
        } => {
            assert_eq!(*via, ProviderVia::Outbound(idx("Proxy")));
            assert_eq!(*interval_secs, Some(86400));
            assert!(cache_path.starts_with("providers/") && cache_path.ends_with(".txt"));
        }
        s => panic!("{s:?}"),
    }
    assert!(
        matches!(&c.providers[2].source, ProviderSource::File { path } if path == "rules/local.yaml")
    );
    assert_eq!(c.providers[4].domain_style, DomainStyle::Surge);
    // Surge 写在规则里的地址没有 `proxy`：遵循分流规则下载
    assert!(matches!(
        &c.providers[3].source,
        ProviderSource::Http {
            via: ProviderVia::Rules,
            ..
        }
    ));

    // 规则：PROCESS-NAME、mrs 规则集、MATCH 之后的规则都被跳过
    let texts: Vec<&str> = c.rules.iter().map(|r| r.text.as_str()).collect();
    assert_eq!(texts.len(), 18);
    assert_eq!(texts.last(), Some(&"MATCH,Proxy"));
    assert!(!texts
        .iter()
        .any(|t| t.contains("fast") || t.contains("curl")));
    assert!(matches!(c.rules[10].policy, Policy::Pass));
    assert!(matches!(&c.rules[7].kind, RuleKind::GeoIp(code) if code == "CN"));
    assert_eq!(c.rules[17].policy, Policy::Outbound(idx("Proxy")));
    assert!(matches!(c.rules[15].kind, RuleKind::Logic(LogicOp::And, _)));
    assert_eq!(c.rules[14].policy, Policy::Outbound(idx("REJECT")));

    // hosts
    assert_eq!(c.hosts.len(), 3);
    assert_eq!(c.hosts[2].value, HostValue::Alias("www.example.com".into()));
    assert!(c.hosts[1].pattern.matches("a.test.dev"));

    // sniffer：只写了 TLS / HTTP，QUIC 不启用
    assert!(c.sniffer.enable && c.sniffer.force_dns_mapping && c.sniffer.parse_pure_ip);
    assert!(c.sniffer.tls.applies(8443) && !c.sniffer.tls.override_destination);
    assert!(c.sniffer.http.applies(8123) && c.sniffer.http.override_destination);
    assert!(!c.sniffer.quic.enabled);
    assert!(c.sniffer.skip_domain[0].matches("mijia cloud"));

    // dns
    let d = &c.dns;
    assert_eq!(
        d.bootstrap.len(),
        3,
        "域名形式的引导 DNS 被忽略，IP 形式的加密 DNS 保留"
    );
    assert_eq!(d.bootstrap[1].proto, DnsProto::Tls);
    assert_eq!(d.bootstrap[2].proto, DnsProto::Tcp);
    assert_eq!(d.upstreams.len(), 1, "保留名称 bootstrap 被忽略");
    assert_eq!(d.nameserver.len(), 3, "上游组展开为组内服务器");
    assert_eq!(d.nameserver[0].proto, DnsProto::Https);
    assert_eq!(d.proxy_server.len(), 1);
    // nameserver-policy 两个域名 + 一个 rule-set（geosite 忽略），之后是 6 条 forward-rules
    assert_eq!(d.forward.len(), 9);
    assert!(
        matches!(&d.forward[0].matcher, ForwardMatch::Pattern(p) if p.matches("mail.google.com"))
    );
    assert!(matches!(&d.forward[2].matcher, ForwardMatch::RuleSet(0)));
    assert!(matches!(d.forward[2].target, ForwardTarget::Upstream(0)));
    assert!(matches!(d.forward[4].target, ForwardTarget::Reject));
    assert!(matches!(&d.forward[5].matcher, ForwardMatch::Ssid(s) if s == "Home*"));
    assert!(matches!(d.forward[6].target, ForwardTarget::Bootstrap));
    assert!(matches!(d.forward[8].matcher, ForwardMatch::Final));
    assert!(!d.respect_rules && !d.ipv6 && d.skip_cert_verify && d.use_hosts);
    assert_eq!(d.blocked_ips.len(), 2);
    assert_eq!(d.public_ip_url.as_deref(), Some("https://ifconfig.me/ip"));
    assert_eq!(d.reject_response, RejectResponse::NxDomain);

    let w = c.warnings.join("\n");
    for needle in [
        "ipcidr set",
        "relay: 1",
        "mrs",
        "PROCESS-NAME",
        "geosite",
        "bogus",
        "default-nameserver",
    ] {
        assert!(w.contains(needle), "缺少关于 {needle} 的警告：\n{w}");
    }
    #[cfg(not(feature = "hysteria2"))]
    assert!(
        w.contains("hysteria2 is not compiled in"),
        "缺少未编译警告：\n{w}"
    );
}

#[test]
fn defaults_for_empty_config() {
    let c = parse_config("").unwrap();
    assert_eq!(c.mode, Mode::Rule);
    assert_eq!(c.rules.len(), 1);
    assert!(matches!(c.rules[0].kind, RuleKind::Final));
    assert_eq!(c.rules[0].policy, Policy::Outbound(c.direct_index()));
    let hosts: Vec<&str> = c.dns.bootstrap.iter().map(|s| s.host.as_str()).collect();
    assert_eq!(hosts, ["119.29.29.29", "223.5.5.5"]);
    let hosts: Vec<&str> = c.dns.nameserver.iter().map(|s| s.host.as_str()).collect();
    assert_eq!(hosts, ["8.8.8.8", "1.1.1.1", "9.9.9.9"]);
    assert!(c.dns.respect_rules && c.dns.ipv6 && c.dns.proxy_server.is_empty());
    assert_eq!(c.dns.reject_response, RejectResponse::Refused);
    assert!(!c.sniffer.enable);
    assert_eq!(c.geoip.url, DEFAULT_MMDB_URL);
    // GLOBAL 只有 DIRECT、REJECT
    match &c.outbounds[c.global_index()].kind {
        OutboundKind::Group(g) => assert_eq!(g.members.len(), 2),
        k => panic!("{k:?}"),
    }
}

#[test]
fn parses_inline_module_spec() {
    let yaml = r#"
modules:
  - format: surge
    inline: |
      #!name=Inline
      [Body Rewrite]
      http-response-jq ^https://example.com 'del(.ad)'
      [MITM]
      hostname = example.com
    arguments: {enabled: true}
    policy-map: {PROXY: GLOBAL}
    env: {TOKEN: abc}
"#;
    let config = parse_config(yaml).unwrap();
    assert_eq!(config.modules.len(), 1);
    assert_eq!(
        config.modules[0]
            .inline
            .as_ref()
            .and_then(|m| m.meta.name.as_deref()),
        Some("Inline")
    );
    assert_eq!(
        config.modules[0].policy_map[0],
        ("PROXY".into(), "GLOBAL".into())
    );
    assert_eq!(config.modules[0].env["TOKEN"], "abc");
}

#[test]
fn module_rules_use_profile_policies() {
    let yaml = r#"
proxies: [{name: A, type: socks5, server: a.test, port: 1}]
proxy-groups: [{name: Media, type: select, proxies: [A, DIRECT]}]
rules: [MATCH,DIRECT]
modules:
  - format: surge
    inline: |
      #!arguments=Policy:Media
      [Rule]
      DOMAIN,group.test,{{{Policy}}}
      DOMAIN,proxy.test,PROXY
      IP-CIDR,10.1.0.0/16,REJECT-DROP,no-resolve
      DOMAIN,missing.test,Nope
      FINAL,REJECT
  - format: surge
    inline: |
      [Rule]
      DOMAIN,mapped.test,PROXY
    policy-map: {PROXY: A}
"#;
    let mut c = parse_config(yaml).unwrap();
    merge_module_patches(&mut c).unwrap();
    let idx = |n: &str| Policy::Outbound(c.outbound_index(n).unwrap());
    let texts: Vec<_> = c.rules.iter().map(|r| r.text.as_str()).collect();
    assert_eq!(
        texts,
        [
            "DOMAIN,group.test,Media",
            "DOMAIN,proxy.test,GLOBAL",
            "IP-CIDR,10.1.0.0/16,REJECT-DROP,no-resolve",
            "DOMAIN,mapped.test,A",
            "MATCH,DIRECT",
        ]
    );
    assert_eq!(c.rules[0].policy, idx("Media"));
    assert_eq!(c.rules[2].policy, idx("REJECT"));
    assert!(c.rules[2].no_resolve);
    assert!(c
        .warnings
        .iter()
        .any(|w| w.contains("unknown policy `Nope`")));
}

#[test]
fn swift_inspection_fixture() {
    let c = parse_config(include_str!(
        "../../../Tests/Fixtures/inspection-profile.yaml"
    ))
    .unwrap();
    assert!(c.mitm.enabled && c.mitm.http2 && c.mitm.auto_quic_block);
    assert_eq!(
        c.mitm.hostnames,
        ["api.example.com", "-private.example.com"]
    );
    assert_eq!(c.modules.len(), 1);
    assert_eq!(
        c.modules[0].arguments,
        [("a".into(), "quote\"value".into())]
    );
    assert_eq!(c.modules[0].update_interval, 86400);
}

#[test]
fn errors() {
    let bad = [
        "mode: [",
        "- a\n- b",
        "rules:\n  - DOMAIN,a.com,Nope",
        "proxies: [{name: A, type: socks5, server: a.com, port: 1}, {name: A, type: http, server: b.com, port: 2}]",
        "proxies: [{name: A, type: socks5, server: a.com, port: 0}]",
        "proxy-groups: [{name: G, type: select, proxies: [Missing]}]",
        "proxy-groups: [{name: A, type: select, proxies: [B]}, {name: B, type: select, proxies: [A]}]",
        "rule-providers: {x: {type: http, behavior: domain}}",
        "rule-providers: {x: {type: file, behavior: domain, path: /etc/hosts}}",
        "rule-providers: {x: {type: http, behavior: domain, url: 'https://a.com/x', path: '../x'}}",
    ];
    for b in bad {
        assert!(parse_config(b).is_err(), "{b}");
    }
}

#[test]
fn global_group_can_be_user_defined() {
    let c = parse_config(
        "proxies: [{name: A, type: socks5, server: a.com, port: 1}]\nproxy-groups: [{name: GLOBAL, type: select, proxies: [A]}]\nmode: global",
    )
    .unwrap();
    assert_eq!(c.mode, Mode::Global);
    match &c.outbounds[c.global_index()].kind {
        OutboundKind::Group(g) => assert_eq!(g.members, vec![0]),
        k => panic!("{k:?}"),
    }
}

/// 与 Swift 的 `LocalConfigBuilderTests` 共用：App 生成的 YAML 必须能被 Core 解析。
#[test]
fn swift_generated_fixture() {
    let c = parse_config(include_str!("../../../Tests/Fixtures/local-profile.yaml")).unwrap();
    assert_eq!(c.log_level, "debug");
    for name in [
        "Tokyo",
        "Office",
        "SS",
        "Trojan WS",
        "VLESS",
        "Reality",
        "Proxy",
    ] {
        assert!(c.outbound_index(name).is_some(), "{name}");
    }
    let OutboundKind::Group(g) = &c.outbounds[c.outbound_index("Proxy").unwrap()].kind else {
        panic!()
    };
    assert!(matches!(g.kind, GroupKind::Select));
    // 12 个旧节点 + HTTP2、HTTP Obfs、SS Obfs、SS V2Ray、ShadowTLS v2、SS UoT、Brutal、Chained 始终存在；
    // 0.8.x 的 Vision、SS Gost、SSR、Snell、Naive、SSH 也始终存在；QUIC 与 WireGuard 在精简构建里被跳过
    let expected =
        28 + 2 * usize::from(cfg!(feature = "quic")) + usize::from(cfg!(feature = "wireguard"));
    assert_eq!(g.members.len(), expected);
    let kind = |name: &str| &c.outbounds[c.outbound_index(name).unwrap()].kind;
    assert!(matches!(kind("Vision"), OutboundKind::Vless { stream, .. } if stream.vision));
    assert!(
        matches!(kind("SS Gost"), OutboundKind::Shadowsocks { plugin: SsPlugin::Gost(s), cipher, .. } if s.mux && cipher == "xchacha20-ietf-poly1305")
    );
    assert!(
        matches!(kind("SSR"), OutboundKind::Ssr(s) if s.cipher == "aes-256-cfb" && s.protocol == "auth_aes128_md5" && s.obfs_param == "cover.example")
    );
    assert!(
        matches!(kind("Snell"), OutboundKind::Snell(s) if s.version == 6 && s.mode == SnellMode::Unshaped && s.reuse)
    );
    assert!(
        matches!(kind("Naive"), OutboundKind::Naive(s) if s.username == "user" && s.tls.client_fingerprint.as_deref() == Some("chrome"))
    );
    assert!(
        matches!(kind("SSH"), OutboundKind::Ssh(s) if s.host_keys.len() == 1 && s.password.as_deref() == Some("secret"))
    );
    assert!(
        matches!(kind("Mieru"), OutboundKind::Mieru(s) if s.transport_udp && s.port_end == 4010 && s.no_wait && s.multiplexing == 16 && s.traffic_pattern.low_mode == Some(1))
    );
    assert!(
        matches!(kind("Sudoku"), OutboundKind::Sudoku(s) if s.http_tls && s.multiplex == "on" && s.tables.len() == 2 && !s.pure_downlink)
    );
    if cfg!(feature = "quic") {
        assert!(
            matches!(kind("ShadowQUIC"), OutboundKind::ShadowQuic(s) if s.zero_rtt && s.udp_over_stream && s.up_bps == 6_250_000)
        );
    }
    assert!(
        matches!(&c.outbounds[c.outbound_index("VMess").unwrap()].kind, OutboundKind::Vmess{stream, protocol} if protocol.alter_id == 64 && protocol.cipher == "aes-128-cfb" && matches!(stream.packet_encoding, PacketEncoding::Xudp) && stream.mux.as_ref().unwrap().padding)
    );
    assert!(
        matches!(&c.outbounds[c.outbound_index("gRPC").unwrap()].kind, OutboundKind::Vless{stream,..} if matches!(stream.transport, TransportSpec::Grpc(_)))
    );
    assert!(
        matches!(&c.outbounds[c.outbound_index("HTTPUpgrade").unwrap()].kind, OutboundKind::Trojan{stream,..} if matches!(stream.transport, TransportSpec::HttpUpgrade(_)))
    );
    assert!(
        matches!(&c.outbounds[c.outbound_index("ShadowTLS").unwrap()].kind, OutboundKind::Shadowsocks{plugin:SsPlugin::ShadowTls(s),mux:Some(_),..} if s.password == "cover-secret" && s.version == 3)
    );
    assert!(
        matches!(&c.outbounds[c.outbound_index("AnyTLS").unwrap()].kind, OutboundKind::AnyTls(s) if s.idle_check_secs == 10 && s.idle_timeout_secs == 60 && s.min_idle_sessions == 1 && s.udp)
    );
    let OutboundKind::Trojan { stream, .. } =
        &c.outbounds[c.outbound_index("Trojan WS").unwrap()].kind
    else {
        panic!()
    };
    let ws = stream.ws().unwrap();
    assert_eq!(ws.path, "/ws");
    assert_eq!(ws.max_early_data, 2048);
    assert_eq!(ws.early_data_header, "X-Early-Data");
    assert!(ws
        .headers
        .iter()
        .any(|(k, v)| k == "Host" && v == "cdn.example.com"));
    // VLESS：TLS + WebSocket，路径中的 ed 参数被识别，固定证书与 ALPN 生效
    let OutboundKind::Vless { stream, uuid } =
        &c.outbounds[c.outbound_index("VLESS").unwrap()].kind
    else {
        panic!()
    };
    assert_eq!(uuid[0], 0xb8);
    let ws = stream.ws().unwrap();
    assert_eq!((ws.path.as_str(), ws.max_early_data), ("/vl", 1024));
    let tls = stream.tls().unwrap();
    assert_eq!(tls.alpn, vec!["http/1.1".to_string()]);
    assert!(tls.fingerprint.is_some());
    assert!(!stream.udp);
    let OutboundKind::Vless { stream, .. } =
        &c.outbounds[c.outbound_index("Reality").unwrap()].kind
    else {
        panic!()
    };
    let tls = stream.tls().unwrap();
    assert_eq!(tls.client_fingerprint.as_deref(), Some("chrome"));
    assert_eq!(
        tls.reality.as_ref().unwrap().short_id,
        [1, 35, 69, 103, 137, 171, 205, 239]
    );
    // 0.7.0 的传输、插件、UoT、Brutal、dialer-proxy
    let OutboundKind::Vless { stream, .. } = &c.outbounds[c.outbound_index("HTTP2").unwrap()].kind
    else {
        panic!()
    };
    assert!(
        matches!(&stream.transport, TransportSpec::H2(h) if h.path == "/tun" && h.hosts == ["cdn.example.com", "alt.example.com"])
    );
    let OutboundKind::Vmess { stream, .. } =
        &c.outbounds[c.outbound_index("HTTP Obfs").unwrap()].kind
    else {
        panic!()
    };
    assert!(
        matches!(&stream.transport, TransportSpec::Http(h) if h.method == "POST" && h.path == "/obfs" && h.hosts == ["cdn.example.com"])
    );
    assert!(matches!(
        &c.outbounds[c.outbound_index("SS Obfs").unwrap()].kind,
        OutboundKind::Shadowsocks { plugin: SsPlugin::Obfs(o), .. } if o.tls && o.host == "cover.example.com"
    ));
    assert!(matches!(
        &c.outbounds[c.outbound_index("SS V2Ray").unwrap()].kind,
        OutboundKind::Shadowsocks { plugin: SsPlugin::V2Ray(v), .. } if v.mux && v.path == "/ws" && v.tls.is_some()
    ));
    assert!(matches!(
        &c.outbounds[c.outbound_index("ShadowTLS v2").unwrap()].kind,
        OutboundKind::Shadowsocks { plugin: SsPlugin::ShadowTls(s), .. } if s.version == 2 && s.password == "cover"
    ));
    assert!(matches!(
        &c.outbounds[c.outbound_index("SS UoT").unwrap()].kind,
        OutboundKind::Shadowsocks { uot: Some(2), .. }
    ));
    let OutboundKind::Trojan { stream, .. } =
        &c.outbounds[c.outbound_index("Brutal").unwrap()].kind
    else {
        panic!()
    };
    assert_eq!(
        stream.mux.as_ref().unwrap().brutal,
        Some(BrutalSpec {
            up_mbps: 50,
            down_mbps: 200
        })
    );
    let chained = &c.outbounds[c.outbound_index("Chained").unwrap()];
    assert_eq!(chained.dialer, c.outbound_index("Tokyo"));
    #[cfg(feature = "quic")]
    {
        let OutboundKind::Trojan { stream, .. } =
            &c.outbounds[c.outbound_index("QUIC").unwrap()].kind
        else {
            panic!()
        };
        assert_eq!(stream.transport, TransportSpec::Quic);
    }
    #[cfg(feature = "wireguard")]
    {
        let OutboundKind::WireGuard(w) = &c.outbounds[c.outbound_index("WireGuard").unwrap()].kind
        else {
            panic!()
        };
        assert_eq!(w.peers.len(), 2);
        assert_eq!(w.peers[1].reserved, [1, 2, 3]);
        assert_eq!(w.peers[1].allowed_ips.len(), 2);
        assert_eq!(w.refresh_secs, Some(300));
        let a = w.amnezia.unwrap();
        assert_eq!(
            (a.jc, a.jmin, a.jmax, a.h),
            (5, 40, 70, [100, 200, 300, 400])
        );
    }
    assert_eq!(c.providers.len(), 2);
    assert!(matches!(c.rules.last().unwrap().kind, RuleKind::Final));
    assert_eq!(c.dns.upstreams.len(), 1);
    assert_eq!(c.dns.forward.len(), 3);
    assert_eq!(c.dns.reject_response, RejectResponse::NxDomain);
    assert!(c.sniffer.enable);
    assert_eq!(c.hosts.len(), 2);
}

#[test]
fn p1_options_and_unsupported_nodes() {
    let c = parse_config(r#"
proxies:
  - {name: ss, type: ss, server: localhost, port: 1, cipher: aes-128-gcm, password: " p "}
  - {name: t, type: trojan, server: localhost, port: 2, password: secret, client-fingerprint: chrome, smux: {enabled: true}}
  - name: v
    type: vless
    server: localhost
    port: 3
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    alpn: [http/1.1]
    fingerprint: "aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa"
    network: ws
    ws-opts: {path: /ws, max-early-data: 128, headers: {Host: cdn.example}}
  - {name: vision, type: vless, flow: xtls-rprx-origin}
  - {name: plugin, type: ss, plugin: restls}
  - {name: grpc, type: trojan, network: grpc}
proxy-groups: [{name: G, type: select, proxies: [ss, t, v, vision, plugin, grpc]}]
"#).unwrap();
    assert!(
        matches!(&c.outbounds[0].kind, OutboundKind::Shadowsocks { password, .. } if password == " p ")
    );
    assert!(
        matches!(&c.outbounds[1].kind, OutboundKind::Trojan { stream, .. } if stream.tls().is_some())
    );
    let OutboundKind::Vless { stream, uuid } = &c.outbounds[2].kind else {
        panic!()
    };
    assert_eq!(uuid[0], 0xb8);
    assert_eq!(stream.tls().unwrap().fingerprint, Some([0xaa; 32]));
    assert_eq!(stream.ws().unwrap().max_early_data, 128);
    let OutboundKind::Group(g) = &c.outbounds[c.outbound_index("G").unwrap()].kind else {
        panic!()
    };
    assert_eq!(g.members, [0, 1, 2]);
    let w = c.warnings.join("\n");
    for field in ["flow", "plugin", "network"] {
        assert!(w.contains(field), "{field}: {w}");
    }
}

#[test]
fn p1_invalid_credentials_and_transport() {
    for fields in [
        "type: ss, cipher: des-cfb, password: x",
        "type: ss, cipher: 2022-blake3-aes-128-gcm, password: invalid",
        "type: ss, cipher: 2022-blake3-aes-128-gcm, password: AAAAAAAAAAAA",
        "type: trojan, password: ''",
        "type: vless, uuid: bad",
        "type: vless, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, fingerprint: abc",
        "type: trojan, password: x, network: ws, ws-opts: {path: 'bad path'}",
        "type: trojan, password: x, network: ws, alpn: [h2]",
        "type: trojan, password: x, network: ws, ws-opts: {max-early-data: -1}",
        "type: trojan, password: x, network: ws, ws-opts: {headers: {Upgrade: evil}}",
    ] {
        let yaml = format!("proxies: [{{name: P, server: localhost, port: 443, {fields}}}]");
        assert!(parse_config(&yaml).is_err(), "{fields}");
    }
}

/// 与 Swift 的 `ProxyValidationTests.testValidatorMatchesCoreContract` 共用样例：
/// App 校验通过的代理 Core 必须接受（且不被跳过）；App 拒绝的写法 Core 也必须拒绝。
#[test]
fn swift_validation_contract() {
    let docs = yaml_rust2::YamlLoader::load_from_str(include_str!(
        "../../../Tests/Fixtures/proxy-validation-cases.yaml"
    ))
    .unwrap();
    let cases = docs[0]["cases"].as_vec().expect("cases");
    assert!(cases.len() >= 40, "样例数量异常：{}", cases.len());
    let (mut valid_count, mut invalid_count) = (0, 0);
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let valid = case["valid"].as_bool().unwrap();
        let result = parse_config(case["config"].as_str().unwrap());
        if valid {
            valid_count += 1;
            let c =
                result.unwrap_or_else(|e| panic!("{label}: Core 拒绝了 App 认为有效的配置：{e}"));
            assert!(
                c.outbound_index("P").is_some(),
                "{label}: 代理被跳过：{:?}",
                c.warnings
            );
        } else {
            invalid_count += 1;
            assert!(result.is_err(), "{label}: Core 接受了 App 认为无效的配置");
        }
    }
    assert!(valid_count >= 15 && invalid_count >= 25);
}

#[test]
fn browser_and_reality_config() {
    let yaml = r#"
proxies:
  - name: reality
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: proxy.example
    reality-opts: {public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8, short-id: '012345'}
  - {name: browser, type: http, server: proxy.example, port: 443, tls: true, client-fingerprint: Firefox}
"#;
    let c = parse_config(yaml).unwrap();
    let OutboundKind::Vless { stream, .. } = &c.outbounds[0].kind else {
        panic!()
    };
    let tls = stream.tls().unwrap();
    assert_eq!(tls.client_fingerprint.as_deref(), Some("chrome"));
    let reality = tls.reality.as_ref().unwrap();
    assert_eq!(reality.public_key[31], 31);
    assert_eq!(reality.short_id, [1, 35, 69, 0, 0, 0, 0, 0]);
    assert!(
        matches!(&c.outbounds[1].kind,OutboundKind::Http {tls:Some(t),..} if t.client_fingerprint.as_deref()==Some("firefox"))
    );
    assert!(!c
        .warnings
        .iter()
        .any(|w| w.contains("client-fingerprint") || w.contains("reality-opts")));
    for fields in [
        "client-fingerprint: unknown",
        "client-fingerprint: android, reality-opts: {public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8}",
        "reality-opts: {public-key: bad}",
        "reality-opts: {public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}",
        "reality-opts: {public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8, short-id: abc}",
        "reality-opts: {public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8, short-id: 001122334455667788}",
    ] {
        let yaml=format!("proxies: [{{name: P, type: http, server: proxy.example, port: 443, tls: true, {fields}}}]");
        assert!(parse_config(&yaml).is_err(),"{fields}");
    }
    assert!(parse_config("proxies: [{name: P, type: http, server: proxy.example, port: 443, client-fingerprint: chrome}]").is_err());
}

#[test]
fn p2_contract_boundaries() {
    let base = "name: P, type: vmess, server: localhost, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811";
    for extra in [
        "alterId: -1",
        "alterId: 65536",
        "cipher: rc4",
        "packet-encoding: bad",
        "network: grpc, grpc-opts: {grpc-service-name: service}",
        "tls: true, network: grpc, alpn: [http/1.1], grpc-opts: {grpc-service-name: service}",
        "smux: {enabled: true, max-connections: 16, max-streams: 64}",
        "smux: {enabled: true, min-streams: 9, max-streams: 8}",
    ] {
        assert!(
            parse_config(&format!("proxies: [{{{base}, {extra}}}]")).is_err(),
            "{extra}"
        );
    }
    for version in [0, 4] {
        let yaml = format!("proxies: [{{name: P,type: ss,server: localhost,port: 1,cipher: aes-128-gcm,password: p,plugin: shadow-tls,plugin-opts: {{version: {version}, host: cover.example, password: s}}}}]");
        assert!(parse_config(&yaml).is_err(), "version {version}");
    }
    for extra in [
        "idle-session-timeout: 0",
        "min-idle-session: 5",
        "network: grpc",
    ] {
        let result = parse_config(&format!(
            "proxies: [{{name: P,type: anytls,server: localhost,port: 443,password: p,{extra}}}]"
        ));
        assert!(result.is_err() || result.unwrap().outbound_index("P").is_none());
    }
}

const VLESS_BASE: &str = "name: P, type: vless, server: localhost, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811";

fn vless(extra: &str) -> Result<RuntimeConfig, ConfigError> {
    parse_config(&format!("proxies: [{{{VLESS_BASE}, {extra}}}]"))
}

fn transport_of(c: &RuntimeConfig) -> TransportSpec {
    match &c.outbounds[c.outbound_index("P").unwrap()].kind {
        OutboundKind::Vless { stream, .. } => stream.transport.clone(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn h2_http_and_quic_transports() {
    // h2：host 列表与路径
    let c = vless("tls: true, network: h2, h2-opts: {host: [a.example, b.example], path: /tun}")
        .unwrap();
    assert_eq!(
        transport_of(&c),
        TransportSpec::H2(H2Spec {
            hosts: vec!["a.example".into(), "b.example".into()],
            path: "/tun".into()
        })
    );
    let c = vless("tls: true, network: h2").unwrap();
    assert_eq!(
        transport_of(&c),
        TransportSpec::H2(H2Spec {
            hosts: vec![],
            path: "/".into()
        })
    );
    let c = vless("tls: true, alpn: [h2], network: h2").unwrap();
    assert!(matches!(transport_of(&c), TransportSpec::H2(_)));
    for bad in [
        "network: h2",
        "tls: true, alpn: [http/1.1], network: h2",
        "tls: true, network: h2, h2-opts: {path: tun}",
        "tls: true, network: h2, h2-opts: {path: '/a b'}",
        "tls: true, network: h2, h2-opts: {host: [a, b, c, d, e, f, g, h, i]}",
    ] {
        assert!(vless(bad).is_err(), "{bad}");
    }
    // http：method、第一个 path、Host 列表与其它首部
    let c = vless("network: http, http-opts: {method: PUT, path: [/a, /b], headers: {Host: [h1.example, h2.example], X-Test: [v1, v2]}}").unwrap();
    assert_eq!(
        transport_of(&c),
        TransportSpec::Http(HttpSpec {
            method: "PUT".into(),
            path: "/a".into(),
            headers: vec![("X-Test".into(), "v1".into())],
            hosts: vec!["h1.example".into(), "h2.example".into()],
        })
    );
    let c = vless("network: http").unwrap();
    assert!(
        matches!(transport_of(&c), TransportSpec::Http(HttpSpec { method, path, .. }) if method == "GET" && path == "/")
    );
    assert!(vless("tls: true, alpn: [http/1.1], network: http").is_ok());
    for bad in [
        "tls: true, alpn: [h2], network: http",
        "network: http, http-opts: {method: 'G E'}",
        "network: http, http-opts: {path: [nope]}",
        "network: http, http-opts: {headers: {Connection: [x]}}",
    ] {
        assert!(vless(bad).is_err(), "{bad}");
    }
    // quic：需要 TLS，h3 ALPN，不能用 Reality
    #[cfg(feature = "quic")]
    {
        let c = vless("tls: true, network: quic").unwrap();
        assert_eq!(transport_of(&c), TransportSpec::Quic);
        assert!(vless("tls: true, alpn: [h3], network: quic").is_ok());
        for bad in [
            "network: quic",
            "tls: true, alpn: [h2], network: quic",
            "tls: true, network: quic, reality-opts: {public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8}",
        ] {
            assert!(vless(bad).is_err(), "{bad}");
        }
    }
    #[cfg(not(feature = "quic"))]
    {
        let c = vless("tls: true, network: quic").unwrap();
        assert!(c.outbound_index("P").is_none());
        assert!(c
            .warnings
            .iter()
            .any(|w| w.contains("quic is not compiled in")));
    }
    // 只有 Trojan / VLESS / VMess 支持这些传输，其它类型跳过并警告
    let c = parse_config("proxies: [{name: S, type: ss, server: localhost, port: 1, cipher: aes-128-gcm, password: p, network: h2}]").unwrap();
    assert!(c.outbound_index("S").is_none());
    assert!(c.warnings.iter().any(|w| w.contains("network")));
}

fn ss_plugin_of(extra: &str) -> Result<(SsPlugin, Option<u8>), ConfigError> {
    let yaml = format!("proxies: [{{name: P, type: ss, server: localhost, port: 8388, cipher: aes-128-gcm, password: p, {extra}}}]");
    let c = parse_config(&yaml)?;
    match &c.outbounds[c.outbound_index("P").ok_or(ConfigError("ignored".into()))?].kind {
        OutboundKind::Shadowsocks { plugin, uot, .. } => Ok((plugin.clone(), *uot)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn shadowsocks_plugins_and_udp_over_tcp() {
    let (p, uot) =
        ss_plugin_of("plugin: obfs, plugin-opts: {mode: tls, host: cover.example}").unwrap();
    assert_eq!(
        p,
        SsPlugin::Obfs(ObfsSpec {
            tls: true,
            host: "cover.example".into()
        })
    );
    assert_eq!(uot, None);
    let (p, _) = ss_plugin_of("plugin: simple-obfs, plugin-opts: {mode: http}").unwrap();
    assert_eq!(
        p,
        SsPlugin::Obfs(ObfsSpec {
            tls: false,
            host: "bing.com".into()
        })
    );
    for bad in [
        "plugin: obfs, plugin-opts: {mode: quic}",
        "plugin: obfs, plugin-opts: {mode: http, host: 'a b'}",
    ] {
        assert!(ss_plugin_of(bad).is_err(), "{bad}");
    }
    // v2ray-plugin：默认 websocket、开启 mux；tls 时 SNI 取 host
    let (p, _) = ss_plugin_of("plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, host: cdn.example, path: /ws, mux: false, skip-cert-verify: true}").unwrap();
    let SsPlugin::V2Ray(v) = p else { panic!() };
    assert_eq!(
        (v.host.as_str(), v.path.as_str(), v.mux),
        ("cdn.example", "/ws", false)
    );
    let tls = v.tls.unwrap();
    assert_eq!(tls.sni.as_deref(), Some("cdn.example"));
    assert!(tls.skip_cert_verify);
    assert_eq!(tls.alpn, vec!["http/1.1".to_string()]);
    let (p, _) = ss_plugin_of("plugin: v2ray-plugin").unwrap();
    assert!(matches!(p, SsPlugin::V2Ray(v) if v.tls.is_none() && v.mux && v.path == "/"));
    for bad in [
        "plugin: v2ray-plugin, plugin-opts: {mode: quic}",
        "plugin: v2ray-plugin, plugin-opts: {path: ws}",
        "plugin: v2ray-plugin, plugin-opts: {v2ray-http-upgrade: true}",
    ] {
        assert!(ss_plugin_of(bad).is_err(), "{bad}");
    }
    // ShadowTLS 三个版本：v1 不要求密码，v2 / v3 要求
    let (p, _) =
        ss_plugin_of("plugin: shadow-tls, plugin-opts: {version: 1, host: cover.example}").unwrap();
    assert!(matches!(p, SsPlugin::ShadowTls(s) if s.version == 1 && s.password.is_empty()));
    let (p, _) = ss_plugin_of(
        "plugin: shadow-tls, plugin-opts: {version: 2, host: cover.example, password: s}",
    )
    .unwrap();
    assert!(matches!(p, SsPlugin::ShadowTls(s) if s.version == 2));
    assert!(
        ss_plugin_of("plugin: shadow-tls, plugin-opts: {version: 2, host: cover.example}").is_err()
    );
    assert!(
        ss_plugin_of("plugin: shadow-tls, plugin-opts: {version: 3, host: cover.example}").is_err()
    );
    // skip-cert-verify：mihomo 写在 plugin-opts 里，也接受代理顶层；缺省不跳过
    for (extra, skip) in [
        (
            "plugin: shadow-tls, plugin-opts: {version: 3, host: cover.example, password: s, skip-cert-verify: true}",
            true,
        ),
        (
            "skip-cert-verify: true, plugin: shadow-tls, plugin-opts: {version: 3, host: cover.example, password: s}",
            true,
        ),
        (
            "plugin: shadow-tls, plugin-opts: {version: 3, host: cover.example, password: s}",
            false,
        ),
    ] {
        let (p, _) = ss_plugin_of(extra).unwrap();
        assert!(
            matches!(&p, SsPlugin::ShadowTls(s) if s.skip_cert_verify == skip),
            "{extra}: {p:?}"
        );
    }
    // gost-plugin：字段与 v2ray-plugin 相同，mux（smux）默认开启
    let (p, _) = ss_plugin_of("plugin: gost-plugin, plugin-opts: {mode: websocket, tls: true, host: cdn.example, path: /gost}").unwrap();
    assert!(
        matches!(p, SsPlugin::Gost(g) if g.mux && g.path == "/gost" && g.tls.as_ref().unwrap().sni.as_deref() == Some("cdn.example"))
    );
    let (p, _) = ss_plugin_of("plugin: gost-plugin, plugin-opts: {mux: false}").unwrap();
    assert!(matches!(p, SsPlugin::Gost(g) if !g.mux && g.tls.is_none()));
    assert!(ss_plugin_of("plugin: gost-plugin, plugin-opts: {mode: quic}").is_err());
    // 不支持的插件跳过并警告
    let yaml = "proxies: [{name: P, type: ss, server: localhost, port: 1, cipher: aes-128-gcm, password: p, plugin: restls}]";
    let c = parse_config(yaml).unwrap();
    assert!(c.outbound_index("P").is_none());
    assert!(c.warnings.iter().any(|w| w.contains("plugin")));
    // udp-over-tcp
    assert_eq!(ss_plugin_of("udp-over-tcp: true").unwrap().1, Some(1));
    assert_eq!(
        ss_plugin_of("udp-over-tcp: true, udp-over-tcp-version: 2")
            .unwrap()
            .1,
        Some(2)
    );
    assert_eq!(
        ss_plugin_of("udp-over-tcp: false, udp-over-tcp-version: 2")
            .unwrap()
            .1,
        None
    );
    assert!(ss_plugin_of("udp-over-tcp: true, udp-over-tcp-version: 3").is_err());
    // 非 SS 节点上的 udp-over-tcp 忽略并警告
    let c = parse_config("proxies: [{name: T, type: trojan, server: localhost, port: 443, password: p, udp-over-tcp: true}]").unwrap();
    assert!(c.warnings.iter().any(|w| w.contains("udp-over-tcp")));
}

#[test]
fn smux_brutal_options() {
    let yaml = |brutal: &str| {
        format!("proxies: [{{name: P, type: trojan, server: localhost, port: 443, password: p, smux: {{enabled: true, brutal-opts: {brutal}}}}}]")
    };
    let c = parse_config(&yaml("{enabled: true, up: 50, down: '100 Mbps'}")).unwrap();
    let OutboundKind::Trojan { stream, .. } = &c.outbounds[0].kind else {
        panic!()
    };
    assert_eq!(
        stream.mux.as_ref().unwrap().brutal,
        Some(BrutalSpec {
            up_mbps: 50,
            down_mbps: 100
        })
    );
    let c = parse_config(&yaml("{enabled: false, up: 50, down: 100}")).unwrap();
    let OutboundKind::Trojan { stream, .. } = &c.outbounds[0].kind else {
        panic!()
    };
    assert_eq!(stream.mux.as_ref().unwrap().brutal, None);
    for bad in [
        "{enabled: true, up: 0, down: 10}",
        "{enabled: true, up: 10, down: 10001}",
        "{enabled: true, up: 10}",
        "{enabled: true, up: x, down: 1}",
    ] {
        assert!(parse_config(&yaml(bad)).is_err(), "{bad}");
    }
}

#[test]
fn dialer_proxy_chains() {
    let c = parse_config(
        r#"
proxies:
  - {name: hop, type: socks5, server: hop.example, port: 1080}
  - {name: far, type: trojan, server: far.example, port: 443, password: p, dialer-proxy: hop}
  - {name: chained, type: socks5, server: c.example, port: 1080, dialer-proxy: far}
  - {name: viagroup, type: socks5, server: g.example, port: 1080, dialer-proxy: G}
proxy-groups: [{name: G, type: select, proxies: [hop]}]
"#,
    )
    .unwrap();
    let index = |n: &str| c.outbound_index(n).unwrap();
    assert_eq!(c.outbounds[index("hop")].dialer, None);
    assert_eq!(c.outbounds[index("far")].dialer, Some(index("hop")));
    assert_eq!(c.outbounds[index("chained")].dialer, Some(index("far")));
    assert_eq!(c.outbounds[index("viagroup")].dialer, Some(index("G")));
    for (yaml, why) in [
        ("proxies: [{name: a, type: socks5, server: s, port: 1, dialer-proxy: a}]", "itself"),
        ("proxies: [{name: a, type: socks5, server: s, port: 1, dialer-proxy: missing}]", "unknown"),
        ("proxies: [{name: a, type: socks5, server: s, port: 1, dialer-proxy: b}, {name: b, type: socks5, server: s, port: 1, dialer-proxy: a}]", "cycle"),
        ("proxies: [{name: a, type: socks5, server: s, port: 1, dialer-proxy: G}]\nproxy-groups: [{name: G, type: select, proxies: [a]}]", "group member cycle"),
    ] {
        assert!(parse_config(yaml).is_err(), "{why}");
    }
    // 目标因不支持被忽略：节点改为拒绝，不能悄悄直连
    let c = parse_config(
        r#"
proxies:
  - {name: odd, type: unknown-protocol}
  - {name: a, type: socks5, server: s, port: 1, dialer-proxy: odd}
"#,
    )
    .unwrap();
    assert!(matches!(
        c.outbounds[c.outbound_index("a").unwrap()].kind,
        OutboundKind::Reject
    ));
    assert!(c.warnings.iter().any(|w| w.contains("dialer-proxy")));
}

#[cfg(feature = "wireguard")]
const WG_KEY_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
#[cfg(feature = "wireguard")]
const WG_KEY_B: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

#[cfg(feature = "wireguard")]
fn wg(extra: &str) -> Result<WireGuardSpec, ConfigError> {
    let yaml = format!(
        "proxies: [{{name: P, type: wireguard, private-key: {WG_KEY_B}, ip: 10.0.0.2, {extra}}}]"
    );
    let c = parse_config(&yaml)?;
    match &c.outbounds[c.outbound_index("P").ok_or(ConfigError("ignored".into()))?].kind {
        OutboundKind::WireGuard(spec) => Ok(spec.clone()),
        other => panic!("{other:?}"),
    }
}

#[cfg(feature = "wireguard")]
#[test]
fn wireguard_peers_amnezia_and_refresh() {
    let single = format!(
        "server: a.example, port: 51820, public-key: {WG_KEY_A}, allowed-ips: ['10.0.0.0/24']"
    );
    let spec = wg(&single).unwrap();
    assert_eq!(spec.peers.len(), 1);
    assert!(spec.amnezia.is_none() && spec.refresh_secs.is_none());
    // 多对端
    let multi = format!(
        "peers: [{{server: a.example, port: 1, public-key: {WG_KEY_A}, allowed-ips: ['10.0.0.0/24'], reserved: [1, 2, 3]}}, {{server: '[::1]', port: 2, public-key: {WG_KEY_B}, allowed-ips: ['192.168.0.0/16', 'fd00::/64']}}]"
    );
    let spec = wg(&multi).unwrap();
    assert_eq!(spec.peers.len(), 2);
    assert_eq!(spec.peers[0].reserved, [1, 2, 3]);
    assert_eq!(spec.peers[1].allowed_ips.len(), 2);
    assert!(matches!(&spec.peers[1].endpoint, TargetAddr::Ip(a) if a.is_ipv6() && a.port() == 2));
    // 顶层的对端字段在有 peers 时被忽略并警告
    let c = parse_config(&format!(
        "proxies: [{{name: P, type: wireguard, private-key: {WG_KEY_B}, ip: 10.0.0.2, server: x.example, port: 9, {multi}}}]"
    ))
    .unwrap();
    assert!(c.warnings.iter().any(|w| w.contains("top-level")));
    // 对端数量：0 个与 9 个都不行（跳过并警告）
    assert!(wg("peers: []").is_err());
    let nine =
        vec![
            format!("{{server: a, port: 1, public-key: {WG_KEY_A}, allowed-ips: ['10.0.0.0/24']}}");
            9
        ]
        .join(", ");
    assert!(wg(&format!("peers: [{nine}]")).is_err());
    // AmneziaWG
    let spec = wg(&format!("{single}, amnezia-wg-option: {{jc: 5, jmin: 50, jmax: 90, s1: 20, s2: 30, h1: 100, h2: 200, h3: 300, h4: 400}}")).unwrap();
    assert_eq!(
        spec.amnezia,
        Some(AmneziaSpec {
            jc: 5,
            jmin: 50,
            jmax: 90,
            s1: 20,
            s2: 30,
            h: [100, 200, 300, 400]
        })
    );
    let spec = wg(&format!("{single}, amnezia-wg-option: {{jc: 3}}")).unwrap();
    assert_eq!(spec.amnezia.unwrap().h, [1, 2, 3, 4]);
    for bad in [
        "jc: 129",
        "jmin: 100, jmax: 50",
        "jmax: 1281",
        "s1: 10, s2: 66",
        "h1: 7, h2: 7",
        "h1: 0",
        "h4: 4294967296",
    ] {
        assert!(
            wg(&format!("{single}, amnezia-wg-option: {{{bad}}}")).is_err(),
            "{bad}"
        );
    }
    // 1.5 / 2.0 字段忽略并警告
    let c = parse_config(&format!(
        "proxies: [{{name: P, type: wireguard, private-key: {WG_KEY_B}, ip: 10.0.0.2, {single}, amnezia-wg-option: {{jc: 3, i1: '<b 0x00>'}}}}]"
    ))
    .unwrap();
    assert!(c.warnings.iter().any(|w| w.contains("i1")));
    // refresh-server-ip-interval
    assert_eq!(
        wg(&format!("{single}, refresh-server-ip-interval: 300"))
            .unwrap()
            .refresh_secs,
        Some(300)
    );
    assert_eq!(
        wg(&format!("{single}, refresh-server-ip-interval: 0"))
            .unwrap()
            .refresh_secs,
        None
    );
    assert!(wg(&format!("{single}, refresh-server-ip-interval: 5")).is_err());
    assert!(wg(&format!("{single}, refresh-server-ip-interval: 86401")).is_err());
}

#[test]
fn wireguard_tcp_buffers() {
    let single = format!(
        "server: a.example, port: 51820, public-key: {WG_KEY_A}, allowed-ips: ['10.0.0.0/24']"
    );
    // 缺省：上限 256 / 128 KiB，预算 6 MiB
    assert_eq!(
        wg(&single).unwrap().tcp_buffers,
        WireGuardTcpBuffers {
            rx: 262144,
            tx: 131072,
            budget: 6 * 1024 * 1024
        }
    );
    // 上限之和超过 6 MiB 时，缺省预算至少容纳一条用满上限的连接
    let b = wg(&format!(
        "{single}, tcp-rx-buffer: 4194304, tcp-tx-buffer: 4194304"
    ))
    .unwrap()
    .tcp_buffers;
    assert_eq!(b.budget, 8 * 1024 * 1024);
    let b = wg(&format!(
        "{single}, tcp-rx-buffer: 65536, tcp-buffer-budget: 1048576"
    ))
    .unwrap()
    .tcp_buffers;
    assert_eq!((b.rx, b.tx, b.budget), (65536, 131072, 1048576));
    for bad in [
        "tcp-rx-buffer: 16383",
        "tcp-rx-buffer: 4194305",
        "tcp-tx-buffer: 8191",
        "tcp-tx-buffer: '64K'",
        "tcp-buffer-budget: 393215",
        "tcp-buffer-budget: 67108865",
        "tcp-rx-buffer: 1048576, tcp-buffer-budget: 1000000",
    ] {
        assert!(wg(&format!("{single}, {bad}")).is_err(), "{bad}");
    }
}

fn kind_of(proxy: &str) -> Result<OutboundKind, ConfigError> {
    let c = parse_config(&format!("proxies: [{{name: P, {proxy}}}]"))?;
    let index = c.outbound_index("P").ok_or(ConfigError("ignored".into()))?;
    Ok(c.outbounds[index].kind.clone())
}

#[test]
fn vision_ssr_and_legacy_ciphers() {
    let vless = "type: vless, server: a.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811";
    match kind_of(&format!("{vless}, tls: true, flow: xtls-rprx-vision")).unwrap() {
        OutboundKind::Vless { stream, .. } => assert!(stream.vision),
        other => panic!("{other:?}"),
    }
    // Vision 只能跑在 TCP + TLS 上
    assert!(kind_of(&format!("{vless}, flow: xtls-rprx-vision")).is_err());
    assert!(kind_of(&format!(
        "{vless}, tls: true, network: ws, flow: xtls-rprx-vision"
    ))
    .is_err());

    for cipher in [
        "aes-192-gcm",
        "xchacha20-ietf-poly1305",
        "rc4-md5",
        "aes-256-cfb",
        "chacha20-ietf",
        "camellia-128-cfb",
    ] {
        assert!(
            kind_of(&format!(
                "type: ss, server: a.com, port: 1, cipher: {cipher}, password: p"
            ))
            .is_ok(),
            "{cipher}"
        );
    }

    let ssr = "type: ssr, server: a.com, port: 1, cipher: aes-256-cfb, password: p";
    match kind_of(&format!("{ssr}, protocol: auth_chain_a, protocol-param: '1:x', obfs: tls1.2_ticket_auth, obfs-param: b.com")).unwrap() {
        OutboundKind::Ssr(spec) => {
            assert_eq!((spec.protocol.as_str(), spec.obfs.as_str()), ("auth_chain_a", "tls1.2_ticket_auth"));
            assert_eq!((spec.protocol_param.as_str(), spec.obfs_param.as_str()), ("1:x", "b.com"));
        }
        other => panic!("{other:?}"),
    }
    match kind_of(ssr).unwrap() {
        OutboundKind::Ssr(spec) => assert_eq!(
            (spec.protocol.as_str(), spec.obfs.as_str()),
            ("origin", "plain")
        ),
        other => panic!("{other:?}"),
    }
    assert!(kind_of(&format!("{ssr}, protocol: auth_unknown")).is_err());
    assert!(kind_of(&format!("{ssr}, obfs: tls1.3")).is_err());
    // SSR 只接受流式加密
    assert!(
        kind_of("type: ssr, server: a.com, port: 1, cipher: aes-128-gcm, password: p").is_err()
    );
}

#[cfg(feature = "hysteria2")]
#[test]
fn hysteria_v1_and_gecko() {
    let base = "type: hysteria, server: a.com, port: 443, auth-str: s";
    match kind_of(&format!("{base}, up: 30 Mbps, down: '100', obfs: xplus")).unwrap() {
        OutboundKind::Hysteria(spec) => {
            assert_eq!((spec.up_bps, spec.down_bps), (3_750_000, 12_500_000));
            assert_eq!(spec.auth, b"s");
            assert_eq!(spec.obfs.as_deref(), Some("xplus"));
            assert_eq!(spec.tls.alpn, vec!["hysteria".to_string()]);
        }
        other => panic!("{other:?}"),
    }
    assert!(kind_of(base).is_err(), "up / down 必填");
    assert!(kind_of(&format!("{base}, up: 1 kbps, down: 10")).is_err());
    // wechat-video 进入独立 UDP 伪装；FakeTCP 照常解析但给出未实现警告，运行时拒绝。
    match kind_of(&format!(
        "{base}, up: 30 Mbps, down: 100 Mbps, protocol: wechat-video"
    ))
    .unwrap()
    {
        OutboundKind::Hysteria(spec) => assert_eq!(spec.protocol, "wechat-video"),
        other => panic!("{other:?}"),
    }
    match kind_of(&format!(
        "{base}, up: 30 Mbps, down: 100 Mbps, protocol: faketcp"
    ))
    .unwrap()
    {
        OutboundKind::Hysteria(spec) => assert_eq!(spec.protocol, "faketcp"),
        other => panic!("{other:?}"),
    }
    let c = parse_config(&format!(
        "proxies: [{{name: P, {base}, up: 30 Mbps, down: 100 Mbps, protocol: FakeTCP}}]"
    ))
    .unwrap();
    assert!(
        c.warnings
            .iter()
            .any(|w| w.contains("faketcp is not implemented") && !w.contains("iOS")),
        "{:?}",
        c.warnings
    );

    let h2 = "type: hysteria2, server: a.com, port: 443, password: p, obfs-password: obfs";
    match kind_of(&format!("{h2}, obfs: gecko")).unwrap() {
        OutboundKind::Hysteria2(spec) => assert_eq!(spec.gecko, Some((512, 1200))),
        other => panic!("{other:?}"),
    }
    match kind_of(&format!(
        "{h2}, obfs: gecko, obfs-min-packet-size: 900, obfs-max-packet-size: 1400"
    ))
    .unwrap()
    {
        OutboundKind::Hysteria2(spec) => assert_eq!(spec.gecko, Some((900, 1400))),
        other => panic!("{other:?}"),
    }
    match kind_of(&format!("{h2}, obfs: salamander")).unwrap() {
        OutboundKind::Hysteria2(spec) => {
            assert!(spec.gecko.is_none() && spec.obfs_password.is_some())
        }
        other => panic!("{other:?}"),
    }
    assert!(kind_of(&format!(
        "{h2}, obfs: gecko, obfs-min-packet-size: 1400, obfs-max-packet-size: 900"
    ))
    .is_err());
    assert!(kind_of(&format!("{h2}, obfs: gecko, obfs-max-packet-size: 4000")).is_err());

    // Realm：server / port 可省略
    let realm = "type: hysteria2, password: p, realm-opts: {enable: true, server-url: 'https://realm.example.com:8443/base/', token: t, realm-id: my-realm, stun-servers: ['stun.example.com', '1.2.3.4:19302', '[2001:db8::1]:3478']";
    match kind_of(&format!("{realm}}}")).unwrap() {
        OutboundKind::Hysteria2(spec) => {
            let r = spec.realm.unwrap();
            assert!(r.tls);
            assert_eq!(
                (r.host.as_str(), r.port, r.path.as_str()),
                ("realm.example.com", 8443, "/base")
            );
            assert_eq!((r.token.as_str(), r.realm_id.as_str()), ("t", "my-realm"));
            assert_eq!(r.stun_servers.len(), 3);
            assert_eq!(r.stun_servers[0].port(), 3478);
            assert_eq!(
                spec.server,
                TargetAddr::Domain("realm.example.com".into(), 443)
            );
        }
        other => panic!("{other:?}"),
    }
    match kind_of(&format!("{realm}}}, server: hy.example.com, port: 443")).unwrap() {
        OutboundKind::Hysteria2(spec) => assert_eq!(
            spec.server,
            TargetAddr::Domain("hy.example.com".into(), 443)
        ),
        other => panic!("{other:?}"),
    }
    // enable: false 时按普通节点处理
    match kind_of(
        "type: hysteria2, server: a.com, port: 443, password: p, realm-opts: {enable: false}",
    )
    .unwrap()
    {
        OutboundKind::Hysteria2(spec) => assert!(spec.realm.is_none()),
        other => panic!("{other:?}"),
    }
    assert!(
        kind_of(&format!("{realm}}}, server: a.com, ports: '1000-2000'")).is_err(),
        "realm 与端口跳跃互斥"
    );
    assert!(kind_of("type: hysteria2, password: p, realm-opts: {enable: true, server-url: 'https://r.com', realm-id: x}").is_err(), "需要 STUN");
    assert!(kind_of("type: hysteria2, password: p, realm-opts: {enable: true, server-url: 'https://r.com', realm-id: '-x', stun-servers: [s.com]}").is_err());
    assert!(kind_of("type: hysteria2, password: p, realm-opts: {enable: true, server-url: 'ftp://r.com', realm-id: x, stun-servers: [s.com]}").is_err());
}

#[cfg(feature = "tuic")]
#[test]
fn tuic_udp_over_stream_and_reduce_rtt() {
    let base = "type: tuic, server: a.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: p";
    let tuic = |extra: &str| match kind_of(&format!("{base}{extra}")) {
        Ok(OutboundKind::Tuic(spec)) => Ok(spec),
        Ok(other) => panic!("{other:?}"),
        Err(err) => Err(err),
    };
    let plain = tuic("").unwrap();
    assert!(plain.udp_over_stream.is_none() && !plain.reduce_rtt);
    // 与 mihomo 一致：版本缺省为旧版 1
    assert_eq!(
        tuic(", udp-over-stream: true").unwrap().udp_over_stream,
        Some(1)
    );
    assert_eq!(
        tuic(", udp-over-stream: true, udp-over-stream-version: 2")
            .unwrap()
            .udp_over_stream,
        Some(2)
    );
    assert_eq!(
        tuic(", udp-over-stream-version: 2")
            .unwrap()
            .udp_over_stream,
        None
    );
    assert!(tuic(", udp-over-stream: true, udp-over-stream-version: 3").is_err());
    assert!(tuic(", reduce-rtt: true").unwrap().reduce_rtt);
}

/// 未写 congestion-controller 时用 BBR（千兆有线下默认 Cubic 慢一半）；显式写的照配置。
#[cfg(feature = "tuic")]
#[test]
fn tuic_congestion_defaults_to_bbr() {
    use crate::QuicCongestion;
    let base = "type: tuic, server: a.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: p";
    let congestion = |extra: &str| match kind_of(&format!("{base}{extra}")) {
        Ok(OutboundKind::Tuic(spec)) => spec.congestion,
        other => panic!("{other:?}"),
    };
    assert_eq!(congestion(""), QuicCongestion::Bbr);
    assert_eq!(
        congestion(", congestion-controller: cubic"),
        QuicCongestion::Cubic
    );
    assert_eq!(
        congestion(", congestion-controller: new_reno"),
        QuicCongestion::NewReno
    );
    assert_eq!(
        congestion(", congestion-controller: bbr_meta_v2"),
        QuicCongestion::Bbr
    );
}

#[test]
fn snell_versions_and_options() {
    let base = "type: snell, server: a.com, port: 443, psk: secret";
    let snell = |extra: &str| match kind_of(&format!("{base}{extra}")) {
        Ok(OutboundKind::Snell(spec)) => Ok(spec),
        Ok(other) => panic!("{other:?}"),
        Err(err) => Err(err),
    };
    // 与 mihomo 一样缺省为 v1：不支持，节点被忽略
    assert!(snell("").is_err());
    assert!(snell(", version: 3").is_err());
    let v4 =
        snell(", version: 4, obfs-opts: {mode: tls, host: b.com}, reuse: true, udp: true").unwrap();
    assert_eq!(v4.version, 4);
    assert_eq!(
        v4.obfs,
        Some(ObfsSpec {
            tls: true,
            host: "b.com".into()
        })
    );
    assert!(v4.reuse && v4.udp);
    assert_eq!(
        snell(", version: 5").unwrap().version,
        5,
        "v5 保留声明版本并使用 v4 记录层"
    );
    let v6 = snell(", version: 6, mode: unsafe-raw").unwrap();
    assert_eq!((v6.version, v6.mode), (6, SnellMode::UnsafeRaw));
    // reuse 缺省开启，显式 false 才关闭
    assert!(snell(", version: 4").unwrap().reuse);
    assert!(snell(", version: 6").unwrap().reuse);
    assert!(!snell(", version: 4, reuse: false").unwrap().reuse);
    assert_eq!(snell(", version: 6").unwrap().mode, SnellMode::Default);
    assert!(
        snell(", version: 6, obfs-opts: {mode: http}")
            .unwrap()
            .obfs
            .is_none(),
        "v6 没有 obfs"
    );
    assert!(snell(", version: 6, mode: fancy").is_err());
    assert!(snell(", version: 7").is_err());
    assert!(
        snell(", version: 4, obfs-opts: {mode: shadow-tls}").is_err(),
        "不支持的 obfs 忽略节点"
    );
    assert!(
        kind_of("type: snell, server: a.com, port: 443, version: 4").is_err(),
        "psk 必填"
    );
}

#[test]
fn naive_and_ssh() {
    match kind_of("type: naive, server: a.com, port: 443, username: u, password: p, udp: true, headers: {X-A: b}, client-fingerprint: chrome").unwrap() {
        OutboundKind::Naive(spec) => {
            assert_eq!((spec.username.as_str(), spec.password.as_str()), ("u", "p"));
            assert_eq!(spec.uot, Some(2));
            assert_eq!(spec.tls.alpn, vec!["h2".to_string()]);
            assert_eq!(spec.tls.client_fingerprint.as_deref(), Some("chrome"));
            assert_eq!(spec.headers, vec![("X-A".to_string(), "b".to_string())]);
        }
        other => panic!("{other:?}"),
    }
    match kind_of("type: naive, server: a.com, port: 443, udp: true, udp-over-tcp-version: 1")
        .unwrap()
    {
        OutboundKind::Naive(spec) => assert_eq!(spec.uot, Some(1)),
        other => panic!("{other:?}"),
    }
    match kind_of("type: naive, server: a.com, port: 443, quic: true").unwrap() {
        OutboundKind::Naive(spec) => {
            assert!(spec.quic);
            assert_eq!(spec.tls.alpn, vec!["h3".to_string()]);
        }
        other => panic!("{other:?}"),
    }
    assert!(kind_of(
        "type: naive, server: a.com, port: 443, quic: true, client-fingerprint: chrome"
    )
    .is_err());
    assert!(kind_of("type: naive, server: a.com, port: 443, username: 'a:b'").is_err());

    let key = "-----BEGIN OPENSSH PRIVATE KEY-----\\nabc\\n-----END OPENSSH PRIVATE KEY-----";
    match kind_of(&format!("type: ssh, server: a.com, port: 22, username: u, private-key: \"{key}\", host-key: ['ssh-ed25519 AAAA'], host-key-algorithms: [ssh-ed25519]")).unwrap() {
        OutboundKind::Ssh(spec) => {
            assert!(spec.private_key.unwrap().contains("PRIVATE KEY"));
            assert_eq!(spec.host_keys, vec!["ssh-ed25519 AAAA".to_string()]);
            assert_eq!(spec.host_key_algorithms, vec!["ssh-ed25519".to_string()]);
        }
        other => panic!("{other:?}"),
    }
    assert!(
        kind_of("type: ssh, server: a.com, port: 22, username: u").is_err(),
        "需要密码或私钥"
    );
    assert!(
        kind_of("type: ssh, server: a.com, port: 22, username: u, private-key: ~/.ssh/id_ed25519")
            .is_err(),
        "不支持文件路径"
    );
    assert!(
        kind_of("type: ssh, server: a.com, port: 22, password: p").is_err(),
        "username 必填"
    );
    assert!(kind_of(
        "type: ssh, server: a.com, port: 22, username: u, password: p, host-key: [bad]"
    )
    .is_err());
}

#[test]
fn ech_rejects_silently_ignored_security_combinations() {
    let base = "type: vless, server: e.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true";
    for ech in [
        "ech-config: AQIDBA==",
        "ech-opts: {enable: true, config: AQIDBA==}",
    ] {
        for skip in [false, true] {
            let pin = "11".repeat(32);
            let result = kind_of(&format!(
                "{base}, {ech}, fingerprint: '{pin}', skip-cert-verify: {skip}"
            ));
            assert!(
                result.is_err(),
                "ECH must not silently ignore certificate fingerprint"
            );
        }
        assert!(
            kind_of(&format!("{base}, {ech}, network: quic")).is_err(),
            "QUIC must not silently ignore ECH"
        );
        assert!(
            kind_of(&format!("{base}, {ech}")).is_ok(),
            "ordinary ECH remains accepted"
        );
    }
    assert!(kind_of(&format!("{base}, network: quic")).is_ok());
}

#[test]
fn ech_xhttp_and_kcp() {
    let c = parse_config(r#"
proxies:
  - {name: ech, type: vless, server: e.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, ech-config: AQIDBAUGBwgJCgsMDQ4PEA==}
  - {name: x, type: vless, server: x.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: xhttp, tls: true, xhttp-opts: {path: /x, mode: stream-up, headers: {X-Test: ok}}}
  - {name: xp, type: vless, server: x.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: xhttp, tls: true, xhttp-opts: {path: /x, mode: packet-up, uplink-chunk-size: 4096, session-placement: header, session-key: X-Session, seq-placement: header, seq-key: X-Seq, no-grpc-header: true}}
  - {name: k, type: vmess, server: k.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: kcp, kcp-opts: {mtu: 1200, tti: 40, header: none}}
  - {name: mk, type: vmess, server: k.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: mekya, tls: true, mekya-opts: {url: 'https://k.example/mekya', h2-pool-size: 2, max-request-size: 65536, kcp: {mtu: 1200, tti: 40, header: none}}}
"#).unwrap();
    let OutboundKind::Vless { stream, .. } = &c.outbounds[c.outbound_index("ech").unwrap()].kind
    else {
        panic!()
    };
    assert_eq!(stream.tls().unwrap().ech.as_ref().unwrap().config.len(), 16);
    let OutboundKind::Vless { stream, .. } = &c.outbounds[c.outbound_index("x").unwrap()].kind
    else {
        panic!()
    };
    assert!(matches!(&stream.transport, TransportSpec::XHttp(x) if x.mode == "stream-up"));
    let OutboundKind::Vless { stream, .. } = &c.outbounds[c.outbound_index("xp").unwrap()].kind
    else {
        panic!()
    };
    assert!(
        matches!(&stream.transport, TransportSpec::XHttp(x) if x.mode == "packet-up" && x.uplink_chunk_size == 4096 && x.session_placement == "header" && x.no_grpc_header)
    );
    let OutboundKind::Vmess { stream, .. } = &c.outbounds[c.outbound_index("k").unwrap()].kind
    else {
        panic!()
    };
    assert!(matches!(&stream.transport, TransportSpec::Kcp(k) if k.mtu == 1200 && k.tti == 40));
    let OutboundKind::Vmess { stream, .. } = &c.outbounds[c.outbound_index("mk").unwrap()].kind
    else {
        panic!()
    };
    assert!(
        matches!(&stream.transport, TransportSpec::Mekya(m) if m.url == "https://k.example/mekya" && m.h2_pool_size == 2 && m.kcp.mtu == 1200)
    );
}

#[test]
fn xhttp_payload_placement_matches_mihomo_separately_from_metadata() {
    let base = "type: vless, server: example.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, network: xhttp";
    for placement in ["query", "path"] {
        assert!(
            kind_of(&format!(
                "{base}, xhttp-opts: {{mode: packet-up, uplink-data-placement: {placement}}}"
            ))
            .is_err(),
            "unsupported payload placement {placement} must be rejected"
        );
    }
    for placement in ["body", "auto", "header", "cookie"] {
        assert!(kind_of(&format!("{base}, xhttp-opts: {{mode: packet-up, uplink-data-placement: {placement}, session-placement: query, seq-placement: query}}")).is_ok(), "valid payload {placement} and metadata query remain supported");
    }
}

#[test]
fn xhttp_padding_download_and_reuse_are_bounded() {
    let c = parse_config(
        r#"
proxies:
  - name: x
    type: vless
    server: x.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: xhttp
    xhttp-opts:
      mode: stream-up
      host: upload.example
      path: /up
      x-padding-bytes: 80-120
      x-padding-obfs-mode: true
      x-padding-placement: header
      x-padding-key: xpad
      x-padding-header: X-Padding
      x-padding-method: tokenish
      download-settings:
        host: download.example
        path: /down
        headers:
          X-Download: yes
      reuse-settings:
        max-concurrency: 8
        max-connections: 2
        c-max-reuse-times: 12-20
        h-max-request-times: 50
        h-max-reusable-secs: 120
"#,
    )
    .unwrap();
    let OutboundKind::Vless { stream, .. } = &c.outbounds[c.outbound_index("x").unwrap()].kind
    else {
        panic!()
    };
    let TransportSpec::XHttp(x) = &stream.transport else {
        panic!()
    };
    assert_eq!((x.padding.min, x.padding.max), (80, 120));
    assert_eq!(x.padding.placement, "header");
    assert_eq!(x.download.as_ref().unwrap().path, "/down");
    assert_eq!(x.reuse.max_connections, 2);
    assert_eq!(x.reuse.max_reuse_times, 20);
}

#[test]
fn vless_encryption_config_is_carried_to_runtime() {
    let c = parse_config(r#"
proxies:
  - {name: enc, type: vless, server: e.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, encryption: mlkem768x25519plus.native.1rtt.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE}
"#).unwrap();
    let OutboundKind::Vless { stream, .. } = &c.outbounds[c.outbound_index("enc").unwrap()].kind
    else {
        panic!()
    };
    assert!(!stream.vless_encryption.as_ref().unwrap().zero_rtt);
}

#[test]
fn ssh_udp_is_explicit_oryn_extension_in_yaml_and_json() {
    for extra in ["", ", udp: true", ", oryn-ssh-udp: off, udp: true"] {
        let OutboundKind::Ssh(s) = kind_of(&format!(
            "type: ssh, server: a.com, port: 22, username: u, password: p{extra}"
        ))
        .unwrap() else {
            panic!()
        };
        assert!(s.udp_gateway.is_none());
    }
    for (value, mode) in [
        ("badvpn", SshUdpMode::BadVpn),
        ("tun2proxy", SshUdpMode::Tun2Proxy),
    ] {
        let OutboundKind::Ssh(s) = kind_of(&format!(
            "type: ssh, server: a.com, port: 22, username: u, password: p, oryn-ssh-udp: {value}"
        ))
        .unwrap() else {
            panic!()
        };
        assert_eq!(
            s.udp_gateway.unwrap(),
            SshUdpSpec {
                mode,
                server: "127.0.0.1:7300".parse().unwrap()
            }
        );
        let json = format!(
            r#"{{"proxies":[{{"name":"P","type":"ssh","server":"a.com","port":22,"username":"u","password":"p","oryn-ssh-udp":"{value}","oryn-ssh-udp-server":"[::1]:7400"}}]}}"#
        );
        let cfg = parse_config(&json).unwrap();
        let OutboundKind::Ssh(s) = &cfg.outbounds[cfg.outbound_index("P").unwrap()].kind else {
            panic!()
        };
        assert_eq!(s.udp_gateway.unwrap().server, "[::1]:7400".parse().unwrap());
    }
    for option in [
        "oryn-ssh-udp: true",
        "oryn-ssh-udp: bogus",
        "oryn-ssh-udp-server: gateway.example:7300",
        "oryn-ssh-udp-server: '127.0.0.1:0'",
        "oryn-ssh-udp-server: '::1:7300'",
        "oryn-ssh-udp-server: 7300",
    ] {
        assert!(
            kind_of(&format!(
                "type: ssh, server: a.com, port: 22, username: u, password: p, {option}"
            ))
            .is_err(),
            "{option}"
        );
    }
}

#[test]
fn xhttp_download_endpoint_inheritance_and_rejections() {
    fn read(extra: &str) -> Result<XHttpSpec, ConfigError> {
        let kind = kind_of(&format!("type: vless, server: up.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, network: xhttp, xhttp-opts: {{mode: stream-up, path: /up, headers: {{X-Up: yes}}, reuse-settings: {{c-max-reuse-times: '3-9'}}, download-settings: {{{extra}}}}}"))?;
        let OutboundKind::Vless { stream, .. } = kind else {
            panic!()
        };
        let TransportSpec::XHttp(x) = stream.transport else {
            panic!()
        };
        Ok(x)
    }
    let x = read("server: down.test, port: 8443, servername: cert.test, headers: {}, reuse-settings: {max-connections: 2}").unwrap();
    let d = x.download.unwrap();
    assert_eq!(d.server, TargetAddr::Domain("down.test".into(), 8443));
    assert_eq!(d.path, "/up");
    assert!(d.headers.is_empty());
    assert_eq!(d.transport.reuse.max_connections, 2);
    assert_eq!(
        (x.reuse.min_max_reuse_times, x.reuse.max_reuse_times),
        (3, 9)
    );
    assert!(
        matches!(d.security, SecuritySpec::Tls(ref t) if t.sni.as_deref() == Some("cert.test"))
    );
    assert!(matches!(
        read("tls: false").unwrap().download.unwrap().security,
        SecuritySpec::None
    ));
    for bad in [
        "server: down.test, port: 0",
        "tls: wrong",
        "alpn: [h3]",
        "jls-opts: {}",
        "reuse-settings: {h-keep-alive-period: 3}",
        "reuse-settings: {max-connections: '4-2'}",
    ] {
        assert!(read(bad).is_err(), "{bad}");
    }
}

#[test]
fn mkcp_alias_and_mekya_packet_capacity() {
    let base =
        "type: vmess, server: k.test, port: 1234, uuid: b831381d-6324-4d53-ad4f-8cda48b30811";
    let OutboundKind::Vmess { stream, .. } = kind_of(&format!(
        "{base}, network: mkcp, mkcp-opts: {{mtu: 1000, seed: ' keep spaces '}}"
    ))
    .unwrap() else {
        panic!()
    };
    assert!(
        matches!(stream.transport, TransportSpec::Kcp(k) if k.mtu == 1000 && k.seed.as_deref() == Some(" keep spaces "))
    );
    assert!(kind_of(&format!(
        "{base}, network: mekya, mekya-opts: {{max-request-size: 256}}"
    ))
    .is_err());
    assert!(kind_of(&format!("{base}, network: mkcp, tls: true")).is_err());
}

/// 与 Swift 的 `MihomoImporterTests` 共用：mihomo 配置经 App 转换后，Core 得到的运行配置必须与直接解析原文一致
/// （警告除外；展示用的规则原文也不比较）。
#[test]
fn mihomo_import_conversion_is_equivalent() {
    fn normalized(text: &str) -> String {
        let mut c = parse_config(text).unwrap();
        c.warnings.clear();
        for r in &mut c.rules {
            r.text.clear();
        }
        format!("{c:#?}")
    }
    let fixtures = [
        (
            "basic",
            include_str!("../../../Tests/Fixtures/mihomo-import/basic.yaml"),
            include_str!("../../../Tests/Fixtures/mihomo-import/basic.converted.yaml"),
        ),
        (
            "anchors",
            include_str!("../../../Tests/Fixtures/mihomo-import/anchors.yaml"),
            include_str!("../../../Tests/Fixtures/mihomo-import/anchors.converted.yaml"),
        ),
        (
            "edge",
            include_str!("../../../Tests/Fixtures/mihomo-import/edge.yaml"),
            include_str!("../../../Tests/Fixtures/mihomo-import/edge.converted.yaml"),
        ),
    ];
    for (name, original, converted) in fixtures {
        let (a, b) = (normalized(original), normalized(converted));
        if a != b {
            if let Ok(dir) = std::env::var("ORYN_DIFF_DIR") {
                std::fs::write(format!("{dir}/{name}.original.txt"), &a).unwrap();
                std::fs::write(format!("{dir}/{name}.converted.txt"), &b).unwrap();
            }
            panic!("{name}: converted configuration differs from the original (set ORYN_DIFF_DIR to dump both)");
        }
    }
}

fn members_of(c: &RuntimeConfig, group: &str) -> Vec<String> {
    let OutboundKind::Group(g) = &c.outbounds[c.outbound_index(group).unwrap()].kind else {
        panic!("{group} is not a group")
    };
    g.members
        .iter()
        .map(|&i| c.outbounds[i].name.clone())
        .collect()
}

#[test]
fn proxy_provider_inline_filter_override_and_use() {
    let c = parse_config(
        r#"
proxies:
  - {name: Local, type: socks5, server: 1.1.1.1, port: 1}
  - {name: "[A] HK 1", type: socks5, server: 1.1.1.9, port: 1}
proxy-providers:
  a:
    type: inline
    filter: "香港|JP"
    exclude-filter: "Expired"
    exclude-type: "http"
    override:
      additional-prefix: "[A] "
      proxy-name: [{pattern: "香港", target: "HK"}]
      udp: true
    health-check: {enable: true}
    payload:
      - {name: "香港 1", type: socks5, server: 2.2.2.1, port: 1}
      - {name: JP 1, type: socks5, server: 2.2.2.2, port: 1}
      - {name: JP Expired, type: socks5, server: 2.2.2.3, port: 1}
      - {name: JP http, type: http, server: 2.2.2.4, port: 1}
      - {name: US 1, type: socks5, server: 2.2.2.5, port: 1}
      - {name: JP bad, type: socks5, port: 1}
proxy-groups:
  - {name: Use, type: select, proxies: [Local], use: [a]}
  - {name: All, type: select, include-all: true}
  - {name: OnlyProxies, type: select, include-all-proxies: true}
  - {name: OnlyProviders, type: select, include-all-providers: true, filter: "JP"}
"#,
    )
    .unwrap();
    // 前缀与改名后和配置里的节点重名 → 加集合名
    assert_eq!(members_of(&c, "Use"), ["Local", "[A] HK 1 (a)", "[A] JP 1"]);
    assert_eq!(c.proxy_providers.len(), 1);
    assert!(c.proxy_providers[0].loaded);
    assert_eq!(c.proxy_providers[0].members.len(), 2);
    // override 写入的 udp 生效
    let i = c.outbound_index("[A] JP 1").unwrap();
    assert!(matches!(
        c.outbounds[i].kind,
        OutboundKind::Socks5 { udp: true, .. }
    ));
    assert_eq!(
        members_of(&c, "All"),
        ["Local", "[A] HK 1", "[A] HK 1 (a)", "[A] JP 1"]
    );
    assert_eq!(members_of(&c, "OnlyProxies"), ["Local", "[A] HK 1"]);
    assert_eq!(members_of(&c, "OnlyProviders"), ["[A] JP 1"]);
    // 坏节点只跳过并警告；health-check 警告
    assert!(c.warnings.iter().any(|w| w.contains("JP bad")));
    // health-check 是集合级的检查，不再警告
    let health = c.proxy_providers[0].health.as_ref().unwrap();
    assert_eq!((health.interval_secs, health.lazy), (300, true));
    // GLOBAL 也包含集合的节点
    assert!(members_of(&c, "GLOBAL").contains(&"[A] JP 1".to_string()));
}

#[test]
fn proxy_provider_http_uses_loader_and_resolves_via() {
    let text = r#"
proxies:
  - {name: Up, type: socks5, server: 1.1.1.1, port: 1}
proxy-providers:
  sub:
    type: http
    url: https://example.com/sub
    interval: 3600
    proxy: Up
    header: {User-Agent: [clash.meta]}
  local:
    type: file
    path: providers/local.yaml
proxy-groups:
  - {name: G, type: url-test, use: [sub, local]}
"#;
    // 没有缓存：集合为空，组退回 DIRECT
    let empty = parse_config(text).unwrap();
    assert!(!empty.proxy_providers[0].loaded);
    assert_eq!(members_of(&empty, "G"), ["DIRECT"]);

    let load = |path: &str| -> Option<String> {
        if path == "providers/local.yaml" {
            Some("not: [proxies".into())
        } else {
            assert!(path.starts_with("providers/proxy-") && path.ends_with(".yaml"));
            Some("proxies:\n  - {name: S1, type: socks5, server: 3.3.3.3, port: 1}\n".into())
        }
    };
    let c = parse_config_with(text, &load).unwrap();
    assert_eq!(members_of(&c, "G"), ["S1"]);
    let ProxyProviderSource::Http {
        via,
        interval_secs,
        headers,
        ..
    } = &c.proxy_providers[0].source
    else {
        panic!()
    };
    assert!(matches!(via, ProviderVia::Outbound(i) if c.outbounds[*i].name == "Up"));
    assert_eq!(*interval_secs, Some(3600));
    assert_eq!(
        headers,
        &[("User-Agent".to_string(), "clash.meta".to_string())]
    );
    // 没写 proxy：遵循分流规则；写了 DIRECT：直连
    let routed = parse_config("proxy-providers: {a: {type: http, url: 'https://x.test/a'}, b: {type: http, url: 'https://x.test/b', proxy: DIRECT}}").unwrap();
    let vias: Vec<_> = routed
        .proxy_providers
        .iter()
        .map(|p| match &p.source {
            ProxyProviderSource::Http { via, .. } => *via,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(vias[0], ProviderVia::Rules);
    assert!(matches!(vias[1], ProviderVia::Outbound(i) if routed.outbounds[i].name == "DIRECT"));
    // 不是 YAML：记录错误，配置仍然可用
    assert!(c.proxy_providers[1]
        .error
        .as_deref()
        .unwrap()
        .contains("neither"));
}

#[test]
fn proxy_provider_errors() {
    assert!(parse_config("proxy-groups: [{name: G, type: select, use: [nope]}]").is_err());
    assert!(parse_config("proxy-providers: {a: {type: http}}").is_err());
    assert!(parse_config("proxy-providers: {a: {type: file, path: /etc/passwd}}").is_err());
    let c = parse_config("proxy-providers: {a: {type: weird}}").unwrap();
    assert!(c.proxy_providers.is_empty());
    assert!(proxy_provider_nodes("hello world").is_err());
    // 链接订阅：坏链接只被跳过
    assert!(proxy_provider_nodes("vmess://abc\nss://def")
        .unwrap()
        .is_empty());
}

#[test]
fn group_flatten_adds_nested_proxies() {
    let c = parse_config(
        r#"
proxies:
  - {name: P1, type: socks5, server: 1.1.1.1, port: 1}
  - {name: P2, type: socks5, server: 1.1.1.2, port: 1}
  - {name: P3, type: socks5, server: 1.1.1.3, port: 1}
proxy-groups:
  - {name: A, type: select, flatten: true, proxies: [B, P3, DIRECT]}
  - {name: B, type: url-test, proxies: [P1, C, DIRECT]}
  - {name: C, type: select, proxies: [P2, P3]}
  - {name: NoFlat, type: select, proxies: [B]}
"#,
    )
    .unwrap();
    // B 之后紧跟 B 的全部节点（递归到 C）；P3 在 A 里已明确列出，保持原位置
    assert_eq!(members_of(&c, "A"), ["B", "P1", "P2", "P3", "DIRECT"]);
    assert_eq!(members_of(&c, "B"), ["P1", "C", "DIRECT"]);
    assert_eq!(members_of(&c, "NoFlat"), ["B"]);
}

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

fn b64url(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
}

/// 链接订阅经代理集合进入配置：每种链接都能被节点解析器接受。
#[test]
fn proxy_provider_share_links() {
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let vmess_json = format!(
        r#"{{"v":"2","ps":"VM WS","add":"vm.example.com","port":"443","id":"{uuid}","aid":"0","scy":"auto","net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"cdn.example.com"}}"#
    );
    let lines = vec![
        format!("ss://{}@1.2.3.4:8388#SS%20SIP002", b64url("aes-128-gcm:pa:ss")),
        format!("ss://{}#SS%20Legacy", b64("chacha20-poly1305:secret@example.com:1234")),
        format!("ss://{}@5.6.7.8:443/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dbing.com#SS%20Obfs", b64url("aes-256-gcm:pw")),
        format!("vmess://{}", b64(&vmess_json)),
        format!("vless://{uuid}@v.example.com:443?security=reality&sni=www.microsoft.com&pbk=7yXkRU4O-4UQbsMJLJ1CvDdgXkzu3IRZxWT4S7p3Dl0&sid=ab12&flow=xtls-rprx-vision&type=tcp#VLESS%20Reality"),
        format!("vless://{uuid}@w.example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048#VLESS%20WS"),
        "trojan://pass@t.example.com:443?sni=t.example.com&type=grpc&serviceName=svc#Trojan%20gRPC".to_string(),
        "hysteria2://pw@h.example.com:443,20000-30000?sni=h.example.com&obfs=salamander&obfs-password=obfs-pass&up=50%20Mbps#Hy2".to_string(),
        format!("tuic://{uuid}:pw@tu.example.com:443?congestion_control=bbr&udp_relay_mode=native&sni=tu.example.com#TUIC"),
        "anytls://pw@a.example.com:443?sni=a.example.com#AnyTLS".to_string(),
        format!("socks5://{}@9.9.9.9:1080#Socks", b64url("user:pass")),
        "http://u:p@8.8.8.8:8080#HTTP".to_string(),
        // 带有无法表示的参数：整条跳过
        "trojan://pass@bad.example.com:443?flow=xtls-rprx-vision#Bad".to_string(),
        "ss://garbage".to_string(),
    ];
    let text = lines.join("\n");
    for content in [text.clone(), b64(&text)] {
        let load = |_: &str| Some(content.clone());
        let c = parse_config_with(
            "proxy-providers: {sub: {type: file, path: sub.txt}}\nproxy-groups: [{name: G, type: select, use: [sub]}]",
            &load,
        )
        .unwrap();
        assert_eq!(c.proxy_providers[0].error, None);
        assert_eq!(
            members_of(&c, "G"),
            [
                "SS SIP002",
                "SS Legacy",
                "SS Obfs",
                "VM WS",
                "VLESS Reality",
                "VLESS WS",
                "Trojan gRPC",
                "Hy2",
                "TUIC",
                "AnyTLS",
                "Socks",
                "HTTP"
            ]
        );
        assert!(
            c.warnings.iter().any(|w| w.contains("flow")),
            "{:?}",
            c.warnings
        );

        let sip = &c.outbounds[c.outbound_index("SS SIP002").unwrap()].kind;
        assert!(matches!(sip, OutboundKind::Shadowsocks { password, .. } if password == "pa:ss"));
        let legacy = &c.outbounds[c.outbound_index("SS Legacy").unwrap()].kind;
        assert!(
            matches!(legacy, OutboundKind::Shadowsocks { cipher, .. } if cipher == "chacha20-ietf-poly1305")
        );
    }
    // 不是链接也不是 YAML：给出原因
    let c = parse_config_with(
        "proxy-providers: {sub: {type: file, path: sub.txt}}",
        &|_| Some("hello world".to_string()),
    )
    .unwrap();
    assert!(c.proxy_providers[0]
        .error
        .as_deref()
        .unwrap()
        .contains("share-link"));
}

#[test]
fn maxmind_database_addresses() {
    let config = crate::parse_config("geox-url: {mmdb: 'https://example.com/country.mmdb', asn: 'https://example.com/asn.mmdb'}\ngeo-auto-update: true\ngeo-update-interval: 168\nrules: ['MATCH,DIRECT']").unwrap();
    assert_eq!(config.geoip.url, "https://example.com/country.mmdb");
    assert_eq!(
        config.geoip.asn_url.as_deref(),
        Some("https://example.com/asn.mmdb")
    );
    assert!(config.geoip.auto_update);
    assert_eq!(config.geoip.interval_hours, 168);
}

#[test]
fn modules_accept_egern_arguments_and_script_hub_urls() {
    let yaml = r#"
rules: ["MATCH,DIRECT"]
modules:
  - url: http://script.hub/file/_start_/https://a.test/B.plugin/_end_/B.sgmodule?type=loon-plugin&target=surge-module
    compat_arguments: {app: ng}
  - format: surge
    inline: |
      [Rule]
      URL-REGEX,^http://a\.test/,REJECT
      DOMAIN,b.test,REJECT
"#;
    let mut c = parse_config(yaml).unwrap();
    assert_eq!(c.modules[0].url.as_deref(), Some("https://a.test/B.plugin"));
    assert_eq!(c.modules[0].format, Some(oryn_module::ModuleFormat::Loon));
    assert_eq!(
        c.modules[0].arguments,
        [("app".to_string(), "ng".to_string())]
    );
    merge_module_patches(&mut c).unwrap();
    let texts: Vec<_> = c.rules.iter().map(|r| r.text.as_str()).collect();
    assert_eq!(texts, ["DOMAIN,b.test,REJECT", "MATCH,DIRECT"]);
    assert!(
        !c.warnings.iter().any(|w| w.contains("URL-REGEX")),
        "{:?}",
        c.warnings
    );
}

#[test]
fn module_merge_warns_and_maps_policies() {
    let yaml = r#"
rules: ["MATCH,DIRECT"]
mitm: {hostnames: [main.test]}
modules:
  - format: surge
    policy-map: {ADBLOCK: REJECT}
    inline: |
      [Rule]
      URL-REGEX,^http://ad\.test/,ADBLOCK
      DOMAIN,p.test,PROXY
      FINAL,PROXY
      [Host]
      +. = 1.2.3.4
      [MITM]
      hostname = %INSERT% a.test, %APPEND%b.test, c.test
      [General]
      force-http-engine-hosts = %INSERT%%APPEND%x.test
"#;
    let mut c = parse_config(yaml).unwrap();
    merge_module_patches(&mut c).unwrap();
    let texts: Vec<_> = c.rules.iter().map(|r| r.text.as_str()).collect();
    // policy-map 到 REJECT 的 URL-REGEX 交给 HTTP 检查，不进 Router
    assert_eq!(texts, ["DOMAIN,p.test,GLOBAL", "MATCH,DIRECT"]);
    let warned = |s: &str| c.warnings.iter().any(|w| w.contains(s));
    assert!(warned("policy PROXY is not defined"), "{:?}", c.warnings);
    assert!(warned("MATCH/FINAL rule ignored"), "{:?}", c.warnings);
    assert!(warned("invalid Host pattern"), "{:?}", c.warnings);
    assert_eq!(
        c.mitm.hostnames,
        ["a.test", "c.test", "main.test", "b.test"]
    );
    assert_eq!(c.force_http_hosts, ["x.test"]);
}

#[test]
fn fake_ip_range_custom_and_fallback() {
    let range = |value: &str| {
        let c = parse_config(&format!(
            "dns:\n  fake-ip-range: {value}\nrules: ['MATCH,DIRECT']\n"
        ))
        .unwrap();
        let warned = c.warnings.iter().any(|w| w.contains("fake-ip-range"));
        (c.dns.fake_ip_range.to_string(), warned)
    };
    // 显式写 mihomo 默认值不应回退或警告；隧道 /24 由地址池跳过。
    assert_eq!(range("198.18.0.0/15"), ("198.18.0.0/15".into(), false));
    assert_eq!(range("10.20.30.40/16"), ("10.20.0.0/16".into(), false));
    assert_eq!(range("10.0.0.0/24"), ("198.18.0.0/15".into(), true));
    assert_eq!(range("127.0.0.0/8"), ("198.18.0.0/15".into(), true));
    assert_eq!(range("nope"), ("198.18.0.0/15".into(), true));
}

#[test]
fn rule_provider_download_defaults_to_routing_rules() {
    let c = parse_config(
        r#"
proxies:
  - {name: P, type: socks5, server: 127.0.0.1, port: 1080}
rule-providers:
  plain: {type: http, behavior: domain, url: https://example.com/a.txt}
  direct: {type: http, behavior: domain, url: https://example.com/b.txt, proxy: DIRECT}
  node: {type: http, behavior: domain, url: https://example.com/c.txt, proxy: P}
  unknown: {type: http, behavior: domain, url: https://example.com/d.txt, proxy: Nope}
rules:
  - MATCH,P
"#,
    )
    .unwrap();
    let vias: Vec<ProviderVia> = c
        .providers
        .iter()
        .map(|p| match &p.source {
            ProviderSource::Http { via, .. } => *via,
            s => panic!("{s:?}"),
        })
        .collect();
    let idx = |name: &str| c.outbounds.iter().position(|o| o.name == name).unwrap();
    assert_eq!(vias[0], ProviderVia::Rules);
    assert_eq!(vias[1], ProviderVia::Outbound(idx("DIRECT")));
    assert_eq!(vias[2], ProviderVia::Outbound(idx("P")));
    assert_eq!(vias[3], ProviderVia::Outbound(idx("DIRECT")));
    assert!(c
        .warnings
        .iter()
        .any(|w| w.contains("unknown proxy `Nope`")));
}

/// sing-box 订阅经代理集合进入配置：各协议都能被节点解析器接受，非节点出站跳过，无法表示的写法给出原因。
#[test]
fn proxy_provider_sing_box() {
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let text = format!(
        r#"{{
  "log": {{"level": "info"}},
  "outbounds": [
    {{"type": "selector", "tag": "proxy", "outbounds": ["SS"]}},
    {{"type": "direct", "tag": "direct"}},
    {{"type": "shadowsocks", "tag": "SS", "server": "1.2.3.4", "server_port": 8388, "method": "aes-128-gcm", "password": "pw", "udp_over_tcp": {{"enabled": true, "version": 2}}, "tcp_fast_open": true}},
    {{"type": "shadowsocks", "tag": "SS Obfs", "server": "1.2.3.5", "server_port": 443, "method": "aes-256-gcm", "password": "pw", "plugin": "obfs-local", "plugin_opts": "obfs=tls;obfs-host=bing.com"}},
    {{"type": "shadowsocks", "tag": "SS STLS", "server": "127.0.0.1", "server_port": 1, "method": "2022-blake3-aes-128-gcm", "password": "AAECAwQFBgcICQoLDA0ODw==", "detour": "stls"}},
    {{"type": "shadowtls", "tag": "stls", "server": "st.example.com", "server_port": 443, "version": 3, "password": "stpw", "tls": {{"enabled": true, "server_name": "www.apple.com", "utls": {{"enabled": true, "fingerprint": "chrome"}}}}}},
    {{"type": "vmess", "tag": "VM WS", "server": "vm.example.com", "server_port": 443, "uuid": "{uuid}", "security": "auto", "alter_id": 0, "network": "tcp", "tls": {{"enabled": true, "server_name": "cdn.example.com"}}, "transport": {{"type": "ws", "path": "/ws", "headers": {{"Host": "cdn.example.com"}}, "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}}}},
    {{"type": "vless", "tag": "VLESS Reality", "server": "v.example.com", "server_port": 443, "uuid": "{uuid}", "flow": "xtls-rprx-vision", "packet_encoding": "xudp", "tls": {{"enabled": true, "server_name": "www.microsoft.com", "utls": {{"enabled": true, "fingerprint": "chrome"}}, "reality": {{"enabled": true, "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "short_id": "ab12"}}}}}},
    {{"type": "vless", "tag": "VLESS HU", "server": "w.example.com", "server_port": 443, "uuid": "{uuid}", "tls": {{"enabled": true}}, "transport": {{"type": "httpupgrade", "host": "cdn.example.com", "path": "/up"}}, "multiplex": {{"enabled": true, "protocol": "smux", "max_streams": 8}}}},
    {{"type": "trojan", "tag": "Trojan gRPC", "server": "t.example.com", "server_port": 443, "password": "pw", "tls": {{"enabled": true, "server_name": "t.example.com", "alpn": ["h2"]}}, "transport": {{"type": "grpc", "service_name": "svc"}}}},
    {{"type": "trojan", "tag": "Trojan H2", "server": "t2.example.com", "server_port": 443, "password": "pw", "tls": {{"enabled": true}}, "transport": {{"type": "http", "host": ["t2.example.com"], "path": "/h2"}}}},
    {{"type": "hysteria2", "tag": "Hy2", "server": "h.example.com", "server_ports": ["20000:30000"], "hop_interval": "30s", "up_mbps": 50, "down_mbps": 200, "password": "pw", "obfs": {{"type": "salamander", "password": "obfs-password"}}, "tls": {{"enabled": true, "server_name": "h.example.com"}}}},
    {{"type": "hysteria", "tag": "Hy1", "server": "h1.example.com", "server_port": 443, "up_mbps": 20, "down_mbps": 100, "auth_str": "pw", "obfs": "x", "tls": {{"enabled": true, "server_name": "h1.example.com", "alpn": ["hysteria"]}}}},
    {{"type": "tuic", "tag": "TUIC", "server": "tu.example.com", "server_port": 443, "uuid": "{uuid}", "password": "pw", "congestion_control": "bbr", "udp_relay_mode": "native", "zero_rtt_handshake": true, "heartbeat": "10s", "tls": {{"enabled": true, "server_name": "tu.example.com", "alpn": ["h3"]}}}},
    {{"type": "anytls", "tag": "AnyTLS", "server": "a.example.com", "server_port": 443, "password": "pw", "idle_session_check_interval": "30s", "idle_session_timeout": "1m", "min_idle_session": 1, "tls": {{"enabled": true, "server_name": "a.example.com"}}}},
    {{"type": "socks", "tag": "Socks", "server": "9.9.9.9", "server_port": 1080, "version": "5", "username": "u", "password": "p"}},
    {{"type": "http", "tag": "HTTP", "server": "8.8.8.8", "server_port": 8080, "username": "u", "password": "p", "tls": {{"enabled": true, "server_name": "proxy.example.com"}}}},
    {{"type": "ssh", "tag": "SSH", "server": "s.example.com", "server_port": 22, "user": "root", "password": "pw"}},
    {{"type": "snell", "tag": "Snell v6", "server": "sn.example.com", "server_port": 443, "version": 6, "psk": "pw", "mode": "unshaped", "reuse": true, "tcp_fast_open": true}},
    {{"type": "snell", "tag": "Snell v5", "server": "sn.example.com", "server_port": 444, "version": 5, "psk": "pw", "obfs_mode": "http", "obfs_host": "bing.com", "network": "tcp"}},
    {{"type": "snell", "tag": "Bad Snell", "server": "sn.example.com", "server_port": 445, "version": 6, "psk": "pw", "userkey": "u"}},
    {{"type": "wireguard", "tag": "WG Legacy", "server": "wg.example.com", "server_port": 51820, "local_address": ["10.0.0.2/32", "fd00::2/128"], "private_key": "{key}", "peer_public_key": "{key}", "reserved": [1, 2, 3], "mtu": 1408}},
    {{"type": "tor", "tag": "Tor"}},
    {{"type": "trojan", "tag": "Bad Cert", "server": "b.example.com", "server_port": 443, "password": "pw", "tls": {{"enabled": true, "certificate": "x"}}}},
    {{"type": "vmess", "tag": "Bad H1", "server": "b.example.com", "server_port": 80, "uuid": "{uuid}", "transport": {{"type": "http"}}}}
  ],
  "endpoints": [
    {{"type": "wireguard", "tag": "WG", "address": ["10.0.0.3/32"], "private_key": "{key}", "peers": [{{"address": "wg2.example.com", "port": 51820, "public_key": "{key}", "allowed_ips": ["0.0.0.0/0"], "persistent_keepalive_interval": 25}}]}}
  ],
  "route": {{"final": "proxy"}}
}}"#
    );
    let load = |_: &str| Some(text.clone());
    let c = parse_config_with(
        "proxy-providers: {sub: {type: file, path: sub.json}}\nproxy-groups: [{name: G, type: select, use: [sub]}]",
        &load,
    )
    .unwrap();
    assert_eq!(c.proxy_providers[0].error, None);
    assert_eq!(
        members_of(&c, "G"),
        [
            "SS",
            "SS Obfs",
            "SS STLS",
            "VM WS",
            "VLESS Reality",
            "VLESS HU",
            "Trojan gRPC",
            "Trojan H2",
            "Hy2",
            "Hy1",
            "TUIC",
            "AnyTLS",
            "Socks",
            "HTTP",
            "SSH",
            "Snell v6",
            "Snell v5",
            "WG Legacy",
            "WG"
        ],
        "{:?}",
        c.warnings
    );
    for reason in [
        "`tor` type",
        "tls.certificate",
        "http transport without TLS",
        "Snell userkey",
    ] {
        assert!(
            c.warnings.iter().any(|w| w.contains(reason)),
            "{reason}: {:?}",
            c.warnings
        );
    }
    let snell = &c.outbounds[c.outbound_index("Snell v6").unwrap()].kind;
    assert!(
        matches!(snell, OutboundKind::Snell(s) if s.version == 6 && s.mode == SnellMode::Unshaped && s.udp),
        "{snell:?}"
    );
    let stls = &c.outbounds[c.outbound_index("SS STLS").unwrap()];
    assert!(
        format!("{:?}", stls.kind).contains("st.example.com"),
        "{:?}",
        stls.kind
    );

    // 只有出站数组的写法
    let nodes = crate::singbox::parse_outbounds(
        r#"[{"type": "trojan", "server": "t.example.com", "server_port": 443, "password": "pw", "tls": {"enabled": true}}]"#,
    )
    .unwrap();
    assert_eq!(nodes.nodes.len(), 1);
    // 普通 JSON 不当作 sing-box
    assert!(crate::singbox::parse_outbounds(r#"{"proxies": []}"#).is_none());
}

#[test]
fn payload_rules_parse_without_warnings() {
    let yaml = r#"
rules:
  - AND,((URL-REGEX,^http:\/\/119\.29\.29\.90\/d\?),(USER-AGENT,%E5%98%80%E5%97%92%E5%87%BA%E8%A1%8C*)),DIRECT
  - AND,((DOMAIN-SUFFIX,spotify.com),(PROTOCOL,QUIC)),REJECT
  - USER-AGENT,Spotify*,DIRECT
  - URL-REGEX,^http://a\.test/ad,REJECT
  - PROTOCOL,HTTPS,DIRECT
  - MATCH,DIRECT
"#;
    let c = parse_config(yaml).unwrap();
    assert_eq!(c.rules.len(), 6, "{:?}", c.warnings);
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    assert!(matches!(c.rules[2].kind, RuleKind::UserAgent(ref u) if u == "Spotify*"));
    assert!(parse_config("rules: ['PROTOCOL,STUN,DIRECT']")
        .unwrap()
        .warnings
        .iter()
        .any(|w| w.contains("unsupported protocol")));
}
