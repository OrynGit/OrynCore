use crate::stats::ConnView;
use oryn_config::{OutboundKind, OutboundSpec, TargetAddr};
use std::{collections::HashMap, hint::black_box, mem::size_of, time::Instant};

fn lookup(name: &str, outbounds: &[OutboundSpec]) -> Option<String> {
    outbounds.iter().find(|o| o.name == name)
        .and_then(|o| o.kind.server_addr()).map(ToString::to_string)
}

// 返回额外临时内存的粗估（非分配器测量）；不包含所有方案共有的结果 String。
fn linear(connections: &mut [ConnView], outbounds: &[OutboundSpec]) -> usize {
    for c in connections { c.server = lookup(&c.outbound, outbounds); }
    0
}

fn table_bytes<K, V>(table: &HashMap<K, V>) -> usize {
    // 按 7/8 装载率、2 次幂 bucket、每 bucket 一字节 control 估算。
    let buckets = if table.capacity() == 0 { 0 } else {
        (table.capacity() * 8 / 7).next_power_of_two()
    };
    size_of::<HashMap<K, V>>() + buckets * (size_of::<(K, V)>() + 1)
}

fn indexed(connections: &mut [ConnView], outbounds: &[OutboundSpec]) -> usize {
    let mut index = HashMap::with_capacity(outbounds.len());
    for o in outbounds { index.entry(o.name.as_str()).or_insert(o); }
    for c in connections {
        c.server = index.get(c.outbound.as_str())
            .and_then(|o| o.kind.server_addr()).map(ToString::to_string);
    }
    table_bytes(&index)
}

fn demand(connections: &mut [ConnView], outbounds: &[OutboundSpec]) -> usize {
    // 仅活到本次请求结束；最多 64 项（也不超过 connections 数）。
    // 满后继续查询已缓存项，新的名字走 linear，不逐出。
    let limit = connections.len().min(64);
    let mut cache: HashMap<&str, Option<String>> = HashMap::new();
    let mut strings = 0;
    for c in connections {
        c.server = if let Some(server) = cache.get(c.outbound.as_str()) {
            server.clone()
        } else {
            let server = lookup(&c.outbound, outbounds);
            if cache.len() < limit {
                let cached = server.clone();
                strings += cached.as_ref().map_or(0, String::capacity);
                cache.insert(&c.outbound, cached);
            }
            server
        };
    }
    assert!(cache.len() <= limit);
    table_bytes(&cache) + strings
}

fn last_name(connections: &mut [ConnView], outbounds: &[OutboundSpec]) -> usize {
    let mut last: Option<(&str, Option<String>)> = None;
    let mut peak = 0;
    for c in connections {
        c.server = match &last {
            Some((name, server)) if *name == c.outbound => server.clone(),
            _ => {
                let server = lookup(&c.outbound, outbounds);
                let cached = server.clone();
                peak = peak.max(cached.as_ref().map_or(0, String::capacity));
                last = Some((&c.outbound, cached));
                server
            }
        };
    }
    size_of::<Option<(&str, Option<String>)>>() + peak
}

type Candidate = fn(&mut [ConnView], &[OutboundSpec]) -> usize;
const CANDIDATES: [Candidate; 4] = [linear, indexed, demand, last_name];
const PATTERNS: [&str; 5] = ["first", "last", "spread", "hot8", "missing"];

fn fixtures(n: usize, nodes: usize, pattern: &str) -> (Vec<ConnView>, Vec<OutboundSpec>) {
    let outbounds = (0..nodes).map(|i| OutboundSpec {
        name: format!("test-node-{i:04}"), dialer: None,
        kind: OutboundKind::Http {
            server: TargetAddr::Domain(format!("node-{i}.example.invalid"), 443),
            auth: None, tls: None,
        },
    }).collect();
    let connections = (0..n).map(|i| ConnView {
        id: i as u64, network: "tcp", source: "127.0.0.1:1234".into(),
        destination: "192.0.2.1:443".into(), domain: None, domain_source: "none",
        rule: "MATCH".into(), outbound: if pattern == "missing" { "absent".into() } else {
            format!("test-node-{:04}", match pattern {
                "first" => 0,
                "last" => nodes - 1,
                "spread" => (i * 7919) % nodes,
                // 在整个节点表上均匀放置最多八个交错热点，而非只测前八项。
                "hot8" => (i % nodes.min(8)) * (nodes - 1) / (nodes.min(8) - 1).max(1),
                _ => unreachable!(),
            })
        },
        chain: vec![], started_at: 0.0, upload: 0, download: 0, state: "active",
        protocol: "tls", connect_ms: None, error: None, modified: false,
        inbound: "vif", closed_at: None, server: Some("stale:1".into()),
    }).collect();
    (connections, outbounds)
}

fn equivalent(n: usize, nodes: usize, pattern: &str, special: bool) {
    let (mut baseline, mut outbounds) = fixtures(n, nodes, pattern);
    if special {
        // 首个同名节点没有 server；不能错误地继续找第二个有 server 的节点。
        outbounds.insert(0, OutboundSpec {
            name: "test-node-0000".into(), dialer: None, kind: OutboundKind::Direct,
        });
        // 有 server 的重复名字也必须取首项。
        outbounds.push(OutboundSpec {
            name: format!("test-node-{:04}", nodes - 1), dialer: None,
            kind: OutboundKind::Http {
                server: TargetAddr::Domain("wrong.example.invalid".into(), 1),
                auth: None, tls: None,
            },
        });
    }
    linear(&mut baseline, &outbounds);
    let expected = serde_json::to_value(&baseline).unwrap();
    for candidate in CANDIDATES {
        let (mut connections, _) = fixtures(n, nodes, pattern);
        candidate(&mut connections, &outbounds);
        assert_eq!(serde_json::to_value(&connections).unwrap(), expected);
    }
    if n > 0 && pattern == "first" {
        assert_eq!(baseline[0].server.as_deref(), if special { None } else { Some("node-0.example.invalid:443") });
    }
    if pattern == "missing" { assert!(baseline.iter().all(|c| c.server.is_none())); }
}

#[test]
#[ignore = "dev-only bounded microbenchmark; no network"]
fn connection_servers_benchmark() {
    let total = Instant::now();
    println!("dev; 5 rounds x 10 requests; median ns/request; order linear,indexed,demand64,last-name; bytes=estimated extra peak");
    for n in [0, 1, 16, 500] {
        for nodes in [1, 8, 1000] {
            for pattern in PATTERNS {
                equivalent(n, nodes, pattern, false);
                equivalent(n, nodes, pattern, true);
                let (mut connections, outbounds) = fixtures(n, nodes, pattern);
                let mut times = [Vec::with_capacity(5), Vec::with_capacity(5), Vec::with_capacity(5), Vec::with_capacity(5)];
                let mut bytes = [0; 4];
                for round in 0..5 {
                    // 轮换顺序；每次调用都新建/销毁请求级缓存。
                    for offset in 0..4 {
                        let which = (round + offset) % 4;
                        let start = Instant::now();
                        for _ in 0..10 {
                            bytes[which] = black_box(CANDIDATES[which](
                                black_box(&mut connections), black_box(&outbounds)));
                            black_box(&connections);
                        }
                        times[which].push(start.elapsed().as_nanos() / 10);
                    }
                }
                for t in &mut times { t.sort(); }
                println!("n={n} nodes={nodes} {pattern} ns={:?} bytes={bytes:?}", times.map(|t| t[2]));
                assert!(total.elapsed().as_secs() < 30, "measurement budget exceeded");
            }
        }
    }
    println!("full JSON equivalence: 120 fixtures x 4 candidates; elapsed={:?}", total.elapsed());
}
