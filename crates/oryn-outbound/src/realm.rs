//! Hysteria Realm 客户端：经会合服务器（sing-box 1.14 的 `hysteria-realm` 服务）打洞，连接 NAT 后的 Hysteria2 服务端。
//!
//! 移植自 sagernet/sing-quic v0.7.0-beta.4（commit 4ab2eceaac81e073f53b22ec72ff56aaea89a3d1）：
//! hysteria2/realm/control.go（Connect）、punch.go、punch_engine.go（Punch、候选地址）、stun.go（Discover）、
//! hysteria2/internal/stun/stun.go，以及 hysteria2/client.go 的 offerNewRealm / realmDiscoverFamilies / realmRacePunch。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! 流程：每个地址族各开一个 UDP 套接字 → 向 STUN 服务器查询公网地址 → 带着地址与打洞元数据（nonce、混淆密钥）
//! 向会合服务器 `POST /v1/{realm}/connect` → 用返回的服务端地址与元数据在各套接字上并发打洞，先成功的胜出 →
//! QUIC 跑在胜出的套接字上。未移植端口映射（UPnP / NAT-PMP），mihomo 也没有对应配置。
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use oryn_config::{RealmSpec, TargetAddr, REALM_MAX_ADDRESSES};
use oryn_quic::Rendezvous;
use oryn_udp::{DatagramFactory, Datagrams};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::time::Instant;

use crate::{BoxStream, Dialer, Resolver};

const STUN_HEADER: usize = 20;
const STUN_COOKIE: u32 = 0x2112_A442;
const STUN_ATTEMPTS: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_secs(2),
    Duration::from_secs(4),
];
/// 解析后的 STUN 地址上限（每个配置项可能解析出多个地址）。
const MAX_STUN_ADDRS: usize = 16;

const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const PUNCH_HELLO: u8 = 0x01;
const PUNCH_ACK: u8 = 0x02;
const SALT: usize = 8;
const MAGIC: [u8; 8] = *b"HYRLMv1\0";
const NONCE: usize = 16;
const MIN_BODY: usize = MAGIC.len() + 1 + NONCE;
const MAX_PADDING: usize = 1024;
const SYMMETRIC_NAT_PORT_GAP: u16 = 4;
const SYMMETRIC_NAT_EXTRA_PORTS: u32 = 4;
const SYMMETRIC_NAT_MAX_PORTS_PER_HOST: usize = 32;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
/// 会合服务器响应体上限（与 sing-quic 的错误体上限一致）。
const MAX_RESPONSE: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct PunchMetadata {
    nonce: [u8; NONCE],
    obfs: [u8; 32],
}

pub(crate) struct Realm {
    spec: RealmSpec,
    resolver: Arc<dyn Resolver>,
    dialer: Arc<dyn Dialer>,
    datagrams: Arc<dyn DatagramFactory>,
}

impl Realm {
    pub(crate) fn new(
        spec: RealmSpec,
        resolver: Arc<dyn Resolver>,
        dialer: Arc<dyn Dialer>,
        datagrams: Arc<dyn DatagramFactory>,
    ) -> Self {
        Self {
            spec,
            resolver,
            dialer,
            datagrams,
        }
    }

    async fn stun_servers(&self) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        for server in &self.spec.stun_servers {
            match server {
                TargetAddr::Ip(addr) => out.push(*addr),
                TargetAddr::Domain(host, port) => {
                    if let Ok(ips) = self.resolver.resolve(host).await {
                        out.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, *port)));
                    }
                }
            }
        }
        let mut seen = HashSet::new();
        out.retain(|addr| seen.insert(*addr));
        out.truncate(MAX_STUN_ADDRS);
        out
    }

    /// `POST {path}/v1/{realm}/connect`：上报本端地址与打洞元数据，取回服务端地址与元数据。
    async fn connect(
        &self,
        addresses: &[SocketAddr],
        metadata: &PunchMetadata,
    ) -> io::Result<(Vec<SocketAddr>, PunchMetadata)> {
        let spec = &self.spec;
        let tcp = self
            .dialer
            .dial_tcp(&TargetAddr::from_host(&spec.host, spec.port))
            .await?;
        let io: BoxStream = if spec.tls {
            let name = spec.sni.as_deref().unwrap_or(&spec.host);
            Box::new(
                oryn_tls::connect_pinned(
                    tcp,
                    name,
                    &[b"h2"],
                    spec.skip_cert_verify,
                    spec.fingerprint,
                )
                .await?,
            )
        } else {
            tcp
        };
        let (client, connection) = h2::client::handshake(io).await.map_err(io::Error::other)?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let result = async {
            let body = serde_json::json!({
                "addresses": addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "nonce": hex(&metadata.nonce),
                "obfs": hex(&metadata.obfs),
            })
            .to_string();
            let authority = if spec.host.contains(':') {
                format!("[{}]:{}", spec.host, spec.port)
            } else {
                format!("{}:{}", spec.host, spec.port)
            };
            let uri = format!(
                "{}://{}{}/v1/{}/connect",
                if spec.tls { "https" } else { "http" },
                authority,
                spec.path,
                spec.realm_id
            );
            let mut request = http::Request::post(uri).header("content-type", "application/json");
            if !spec.token.is_empty() {
                request = request.header("authorization", format!("Bearer {}", spec.token));
            }
            let request = request.body(()).map_err(io::Error::other)?;
            let mut client = client.clone().ready().await.map_err(io::Error::other)?;
            let (response, mut send) = client
                .send_request(request, false)
                .map_err(io::Error::other)?;
            send.send_data(Bytes::from(body), true)
                .map_err(io::Error::other)?;
            let response = response.await.map_err(io::Error::other)?;
            let status = response.status();
            let mut recv = response.into_body();
            let mut data = Vec::new();
            while let Some(chunk) = recv.data().await {
                let chunk = chunk.map_err(io::Error::other)?;
                let _ = recv.flow_control().release_capacity(chunk.len());
                if data.len() + chunk.len() > MAX_RESPONSE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "realm response too large",
                    ));
                }
                data.extend_from_slice(&chunk);
            }
            let json: serde_json::Value =
                serde_json::from_slice(&data).unwrap_or(serde_json::Value::Null);
            if !status.is_success() {
                let code = json.get("error").and_then(|v| v.as_str()).unwrap_or("");
                let message = json.get("message").and_then(|v| v.as_str()).unwrap_or("");
                let kind = if status.as_u16() == 401 || status.as_u16() == 403 {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::Other
                };
                return Err(io::Error::new(
                    kind,
                    format!("realm connect {}/{code}: {message}", status.as_u16()),
                ));
            }
            parse_connect_response(&json)
        };
        let result = tokio::time::timeout(CONTROL_TIMEOUT, result)
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "realm connect timed out",
                ))
            });
        drop(client);
        driver.abort();
        result
    }
}

#[async_trait]
impl Rendezvous for Realm {
    async fn establish(&self) -> io::Result<(Arc<dyn Datagrams>, SocketAddr)> {
        let stun = self.stun_servers().await;
        if stun.is_empty() {
            return Err(io::Error::other("no STUN servers resolved"));
        }
        // 每个有 STUN 服务器的地址族开一个套接字，并发查询公网地址
        let mut discovery = tokio::task::JoinSet::new();
        for v6 in [false, true] {
            let servers: Vec<SocketAddr> =
                stun.iter().copied().filter(|a| a.is_ipv6() == v6).collect();
            if servers.is_empty() {
                continue;
            }
            let any = if v6 {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            };
            let Ok(udp) = self.datagrams.bind(any).await else {
                continue;
            };
            discovery.spawn(async move {
                let found = discover(udp.as_ref(), &servers).await;
                (udp, v6, found)
            });
        }
        let mut families = Vec::new();
        let mut local = Vec::new();
        let mut last = io::Error::other("realm STUN discovery failed");
        while let Some(joined) = discovery.join_next().await {
            let Ok((udp, v6, found)) = joined else {
                continue;
            };
            match found {
                Ok(addrs) => {
                    for addr in addrs {
                        if !local.contains(&addr) {
                            local.push(addr);
                        }
                    }
                    families.push((udp, v6));
                }
                Err(err) => last = err,
            }
        }
        if families.is_empty() {
            return Err(last);
        }
        // 按地址族交替排列再截断：v4 地址多时不能把 v6 全部截光（反之亦然）
        let (v4, v6): (Vec<SocketAddr>, Vec<SocketAddr>) =
            local.into_iter().partition(|a| a.is_ipv4());
        let mut local = Vec::with_capacity(v4.len() + v6.len());
        let (mut v4, mut v6) = (v4.into_iter(), v6.into_iter());
        loop {
            let (a, b) = (v4.next(), v6.next());
            if a.is_none() && b.is_none() {
                break;
            }
            local.extend(a);
            local.extend(b);
        }
        local.truncate(REALM_MAX_ADDRESSES);
        let metadata = random_metadata()?;
        let (peers, metadata) = self.connect(&local, &metadata).await?;
        // 各地址族并发打洞，先成功的胜出；其余套接字随任务结束释放
        let mut race = tokio::task::JoinSet::new();
        for (udp, v6) in families {
            let peers: Vec<SocketAddr> = peers
                .iter()
                .copied()
                .filter(|a| a.is_ipv6() == v6)
                .collect();
            race.spawn(async move {
                let result = punch(udp.as_ref(), &peers, &metadata).await;
                result.map(|peer| (udp, peer))
            });
        }
        let mut last = io::Error::other("realm punch failed");
        while let Some(joined) = race.join_next().await {
            match joined {
                Ok(Ok(winner)) => {
                    race.abort_all();
                    return Ok(winner);
                }
                Ok(Err(err)) => last = err,
                Err(_) => {}
            }
        }
        Err(last)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn random_metadata() -> io::Result<PunchMetadata> {
    let mut metadata = PunchMetadata {
        nonce: [0; NONCE],
        obfs: [0; 32],
    };
    let rng = SystemRandom::new();
    rng.fill(&mut metadata.nonce)
        .and_then(|_| rng.fill(&mut metadata.obfs))
        .map_err(|_| io::Error::other("system random source failed"))?;
    Ok(metadata)
}

fn parse_connect_response(
    json: &serde_json::Value,
) -> io::Result<(Vec<SocketAddr>, PunchMetadata)> {
    let invalid = |m: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("realm connect response: {m}"),
        )
    };
    let addresses = json
        .get("addresses")
        .and_then(|v| v.as_array())
        .ok_or_else(|| invalid("missing addresses"))?
        .iter()
        .take(REALM_MAX_ADDRESSES * 4)
        .filter_map(|v| v.as_str()?.parse::<SocketAddr>().ok())
        .map(|a| SocketAddr::new(canonical(a.ip()), a.port()))
        .collect::<Vec<_>>();
    let nonce = json
        .get("nonce")
        .and_then(|v| v.as_str())
        .and_then(unhex::<NONCE>)
        .ok_or_else(|| invalid("invalid nonce"))?;
    let obfs = json
        .get("obfs")
        .and_then(|v| v.as_str())
        .and_then(unhex::<32>)
        .ok_or_else(|| invalid("invalid obfs"))?;
    Ok((addresses, PunchMetadata { nonce, obfs }))
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

// ---------------------------------------------------------------------------
// STUN（RFC 5389 Binding，只读 XOR-MAPPED-ADDRESS）
// ---------------------------------------------------------------------------

fn binding_request() -> io::Result<([u8; STUN_HEADER], [u8; 12])> {
    let mut id = [0u8; 12];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| io::Error::other("system random source failed"))?;
    let mut raw = [0u8; STUN_HEADER];
    raw[0..2].copy_from_slice(&1u16.to_be_bytes());
    raw[4..8].copy_from_slice(&STUN_COOKIE.to_be_bytes());
    raw[8..].copy_from_slice(&id);
    Ok((raw, id))
}

/// 解析 STUN 响应，返回事务 ID 与 XOR-MAPPED-ADDRESS。
fn parse_binding_response(data: &[u8]) -> Option<([u8; 12], Option<SocketAddr>)> {
    if data.len() < STUN_HEADER || data[4..8] != STUN_COOKIE.to_be_bytes() {
        return None;
    }
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let body = data.get(STUN_HEADER..STUN_HEADER + len)?;
    let mut id = [0u8; 12];
    id.copy_from_slice(&data[8..STUN_HEADER]);
    let mut rest = body;
    while rest.len() >= 4 {
        let kind = u16::from_be_bytes([rest[0], rest[1]]);
        let value_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        let padded = (value_len + 3) & !3;
        if 4 + padded > rest.len() {
            return Some((id, None));
        }
        let value = &rest[4..4 + value_len];
        rest = &rest[4 + padded..];
        if kind != 0x0020 || value.len() < 4 {
            continue;
        }
        let port = u16::from_be_bytes([value[2], value[3]]) ^ (STUN_COOKIE >> 16) as u16;
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&STUN_COOKIE.to_be_bytes());
        key[4..].copy_from_slice(&id);
        let ip = match (value[1], value.len()) {
            (0x01, 8) => {
                let mut b = [0u8; 4];
                for i in 0..4 {
                    b[i] = value[4 + i] ^ key[i];
                }
                IpAddr::V4(Ipv4Addr::from(b))
            }
            (0x02, 20) => {
                let mut b = [0u8; 16];
                for i in 0..16 {
                    b[i] = value[4 + i] ^ key[i];
                }
                IpAddr::V6(Ipv6Addr::from(b))
            }
            _ => return Some((id, None)),
        };
        return Some((id, Some(SocketAddr::new(canonical(ip), port))));
    }
    Some((id, None))
}

/// 向每个 STUN 服务器发 Binding 请求，分三轮（0.5 / 2 / 4 秒）重发未应答的请求。
async fn discover(udp: &dyn Datagrams, servers: &[SocketAddr]) -> io::Result<Vec<SocketAddr>> {
    let mut requests = Vec::with_capacity(servers.len());
    for server in servers {
        let (raw, id) = binding_request()?;
        requests.push((*server, raw, id));
    }
    let mut pending: HashSet<[u8; 12]> = requests.iter().map(|r| r.2).collect();
    let mut found = Vec::new();
    let mut buf = vec![0u8; 1500];
    for attempt in STUN_ATTEMPTS {
        if pending.is_empty() {
            break;
        }
        for (server, raw, id) in &requests {
            if pending.contains(id) {
                let _ = udp.try_send_to(raw, *server);
            }
        }
        let deadline = Instant::now() + attempt;
        while !pending.is_empty() {
            let Ok(received) = tokio::time::timeout_at(deadline, udp.recv_from(&mut buf)).await
            else {
                break;
            };
            // 单次接收错误（如某个 STUN 服务器回 ICMP 不可达）不放弃整个地址族：进入下一轮重发，
            // 轮数有限，持续出错时最终按「没有响应」失败
            let Ok((n, _)) = received else {
                break;
            };
            let Some((id, addr)) = parse_binding_response(&buf[..n]) else {
                continue;
            };
            if !pending.remove(&id) {
                continue;
            }
            if let Some(addr) = addr {
                if !found.contains(&addr) {
                    found.push(addr);
                }
            }
        }
    }
    if found.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no STUN responses received",
        ));
    }
    Ok(found)
}

// ---------------------------------------------------------------------------
// 打洞包：salt(8) + 混淆后的 [magic(8) + type(1) + nonce(16) + padding(0..=1024)]
// ---------------------------------------------------------------------------

fn xor_obfuscate(key: &[u8; 32], salt: &[u8], body: &mut [u8]) {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(key);
    material[32..].copy_from_slice(salt);
    let digest = ring::digest::digest(&ring::digest::SHA256, &material);
    let key = digest.as_ref();
    for (i, byte) in body.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

fn encode_punch(kind: u8, metadata: &PunchMetadata) -> io::Result<Vec<u8>> {
    let mut random = vec![0u8; SALT + 2 + MAX_PADDING];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("system random source failed"))?;
    let padding =
        (usize::from(random[SALT]) << 8 | usize::from(random[SALT + 1])) % (MAX_PADDING + 1);
    let mut packet = vec![0u8; SALT + MIN_BODY + padding];
    packet[..SALT].copy_from_slice(&random[..SALT]);
    let (salt, body) = packet.split_at_mut(SALT);
    body[..MAGIC.len()].copy_from_slice(&MAGIC);
    body[MAGIC.len()] = kind;
    body[MAGIC.len() + 1..MIN_BODY].copy_from_slice(&metadata.nonce);
    body[MIN_BODY..].copy_from_slice(&random[SALT + 2..SALT + 2 + padding]);
    xor_obfuscate(&metadata.obfs, salt, body);
    Ok(packet)
}

fn decode_punch(data: &[u8], metadata: &PunchMetadata) -> Option<u8> {
    if data.len() < SALT + MIN_BODY || data.len() > SALT + MIN_BODY + MAX_PADDING {
        return None;
    }
    // 只需要解开固定部分
    let mut body = [0u8; MIN_BODY];
    body.copy_from_slice(&data[SALT..SALT + MIN_BODY]);
    xor_obfuscate(&metadata.obfs, &data[..SALT], &mut body);
    if body[..MAGIC.len()] != MAGIC || body[MAGIC.len() + 1..] != metadata.nonce {
        return None;
    }
    match body[MAGIC.len()] {
        kind @ (PUNCH_HELLO | PUNCH_ACK) => Some(kind),
        _ => None,
    }
}

/// 去重；IPv4 地址若端口相近（像对称 NAT 顺序分配），补上中间与之后的几个端口。
fn candidates(peers: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut out: Vec<SocketAddr> = peers
        .iter()
        .copied()
        .filter(|a| a.port() != 0 && seen.insert(*a))
        .collect();
    let mut hosts: Vec<(Ipv4Addr, Vec<u16>)> = Vec::new();
    for addr in &out {
        if let SocketAddr::V4(v4) = addr {
            match hosts.iter_mut().find(|(ip, _)| ip == v4.ip()) {
                Some((_, ports)) => ports.push(v4.port()),
                None => hosts.push((*v4.ip(), vec![v4.port()])),
            }
        }
    }
    for (ip, mut ports) in hosts {
        ports.sort_unstable();
        ports.dedup();
        if ports.len() < 2
            || ports
                .windows(2)
                .any(|w| w[1] - w[0] > SYMMETRIC_NAT_PORT_GAP)
        {
            continue;
        }
        let start = u32::from(ports[0]);
        let end = (u32::from(*ports.last().unwrap()) + SYMMETRIC_NAT_EXTRA_PORTS).min(65535);
        let mut added = 0;
        for port in start..=end {
            if added >= SYMMETRIC_NAT_MAX_PORTS_PER_HOST {
                break;
            }
            let addr = SocketAddr::new(IpAddr::V4(ip), port as u16);
            if seen.insert(addr) {
                out.push(addr);
                added += 1;
            }
        }
    }
    out
}

/// 每 100 毫秒向全部候选地址发 Hello，直到收到对端的 Hello（回 Ack）或 Ack；最多 10 秒。
async fn punch(
    udp: &dyn Datagrams,
    peers: &[SocketAddr],
    metadata: &PunchMetadata,
) -> io::Result<SocketAddr> {
    let targets = candidates(peers);
    if targets.is_empty() {
        return Err(io::Error::other("no compatible peer addresses"));
    }
    let deadline = Instant::now() + PUNCH_TIMEOUT;
    let mut next_send = Instant::now();
    let mut buf = vec![0u8; SALT + MIN_BODY + MAX_PADDING];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "realm punch timed out",
            ));
        }
        if now >= next_send {
            for target in &targets {
                let _ = udp.try_send_to(&encode_punch(PUNCH_HELLO, metadata)?, *target);
            }
            next_send = now + PUNCH_INTERVAL;
        }
        let Ok(received) =
            tokio::time::timeout_at(next_send.min(deadline), udp.recv_from(&mut buf)).await
        else {
            continue;
        };
        let (n, from) = received?;
        let from = SocketAddr::new(canonical(from.ip()), from.port());
        if let Some(kind) = decode_punch(&buf[..n], metadata) {
            if kind == PUNCH_HELLO {
                let _ = udp.try_send_to(&encode_punch(PUNCH_ACK, metadata)?, from);
            }
            return Ok(from);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punch_packet_roundtrip() {
        let metadata = random_metadata().unwrap();
        for kind in [PUNCH_HELLO, PUNCH_ACK] {
            let packet = encode_punch(kind, &metadata).unwrap();
            assert!(
                packet.len() >= SALT + MIN_BODY && packet.len() <= SALT + MIN_BODY + MAX_PADDING
            );
            assert_eq!(decode_punch(&packet, &metadata), Some(kind));
            let other = random_metadata().unwrap();
            assert_eq!(decode_punch(&packet, &other), None);
        }
    }

    #[test]
    fn stun_xor_mapped_address() {
        let (_, id) = binding_request().unwrap();
        let mut response = vec![0x01, 0x01, 0, 12];
        response.extend_from_slice(&STUN_COOKIE.to_be_bytes());
        response.extend_from_slice(&id);
        let port = 54321u16 ^ 0x2112;
        let ip = [203u8, 0, 113, 7];
        let cookie = STUN_COOKIE.to_be_bytes();
        response.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 0x01]);
        response.extend_from_slice(&port.to_be_bytes());
        for i in 0..4 {
            response.push(ip[i] ^ cookie[i]);
        }
        let (got_id, addr) = parse_binding_response(&response).unwrap();
        assert_eq!(got_id, id);
        assert_eq!(addr, Some("203.0.113.7:54321".parse().unwrap()));
        assert!(parse_binding_response(&response[..10]).is_none());
    }

    #[test]
    fn symmetric_nat_candidates() {
        let peers: Vec<SocketAddr> = vec![
            "1.2.3.4:1000".parse().unwrap(),
            "1.2.3.4:1002".parse().unwrap(),
        ];
        let out = candidates(&peers);
        // 1000..=1006 共 7 个
        assert_eq!(out.len(), 7);
        let spread: Vec<SocketAddr> = vec![
            "1.2.3.4:1000".parse().unwrap(),
            "1.2.3.4:2000".parse().unwrap(),
        ];
        assert_eq!(candidates(&spread).len(), 2);
    }

    #[test]
    fn connect_response() {
        let json = serde_json::json!({"addresses": ["127.0.0.1:5000", "[::1]:5001", "bad"], "nonce": "00".repeat(16), "obfs": "ff".repeat(32)});
        let (addrs, meta) = parse_connect_response(&json).unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(meta.obfs, [0xff; 32]);
        assert!(
            parse_connect_response(&serde_json::json!({"addresses": [], "nonce": "00"})).is_err()
        );
    }
}
