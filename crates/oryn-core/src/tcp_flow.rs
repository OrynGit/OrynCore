//! TCP Flow：`Flow → 嗅探 → Router → 策略组 → Outbound → relay`。

use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use log::{debug, info, warn};
use oryn_config::TargetAddr;
use oryn_netstack::LwipTcpStream;
use oryn_outbound::{resolve, PickMeta};
use oryn_router::{DomainSource, FlowContext, Network};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::context::EngineCtx;
use crate::{relay, sniff};

/// DNS over TCP 连接的空闲超时。
const DNS_TCP_IDLE: Duration = Duration::from_secs(30);

/// 同步 factory：未 poll / 取消同样归还额度。
/// 额度不足时连接（lwIP 已完成握手）进入有界等待队列，等额度释放后继续；队列满或等待超时才 RST。
pub fn admit(ctx: Rc<EngineCtx>, stream: LwipTcpStream) -> Option<impl std::future::Future<Output = ()>> {
    let destination = stream.destination();
    let dns = ctx.is_dns_target(destination.ip(), destination.port());
    let mut tcp_permit = if dns { None } else { ctx.admission.try_tcp() };
    let dns_permit = if dns { ctx.admission.try_dns() } else { None };
    let wait_slot = if !dns && tcp_permit.is_none() { ctx.admission.try_wait_slot() } else { None };
    if tcp_permit.is_none() && dns_permit.is_none() && wait_slot.is_none() {
        stream.abort();
        return None;
    }
    Some(async move {
        if let Some(slot) = wait_slot {
            tcp_permit = ctx.admission.wait_tcp(slot).await;
            if tcp_permit.is_none() {
                stream.abort();
                return;
            }
        }
        if let Some(permit) = tcp_permit {
            permit.run(handle(ctx, stream, permit.phase())).await;
        } else {
            let _permit = dns_permit;
            let source = stream.source();
            let id = ctx.next_id();
            ctx.stats.tcp_total.fetch_add(1, Ordering::Relaxed);
            dns_over_tcp(ctx, stream, id, source).await;
        }
    })
}

async fn handle(ctx: Rc<EngineCtx>, mut stream: LwipTcpStream, phase: &crate::admission::Establishing) {
    let source = stream.source();
    let destination = stream.destination();
    let id = ctx.next_id();
    ctx.stats.tcp_total.fetch_add(1, Ordering::Relaxed);

    if destination.ip() == std::net::IpAddr::V4(crate::virtual_interface::SELF_V4) {
        self_loopback(ctx, stream, phase, id, source, destination).await;
        return;
    }
    if destination.ip() == std::net::IpAddr::V4(crate::virtual_interface::SYNTHETIC_V4) {
        synthetic_endpoint(ctx, stream, phase, id, source, destination).await;
        return;
    }
    if crate::virtual_interface::is_tunnel_subnet(destination.ip()) {
        warn!("TCP #{id} {source} → {destination} is inside the tunnel subnet; reset");
        stream.abort();
        return;
    }

    let state = ctx.state();
    let fake_ip = ctx.dns.is_fake_ip(&destination.ip());
    let mut flow = FlowContext::new(id, Network::Tcp, source, destination);
    if fake_ip {
        if let Some(domain) = ctx.dns.lookup_fake_domain(&destination.ip()) {
            flow.set_domain(domain, DomainSource::FakeIp);
        }
    } else if let Some(domain) = ctx.dns.lookup_domain(&destination.ip()) {
        flow.set_domain(domain, DomainSource::DnsMapping);
    }

    // 路由之前嗅探首包；读到的数据稍后原样转发。
    // 映射缺失时仍读首包：系统解析器会缓存 Fake-IP，TLS SNI / HTTP Host 还能把连接接回去。
    let (sniffed, mut first) = if fake_ip && flow.domain.is_some() {
        (None, Vec::new())
    } else if fake_ip {
        let (domain, bytes) = sniff::recover_tcp_domain(&mut stream).await;
        if let Some(domain) = domain {
            warn!("TCP #{id} {source} → {destination} Fake-IP mapping missing; recovered {domain}");
            ctx.dns.remember_fake_ip(&destination.ip(), &domain);
            flow.set_domain(domain, DomainSource::Sniffed);
        }
        (None, bytes)
    } else {
        sniff::sniff_tcp(&mut stream, &state.config.sniffer, &flow).await
    };
    if fake_ip && flow.domain.is_none() {
        warn!("TCP #{id} {source} → {destination} Fake-IP mapping missing; reset");
        stream.abort();
        return;
    }

    // 仅在当前规则表确实会走到 IP 类规则时解析一次真实地址。
    if fake_ip && state.router().needs_ip_resolution(&flow) {
        if let Some(domain) = flow.domain.clone() {
            if let Ok(ips) = ctx.dns.resolve_direct_target(&domain).await {
                if let Some(ip) = ips.into_iter().next() {
                    flow.destination = SocketAddr::new(ip, destination.port());
                }
            }
        }
    }
    let mut override_destination = false;
    if let Some(s) = sniffed {
        flow.set_domain(s.domain, DomainSource::Sniffed);
        override_destination = s.override_destination;
    }

    // PROTOCOL / USER-AGENT / URL-REGEX 等规则看首包；前面的规则已能决定时不读
    if state.router().needs_payload(&flow) {
        sniff::read_payload(&mut stream, &mut first, &mut flow).await;
    }

    // 一个 Flow 只匹配一次。包名只在 Android 上查得到。
    flow.package = crate::android_package::lookup(&flow);
    let decision = state.router().route(&flow);
    flow.route = Some(decision);
    let rule = state.router().rule_text(decision.rule);
    let target = match (&flow.domain, fake_ip || override_destination) {
        (Some(d), true) => TargetAddr::Domain(d.clone(), destination.port()),
        _ => TargetAddr::Ip(destination),
    };
    let start = state.routing.outbounds[decision.outbound].clone();
    let resolved = resolve(
        &start,
        &PickMeta {
            source: Some(source),
            target: &target,
            network: Network::Tcp,
        },
    );
    let label = sniff::label(&flow, destination);
    let Some(resolved) = resolved else {
        debug!("TCP #{id} {source} → {label} matched {rule} → rejected by group");
        stream.abort();
        return;
    };
    let chain = resolved.chain.join(" → ");
    debug!("TCP #{id} {source} → {label} matched {rule} → {chain}");
    let conn = Rc::new(ctx.conns.register(&flow, resolved.chain.clone(), rule));
    if first.first() == Some(&22) {
        conn.set_protocol("tls");
    } else if sniff::looks_like_http(&first) {
        conn.set_protocol("http");
    }

    if resolved.leaf.is_reject() {
        conn.set_error("Rejected by policy");
        stream.abort();
        return;
    }

    let mut tls_host = Some(
        flow.domain
            .clone()
            .unwrap_or_else(|| destination.ip().to_string()),
    );
    let mut mitm = tls_host
        .as_deref()
        .is_some_and(|h| state.config.mitm.matches(h, destination.port()));
    let list_match = |items: &[String]| {
        items.iter().any(|s| {
            oryn_config::listed_host_matches(
                s,
                flow.domain.as_deref(),
                destination.port(),
                oryn_config::ListedPort::Connection,
            )
        })
    };
    let raw = list_match(&state.config.raw_tcp_hosts);
    mitm &= !raw;
    let inspect = !raw
        && (mitm
            || state.config.mitm.enabled && destination.port() == 443
            || !state.http_plan.is_empty() && matches!(destination.port(), 80 | 443 | 8080)
            || list_match(&state.config.force_http_hosts));
    if inspect && first.is_empty() {
        let mut buf = [0u8; 4096];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await
        {
            first.extend_from_slice(&buf[..n]);
        }
    }
    if inspect && first.first() == Some(&22) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            match oryn_sniff::sniff_tls(&first) {
                oryn_sniff::Sniff::Found(host) => {
                    mitm = state.config.mitm.matches(&host, destination.port());
                    tls_host = Some(host);
                    break;
                }
                oryn_sniff::Sniff::NeedMore if first.len() < 16384 => {
                    let mut buf = [0u8; 2048];
                    match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
                        Ok(Ok(n)) if n > 0 => first.extend_from_slice(&buf[..n]),
                        _ => break,
                    }
                }
                _ => break,
            }
        }
    }
    // 之前握手失败（证书固定 App、超时）的主机暂时直通，不再解密。
    if mitm {
        if let Some(h) = tls_host.as_deref() {
            if ctx.mitm_bypassed(h, destination.port()) {
                debug!("TCP #{id} {label} MITM bypassed after an earlier handshake failure");
                mitm = false;
            }
        }
    }
    // 在证书创建之前取得 inspection 额度；容量拒绝不进入 bypass。
    let clear_http = inspect && sniff::looks_like_http(&first);
    let mut inspection_permit = if clear_http || mitm && first.first() == Some(&22) {
        match ctx.http_connections.as_ref() {
            // 额度满时等一会儿（其他检查连接结束即放行），超时才 RST；等待期间仍持有 establishing 额度，受 30 秒建立期限约束
            Some(semaphore) => match tokio::time::timeout(
                crate::admission::patience(8),
                semaphore.clone().acquire_owned(),
            )
            .await
            {
                Ok(Ok(permit)) => Some(permit),
                _ => { stream.abort(); return; }
            },
            None => None,
        }
    } else { None };
    // 还没向客户端发送任何数据前取得证书配置；失败时整条连接直通，不断流。
    let mut mitm_config = None;
    if mitm && first.first() == Some(&22) {
        let host = tls_host.clone().unwrap_or_else(|| destination.ip().to_string());
        let config = state
            .mitm_ca
            .borrow_mut()
            .as_mut()
            .ok_or_else(|| io::Error::other("MITM enabled without a valid CA"))
            .and_then(|c| c.server_config(&host, state.config.mitm.http2));
        match config {
            Ok(c) => mitm_config = Some(c),
            Err(e) => {
                warn!("TCP #{id} {label} MITM unavailable, passing through: {e}");
                mitm = false;
                inspection_permit.take();
            }
        }
    }
    if clear_http {
        conn.set_protocol("http");
    } else if inspect && first.first() == Some(&22) {
        conn.set_protocol("tls");
    }
    if clear_http || mitm && first.first() == Some(&22) {
        if mitm {
            conn.set_modified();
        }
        let mut cancel = state.inspection_cancel.subscribe();
        let host = tls_host.unwrap_or_else(|| destination.ip().to_string());
        let authority = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let origin = format!(
            "{}://{}:{}",
            if mitm { "https" } else { "http" },
            authority,
            destination.port()
        );
        let inspector = crate::http::Inspector {
            scripts: state.scripts.clone(),
            plan: state.http_plan.clone(),
            outbound: resolved.leaf.clone(),
            origin,
            skip_verify: state.config.mitm.skip_server_cert_verify,
            transactions: state.http_transactions.clone(),
            upstream_establish: ctx.http_upstream_establish.clone(),
            bodies: state.http_bodies.clone(),
        };
        let io = crate::http::FlowIo::new(first, stream, conn.clone(), ctx.stats.clone());
        let operation = async {
            if let Some(config) = mitm_config {
                let timeout_ctx = ctx.clone();
                let timeout_host = host.clone();
                phase.on_timeout(move || timeout_ctx.bypass_mitm(&timeout_host, destination.port()));
                let handshake = tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio_rustls::TlsAcceptor::from(config).accept(io),
                )
                .await;
                phase.clear_timeout();
                let failure = match handshake {
                    Ok(Ok(tls)) => {
                        let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
                        phase.complete();
                        return inspector.serve(tls, h2).await;
                    }
                    Ok(Err(e)) => e,
                    Err(_) => io::Error::new(io::ErrorKind::TimedOut, "MITM TLS handshake timeout"),
                };
                // ServerHello 已发出，这条连接无法再直通；之后到该主机的连接直通（与 Surge 一致，
                // 证书固定的 App 重试即可恢复）。
                ctx.bypass_mitm(&host, destination.port());
                Err(io::Error::new(
                    failure.kind(),
                    format!("{failure}; {host} passes through without MITM for 10 minutes"),
                ))
            } else {
                phase.complete();
                inspector.serve(io, false).await
            }
        };
        let result = tokio::select! { result=operation=>result, _=async{while !*cancel.borrow(){if cancel.changed().await.is_err(){break}}}=>Ok(()), _=conn.cancelled()=>Ok(()) };
        if let Err(e) = result {
            conn.set_error(&e);
            warn!("TCP #{id} {label} HTTP inspection: {e}");
        }
        return;
    }
    drop(state);
    let connect_started = std::time::Instant::now();
    let connected = tokio::select! {
        result = resolved.leaf.connect_tcp(&target) => result,
        _ = conn.cancelled() => Err(io::Error::other("closed by policy switch")),
    };
    match connected {
        Ok(remote) => {
            conn.set_actual_outbound(resolved.leaf.actual_tag());
            conn.set_connect_ms(connect_started.elapsed());
            ctx.local_ipv6.connected(destination.ip());
            let mut remote = remote;
            if !first.is_empty() {
                if let Err(e) = async {
                    remote.write_all(&first).await?;
                    remote.flush().await
                }
                .await
                {
                    warn!("TCP #{id} {label} via {chain}: {e}");
                    conn.set_error(&e);
                    stream.abort();
                    return;
                }
                conn.add_up(first.len() as u64);
                ctx.stats.add_up(first.len() as u64);
            }
            phase.complete();
            let started = std::time::Instant::now();
            let end = relay::relay(stream, crate::offload::Offload::new(remote), &conn, &ctx.stats).await;
            let ms = |d: Option<u64>| d.map_or_else(|| "-".to_string(), |v| format!("{v} ms"));
            let summary = format!(
                "TCP #{id} {label} via {chain} ended: {} (up {} B, down {} B, {:.1}s, connect {}, first byte {})",
                end.reason,
                conn.up_bytes(),
                conn.down_bytes(),
                started.elapsed().as_secs_f32(),
                ms(conn.connect_ms()),
                ms(end.first_down.map(|d| d.as_millis() as u64)),
            );
            if end.abnormal {
                conn.set_error(&end.reason);
                warn!("{summary}");
            } else {
                debug!("{summary}");
            }
        }
        Err(e) => {
            ctx.local_ipv6
                .connect_failed(&ctx, destination.ip(), &e, connect_started.elapsed());
            warn!("TCP #{id} {label} via {chain} failed to connect: {e}");
            conn.set_error(&e);
            stream.abort();
        }
    }
    drop(conn);
}

/// 隧道内自回环：完整经过 utun → Netstack → relay，再由本机直连 `127.0.0.1`，不经规则、嗅探与出站绑定接口。
/// 用于测量隧道自身吞吐；本机任何进程本可直连回环，不扩大可达范围。
async fn self_loopback(
    ctx: Rc<EngineCtx>,
    stream: LwipTcpStream,
    phase: &crate::admission::Establishing,
    id: u64,
    source: SocketAddr,
    destination: SocketAddr,
) {
    let target = SocketAddr::from(([127, 0, 0, 1], destination.port()));
    let flow = FlowContext::new(id, Network::Tcp, source, destination);
    let conn = Rc::new(ctx.conns.register(&flow, vec!["DIRECT".into()], "LOOPBACK".into()));
    let connect_started = std::time::Instant::now();
    let connected = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(target)) => {
            result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "loopback connect timeout")))
        }
        _ = conn.cancelled() => Err(io::Error::other("closed by policy switch")),
    };
    match connected {
        Ok(remote) => {
            let _ = remote.set_nodelay(true);
            conn.set_connect_ms(connect_started.elapsed());
            phase.complete();
            let end = relay::relay(stream, crate::offload::Offload::new(Box::new(remote)), &conn, &ctx.stats).await;
            if end.abnormal {
                conn.set_error(&end.reason);
            }
            debug!("TCP #{id} {source} → {destination} (loopback {target}) ended: {}", end.reason);
        }
        Err(e) => {
            debug!("TCP #{id} {source} → {destination} loopback to {target} failed: {e}");
            conn.set_error(&e);
            stream.abort();
        }
    }
}

async fn dns_over_tcp(ctx: Rc<EngineCtx>, mut stream: LwipTcpStream, id: u64, source: SocketAddr) {
    let result: io::Result<()> = async {
        loop {
            tokio::time::timeout(DNS_TCP_IDLE, async {
            let len = stream.read_u16().await? as usize;
            let mut query = vec![0u8; len];
            stream.read_exact(&mut query).await?;
            ctx.stats.dns_queries.fetch_add(1, Ordering::Relaxed);
            let (resp, _) = ctx.dns.handle_query(&query, source).await;
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            out.extend_from_slice(&resp);
            stream.write_all(&out).await?;
            Ok::<_, io::Error>(())
            }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP operation timeout"))??;
        }
    }
    .await;
    if let Err(e) = result {
        info!("DNS over TCP #{id} ended: {e}");
    }
}

/// `SYNTHETIC_V4`：内存里的吞吐源 / 汇，只用来测隧道自身（见 `synthetic.rs`）。
async fn synthetic_endpoint(
    ctx: Rc<EngineCtx>,
    stream: LwipTcpStream,
    phase: &crate::admission::Establishing,
    id: u64,
    source: SocketAddr,
    destination: SocketAddr,
) {
    let flow = FlowContext::new(id, Network::Tcp, source, destination);
    let conn = Rc::new(ctx.conns.register(&flow, vec!["DIRECT".into()], "SYNTHETIC".into()));
    phase.complete();
    let end = relay::relay(stream, crate::synthetic::SyntheticStream::default(), &conn, &ctx.stats).await;
    if end.abnormal {
        conn.set_error(&end.reason);
    }
    debug!("TCP #{id} {source} → {destination} (synthetic) ended: {}", end.reason);
}
