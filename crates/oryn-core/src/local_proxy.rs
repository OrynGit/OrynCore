//! 本地 HTTP / SOCKS5 入站。
//!
//! 这是一个直接的 Flow 入站：解析完代理握手后马上交给 Router 和 Outbound，
//! 不经过 tun2socks，也不把流量重新送回 PacketTunnel。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;

use log::{debug, warn};
use oryn_config::TargetAddr;
use oryn_outbound::{resolve, BoxStream, PickMeta};
use oryn_router::{DomainSource, FlowContext, Network};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::context::EngineCtx;
use crate::options::LocalProxyOptions;
use crate::relay;

#[cfg(test)]
#[path = "local_proxy_admission_tests.rs"]
mod admission_tests;

const MAX_HEADER: usize = 16 * 1024;
const MAX_DOMAIN: usize = 255;

#[derive(Clone, Copy)]
enum ListenerKind {
    Http,
    Socks,
}

pub fn restart(ctx: &Rc<EngineCtx>) {
    if let Some(handle) = ctx.local_proxy_abort.borrow_mut().take() {
        handle.abort();
    }
    let options = ctx.local_proxy_options();
    if !options.enabled {
        return;
    }
    let handle = tokio::task::spawn_local(run(ctx.clone(), options));
    *ctx.local_proxy_abort.borrow_mut() = Some(handle.abort_handle());
}

async fn run(ctx: Rc<EngineCtx>, options: LocalProxyOptions) {
    let host = if options.allow_external {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    };
    let http = bind(host, options.http_port, ListenerKind::Http).await;
    let socks = bind(host, options.socks_port, ListenerKind::Socks).await;
    if http.is_none() && socks.is_none() {
        warn!("local proxy disabled: both listener ports failed to bind");
        return;
    }
    let http_task = accept_loop(ctx.clone(), http, ListenerKind::Http);
    let socks_task = accept_loop(ctx, socks, ListenerKind::Socks);
    tokio::join!(http_task, socks_task);
}

async fn bind(host: Ipv4Addr, port: u16, kind: ListenerKind) -> Option<TcpListener> {
    let address = SocketAddr::new(IpAddr::V4(host), port);
    match TcpListener::bind(address).await {
        Ok(listener) => {
            let name = match kind {
                ListenerKind::Http => "HTTP",
                ListenerKind::Socks => "SOCKS5",
            };
            debug!("local {name} proxy listening on {address}");
            Some(listener)
        }
        Err(error) => {
            let name = match kind {
                ListenerKind::Http => "HTTP",
                ListenerKind::Socks => "SOCKS5",
            };
            warn!("local {name} proxy failed to bind {address}: {error}");
            None
        }
    }
}

async fn accept_loop(ctx: Rc<EngineCtx>, listener: Option<TcpListener>, kind: ListenerKind) {
    let Some(listener) = listener else { return };
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                if let Some(operation) = admit(ctx.clone(), stream, peer, kind) {
                    tokio::task::spawn_local(operation);
                }
            }
            Err(error) => {
                warn!("local proxy accept failed: {error}");
                return;
            }
        }
    }
}

fn admit(
    ctx: Rc<EngineCtx>,
    stream: TcpStream,
    peer: SocketAddr,
    kind: ListenerKind,
) -> Option<impl std::future::Future<Output = ()>> {
    let Some(permit) = ctx.admission.try_tcp() else {
        if matches!(kind, ListenerKind::Http) {
            let _ = stream.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
        return None;
    };
    Some(async move {
        if let Some(Err(error)) = permit.run(handle(ctx, stream, peer, kind, permit.phase())).await {
            debug!("local proxy connection {peer} ended: {error}");
        }
    })
}

async fn handle(
    ctx: Rc<EngineCtx>,
    mut stream: TcpStream,
    peer: SocketAddr,
    kind: ListenerKind,
    phase: &crate::admission::Establishing,
) -> io::Result<()> {
    match kind {
        ListenerKind::Http => handle_http(&ctx, &mut stream, peer, phase).await,
        ListenerKind::Socks => handle_socks(&ctx, &mut stream, peer, phase).await,
    }
}

async fn handle_http(
    ctx: &Rc<EngineCtx>,
    stream: &mut TcpStream,
    peer: SocketAddr,
    phase: &crate::admission::Establishing,
) -> io::Result<()> {
    let request = read_headers(stream).await?;
    let (head, remainder) = split_headers(&request)?;
    let mut lines = head.split(|byte| *byte == b'\n');
    let request_line = lines
        .next()
        .ok_or_else(|| invalid_data("HTTP request line is missing"))?
        .strip_suffix(b"\r")
        .unwrap_or_default();
    let parts: Vec<&[u8]> = request_line.split(|byte| *byte == b' ').collect();
    if parts.len() < 3 {
        return http_error(stream, "400 Bad Request").await;
    }
    let method = String::from_utf8_lossy(parts[0]);
    let target_text = String::from_utf8_lossy(parts[1]);
    let version = parts[2];
    if method.eq_ignore_ascii_case("CONNECT") {
        let target = parse_authority(&target_text, 443)?;
        let (remote, conn) = open_flow(ctx, peer, &target).await?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if !remainder.is_empty() {
            let mut remote = remote;
            remote.write_all(remainder).await?;
            remote.flush().await?;
            phase.complete();
            relay::relay(stream, remote, &conn, &ctx.stats).await;
        } else {
            phase.complete();
            relay::relay(stream, remote, &conn, &ctx.stats).await;
        }
        return Ok(());
    }

    let url = url::Url::parse(&target_text)
        .map_err(|_| invalid_data("HTTP proxy requires an absolute URL or CONNECT"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return http_error(stream, "400 Bad Request").await;
    }
    let host = url
        .host_str()
        .ok_or_else(|| invalid_data("HTTP URL has no host"))?;
    let default_port = if url.scheme() == "https" { 443 } else { 80 };
    let port = url.port().unwrap_or(default_port);
    let target = TargetAddr::from_host(host, port);
    let (remote, conn) = open_flow(ctx, peer, &target).await?;
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let path = match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    let mut rewritten = Vec::with_capacity(request.len());
    rewritten.extend_from_slice(parts[0]);
    rewritten.push(b' ');
    rewritten.extend_from_slice(path.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(version);
    rewritten.extend_from_slice(b"\r\n");
    for line in head.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.eq_ignore_ascii_case(b"proxy-connection: keep-alive")
            || line.eq_ignore_ascii_case(b"proxy-connection: close")
        {
            continue;
        }
        if !line.is_empty() {
            rewritten.extend_from_slice(line);
            rewritten.extend_from_slice(b"\r\n");
        }
    }
    rewritten.extend_from_slice(b"\r\n");
    rewritten.extend_from_slice(remainder);
    let mut remote = remote;
    remote.write_all(&rewritten).await?;
    remote.flush().await?;
    phase.complete();
    relay::relay(stream, remote, &conn, &ctx.stats).await;
    Ok(())
}

async fn handle_socks(
    ctx: &Rc<EngineCtx>,
    stream: &mut TcpStream,
    peer: SocketAddr,
    phase: &crate::admission::Establishing,
) -> io::Result<()> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 {
        return Err(invalid_data("SOCKS version is not 5"));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await?;
        return Err(invalid_data("SOCKS5 no-authentication is required"));
    }
    stream.write_all(&[5, 0]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 5 || request[1] != 1 || request[2] != 0 {
        write_socks_reply(stream, 7).await?;
        return Err(invalid_data("SOCKS5 supports CONNECT only"));
    }
    let target = read_socks_target(stream, request[3]).await?;
    let (remote, conn) = match open_flow(ctx, peer, &target).await {
        Ok(value) => value,
        Err(error) => {
            write_socks_reply(stream, 5).await?;
            return Err(error);
        }
    };
    write_socks_reply(stream, 0).await?;
    phase.complete();
    relay::relay(stream, remote, &conn, &ctx.stats).await;
    Ok(())
}

async fn open_flow(
    ctx: &Rc<EngineCtx>,
    source: SocketAddr,
    target: &TargetAddr,
) -> io::Result<(BoxStream, crate::stats::ConnGuard)> {
    ctx.stats
        .tcp_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let state = ctx.state();
    let destination = match target {
        TargetAddr::Ip(address) => *address,
        TargetAddr::Domain(_, port) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), *port),
    };
    let mut flow = FlowContext::new(ctx.next_id(), Network::Tcp, source, destination);
    if let TargetAddr::Domain(domain, _) = target {
        flow.set_domain(domain.clone(), DomainSource::Explicit);
    }
    let decision = state.router().route(&flow);
    flow.route = Some(decision);
    let rule = state.router().rule_text(decision.rule);
    let start = state.routing.outbounds[decision.outbound].clone();
    let resolved = resolve(
        &start,
        &PickMeta {
            source: Some(source),
            target,
            network: Network::Tcp,
        },
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused, "rejected by policy group"))?;
    let conn = ctx.conns.register(&flow, resolved.chain.clone(), rule);
    conn.set_inbound("local-proxy");
    drop(state);
    if resolved.leaf.is_reject() {
        conn.set_error("Rejected by policy");
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "rejected by policy",
        ));
    }
    let started = std::time::Instant::now();
    let connected = tokio::select! {
        result = resolved.leaf.connect_tcp(target) => result,
        _ = conn.cancelled() => Err(io::Error::other("closed by policy switch")),
    };
    let remote = match connected {
        Ok(remote) => remote,
        Err(e) => {
            conn.set_error(&e);
            return Err(e);
        }
    };
    conn.set_actual_outbound(resolved.leaf.actual_tag());
    conn.set_connect_ms(started.elapsed());
    Ok((remote, conn))
}

async fn read_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut data = Vec::with_capacity(1024);
    let mut buffer = [0u8; 1024];
    while data.len() < MAX_HEADER {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy headers ended",
            ));
        }
        data.extend_from_slice(&buffer[..count]);
        if data.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(data);
        }
    }
    Err(invalid_data("proxy headers exceed the limit"))
}

fn split_headers(data: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err(invalid_data("proxy headers are incomplete"));
    };
    Ok((&data[..index], &data[index + 4..]))
}

fn parse_authority(value: &str, default_port: u16) -> io::Result<TargetAddr> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid_data("proxy target is empty"));
    }
    if value.starts_with('[') {
        let end = value
            .find(']')
            .ok_or_else(|| invalid_data("invalid IPv6 authority"))?;
        let host = &value[1..end];
        let port = value[end + 1..]
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .unwrap_or(default_port);
        if host.parse::<Ipv6Addr>().is_err() {
            return Err(invalid_data("invalid IPv6 authority"));
        }
        return Ok(TargetAddr::from_host(host, port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return Ok(TargetAddr::from_host(host, port));
        }
    }
    Ok(TargetAddr::from_host(value, default_port))
}

async fn read_socks_target(stream: &mut TcpStream, atyp: u8) -> io::Result<TargetAddr> {
    let host = match atyp {
        1 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V4(Ipv4Addr::from(bytes)).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            if length[0] as usize > MAX_DOMAIN {
                return Err(invalid_data("SOCKS5 domain is too long"));
            }
            let mut bytes = vec![0u8; length[0] as usize];
            stream.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).map_err(|_| invalid_data("SOCKS5 domain is invalid"))?
        }
        4 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V6(Ipv6Addr::from(bytes)).to_string()
        }
        _ => return Err(invalid_data("SOCKS5 address type is unsupported")),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(TargetAddr::from_host(&host, u16::from_be_bytes(port)))
}

async fn write_socks_reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

async fn http_error(stream: &mut TcpStream, status: &str) -> io::Result<()> {
    let body = format!("{status}\r\n");
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
