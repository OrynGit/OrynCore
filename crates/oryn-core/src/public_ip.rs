//! 公网 IP 查询：结果作为 ECS 附加在发往上游的 DNS 查询中。

use std::net::IpAddr;
use std::rc::{Rc, Weak};
use std::time::Duration;

use log::{debug, info};
use oryn_config::IpCidr;
use oryn_http::{get, Options, OutboundConnector};

use crate::context::{EngineCtx, RuntimeState};

const REFRESH: Duration = Duration::from_secs(30 * 60);

pub fn spawn(ctx: &Rc<EngineCtx>, state: &Rc<RuntimeState>) {
    match state.config.dns.public_ip_url.clone() {
        Some(url) => state.spawn(run(ctx.clone(), Rc::downgrade(state), url)),
        None => ctx.dns.set_public_ecs(None),
    }
}

async fn run(ctx: Rc<EngineCtx>, state: Weak<RuntimeState>, url: String) {
    loop {
        let Some(st) = state.upgrade() else { return };
        let direct = st.routing.outbounds[st.config.direct_index()].clone();
        drop(st);
        let opts = Options {
            timeout: Duration::from_secs(10),
            max_body: 1024,
            ..Options::default()
        };
        match get(&OutboundConnector(direct), &url, &opts).await {
            Ok(resp) if resp.is_success() => match parse_ip(&resp.body) {
                Some(ip) => {
                    let subnet = subnet_of(ip);
                    if ctx.dns.public_ecs() != Some(subnet) {
                        info!("public IP subnet for ECS: {subnet}");
                    }
                    ctx.dns.set_public_ecs(Some(subnet));
                }
                None => debug!("public IP lookup returned no IP address"),
            },
            Ok(resp) => debug!("public IP lookup failed: HTTP {}", resp.status),
            Err(e) => debug!("public IP lookup failed: {e}"),
        }
        // 定期刷新；网络切换时提前刷新
        let notify = ctx.public_ip_refresh.clone();
        tokio::select! {
            _ = tokio::time::sleep(REFRESH) => {}
            _ = notify.notified() => {}
        }
    }
}

fn parse_ip(body: &[u8]) -> Option<IpAddr> {
    String::from_utf8_lossy(body)
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// IPv4 取 /24，IPv6 取 /56。
pub fn subnet_of(ip: IpAddr) -> IpCidr {
    let prefix = if ip.is_ipv4() { 24 } else { 56 };
    IpCidr::parse(&format!("{ip}/{prefix}"))
        .expect("合法的网段")
        .network()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        assert_eq!(
            parse_ip(b" 203.0.113.9\n"),
            Some("203.0.113.9".parse().unwrap())
        );
        assert_eq!(parse_ip(b"<html>"), None);
        assert_eq!(
            subnet_of("203.0.113.9".parse().unwrap()),
            IpCidr::parse("203.0.113.0/24").unwrap()
        );
        assert!(
            subnet_of("2001:db8::1".parse().unwrap()).contains("2001:db8:0:ff::1".parse().unwrap())
        );
    }
}
