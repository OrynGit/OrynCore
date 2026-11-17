//! 在路由之前嗅探域名（`sniffer` 配置）。

use std::net::SocketAddr;
use std::time::Duration;

use oryn_config::SnifferSpec;
use oryn_netstack::LwipTcpStream;
use oryn_router::{DomainSource, FlowContext, HttpRequestInfo};
use oryn_sniff::{sniff_http, sniff_tls, Head, QuicSniffer, Sniff};
use tokio::io::AsyncReadExt;

/// 等待首包的最长时间。
pub const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
/// 嗅探最多读取的字节数。
pub const SNIFF_MAX: usize = 16 * 1024;
/// QUIC 嗅探最多缓存的数据报个数。
pub const SNIFF_MAX_DATAGRAMS: usize = 8;

pub fn looks_like_http(first: &[u8]) -> bool {
    first.starts_with(b"GET ")
        || first.starts_with(b"POST ")
        || first.starts_with(b"PUT ")
        || first.starts_with(b"PATCH ")
        || first.starts_with(b"DELETE ")
        || first.starts_with(b"HEAD ")
        || first.starts_with(b"OPTIONS ")
}

/// 嗅探结果：域名，以及是否用它改写连接目标。
pub struct Sniffed {
    pub domain: String,
    pub override_destination: bool,
}

/// 是否需要对该连接嗅探（不看端口）。
fn eligible(spec: &SnifferSpec, flow: &FlowContext) -> bool {
    if !spec.enable {
        return false;
    }
    if spec.skip_src.iter().any(|c| c.contains(flow.source.ip()))
        || spec
            .skip_dst
            .iter()
            .any(|c| c.contains(flow.destination.ip()))
    {
        return false;
    }
    match flow.domain.as_deref() {
        Some(d) if flow.domain_source == DomainSource::DnsMapping => {
            spec.force_dns_mapping || spec.force_domain.iter().any(|p| p.matches(d))
        }
        Some(_) => true,
        None => spec.parse_pure_ip,
    }
}

fn accept(spec: &SnifferSpec, domain: String, override_destination: bool) -> Option<Sniffed> {
    if spec.skip_domain.iter().any(|p| p.matches(&domain)) {
        return None;
    }
    Some(Sniffed {
        domain,
        override_destination,
    })
}

/// TCP：读取首批数据尝试解析 TLS SNI 或 HTTP Host。已读取的数据通过返回值交回，必须原样转发。
pub async fn sniff_tcp(
    stream: &mut LwipTcpStream,
    spec: &SnifferSpec,
    flow: &FlowContext,
) -> (Option<Sniffed>, Vec<u8>) {
    let port = flow.destination.port();
    let (tls, http) = (spec.tls.applies(port), spec.http.applies(port));
    if !(tls || http) || !eligible(spec, flow) {
        return (None, Vec::new());
    }
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        let n = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return (None, buf),
        };
        buf.extend_from_slice(&chunk[..n]);
        let mut need_more = false;
        for (enabled, result, over) in [
            (
                tls,
                if tls {
                    sniff_tls(&buf)
                } else {
                    Sniff::NotMatch
                },
                spec.tls.override_destination,
            ),
            (
                http,
                if http {
                    sniff_http(&buf)
                } else {
                    Sniff::NotMatch
                },
                spec.http.override_destination,
            ),
        ] {
            if !enabled {
                continue;
            }
            match result {
                Sniff::Found(d) => return (accept(spec, d, over), buf),
                Sniff::NeedMore => need_more = true,
                Sniff::NotMatch => {}
            }
        }
        if !need_more || buf.len() >= SNIFF_MAX {
            return (None, buf);
        }
    }
}

/// Fake-IP 映射缺失时恢复域名。不看嗅探开关：系统 DNS 缓存可能还拿着旧地址。
pub async fn recover_tcp_domain(stream: &mut LwipTcpStream) -> (Option<String>, Vec<u8>) {
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        let n = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return (None, buf),
        };
        buf.extend_from_slice(&chunk[..n]);
        let mut need_more = false;
        for result in [sniff_tls(&buf), sniff_http(&buf)] {
            match result {
                Sniff::Found(domain) => return (Some(domain), buf),
                Sniff::NeedMore => need_more = true,
                Sniff::NotMatch => {}
            }
        }
        if !need_more || buf.len() >= SNIFF_MAX {
            return (None, buf);
        }
    }
}

/// 规则要看首包时（`Router::needs_payload`）补读首批数据并填入 Flow：TLS 记录头即可判断，
/// 明文 HTTP 读到请求头结束。读到的数据追加到 `first`，必须原样转发。
pub async fn read_payload(stream: &mut LwipTcpStream, first: &mut Vec<u8>, flow: &mut FlowContext) {
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    let mut chunk = vec![0u8; 4096];
    let mut last = false;
    loop {
        if !first.is_empty() && first[0] == 22 {
            flow.is_tls = true;
            return;
        }
        match oryn_sniff::http_head(first, last || first.len() >= SNIFF_MAX) {
            Head::Found(head) => {
                flow.http = Some(http_info(head, flow));
                return;
            }
            Head::NotHttp => return,
            Head::NeedMore if last => return,
            Head::NeedMore => {}
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => first.extend_from_slice(&chunk[..n]),
            _ => last = true,
        }
    }
}

/// `URL-REGEX` 匹配的完整地址：代理式目标原样，否则 `http://` + Host（缺省用域名或目的地址）+ 路径。
fn http_info(head: oryn_sniff::HttpHead, flow: &FlowContext) -> HttpRequestInfo {
    let url = if head.target.starts_with("http://") || head.target.starts_with("https://") {
        head.target
    } else {
        let port = flow.destination.port();
        let host = head.host.unwrap_or_else(|| {
            let name = flow
                .domain
                .clone()
                .unwrap_or_else(|| match flow.destination.ip() {
                    std::net::IpAddr::V6(ip) => format!("[{ip}]"),
                    ip => ip.to_string(),
                });
            if port == 80 {
                name
            } else {
                format!("{name}:{port}")
            }
        });
        format!("http://{host}{}", head.target)
    };
    HttpRequestInfo {
        url,
        user_agent: head.user_agent,
    }
}

/// UDP：是否需要对该会话做 QUIC 嗅探。
pub fn quic_applies(spec: &SnifferSpec, flow: &FlowContext) -> bool {
    spec.quic.applies(flow.destination.port()) && eligible(spec, flow)
}

/// UDP：输入会话的首批数据报，直到解析出 SNI、确定不是 QUIC 或达到上限。
pub struct QuicProbe {
    sniffer: QuicSniffer,
    pub datagrams: Vec<Vec<u8>>,
    done: bool,
}

impl QuicProbe {
    pub fn new() -> Self {
        QuicProbe {
            sniffer: QuicSniffer::new(),
            datagrams: Vec::new(),
            done: false,
        }
    }

    /// 不套用嗅探配置，只从 QUIC Initial 里取 SNI。
    pub fn push_any(&mut self, payload: Vec<u8>) -> Option<Option<String>> {
        let result = self.sniffer.push(&payload);
        self.datagrams.push(payload);
        match result {
            Sniff::Found(domain) => {
                self.done = true;
                Some(Some(domain))
            }
            Sniff::NotMatch => {
                self.done = true;
                Some(None)
            }
            Sniff::NeedMore if self.datagrams.len() >= SNIFF_MAX_DATAGRAMS => {
                self.done = true;
                Some(None)
            }
            Sniff::NeedMore => None,
        }
    }

    /// 返回 `Some` 表示嗅探结束（`Some(None)` 为未得到域名）。
    pub fn push(&mut self, spec: &SnifferSpec, payload: Vec<u8>) -> Option<Option<Sniffed>> {
        let r = self.sniffer.push(&payload);
        self.datagrams.push(payload);
        match r {
            Sniff::Found(d) => {
                self.done = true;
                Some(accept(spec, d, spec.quic.override_destination))
            }
            Sniff::NotMatch => {
                self.done = true;
                Some(None)
            }
            Sniff::NeedMore if self.datagrams.len() >= SNIFF_MAX_DATAGRAMS => {
                self.done = true;
                Some(None)
            }
            Sniff::NeedMore => None,
        }
    }
}

impl Default for QuicProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// 日志中展示的目标。
pub fn label(flow: &FlowContext, destination: SocketAddr) -> String {
    match &flow.domain {
        Some(d) => format!("{d} ({destination})"),
        None => destination.to_string(),
    }
}

#[cfg(test)]
mod payload_tests {
    use super::*;
    use oryn_router::Network;

    #[test]
    fn http_url_from_host_or_destination() {
        let mut flow = FlowContext::new(
            1,
            Network::Tcp,
            "10.0.0.2:5000".parse().unwrap(),
            "119.29.29.90:8080".parse().unwrap(),
        );
        let head = |host: Option<&str>| oryn_sniff::HttpHead {
            target: "/d?dn=a".into(),
            host: host.map(Into::into),
            user_agent: None,
        };
        assert_eq!(
            http_info(head(Some("a.test")), &flow).url,
            "http://a.test/d?dn=a"
        );
        assert_eq!(
            http_info(head(None), &flow).url,
            "http://119.29.29.90:8080/d?dn=a"
        );
        flow.set_domain("b.test".into(), DomainSource::FakeIp);
        assert_eq!(
            http_info(head(None), &flow).url,
            "http://b.test:8080/d?dn=a"
        );
    }
}
