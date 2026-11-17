//! 域名嗅探：从连接的首批数据中解析域名。
//!
//! - TLS：ClientHello 的 SNI（支持跨多个 TLS 记录）。
//! - HTTP：请求头中的 `Host`。
//! - QUIC：解密 Initial 包，重组 CRYPTO 帧后解析 ClientHello 的 SNI（支持 QUIC v1 / v2、
//!   ClientHello 跨多个 Initial 包、帧乱序）。
//!
//! 本 crate 只做解析，不涉及网络与超时。

mod quic;

pub use quic::QuicSniffer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniff {
    /// 解析出域名（小写）。
    Found(String),
    /// 数据还不完整，需要更多数据。
    NeedMore,
    /// 不是该协议，或没有可用的域名。
    NotMatch,
}

/// 域名的基本合法性检查；IP 字面量不算域名。
fn valid_domain(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 || s.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let ok = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    (ok && !s.starts_with('.') && !s.contains("..")).then_some(s)
}

/// 从 TLS 记录流中解析 SNI。
pub fn sniff_tls(buf: &[u8]) -> Sniff {
    if buf.is_empty() {
        return Sniff::NeedMore;
    }
    if buf[0] != 0x16 {
        return Sniff::NotMatch;
    }
    let mut handshake = Vec::new();
    let mut pos = 0;
    // 拼接连续的握手记录，直到 ClientHello 完整
    loop {
        if buf.len() < pos + 5 {
            return Sniff::NeedMore;
        }
        if buf[pos] != 0x16 || buf[pos + 1] != 0x03 {
            return Sniff::NotMatch;
        }
        let len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        if len == 0 || len > 16384 + 256 {
            return Sniff::NotMatch;
        }
        if buf.len() < pos + 5 + len {
            // 记录不完整：如果已有的部分足够解析也可以提前返回
            handshake.extend_from_slice(&buf[pos + 5..]);
            return match client_hello_sni(&handshake) {
                Sniff::NeedMore => Sniff::NeedMore,
                other => other,
            };
        }
        handshake.extend_from_slice(&buf[pos + 5..pos + 5 + len]);
        pos += 5 + len;
        match client_hello_sni(&handshake) {
            Sniff::NeedMore if pos < buf.len() => continue,
            other => return other,
        }
    }
}

/// 解析握手消息流开头的 ClientHello（不含 TLS 记录头）。TLS 与 QUIC 共用。
pub fn client_hello_sni(h: &[u8]) -> Sniff {
    if h.len() < 4 {
        return Sniff::NeedMore;
    }
    if h[0] != 0x01 {
        return Sniff::NotMatch;
    }
    let len = ((h[1] as usize) << 16) | ((h[2] as usize) << 8) | h[3] as usize;
    if len > 64 * 1024 {
        return Sniff::NotMatch;
    }
    if h.len() < 4 + len {
        return Sniff::NeedMore;
    }
    match parse_sni(&h[4..4 + len]) {
        Some(Some(name)) => valid_domain(&name).map_or(Sniff::NotMatch, Sniff::Found),
        _ => Sniff::NotMatch,
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

/// ClientHello 主体 → SNI。外层 `None` 表示格式错误，内层 `None` 表示没有 SNI。
fn parse_sni(body: &[u8]) -> Option<Option<String>> {
    let mut r = Reader { b: body, pos: 0 };
    r.take(2 + 32)?; // legacy_version + random
    let sid = r.u8()? as usize;
    r.take(sid)?;
    let cs = r.u16()? as usize;
    r.take(cs)?;
    let comp = r.u8()? as usize;
    r.take(comp)?;
    if r.pos == body.len() {
        return Some(None);
    }
    let ext_len = r.u16()? as usize;
    let exts = r.take(ext_len)?;
    let mut e = Reader { b: exts, pos: 0 };
    while e.pos < exts.len() {
        let ty = e.u16()?;
        let len = e.u16()? as usize;
        let data = e.take(len)?;
        if ty == 0 {
            let mut s = Reader { b: data, pos: 0 };
            let list = s.u16()? as usize;
            let list = s.take(list)?;
            let mut l = Reader { b: list, pos: 0 };
            while l.pos < list.len() {
                let name_type = l.u8()?;
                let n = l.u16()? as usize;
                let name = l.take(n)?;
                if name_type == 0 {
                    return Some(Some(String::from_utf8_lossy(name).into_owned()));
                }
            }
            return Some(None);
        }
    }
    Some(None)
}

const METHODS: [&str; 9] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH", "TRACE",
];

/// 从 HTTP/1.x 请求中解析 `Host`。
pub fn sniff_http(buf: &[u8]) -> Sniff {
    if buf.is_empty() {
        return Sniff::NeedMore;
    }
    // 先确认是 HTTP 请求行
    let first_space = buf.iter().take(9).position(|&b| b == b' ');
    match first_space {
        Some(i) => {
            if !METHODS.iter().any(|m| m.as_bytes() == &buf[..i]) {
                return Sniff::NotMatch;
            }
        }
        None if buf.len() < 9 && METHODS.iter().any(|m| m.as_bytes().starts_with(buf)) => {
            return Sniff::NeedMore
        }
        None => return Sniff::NotMatch,
    }
    let text = String::from_utf8_lossy(buf);
    let complete = text.contains("\r\n\r\n");
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let v = v.trim();
                // 去掉端口；IPv6 字面量带方括号
                let host = if v.starts_with('[') {
                    v.trim_start_matches('[').split(']').next().unwrap_or("")
                } else {
                    v.rsplit_once(':').map_or(v, |(h, p)| {
                        if p.chars().all(|c| c.is_ascii_digit()) {
                            h
                        } else {
                            v
                        }
                    })
                };
                return valid_domain(host).map_or(Sniff::NotMatch, Sniff::Found);
            }
        }
    }
    if complete || buf.len() > 16 * 1024 {
        Sniff::NotMatch
    } else {
        Sniff::NeedMore
    }
}

/// 明文 HTTP 请求头中分流规则用到的字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHead {
    /// 请求行的目标（`/路径` 或代理式的完整地址）。
    pub target: String,
    /// `Host` 头原样（可带端口）。
    pub host: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head {
    Found(HttpHead),
    NeedMore,
    NotHttp,
}

/// 解析请求行与请求头。请求头未结束时返回 `NeedMore`；`last` 为真（不会再有数据）时按已有部分解析。
pub fn http_head(buf: &[u8], last: bool) -> Head {
    let space = buf.iter().take(9).position(|&b| b == b' ');
    match space {
        Some(i) if METHODS.iter().any(|m| m.as_bytes() == &buf[..i]) => {}
        None if !last && buf.len() < 9 && METHODS.iter().any(|m| m.as_bytes().starts_with(buf)) => {
            return Head::NeedMore
        }
        _ => return Head::NotHttp,
    }
    let text = String::from_utf8_lossy(buf);
    let end = text.find("\r\n\r\n");
    if end.is_none() && !last {
        return Head::NeedMore;
    }
    let mut lines = text[..end.unwrap_or(text.len())].split("\r\n");
    let Some(target) = lines.next().and_then(|l| l.split(' ').nth(1)) else {
        return Head::NotHttp;
    };
    let mut head = HttpHead {
        target: target.to_string(),
        host: None,
        user_agent: None,
    };
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim();
        if k.eq_ignore_ascii_case("host") && head.host.is_none() {
            head.host = Some(v.trim().to_string());
        } else if k.eq_ignore_ascii_case("user-agent") && head.user_agent.is_none() {
            head.user_agent = Some(v.trim().to_string());
        }
    }
    Head::Found(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 用 rustls 生成真实的 ClientHello。
    pub(crate) fn client_hello(sni: &str) -> Vec<u8> {
        let mut config = (*oryn_tls::client_config(&[b"h2"], true).unwrap()).clone();
        config.enable_sni = true;
        let mut conn =
            rustls::ClientConnection::new(Arc::new(config), sni.to_string().try_into().unwrap())
                .unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn tls_sni() {
        let hello = client_hello("www.Example.com");
        assert_eq!(sniff_tls(&hello), Sniff::Found("www.example.com".into()));
        assert_eq!(sniff_tls(&hello[..hello.len() / 2]), Sniff::NeedMore);
        assert_eq!(sniff_tls(&hello[..3]), Sniff::NeedMore);
        assert_eq!(sniff_tls(b"GET / HTTP/1.1\r\n"), Sniff::NotMatch);
        assert_eq!(sniff_tls(&[]), Sniff::NeedMore);

        // 同一 ClientHello 拆成两个 TLS 记录
        let body = &hello[5..];
        let (a, b) = body.split_at(40);
        let mut split = Vec::new();
        for part in [a, b] {
            split.extend_from_slice(&[0x16, 0x03, 0x01]);
            split.extend_from_slice(&(part.len() as u16).to_be_bytes());
            split.extend_from_slice(part);
        }
        assert_eq!(sniff_tls(&split), Sniff::Found("www.example.com".into()));
        assert_eq!(sniff_tls(&split[..50]), Sniff::NeedMore);
    }

    #[test]
    fn tls_without_sni_or_ip() {
        let hello = client_hello("1.2.3.4");
        assert_eq!(sniff_tls(&hello), Sniff::NotMatch);
    }

    #[test]
    fn http_host() {
        assert_eq!(
            sniff_http(b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\nAccept: */*\r\n\r\n"),
            Sniff::Found("example.com".into())
        );
        assert_eq!(
            sniff_http(b"POST /x HTTP/1.1\r\nhost:a.b.c\r\n"),
            Sniff::Found("a.b.c".into())
        );
        assert_eq!(
            sniff_http(b"GET / HTTP/1.1\r\nAccept: */*\r\n"),
            Sniff::NeedMore
        );
        assert_eq!(
            sniff_http(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"),
            Sniff::NotMatch
        );
        assert_eq!(sniff_http(b"GE"), Sniff::NeedMore);
        assert_eq!(sniff_http(b"\x16\x03\x01\x02\x00"), Sniff::NotMatch);
        assert_eq!(
            sniff_http(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n"),
            Sniff::NotMatch
        );
        assert_eq!(
            sniff_http(b"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n"),
            Sniff::NotMatch
        );
    }

    #[test]
    fn http_head_fields() {
        let req =
            b"GET /d?dn=a.test HTTP/1.1\r\nhost: 119.29.29.90\r\nUser-Agent: %E5%98%80 1.0\r\n\r\n";
        assert_eq!(
            http_head(req, false),
            Head::Found(HttpHead {
                target: "/d?dn=a.test".into(),
                host: Some("119.29.29.90".into()),
                user_agent: Some("%E5%98%80 1.0".into()),
            })
        );
        assert_eq!(http_head(&req[..30], false), Head::NeedMore);
        assert!(matches!(http_head(&req[..30], true), Head::Found(h) if h.user_agent.is_none()));
        assert_eq!(http_head(b"GE", false), Head::NeedMore);
        assert_eq!(http_head(b"\x16\x03\x01", false), Head::NotHttp);
    }
}
