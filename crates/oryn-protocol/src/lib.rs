//! 代理协议的客户端编解码。只依赖 `AsyncRead + AsyncWrite`，不创建 socket。

pub mod http;
pub mod shadowsocks;
pub mod socks5;
pub mod trojan;
pub mod vless;
pub mod vless_encryption;

use std::io;

pub(crate) fn proto_err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// `host:port` 形式，IPv6 加方括号。
///
/// 域名来自隧道流量（应用请求的域名、嗅探到的 SNI），要拼进 HTTP 请求行与首部：
/// 只接受可见 ASCII，拒绝 CR / LF / 空格等控制字符与非 ASCII，防止首部注入。
pub(crate) fn host_port(target: &oryn_config::TargetAddr) -> io::Result<String> {
    match target {
        oryn_config::TargetAddr::Ip(a) => Ok(a.to_string()),
        oryn_config::TargetAddr::Domain(d, p) => {
            if d.is_empty() || !d.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "target domain contains invalid characters",
                ));
            }
            Ok(format!("{d}:{p}"))
        }
    }
}

#[cfg(test)]
mod host_port_tests {
    use oryn_config::TargetAddr;

    #[test]
    fn rejects_header_injection() {
        assert_eq!(
            super::host_port(&TargetAddr::Domain("example.com".into(), 443)).unwrap(),
            "example.com:443"
        );
        for bad in ["a.com\r\nX: y", "a b", "", "例子.com", "a\0b"] {
            assert!(super::host_port(&TargetAddr::Domain(bad.into(), 1)).is_err(), "{bad:?}");
        }
    }
}

pub mod vmess;
