//! SOCKS5 客户端（RFC 1928 / RFC 1929）。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use oryn_config::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto_err;

const VER: u8 = 0x05;
const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_REJECTED: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// 协商认证方式；提供用户名时同时声明无认证与用户名密码认证。
pub async fn handshake<S>(s: &mut S, auth: Option<(&str, &str)>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if auth.is_some() {
        s.write_all(&[VER, 2, METHOD_NONE, METHOD_USERPASS]).await?;
    } else {
        s.write_all(&[VER, 1, METHOD_NONE]).await?;
    }
    s.flush().await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != VER {
        return Err(proto_err("SOCKS5: server version mismatch"));
    }
    match resp[1] {
        METHOD_NONE => Ok(()),
        METHOD_USERPASS => {
            let (user, pass) =
                auth.ok_or_else(|| proto_err("SOCKS5: server requires authentication"))?;
            if user.len() > 255 || pass.len() > 255 {
                return Err(proto_err("SOCKS5: username or password too long"));
            }
            let mut req = Vec::with_capacity(3 + user.len() + pass.len());
            req.push(0x01);
            req.push(user.len() as u8);
            req.extend_from_slice(user.as_bytes());
            req.push(pass.len() as u8);
            req.extend_from_slice(pass.as_bytes());
            s.write_all(&req).await?;
            s.flush().await?;
            let mut resp = [0u8; 2];
            s.read_exact(&mut resp).await?;
            // RFC 1929 子协商版本是 0x01；个别服务端错误地回 0x05，一并接受
            if !matches!(resp[0], 0x01 | VER) {
                return Err(proto_err("SOCKS5: invalid auth negotiation version"));
            }
            if resp[1] != 0 {
                return Err(proto_err("SOCKS5: wrong username or password"));
            }
            Ok(())
        }
        METHOD_REJECTED => Err(proto_err(
            "SOCKS5: server rejected all authentication methods",
        )),
        m => Err(proto_err(format!(
            "SOCKS5: unsupported authentication method {m}"
        ))),
    }
}

/// 发送 CONNECT 请求并读取回复。
pub async fn connect<S>(s: &mut S, target: &TargetAddr) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    request(s, CMD_CONNECT, target).await.map(|_| ())
}

/// 发送 UDP ASSOCIATE，返回中继地址。中继 IP 为未指定地址时用代理服务器 IP 代替。
pub async fn udp_associate<S>(s: &mut S, server_ip: IpAddr) -> io::Result<SocketAddr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let any = TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    match request(s, CMD_UDP_ASSOCIATE, &any).await? {
        TargetAddr::Ip(mut a) => {
            if a.ip().is_unspecified() {
                a.set_ip(server_ip);
            }
            Ok(a)
        }
        TargetAddr::Domain(..) => Err(proto_err("SOCKS5: UDP relay address is not an IP")),
    }
}

async fn request<S>(s: &mut S, cmd: u8, target: &TargetAddr) -> io::Result<TargetAddr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = vec![VER, cmd, 0x00];
    encode_addr(target, &mut req)?;
    s.write_all(&req).await?;
    s.flush().await?;

    let mut head = [0u8; 3];
    s.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(proto_err("SOCKS5: server version mismatch"));
    }
    if head[1] != 0 {
        return Err(proto_err(format!("SOCKS5: {}", reply_text(head[1]))));
    }
    read_addr(s).await
}

fn reply_text(code: u8) -> &'static str {
    match code {
        1 => "general server failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown error",
    }
}

pub fn encode_addr(target: &TargetAddr, out: &mut Vec<u8>) -> io::Result<()> {
    match target {
        TargetAddr::Ip(SocketAddr::V4(a)) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&a.ip().octets());
        }
        TargetAddr::Ip(SocketAddr::V6(a)) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&a.ip().octets());
        }
        TargetAddr::Domain(d, _) => {
            if d.is_empty() || d.len() > 255 {
                return Err(proto_err("SOCKS5: invalid domain length"));
            }
            out.push(ATYP_DOMAIN);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}

pub async fn read_addr<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<TargetAddr> {
    let atyp = s.read_u8().await?;
    let addr = match atyp {
        ATYP_V4 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            let port = s.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(b)), port))
        }
        ATYP_V6 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            let port = s.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(b)), port))
        }
        ATYP_DOMAIN => {
            let len = s.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            s.read_exact(&mut b).await?;
            let port = s.read_u16().await?;
            TargetAddr::Domain(String::from_utf8_lossy(&b).into_owned(), port)
        }
        t => return Err(proto_err(format!("SOCKS5: unknown address type {t}"))),
    };
    Ok(addr)
}

/// UDP 数据报头：`RSV(2) FRAG(1) ATYP ADDR PORT`。
pub fn encode_udp(target: &TargetAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len() + 22);
    out.extend_from_slice(&[0, 0, 0]);
    encode_addr(target, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// 解析 UDP 数据报；分片（FRAG ≠ 0）直接丢弃。
pub fn decode_udp(buf: &[u8]) -> Option<(TargetAddr, &[u8])> {
    if buf.len() < 4 || buf[2] != 0 {
        return None;
    }
    let (addr, used) = decode_addr(&buf[3..])?;
    Some((addr, &buf[3 + used..]))
}

pub fn decode_addr(rest: &[u8]) -> Option<(TargetAddr, usize)> {
    if rest.is_empty() {
        return None;
    }
    let (addr, used) = match rest[0] {
        ATYP_V4 if rest.len() >= 7 => {
            let ip = Ipv4Addr::new(rest[1], rest[2], rest[3], rest[4]);
            let port = u16::from_be_bytes([rest[5], rest[6]]);
            (TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 7)
        }
        ATYP_V6 if rest.len() >= 19 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&rest[1..17]);
            let port = u16::from_be_bytes([rest[17], rest[18]]);
            (
                TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(b)), port)),
                19,
            )
        }
        ATYP_DOMAIN if rest.len() >= 2 => {
            let len = rest[1] as usize;
            if rest.len() < 2 + len + 2 {
                return None;
            }
            let d = String::from_utf8_lossy(&rest[2..2 + len]).into_owned();
            let port = u16::from_be_bytes([rest[2 + len], rest[3 + len]]);
            (TargetAddr::Domain(d, port), 4 + len)
        }
        _ => return None,
    };
    Some((addr, used))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn connect_with_auth() {
        let (mut client, mut server) = duplex(1024);
        let srv = tokio::spawn(async move {
            let mut b = [0u8; 4];
            server.read_exact(&mut b).await.unwrap();
            assert_eq!(b, [5, 2, 0, 2]);
            server.write_all(&[5, 2]).await.unwrap();
            let mut b = [0u8; 1 + 1 + 1 + 1 + 2];
            server.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, &[1, 1, b'u', 2, b'p', b'w']);
            server.write_all(&[1, 0]).await.unwrap();
            let mut b = [0u8; 3 + 1 + 1 + 11 + 2];
            server.read_exact(&mut b).await.unwrap();
            assert_eq!(&b[..5], &[5, 1, 0, 3, 11]);
            assert_eq!(&b[5..16], b"example.com");
            assert_eq!(&b[16..], &443u16.to_be_bytes());
            server
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        handshake(&mut client, Some(("u", "pw"))).await.unwrap();
        connect(&mut client, &TargetAddr::Domain("example.com".into(), 443))
            .await
            .unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn connect_refused() {
        let (mut client, mut server) = duplex(1024);
        tokio::spawn(async move {
            let mut b = [0u8; 3];
            server.read_exact(&mut b).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            let mut b = [0u8; 10];
            server.read_exact(&mut b).await.unwrap();
            server
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        handshake(&mut client, None).await.unwrap();
        let e = connect(&mut client, &TargetAddr::Ip("1.2.3.4:80".parse().unwrap())).await;
        assert!(e.unwrap_err().to_string().contains("connection refused"));
    }

    #[test]
    fn udp_roundtrip() {
        for t in [
            TargetAddr::Ip("1.2.3.4:53".parse().unwrap()),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap()),
            TargetAddr::Domain("a.example".into(), 8080),
        ] {
            let pkt = encode_udp(&t, b"hello").unwrap();
            let (a, p) = decode_udp(&pkt).unwrap();
            assert_eq!(a, t);
            assert_eq!(p, b"hello");
        }
        assert!(decode_udp(&[0, 0, 1, 1, 0, 0, 0, 0, 0, 0]).is_none());
    }
}
