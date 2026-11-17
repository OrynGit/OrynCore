//! HTTP CONNECT 客户端。

use std::io;

use oryn_config::{ProxyAuth, TargetAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{host_port, proto_err};

const MAX_HEADER: usize = 8 * 1024;

/// 发送 CONNECT 并读取响应头。逐字节读取，确保不会吞掉隧道里的数据。
pub async fn connect<S>(s: &mut S, target: &TargetAddr, auth: Option<&ProxyAuth>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hp = host_port(target)?;
    let mut req =
        format!("CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\nProxy-Connection: Keep-Alive\r\n");
    if let Some(a) = auth {
        let token = base64(format!("{}:{}", a.username, a.password).as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;

    let mut head = Vec::with_capacity(256);
    loop {
        let b = s.read_u8().await?;
        head.push(b);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HEADER {
            return Err(proto_err("HTTP CONNECT: response header too long"));
        }
    }
    let status_line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let status_line = String::from_utf8_lossy(status_line);
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(proto_err("HTTP CONNECT: malformed response"));
    }
    if code != "200" {
        return Err(proto_err(format!(
            "HTTP CONNECT: proxy returned {}",
            status_line.trim()
        )));
    }
    Ok(())
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn b64() {
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
    }

    #[tokio::test]
    async fn connect_ok_keeps_tunnel_data() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
            assert!(req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\nTUNNEL")
                .await
                .unwrap();
        });
        let auth = ProxyAuth {
            username: "user".into(),
            password: "pass".into(),
        };
        let target = TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap());
        connect(&mut client, &target, Some(&auth)).await.unwrap();
        let mut rest = [0u8; 6];
        client.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"TUNNEL");
    }

    #[tokio::test]
    async fn connect_denied() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let e = connect(&mut client, &TargetAddr::Domain("a.com".into(), 80), None).await;
        assert!(e.unwrap_err().to_string().contains("407"));
    }
}
