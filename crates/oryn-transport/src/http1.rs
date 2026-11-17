//! `network: http`：HTTP/1.1 首部伪装。
//!
//! 客户端写出 `METHOD path HTTP/1.1` 请求首部（协议首部紧跟在首部之后），服务端回 `HTTP/1.1 200`
//! 响应首部；两边的首部之后都是原始字节流，没有分块或长度分帧。与 V2Ray / sing-box `v2rayhttp`
//! 的 HTTP/1.1 路径一致。

use std::io;

use oryn_config::HttpSpec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::HttpUpgradeStream;

const MAX_RESPONSE_HEAD: usize = 32 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

/// 发出请求并读完响应首部，返回之后的裸字节流。`initial` 与请求首部一次写出。
pub async fn connect_http<S>(
    mut stream: S,
    authority: &str,
    spec: &HttpSpec,
    initial: &[u8],
) -> io::Result<HttpUpgradeStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let host = spec.hosts.first().map(String::as_str).unwrap_or(authority);
    let mut request =
        format!("{} {} HTTP/1.1\r\nHost: {host}\r\n", spec.method, spec.path).into_bytes();
    for (name, value) in &spec.headers {
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(initial);
    stream.write_all(&request).await?;
    stream.flush().await?;
    // 逐字节读到首部结束，不多读：之后的字节属于上层协议
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_RESPONSE_HEAD {
            return Err(invalid("HTTP transport response head is too large"));
        }
        if stream.read_exact(&mut byte).await.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP transport response truncated",
            ));
        }
        head.push(byte[0]);
    }
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut parts = line.trim_end().splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") || status != "200" {
        return Err(invalid("HTTP transport did not return 200"));
    }
    Ok(HttpUpgradeStream::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt};

    fn spec() -> HttpSpec {
        HttpSpec {
            method: "POST".into(),
            path: "/obfs".into(),
            headers: vec![("User-Agent".into(), "test".into())],
            hosts: vec!["cdn.example".into(), "other.example".into()],
        }
    }

    #[tokio::test]
    async fn request_head_carries_the_initial_bytes_and_response_is_raw() {
        let (client, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            let text = String::from_utf8(head).unwrap();
            assert_eq!(
                text,
                "POST /obfs HTTP/1.1\r\nHost: cdn.example\r\nUser-Agent: test\r\n\r\n"
            );
            let mut first = [0; 7];
            server.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"initial");
            server
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nraw-reply")
                .await
                .unwrap();
            let mut more = [0; 4];
            server.read_exact(&mut more).await.unwrap();
            assert_eq!(&more, b"more");
        });
        let mut c = connect_http(client, "proxy.test:443", &spec(), b"initial")
            .await
            .unwrap();
        let mut got = [0; 9];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"raw-reply");
        c.write_all(b"more").await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn defaults_and_rejections() {
        let mut plain = spec();
        plain.hosts.clear();
        plain.headers.clear();
        let (client, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            let n = server.read(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(
                text.starts_with("POST /obfs HTTP/1.1\r\nHost: proxy.test:443\r\n\r\n"),
                "{text}"
            );
            server
                .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
        });
        assert!(connect_http(client, "proxy.test:443", &plain, b"")
            .await
            .is_err());
        task.await.unwrap();
        // 响应首部被截断
        let (client, mut server) = duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            let _ = server.read(&mut buf).await;
            server.write_all(b"HTTP/1.1 200 OK\r\nX: y").await.unwrap();
            drop(server);
        });
        assert!(connect_http(client, "a:1", &spec(), b"").await.is_err());
    }
}
