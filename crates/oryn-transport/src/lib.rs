//! WebSocket 是字节流传输，协议与 TLS 由上下层负责。
use base64::Engine;
use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use oryn_config::WsSpec;
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig, Message},
    WebSocketStream,
};

/// 完成 Upgrade，将协议首部的前缀作为 early data；剩余首部发送为 WS 二进制帧。
pub async fn connect<S>(
    stream: S,
    authority: &str,
    spec: &WsSpec,
    initial: &[u8],
) -> io::Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = format!("ws://{authority}{}", spec.path)
        .into_client_request()
        .map_err(io::Error::other)?;
    for (name, value) in &spec.headers {
        request.headers_mut().insert(
            name.parse::<tokio_tungstenite::tungstenite::http::HeaderName>()
                .map_err(io::Error::other)?,
            value.parse().map_err(io::Error::other)?,
        );
    }
    let n = initial.len().min(spec.max_early_data);
    if n > 0 {
        request.headers_mut().insert(
            spec.early_data_header
                .parse::<tokio_tungstenite::tungstenite::http::HeaderName>()
                .map_err(io::Error::other)?,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&initial[..n])
                .parse()
                .map_err(io::Error::other)?,
        );
    }
    let config = WebSocketConfig::default()
        .read_buffer_size(8192)
        .write_buffer_size(0)
        .max_write_buffer_size(128 * 1024)
        .max_message_size(Some(64 * 1024))
        .max_frame_size(Some(64 * 1024));
    let (ws, _) = tokio_tungstenite::client_async_with_config(request, stream, Some(config))
        .await
        .map_err(io::Error::other)?;
    let mut s = WsStream::from_websocket(ws);
    s.write_all(&initial[n..]).await?;
    s.flush().await?;
    Ok(s)
}

pub struct WsStream<S> {
    ws: WebSocketStream<S>,
    read: Bytes,
    eof: bool,
    flush_control: bool,
}

/// HTTP/1.1 Upgrade：有界读取握手首部，101 后返回裸字节流。
pub async fn connect_http_upgrade<S>(
    mut stream: S,
    authority: &str,
    spec: &oryn_config::HttpUpgradeSpec,
    initial: &[u8],
) -> io::Result<HttpUpgradeStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
        spec.path,
        spec.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str())
            .unwrap_or(authority)
    );
    for (name, value) in &spec.headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut response = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while !response.windows(4).any(|w| w == b"\r\n\r\n") {
        if response.len() >= 32 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTPUpgrade response too large",
            ));
        }
        if stream.read_exact(&mut byte).await.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTPUpgrade response truncated",
            ));
        }
        response.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&response);
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 101 ") && !status.starts_with("HTTP/1.0 101 ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTPUpgrade did not return 101",
        ));
    }
    let mut upgrade = false;
    let mut connection = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "upgrade" => upgrade = value.trim().eq_ignore_ascii_case("websocket"),
                "connection" => {
                    connection = value
                        .split(',')
                        .any(|v| v.trim().eq_ignore_ascii_case("upgrade"))
                }
                _ => {}
            }
        }
    }
    if !upgrade || !connection {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTPUpgrade response headers",
        ));
    }
    stream.write_all(initial).await?;
    stream.flush().await?;
    Ok(HttpUpgradeStream { stream })
}

pub struct HttpUpgradeStream<S> {
    stream: S,
}
impl<S> HttpUpgradeStream<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self { stream }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpUpgradeStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HttpUpgradeStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

mod h2pool;
mod http1;
mod kcp;
mod mekya;
mod obfs;
pub use h2pool::{
    drive_with_window, stream_window as h2_stream_window, GrpcPool, GrpcStream, XHttpDial, XHttpIo,
    WINDOW_BUDGET as H2_WINDOW_BUDGET,
};
pub use http1::connect_http;
pub use kcp::{connect_kcp, KcpStream, PacketIo as KcpPacketIo};
pub use mekya::{connect_kcp_dial, encode_bundle as mekya_encode_bundle, MekyaDial, MekyaStream};
pub use obfs::{HttpObfs, TlsObfs};

/// 随机字节（系统随机源）。
pub(crate) fn random_bytes(len: usize) -> Vec<u8> {
    use ring::rand::SecureRandom;
    let mut out = vec![0u8; len];
    // 系统随机源失败时没有安全的退路；此处宁可 panic，也不发送可预测的值
    ring::rand::SystemRandom::new()
        .fill(&mut out)
        .expect("system random source failed");
    out
}

impl<S> WsStream<S> {
    pub fn from_websocket(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            read: Bytes::new(),
            eof: false,
            flush_control: false,
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.flush_control {
                ready!(Pin::new(&mut this.ws).poll_flush(cx)).map_err(io::Error::other)?;
                this.flush_control = false;
            }
            if !this.read.is_empty() {
                let n = this.read.len().min(buf.remaining());
                buf.put_slice(&this.read[..n]);
                this.read.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => this.read = data,
                Some(Ok(Message::Close(_))) | None => {
                    this.eof = true;
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                    // tungstenite 排队的 pong 必须实际写出；在下一次读取前冲刷。
                    this.flush_control = true;
                }
                Some(Ok(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "WebSocket proxy received non-binary data",
                    )))
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            }
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        ready!(Pin::new(&mut this.ws).poll_ready(cx)).map_err(io::Error::other)?;
        let n = data.len().min(16 * 1024);
        Pin::new(&mut this.ws)
            .start_send(Message::Binary(Bytes::copy_from_slice(&data[..n])))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().ws)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().ws)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{duplex, AsyncReadExt};
    fn spec() -> WsSpec {
        WsSpec {
            path: "/ws".into(),
            headers: vec![],
            max_early_data: 0,
            early_data_header: "Sec-WebSocket-Protocol".into(),
        }
    }
    #[tokio::test]
    async fn ping_pong_and_message_boundaries() {
        let (client, server) = duplex(4096);
        let task = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_async(server).await.unwrap();
            ws.send(Message::Ping(Bytes::from_static(b"ping")))
                .await
                .unwrap();
            assert_eq!(
                ws.next().await.unwrap().unwrap(),
                Message::Pong(Bytes::from_static(b"ping"))
            );
            ws.send(Message::Binary(Bytes::from_static(b"ab")))
                .await
                .unwrap();
            ws.send(Message::Binary(Bytes::from_static(b"cdef")))
                .await
                .unwrap();
            ws.close(None).await.unwrap();
        });
        let mut client = connect(client, "proxy.test", &spec(), &[]).await.unwrap();
        let mut data = Vec::new();
        client.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"abcdef");
        task.await.unwrap();
    }
    #[tokio::test]
    async fn rejects_bad_upgrade_and_oversize_message() {
        let (client, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(server.read_u8().await.unwrap());
            }
            server.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n").await.unwrap();
        });
        assert!(connect(client, "proxy.test", &spec(), &[]).await.is_err());
        task.await.unwrap();
        let (client, server) = duplex(128 * 1024);
        let task = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_async(server).await.unwrap();
            ws.send(Message::Binary(vec![0; 65537].into()))
                .await
                .unwrap();
        });
        let mut client = connect(client, "proxy.test", &spec(), &[]).await.unwrap();
        assert!(client.read_u8().await.is_err());
        task.await.unwrap();
    }
}
