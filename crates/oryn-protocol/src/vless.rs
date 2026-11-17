//! VLESS v0（无 flow / XUDP），响应头在首次读时剥离。
use crate::proto_err;
use oryn_config::TargetAddr;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub fn request(uuid: &[u8; 16], target: &TargetAddr, udp: bool) -> io::Result<Vec<u8>> {
    request_with_flow(
        uuid,
        Some(target),
        if udp { COMMAND_UDP } else { COMMAND_TCP },
        "",
    )
}

pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;
/// Mux.Cool / XUDP：没有目的地址。
pub const COMMAND_MUX: u8 = 3;
pub const FLOW_VISION: &str = "xtls-rprx-vision";

/// 带 flow 附加字段（protobuf field 1）的请求首部。`target` 为 None 时（Mux 命令）不写地址。
pub fn request_with_flow(
    uuid: &[u8; 16],
    target: Option<&TargetAddr>,
    command: u8,
    flow: &str,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(300);
    out.push(0);
    out.extend_from_slice(uuid);
    if flow.is_empty() {
        out.push(0);
    } else {
        // flow 只有固定的短字符串，uvarint 长度只占一字节
        if flow.len() > 127 {
            return Err(proto_err("VLESS flow too long"));
        }
        out.push(2 + flow.len() as u8);
        out.extend_from_slice(&[10, flow.len() as u8]);
        out.extend_from_slice(flow.as_bytes());
    }
    out.push(command);
    let Some(target) = target else {
        return Ok(out);
    };
    out.extend_from_slice(&target.port().to_be_bytes());
    match target {
        TargetAddr::Ip(SocketAddr::V4(a)) => {
            out.push(1);
            out.extend_from_slice(&a.ip().octets());
        }
        TargetAddr::Ip(SocketAddr::V6(a)) => {
            out.push(3);
            out.extend_from_slice(&a.ip().octets());
        }
        TargetAddr::Domain(host, _) => {
            if host.is_empty() || host.len() > 255 {
                return Err(proto_err("VLESS invalid domain length"));
            }
            out.extend_from_slice(&[2, host.len() as u8]);
            out.extend_from_slice(host.as_bytes());
        }
    }
    Ok(out)
}

pub fn encode_udp(payload: &[u8]) -> io::Result<Vec<u8>> {
    let len = u16::try_from(payload.len()).map_err(|_| proto_err("VLESS UDP payload too large"))?;
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}
pub async fn read_udp<S: AsyncRead + Unpin>(s: &mut S, buf: &mut [u8]) -> io::Result<usize> {
    let len = s.read_u16().await? as usize;
    read_payload(s, len, buf).await
}
// 小接收缓冲截断后仍消耗完整帧，保持下一包边界；不按不可信长度分配内存。
pub(crate) async fn read_payload<S: AsyncRead + Unpin>(
    s: &mut S,
    len: usize,
    buf: &mut [u8],
) -> io::Result<usize> {
    let n = len.min(buf.len());
    s.read_exact(&mut buf[..n]).await?;
    let mut left = len - n;
    let mut scratch = [0; 1024];
    while left > 0 {
        let n = left.min(scratch.len());
        s.read_exact(&mut scratch[..n]).await?;
        left -= n;
    }
    Ok(n)
}

pub struct ResponseStream<S> {
    inner: S,
    header: [u8; 257],
    read: usize,
    need: usize,
    checked: bool,
    failed: bool,
}
impl<S> ResponseStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 257],
            read: 0,
            need: 2,
            checked: false,
            failed: false,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for ResponseStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(proto_err("VLESS invalid response header")));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            while this.read < this.need {
                let mut part = ReadBuf::new(&mut this.header[this.read..this.need]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
                let n = part.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VLESS truncated response header",
                    )));
                }
                this.read += n;
            }
            if !this.checked {
                this.checked = true;
                if this.header[0] != 0 {
                    this.failed = true;
                    return Poll::Ready(Err(proto_err("VLESS invalid response version")));
                }
                this.need = 2 + this.header[1] as usize;
                continue;
            }
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ResponseStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    #[test]
    fn request_wire_format() {
        let req = request(
            &[0xab; 16],
            &TargetAddr::Domain("x.test".into(), 443),
            false,
        )
        .unwrap();
        assert_eq!(
            &req[..19],
            &[
                0, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171,
                0, 1
            ]
        );
        assert_eq!(
            &req[19..],
            &[1, 187, 2, 6, b'x', b'.', b't', b'e', b's', b't']
        );
        assert_eq!(
            request(&[0; 16], &TargetAddr::Ip("[::1]:53".parse().unwrap()), true).unwrap()[18],
            2
        );
        // flow 附加字段：长度 18 = 0x0a + 长度 + 16 字节 flow；Mux 命令没有地址
        let vision = request_with_flow(&[0; 16], None, COMMAND_MUX, FLOW_VISION).unwrap();
        assert_eq!(vision.len(), 1 + 16 + 1 + 18 + 1);
        assert_eq!(&vision[17..20], &[18, 10, 16]);
        assert_eq!(&vision[20..36], FLOW_VISION.as_bytes());
        assert_eq!(vision[36], COMMAND_MUX);
    }
    #[tokio::test]
    async fn response_addons_and_truncation() {
        let (r, mut w) = duplex(1024);
        let mut r = ResponseStream::new(r);
        let task = tokio::spawn(async move {
            for byte in [0, 3, 9, 8, 7, b'h', b'i'] {
                w.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut data = [0; 2];
        r.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"hi");
        task.await.unwrap();
        for head in [vec![1, 0], vec![0, 4, 1]] {
            let (r, mut w) = duplex(16);
            w.write_all(&head).await.unwrap();
            drop(w);
            assert!(ResponseStream::new(r).read_u8().await.is_err());
        }
    }
}
