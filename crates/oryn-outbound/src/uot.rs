//! UDP-over-TCP v2 线格式：移植自 SagerNet/sing common/uot（protocol.go、conn.go、client.go、lazy.go）。
//! commit c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b（v0.8.11）。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! v2 的流目标为 `sp.v2.udp-over-tcp.arpa`。请求为 isConnect:u8 + socks5 地址，与第一个数据报一起写出；
//! 之后每包为地址（0 IPv4 / 1 IPv6 / 2 域名）+ 端口 + u16 长度 + 载荷，双向相同。
//! v1（旧版）的流目标为 `sp.udp-over-tcp.arpa`，没有请求，其余帧格式与 v2 相同。
use crate::{BoxStream, PacketConn};
use async_trait::async_trait;
use oryn_config::TargetAddr;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::{
    io::{AsyncReadExt, ReadHalf, WriteHalf},
    sync::Mutex,
};

const MAGIC_V2: &str = "sp.v2.udp-over-tcp.arpa";
const MAGIC_V1: &str = "sp.udp-over-tcp.arpa";

/// 承载 UoT 的流要连接的魔法目标。
pub(crate) fn magic(version: u8) -> &'static str {
    if version == 1 {
        MAGIC_V1
    } else {
        MAGIC_V2
    }
}
/// 最大帧：域名地址（1 + 1 + 255 + 2）+ 长度 2 + 载荷 65535。
const MAX_FRAME: usize = 259 + 2 + 65535;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// 请求首部；Oryn 总是逐包寻址（isConnect = 0），对应 sing 的 ListenPacket。
fn request(destination: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut out = vec![0];
    oryn_protocol::socks5::encode_addr(destination, &mut out)?;
    Ok(out)
}

fn encode_addr(target: &TargetAddr, out: &mut Vec<u8>) -> io::Result<()> {
    match target {
        TargetAddr::Ip(SocketAddr::V4(a)) => {
            out.push(0);
            out.extend_from_slice(&a.ip().octets());
        }
        TargetAddr::Ip(SocketAddr::V6(a)) => {
            out.push(1);
            out.extend_from_slice(&a.ip().octets());
        }
        TargetAddr::Domain(d, _) => {
            if d.is_empty() || d.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UoT: invalid domain length",
                ));
            }
            out.push(2);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}

fn encode_packet(target: &TargetAddr, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    let len = u16::try_from(data.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "UoT datagram exceeds 65535 bytes",
        )
    })?;
    encode_addr(target, out)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

/// 解析一个完整帧：返回（来源，载荷起点，帧长）；数据不足返回 None。
fn decode_packet(buf: &[u8]) -> io::Result<Option<(TargetAddr, usize, usize)>> {
    let Some(&family) = buf.first() else {
        return Ok(None);
    };
    let (ip, addr_len) = match family {
        0 => {
            if buf.len() < 7 {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            (Some(IpAddr::V4(ip)), 5)
        }
        1 => {
            if buf.len() < 19 {
                return Ok(None);
            }
            let mut b = [0; 16];
            b.copy_from_slice(&buf[1..17]);
            (Some(IpAddr::V6(Ipv6Addr::from(b))), 17)
        }
        2 => {
            if buf.len() < 2 {
                return Ok(None);
            }
            let n = buf[1] as usize;
            if n == 0 {
                return Err(invalid("UoT: empty domain"));
            }
            if buf.len() < 2 + n + 2 {
                return Ok(None);
            }
            (None, 2 + n)
        }
        _ => return Err(invalid("UoT: unknown address family")),
    };
    if buf.len() < addr_len + 4 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([buf[addr_len], buf[addr_len + 1]]);
    let len = u16::from_be_bytes([buf[addr_len + 2], buf[addr_len + 3]]) as usize;
    let start = addr_len + 4;
    if buf.len() < start + len {
        return Ok(None);
    }
    let from = match ip {
        Some(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
        None => TargetAddr::Domain(
            String::from_utf8_lossy(&buf[2..addr_len]).into_owned(),
            port,
        ),
    };
    Ok(Some((from, start, start + len)))
}

struct Reader {
    stream: ReadHalf<BoxStream>,
    pending: Vec<u8>,
    failed: bool,
}
impl Reader {
    // select! 可能取消 recv_from：已读字节留在 pending，不用局部 read_exact。
    async fn packet(&mut self, out: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        loop {
            if self.failed {
                return Err(io::Error::other("UoT stream is closed"));
            }
            match decode_packet(&self.pending) {
                Ok(Some((from, start, end))) => {
                    let n = crate::copy_datagram(&self.pending[start..end], out, "UoT");
                    self.pending.drain(..end);
                    return Ok((n, from));
                }
                Ok(None) => {}
                Err(err) => {
                    self.failed = true;
                    return Err(err);
                }
            }
            let mut scratch = [0; 4096];
            let limit = scratch.len().min(MAX_FRAME - self.pending.len());
            let n = self.stream.read(&mut scratch[..limit]).await?;
            if n == 0 {
                self.failed = true;
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "UoT stream closed",
                ));
            }
            self.pending.extend_from_slice(&scratch[..n]);
        }
    }
}

struct Writer {
    stream: crate::FrameWriter<WriteHalf<BoxStream>>,
    /// 尚未写出的请求首部，与第一个数据报合并（sing 的 LazyClientConn）。
    request: Option<Vec<u8>>,
}

pub(crate) struct UotConn {
    read: Mutex<Reader>,
    write: Mutex<Writer>,
}
impl UotConn {
    /// `version` 为 1 或 2；v2 的请求与第一个数据报合并写出。
    pub(crate) fn new(
        stream: BoxStream,
        version: u8,
        first_target: &TargetAddr,
    ) -> io::Result<Self> {
        let request = if version == 1 {
            None
        } else {
            Some(request(first_target)?)
        };
        let (read, write) = tokio::io::split(stream);
        Ok(Self {
            read: Mutex::new(Reader {
                stream: read,
                pending: Vec::new(),
                failed: false,
            }),
            write: Mutex::new(Writer {
                stream: crate::FrameWriter::new(write),
                request,
            }),
        })
    }
}
#[async_trait]
impl PacketConn for UotConn {
    async fn send_to(&self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        let mut write = self.write.lock().await;
        let mut frame = write.request.clone().unwrap_or_default();
        encode_packet(target, data, &mut frame)?;
        // 首部随这一帧进入取消安全的写缓冲：即使这次写出被取消，下次发送也会先补完它，不能重复
        write.request = None;
        write.stream.send(frame).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        self.read.lock().await.packet(buf).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// 回归：首帧必须先进入持久缓冲；flush取消后续发不丢请求首部。
    #[test]
    fn first_request_survives_flush_cancellation() {
        use std::{
            future::Future,
            pin::Pin,
            sync::{Arc, Mutex as StdMutex},
            task::{Context, Poll, Waker},
        };
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
        #[derive(Default)]
        struct State {
            pending_flush: bool,
            bytes: Vec<u8>,
        }
        struct Stream(Arc<StdMutex<State>>);
        impl AsyncRead for Stream {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for Stream {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                b: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.0.lock().unwrap().bytes.extend_from_slice(b);
                Poll::Ready(Ok(b.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.0.lock().unwrap().pending_flush {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let state = Arc::new(StdMutex::new(State {
            pending_flush: true,
            bytes: Vec::new(),
        }));
        let target = TargetAddr::Ip("192.0.2.1:53".parse().unwrap());
        let conn = UotConn::new(Box::new(Stream(state.clone())), 2, &target).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        let mut first = Box::pin(conn.send_to(b"first", &target));
        assert!(first.as_mut().poll(&mut cx).is_pending());
        drop(first);
        let mut valid = request(&target).unwrap();
        encode_packet(&target, b"first", &mut valid).unwrap();
        assert_eq!(state.lock().unwrap().bytes, valid);
        state.lock().unwrap().pending_flush = false;
        let mut second = Box::pin(conn.send_to(b"second", &target));
        assert!(matches!(second.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        let mut bare = Vec::new();
        encode_packet(&target, b"second", &mut bare).unwrap();
        valid.extend_from_slice(&bare);
        let actual = &state.lock().unwrap().bytes;
        assert_eq!(actual, &valid);
        println!(
            "uot_flush_cancel request_preserved=true two_complete_packets=true bytes={}",
            actual.len()
        );
    }

    #[test]
    fn wire_format_matches_sing() {
        let v4 = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        assert_eq!(request(&v4).unwrap(), [0, 1, 1, 2, 3, 4, 0, 53]);
        let mut out = Vec::new();
        encode_packet(&v4, b"hi", &mut out).unwrap();
        assert_eq!(out, [0, 1, 2, 3, 4, 0, 53, 0, 2, b'h', b'i']);
        let v6 = TargetAddr::Ip("[::1]:443".parse().unwrap());
        out.clear();
        encode_packet(&v6, b"", &mut out).unwrap();
        assert_eq!(out[0], 1);
        assert_eq!(out.len(), 1 + 16 + 2 + 2);
        let domain = TargetAddr::Domain("a.test".into(), 80);
        out.clear();
        encode_packet(&domain, b"x", &mut out).unwrap();
        assert_eq!(&out[..8], b"\x02\x06a.test");
        assert_eq!(&out[8..], [0, 80, 0, 1, b'x']);
        for target in [v4, v6, domain] {
            out.clear();
            encode_packet(&target, b"payload", &mut out).unwrap();
            for cut in 0..out.len() {
                assert!(decode_packet(&out[..cut]).unwrap().is_none());
            }
            let (from, start, end) = decode_packet(&out).unwrap().unwrap();
            assert_eq!((from, &out[start..end]), (target, b"payload".as_slice()));
            assert_eq!(end, out.len());
        }
        assert!(decode_packet(&[3, 0]).is_err());
        assert!(decode_packet(&[2, 0, 0, 0]).is_err());
        assert!(encode_packet(
            &TargetAddr::Domain("x".into(), 1),
            &vec![0; 65536],
            &mut out
        )
        .is_err());
    }

    #[tokio::test]
    async fn legacy_version_has_no_request() {
        let (stream, mut server) = tokio::io::duplex(4096);
        let first = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let conn = UotConn::new(Box::new(stream), 1, &first).unwrap();
        conn.send_to(b"one", &first).await.unwrap();
        let mut expected = Vec::new();
        encode_packet(&first, b"one", &mut expected).unwrap();
        let mut got = vec![0; expected.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
        assert_eq!(magic(1), "sp.udp-over-tcp.arpa");
        assert_eq!(magic(2), "sp.v2.udp-over-tcp.arpa");
    }

    #[tokio::test]
    async fn request_once_cancellation_and_small_buffers() {
        let (stream, mut server) = tokio::io::duplex(128 * 1024);
        let first = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let conn = UotConn::new(Box::new(stream), 2, &first).unwrap();
        conn.send_to(b"one", &first).await.unwrap();
        conn.send_to(b"two", &first).await.unwrap();
        let mut expected = request(&first).unwrap();
        encode_packet(&first, b"one", &mut expected).unwrap();
        encode_packet(&first, b"two", &mut expected).unwrap();
        let mut got = vec![0; expected.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);

        let mut reply = Vec::new();
        encode_packet(&first, b"abcdef", &mut reply).unwrap();
        server.write_all(&reply[..3]).await.unwrap();
        let mut buf = [0; 3];
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            conn.recv_from(&mut buf)
        )
        .await
        .is_err());
        server.write_all(&reply[3..]).await.unwrap();
        let big = vec![7; 65535];
        let mut frame = Vec::new();
        encode_packet(&TargetAddr::Domain("b.test".into(), 9), &big, &mut frame).unwrap();
        server.write_all(&frame).await.unwrap();
        assert_eq!(conn.recv_from(&mut buf).await.unwrap(), (3, first.clone()));
        assert_eq!(&buf, b"abc");
        let mut large = vec![0; 65535];
        let (n, from) = conn.recv_from(&mut large).await.unwrap();
        assert_eq!((n, from), (65535, TargetAddr::Domain("b.test".into(), 9)));
        assert_eq!(large, big);
        server.write_all(&[9]).await.unwrap();
        assert!(conn.recv_from(&mut buf).await.is_err());
        assert!(conn.recv_from(&mut buf).await.is_err());
    }
}
