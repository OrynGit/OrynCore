//! packetaddr / XUDP 客户端适配，按 sing-vmess 的线格式改写为有界 Rust 状态机。
//! 来源：SagerNet/sing-vmess，packetaddr/conn.go、xudp.go。
//! commit 3a8da1e3baff96ba453501e0959863fec2c30977（v0.2.7）。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
use crate::{unsupported, BoxStream, PacketConn};
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
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid packet encoding frame")
}
pub struct PacketAddrConn {
    pub inner: Box<dyn PacketConn>,
    pub magic: TargetAddr,
    pub(crate) scratch: crate::RecvScratch,
}
#[async_trait]
impl PacketConn for PacketAddrConn {
    async fn send_to(&self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        let TargetAddr::Ip(a) = target else {
            return Err(unsupported(
                "packetaddr does not support domain destinations",
            ));
        };
        let mut wire = Vec::new();
        match a.ip() {
            IpAddr::V4(ip) => {
                wire.push(1);
                wire.extend(ip.octets());
            }
            IpAddr::V6(ip) => {
                wire.push(2);
                wire.extend(ip.octets());
            }
        }
        wire.extend(a.port().to_be_bytes());
        wire.extend(data);
        self.inner.send_to(&wire, &self.magic).await
    }
    async fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut wire = self.scratch.take();
        let (n, _) = self.inner.recv_from(&mut wire).await?;
        let size = match wire.first() {
            Some(1) => 4,
            Some(2) => 16,
            _ => return Err(invalid()),
        };
        if n < size + 3 {
            return Err(invalid());
        }
        let ip = if size == 4 {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&wire[1..5]).unwrap()))
        } else {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&wire[1..17]).unwrap()))
        };
        let port = u16::from_be_bytes(wire[1 + size..3 + size].try_into().unwrap());
        let count = crate::copy_datagram(&wire[size + 3..n], out, "packetaddr");
        Ok((count, TargetAddr::Ip(SocketAddr::new(ip, port))))
    }
}
pub struct XudpConn {
    read: Mutex<XudpReader>,
    write: Mutex<(crate::FrameWriter<WriteHalf<BoxStream>>, bool)>,
}
struct XudpReader {
    stream: ReadHalf<BoxStream>,
    pending: Vec<u8>,
    target: TargetAddr,
    failed: bool,
}
impl XudpConn {
    pub fn new(stream: BoxStream, target: TargetAddr) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            read: Mutex::new(XudpReader {
                stream: read,
                pending: Vec::new(),
                target,
                failed: false,
            }),
            write: Mutex::new((crate::FrameWriter::new(write), false)),
        }
    }
}
fn addr(data: &[u8]) -> io::Result<TargetAddr> {
    if data.len() < 3 {
        return Err(invalid());
    }
    let port = u16::from_be_bytes(data[..2].try_into().unwrap());
    let target = match data[2] {
        1 if data.len() == 7 => TargetAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&data[3..]).unwrap())),
            port,
        )),
        3 if data.len() == 19 => TargetAddr::Ip(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[3..]).unwrap())),
            port,
        )),
        2 if data.len() > 3 && data.len() == 4 + data[3] as usize => TargetAddr::Domain(
            std::str::from_utf8(&data[4..])
                .map_err(|_| invalid())?
                .into(),
            port,
        ),
        _ => return Err(invalid()),
    };
    Ok(target)
}
impl XudpReader {
    async fn receive(&mut self, out: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        // 读取次数不应限制为固定值：TCP 可以把一个合法的最大 UDP 帧
        // （65507 字节）拆成远多于 256 次的小片。pending 有明确上限，
        // 因此解析失败或超限时仍会有界退出。
        loop {
            if self.failed {
                return Err(invalid());
            }
            if self.pending.len() >= 2 {
                let h = u16::from_be_bytes(self.pending[..2].try_into().unwrap()) as usize;
                if !(4..=263).contains(&h) {
                    self.failed = true;
                    return Err(invalid());
                }
                if self.pending.len() >= 2 + h {
                    let header = &self.pending[2..2 + h];
                    if header[..2] != [0, 0] || !matches!(header[2], 2..=4) || header[3] & 2 != 0 {
                        self.failed = true;
                        return Err(invalid());
                    }
                    if header[2] == 3 {
                        self.failed = true;
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    if header[3] & 1 == 0 {
                        self.pending.drain(..2 + h);
                        continue;
                    }
                    let discard = header[2] == 4;
                    let target = if discard || h == 4 {
                        self.target.clone()
                    } else {
                        if header[4] != 2 {
                            self.failed = true;
                            return Err(invalid());
                        }
                        match addr(&header[5..]) {
                            Ok(target) => target,
                            // 与其他坏帧一样终态化：否则同一坏帧被反复解析、反复报错
                            Err(e) => {
                                self.failed = true;
                                return Err(e);
                            }
                        }
                    };
                    if self.pending.len() >= h + 4 {
                        let n = u16::from_be_bytes(self.pending[2 + h..4 + h].try_into().unwrap())
                            as usize;
                        if self.pending.len() >= 4 + h + n {
                            if discard {
                                self.pending.drain(..4 + h + n);
                                continue;
                            }
                            let count =
                                crate::copy_datagram(&self.pending[4 + h..4 + h + n], out, "XUDP");
                            self.pending.drain(..4 + h + n);
                            self.target = target.clone();
                            return Ok((count, target));
                        }
                    }
                }
            }
            let mut scratch = [0; 4096];
            let n = self.stream.read(&mut scratch).await?;
            if n == 0 {
                self.failed = true;
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if self.pending.len() + n > 65535 + 267 + 4096 {
                self.failed = true;
                return Err(invalid());
            }
            self.pending.extend_from_slice(&scratch[..n]);
        }
    }
}
#[async_trait]
impl PacketConn for XudpConn {
    async fn send_to(&self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        let n = u16::try_from(data.len()).map_err(|_| invalid())?;
        let address = oryn_protocol::vmess::address(target)?;
        let mut write = self.write.lock().await;
        let mut wire = ((5 + address.len()) as u16).to_be_bytes().to_vec();
        wire.extend([0, 0, if write.1 { 2 } else { 1 }, 1, 2]);
        wire.extend(address);
        wire.extend(n.to_be_bytes());
        wire.extend(data);
        write.1 = true;
        write.0.send(wire).await
    }
    async fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        self.read.lock().await.receive(out).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// 每次只返回一个字节，模拟极端碎片化的 TCP 读取。
    struct OneByte {
        data: VecDeque<u8>,
    }

    impl AsyncRead for OneByte {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(byte) = self.data.pop_front() {
                out.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for OneByte {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::Unsupported, "read-only")))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn audit_xudp_keepalive_cancelled_then_business() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(1024);
        let target = TargetAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 443)));
        let c = XudpConn::new(Box::new(client), target.clone());
        // KeepAlive 的元数据不是业务地址，不应解析或更新 target。
        let mut wire = vec![0, 5, 0, 0, 4, 1, 99, 255, 255];
        wire.extend(std::iter::repeat_n(0x5a, 65535));
        wire.extend_from_slice(&[0, 4, 0, 0, 4, 1, 0, 0]);
        wire.extend_from_slice(&[0, 4, 0, 0, 4, 1, 0, 1, 42]);
        let mut out = [0; 8];
        for byte in wire {
            server.write_all(&[byte]).await.unwrap();
            {
                let mut recv = Box::pin(c.recv_from(&mut out));
                assert!(matches!(futures_util::poll!(recv.as_mut()), Poll::Pending));
            }
            assert!(c.read.lock().await.pending.len() <= 65535 + 267 + 4096);
        }
        server
            .write_all(&[0, 4, 0, 0, 2, 1, 0, 2, b'o', b'k'])
            .await
            .unwrap();
        let (n, got) = c.recv_from(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"ok");
        assert_eq!(got, target);
        assert!(c.read.lock().await.pending.is_empty());
    }

    #[tokio::test]
    async fn xudp_accepts_frame_split_into_more_than_256_reads() {
        let payload = vec![0x5a; 1024];
        let mut wire = Vec::with_capacity(payload.len() + 8);
        wire.extend_from_slice(&4u16.to_be_bytes());
        // header length 4, target inherited from the connection.
        wire.extend_from_slice(&[0, 0, 2, 1]);
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(&payload);
        let stream: BoxStream = Box::new(OneByte { data: wire.into() });
        let (read, _) = tokio::io::split(stream);
        let target = TargetAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 443)));
        let mut reader = XudpReader {
            stream: read,
            pending: Vec::new(),
            target: target.clone(),
            failed: false,
        };
        let mut out = vec![0; payload.len()];
        let (n, got) = reader.receive(&mut out).await.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&out[..n], payload.as_slice());
        assert_eq!(got, target);
    }
}
