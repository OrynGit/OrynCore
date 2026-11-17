//! `dialer-proxy`：经由另一个出站拨出。
//!
//! TCP 协议的下层拨号器换成另一个出站的 `connect_tcp`；基于 UDP 的协议（QUIC、WireGuard、
//! SOCKS5 UDP、Shadowsocks 原生 UDP）的数据报通道换成另一个出站的 `bind_udp`。链在出站内部，
//! 不再经过 Router：Flow 仍然只做一次规则匹配。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use oryn_config::TargetAddr;
use oryn_udp::{DatagramFactory, Datagrams};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::{BoxStream, Dialer, Outbound, PacketConn};

/// 队列容量（数据报个数）。队列满时丢弃，由上层协议重传。
const QUEUE: usize = 256;
const MAX_DATAGRAM: usize = 65535;

pub(crate) struct ChainDialer(pub Arc<dyn Outbound>);

#[async_trait]
impl Dialer for ChainDialer {
    async fn dial_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        self.0.connect_tcp(target).await
    }
}

pub(crate) struct ChainDatagrams(pub Arc<dyn Outbound>);

#[async_trait]
impl DatagramFactory for ChainDatagrams {
    async fn bind(&self, peer: SocketAddr) -> io::Result<Arc<dyn Datagrams>> {
        let conn: Arc<dyn PacketConn> = Arc::from(self.0.bind_udp(&TargetAddr::Ip(peer)).await?);
        let (out_tx, mut out_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(QUEUE);
        let (in_tx, in_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(QUEUE);
        let sender = {
            let conn = conn.clone();
            tokio::spawn(async move {
                while let Some((data, dest)) = out_rx.recv().await {
                    // 单个数据报发送失败不拆通道：UDP 语义
                    let _ = conn.send_to(&data, &TargetAddr::Ip(dest)).await;
                }
            })
        };
        // 独立任务读取，避免调用方的 select! 取消 recv_from 时丢数据报
        let receiver = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            while let Ok((n, from)) = conn.recv_from(&mut buf).await {
                if let TargetAddr::Ip(addr) = from {
                    if in_tx.try_send((buf[..n].to_vec(), addr)).is_err() && in_tx.is_closed() {
                        break;
                    }
                }
            }
        });
        Ok(Arc::new(ChainChannel {
            tx: out_tx,
            rx: tokio::sync::Mutex::new(in_rx),
            tasks: vec![sender, receiver],
        }))
    }
}

struct ChainChannel {
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for ChainChannel {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[async_trait]
impl Datagrams for ChainChannel {
    fn try_send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<()> {
        match self.tx.try_send((buf.to_vec(), peer)) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        let (data, from) = rx
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let n = crate::copy_datagram(&data, buf, "chain");
        Ok((n, from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DirectDialer, DirectOutbound, Resolver};
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    struct Local;
    #[async_trait]
    impl Resolver for Local {
        async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
            Ok(vec!["127.0.0.1".parse().unwrap()])
        }
    }

    fn direct() -> Arc<dyn Outbound> {
        Arc::new(DirectOutbound::new(
            "D".into(),
            Arc::new(DirectDialer::new(Arc::new(Local))),
        ))
    }

    #[tokio::test]
    async fn tcp_goes_through_the_chained_outbound() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });
        let dialer = ChainDialer(direct());
        let mut stream = dialer
            .dial_tcp(&TargetAddr::Domain("chain.test".into(), addr.port()))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut b = [0; 5];
        stream.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hello");
    }

    #[tokio::test]
    async fn datagrams_go_through_the_chained_outbound() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0; 2048];
            loop {
                let (n, from) = echo.recv_from(&mut b).await.unwrap();
                echo.send_to(&b[..n], from).await.unwrap();
            }
        });
        let channel = ChainDatagrams(direct()).bind(addr).await.unwrap();
        let mut buf = vec![0u8; 2048];
        // recv_from 被取消不丢数据报
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(30),
            channel.recv_from(&mut buf)
        )
        .await
        .is_err());
        for payload in [b"one".as_slice(), b"two", &[7; 1200]] {
            channel.try_send_to(payload, addr).unwrap();
            let (n, from) = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                channel.recv_from(&mut buf),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!((from, &buf[..n]), (addr, payload));
        }
    }
}
