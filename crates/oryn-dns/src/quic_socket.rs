//! 让 quinn 通过任意出站的 UDP（[`PacketConn`]）收发数据，用于经代理访问 DoQ / DoH3。

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use oryn_config::TargetAddr;
use oryn_outbound::PacketConn;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// 发送与接收队列的容量（数据报个数）。队列满时丢弃，由 QUIC 自身重传。
const QUEUE: usize = 256;
const MAX_DATAGRAM: usize = 2048;

pub struct PacketConnSocket {
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    local: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl fmt::Debug for PacketConnSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketConnSocket")
            .field("local", &self.local)
            .finish()
    }
}

impl Drop for PacketConnSocket {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl PacketConnSocket {
    pub fn new(pc: Box<dyn PacketConn>, ipv6: bool) -> Arc<Self> {
        let pc: Arc<dyn PacketConn> = Arc::from(pc);
        let (out_tx, mut out_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(QUEUE);
        let (in_tx, in_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(QUEUE);
        let sender = {
            let pc = pc.clone();
            tokio::spawn(async move {
                while let Some((data, addr)) = out_rx.recv().await {
                    if pc.send_to(&data, &TargetAddr::Ip(addr)).await.is_err() {
                        break;
                    }
                }
            })
        };
        let receiver = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            while let Ok((n, from)) = pc.recv_from(&mut buf).await {
                if let TargetAddr::Ip(addr) = from {
                    if in_tx.try_send((buf[..n].to_vec(), addr)).is_err() && in_tx.is_closed() {
                        break;
                    }
                }
            }
        });
        let local = if ipv6 {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        };
        Arc::new(PacketConnSocket {
            tx: out_tx,
            rx: Mutex::new(in_rx),
            local,
            tasks: vec![sender, receiver],
        })
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for PacketConnSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        for chunk in transmit.contents.chunks(segment) {
            // 队列满时丢弃（UDP 语义），不返回 WouldBlock
            let _ = self.tx.try_send((chunk.to_vec(), transmit.destination));
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.rx.lock().unwrap();
        match rx.poll_recv(cx) {
            Poll::Ready(Some((data, addr))) => {
                let n = data.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&data[..n]);
                meta[0] = RecvMeta {
                    addr,
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}
