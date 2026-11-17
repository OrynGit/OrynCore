// Sudoku UoT 格式参考 MetaCubeX/mihomo transport/sudoku/uot.go @ 88dcbf7f1614a67c3b36b848ee3592dfa92ada36。
// GPL-3.0；原文件未单列版权声明。读取与发送缓冲跨取消保留，避免错位。
use super::bad;
use crate::{BoxStream, PacketConn, Resolver};
use async_trait::async_trait;
use oryn_config::TargetAddr;
use oryn_protocol::socks5;
use std::{io, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::Mutex,
};
struct Read {
    inner: ReadHalf<BoxStream>,
    pending: Vec<u8>,
}
struct Write {
    inner: WriteHalf<BoxStream>,
    pending: Vec<u8>,
    offset: usize,
}
pub struct Packet {
    read: Mutex<Read>,
    write: Mutex<Write>,
    resolver: Arc<dyn Resolver>,
}
impl Packet {
    pub fn new(stream: BoxStream, resolver: Arc<dyn Resolver>) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self {
            read: Mutex::new(Read {
                inner: r,
                pending: vec![],
            }),
            write: Mutex::new(Write {
                inner: w,
                pending: vec![],
                offset: 0,
            }),
            resolver,
        }
    }
}
impl Write {
    async fn flush(&mut self) -> io::Result<()> {
        while self.offset < self.pending.len() {
            let n = self.inner.write(&self.pending[self.offset..]).await?;
            if n == 0 {
                return Err(bad("Sudoku UoT write closed"));
            }
            self.offset += n;
        }
        self.pending.clear();
        self.offset = 0;
        self.inner.flush().await
    }
}
#[async_trait]
impl PacketConn for Packet {
    async fn send_to(&self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        if data.len() > 8192 {
            return Err(bad("Sudoku UDP payload exceeds 8192 bytes"));
        }
        let addresses = crate::resolve_target(self.resolver.as_ref(), target).await?;
        let mut addr = vec![];
        socks5::encode_addr(&TargetAddr::Ip(addresses[0]), &mut addr)?;
        let mut w = self.write.lock().await;
        w.flush().await?;
        w.pending
            .extend_from_slice(&(addr.len() as u16).to_be_bytes());
        w.pending
            .extend_from_slice(&(data.len() as u16).to_be_bytes());
        w.pending.extend_from_slice(&addr);
        w.pending.extend_from_slice(data);
        w.flush().await
    }
    async fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut r = self.read.lock().await;
        loop {
            if r.pending.len() >= 4 {
                let a = usize::from(u16::from_be_bytes([r.pending[0], r.pending[1]]));
                let n = usize::from(u16::from_be_bytes([r.pending[2], r.pending[3]]));
                if !(7..=259).contains(&a) || n > 8192 {
                    return Err(bad("invalid Sudoku UoT frame length"));
                }
                if r.pending.len() >= 4 + a + n {
                    let (addr, used) = socks5::decode_addr(&r.pending[4..4 + a])
                        .ok_or_else(|| bad("invalid Sudoku UoT address"))?;
                    if used != a {
                        return Err(bad("invalid Sudoku UoT address length"));
                    }
                    let len = crate::copy_datagram(&r.pending[4 + a..4 + a + n], out, "Sudoku");
                    r.pending.drain(..4 + a + n);
                    return Ok((len, addr));
                }
            }
            let mut scratch = [0; 2048];
            let n = r.inner.read(&mut scratch).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Sudoku UoT stream closed",
                ));
            }
            r.pending.extend_from_slice(&scratch[..n]);
        }
    }
}
