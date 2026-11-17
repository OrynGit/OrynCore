//! WireGuard 的虚拟 IP 设备。包不离开本 crate。

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

/// 待加密发送队列上限。满了 smoltcp 拿不到发送令牌：TCP 自然回压，UDP 留在套接字缓冲里，
/// 套接字缓冲再满则新数据报被丢弃。
pub const TX_QUEUE: usize = 32;
const RX_QUEUE: usize = 64;

pub struct VirtDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl VirtDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }

    /// 解密后的包；队列满则丢弃（对端会按 TCP 重传）。
    pub fn push_rx(&mut self, packet: Vec<u8>) {
        if self.rx.len() < RX_QUEUE {
            self.rx.push_back(packet);
        }
    }

    /// 一组分片整组入队；放不下整组时整组丢弃，返回 false。
    pub fn push_tx_all(&mut self, packets: Vec<Vec<u8>>) -> bool {
        if self.tx.len() + packets.len() > TX_QUEUE {
            return false;
        }
        self.tx.extend(packets);
        true
    }

    pub fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }
}

pub struct VirtRx(Vec<u8>);
pub struct VirtTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for VirtRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = self.0;
        f(&mut packet)
    }
}

impl TxToken for VirtTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        // 只有 `transmit` 在队列未满时才发令牌；`receive` 附带的令牌用于即时 ACK，可能多出一个
        if self.0.len() < TX_QUEUE {
            self.0.push_back(packet);
        }
        result
    }
}

impl Device for VirtDevice {
    type RxToken<'a> = VirtRx;
    type TxToken<'a> = VirtTx<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((VirtRx(packet), VirtTx(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.tx.len() >= TX_QUEUE {
            return None;
        }
        Some(VirtTx(&mut self.tx))
    }
}
