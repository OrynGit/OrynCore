//! 自定义 UDP 套接字：对 quinn 呈现稳定对端，线上可以混淆并改端口。
//!
//! Salamander 按 Hysteria2 公开协议独立实现。XPlus 与 Gecko 移植自 SagerNet/sing-quic：
//! `hysteria/xplus.go`（v0.6.1，commit 907fec5e8e6b973ff6a06f22b9aae010e17c96b0）与
//! `hysteria2/gecko.go`（v0.7.0-beta.4，commit 4ab2eceaac81e073f53b22ec72ff56aaea89a3d1）。
//! Copyright (C) 2023 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use blake2::digest::consts::U32;
use blake2::digest::Digest;
use blake2::Blake2b;
use oryn_udp::Datagrams;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::{mpsc, Notify};

use crate::brutal::Pacer;

const QUEUE: usize = 64;
/// 接收的单个线上数据报上限：覆盖 jumbo 帧链路与经 dialer-proxy 的大包。
/// 超过的包整包丢弃（截断后只会解密失败，还会污染重组状态）。
const MAX_DATAGRAM: usize = 9216;
/// 新缓冲的初始容量：覆盖以太网 MTU 的 QUIC 包与混淆开销，大包按需增长。
const POOL_INITIAL: usize = 1536;

/// 数据报缓冲池：收发通道里流转的 `Vec` 用完归还，稳态下每包不再分配。
/// 池中缓冲数不超过通道容量，所以不会比通道排满时占用更多内存。
struct BufPool(Mutex<Vec<Vec<u8>>>);

impl BufPool {
    fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    fn take(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(POOL_INITIAL))
    }

    fn put(&self, mut buf: Vec<u8>) {
        if buf.capacity() > MAX_DATAGRAM + 64 {
            return;
        }
        buf.clear();
        let mut pool = self.0.lock().unwrap();
        if pool.len() < QUEUE {
            pool.push(buf);
        }
    }
}

pub struct Salamander {
    key: Vec<u8>,
}

impl Salamander {
    pub fn new(password: &[u8]) -> Self {
        Self {
            key: password.to_vec(),
        }
    }

    pub fn obfuscate(&self, packet: &[u8], out: &mut Vec<u8>) {
        salamander_obfuscate(&self.key, packet, out);
    }

    pub fn deobfuscate(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        salamander_deobfuscate(&self.key, packet, &mut out).then_some(out)
    }
}

fn salamander_hash(key: &[u8], salt: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::new()
        .chain_update(key)
        .chain_update(salt)
        .finalize()
        .into()
}

/// 追加「8 字节盐 + 异或后的包」到 `out`。
fn salamander_obfuscate(key: &[u8], packet: &[u8], out: &mut Vec<u8>) {
    let mut salt = [0u8; 8];
    fill_salt(&mut salt);
    out.extend_from_slice(&salt);
    xor_in(out, packet, &salamander_hash(key, &salt));
}

/// 还原后的包追加到 `out`；太短返回 false。
fn salamander_deobfuscate(key: &[u8], wire: &[u8], out: &mut Vec<u8>) -> bool {
    if wire.len() <= 8 {
        return false;
    }
    xor_in(out, &wire[8..], &salamander_hash(key, &wire[..8]));
    true
}

/// 套接字层的混淆。Salamander（Hysteria2）、XPlus（Hysteria v1）与 Gecko（Hysteria2，Salamander 之上
/// 把 QUIC 长首部包切成 2–8 片并填充到给定大小，见 docs/protocols/hysteria2.md）。
#[derive(Clone)]
pub enum Obfs {
    Salamander(Vec<u8>),
    XPlus(Vec<u8>),
    /// Hysteria v1 wechat-video：固定 13 字节外层首部，XPlus（若有）在其内层。
    WechatVideo {
        key: Option<Vec<u8>>,
        sequence: Arc<AtomicU32>,
    },
    Gecko {
        key: Vec<u8>,
        min: usize,
        max: usize,
    },
}

const XPLUS_SALT: usize = 16;
const GECKO_FLAG: u8 = 0x80;
const GECKO_HEADER: usize = 5;
const GECKO_MIN_CHUNKS: usize = 2;
const GECKO_MAX_CHUNKS: usize = 8;
const GECKO_TTL: std::time::Duration = std::time::Duration::from_secs(8);
/// 同时在重组的消息数（单个对端）。
const GECKO_MAX_PENDING: usize = 8;

/// 盐与填充用线程本地 CSPRNG（见 `fill_salt`），不每包一次系统调用、也不分配。
fn fill_random(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rng().fill_bytes(buf);
}

fn random_below(n: usize) -> usize {
    use rand::Rng;
    if n == 0 {
        0
    } else {
        rand::rng().random_range(0..n)
    }
}

fn xplus_apply(key: &[u8], salt: &[u8], input: &[u8], out: &mut Vec<u8>) {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(key);
    context.update(salt);
    xor_in(out, input, context.finish().as_ref());
}

/// 追加「16 字节盐 + XPlus 异或后的包」到 `out`。
fn xplus_obfuscate(key: &[u8], packet: &[u8], out: &mut Vec<u8>) {
    let mut salt = [0u8; XPLUS_SALT];
    fill_random(&mut salt);
    out.extend_from_slice(&salt);
    xplus_apply(key, &salt, packet, out);
}

/// 把 `input` 与 32 字节的密钥流按位异或后追加到 `out`。
/// 先整体复制再按 32 字节块原地异或，编译器能向量化；逐字节 `push` + 取模在每个数据报两个方向都要跑，
/// 曾是 Salamander 路径上比 AES 还重的热点（主机剖析）。
fn xor_in(out: &mut Vec<u8>, input: &[u8], key: &[u8]) {
    let start = out.len();
    out.extend_from_slice(input);
    xor_in_place(&mut out[start..], key);
}

fn xor_in_place(buf: &mut [u8], key: &[u8]) {
    let key: &[u8; 32] = key[..32].try_into().expect("32-byte keystream");
    for chunk in buf.chunks_mut(32) {
        for (byte, k) in chunk.iter_mut().zip(key) {
            *byte ^= k;
        }
    }
}

impl Obfs {
    /// 一个 QUIC 包变成线上的一个或多个数据报，逐个交给 `emit`。`wire` 是调用方复用的缓冲，
    /// 每个数据报写进去之后立刻交出，整个过程不分配。`emit` 出错时停止并返回该错误。
    pub fn write_wire(
        &self,
        packet: &[u8],
        gecko_id: &mut u8,
        wire: &mut Vec<u8>,
        emit: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        wire.clear();
        match self {
            Obfs::Salamander(key) => {
                salamander_obfuscate(key, packet, wire);
                emit(wire)
            }
            Obfs::XPlus(key) => {
                xplus_obfuscate(key, packet, wire);
                emit(wire)
            }
            Obfs::WechatVideo { key, sequence } => {
                wire.extend_from_slice(&[0xa1, 0x08]);
                let sequence = sequence.fetch_add(1, Ordering::Relaxed);
                wire.extend_from_slice(&sequence.to_be_bytes());
                wire.extend_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
                match key {
                    Some(key) => xplus_obfuscate(key, packet, wire),
                    None => wire.extend_from_slice(packet),
                }
                emit(wire)
            }
            Obfs::Gecko { key, min, max } => {
                if packet.is_empty() || packet[0] & GECKO_FLAG == 0 {
                    salamander_obfuscate(key, packet, wire);
                    return emit(wire);
                }
                let chunks =
                    GECKO_MIN_CHUNKS + random_below(GECKO_MAX_CHUNKS - GECKO_MIN_CHUNKS + 1);
                let size = packet.len() / chunks;
                *gecko_id = gecko_id.wrapping_add(1);
                for i in 0..chunks {
                    let start = i * size;
                    let end = if i < chunks - 1 {
                        start + size
                    } else {
                        packet.len()
                    };
                    let chunk = &packet[start..end];
                    // 线上大小（含 8 字节盐）落在 [min, max]；放不下时不填充
                    let base = 8 + GECKO_HEADER + chunk.len();
                    let lo = (*min).max(base);
                    let pad = if lo > *max {
                        0
                    } else {
                        lo - base + random_below(*max - lo + 1)
                    };
                    // 盐 + 明文帧原地拼好，再对盐之后的部分整体异或
                    wire.clear();
                    let mut salt = [0u8; 8];
                    fill_salt(&mut salt);
                    wire.extend_from_slice(&salt);
                    wire.extend_from_slice(&[
                        GECKO_FLAG,
                        *gecko_id,
                        (i as u8) << 4 | (chunks as u8 & 0x0f),
                    ]);
                    wire.extend_from_slice(&(pad as u16).to_be_bytes());
                    let padded = wire.len();
                    wire.resize(padded + pad, 0);
                    fill_random(&mut wire[padded..]);
                    wire.extend_from_slice(chunk);
                    xor_in_place(&mut wire[8..], &salamander_hash(key, &salt));
                    emit(wire)?;
                }
                Ok(())
            }
        }
    }

    /// 测试与诊断用：一次返回全部线上数据报。
    pub fn outgoing(&self, packet: &[u8], gecko_id: &mut u8) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut wire = Vec::new();
        let _ = self.write_wire(packet, gecko_id, &mut wire, &mut |w| {
            frames.push(w.to_vec());
            Ok(())
        });
        frames
    }
}

/// 一个正在重组的 Gecko 包：消息 ID、首片到达时间、各分片。
type GeckoPending = (u8, std::time::Instant, Vec<Option<Vec<u8>>>);

/// 接收方向的状态（Gecko 的分片重组）。
pub struct Deobfuscator {
    obfs: Obfs,
    pending: Vec<GeckoPending>,
    /// Gecko 解混淆的临时缓冲，跨包复用。
    scratch: Vec<u8>,
}

impl Deobfuscator {
    pub fn new(obfs: Obfs) -> Self {
        Self {
            obfs,
            pending: Vec::new(),
            scratch: Vec::new(),
        }
    }

    /// 测试用：还原一个线上数据报到新的 `Vec`。
    #[cfg(test)]
    pub fn incoming(&mut self, wire: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.incoming_into(wire, &mut out).then_some(out)
    }

    /// 还原一个线上数据报，追加到 `out`（调用方复用的缓冲）。返回 false 表示丢弃或还在等其它分片。
    pub fn incoming_into(&mut self, wire: &[u8], out: &mut Vec<u8>) -> bool {
        match &self.obfs {
            Obfs::Salamander(key) => salamander_deobfuscate(key, wire, out),
            Obfs::XPlus(key) => {
                if wire.len() < XPLUS_SALT {
                    return false;
                }
                xplus_apply(key, &wire[..XPLUS_SALT], &wire[XPLUS_SALT..], out);
                true
            }
            Obfs::WechatVideo { key, .. } => {
                if wire.len() <= 13
                    || wire[..2] != [0xa1, 0x08]
                    || wire[6..13] != [0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]
                {
                    return false;
                }
                let payload = &wire[13..];
                if let Some(key) = key {
                    if payload.len() < XPLUS_SALT {
                        return false;
                    }
                    xplus_apply(key, &payload[..XPLUS_SALT], &payload[XPLUS_SALT..], out);
                } else {
                    out.extend_from_slice(payload);
                }
                true
            }
            Obfs::Gecko { key, .. } => {
                let p = &mut self.scratch;
                p.clear();
                if !salamander_deobfuscate(key, wire, p) || p.is_empty() {
                    return false;
                }
                if p[0] & GECKO_FLAG == 0 {
                    out.extend_from_slice(p);
                    return true;
                }
                if p.len() < GECKO_HEADER {
                    return false;
                }
                let (id, index, total) = (p[1], (p[2] >> 4) as usize, (p[2] & 0x0f) as usize);
                let pad = u16::from_be_bytes([p[3], p[4]]) as usize;
                if !(GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS).contains(&total)
                    || index >= total
                    || GECKO_HEADER + pad > p.len()
                {
                    return false;
                }
                let now = std::time::Instant::now();
                self.pending
                    .retain(|(_, at, _)| now.duration_since(*at) < GECKO_TTL);
                let slot = match self.pending.iter().position(|(pid, _, _)| *pid == id) {
                    Some(i) => i,
                    None => {
                        if self.pending.len() >= GECKO_MAX_PENDING {
                            self.pending.remove(0);
                        }
                        self.pending.push((id, now, vec![None; total]));
                        self.pending.len() - 1
                    }
                };
                let chunks = &mut self.pending[slot].2;
                if chunks.len() != total || chunks[index].is_some() {
                    return false;
                }
                chunks[index] = Some(p[GECKO_HEADER + pad..].to_vec());
                if chunks.iter().any(Option::is_none) {
                    return false;
                }
                let (_, _, chunks) = self.pending.remove(slot);
                for chunk in chunks.into_iter().flatten() {
                    out.extend_from_slice(&chunk);
                }
                true
            }
        }
    }
}

/// Salamander 每包 8 字节盐。必须不可预测且不重复：同一盐对应同一密钥流，两包异或即暴露 QUIC 结构。
/// 用线程本地 CSPRNG（ChaCha，定期从系统熵重播种），不每包一次系统调用。
fn fill_salt(salt: &mut [u8; 8]) {
    use rand::RngCore;
    rand::rng().fill_bytes(salt);
}

/// 当前跳跃端口。0 表示不改写。
pub struct HopPort(pub AtomicU16);

pub struct QuicSocket {
    tx: mpsc::Sender<Vec<u8>>,
    /// 发送方向的缓冲池：`try_send` 取、发送任务发完归还。
    tx_pool: Arc<BufPool>,
    /// 接收方向的缓冲池：接收任务取、`poll_recv` 拷给 quinn 后归还。
    rx_pool: Arc<BufPool>,
    writable: Arc<Notify>,
    rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    local: SocketAddr,
    stable: SocketAddr,
    /// 发出的数据报带了「不分片」标志：quinn 才会做路径 MTU 探测（`may_fragment()` 为 false）。
    dont_fragment: bool,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for QuicSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicSocket")
            .field("local", &self.local)
            .field("stable", &self.stable)
            .finish()
    }
}

impl Drop for QuicSocket {
    fn drop(&mut self) {
        for task in &self._tasks {
            task.abort();
        }
    }
}

impl QuicSocket {
    /// `udp` 是到对端的数据报通道（直连的 UDP 套接字，或经由另一个出站）。
    pub fn bind(
        udp: Arc<dyn Datagrams>,
        stable: SocketAddr,
        hop: Arc<HopPort>,
        obfs: Option<Obfs>,
        pace: Option<Arc<AtomicU64>>,
    ) -> io::Result<Arc<Self>> {
        // 对 quinn 呈现的本地地址只用来区分地址族
        let local = SocketAddr::new(
            if stable.is_ipv6() {
                std::net::Ipv6Addr::UNSPECIFIED.into()
            } else {
                std::net::Ipv4Addr::UNSPECIFIED.into()
            },
            0,
        );
        // 套接字不会悄悄分片：quinn 因此可以把包从 1200 字节探测到路径允许的上限（见 `may_fragment`）。
        // 不支持的通道（经由其它出站、混淆改写长度）保持原来的固定 1200 字节。
        let dont_fragment = obfs.is_none() && udp.set_dont_fragment();
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let writable = Arc::new(Notify::new());
        let writable_sender = writable.clone();
        let (in_tx, in_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(QUEUE);
        let tx_pool = Arc::new(BufPool::new());
        let rx_pool = Arc::new(BufPool::new());
        let sender = {
            let udp = udp.clone();
            let obfs = obfs.clone();
            let pool = tx_pool.clone();
            tokio::spawn(async move {
                let mut pacer = pace.map(Pacer::new);
                let mut gecko_id = 0u8;
                let mut wire = Vec::with_capacity(POOL_INITIAL);
                while let Some(first) = out_rx.recv().await {
                    // 队列里积压的包一起处理：一次唤醒发完，而不是每个包唤醒一次
                    let mut next = Some(first);
                    let mut batch = 0;
                    while let Some(packet) = next.take() {
                        // Brutal 的速率在这里落实：quinn 的步调只跟随窗口 ÷ RTT，
                        // 低时延链路上窗口下限就足以让发送远超配置速率
                        if let Some(pacer) = &mut pacer {
                            pacer.wait(packet.len()).await;
                        }
                        writable_sender.notify_waiters();
                        let mut dest = stable;
                        let port = hop.0.load(Ordering::Relaxed);
                        if port != 0 {
                            dest.set_port(port);
                        }
                        // 只有通道关闭才结束；其它发送错误按丢包处理，由 QUIC 重传
                        let mut emit = |w: &[u8]| match udp.try_send_to(w, dest) {
                            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Err(err),
                            _ => Ok(()),
                        };
                        let sent = match &obfs {
                            Some(obfs) => {
                                obfs.write_wire(&packet, &mut gecko_id, &mut wire, &mut emit)
                            }
                            None => emit(&packet),
                        };
                        pool.put(packet);
                        if sent.is_err() {
                            return;
                        }
                        batch += 1;
                        if batch < QUEUE {
                            next = out_rx.try_recv().ok();
                        }
                    }
                }
            })
        };
        let receiver = {
            let mut deobfs = obfs.map(Deobfuscator::new);
            let pool = rx_pool.clone();
            tokio::spawn(async move {
                // 多留 1 字节：读满即说明数据报超过上限（已被截断）
                let mut buf = vec![0u8; MAX_DATAGRAM + 1];
                'outer: loop {
                    let Ok(mut received) = udp.recv_from(&mut buf).await else {
                        break;
                    };
                    // 等到一个包后，把已经到达的积压一次取完（有上限，避免饿死其它任务）
                    let mut drained = 0;
                    loop {
                        let (n, mut from) = received;
                        if n <= MAX_DATAGRAM {
                            let mut plain = pool.take();
                            let ok = match &mut deobfs {
                                Some(d) => d.incoming_into(&buf[..n], &mut plain),
                                None => {
                                    plain.extend_from_slice(&buf[..n]);
                                    true
                                }
                            };
                            if ok {
                                from.set_port(stable.port());
                                match in_tx.try_send((plain, from)) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full((plain, _))) => {
                                        pool.put(plain)
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => break 'outer,
                                }
                            } else {
                                pool.put(plain);
                            }
                        }
                        drained += 1;
                        if drained >= QUEUE {
                            break;
                        }
                        match udp.try_recv_from(&mut buf) {
                            Ok(Some(next)) => received = next,
                            Ok(None) => break,
                            Err(_) => break 'outer,
                        }
                    }
                }
            })
        };
        Ok(Arc::new(QuicSocket {
            tx: out_tx,
            tx_pool,
            rx_pool,
            writable,
            rx: Mutex::new(in_rx),
            local,
            stable,
            dont_fragment,
            _tasks: vec![sender, receiver],
        }))
    }
}

struct SocketPoller {
    socket: Arc<QuicSocket>,
    wait: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>,
}
impl std::fmt::Debug for SocketPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketPoller").finish()
    }
}
impl UdpPoller for SocketPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.socket.tx.is_closed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.socket.tx.capacity() > 0 {
            this.wait.lock().unwrap().take();
            return Poll::Ready(Ok(()));
        }
        let mut wait = this.wait.lock().unwrap().take();
        if wait.is_none() {
            let writable = this.socket.writable.clone();
            wait = Some(Box::pin(writable.notified_owned()));
        }
        // 订阅通知前后队列可能刚好释放槽位；重新检查避免错过通知后永久 Pending。
        if this.socket.tx.capacity() > 0 {
            return Poll::Ready(Ok(()));
        }
        let result = match wait
            .as_mut()
            .expect("writable wait initialized")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(()) => {
                if this.socket.tx.is_closed() {
                    Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
                } else if this.socket.tx.capacity() > 0 {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
            Poll::Pending => Poll::Pending,
        };
        if result.is_pending() {
            *this.wait.lock().unwrap() = wait;
        }
        result
    }
}

impl AsyncUdpSocket for QuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SocketPoller {
            socket: self,
            wait: Mutex::new(None),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        let needed = transmit.contents.chunks(segment).len();
        if self.tx.is_closed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if self.tx.capacity() < needed {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        for chunk in transmit.contents.chunks(segment) {
            let mut packet = self.tx_pool.take();
            packet.extend_from_slice(chunk);
            self.tx.try_send(packet).map_err(|err| match err {
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    io::Error::from(io::ErrorKind::BrokenPipe)
                }
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    io::Error::from(io::ErrorKind::WouldBlock)
                }
            })?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.rx.lock().unwrap();
        let mut filled = 0;
        let limit = bufs.len().min(meta.len());
        while filled < limit {
            let next = if filled == 0 {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(item)) => item,
                    Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                // 一次交给 quinn 尽量多的包，省掉每个包一次的轮询
                match rx.try_recv() {
                    Ok(item) => item,
                    Err(_) => break,
                }
            };
            let (data, addr) = next;
            let n = data.len().min(bufs[filled].len());
            bufs[filled][..n].copy_from_slice(&data[..n]);
            self.rx_pool.put(data);
            meta[filled] = RecvMeta {
                addr,
                len: n,
                stride: n,
                ecn: None,
                dst_ip: None,
            };
            filled += 1;
        }
        Poll::Ready(Ok(filled))
    }

    fn may_fragment(&self) -> bool {
        !self.dont_fragment
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_roundtrip() {
        let obfs = Salamander::new(b"secret-password");
        let mut wire = Vec::new();
        obfs.obfuscate(b"quic-packet", &mut wire);
        assert_eq!(wire.len(), 8 + 11);
        assert_eq!(obfs.deobfuscate(&wire).unwrap(), b"quic-packet");
        assert!(obfs.deobfuscate(&[1, 2, 3]).is_none());
    }

    #[test]
    fn xplus_and_gecko_roundtrip() {
        let mut id = 0u8;
        let xplus = Obfs::XPlus(b"xplus".to_vec());
        let wires = xplus.outgoing(b"quic-packet", &mut id);
        assert_eq!(wires.len(), 1);
        assert_eq!(wires[0].len(), 16 + 11);
        let mut d = Deobfuscator::new(xplus);
        assert_eq!(d.incoming(&wires[0]).unwrap(), b"quic-packet");
        // Gecko：短首部包不切片；长首部包切成 2–8 片，每片线上大小在 [min, max]
        let gecko = Obfs::Gecko {
            key: b"gecko".to_vec(),
            min: 512,
            max: 1200,
        };
        let short = gecko.outgoing(&[0x40, 1, 2, 3], &mut id);
        assert_eq!(short.len(), 1);
        let mut long = vec![0xc3u8];
        long.extend((0..1200u32).map(|i| i as u8));
        let frames = gecko.outgoing(&long, &mut id);
        assert!((2..=8).contains(&frames.len()));
        for f in &frames {
            assert!(
                f.len() >= 512 && f.len() <= 1200 || f.len() > 1200 - 8,
                "{}",
                f.len()
            );
        }
        let mut d = Deobfuscator::new(gecko.clone());
        assert_eq!(d.incoming(&short[0]).unwrap(), [0x40, 1, 2, 3]);
        // 乱序到达也能重组；重复分片忽略
        let mut out = None;
        for f in frames.iter().rev() {
            out = d.incoming(f).or(out);
            assert!(d.incoming(f).is_none() || out.is_some());
        }
        assert_eq!(out.unwrap(), long);
        // 未完成的消息数有上限
        let mut d = Deobfuscator::new(gecko.clone());
        for _ in 0..20 {
            let frames = gecko.outgoing(&long, &mut id);
            assert!(d.incoming(&frames[0]).is_none());
        }
        assert!(d.pending.len() <= GECKO_MAX_PENDING);
    }

    #[test]
    fn wechat_video_header_and_xplus_roundtrip() {
        let obfs = Obfs::WechatVideo {
            key: Some(b"xplus".to_vec()),
            sequence: Arc::new(AtomicU32::new(7)),
        };
        let mut id = 0u8;
        let wire = obfs.outgoing(b"quic-packet", &mut id);
        assert_eq!(wire.len(), 1);
        assert_eq!(&wire[0][..2], &[0xa1, 0x08]);
        assert_eq!(&wire[0][6..13], &[0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
        assert_eq!(wire[0].len(), 13 + 16 + 11);
        let mut decoder = Deobfuscator::new(obfs);
        assert_eq!(decoder.incoming(&wire[0]).unwrap(), b"quic-packet");
    }

    /// 混淆开销基准（默认忽略）：Salamander 与 XPlus 各处理 20 万个 1200 字节的包（各一去一回）。
    /// `cargo test --release -p oryn-quic obfs_bench -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn obfs_bench() {
        let packet = vec![0x5au8; 1200];
        let salamander = Salamander::new(b"bench-password");
        let started = std::time::Instant::now();
        let mut total = 0usize;
        for _ in 0..200_000 {
            let mut out = Vec::with_capacity(1208);
            salamander.obfuscate(&packet, &mut out);
            total += salamander.deobfuscate(&out).unwrap().len();
        }
        let salamander_time = started.elapsed();
        let started = std::time::Instant::now();
        for _ in 0..200_000 {
            let mut out = Vec::with_capacity(1200);
            xplus_apply(b"bench-password", &[1; 16], &packet, &mut out);
            total += out.len();
        }
        let xplus_time = started.elapsed();
        let mib = 200_000.0 * 1200.0 / 1048576.0;
        eprintln!(
            "salamander: {:.0} MiB/s (obfuscate + deobfuscate), xplus: {:.0} MiB/s, checksum {total}",
            mib / salamander_time.as_secs_f64(),
            mib / xplus_time.as_secs_f64()
        );
    }
}
