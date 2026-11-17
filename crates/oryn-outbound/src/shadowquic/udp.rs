// 线格式与控制流映射移植自 MetaCubeX/mihomo transport/shadowquic/{packet,state,protocol}.go
// @ 88dcbf7f1614a67c3b36b848ee3592dfa92ada36。Copyright (C) MetaCubeX contributors.
// SPDX-License-Identifier: GPL-3.0-or-later
// Modified for Oryn: 所有映射、未知 ID 暂存、后台任务和队列均有硬上限。
use crate::{slots::Slot, PacketConn, Resolver};
use async_trait::async_trait;
use oryn_config::TargetAddr;
use oryn_protocol::socks5;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
#[cfg(test)]
#[path = "udp_lifecycle_tests.rs"]
mod lifecycle_tests;
const MAX_IDS: usize = 256;
const MAX_DESTINATIONS: usize = 32;
const MAX_PAYLOAD: usize = 8192;
struct Receiver {
    id: u64,
    tx: mpsc::Sender<(Vec<u8>, TargetAddr)>,
    stop: CancellationToken,
}
struct Route {
    receiver: Weak<Receiver>,
    target: TargetAddr,
}
struct Pending {
    id: u16,
    data: Vec<u8>,
    when: Instant,
}
type StreamBinding = (Arc<Receiver>, TargetAddr);

#[derive(Default)]
struct Routes {
    recv: HashMap<u16, Route>,
    send: HashSet<u16>,
    next: u16,
    pending: VecDeque<Pending>,
    // 仅由最多 32 个接收 child 创建；注册时固定关联代次，不能重新按 ID 投递。
    waiting: Vec<(u16, oneshot::Sender<StreamBinding>)>,
}
pub(super) struct Hub {
    pub conn: quinn::Connection,
    routes: Mutex<Routes>,
    notify: Notify,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    next: AtomicU64,
}
impl Drop for Hub {
    fn drop(&mut self) {
        for task in self.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}
impl Hub {
    pub fn new(conn: quinn::Connection) -> Arc<Self> {
        let hub = Arc::new(Self {
            conn: conn.clone(),
            routes: Mutex::new(Routes::default()),
            notify: Notify::new(),
            tasks: Mutex::new(Vec::new()),
            next: AtomicU64::new(1),
        });
        let weak = Arc::downgrade(&hub);
        let datagrams = conn.clone();
        let read = tokio::spawn(async move {
            while let Ok(packet) = datagrams.read_datagram().await {
                if packet.len() < 2 || packet.len() > MAX_PAYLOAD + 2 {
                    continue;
                }
                let Some(h) = weak.upgrade() else {
                    break;
                };
                h.deliver(
                    u16::from_be_bytes([packet[0], packet[1]]),
                    packet[2..].to_vec(),
                );
            }
        });
        let weak = Arc::downgrade(&hub);
        let streams = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    _=conn.closed()=>break,
                    _=children.join_next(),if !children.is_empty()=>{},
                    incoming=conn.accept_uni(),if children.len()<32=>{
                        let Ok(mut stream)=incoming else{break;};let weak=weak.clone();
                        children.spawn(async move {
                            let header=tokio::time::timeout(Duration::from_secs(2),stream.read_u16()).await;
                            let Ok(Ok(id))=header else{let _=stream.stop(0u32.into());return;};
                            let binding = weak.upgrade().map(|h| h.bind_stream(id));
                            if let Some(binding) = binding {
                                // 未知 ID 可以先到：暂存在线流中等待控制注册，但等待有界。
                                if let Ok(Ok((receiver, target))) = tokio::time::timeout(Duration::from_secs(2), binding).await {
                                    let read = async {
                                        while let Ok(n) = stream.read_u16().await {
                                            let n = usize::from(n);
                                            if n > MAX_PAYLOAD { break; }
                                            let mut data = vec![0; n];
                                            if stream.read_exact(&mut data).await.is_err() { break; }
                                            let _ = receiver.tx.try_send((data, target.clone()));
                                        }
                                    };
                                    tokio::select! {
                                        biased;
                                        _ = receiver.stop.cancelled() => {},
                                        _ = read => {},
                                    }
                                }
                            }
                            let _ = stream.stop(0u32.into());
                        });
                    }
                }
            }
        });
        hub.tasks.lock().unwrap().extend([read, streams]);
        hub
    }
    fn bind_stream(&self, id: u16) -> oneshot::Receiver<StreamBinding> {
        let (tx, rx) = oneshot::channel();
        let mut r = self.routes.lock().unwrap();
        r.waiting.retain(|(_, tx)| !tx.is_closed());
        if let Some(route) = r.recv.get(&id) {
            if let Some(receiver) = route.receiver.upgrade() {
                let _ = tx.send((receiver, route.target.clone()));
            }
        } else {
            r.waiting.push((id, tx));
        }
        rx
    }
    fn deliver(&self, id: u16, data: Vec<u8>) {
        let mut r = self.routes.lock().unwrap();
        if let Some(route) = r.recv.get(&id) {
            if let Some(receiver) = route.receiver.upgrade() {
                let _ = receiver.tx.try_send((data, route.target.clone()));
            }
            return;
        }
        r.pending
            .retain(|p| p.when.elapsed() < Duration::from_secs(2));
        if r.pending.len() < 8
            && r.pending.iter().map(|p| p.data.len()).sum::<usize>() + data.len() <= 64 * 1024
        {
            r.pending.push_back(Pending {
                id,
                data,
                when: Instant::now(),
            });
        }
    }
    fn register(&self, id: u16, receiver: &Arc<Receiver>, target: TargetAddr) -> io::Result<()> {
        let mut r = self.routes.lock().unwrap();
        let count = r
            .recv
            .values()
            .filter(|v| v.receiver.upgrade().is_some_and(|v| v.id == receiver.id))
            .count();
        if count >= MAX_DESTINATIONS || r.recv.len() >= MAX_IDS {
            return Err(io::Error::other("ShadowQUIC receive context limit reached"));
        }
        if r.recv.contains_key(&id) {
            return Err(io::Error::other("ShadowQUIC duplicate receive context"));
        }
        r.recv.insert(
            id,
            Route {
                receiver: Arc::downgrade(receiver),
                target: target.clone(),
            },
        );
        let mut waiting = Vec::new();
        for (waiting_id, tx) in r.waiting.drain(..) {
            if waiting_id == id {
                let _ = tx.send((receiver.clone(), target.clone()));
            } else if !tx.is_closed() {
                waiting.push((waiting_id, tx));
            }
        }
        r.waiting = waiting;
        let mut keep = VecDeque::new();
        while let Some(p) = r.pending.pop_front() {
            if p.when.elapsed() >= Duration::from_secs(2) {
                continue;
            }
            if p.id == id {
                let _ = receiver.tx.try_send((p.data, target.clone()));
            } else {
                keep.push_back(p);
            }
        }
        r.pending = keep;
        self.notify.notify_waiters();
        Ok(())
    }
    fn id(&self) -> io::Result<u16> {
        let mut r = self.routes.lock().unwrap();
        if r.send.len() >= MAX_IDS {
            return Err(io::Error::other("ShadowQUIC send context limit reached"));
        }
        for _ in 0..=u16::MAX {
            let id = r.next;
            r.next = r.next.wrapping_add(1);
            if r.send.insert(id) {
                return Ok(id);
            }
        }
        Err(io::Error::other("ShadowQUIC context IDs exhausted"))
    }
}
struct Writer {
    control: quinn::SendStream,
    ids: HashMap<TargetAddr, u16>,
    streams: HashMap<u16, quinn::SendStream>,
}
struct Packet {
    hub: Arc<Hub>,
    receiver: Arc<Receiver>,
    read: AsyncMutex<mpsc::Receiver<(Vec<u8>, TargetAddr)>>,
    write: AsyncMutex<Writer>,
    task: JoinHandle<()>,
    uos: bool,
    max_datagram: usize,
    resolver: Arc<dyn Resolver>,
    _slot: Slot,
}
impl Drop for Packet {
    fn drop(&mut self) {
        self.receiver.stop.cancel();
        self.task.abort();
        let writer = self.write.get_mut();
        let _ = writer.control.reset(0u32.into());
        for stream in writer.streams.values_mut() {
            let _ = stream.reset(0u32.into());
        }
        let mut r = self.hub.routes.lock().unwrap();
        for id in writer.ids.values() {
            r.send.remove(id);
        }
        r.recv.retain(|_, route| {
            route
                .receiver
                .upgrade()
                .is_some_and(|v| v.id != self.receiver.id)
        });
    }
}
pub(super) async fn open(
    hub: Arc<Hub>,
    uos: bool,
    max_datagram: usize,
    resolver: Arc<dyn Resolver>,
    slot: Slot,
) -> io::Result<Box<dyn PacketConn>> {
    let (mut control, mut incoming) = hub.conn.open_bi().await.map_err(io::Error::other)?;
    control
        .write_all(&[if uos { 4 } else { 3 }, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(io::Error::other)?;
    let (tx, rx) = mpsc::channel(8);
    let receiver = Arc::new(Receiver {
        id: hub.next.fetch_add(1, Ordering::Relaxed),
        tx,
        stop: CancellationToken::new(),
    });
    let recv = receiver.clone();
    let weak = Arc::downgrade(&hub);
    let task = tokio::spawn(async move {
        let work = async {
            loop {
                let target = socks5::read_addr(&mut incoming).await?;
                let id = incoming.read_u16().await?;
                let h = weak
                    .upgrade()
                    .ok_or_else(|| io::Error::other("ShadowQUIC connection dropped"))?;
                h.register(id, &recv, target)?;
            }
        };
        tokio::select! {_=recv.stop.cancelled()=>{},r=work=>{let _:io::Result<()>=r;}}
        recv.stop.cancel();
        let _ = incoming.stop(0u32.into());
    });
    Ok(Box::new(Packet {
        hub,
        receiver,
        read: AsyncMutex::new(rx),
        write: AsyncMutex::new(Writer {
            control,
            ids: HashMap::new(),
            streams: HashMap::new(),
        }),
        task,
        uos,
        max_datagram,
        resolver,
        _slot: slot,
    }))
}
struct CancelGuard {
    stop: CancellationToken,
    armed: bool,
}
impl Drop for CancelGuard {
    fn drop(&mut self) {
        if self.armed {
            self.stop.cancel();
        }
    }
}
#[async_trait]
impl PacketConn for Packet {
    async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<()> {
        if self.receiver.stop.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "ShadowQUIC association closed",
            ));
        }
        let limit = if self.uos {
            MAX_PAYLOAD
        } else {
            self.hub
                .conn
                .max_datagram_size()
                .unwrap_or(0)
                .min(self.max_datagram)
                .saturating_sub(2)
        };
        if buf.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ShadowQUIC UDP payload exceeds carrier limit",
            ));
        }
        let addresses = crate::resolve_target(self.resolver.as_ref(), target).await?;
        let target = TargetAddr::Ip(addresses[0]);
        let mut w = self.write.lock().await;
        let id = if let Some(id) = w.ids.get(&target) {
            *id
        } else {
            // 目的地满、ID 用尽只是这一个包失败，不能拆掉整个关联
            if w.ids.len() >= MAX_DESTINATIONS {
                return Err(io::Error::other("ShadowQUIC destination limit reached"));
            }
            self.hub.id()?
        };
        // 守卫只覆盖会写流的部分：控制流 / UoS 流上的部分写入（出错或被取消）会破坏帧边界，
        // 这时整个关联必须作废；数据报发送失败只影响这一个包。
        let mut guard = CancelGuard {
            stop: self.receiver.stop.clone(),
            armed: true,
        };
        if !w.ids.contains_key(&target) {
            w.ids.insert(target.clone(), id);
            let mut header = Vec::new();
            socks5::encode_addr(&target, &mut header)?;
            header.extend_from_slice(&id.to_be_bytes());
            w.control
                .write_all(&header)
                .await
                .map_err(io::Error::other)?;
        }
        if self.uos {
            if let std::collections::hash_map::Entry::Vacant(e) = w.streams.entry(id) {
                let mut stream = self.hub.conn.open_uni().await.map_err(io::Error::other)?;
                stream
                    .write_all(&id.to_be_bytes())
                    .await
                    .map_err(io::Error::other)?;
                e.insert(stream);
            }
            let stream = w.streams.get_mut(&id).unwrap();
            let mut packet = (buf.len() as u16).to_be_bytes().to_vec();
            packet.extend_from_slice(buf);
            stream.write_all(&packet).await.map_err(io::Error::other)?;
        } else {
            guard.armed = false;
            let mut packet = id.to_be_bytes().to_vec();
            packet.extend_from_slice(buf);
            self.hub
                .conn
                .send_datagram(packet.into())
                .map_err(io::Error::other)?;
        }
        guard.armed = false;
        Ok(())
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut rx = self.read.lock().await;
        let result = tokio::select! {_=self.receiver.stop.cancelled()=>None,_=self.hub.conn.closed()=>None,item=rx.recv()=>item};
        let (data, target) = result.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "ShadowQUIC UDP association closed",
            )
        })?;
        let n = crate::copy_datagram(&data, buf, "ShadowQUIC");
        Ok((n, target))
    }
}
