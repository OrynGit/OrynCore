//! 有界载体池：只复用协议连接，DNS 与链式代理继续走现有接口。
use super::wire::{self, Codec, Frame};
use crate::{BoxStream, Dialer, Resolver};
use oryn_config::{MieruSpec, TargetAddr};
use oryn_udp::DatagramFactory;
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, Semaphore},
};
use tokio_util::sync::CancellationToken;

/// 独立于活跃会话，限制满发送队列下尚未完成的关闭通知。
pub(super) const MAX_CLOSE_WAITERS: usize = 32;

pub struct Carrier {
    pub send: mpsc::Sender<Frame>,
    pub close_waiters: Arc<Semaphore>,
    pub sessions: Mutex<HashMap<u32, mpsc::Sender<Frame>>>,
    pub stop: CancellationToken,
    pub packet: bool,
    pub reusable: bool,
    pub chunk: usize,
}
impl Drop for Carrier {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
/// 一个帧装多少应用数据。
///
/// UDP 数据报要小于路径 MTU，所以 1 KiB（低熵画像 512）；TCP 载体是字节流，解码端允许到 32 KiB，
/// 用 8 KiB 一帧：每帧一次 XChaCha20-Poly1305 加密和一次队列传递，原来固定 1 KiB 时上行每传 1 GiB
/// 要多花 8 倍的这些固定开销，真机上行只有 220–330 Mbit/s（下行服务端发大记录，不受影响）。
fn payload_chunk(udp: bool, low_entropy: bool) -> usize {
    match (udp, low_entropy) {
        (true, true) => 512,
        (true, false) => wire::CHUNK,
        (false, _) => TCP_CHUNK,
    }
}
pub const TCP_CHUNK: usize = 8 * 1024;
// 解码端对 TCP 记录的上限是 32 KiB，帧负载加上元数据必须放得下（编译期检查）
const _: () = assert!(TCP_CHUNK + 1024 <= 32 * 1024);

impl Carrier {
    pub async fn connect(
        spec: &MieruSpec,
        dialer: &dyn Dialer,
        resolver: &dyn Resolver,
        datagrams: &dyn DatagramFactory,
    ) -> io::Result<(Arc<Self>, u64)> {
        let begin = spec.server.port();
        let offset = u32::from_be_bytes(wire::random()?)
            % (u32::from(spec.port_end).saturating_sub(u32::from(begin)) + 1);
        let port = begin + offset as u16;
        let target = match &spec.server {
            TargetAddr::Domain(host, _) => TargetAddr::Domain(host.clone(), port),
            TargetAddr::Ip(a) => {
                let mut a = *a;
                a.set_port(port);
                TargetAddr::Ip(a)
            }
        };
        let key_time = wire::now();
        let key = wire::key(&spec.username, &spec.password, key_time);
        let pattern = super::pattern::Pattern::new(&spec.traffic_pattern);
        let chunk = payload_chunk(spec.transport_udp, pattern.mode != 0);
        let mut send_codec = Codec::new(
            &key,
            spec.username.clone(),
            spec.transport_udp,
            pattern.clone(),
        );
        let mut recv_codec = Codec::new(&key, spec.username.clone(), spec.transport_udp, pattern);
        // 队列按字节算有上限：UDP 32 × 1 KiB，TCP 16 × 8 KiB（原来 TCP 也是 32 × 1 KiB，上行被小帧拖慢）
        let (tx, mut rx) = mpsc::channel::<Frame>(if spec.transport_udp { 32 } else { 16 });
        let carrier = Arc::new(Self {
            send: tx,
            close_waiters: Arc::new(Semaphore::new(MAX_CLOSE_WAITERS)),
            sessions: Mutex::new(HashMap::new()),
            stop: CancellationToken::new(),
            packet: spec.transport_udp,
            reusable: spec.multiplexing > 1,
            chunk,
        });
        if spec.transport_udp {
            let peer = crate::resolve_target(resolver, &target)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| wire::bad("Mieru no server address"))?;
            let socket = datagrams.bind(peer).await?;
            let weak = Arc::downgrade(&carrier);
            let stop = carrier.stop.clone();
            let sender = socket.clone();
            tokio::spawn(async move {
                let work = async {
                    while let Some(frame) = rx.recv().await {
                        let packet = send_codec.encode(&frame)?;
                        // 瞬时发送错误只丢这一个数据报，会话层的重传会补上；
                        // 不能让它结束任务、拆掉载体上的全部会话
                        if let Err(err) = sender.try_send_to(&packet, peer) {
                            if !crate::is_transient_udp_send_error(&err) {
                                return Err(err);
                            }
                        }
                    }
                    Ok::<_, io::Error>(())
                };
                tokio::select! { _ = stop.cancelled() => {}, _ = work => {} }
                stop.cancel();
            });
            let stop = carrier.stop.clone();
            tokio::spawn(async move {
                let work = async {
                    let mut buf = [0; 1501];
                    loop {
                        let (n, from) = socket.recv_from(&mut buf).await?;
                        if from != peer {
                            continue;
                        }
                        let Ok(frame) = recv_codec.decode(&buf[..n]) else {
                            continue;
                        };
                        let Some(c) = weak.upgrade() else {
                            break;
                        };
                        let tx = c.sessions.lock().unwrap().get(&frame.id).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.try_send(frame);
                        }
                    }
                    Ok::<_, io::Error>(())
                };
                tokio::select! { _ = stop.cancelled() => {}, _ = work => {} }
                stop.cancel();
            });
        } else {
            let stream: BoxStream = dialer.dial_tcp(&target).await?;
            let (mut reader, mut writer) = tokio::io::split(stream);
            let weak = Arc::downgrade(&carrier);
            let stop = carrier.stop.clone();
            tokio::spawn(async move {
                let work = async {
                    while let Some(frame) = rx.recv().await {
                        let data = send_codec.encode(&frame)?;
                        if frame.kind <= 5 && send_codec.pattern.fragment {
                            let min = (data.len() as f64).sqrt() as usize + 1;
                            let max = min.max(data.len() / 2);
                            let mut at = 0;
                            while at < data.len() {
                                let size = (min
                                    + usize::from(wire::random::<1>()?[0]) % (max - min + 1))
                                    .min(data.len() - at);
                                writer.write_all(&data[at..at + size]).await?;
                                at += size;
                                let ms = u64::from(wire::random::<1>()?[0])
                                    % (u64::from(send_codec.pattern.sleep_ms) + 1);
                                if ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(ms)).await;
                                }
                            }
                        } else {
                            writer.write_all(&data).await?;
                        }
                    }
                    Ok::<_, io::Error>(())
                };
                tokio::select! { _ = stop.cancelled() => {}, _ = work => {} }
                stop.cancel();
            });
            let stop = carrier.stop.clone();
            tokio::spawn(async move {
                let work = async {
                    loop {
                        let frame = recv_codec.read(&mut reader).await?;
                        let Some(c) = weak.upgrade() else {
                            break;
                        };
                        let tx = c.sessions.lock().unwrap().get(&frame.id).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send(frame).await;
                        }
                    }
                    Ok::<_, io::Error>(())
                };
                tokio::select! { _ = stop.cancelled() => {}, _ = work => {} }
                stop.cancel();
            });
        }
        let weak = Arc::downgrade(&carrier);
        let stop = carrier.stop.clone();
        tokio::spawn(async move {
            let mut idle = tokio::time::interval(Duration::from_secs(30));
            idle.tick().await;
            let mut was_empty = false;
            loop {
                tokio::select! { _ = stop.cancelled() => break, _ = idle.tick() => {} }
                let Some(c) = weak.upgrade() else {
                    break;
                };
                let empty = c.sessions.lock().unwrap().is_empty();
                if empty && was_empty {
                    stop.cancel();
                    break;
                }
                was_empty = empty;
            }
        });
        Ok((carrier, key_time))
    }
    pub async fn write(&self, frame: Frame) -> io::Result<()> {
        tokio::select! {
            _ = self.stop.cancelled() => Err(io::Error::new(io::ErrorKind::BrokenPipe, "Mieru carrier closed")),
            r = self.send.send(frame) => r.map_err(|_| wire::bad("Mieru writer closed")),
        }
    }
}

#[cfg(test)]
#[path = "carrier_backpressure_tests.rs"]
mod backpressure_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_carrier_frames_are_large_and_udp_stays_under_the_mtu() {
        assert_eq!(payload_chunk(false, false), 8 * 1024);
        assert_eq!(payload_chunk(false, true), 8 * 1024);
        assert_eq!(payload_chunk(true, false), 1024);
        assert_eq!(payload_chunk(true, true), 512);
    }
}
