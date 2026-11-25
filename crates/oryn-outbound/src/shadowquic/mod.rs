// 协议移植自 MetaCubeX/mihomo transport/shadowquic/{client,protocol,packet,state,extension_brutal}.go
// @ 88dcbf7f1614a67c3b36b848ee3592dfa92ada36。Copyright (C) MetaCubeX contributors.
// SPDX-License-Identifier: GPL-3.0-or-later
// Modified for Oryn: Flow 接口、有界上下文与队列，QUIC / TLS 使用原生 Rust。
mod udp;
use crate::{
    slots::{Counted, HeldStream, Slots},
    BoxStream, Outbound, PacketConn, Resolver, SessionControl,
};
use async_trait::async_trait;
use oryn_config::{ShadowQuicSpec, TargetAddr};
use oryn_quic::{Congestion, NegotiatedFactory, QuicClient, QuicParams};
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use std::{
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Mutex;

pub struct ShadowQuicOutbound {
    name: String,
    spec: ShadowQuicSpec,
    resolver: Arc<dyn Resolver>,
    target_resolver: Arc<dyn Resolver>,
    quic: Arc<QuicClient>,
    slots: Slots,
    hub: std::sync::Mutex<Option<Arc<udp::Hub>>>,
    /// 协商单飞锁：等握手（最长 10 秒）与带宽协商（2 秒）期间持有；
    /// 已协商连接上的新 Flow 走 `hub` 快路径，不在这里排队。
    negotiating: Mutex<()>,
    rate: Arc<AtomicU64>,
}
struct Control(Arc<QuicClient>);
impl SessionControl for Control {
    fn on_network_changed(&self) {
        self.0.on_network_changed();
    }
    fn on_sleep(&self) {
        self.0.on_sleep();
        self.0.on_network_changed();
    }
    fn on_wake(&self) {
        self.0.on_wake();
    }
}
impl ShadowQuicOutbound {
    pub fn new(
        name: String,
        spec: ShadowQuicSpec,
        resolver: Arc<dyn Resolver>,
        target_resolver: Arc<dyn Resolver>,
        datagrams: Arc<dyn oryn_udp::DatagramFactory>,
    ) -> io::Result<Arc<Self>> {
        let tls = oryn_tls::jls::client_config(
            &spec.username,
            &spec.password,
            &spec.alpn,
            spec.zero_rtt,
        )?;
        // 至少两个包：一个包的窗口等于 Initial 数据报大小，quinn 判定阻塞后首包永远发不出（OrynCore#58）
        let window = u64::from(spec.cwnd.max(2)) * 1200;
        let factory: Arc<dyn ControllerFactory + Send + Sync> = match spec.congestion.as_str() {
            "bbr" => {
                let mut c = BbrConfig::default();
                c.initial_window(window);
                Arc::new(c)
            }
            "newreno" | "new_reno" => {
                let mut c = NewRenoConfig::default();
                c.initial_window(window);
                Arc::new(c)
            }
            _ => {
                let mut c = CubicConfig::default();
                c.initial_window(window);
                Arc::new(c)
            }
        };
        let rate = Arc::new(AtomicU64::new(0));
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(Some(
                Duration::from_secs(60)
                    .try_into()
                    .map_err(io::Error::other)?,
            ))
            .keep_alive_interval(
                (spec.keep_alive_ms > 0).then_some(Duration::from_millis(spec.keep_alive_ms)),
            )
            .stream_receive_window(quinn::VarInt::from_u32(spec.stream_window))
            .receive_window(quinn::VarInt::from_u32(spec.receive_window))
            .send_window(256 * 1024)
            .max_concurrent_bidi_streams(0u32.into())
            .max_concurrent_uni_streams(32u32.into())
            .datagram_receive_buffer_size(Some(spec.max_datagram))
            .datagram_send_buffer_size(64 * 1024)
            .initial_mtu(1200)
            .congestion_controller_factory(Arc::new(NegotiatedFactory {
                fallback: factory,
                rate: rate.clone(),
            }));
        if spec.disable_mtu_discovery {
            transport.mtu_discovery_config(None);
        }
        let quic = QuicClient::with_config(
            QuicParams {
                datagrams,
                alpn: spec.alpn.iter().map(|s| s.as_bytes().to_vec()).collect(),
                skip_verify: false,
                fingerprint: None,
                disable_sni: false,
                congestion: Congestion::Cubic,
                brutal_rate: None,
                obfs: None,
                hop: None,
                rendezvous: None,
                zero_rtt: spec.zero_rtt,
                keep_alive: None,
            },
            tls,
            Arc::new(transport),
        );
        Ok(Arc::new(Self {
            name,
            spec,
            resolver,
            target_resolver,
            quic,
            slots: Slots::default(),
            hub: std::sync::Mutex::new(None),
            negotiating: Mutex::new(()),
            rate,
        }))
    }
    async fn connection(&self) -> io::Result<quinn::Connection> {
        if self.quic.is_asleep() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "ShadowQUIC is sleeping",
            ));
        }
        let addresses = crate::resolve_target(self.resolver.as_ref(), &self.spec.server).await?;
        self.quic
            .connection(addresses[0].ip(), &self.spec.sni, addresses[0].port())
            .await
    }
    async fn negotiated(&self, conn: &quinn::Connection) -> io::Result<Arc<udp::Hub>> {
        let cached = || {
            self.hub
                .lock()
                .unwrap()
                .as_ref()
                .filter(|h| h.conn.stable_id() == conn.stable_id())
                .cloned()
        };
        if let Some(h) = cached() {
            return Ok(h);
        }
        let _single = self.negotiating.lock().await;
        if let Some(h) = cached() {
            return Ok(h);
        }
        if let Some(mut rx) = self.quic.handshake(conn) {
            while rx.borrow().is_none() {
                rx.changed()
                    .await
                    .map_err(|_| io::Error::other("ShadowQUIC handshake cancelled"))?;
            }
            // 0-RTT 被拒绝不等于 TLS 失败，重新打开的 1-RTT 流仍然可用。
            if let Some(reason) = conn.close_reason() {
                return Err(io::Error::other(reason));
            }
        }
        self.rate.store(0, Ordering::Relaxed);
        if self.spec.up_bps > 0 || self.spec.down_bps > 0 {
            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;
                let mut request = vec![255];
                request.extend_from_slice(&0x6d69686f6d6f0001u64.to_be_bytes());
                request.extend_from_slice(&[1, 0, 0, 8]);
                request.extend_from_slice(&self.spec.down_bps.to_be_bytes());
                send.write_all(&request).await.map_err(io::Error::other)?;
                let mut header = [0; 4];
                recv.read_exact(&mut header)
                    .await
                    .map_err(io::Error::other)?;
                let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
                if header[0] != 1 || !(8..=64).contains(&len) {
                    return Err(io::Error::other("invalid ShadowQUIC bandwidth response"));
                }
                let mut payload = [0; 64];
                recv.read_exact(&mut payload[..len])
                    .await
                    .map_err(io::Error::other)?;
                let _ = send.finish();
                let rx = u64::from_be_bytes(payload[..8].try_into().unwrap());
                Ok::<_, io::Error>((rx, header[1] & 1 != 0))
            })
            .await;
            if let Ok(Ok((rx, false))) = result {
                let rate = if rx == 0 {
                    self.spec.up_bps
                } else {
                    rx.min(self.spec.up_bps)
                };
                self.rate.store(rate, Ordering::Relaxed);
            }
        }
        let hub = udp::Hub::new(conn.clone());
        *self.hub.lock().unwrap() = Some(hub.clone());
        Ok(hub)
    }
}
#[async_trait]
impl Outbound for ShadowQuicOutbound {
    fn tag(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "shadowquic"
    }
    fn session_control(&self) -> Option<Arc<dyn SessionControl>> {
        Some(Arc::new(Control(self.quic.clone())))
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let slot = self.slots.acquire(self.spec.max_streams).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "ShadowQUIC active flow limit reached",
            )
        })?;
        crate::with_timeout(
            async {
                let conn = self.connection().await?;
                let mut request = vec![1];
                oryn_protocol::socks5::encode_addr(target, &mut request)?;
                let early = self
                    .quic
                    .handshake(&conn)
                    .is_some_and(|h| h.borrow().is_none());
                let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;
                let sent = send.write_all(&request).await;
                self.negotiated(&conn).await?;
                if sent.is_err()
                    || early
                        && self
                            .quic
                            .handshake(&conn)
                            .is_some_and(|h| *h.borrow() == Some(false))
                {
                    let pair = conn.open_bi().await.map_err(io::Error::other)?;
                    send = pair.0;
                    recv = pair.1;
                    send.write_all(&request).await.map_err(io::Error::other)?;
                }
                Ok(HeldStream::boxed(
                    Counted::boxed(Box::new(tokio::io::join(recv, send)), slot),
                    self.quic.clone(),
                ))
            },
            "ShadowQUIC connect",
        )
        .await
    }
    async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        let slot = self.slots.acquire(self.spec.max_streams).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "ShadowQUIC active flow limit reached",
            )
        })?;
        crate::with_timeout(
            async {
                let conn = self.connection().await?;
                let hub = self.negotiated(&conn).await?;
                udp::open(
                    hub,
                    self.spec.udp_over_stream,
                    self.spec.max_datagram,
                    self.target_resolver.clone(),
                    slot,
                    self.quic.clone(),
                )
                .await
            },
            "ShadowQUIC UDP associate",
        )
        .await
    }
}
