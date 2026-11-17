//! 可控 Pending I/O：业务取消不放行 I/O，不使用 task.abort。
use super::*;
use async_trait::async_trait;
use oryn_outbound::{BoxStream, Outbound, PacketConn};
use std::io;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Default)]
struct Control {
    binds: AtomicUsize,
    sends: AtomicUsize,
    drops: AtomicUsize,
    bind_gate: tokio::sync::Notify,
}
struct PendingOutbound(Arc<Control>);
struct PendingPacket(Arc<Control>);
impl Drop for PendingPacket {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::Relaxed);
    }
}
#[async_trait]
impl PacketConn for PendingPacket {
    async fn send_to(&self, _: &[u8], _: &TargetAddr) -> io::Result<()> {
        self.0.sends.fetch_add(1, Ordering::Relaxed);
        std::future::pending().await
    }
    async fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        std::future::pending().await
    }
}
#[async_trait]
impl Outbound for PendingOutbound {
    fn tag(&self) -> &str {
        "controlled"
    }
    fn kind(&self) -> &'static str {
        "test"
    }
    async fn connect_tcp(&self, _: &TargetAddr) -> io::Result<BoxStream> {
        unreachable!()
    }
    async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        self.0.binds.fetch_add(1, Ordering::Relaxed);
        self.0.bind_gate.notified().await;
        Ok(Box::new(PendingPacket(self.0.clone())))
    }
}
fn context(control: &Arc<Control>, sniff: bool) -> Rc<EngineCtx> {
    let yaml = if sniff {
        "rules: ['PROTOCOL,QUIC,DIRECT', 'MATCH,DIRECT']"
    } else {
        "rules: ['MATCH,DIRECT']"
    };
    let mut config = crate::proxy_providers::compile(yaml, None, None).unwrap();
    config.dns.public_ip_url = None;
    config.geoip.auto_update = false;
    config.geoip.asn_url = None;
    let ctx = EngineCtx::new(
        oryn_netstack::LwipStack::new(1500).unwrap(),
        config,
        Default::default(),
        Arc::new(crate::stats::Stats::default()),
    );
    {
        let mut state = ctx.state.borrow_mut();
        let state = Rc::get_mut(&mut state).unwrap();
        let router =
            oryn_router::Router::new(&state.config, state.rule_sets.clone(), ctx.geoip.clone());
        let outbounds = state
            .routing
            .outbounds
            .iter()
            .map(|_| Arc::new(PendingOutbound(control.clone())) as Arc<dyn Outbound>)
            .collect();
        state.routing = Arc::new(oryn_dns::Routing { router, outbounds });
    }
    ctx
}
fn enqueue(ctx: &Rc<EngineCtx>, slot: usize) -> Key {
    let key = (
        format!("198.18.0.10:{}", 10000 + slot).parse().unwrap(),
        "203.0.113.10:9000".parse().unwrap(),
    );
    for size in [1200, 2048] {
        handle_datagram(
            ctx,
            UdpDatagram {
                src: key.0,
                dst: key.1,
                payload: vec![0; size],
            },
        );
    }
    key
}
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}
fn refunded(ctx: &EngineCtx) {
    assert_eq!(ctx.conns.count(Network::Udp), 0);
    assert_eq!(ctx.udp.tasks.get(), 0);
    assert_eq!(ctx.udp.queued_bytes.get(), 0);
    assert_eq!(ctx.stats.upload.load(Ordering::Relaxed), 0);
}
#[test]
fn udp_pending_bind_send_cancellation() {
    let _lock = super::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        for stage in ["bind", "send", "pending_send"] {
            for stop in ["clear", "remove", "cancel", "idle"] {
                let control = Arc::new(Control::default());
                let ctx = context(&control, stage == "pending_send");
                if stage != "bind" {
                    control.bind_gate.notify_one();
                }
                let key = enqueue(&ctx, 0);
                if stop == "idle" {
                    ctx.udp.sessions.borrow()[&key]
                        .last_active
                        .set(Instant::now() - IDLE_TIMEOUT + Duration::from_millis(50));
                }
                settle().await;
                assert_eq!(control.binds.load(Ordering::Relaxed), 1);
                assert_eq!(
                    control.sends.load(Ordering::Relaxed),
                    usize::from(stage != "bind")
                );
                match stop {
                    "clear" => ctx.udp.clear(),
                    "remove" => {
                        let generation = ctx.udp.sessions.borrow()[&key].generation;
                        ctx.udp.remove_if(&key, generation);
                    }
                    "cancel" => {
                        assert_eq!(ctx.conns.close_through("controlled"), 1);
                    }
                    _ => tokio::time::sleep(Duration::from_millis(100)).await,
                }
                settle().await;
                refunded(&ctx);
                assert_eq!(
                    control.drops.load(Ordering::Relaxed),
                    usize::from(stage != "bind")
                );
                assert_eq!(ctx.udp.count(), 0);
            }
        }
    });
}
#[test]
fn udp_pending_idle_uses_latest_activity() {
    let _lock = super::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let control = Arc::new(Control::default());
        let ctx = context(&control, false);
        let key = enqueue(&ctx, 0);
        ctx.udp.sessions.borrow()[&key]
            .last_active
            .set(Instant::now() - IDLE_TIMEOUT + Duration::from_millis(50));
        settle().await;
        // 模拟实际入包刷新活跃时间；旧 deadline 到达不能取消仍活跃的 bind。
        enqueue(&ctx, 0);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(ctx.udp.tasks.get(), 1);
        assert_eq!(
            control.binds.load(Ordering::Relaxed),
            1,
            "no retry of pending bind"
        );
        ctx.udp.clear();
        settle().await;
        refunded(&ctx);
    });
}

#[test]
fn udp_pending_task_cap_clear_reopen() {
    let _lock = super::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        for bind_pending in [true, false] {
            let control = Arc::new(Control::default());
            let ctx = context(&control, false);
            for round in 0..2 {
                for slot in 0..MAX_SESSIONS {
                    if !bind_pending {
                        control.bind_gate.notify_one();
                    }
                    enqueue(&ctx, slot);
                    settle().await;
                }
                assert_eq!(ctx.udp.tasks.get(), MAX_SESSIONS);
                assert_eq!(
                    control.binds.load(Ordering::Relaxed),
                    (round + 1) * MAX_SESSIONS
                );
                enqueue(&ctx, MAX_SESSIONS);
                assert_eq!(ctx.udp.count(), MAX_SESSIONS);
                let before = ctx.udp.queued_bytes.get();
                enqueue(&ctx, 0);
                assert_eq!(ctx.udp.queued_bytes.get(), before + 3248);
                ctx.udp.clear();
                assert_eq!(
                    ctx.udp.tasks.get(),
                    MAX_SESSIONS,
                    "permits remain RAII-owned until task exit"
                );
                settle().await;
                refunded(&ctx);
                assert_eq!(
                    control.drops.load(Ordering::Relaxed),
                    if bind_pending {
                        0
                    } else {
                        (round + 1) * MAX_SESSIONS
                    }
                );
            }
        }
    });
}
