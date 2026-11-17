//! 从预算泄漏调查转换的回归；无外部网络流量。
use super::*;
use crate::{options::EngineOptions, stats::Stats};
use std::sync::Arc;

// lwIP 仅允许一个实例；两个 UDP 测试共享此锁。
pub(crate) static STACK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn queue(manager: &UdpManager, sizes: &[usize]) -> (mpsc::Sender<Vec<u8>>, SessionQueue) {
    let (tx, rx) = mpsc::channel(SESSION_QUEUE);
    let bytes = Rc::new(Cell::new(0));
    for &size in sizes {
        assert!(manager.reserve(size));
        tx.try_send(vec![0; size]).unwrap();
        bytes.set(bytes.get() + size);
    }
    (
        tx,
        SessionQueue {
            _task: manager.acquire_task().unwrap(),
            rx,
            bytes,
            total: manager.queued_bytes.clone(),
            ctx: Weak::new(),
            key: (
                "198.18.0.10:40000".parse().unwrap(),
                "203.0.113.10:9000".parse().unwrap(),
            ),
            generation: 1,
        },
    )
}

#[test]
fn udp_queue_dequeue_cancel_and_unpolled_drop() {
    let rt = runtime();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let manager = UdpManager::default();
        let (_tx, mut first) = queue(&manager, &[1200, 1200]);
        let (_tx2, second) = queue(&manager, &[2048]);
        assert_eq!(first.recv().await.unwrap().len(), 1200);
        assert_eq!(manager.queued_bytes.get(), 3248);
        drop(first);
        assert_eq!(
            manager.queued_bytes.get(),
            2048,
            "other queue budget survives"
        );
        drop(second);
        assert_eq!(manager.queued_bytes.get(), 0);

        let (_tx, mut waiting) = queue(&manager, &[]);
        assert!(
            tokio::time::timeout(Duration::from_millis(1), waiting.recv())
                .await
                .is_err()
        );
        assert_eq!(
            manager.queued_bytes.get(),
            0,
            "cancelled Pending recv does not debit"
        );
        drop(waiting);

        let (_tx, queued) = queue(&manager, &[3000]);
        let task = tokio::task::spawn_local(async move {
            let _queue = queued;
            std::future::pending::<()>().await;
        });
        task.abort(); // 从未 poll。
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(manager.queued_bytes.get(), 0);

        let (_tx, queued) = queue(&manager, &[4000]);
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::task::spawn_local(async move {
            let _queue = queued;
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        task.abort(); // 已开始但还有未消费包。
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(manager.queued_bytes.get(), 0);
        assert_eq!(
            manager.tasks.get(),
            0,
            "unpolled and running task cancellation refund permits"
        );
        let permits: Vec<_> = (0..MAX_SESSIONS)
            .map(|_| manager.acquire_task().unwrap())
            .collect();
        assert!(manager.acquire_task().is_none());
        manager.clear();
        assert!(
            manager.acquire_task().is_none(),
            "clearing the map cannot release task owners"
        );
        drop(permits);
        assert!(manager.acquire_task().is_some());
        assert_eq!(manager.tasks.get(), 0);
    });
}

#[test]
fn udp_blocked_quic_refunds_budget_and_preserves_generation() {
    let _stack_lock = STACK_LOCK.lock().unwrap();
    let rt = runtime();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let mut config =
            crate::proxy_providers::compile("rules: ['MATCH,REJECT']", None, None).unwrap();
        config.dns.public_ip_url = None;
        config.geoip.auto_update = false;
        config.geoip.asn_url = None;
        let options = EngineOptions {
            block_quic: "always".into(),
            ..Default::default()
        };
        let ctx = EngineCtx::new(
            oryn_netstack::LwipStack::new(1500).unwrap(),
            config,
            options,
            Arc::new(Stats::default()),
        );
        // 不依赖 MTU：单会话累计上限，拒绝后出队可恢复，且全局计费不变。
        let (tx, mut bounded) = queue(&ctx.udp, &[SESSION_QUEUE_BYTES - 1]);
        let key = bounded.key;
        ctx.udp.sessions.borrow_mut().insert(
            key,
            Session {
                close: watch::channel(false).0,
                tx,
                queued_bytes: bounded.bytes.clone(),
                generation: bounded.generation,
                last_active: Rc::new(Cell::new(Instant::now())),
            },
        );
        for size in [2, 1, 1] {
            handle_datagram(
                &ctx,
                UdpDatagram {
                    src: key.0,
                    dst: key.1,
                    payload: vec![0; size],
                },
            );
        }
        assert_eq!(bounded.bytes.get(), SESSION_QUEUE_BYTES);
        assert_eq!(ctx.udp.queued_bytes.get(), SESSION_QUEUE_BYTES);
        assert_eq!(bounded.recv().await.unwrap().len(), SESSION_QUEUE_BYTES - 1);
        handle_datagram(
            &ctx,
            UdpDatagram {
                src: key.0,
                dst: key.1,
                payload: vec![0; SESSION_QUEUE_BYTES - 1],
            },
        );
        assert_eq!(bounded.bytes.get(), SESSION_QUEUE_BYTES);
        ctx.udp.clear();
        drop(bounded);
        assert_eq!(ctx.udp.queued_bytes.get(), 0);

        let mut payload = vec![0u8; 1200];
        payload[..5].copy_from_slice(&[0xc0, 0, 0, 0, 1]);
        assert!(is_quic_initial(&payload));
        let mut probe = QuicProbe::new();
        assert!(probe
            .push(&ctx.state().config.sniffer, payload.clone())
            .is_some());
        // 旧实现57轮时接近4 MiB预算；现在每轮都应完全回收。
        for round in 0..100u16 {
            let src = SocketAddr::from(([198, 18, 0, 10], 40000 + round));
            let dst = SocketAddr::from(([203, 0, 113, 10], 443));
            for _ in 0..SESSION_QUEUE {
                handle_datagram(
                    &ctx,
                    UdpDatagram {
                        src,
                        dst,
                        payload: payload.clone(),
                    },
                );
            }
            for _ in 0..10 {
                tokio::task::yield_now().await;
                if ctx.udp.count() == 0 {
                    break;
                }
            }
            assert_eq!(ctx.udp.count(), 0);
            assert_eq!(ctx.udp.queued_bytes.get(), 0, "round {round}");
        }
        let before = ctx.stats.udp_total.load(Ordering::Relaxed);
        handle_datagram(
            &ctx,
            UdpDatagram {
                src: "198.18.0.10:55000".parse().unwrap(),
                dst: "203.0.113.20:9000".parse().unwrap(),
                payload: vec![0; 2048],
            },
        );
        tokio::task::yield_now().await;
        assert_eq!(ctx.stats.udp_total.load(Ordering::Relaxed) - before, 1);
        ctx.udp.clear();
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(ctx.udp.queued_bytes.get(), 0);
        println!("udp_budget rounds=100 queued_bytes=0 ordinary_new_sessions=1");

        // clear不能提前清零全局计费；旧任务退出不能删除同key的新generation。
        let (_old_tx, mut old) = queue(&ctx.udp, &[1200]);
        old.ctx = Rc::downgrade(&ctx);
        let key = old.key;
        ctx.udp.sessions.borrow_mut().insert(
            key,
            Session {
                close: watch::channel(false).0,
                tx: _old_tx,
                queued_bytes: old.bytes.clone(),
                generation: 1,
                last_active: Rc::new(Cell::new(Instant::now())),
            },
        );
        ctx.udp.clear();
        assert_eq!(ctx.udp.queued_bytes.get(), 1200);
        let (new_tx, mut new) = queue(&ctx.udp, &[2048]);
        new.ctx = Rc::downgrade(&ctx);
        new.generation = 2;
        ctx.udp.sessions.borrow_mut().insert(
            key,
            Session {
                close: watch::channel(false).0,
                tx: new_tx,
                queued_bytes: new.bytes.clone(),
                generation: 2,
                last_active: Rc::new(Cell::new(Instant::now())),
            },
        );
        drop(old);
        assert_eq!(ctx.udp.queued_bytes.get(), 2048);
        assert_eq!(ctx.udp.sessions.borrow()[&key].generation, 2);
        drop(new);
        assert_eq!(ctx.udp.count(), 0);
        assert_eq!(ctx.udp.queued_bytes.get(), 0);

        // 真正run_session的取消同时清理预算与会话表（未poll / 已进入REJECT等待）。
        for started in [false, true] {
            let (tx, mut pending) = queue(&ctx.udp, &[1200, 1200]);
            pending.ctx = Rc::downgrade(&ctx);
            let key = pending.key;
            let last_active = Rc::new(Cell::new(Instant::now()));
            ctx.udp.sessions.borrow_mut().insert(
                key,
                Session {
                    close: watch::channel(false).0,
                    tx,
                    queued_bytes: pending.bytes.clone(),
                    generation: pending.generation,
                    last_active: last_active.clone(),
                },
            );
            let task =
                tokio::task::spawn_local(run_session(ctx.clone(), key, pending, last_active));
            if started {
                tokio::task::yield_now().await;
            }
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(ctx.udp.count(), 0);
            assert_eq!(ctx.udp.queued_bytes.get(), 0);
        }
        let weak = Rc::downgrade(&ctx);
        drop(ctx);
        assert!(
            weak.upgrade().is_none(),
            "session cleanup must not retain EngineCtx"
        );
    });
}
