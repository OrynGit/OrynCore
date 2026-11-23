//! 实际健康检查入口的有界生产、跨组进展及取消回归；不访问网络。
use super::*;
use oryn_outbound::{BoxStream, GroupOutbound, PacketConn};
use std::cell::Cell;
use std::io;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

thread_local! {
    static PEAK: Cell<usize> = const { Cell::new(0) };
    static WINDOW: Cell<usize> = const { Cell::new(PROBE_TASK_LIMIT) };
}
pub(super) fn window() -> usize {
    WINDOW.with(Cell::get)
}
pub(super) fn observe(len: usize) {
    PEAK.with(|p| p.set(p.get().max(len)));
}

struct Control {
    started: AtomicUsize,
    gate: Semaphore,
}
struct Controlled {
    name: String,
    control: Arc<Control>,
    outcome: u8,
}
impl Controlled {
    async fn enter(&self) -> io::Result<()> {
        self.control.started.fetch_add(1, Ordering::SeqCst);
        self.control.gate.acquire().await.unwrap().forget();
        match self.outcome {
            1 => Err(io::Error::other("controlled failure")),
            2 => std::future::pending().await,
            _ => Ok(()),
        }
    }
}
struct Packet(Mutex<Vec<u8>>);
#[async_trait::async_trait]
impl PacketConn for Packet {
    async fn send_to(&self, data: &[u8], _: &TargetAddr) -> io::Result<()> {
        *self.0.lock().unwrap() = data.to_vec();
        Ok(())
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let data = self.0.lock().unwrap();
        buf[..data.len()].copy_from_slice(&data);
        Ok((data.len(), TargetAddr::from_host("127.0.0.1", 53)))
    }
}
#[async_trait::async_trait]
impl Outbound for Controlled {
    fn tag(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "controlled"
    }
    async fn connect_tcp(&self, _: &TargetAddr) -> io::Result<BoxStream> {
        self.enter().await?;
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            for _ in 0..2 {
                let mut header = Vec::new();
                loop {
                    let Ok(b) = server.read_u8().await else {
                        return;
                    };
                    header.push(b);
                    if header.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                if server
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        Ok(Box::new(client))
    }
    async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        self.enter().await?;
        Ok(Box::new(Packet(Mutex::new(Vec::new()))))
    }
}
fn group(
    state: &RuntimeState,
    control: &Arc<Control>,
    prefix: &str,
    count: usize,
    mixed: bool,
) -> Arc<dyn Outbound> {
    let members = (0..count)
        .map(|i| {
            Arc::new(Controlled {
                name: format!("{prefix}-{i}"),
                control: control.clone(),
                outcome: if mixed { (i % 3) as u8 } else { 0 },
            }) as Arc<dyn Outbound>
        })
        .collect();
    Arc::new(GroupOutbound::new(
        prefix.into(),
        oryn_config::GroupKind::UrlTest { tolerance_ms: 0 },
        members,
        oryn_config::HealthSpec {
            url: "http://probe.invalid/".into(),
            timeout_ms: 100,
            ..Default::default()
        },
        false,
        state.health.clone(),
        None,
    ))
}
async fn run(state: Rc<RuntimeState>, group: Arc<dyn Outbound>, udp: bool) {
    if udp {
        test_group_udp(&state, &group, "example.invalid@127.0.0.1", None, None).await
    } else {
        test_group(&state, &group).await
    }
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("condition did not become true");
}
fn control() -> Arc<Control> {
    Arc::new(Control {
        started: AtomicUsize::new(0),
        gate: Semaphore::new(0),
    })
}

#[tokio::test(flavor = "current_thread")]
async fn bounded_health_scheduling() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = oryn_config::parse_config("rules: ['MATCH,REJECT']").unwrap();
            let ctx = crate::context::EngineCtx::new(
                oryn_netstack::LwipStack::new(1500).unwrap(),
                config,
                Default::default(),
                Arc::new(crate::stats::Stats::default()),
            );
            let state = ctx.state();
            for udp in [false, true] {
                // 仅测试扩大生产窗口，重现旧版全部 spawn 后才等待的结构。
                for (window, expected) in [(usize::MAX, 1000), (PROBE_TASK_LIMIT, 6)] {
                    WINDOW.with(|w| w.set(window));
                    PEAK.with(|p| p.set(0));
                    let a = control();
                    let parent = tokio::task::spawn_local(run(
                        state.clone(),
                        group(&state, &a, "large", 1000, false),
                        udp,
                    ));
                    until(|| a.started.load(Ordering::SeqCst) == 6).await;
                    let peak = PEAK.with(Cell::get);
                    eprintln!(
                        "udp={udp} window={window} members=1000 unreaped_task_peak={peak} active=6"
                    );
                    parent.abort();
                    let _ = parent.await;
                    until(|| PROBE_LIMIT.available_permits() == 6).await;
                    assert_eq!(peak, expected);
                }

                // 取消持有名额及尚未启动的 A 子任务后，B 可立即复用预算。
                let a = control();
                let b = control();
                let parent = tokio::task::spawn_local(run(
                    state.clone(),
                    group(&state, &a, "cancel", 1000, false),
                    udp,
                ));
                until(|| a.started.load(Ordering::SeqCst) == 6).await;
                let other = tokio::task::spawn_local(run(
                    state.clone(),
                    group(&state, &b, "other", 3, true),
                    !udp,
                ));
                parent.abort();
                let _ = parent.await;
                until(|| b.started.load(Ordering::SeqCst) == 3).await;
                b.gate.add_permits(3);
                let get = |name: &str| {
                    if !udp {
                        state.health.get_udp(name)
                    } else {
                        state.health.get(name)
                    }
                };
                until(|| get("other-0").is_some() && get("other-1").is_some()).await;
                assert!(
                    get("other-2").is_none(),
                    "completed results must not wait for timeout member"
                );
                other.await.unwrap();
                assert!(get("other-0").unwrap().alive());
                assert!(!get("other-1").unwrap().alive());
                assert!(!get("other-2").unwrap().alive());
                until(|| PROBE_LIMIT.available_permits() == 6).await;

                // 等待全局名额超过 timeout，拿到名额后仍能成功。
                let held = PROBE_LIMIT.acquire_many(6).await.unwrap();
                let waiting = control();
                let name = if udp { "queued-udp" } else { "queued-tcp" };
                let queued = tokio::task::spawn_local(run(
                    state.clone(),
                    group(&state, &waiting, name, 1, false),
                    udp,
                ));
                tokio::time::sleep(Duration::from_millis(150)).await;
                assert!(!queued.is_finished());
                assert_eq!(waiting.started.load(Ordering::SeqCst), 0);
                waiting.gate.add_permits(1);
                drop(held);
                queued.await.unwrap();
                let tag = format!("{name}-0");
                let result = if udp {
                    state.health.get_udp(&tag)
                } else {
                    state.health.get(&tag)
                };
                assert!(result.unwrap().alive());

                // 非严格轮询：小组无需等待大组全部结束，两个传输共用同一预算。
                let a = control();
                let b = control();
                let parent = tokio::task::spawn_local(run(
                    state.clone(),
                    group(&state, &a, "fair", 1000, false),
                    udp,
                ));
                until(|| a.started.load(Ordering::SeqCst) == 6).await;
                let other = tokio::task::spawn_local(run(
                    state.clone(),
                    group(&state, &b, "small", 1, false),
                    !udp,
                ));
                tokio::task::yield_now().await;
                assert_eq!(b.started.load(Ordering::SeqCst), 0);
                a.gate.add_permits(6);
                until(|| b.started.load(Ordering::SeqCst) == 1).await;
                assert!(a.started.load(Ordering::SeqCst) < 1000);
                b.gate.add_permits(1);
                other.await.unwrap();
                assert!(!parent.is_finished());
                parent.abort();
                let _ = parent.await;
                until(|| PROBE_LIMIT.available_permits() == 6).await;
            }
        })
        .await;
}
