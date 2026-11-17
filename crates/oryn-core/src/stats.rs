//! 全局流量统计（跨线程可读）与活动连接登记（仅事件循环线程）。

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use oryn_router::{FlowContext, Network};
use serde::Serialize;

#[derive(Default)]
pub struct Stats {
    pub upload: AtomicU64,
    pub download: AtomicU64,
    pub tcp_total: AtomicU64,
    pub udp_total: AtomicU64,
    pub dns_queries: AtomicU64,
}

impl Stats {
    pub fn add_up(&self, n: u64) {
        self.upload.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_down(&self, n: u64) {
        self.download.fetch_add(n, Ordering::Relaxed);
    }
}

/// 已结束连接的保留条数（含失败的），超出时丢弃最早的。
pub const MAX_CONN_HISTORY: usize = 300;
/// 记录的失败原因最大长度。
const MAX_ERROR_LEN: usize = 160;

pub struct ConnInfo {
    pub id: u64,
    pub network: Network,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub domain: Option<String>,
    pub domain_source: &'static str,
    pub rule: String,
    /// 策略链路，最后一项为实际出站。
    pub chain: RefCell<Vec<String>>,
    pub started_at: SystemTime,
    pub upload: Cell<u64>,
    pub download: Cell<u64>,
    /// 应用层协议：`tls`、`http`、`quic`，未识别时为空。
    pub protocol: Cell<&'static str>,
    /// 出站建立连接的耗时（毫秒）。
    pub connect_ms: Cell<Option<u64>>,
    /// 失败或被拒绝的原因。
    pub error: RefCell<Option<String>>,
    /// 流量经过 MITM 解密（可被重写）。
    pub modified: Cell<bool>,
    /// 入口类型：`vif`（隧道）或 `local-proxy`（本地 HTTP / SOCKS 入站）。
    pub inbound: Cell<&'static str>,
    pub closed_at: Cell<Option<SystemTime>>,
    /// 置为 `true` 即要求持有者结束该连接（策略切换等）。
    pub cancel: tokio::sync::watch::Sender<bool>,
}

#[derive(Serialize)]
pub struct ConnView {
    pub id: u64,
    pub network: &'static str,
    pub source: String,
    pub destination: String,
    pub domain: Option<String>,
    pub domain_source: &'static str,
    pub rule: String,
    pub outbound: String,
    pub chain: Vec<String>,
    pub started_at: f64,
    pub upload: u64,
    pub download: u64,
    /// `active`、`closed`、`failed`。
    pub state: &'static str,
    pub protocol: &'static str,
    pub connect_ms: Option<u64>,
    pub error: Option<String>,
    pub modified: bool,
    pub inbound: &'static str,
    pub closed_at: Option<f64>,
    /// 出站的远端服务器 `host:port`，由 `connections` 命令按当前配置补全。
    pub server: Option<String>,
}

#[derive(Default)]
pub struct ConnRegistry {
    map: RefCell<BTreeMap<u64, Rc<ConnInfo>>>,
    /// 已结束的连接，旧的在前，容量有上限。
    history: RefCell<VecDeque<Rc<ConnInfo>>>,
}

/// 连接存活期间持有；Drop 时从登记表移除。
pub struct ConnGuard {
    info: Rc<ConnInfo>,
    registry: Weak<ConnRegistry>,
}

impl ConnGuard {
    pub fn set_actual_outbound(&self, name: Option<String>) {
        if let (Some(name), Some(last)) = (name, self.info.chain.borrow_mut().last_mut()) {
            *last = name;
        }
    }
    pub fn add_up(&self, n: u64) {
        self.info.upload.set(self.info.upload.get() + n);
    }

    pub fn add_down(&self, n: u64) {
        self.info.download.set(self.info.download.get() + n);
    }

    pub fn connect_ms(&self) -> Option<u64> {
        self.info.connect_ms.get()
    }

    pub fn up_bytes(&self) -> u64 {
        self.info.upload.get()
    }

    pub fn down_bytes(&self) -> u64 {
        self.info.download.get()
    }

    pub fn set_protocol(&self, protocol: &'static str) {
        self.info.protocol.set(protocol);
    }

    pub fn set_connect_ms(&self, elapsed: std::time::Duration) {
        self.info.connect_ms.set(Some(elapsed.as_millis() as u64));
    }

    pub fn set_inbound(&self, inbound: &'static str) {
        self.info.inbound.set(inbound);
    }

    pub fn set_modified(&self) {
        self.info.modified.set(true);
    }

    /// 连接被要求结束时完成；中继、连接与 UDP 循环据此提前退出。
    pub fn cancelled(&self) -> impl std::future::Future<Output = ()> {
        let mut rx = self.info.cancel.subscribe();
        async move {
            let _ = rx.wait_for(|cancelled| *cancelled).await;
        }
    }

    /// 记录失败原因；只保留第一次。
    pub fn set_error(&self, error: impl ToString) {
        let mut slot = self.info.error.borrow_mut();
        if slot.is_none() {
            let mut text = error.to_string();
            if text.len() > MAX_ERROR_LEN {
                let mut end = MAX_ERROR_LEN;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
            }
            *slot = Some(text);
        }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(r) = self.registry.upgrade() {
            r.map.borrow_mut().remove(&self.info.id);
            self.info.closed_at.set(Some(SystemTime::now()));
            let mut history = r.history.borrow_mut();
            history.push_back(self.info.clone());
            while history.len() > MAX_CONN_HISTORY {
                history.pop_front();
            }
        }
    }
}

impl ConnRegistry {
    pub fn register(
        self: &Rc<Self>,
        ctx: &FlowContext,
        chain: Vec<String>,
        rule: String,
    ) -> ConnGuard {
        let info = Rc::new(ConnInfo {
            id: ctx.id,
            network: ctx.network,
            source: ctx.source,
            destination: ctx.destination,
            domain: ctx.domain.clone(),
            domain_source: ctx.domain_source.as_str(),
            rule,
            chain: RefCell::new(chain),
            started_at: ctx.started_at,
            upload: Cell::new(0),
            download: Cell::new(0),
            protocol: Cell::new(""),
            connect_ms: Cell::new(None),
            error: RefCell::new(None),
            modified: Cell::new(false),
            inbound: Cell::new("vif"),
            closed_at: Cell::new(None),
            cancel: tokio::sync::watch::channel(false).0,
        });
        self.map.borrow_mut().insert(ctx.id, info.clone());
        ConnGuard {
            info,
            registry: Rc::downgrade(self),
        }
    }

    pub fn count(&self, network: Network) -> usize {
        self.map
            .borrow()
            .values()
            .filter(|c| c.network == network)
            .count()
    }

    /// 要求结束一个活动连接，返回是否找到。
    pub fn close_one(&self, id: u64) -> bool {
        self.map.borrow().get(&id).is_some_and(|c| !c.cancel.send_replace(true))
    }

    /// 要求结束全部活动连接，返回数量。
    pub fn close_all(&self) -> usize {
        let map = self.map.borrow();
        map.values().filter(|c| !c.cancel.send_replace(true)).count()
    }

    /// 要求结束链路经过 `policy`（策略组或节点）的全部活动连接，返回数量。
    pub fn close_through(&self, policy: &str) -> usize {
        let map = self.map.borrow();
        map.values()
            .filter(|c| c.chain.borrow().iter().any(|name| name == policy))
            .filter(|c| !c.cancel.send_replace(true))
            .count()
    }

    /// 登记后立即以失败状态结束的连接（被阻止或拒绝），只进入历史。
    pub fn record_failed(
        self: &Rc<Self>,
        ctx: &FlowContext,
        chain: Vec<String>,
        rule: String,
        protocol: &'static str,
        error: &str,
    ) {
        let guard = self.register(ctx, chain, rule);
        guard.set_protocol(protocol);
        guard.set_error(error);
    }

    pub fn clear_history(&self) {
        self.history.borrow_mut().clear();
    }

    /// 活动连接在前，`with_history` 时再接已结束的连接，各自新的在前，最多 `limit` 个。
    pub fn snapshot(&self, limit: usize, with_history: bool) -> Vec<ConnView> {
        let map = self.map.borrow();
        let history = self.history.borrow();
        let finished = if with_history { history.len() } else { 0 };
        map.values()
            .rev()
            .chain(history.iter().rev().take(finished))
            .take(limit)
            .map(|c| view(c))
            .collect()
    }
}

fn unix(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn view(c: &ConnInfo) -> ConnView {
    let error = c.error.borrow().clone();
    ConnView {
        id: c.id,
        network: c.network.as_str(),
        source: c.source.to_string(),
        destination: c.destination.to_string(),
        domain: c.domain.clone(),
        domain_source: c.domain_source,
        rule: c.rule.clone(),
        outbound: c.chain.borrow().last().cloned().unwrap_or_default(),
        chain: c.chain.borrow().clone(),
        started_at: unix(c.started_at),
        upload: c.upload.get(),
        download: c.download.get(),
        state: match (c.closed_at.get(), error.is_some()) {
            (None, _) => "active",
            (Some(_), true) => "failed",
            (Some(_), false) => "closed",
        },
        protocol: c.protocol.get(),
        connect_ms: c.connect_ms.get(),
        error,
        modified: c.modified.get(),
        inbound: c.inbound.get(),
        closed_at: c.closed_at.get().map(unix),
        server: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(id: u64) -> FlowContext {
        FlowContext::new(
            id,
            Network::Tcp,
            "10.0.0.1:1000".parse().unwrap(),
            "1.1.1.1:443".parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn close_through_cancels_only_connections_via_the_policy() {
        let registry = Rc::new(ConnRegistry::default());
        let chain = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        let via = registry.register(&flow(1), chain(&["Proxy", "A"]), "MATCH".into());
        let other = registry.register(&flow(2), chain(&["Other", "B"]), "MATCH".into());
        let (via_cancelled, other_cancelled) = (via.cancelled(), other.cancelled());
        tokio::pin!(via_cancelled, other_cancelled);

        assert_eq!(registry.close_through("Proxy"), 1);
        // 重复调用不重复计数
        assert_eq!(registry.close_through("Proxy"), 0);
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut via_cancelled)
            .await
            .expect("connection through the group is cancelled");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut other_cancelled)
                .await
                .is_err()
        );
        // 取消之后才创建的 future 也立即完成
        tokio::time::timeout(std::time::Duration::from_secs(1), via.cancelled())
            .await
            .unwrap();
    }

    #[test]
    fn finished_connections_move_to_bounded_history() {
        let registry = Rc::new(ConnRegistry::default());
        let active = registry.register(&flow(1), vec!["DIRECT".into()], "MATCH".into());
        let failed = registry.register(&flow(2), vec!["SJC".into()], "MATCH".into());
        failed.set_error("connection refused");
        drop(failed);
        let closed = registry.register(&flow(3), vec!["SJC".into()], "MATCH".into());
        closed.set_protocol("tls");
        closed.set_connect_ms(std::time::Duration::from_millis(42));
        drop(closed);

        let active_only = registry.snapshot(10, false);
        assert_eq!(active_only.len(), 1);
        assert_eq!(active_only[0].state, "active");

        let all = registry.snapshot(10, true);
        let states: Vec<_> = all.iter().map(|c| (c.id, c.state)).collect();
        assert_eq!(states, [(1, "active"), (3, "closed"), (2, "failed")]);
        assert_eq!(all[1].protocol, "tls");
        assert_eq!(all[1].connect_ms, Some(42));
        assert_eq!(all[2].error.as_deref(), Some("connection refused"));
        assert_eq!(registry.snapshot(2, true).len(), 2);
        drop(active);

        for id in 10..10 + MAX_CONN_HISTORY as u64 + 20 {
            drop(registry.register(&flow(id), vec!["DIRECT".into()], "MATCH".into()));
        }
        assert_eq!(registry.snapshot(10_000, true).len(), MAX_CONN_HISTORY);
        registry.clear_history();
        assert!(registry.snapshot(10, true).is_empty());
    }

    #[test]
    fn blocked_flows_are_recorded_as_failed() {
        let registry = Rc::new(ConnRegistry::default());
        registry.record_failed(
            &flow(7),
            vec!["REJECT".into()],
            "BLOCK-QUIC".into(),
            "quic",
            "QUIC is blocked",
        );
        let all = registry.snapshot(10, true);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].state, "failed");
        assert_eq!(all[0].protocol, "quic");
        assert!(registry.snapshot(10, false).is_empty());
    }
}
