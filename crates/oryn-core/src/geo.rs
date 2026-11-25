//! MaxMind 数据库：GeoIP / ASN 独立状态，串行下载，校验后原子替换。

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{info, warn};
use oryn_config::{ProviderVia, RuntimeConfig};
use oryn_http::Options;
use oryn_router::{GeoIp, Mmdb};
use serde_json::{json, Value};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::context::{EngineCtx, RuntimeState};
use crate::download::{get_via, get_via_file};

// 响应串行且限制为 16 MiB，避免两份数据库同时挤占 Extension 内存。
const MAX_DB: usize = 16 * 1024 * 1024;
const RETRY: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Country = 0,
    Asn = 1,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Country => "geoip",
            Self::Asn => "asn",
        }
    }
    fn path(self, ctx: &EngineCtx) -> Option<PathBuf> {
        ctx.data_dir().map(|d| {
            d.join(match self {
                Self::Country => "geoip/country.mmdb",
                Self::Asn => "geoip/asn.mmdb",
            })
        })
    }
    fn url(self, state: &RuntimeState) -> Option<&str> {
        match self {
            Self::Country => Some(&state.config.geoip.url),
            Self::Asn => state.config.geoip.asn_url.as_deref(),
        }
    }
    fn db(self, ctx: &EngineCtx) -> &GeoIp {
        match self {
            Self::Country => &ctx.geoip,
            Self::Asn => &ctx.asn,
        }
    }
    fn status(self, ctx: &EngineCtx) -> &DatabaseStatus {
        &ctx.databases[self as usize]
    }
}

pub struct DatabaseStatus {
    updated: Cell<Option<SystemTime>>,
    source: RefCell<Option<String>>,
    error: RefCell<Option<String>>,
    updating: Cell<bool>,
    token: Cell<u64>,
    cancel: RefCell<tokio::sync::watch::Sender<bool>>,
    task: RefCell<Option<JoinHandle<()>>>,
    done: Notify,
}

impl Default for DatabaseStatus {
    fn default() -> Self {
        Self {
            updated: Cell::new(None),
            source: RefCell::new(None),
            error: RefCell::new(None),
            updating: Cell::new(false),
            token: Cell::new(0),
            cancel: RefCell::new(tokio::sync::watch::channel(false).0),
            task: RefCell::new(None),
            done: Notify::new(),
        }
    }
}

impl Drop for DatabaseStatus {
    fn drop(&mut self) {
        if let Some(task) = self.task.borrow_mut().take() {
            task.abort();
        }
    }
}

impl DatabaseStatus {
    /// 取消当前进行中的该类型数据库下载（仅在配置中的 URL 变化时触发）。
    pub fn cancel_in_flight(&self, temp_path: Option<PathBuf>) {
        self.token.set(self.token.get().wrapping_add(1));
        let (next, _) = tokio::sync::watch::channel(false);
        let prev = std::mem::replace(&mut *self.cancel.borrow_mut(), next);
        let _ = prev.send_replace(true);
        if let Some(task) = self.task.borrow_mut().take() {
            task.abort();
        }
        if let Some(path) = temp_path {
            let _ = std::fs::remove_file(path);
        }
        self.updating.set(false);
        self.done.notify_waiters();
    }
}

pub fn status_json(ctx: &EngineCtx, state: &RuntimeState, kind: Kind) -> Value {
    let status = kind.status(ctx);
    json!({
        "loaded": kind.db(ctx).is_loaded(),
        "updated_at": status.updated.get().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs_f64()),
        "url": kind.url(state),
        "cached_url": status.source.borrow().clone(),
        "error": status.error.borrow().clone(),
        "updating": status.updating.get(),
    })
}

pub fn rules_need_geoip(config: &RuntimeConfig) -> bool {
    config.rules.iter().any(|r| r.kind.needs_geo_db())
}

pub fn load_cached(ctx: &EngineCtx) {
    for kind in [Kind::Country, Kind::Asn] {
        let Some(path) = kind.path(ctx) else { continue };
        if !path.exists() {
            continue;
        }
        let result = Mmdb::open(&path).and_then(|db| {
            db.validate_kind(kind == Kind::Asn)?;
            Ok(db)
        });
        match result {
            Ok(db) => {
                kind.db(ctx).set(Some(Arc::new(db)));
                let status = kind.status(ctx);
                status
                    .updated
                    .set(std::fs::metadata(&path).and_then(|m| m.modified()).ok());
                *status.source.borrow_mut() = std::fs::read_to_string(path.with_extension("url"))
                    .ok()
                    .filter(|s| s.len() <= 4096);
            }
            Err(e) => {
                warn!("cannot open {} database: {e}", kind.name());
                *kind.status(ctx).error.borrow_mut() = Some(e);
            }
        }
    }
}

/// 一份配置最多启动两个更新循环；已有库与成功时间不随订阅切换而消失。
pub fn ensure(ctx: &Rc<EngineCtx>, state: &Rc<RuntimeState>) {
    if state.geo_started.replace(true) {
        return;
    }
    let spec = &state.config.geoip;
    let interval = Duration::from_secs(spec.interval_hours.saturating_mul(3600));
    for kind in [Kind::Country, Kind::Asn] {
        let Some(url) = kind.url(state) else { continue };
        let status = kind.status(ctx);
        let age = status
            .updated
            .get()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .unwrap_or(Duration::MAX);
        let changed = status.source.borrow().as_deref() != Some(url);
        let first = if !kind.db(ctx).is_loaded() || (spec.auto_update && changed) {
            Duration::ZERO
        } else if spec.auto_update {
            interval.saturating_sub(age)
        } else {
            continue;
        };
        state.spawn(update_loop(
            ctx.clone(),
            Rc::downgrade(state),
            kind,
            first,
            spec.auto_update.then_some(interval),
        ));
    }
}

async fn update_loop(
    ctx: Rc<EngineCtx>,
    state: Weak<RuntimeState>,
    kind: Kind,
    first: Duration,
    interval: Option<Duration>,
) {
    let mut wait = first;
    loop {
        tokio::time::sleep(wait).await;
        let Some(st) = state.upgrade() else { return };
        if !Rc::ptr_eq(&st, &ctx.state()) {
            return;
        }
        if let Some(iv) = interval {
            let status = kind.status(&ctx);
            let age = status
                .updated
                .get()
                .and_then(|t| SystemTime::now().duration_since(t).ok());
            if status.source.borrow().as_deref() == kind.url(&st) {
                if let Some(age) = age.filter(|age| *age < iv) {
                    wait = iv.saturating_sub(age);
                    continue;
                }
            }
        }
        let expected_url = kind.url(&st).map(str::to_string);
        drop(st);
        let ok = if kind.status(&ctx).updating.get() {
            // 已有同 URL 的在途下载（如跨越无关热重载保留下来），等待其完成后检查结果。
            kind.status(&ctx).done.notified().await;
            kind.db(&ctx).is_loaded()
                && kind.status(&ctx).source.borrow().as_deref() == expected_url.as_deref()
        } else {
            match start_download(&ctx, kind) {
                Some(rx) => rx.await.unwrap_or(false),
                None => {
                    kind.status(&ctx).done.notified().await;
                    kind.db(&ctx).is_loaded()
                }
            }
        };
        wait = match (ok, interval) {
            (false, _) => RETRY,
            (true, Some(iv)) => iv,
            (true, None) => return,
        };
    }
}

/// 在创建任务前去重，不让连续控制命令堆积下载任务。
pub fn request(ctx: &Rc<EngineCtx>, state: &Rc<RuntimeState>, kind: Kind) {
    if kind.status(ctx).updating.get() || kind.url(state).is_none() {
        return;
    }
    let _ = start_download(ctx, kind);
}

pub fn cancel_in_flight(ctx: &EngineCtx, kind: Kind) {
    kind.status(ctx)
        .cancel_in_flight(kind.path(ctx).map(|p| p.with_extension("tmp")));
}

fn start_download(
    ctx: &Rc<EngineCtx>,
    kind: Kind,
) -> Option<tokio::sync::oneshot::Receiver<bool>> {
    let guard = DownloadGuard::begin(ctx, kind)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let weak = Rc::downgrade(ctx);
    let handle = tokio::task::spawn_local(async move {
        let ok = download_guarded(weak, kind, guard).await.is_ok();
        let _ = tx.send(ok);
    });
    *kind.status(ctx).task.borrow_mut() = Some(handle);
    Some(rx)
}

struct DownloadGuard {
    ctx: Weak<EngineCtx>,
    kind: Kind,
    token: u64,
    temp: Option<PathBuf>,
}
impl DownloadGuard {
    fn begin(ctx: &Rc<EngineCtx>, kind: Kind) -> Option<Self> {
        let status = kind.status(ctx);
        if status.updating.replace(true) {
            return None;
        }
        let token = status.token.get().wrapping_add(1);
        status.token.set(token);
        *status.error.borrow_mut() = None;
        Some(Self {
            ctx: Rc::downgrade(ctx),
            kind,
            token,
            temp: kind.path(ctx).map(|p| p.with_extension("tmp")),
        })
    }
}
impl Drop for DownloadGuard {
    fn drop(&mut self) {
        let Some(ctx) = self.ctx.upgrade() else {
            return;
        };
        let status = self.kind.status(&ctx);
        if status.token.get() == self.token {
            if let Some(path) = &self.temp {
                let _ = std::fs::remove_file(path);
            }
            status.updating.set(false);
            status.done.notify_waiters();
        }
    }
}

async fn download_guarded(
    ctx_weak: Weak<EngineCtx>,
    kind: Kind,
    guard: DownloadGuard,
) -> Result<(), String> {
    let mut cancelled = {
        let ctx = ctx_weak.upgrade().ok_or("engine stopped")?;
        let rx = kind.status(&ctx).cancel.borrow().subscribe();
        rx
    };
    if *cancelled.borrow() {
        return Err("database configuration changed".into());
    }
    let mutex = ctx_weak
        .upgrade()
        .ok_or("engine stopped")?
        .database_download
        .clone();
    let _permit = tokio::select! {
        biased;
        _ = cancelled.changed() => return Err("database configuration changed".into()),
        permit = mutex.lock_owned() => permit,
    };
    let result = async {
        let (url, routing, direct) = {
            let ctx = ctx_weak.upgrade().ok_or("engine stopped")?;
            let current = ctx.state();
            (
                kind.url(&current)
                    .ok_or("database URL is not configured")?
                    .to_string(),
                current.routing.clone(),
                current.config.direct_index(),
            )
        };
        let opts = Options {
            timeout: Duration::from_secs(120),
            max_body: MAX_DB,
            ..Options::default()
        };
        // 有缓存目录时逐块写临时文件，不保留整份 HTTP 正文。无目录沿用内存后备。
        // 与规则集一样遵循分流规则，连不上时直连再试，每次尝试重置临时文件。
        if let Some(tmp) = guard.temp.as_ref() {
            if let Some(parent) = tmp.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
        }
        let download = async {
            match guard.temp.as_ref() {
                Some(tmp) => {
                    get_via_file(&routing, direct, ProviderVia::Rules, &url, &opts, tmp).await
                }
                None => get_via(&routing, direct, ProviderVia::Rules, &url, &opts).await,
            }
        };
        let resp = tokio::select! {
            biased;
            _ = cancelled.changed() => return Err("database configuration changed".into()),
            response = download => response.map_err(|e| e.to_string())?,
        };
        // 206 不是完整文件，不能替换缓存。
        if resp.status != 200 {
            return Err(format!("HTTP {}", resp.status));
        }
        let ctx = ctx_weak.upgrade().ok_or("engine stopped")?;
        if kind.url(&ctx.state()) != Some(url.as_str()) {
            return Err("database configuration changed".into());
        }
        match kind.path(&ctx) {
            Some(path) => {
                let tmp = guard.temp.as_ref().unwrap();
                debug_assert!(resp.body.is_empty());
                drop(resp);
                let db = Mmdb::open(tmp)?;
                db.validate_kind(kind == Kind::Asn)?;
                std::fs::rename(tmp, &path).map_err(|e| e.to_string())?;
                // 来源标记仅用于调度；写失败则删除，重启后重新校验/下载。
                let source = path.with_extension("url");
                if std::fs::write(&source, &url).is_err() {
                    let _ = std::fs::remove_file(source);
                }
                kind.db(&ctx).set(Some(Arc::new(db)));
            }
            None => {
                let db = Mmdb::from_bytes(resp.body)?;
                db.validate_kind(kind == Kind::Asn)?;
                kind.db(&ctx).set(Some(Arc::new(db)));
            }
        }
        let status = kind.status(&ctx);
        status.updated.set(Some(SystemTime::now()));
        *status.source.borrow_mut() = Some(url.to_string());
        *status.error.borrow_mut() = None;
        Ok(())
    }
    .await;
    if let Some(ctx) = ctx_weak.upgrade() {
        let status = kind.status(&ctx);
        if status.token.get() == guard.token {
            if let Err(e) = &result {
                warn!("{} database update failed: {e}", kind.name());
                *status.error.borrow_mut() = Some(e.clone());
                crate::events::push(
                    "resource",
                    "Database update failed",
                    format!("{}: {e}", kind.name()),
                );
            } else {
                info!("{} database updated", kind.name());
                crate::events::push("resource", "Database updated", kind.name());
            }
        }
    }
    result
}
