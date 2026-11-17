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

#[derive(Default)]
pub struct DatabaseStatus {
    updated: Cell<Option<SystemTime>>,
    source: RefCell<Option<String>>,
    error: RefCell<Option<String>>,
    updating: Cell<bool>,
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
        drop(st);
        let result = download(&ctx, state.clone(), kind).await;
        wait = match (result.is_ok(), interval) {
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
    let Some(guard) = DownloadGuard::begin(ctx, kind) else {
        return;
    };
    let (ctx, st) = (ctx.clone(), Rc::downgrade(state));
    state.spawn(async move {
        let _ = download_guarded(&ctx, st, kind, guard).await;
    });
}

struct DownloadGuard {
    ctx: Rc<EngineCtx>,
    kind: Kind,
    temp: Option<PathBuf>,
}
impl DownloadGuard {
    fn begin(ctx: &Rc<EngineCtx>, kind: Kind) -> Option<Self> {
        if kind.status(ctx).updating.replace(true) {
            return None;
        }
        *kind.status(ctx).error.borrow_mut() = None;
        Some(Self {
            ctx: ctx.clone(),
            kind,
            temp: kind.path(ctx).map(|p| p.with_extension("tmp")),
        })
    }
}
impl Drop for DownloadGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.temp {
            let _ = std::fs::remove_file(path);
        }
        self.kind.status(&self.ctx).updating.set(false);
    }
}

async fn download(
    ctx: &Rc<EngineCtx>,
    state: Weak<RuntimeState>,
    kind: Kind,
) -> Result<(), String> {
    let guard = DownloadGuard::begin(ctx, kind).ok_or("database update already in progress")?;
    download_guarded(ctx, state, kind, guard).await
}

async fn download_guarded(
    ctx: &Rc<EngineCtx>,
    state: Weak<RuntimeState>,
    kind: Kind,
    guard: DownloadGuard,
) -> Result<(), String> {
    // 已建立的 Flow 可能继续持有旧 RuntimeState，不能只依赖其 Drop 来取消下载。
    let mut cancelled = state
        .upgrade()
        .ok_or("database configuration changed")?
        .inspection_cancel
        .subscribe();
    if *cancelled.borrow() {
        return Err("database configuration changed".into());
    }
    let _permit = tokio::select! {
        biased;
        _ = cancelled.changed() => return Err("database configuration changed".into()),
        permit = ctx.database_download.lock() => permit,
    };
    let result = async {
        let (url, routing, direct) = {
            let current = state.upgrade().ok_or("database configuration changed")?;
            if !Rc::ptr_eq(&current, &ctx.state()) {
                return Err("database configuration changed".into());
            }
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
        if !state
            .upgrade()
            .is_some_and(|st| Rc::ptr_eq(&st, &ctx.state()))
        {
            return Err("database configuration changed".into());
        }
        match kind.path(ctx) {
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
                kind.db(ctx).set(Some(Arc::new(db)));
            }
            None => {
                let db = Mmdb::from_bytes(resp.body)?;
                db.validate_kind(kind == Kind::Asn)?;
                kind.db(ctx).set(Some(Arc::new(db)));
            }
        }
        let status = kind.status(ctx);
        status.updated.set(Some(SystemTime::now()));
        *status.source.borrow_mut() = Some(url.to_string());
        *status.error.borrow_mut() = None;
        Ok(())
    }
    .await;
    if let Err(e) = &result {
        warn!("{} database update failed: {e}", kind.name());
        *kind.status(ctx).error.borrow_mut() = Some(e.clone());
        crate::events::push(
            "resource",
            "Database update failed",
            format!("{}: {e}", kind.name()),
        );
    } else {
        info!("{} database updated", kind.name());
        crate::events::push("resource", "Database updated", kind.name());
    }
    result
}
