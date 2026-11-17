//! 规则集：启动时从内联内容、本地文件或缓存加载；`http` 类型在后台下载与定期更新。

use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::time::{Duration, SystemTime};

use log::{info, warn};
use oryn_config::{ProviderSource, ProviderSpec, RuntimeConfig};
use oryn_http::Options;
use oryn_router::{build_inline, parse_rule_set, RuleSetStore};
use tokio::sync::Semaphore;

use crate::context::{EngineCtx, RuntimeState};
use crate::download::get_via;

/// 未设置 `size-limit` 时的下载上限，防止异常文件耗尽内存。
const DEFAULT_MAX_BODY: usize = 32 * 1024 * 1024;
const MAX_PROVIDER_BODY: usize = DEFAULT_MAX_BODY;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// 从未成功下载时的重试间隔。
const RETRY: Duration = Duration::from_secs(60);
static DOWNLOAD_LIMIT: Semaphore = Semaphore::const_new(2);

fn cache_file(data_dir: Option<&Path>, spec: &ProviderSpec) -> Option<PathBuf> {
    let dir = data_dir?;
    match &spec.source {
        ProviderSource::Http { cache_path, .. } => Some(dir.join(cache_path)),
        ProviderSource::File { path } => Some(dir.join(path)),
        ProviderSource::Inline { .. } => None,
    }
}

fn parse_into(
    store: &RuleSetStore,
    i: usize,
    spec: &ProviderSpec,
    content: &str,
    updated: SystemTime,
) -> (usize, bool) {
    let (set, stats) = parse_rule_set(content, spec.behavior, spec.format, spec.domain_style);
    let uses_geoip = set.uses_geoip();
    if let Some(slot) = store.slot(i) {
        slot.set(set, updated);
    }
    (stats.loaded, uses_geoip)
}

/// 同步加载本地已有的内容。返回是否有规则集需要 GEOIP。
pub fn load_local(config: &RuntimeConfig, store: &RuleSetStore, data_dir: Option<&Path>) -> bool {
    let mut uses_geoip = false;
    for (i, spec) in config.providers.iter().enumerate() {
        match &spec.source {
            ProviderSource::Inline { payload } => {
                let (set, _) = build_inline(payload, spec.behavior);
                uses_geoip |= set.uses_geoip();
                if let Some(slot) = store.slot(i) {
                    slot.set(set, SystemTime::now());
                }
            }
            ProviderSource::File { .. } | ProviderSource::Http { .. } => {
                let Some(path) = cache_file(data_dir, spec) else {
                    continue;
                };
                match std::fs::read(&path) {
                    Ok(bytes) => {
                        let updated = std::fs::metadata(&path)
                            .and_then(|m| m.modified())
                            .unwrap_or_else(|_| SystemTime::now());
                        let (_, g) =
                            parse_into(store, i, spec, &String::from_utf8_lossy(&bytes), updated);
                        uses_geoip |= g;
                    }
                    Err(e) if matches!(spec.source, ProviderSource::File { .. }) => {
                        let msg = format!("cannot read {}: {e}", path.display());
                        warn!("rule provider `{}`: {msg}", spec.name);
                        if let Some(slot) = store.slot(i) {
                            slot.set_error(msg);
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }
    uses_geoip
}

/// 为每个 `http` 规则集启动下载 / 更新任务。
pub fn spawn_updates(ctx: &Rc<EngineCtx>, state: &Rc<RuntimeState>) {
    for (i, spec) in state.config.providers.iter().enumerate() {
        let ProviderSource::Http { interval_secs, .. } = &spec.source else {
            continue;
        };
        let loaded = state.rule_sets.slot(i).is_some_and(|s| s.get().is_some());
        let age = cache_file(ctx.data_dir(), spec)
            .and_then(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .unwrap_or(Duration::MAX);
        let interval = interval_secs.map(Duration::from_secs);
        let first = if !loaded {
            Some(Duration::ZERO)
        } else {
            interval.map(|iv| iv.saturating_sub(age))
        };
        let Some(first) = first else { continue };
        state.spawn(update_loop(
            ctx.clone(),
            Rc::downgrade(state),
            i,
            first,
            interval,
        ));
    }
}

async fn update_loop(
    ctx: Rc<EngineCtx>,
    state: Weak<RuntimeState>,
    i: usize,
    first: Duration,
    interval: Option<Duration>,
) {
    let mut wait = first;
    loop {
        tokio::time::sleep(wait).await;
        let Some(st) = state.upgrade() else { return };
        let ok = download(&ctx, &st, i).await.is_ok();
        let loaded = st.rule_sets.slot(i).is_some_and(|s| s.get().is_some());
        drop(st);
        wait = match (ok, loaded, interval) {
            (_, false, _) => RETRY,
            (_, true, Some(iv)) => iv,
            (_, true, None) => return,
        };
    }
}

/// 下载并替换一个规则集，成功时写入缓存。
pub async fn download(
    ctx: &Rc<EngineCtx>,
    state: &Rc<RuntimeState>,
    i: usize,
) -> Result<usize, String> {
    let spec = state.config.providers.get(i).ok_or("no such provider")?;
    let ProviderSource::Http {
        url,
        via,
        size_limit,
        ..
    } = &spec.source
    else {
        return Err("not an http provider".into());
    };
    let slot = state.rule_sets.slot(i).cloned().ok_or("no such provider")?;
    let opts = Options {
        timeout: DOWNLOAD_TIMEOUT,
        max_body: if *size_limit > 0 {
            (*size_limit).min(MAX_PROVIDER_BODY as u64) as usize
        } else {
            DEFAULT_MAX_BODY
        },
        ..Options::default()
    };
    let result = async {
        let _permit = DOWNLOAD_LIMIT
            .acquire()
            .await
            .map_err(|_| "rule provider download limiter closed".to_string())?;
        warn!("rule provider `{}` downloading", spec.name);
        let resp = get_via(
            &state.routing,
            state.config.direct_index(),
            *via,
            url,
            &opts,
        )
        .await
        .map_err(|e| e.to_string())?;
        if !resp.is_success() {
            return Err(format!("HTTP {}", resp.status));
        }
        let text = String::from_utf8_lossy(&resp.body);
        let (set, stats) = parse_rule_set(&text, spec.behavior, spec.format, spec.domain_style);
        if stats.loaded == 0 {
            return Err("no usable rules in the downloaded file".into());
        }
        if let Some(path) = cache_file(ctx.data_dir(), spec) {
            if let Err(e) = write_atomic(&path, &resp.body) {
                warn!("rule provider `{}`: cannot write cache: {e}", spec.name);
            }
        }
        let uses_geoip = set.uses_geoip();
        slot.set(set, SystemTime::now());
        Ok((stats.loaded, uses_geoip))
    }
    .await;
    match result {
        Ok((n, uses_geoip)) => {
            info!("rule provider `{}` updated: {n} rules", spec.name);
            crate::events::push(
                "resource",
                "Rule set updated",
                format!("{}: {n} rules", spec.name),
            );
            if uses_geoip {
                crate::geo::ensure(ctx, state);
            }
            Ok(n)
        }
        Err(e) => {
            warn!("rule provider `{}` update failed: {e}", spec.name);
            crate::events::push(
                "resource",
                "Rule set update failed",
                format!("{}: {e}", spec.name),
            );
            slot.set_error(e.clone());
            Err(e)
        }
    }
}

/// 先写临时文件再改名，避免读到写了一半的文件。
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}
