//! 规则集：启动时从内联内容、本地文件或缓存加载；`http` 类型在后台下载与定期更新。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use log::{info, warn};
use oryn_config::{ProviderFormat, ProviderSource, ProviderSpec, RuntimeConfig};
use oryn_http::Options;
use oryn_router::{build_inline, parse_rule_set, RuleSet, RuleSetSlot, RuleSetStore};
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

struct SlotUpdateGuard(Arc<RuleSetSlot>);

impl SlotUpdateGuard {
    fn try_begin(slot: &Arc<RuleSetSlot>) -> Option<Self> {
        slot.try_begin_update().then(|| Self(slot.clone()))
    }
}

impl Drop for SlotUpdateGuard {
    fn drop(&mut self) {
        self.0.finish_update();
    }
}

pub(crate) struct StoreBuild {
    pub store: Arc<RuleSetStore>,
    pub uses_geoip: bool,
    pub dns_rulesets_changed: bool,
    pub url_changed_indices: Vec<usize>,
}

fn cache_file(data_dir: Option<&Path>, spec: &ProviderSpec) -> Option<PathBuf> {
    let dir = data_dir?;
    match &spec.source {
        ProviderSource::Http { cache_path, .. } => Some(dir.join(cache_path)),
        ProviderSource::File { path } => Some(dir.join(path)),
        ProviderSource::Inline { .. } => None,
    }
}

fn parse_into_slot(slot: &RuleSetSlot, spec: &ProviderSpec, content: &str, updated: SystemTime) -> (usize, bool) {
    let (set, stats) = parse_rule_set(content, spec.behavior, spec.format, spec.domain_style);
    let uses_geoip = set.uses_geoip();
    slot.set(set, updated);
    (stats.loaded, uses_geoip)
}

fn load_slot_local(slot: &RuleSetSlot, spec: &ProviderSpec, data_dir: Option<&Path>, load_disk: bool) -> bool {
    match &spec.source {
        ProviderSource::Inline { payload } => {
            let (set, _) = build_inline(payload, spec.behavior);
            let uses_geoip = set.uses_geoip();
            slot.set(set, SystemTime::now());
            uses_geoip
        }
        ProviderSource::File { .. } | ProviderSource::Http { .. } => {
            if !load_disk {
                return false;
            }
            let Some(path) = cache_file(data_dir, spec) else {
                return false;
            };
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let updated = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .unwrap_or_else(|_| SystemTime::now());
                    parse_into_slot(slot, spec, &String::from_utf8_lossy(&bytes), updated).1
                }
                Err(e) if matches!(spec.source, ProviderSource::File { .. }) => {
                    let msg = format!("cannot read {}: {e}", path.display());
                    warn!("rule provider `{}`: {msg}", spec.name);
                    slot.set_error(msg);
                    false
                }
                Err(_) => false,
            }
        }
    }
}

fn provider_reusable(old: &ProviderSpec, new: &ProviderSpec) -> bool {
    old.name == new.name
        && old.behavior == new.behavior
        && old.format == new.format
        && old.domain_style == new.domain_style
        && old.source == new.source
}

fn http_url_changed(old: &ProviderSpec, new: &ProviderSpec) -> bool {
    matches!(
        (&old.source, &new.source),
        (
            ProviderSource::Http { url: a, .. },
            ProviderSource::Http { url: b, .. }
        ) if a != b
    )
}

fn http_cache_path(spec: &ProviderSpec) -> Option<&str> {
    match &spec.source {
        ProviderSource::Http { cache_path, .. } => Some(cache_path.as_str()),
        _ => None,
    }
}

/// 增量构建规则集存储：复用未变更槽位，识别 HTTP URL 变更，并计算是否影响了 DNS 规则。
pub(crate) fn build_store(
    config: &RuntimeConfig,
    previous: Option<(&RuntimeConfig, &RuleSetStore)>,
    data_dir: Option<&Path>,
) -> StoreBuild {
    let old_by_name: HashMap<&str, usize> = previous
        .map(|(old_cfg, _)| {
            old_cfg
                .providers
                .iter()
                .enumerate()
                .map(|(idx, p)| (p.name.as_str(), idx))
                .collect()
        })
        .unwrap_or_default();

    let mut slots = Vec::with_capacity(config.providers.len());
    let mut uses_geoip = false;
    let mut dns_rulesets_changed = false;
    let mut url_changed_indices = Vec::new();

    for (i, spec) in config.providers.iter().enumerate() {
        let matched = previous.and_then(|(old_cfg, old_store)| {
            let oi = *old_by_name.get(spec.name.as_str())?;
            Some((&old_cfg.providers[oi], old_store.slot(oi)?.clone()))
        });

        match matched {
            Some((old_spec, old_slot)) if provider_reusable(old_spec, spec) => {
                uses_geoip |= old_slot.get().is_some_and(|s| s.uses_geoip());
                slots.push(old_slot);
            }
            Some((old_spec, _)) => {
                let url_changed = http_url_changed(old_spec, spec);
                if url_changed {
                    url_changed_indices.push(i);
                }
                let load_disk = !url_changed || http_cache_path(old_spec) != http_cache_path(spec);
                let slot = RuleSetStore::new_slot(spec);
                uses_geoip |= load_slot_local(&slot, spec, data_dir, load_disk);
                if config.dns_uses_provider(i) {
                    dns_rulesets_changed = true;
                }
                slots.push(slot);
            }
            None => {
                let slot = RuleSetStore::new_slot(spec);
                uses_geoip |= load_slot_local(&slot, spec, data_dir, true);
                if previous.is_some() && config.dns_uses_provider(i) {
                    dns_rulesets_changed = true;
                }
                slots.push(slot);
            }
        }
    }

    StoreBuild {
        store: Arc::new(RuleSetStore::from_slots(slots)),
        uses_geoip,
        dns_rulesets_changed,
        url_changed_indices,
    }
}

/// 同步加载本地已有的内容。返回是否有规则集需要 GEOIP。
#[allow(dead_code)]
pub fn load_local(config: &RuntimeConfig, store: &RuleSetStore, data_dir: Option<&Path>) -> bool {
    let mut uses_geoip = false;
    for (i, spec) in config.providers.iter().enumerate() {
        if let Some(slot) = store.slot(i) {
            uses_geoip |= load_slot_local(slot, spec, data_dir, true);
        }
    }
    uses_geoip
}

/// 为每个 `http` 规则集启动下载 / 更新任务；`force_indices` 中的规则集立即触发一次更新。
pub fn spawn_updates_with_changed(
    ctx: &Rc<EngineCtx>,
    state: &Rc<RuntimeState>,
    force_indices: &[usize],
) {
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
        let first = if !loaded || force_indices.contains(&i) {
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

#[allow(dead_code)]
pub fn spawn_updates(ctx: &Rc<EngineCtx>, state: &Rc<RuntimeState>) {
    spawn_updates_with_changed(ctx, state, &[]);
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

fn commit_slot_update(
    ctx: &EngineCtx,
    slot: &Arc<RuleSetSlot>,
    set: RuleSet,
    count: usize,
    name: &str,
) {
    let uses_geoip = set.uses_geoip();
    slot.set(set, SystemTime::now());
    ctx.resource_revision
        .set(ctx.resource_revision.get().wrapping_add(1));
    let current = ctx.state();
    if let Some(cur_i) = current
        .rule_sets
        .slots()
        .iter()
        .position(|s| Arc::ptr_eq(s, slot))
    {
        if current.config.dns_uses_provider(cur_i) {
            ctx.dns.clear_cache();
        }
    }
    info!("rule provider `{name}` updated: {count} rules");
    crate::events::push("resource", "Rule set updated", format!("{name}: {count} rules"));
    if uses_geoip {
        // 调用方按需触发 geo::ensure
        let _ = uses_geoip;
    }
}

/// 立即重新读取本地 `file` 规则集并原子替换槽位内容。
pub fn reload_file(
    ctx: &Rc<EngineCtx>,
    state: &Rc<RuntimeState>,
    i: usize,
) -> Result<usize, String> {
    let spec = state.config.providers.get(i).ok_or("no such provider")?;
    if !matches!(spec.source, ProviderSource::File { .. }) {
        return Err("not a file provider".into());
    }
    let path = cache_file(ctx.data_dir(), spec).ok_or("no data directory for file rule provider")?;
    let slot = state.rule_sets.slot(i).cloned().ok_or("no such provider")?;
    let _updating = SlotUpdateGuard::try_begin(&slot)
        .ok_or_else(|| "rule provider update already in progress".to_string())?;
    let bytes = std::fs::read(&path).map_err(|e| {
        let msg = format!("cannot read {}: {e}", path.display());
        slot.set_error(msg.clone());
        msg
    })?;
    let text = String::from_utf8_lossy(&bytes);
    let (set, stats) = parse_rule_set(&text, spec.behavior, spec.format, spec.domain_style);
    if stats.loaded == 0 {
        let msg = "no usable rules in the file".to_string();
        slot.set_error(msg.clone());
        return Err(msg);
    }
    let uses_geoip = set.uses_geoip();
    commit_slot_update(ctx, &slot, set, stats.loaded, &spec.name);
    if uses_geoip {
        crate::geo::ensure(ctx, state);
    }
    Ok(stats.loaded)
}

/// 直接推送规则集全文内容以热更新对应槽位（无需重启或重载整份配置）。
pub fn apply_content(
    ctx: &Rc<EngineCtx>,
    state: &Rc<RuntimeState>,
    i: usize,
    content: &str,
    persist: bool,
) -> Result<usize, String> {
    let spec = state.config.providers.get(i).ok_or("no such provider")?;
    let slot = state.rule_sets.slot(i).cloned().ok_or("no such provider")?;
    let _updating = SlotUpdateGuard::try_begin(&slot)
        .ok_or_else(|| "rule provider update already in progress".to_string())?;
    let (set, stats) = parse_rule_set(content, spec.behavior, spec.format, spec.domain_style);
    if stats.loaded == 0 {
        return Err("no usable rules in pushed content".into());
    }
    if persist {
        if let Some(path) = cache_file(ctx.data_dir(), spec) {
            write_atomic(&path, content.as_bytes())
                .map_err(|e| format!("cannot persist rule provider `{}`: {e}", spec.name))?;
        }
    }
    let uses_geoip = set.uses_geoip();
    commit_slot_update(ctx, &slot, set, stats.loaded, &spec.name);
    if uses_geoip {
        crate::geo::ensure(ctx, state);
    }
    Ok(stats.loaded)
}

/// 直接推送条目列表热更新规则集槽位。
pub fn apply_payload(
    ctx: &Rc<EngineCtx>,
    state: &Rc<RuntimeState>,
    i: usize,
    payload: &[String],
    persist: bool,
) -> Result<usize, String> {
    let spec = state.config.providers.get(i).ok_or("no such provider")?;
    let slot = state.rule_sets.slot(i).cloned().ok_or("no such provider")?;
    let _updating = SlotUpdateGuard::try_begin(&slot)
        .ok_or_else(|| "rule provider update already in progress".to_string())?;
    let (set, stats) = build_inline(payload, spec.behavior);
    if stats.loaded == 0 {
        return Err("no usable rules in pushed payload".into());
    }
    if persist {
        if let Some(path) = cache_file(ctx.data_dir(), spec) {
            let serialized = match spec.format {
                ProviderFormat::Text => {
                    let mut out = payload.join("\n");
                    if !out.is_empty() {
                        out.push('\n');
                    }
                    out
                }
                ProviderFormat::Yaml => {
                    let mut out = String::from("payload:\n");
                    for item in payload {
                        out.push_str(&format!("  - '{}'\n", item.replace('\'', "''")));
                    }
                    out
                }
            };
            write_atomic(&path, serialized.as_bytes())
                .map_err(|e| format!("cannot persist rule provider `{}`: {e}", spec.name))?;
        }
    }
    let uses_geoip = set.uses_geoip();
    commit_slot_update(ctx, &slot, set, stats.loaded, &spec.name);
    if uses_geoip {
        crate::geo::ensure(ctx, state);
    }
    Ok(stats.loaded)
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
    let Some(_updating) = SlotUpdateGuard::try_begin(&slot) else {
        return Err("rule provider update already in progress".into());
    };
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
        commit_slot_update(ctx, &slot, set, stats.loaded, &spec.name);
        Ok((stats.loaded, uses_geoip))
    }
    .await;
    match result {
        Ok((n, uses_geoip)) => {
            if uses_geoip {
                crate::geo::ensure(ctx, &ctx.state());
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
