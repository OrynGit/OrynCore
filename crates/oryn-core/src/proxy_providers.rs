//! 代理集合（`proxy-providers`）的下载、缓存与更新。
//!
//! 集合的节点在编译配置时从缓存展开（见 `oryn_config::parse_config_with`），因此内容变化后
//! 走与 `reload` 相同的路径：重新编译配置并应用，策略组的选择按名称保留。

use std::collections::HashMap;
use std::path::Path;
use std::rc::{Rc, Weak};
use std::time::{Duration, SystemTime};

use log::{info, warn};
use oryn_config::{parse_config_with, ConfigError, ProxyProviderSource, RuntimeConfig};
use oryn_http::{Options, Request};
use tokio::sync::Semaphore;

use crate::context::{EngineCtx, RuntimeState};
use crate::download::fetch_via;

const MAX_BODY: usize = 32 * 1024 * 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);
/// 启动时等待缺少缓存的集合下载完成的总时长。
const STARTUP_BUDGET: Duration = Duration::from_secs(15);
/// 从未成功下载时的重试间隔。
const RETRY: Duration = Duration::from_secs(60);
/// 多数订阅服务据此返回 mihomo YAML。
const DEFAULT_USER_AGENT: &str = "clash.meta";
static DOWNLOAD_LIMIT: Semaphore = Semaphore::const_new(2);

/// 配置原文与检查 overlay：集合更新后用它们重新编译。
#[derive(Clone)]
pub struct ConfigSource {
    pub text: String,
    pub inspection: Option<String>,
}

/// 订阅的流量与到期信息（响应头 `subscription-userinfo`）。
#[derive(Clone, Default, PartialEq, Debug)]
pub struct Traffic {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    /// 到期时间（Unix 秒）；0 为不限。
    pub expire: u64,
}

impl Traffic {
    /// `upload=1; download=2; total=3; expire=4`
    pub fn parse(header: &str) -> Option<Traffic> {
        let mut t = Traffic::default();
        let mut any = false;
        for part in header.split(';') {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            let Ok(n) = value.trim().parse::<f64>() else {
                continue;
            };
            let n = n.max(0.0) as u64;
            match key.trim().to_ascii_lowercase().as_str() {
                "upload" => t.upload = n,
                "download" => t.download = n,
                "total" => t.total = n,
                "expire" => t.expire = n,
                _ => continue,
            }
            any = true;
        }
        any.then_some(t)
    }
}

/// 响应头原文保存在缓存旁边（`<缓存>.userinfo`），App 未连接时也能读取，重启后不丢。
pub fn userinfo_path(cache: &Path) -> std::path::PathBuf {
    let mut p = cache.as_os_str().to_owned();
    p.push(".userinfo");
    p.into()
}

/// 最近一次下载的结果，供 `providers` 命令显示。
#[derive(Clone, Default)]
pub struct Status {
    pub error: Option<String>,
    pub updated: Option<SystemTime>,
    pub traffic: Option<Traffic>,
}

/// 读缓存 → 解析 → 叠加检查 overlay。
pub fn compile(
    text: &str,
    inspection: Option<&str>,
    data_dir: Option<&Path>,
) -> Result<RuntimeConfig, ConfigError> {
    let load = |path: &str| -> Option<String> {
        let bytes = std::fs::read(data_dir?.join(path)).ok()?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    };
    let config = (|| {
        let mut config = parse_config_with(text, &load)?;
        if let Some(overlay) = inspection {
            crate::engine::apply_inspection_overlay(&mut config, overlay)?;
        }
        Ok(config)
    })();
    // 解析与脚本校验（大脚本用 16 MiB 编译堆）的临时分配都在调用线程上，
    // 调用方可能是平台层的线程，不会再被事件循环整理
    crate::alloc::trim();
    config
}

fn cache_age(data_dir: Option<&Path>, path: &str) -> Option<Duration> {
    let modified = std::fs::metadata(data_dir?.join(path))
        .and_then(|m| m.modified())
        .ok()?;
    SystemTime::now().duration_since(modified).ok()
}

/// 启动时下载缺少缓存的集合（总时长有上限）。返回是否有集合下载成功（需要重新编译）。
/// 启动时需要先下载的 `http` 代理集合个数（尚无缓存）；与 [`fetch_missing`] 判定一致。
pub fn missing_count(config: &oryn_config::RuntimeConfig, data_dir: Option<&std::path::Path>) -> usize {
    if data_dir.is_none() {
        return 0;
    }
    config
        .proxy_providers
        .iter()
        .filter(|p| matches!(p.source, ProxyProviderSource::Http { .. }) && !p.loaded)
        .count()
}

pub async fn fetch_missing(ctx: &Rc<EngineCtx>) -> bool {
    let state = ctx.state();
    let missing: Vec<usize> = state
        .config
        .proxy_providers
        .iter()
        .enumerate()
        .filter(|(_, p)| matches!(p.source, ProxyProviderSource::Http { .. }) && !p.loaded)
        .map(|(i, _)| i)
        .collect();
    if missing.is_empty() || ctx.data_dir().is_none() {
        return false;
    }
    let mut handles = Vec::with_capacity(missing.len());
    let mut aborts = Vec::with_capacity(missing.len());
    for &i in &missing {
        let (c, s) = (ctx.clone(), state.clone());
        let task = tokio::task::spawn_local(async move { download(&c, &s, i).await });
        aborts.push(task.abort_handle());
        handles.push(task);
    }
    let all = async {
        let mut any = false;
        for h in handles {
            any |= matches!(h.await, Ok(Ok(true)));
        }
        any
    };
    match tokio::time::timeout(STARTUP_BUDGET, all).await {
        Ok(any) => any,
        Err(_) => {
            for abort in aborts {
                abort.abort();
            }
            warn!("proxy providers: initial download did not finish in time; continuing");
            // 已经写入缓存的部分仍然可用
            state.config.proxy_providers.iter().any(|p| {
                !p.loaded
                    && p.file_path()
                        .is_some_and(|f| cache_age(ctx.data_dir(), f).is_some())
            })
        }
    }
}

/// 为每个 `http` 集合启动定期更新。
pub fn spawn_updates(ctx: &Rc<EngineCtx>, state: &Rc<RuntimeState>) {
    for (i, spec) in state.config.proxy_providers.iter().enumerate() {
        let ProxyProviderSource::Http {
            interval_secs,
            cache_path,
            ..
        } = &spec.source
        else {
            continue;
        };
        let interval = interval_secs.map(Duration::from_secs);
        let first = if !spec.loaded {
            Some(Duration::ZERO)
        } else {
            let age = cache_age(ctx.data_dir(), cache_path).unwrap_or(Duration::MAX);
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
        let result = download(&ctx, &st, i).await;
        // 当前配置编译时还没有这个集合的内容（例如启动时下载超时后才写入缓存），同样需要重新编译
        let loaded = st.config.proxy_providers.get(i).is_some_and(|p| p.loaded);
        drop(st);
        match result {
            // 内容变化：重新编译后整个运行状态被替换，本任务随旧状态结束
            Ok(changed) if changed || !loaded => {
                schedule_reload(&ctx);
                return;
            }
            Ok(_) => match interval {
                Some(iv) => wait = iv,
                None => return,
            },
            Err(_) => wait = interval.map_or(RETRY, |iv| iv.min(RETRY * 10)),
        }
    }
}

/// 下载一个集合。内容可用且与缓存不同时写入缓存并返回 `true`。
pub async fn download(
    ctx: &Rc<EngineCtx>,
    state: &Rc<RuntimeState>,
    i: usize,
) -> Result<bool, String> {
    let spec = state
        .config
        .proxy_providers
        .get(i)
        .ok_or("no such proxy provider")?;
    let ProxyProviderSource::Http {
        url,
        via,
        size_limit,
        cache_path,
        headers,
        ..
    } = &spec.source
    else {
        return Err("not an http proxy provider".into());
    };
    let Some(dir) = ctx.data_dir() else {
        return Err("no data directory to cache the proxy provider".into());
    };
    let path = dir.join(cache_path);
    let opts = Options {
        timeout: DOWNLOAD_TIMEOUT,
        max_body: if *size_limit > 0 {
            (*size_limit as usize).min(MAX_BODY)
        } else {
            MAX_BODY
        },
        ..Options::default()
    };
    let mut request_headers: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
    {
        request_headers.push(("User-Agent", DEFAULT_USER_AGENT));
    }
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("accept"))
    {
        request_headers.push(("Accept", "application/yaml, text/yaml, application/json, text/plain, */*"));
    }
    let result = async {
        let _permit = DOWNLOAD_LIMIT
            .acquire()
            .await
            .map_err(|_| "proxy provider download limiter closed".to_string())?;
        warn!("proxy provider `{}` downloading", spec.name);
        let request = || Request {
            method: "GET",
            url,
            headers: &request_headers,
            body: &[],
        };
        let resp = fetch_via(
            &state.routing,
            state.config.direct_index(),
            *via,
            request,
            &opts,
        )
        .await
        .map_err(|e| e.to_string())?;
        if !resp.is_success() {
            return Err(format!("HTTP {}", resp.status));
        }
        // 这里只需要节点数量；解析产物及lossy文本不与缓存比较/写盘同时存活。
        let node_count = {
            let text = String::from_utf8_lossy(&resp.body);
            oryn_config::proxy_provider_nodes(&text)?.len()
        };
        if node_count == 0 {
            return Err("the downloaded content has no proxies".into());
        }
        let traffic = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("subscription-userinfo"))
            .map(|(_, v)| v.clone());
        let changed = !crate::cache_compare::matches(&path, &resp.body).unwrap_or(false);
        if changed {
            crate::providers::write_atomic(&path, &resp.body)
                .map_err(|e| format!("cannot write cache: {e}"))?;
        } else {
            // 内容没变也刷新修改时间，下次按间隔计算
            let _ = crate::providers::write_atomic(&path, &resp.body);
        }
        if let Some(raw) = &traffic {
            let _ = crate::providers::write_atomic(&userinfo_path(&path), raw.as_bytes());
        }
        Ok((
            changed,
            node_count,
            traffic.as_deref().and_then(Traffic::parse),
        ))
    }
    .await;
    let mut statuses = ctx.proxy_provider_status.borrow_mut();
    let status = statuses.entry(spec.name.clone()).or_default();
    match result {
        Ok((changed, n, traffic)) => {
            info!(
                "proxy provider `{}` downloaded: {n} proxies{}",
                spec.name,
                if changed { "" } else { " (unchanged)" }
            );
            if changed {
                crate::events::push(
                    "resource",
                    "Proxy provider updated",
                    format!("{}: {n} proxies", spec.name),
                );
            }
            let traffic = traffic.or_else(|| status.traffic.clone());
            *status = Status {
                error: None,
                updated: Some(SystemTime::now()),
                traffic,
            };
            Ok(changed)
        }
        Err(e) => {
            warn!("proxy provider `{}` update failed: {e}", spec.name);
            crate::events::push(
                "resource",
                "Proxy provider update failed",
                format!("{}: {e}", spec.name),
            );
            status.error = Some(e.clone());
            Err(e)
        }
    }
}

/// 用保存的配置原文重新编译并应用（集合内容变化后）。
pub fn schedule_reload(ctx: &Rc<EngineCtx>) {
    if ctx.reload_compiling.get() {
        ctx.reload_provider_dirty.set(true);
        return;
    }
    let Some(source) = ctx.config_source.borrow().clone() else {
        return;
    };
    let config = match compile(&source.text, source.inspection.as_deref(), ctx.data_dir()) {
        Ok(c) => c,
        Err(e) => {
            warn!("proxy providers: recompiling the configuration failed: {e}");
            return;
        }
    };
    let c = ctx.clone();
    if let Some(previous) = ctx.pending_reload.borrow_mut().take() {
        previous.abort();
    }
    *ctx.pending_reload.borrow_mut() = Some(tokio::task::spawn_local(async move {
        let prepared = crate::modules::prepare_for_apply(&c, config).await;
        c.apply_prepared(prepared);
        info!("configuration recompiled after a proxy provider update");
    }));
}

/// `providers` 命令里的代理集合列表。
pub fn status_json(ctx: &EngineCtx, state: &RuntimeState) -> Vec<serde_json::Value> {
    let statuses: HashMap<String, Status> = ctx.proxy_provider_status.borrow().clone();
    state
        .config
        .proxy_providers
        .iter()
        .map(|p| {
            let status = statuses.get(&p.name).cloned().unwrap_or_default();
            let (kind, url) = match &p.source {
                ProxyProviderSource::Http { url, .. } => ("http", Some(url.clone())),
                ProxyProviderSource::File { .. } => ("file", None),
                ProxyProviderSource::Inline => ("inline", None),
            };
            let updated = status.updated.or_else(|| {
                let f = ctx.data_dir()?.join(p.file_path()?);
                std::fs::metadata(f).and_then(|m| m.modified()).ok()
            });
            // 重启后没有下载过时，用缓存旁边保存的响应头
            let traffic = status.traffic.clone().or_else(|| {
                let f = ctx.data_dir()?.join(p.file_path()?);
                let raw = std::fs::read_to_string(userinfo_path(&f)).ok()?;
                Traffic::parse(&raw)
            });
            serde_json::json!({
                "traffic": traffic.map(|t| serde_json::json!({
                    "upload": t.upload, "download": t.download, "total": t.total, "expire": t.expire,
                })),
                "health_check": p.health.is_some(),
                "name": p.name,
                "type": kind,
                "behavior": "proxy",
                "url": url,
                "count": p.members.len(),
                "loaded": p.loaded && p.error.is_none(),
                "updated_at": updated
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs_f64()),
                "error": status.error.or_else(|| p.error.clone()),
            })
        })
        .collect()
}
