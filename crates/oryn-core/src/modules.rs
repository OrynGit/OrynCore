//! 模块与依赖资源在配置发布前加载。失败保留已验证的磁盘缓存，数据面不下载源码。
use crate::context::EngineCtx;
use oryn_config::RuntimeConfig;
use oryn_http::{fetch, Options, OutboundConnector, Request};
use oryn_module::{ModuleFormat, MAX_MODULE_BYTES};
use oryn_outbound::{resolve, PickMeta};
use oryn_router::{DomainSource, FlowContext, Network};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    rc::Rc,
    time::{Duration, SystemTime},
};

/// 模块与脚本资源下载使用的 User-Agent。部分模块站点（如 kelee.one 的 Cloudflare 规则）
/// 只放行 Surge / Loon / Clash 系客户端，`Oryn/x.y.z` 与空 UA 会得到 403；
/// 前缀沿用 Surge，末尾保留 Oryn 标识。主 App 侧 `OrynConstants.moduleUserAgent` 必须与之一致。
pub const MODULE_USER_AGENT: &str = concat!("Surge iOS/3000 Oryn/", env!("CARGO_PKG_VERSION"));
#[cfg(test)]
#[path = "modules_corpus_tests.rs"]
mod corpus_tests;
#[cfg(test)]
#[path = "modules_generation_tests.rs"]
mod generation_tests;

const MAX_RESOURCES: usize = 8 * 1024 * 1024;
const MAX_SNAPSHOT: usize = 16 * 1024 * 1024;
const MAX_DISK_CACHE: u64 = 64 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
struct ValidatedModule {
    ir: oryn_module::ModuleIR,
    resources: std::collections::BTreeMap<String, String>,
}
fn snapshot_key(spec: &oryn_config::ModuleSpec) -> String {
    let key = serde_json::to_vec(&(&spec.url, spec.format, &spec.arguments)).unwrap();
    format!("{:x}", Sha256::digest(key))
}
fn module_size(spec: &oryn_config::ModuleSpec) -> usize {
    spec.resources.values().map(|v| v.len()).sum::<usize>()
        + spec
            .inline
            .as_ref()
            .map(|ir| {
                serde_json::to_vec(ir)
                    .map(|v| v.len())
                    .unwrap_or(MAX_RESOURCES + 1)
            })
            .unwrap_or(0)
}
fn validate(spec: &oryn_config::ModuleSpec) -> Result<oryn_http_inspect::Plan, String> {
    let ir = spec.inline.as_ref().ok_or("module has no valid source")?;
    if module_size(spec) > MAX_RESOURCES {
        return Err("module resource total exceeds 8 MiB".into());
    }
    oryn_http_inspect::compile_module_with_policies(
        ir,
        &spec.arguments.iter().cloned().collect(),
        &spec.resources,
        &spec.policy_map,
    )
    .map_err(|e| e.to_string())
}
fn save_validated(dir: &Path, spec: &oryn_config::ModuleSpec) -> Result<(), String> {
    use base64::Engine as _;
    validate(spec)?;
    let record = ValidatedModule {
        ir: spec.inline.clone().unwrap(),
        resources: spec
            .resources
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    base64::engine::general_purpose::STANDARD.encode(v),
                )
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_SNAPSHOT {
        return Err("validated module exceeds cache limit".into());
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let file = dir.join(snapshot_key(spec));
    let tmp = file.with_extension("tmp");
    std::fs::write(&tmp, bytes)
        .and_then(|_| std::fs::rename(&tmp, &file))
        .map_err(|e| e.to_string())?;
    trim_cache(dir, &file)?;
    Ok(())
}
fn restore_validated(dir: &Path, spec: &mut oryn_config::ModuleSpec) -> Result<(), String> {
    use base64::Engine as _;
    let bytes = read_bounded(&dir.join(snapshot_key(spec)), MAX_SNAPSHOT)?;
    let record: ValidatedModule = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let mut restored = spec.clone();
    restored.inline = Some(record.ir);
    restored.resources = Default::default();
    for (key, data) in record.resources {
        std::sync::Arc::make_mut(&mut restored.resources).insert(
            key,
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|e| e.to_string())?
                .into(),
        );
        if module_size(&restored) > MAX_RESOURCES {
            return Err("module cache exceeds resource limit".into());
        }
    }
    validate(&restored)?;
    *spec = restored;
    Ok(())
}
/// 只清理专属下载/已验证缓存目录，绝不删除用户导入的模块文件。
fn trim_cache(dir: &Path, keep: &Path) -> Result<(), String> {
    let mut files = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            m.is_file().then(|| {
                (
                    e.path(),
                    m.len(),
                    m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                )
            })
        })
        .collect::<Vec<_>>();
    let mut total = files.iter().map(|v| v.1).sum::<u64>();
    files.sort_by_key(|v| v.2);
    for (path, n, _) in files {
        if total <= MAX_DISK_CACHE {
            break;
        }
        if path != keep {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
            total = total.saturating_sub(n);
        }
    }
    Ok(())
}

/// 仅当前 prepare→apply 拥有；不进入 RuntimeConfig，也不跨线程缓存。
pub(crate) struct PreparedConfig {
    config: RuntimeConfig,
    plans: Vec<(usize, oryn_http_inspect::Plan)>,
    /// 离线准备时有远程资源过期或尚无缓存，需要联网补一次。
    deferred: bool,
}
impl PreparedConfig {
    pub(crate) fn into_parts(self) -> (RuntimeConfig, Vec<(usize, oryn_http_inspect::Plan)>) {
        (self.config, self.plans)
    }
}

#[cfg(test)]
pub async fn prepare(ctx: &Rc<EngineCtx>, config: RuntimeConfig) -> RuntimeConfig {
    prepare_inner(ctx, config, false).await.config
}

pub(crate) async fn prepare_for_apply(ctx: &Rc<EngineCtx>, config: RuntimeConfig) -> PreparedConfig {
    prepare_inner_with(ctx, config, ctx.desktop_reload_compile(), &Fetch::online()).await
}

/// 启动用：只读磁盘缓存（过期也用），不联网，避免隧道在「连接中」停留到所有模块下载完。
/// 返回值为真表示有资源过期或缺失，启动后应调用 [`refresh_deferred`] 联网补齐。
pub(crate) async fn prepare_for_startup(ctx: &Rc<EngineCtx>, config: RuntimeConfig) -> (PreparedConfig, bool) {
    let mode = Fetch { offline: true, deferred: std::cell::Cell::new(false) };
    let prepared = prepare_inner_with(ctx, config, ctx.desktop_reload_compile(), &mode).await;
    let deferred = prepared.deferred;
    (prepared, deferred)
}

/// 启动后在后台联网准备模块并发布。`modules` 是离线准备之前的模块列表：
/// 离线时没有缓存的模块已被禁用，不能拿已发布的 base_config 去刷新。
/// 期间若有其他重载（切换配置、代理集合更新）发布了新配置，它们自己会联网准备，这里放弃。
pub(crate) fn refresh_deferred(ctx: &Rc<EngineCtx>, modules: Vec<oryn_config::ModuleSpec>) {
    if ctx.reload_compiling.get()
        || ctx.pending_reload.borrow().as_ref().is_some_and(|t| !t.is_finished())
    {
        return;
    }
    let state = ctx.state();
    let c = ctx.clone();
    *ctx.pending_reload.borrow_mut() = Some(tokio::task::spawn_local(async move {
        let mut base = state.base_config.clone();
        base.modules = modules;
        let prepared = prepare_for_apply(&c, base).await;
        if Rc::ptr_eq(&state, &c.state()) {
            c.apply_prepared(prepared);
            log::info!("modules refreshed after startup");
        }
    }));
}

/// 资源获取方式。离线时过期缓存直接使用，没有缓存则返回 [`DEFERRED`]。
pub(crate) struct Fetch {
    offline: bool,
    deferred: std::cell::Cell<bool>,
}
impl Fetch {
    fn online() -> Self {
        Self { offline: false, deferred: std::cell::Cell::new(false) }
    }
}
const DEFERRED: &str = "not cached yet; downloading after startup";

#[cfg(test)]
async fn prepare_inner(ctx: &Rc<EngineCtx>, config: RuntimeConfig, retain: bool) -> PreparedConfig {
    prepare_inner_with(ctx, config, retain, &Fetch::online()).await
}

async fn prepare_inner_with(
    ctx: &Rc<EngineCtx>,
    mut config: RuntimeConfig,
    retain: bool,
    mode: &Fetch,
) -> PreparedConfig {
    let mut plans = Vec::new();
    #[cfg(test)]
    let _lifecycle_probe = crate::reload_lifecycle_tests::PrepareProbe::new(&config);
    let mut total = 0;
    let previous = ctx.state();
    let snapshots = ctx.data_dir().map(|d| d.join("modules/.validated"));
    // 执行堆内解析不了的大脚本在校验时编译为字节码，执行时直接读取。
    oryn_script::set_bytecode_cache_dir(ctx.data_dir().map(|d| d.join("modules/.bytecode")));
    for (index, spec) in config.modules.iter_mut().enumerate().filter(|(_, m)| m.enabled).take(64) {
        // inline/缓存资源可能全程同步完成；入口让出也覆盖资源超限的 continue。
        tokio::task::yield_now().await;
        let mut candidate = spec.clone();
        let result = load_candidate(ctx, &mut candidate, mode).await;
        match result {
            Ok(plan) => {
                // Extension 保持原瞬时生命周期，save_validated 再验证前先释放。
                let plan = if retain { Some(plan) } else { drop(plan); None };
                if total + module_size(&candidate) > MAX_RESOURCES {
                    spec.enabled = false;
                    spec.resources = Default::default();
                    spec.inline = None;
                    config
                        .warnings
                        .push("module resource total exceeds 8 MiB; module disabled".into());
                    continue;
                }
                // 离线启动读的就是缓存，没有新内容可存
                if spec.url.is_some() && !mode.offline {
                    if let Some(dir) = &snapshots {
                        if let Err(e) = save_validated(dir, &candidate) {
                            config.warnings.push(format!("module validated cache: {e}"));
                        }
                    }
                }
                *spec = candidate;
                if let Some(plan) = plan {
                    plans.push((index, plan));
                }
            }
            Err(e) => {
                let restored = snapshots
                    .as_ref()
                    .is_some_and(|dir| spec.url.is_some() && restore_validated(dir, spec).is_ok());
                if !restored {
                    let old = previous.config.modules.iter().find(|old| {
                        old.url.is_some()
                            && snapshot_key(old) == snapshot_key(spec)
                            && validate(old).is_ok()
                    });
                    if let Some(old) = old {
                        spec.inline = old.inline.clone();
                        spec.resources = old.resources.clone();
                    } else {
                        spec.enabled = false;
                    }
                }
                // 离线启动时尚无缓存：随后联网补齐，不当作失败告警。
                if e != DEFERRED { config.warnings.push(format!(
                    "module {} update rejected: {e}; {}",
                    spec.url.as_deref().unwrap_or("inline"),
                    if spec.enabled {
                        "previous validated module retained"
                    } else {
                        "module disabled"
                    }
                )); }
            }
        }
        if spec.enabled {
            total += module_size(spec);
            if total > MAX_RESOURCES {
                spec.enabled = false;
                config
                    .warnings
                    .push("module resource total exceeds 8 MiB; module disabled".into());
            }
        }
        if !spec.enabled {
            spec.resources = Default::default();
            spec.inline = None;
        }
    }
    PreparedConfig { config, plans, deferred: mode.deferred.get() }
}
async fn load_candidate(
    ctx: &Rc<EngineCtx>,
    spec: &mut oryn_config::ModuleSpec,
    mode: &Fetch,
) -> Result<oryn_http_inspect::Plan, String> {
    if let Some(source) = &spec.url {
        let bytes = resource(ctx, source, spec.update_interval, MAX_MODULE_BYTES, mode).await?;
        let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
        let format = spec.format.unwrap_or_else(|| {
            // 扩展名比内容判断可靠：只有 [Rule] 的 Loon 插件从内容上看不出方言。
            let path = source.split(['?', '#']).next().unwrap_or(source).to_ascii_lowercase();
            if path.ends_with(".sgmodule") {
                ModuleFormat::Surge
            } else if path.ends_with(".plugin") || path.ends_with(".lpx") {
                ModuleFormat::Loon
            } else {
                oryn_module::detect_format(text)
            }
        });
        let bound =
            oryn_module::bind(text, format, &spec.arguments).map_err(|e| e.to_string())?;
        for w in &bound.warnings {
            log::warn!("module {source}: {w}");
        }
        let text = bound.text;
        spec.inline =
            Some(oryn_module::parse_named(&text, Some(format), source).map_err(|e| e.to_string())?);
    }
    let ir = spec.inline.as_ref().ok_or("module source unavailable")?;
    let refs = resource_references(ir);
    spec.resources = Default::default();
    for path in refs {
        let source = spec.url.as_deref().unwrap_or("");
        let url = if path.starts_with("https://") {
            path.clone()
        } else if source.starts_with("https://") {
            url::Url::parse(source)
                .and_then(|u| u.join(&path))
                .map_err(|e| e.to_string())?
                .to_string()
        } else {
            Path::new(source)
                .parent()
                .unwrap_or(Path::new(""))
                .join(&path)
                .to_string_lossy()
                .into_owned()
        };
        // 单个资源取不到只让引用它的那一行在编译时被跳过（带告警），模块其余部分照常生效。
        let data = match resource(ctx, &url, spec.update_interval, MAX_MODULE_BYTES, mode).await {
            Ok(data) => data,
            // 离线时缺资源：整个模块改用已验证快照，而不是带缺口启用
            Err(e) if e == DEFERRED => return Err(e),
            Err(e) => {
                log::warn!(
                    "module {}: resource {path} unavailable: {e}",
                    spec.url.as_deref().unwrap_or("inline")
                );
                continue;
            }
        };
        std::sync::Arc::make_mut(&mut spec.resources).insert(path, data.into());
        if module_size(spec) > MAX_RESOURCES {
            return Err("module resource total exceeds 8 MiB".into());
        }
    }
    validate(spec)
}
/// `key=` 之后的值：以 `"` 或 `'` 开头时取到配对引号（可含逗号），否则取到逗号或空白。
fn option_value<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(i) = s[from..].find(key) {
        let at = from + i;
        from = at + key.len();
        // 必须是独立的选项名（前面是行首、逗号或空白），避免 `xdata=` 误匹配 `data=`。
        if at > 0 && !s[..at].ends_with([',', ' ', '\t']) {
            continue;
        }
        let rest = s[from..].trim_start();
        let value = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => rest[1..].split_once(q).map(|(v, _)| v),
            _ => rest.split([',', ' ', '\t']).next(),
        };
        return value.map(str::trim).filter(|v| !v.is_empty());
    }
    None
}
fn resource_references(m: &oryn_module::ModuleIR) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    let calls =
        regex::Regex::new(r#"(?:jq_file|script)\(\s*(?:"([^"]+)"|'([^']+)')"#).unwrap();
    // mock_file 的第一个参数是类型，第二个才是文件；两个参数的引号可以不同。
    let mocks = regex::Regex::new(
        r#"mock_file\(\s*(?:"[^"]*"|'[^']*')\s*,\s*(?:"([^"]+)"|'([^']+)')"#,
    )
    .unwrap();
    for s in m
        .rewrites
        .iter()
        .map(|r| r.text.as_str())
        .chain(m.scripts.iter().map(|s| s.text.as_str()))
    {
        for c in calls.captures_iter(s).chain(mocks.captures_iter(s)) {
            if let Some(v) = c.get(1).or_else(|| c.get(2)) {
                out.insert(v.as_str().to_owned());
            }
        }
        for key in ["script-path=", "data-path="] {
            if let Some(path) = option_value(s, key) {
                out.insert(path.into());
            }
        }
        let file_data = option_value(s, "data-type=").is_some_and(|t| t == "file")
            || s.contains("data-type = file");
        if file_data {
            if let Some(path) = option_value(s, "data=") {
                out.insert(path.into());
            }
        }
    }
    out.into_iter().take(128).collect()
}
async fn resource(
    ctx: &Rc<EngineCtx>,
    source: &str,
    interval: u64,
    max: usize,
    mode: &Fetch,
) -> Result<Vec<u8>, String> {
    let dir = ctx
        .data_dir()
        .ok_or("module cache directory unavailable")?
        .join("modules");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let remote = source.starts_with("https://");
    #[cfg(test)]
    let remote = remote || crate::reload_lifecycle_tests::local_resource(source);
    if !remote {
        if source.contains("://") {
            return Err("module resources require HTTPS".into());
        }
        let root = dir.canonicalize().map_err(|e| e.to_string())?;
        let p = root
            .join(source)
            .canonicalize()
            .map_err(|e| e.to_string())?;
        if !p.starts_with(root) {
            return Err("module file escapes resource directory".into());
        }
        return read_bounded(&p, max);
    }
    let dir = dir.join(".downloads");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let digest = format!("{:x}", Sha256::digest(source.as_bytes()));
    let file = dir.join(digest);
    let cached = read_bounded(&file, max).ok();
    let fresh = std::fs::metadata(&file)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|d| d.as_secs() < interval);
    if fresh {
        if let Some(data) = cached {
            return Ok(data);
        }
    }
    if mode.offline {
        mode.deferred.set(true);
        return cached.ok_or_else(|| DEFERRED.into());
    }
    let url = url::Url::parse(source).map_err(|e| e.to_string())?;
    let host = url.host_str().ok_or("missing resource host")?;
    let port = url.port_or_known_default().unwrap_or(443);
    let state = ctx.state();
    let target = oryn_config::TargetAddr::from_host(host, port);
    let mut flow = FlowContext::new(
        0,
        Network::Tcp,
        "127.0.0.1:0".parse().unwrap(),
        format!("0.0.0.0:{port}").parse().unwrap(),
    );
    flow.set_domain(host.into(), DomainSource::Sniffed);
    let route = state.router().route(&flow);
    let out = resolve(
        &state.routing.outbounds[route.outbound],
        &PickMeta {
            source: None,
            target: &target,
            network: Network::Tcp,
        },
    )
    .ok_or("module resource route rejected")?;
    let options = Options {
        max_body: max,
        timeout: Duration::from_secs(15),
        max_redirects: 3,
        ..Default::default()
    };
    let request = Request {
        method: "GET",
        url: source,
        headers: &[("User-Agent", MODULE_USER_AGENT)],
        body: &[],
    };
    match fetch(&OutboundConnector(out.leaf), request, &options).await {
        Ok(r) if r.is_success() => {
            let tmp = file.with_extension("tmp");
            std::fs::write(&tmp, &r.body)
                .and_then(|_| std::fs::rename(tmp, &file))
                .map_err(|e| e.to_string())?;
            trim_cache(&dir, &file)?;
            Ok(r.body)
        }
        Ok(r) => cached.ok_or_else(|| format!("resource HTTP status {}", r.status)),
        Err(e) => cached.ok_or_else(|| e.to_string()),
    }
}
fn read_bounded(p: &Path, max: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(p)
        .map_err(|e| e.to_string())?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max {
        return Err("resource exceeds size limit".into());
    }
    Ok(bytes)
}

/// 定时更新使用 Weak 引用；旧 flow 仍持有配置时，由执行路径检查代际。
pub fn schedule(ctx: &Rc<EngineCtx>, state: &Rc<crate::context::RuntimeState>) {
    let Some(interval) = state
        .config
        .modules
        .iter()
        .filter(|s| s.enabled && s.url.as_ref().is_some_and(|u| u.starts_with("https://")))
        .map(|s| s.update_interval)
        .min()
    else {
        return;
    };
    let weak = Rc::downgrade(ctx);
    let state_weak = Rc::downgrade(state);
    state.spawn(async move {
        tokio::time::sleep(Duration::from_secs(interval.max(60))).await;
        let (Some(ctx), Some(state)) = (weak.upgrade(), state_weak.upgrade()) else {
            return;
        };
        refresh(&ctx, state);
    });
}

// timer 唤醒后的执行路径；与等待时间分开，便于定向验证代际切换。
pub(crate) fn refresh(ctx: &Rc<EngineCtx>, state: Rc<crate::context::RuntimeState>) {
    if !Rc::ptr_eq(&state, &ctx.state()) {
        return;
    }
    if ctx.reload_compiling.get() {
        ctx.reload_modules_dirty.set(true);
        return;
    }
    if ctx
        .pending_reload
        .borrow()
        .as_ref()
        .is_some_and(|t| !t.is_finished())
    {
        return;
    }
    let base = state.base_config.clone();
    let c = ctx.clone();
    *ctx.pending_reload.borrow_mut() = Some(tokio::task::spawn_local(async move {
        let prepared = prepare_for_apply(&c, base).await;
        // prepare 的下载 await 期间可能已发布新配置，不能用旧 base_config 覆盖。
        if Rc::ptr_eq(&state, &c.state()) {
            c.apply_prepared(prepared);
        }
    }));
}

/// 模块的 `#!system` / `#!system_version` / `#!requirement` 是否满足；不满足时给出原因。
pub fn allowed(ir: &oryn_module::ModuleIR, system_version: &str) -> Result<(), String> {
    if let Some(s) = ir.meta.system.as_deref().filter(|s| !s.is_empty()) {
        if !s
            .split(',')
            .any(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "ios" | "ipados"))
        {
            return Err(format!("requires system {s}"));
        }
    }
    let version = |s: &str| {
        let p = s
            .split('.')
            .map(|s| s.parse::<u32>().unwrap_or(0))
            .take(3)
            .collect::<Vec<_>>();
        (
            p.first().copied().unwrap_or(0),
            p.get(1).copied().unwrap_or(0),
            p.get(2).copied().unwrap_or(0),
        )
    };
    if let Some(s) = ir.meta.system_version.as_deref().filter(|s| !s.is_empty()) {
        if version(system_version) < version(s) {
            return Err(format!("requires system version {s} or later"));
        }
    }
    let env = std::collections::BTreeMap::from([
        ("SYSTEM".into(), "iOS".into()),
        ("SYSTEM_VERSION".into(), system_version.into()),
        ("CORE_VERSION".into(), "20".into()),
    ]);
    match ir.meta.core_requirement.as_deref() {
        None => Ok(()),
        Some(r) => match oryn_module::requirements::evaluate(r, &env) {
            Ok(true) => Ok(()),
            Ok(false) => Err(format!("requirement `{r}` not satisfied")),
            Err(e) => Err(format!("requirement `{r}` invalid: {e}")),
        },
    }
}

#[cfg(test)]
mod reference_tests {
    #[test]
    fn option_values_handle_quotes() {
        use super::option_value;
        assert_eq!(option_value("a=1, data='f,1.json', x", "data="), Some("f,1.json"));
        assert_eq!(option_value("script-path=\"https://a/b,c.js\", tag=x", "script-path="), Some("https://a/b,c.js"));
        assert_eq!(option_value("xdata=1,data=f.txt", "data="), Some("f.txt"));
        assert_eq!(option_value("script-path=a.js", "data-path="), None);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validated_bundle_survives_bad_update_and_restart() {
        let dir = std::env::temp_dir().join(format!("oryn-module-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut spec = oryn_config::parse_config("modules:\n  - url: fixture.sgmodule\n")
            .unwrap()
            .modules
            .remove(0);
        spec.inline=Some(oryn_module::parse("[Script]\nfixture = type=http-response, pattern=^https://fixture.test, script-path=script.js, requires-body=true",Some(ModuleFormat::Surge)).unwrap());
        std::sync::Arc::make_mut(&mut spec.resources)
            .insert("script.js".into(), b"$done({body:'ok'});".as_slice().into());
        save_validated(&dir, &spec).unwrap();
        let mut bad = spec.clone();
        std::sync::Arc::make_mut(&mut bad.resources)
            .insert("script.js".into(), b"function {".as_slice().into());
        assert!(save_validated(&dir, &bad).is_err());
        bad.inline = None;
        bad.resources = Default::default();
        restore_validated(&dir, &mut bad).unwrap();
        assert_eq!(bad.inline, spec.inline);
        assert_eq!(bad.resources, spec.resources);
        bad.arguments.push(("changed".into(), "true".into()));
        assert!(restore_validated(&dir, &mut bad).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
