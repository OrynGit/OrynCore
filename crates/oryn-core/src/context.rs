//! 事件循环线程内共享的状态。

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::SystemTime;

use log::warn;
use oryn_config::{Mode, OutboundKind, ProxyProviderSource, RuntimeConfig};
use oryn_dns::{DirectTargetResolver, DnsEngine, ProxyServerResolver, Routing};
use oryn_http_inspect::Plan as HttpPlan;
use oryn_netstack::LwipStack;
use oryn_outbound::{
    build_outbounds_reusing, BuildContext, HealthStore, PreviousOutbounds, SessionControl,
};
use oryn_router::{GeoIp, Router, RuleSetStore};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::options::{EngineOptions, LocalProxyOptions};
use crate::stats::{ConnRegistry, Stats};
use crate::udp::UdpManager;
use crate::{geo, health, providers, public_ip};

/// 同时处理的 DNS 查询上限，超过的查询直接丢弃（应用会重试）。
pub const MAX_CONCURRENT_DNS: usize = 128;

/// 一份运行时配置及其后台任务。重载时整体替换；已建立的 Flow 继续使用旧的。
pub struct RuntimeState {
    pub base_config: RuntimeConfig,
    pub aux_cancel: tokio::sync::watch::Sender<bool>,
    pub compiled_modules_enabled: Vec<bool>,
    pub module_compile_warnings: Vec<String>,
    pub config: RuntimeConfig,
    pub routing: Arc<Routing>,
    pub rule_sets: Arc<RuleSetStore>,
    pub health: Arc<HealthStore>,
    pub sessions: Vec<Arc<dyn SessionControl>>,
    pub http_plan: Rc<HttpPlan>,
    pub scripts: Arc<crate::scripts::ScriptHost>,
    pub mitm_ca: Option<Rc<RefCell<oryn_mitm::CertificateAuthority>>>,
    pub http_transactions: Option<Arc<tokio::sync::Semaphore>>,
    pub http_bodies: Arc<tokio::sync::Semaphore>,
    pub geo_started: Cell<bool>,
    needs_geo: bool,
    tasks: RefCell<Vec<JoinHandle<()>>>,
}

impl RuntimeState {
    pub fn router(&self) -> &Router {
        &self.routing.router
    }

    /// 显式终止维护任务；任务可能持有本state跨await，不能等Drop才打破保活。
    fn cancel_tasks(&self) {
        for task in self.tasks.borrow_mut().drain(..) {
            task.abort();
        }
    }

    /// 启动属于本配置的后台任务，配置被替换时自动取消。
    pub fn spawn(&self, fut: impl Future<Output = ()> + 'static) {
        let handle = tokio::task::spawn_local(fut);
        let mut tasks = self.tasks.borrow_mut();
        tasks.retain(|t| !t.is_finished());
        tasks.push(handle);
    }
}

impl Drop for RuntimeState {
    fn drop(&mut self) {
        #[cfg(test)]
        crate::reload_lifecycle_tests::state_drop(&self.config);
        self.cancel_tasks();
    }
}

type CachedCa = (
    PathBuf,
    Option<(SystemTime, u64)>,
    Rc<RefCell<oryn_mitm::CertificateAuthority>>,
);

pub struct EngineCtx {
    pub admission: crate::admission::Admission,
    pub iperf: Rc<crate::iperf::Manager>,
    pub network_test: Rc<crate::network_test::Manager>,
    pub selftest: Rc<crate::selftest::Manager>,
    pub pending_reload: RefCell<Option<JoinHandle<()>>>,
    pub reload_compiling: Cell<bool>,
    pub reload_provider_dirty: Cell<bool>,
    pub reload_modules_dirty: Cell<bool>,
    pub selection_revision: Cell<u64>,
    pub mode_revision: Cell<u64>,
    pub initialized: Cell<bool>,
    pub health: Arc<HealthStore>,
    pub config_generation: Cell<u64>,
    pub resource_revision: Cell<u64>,
    pub proxy_provider_overrides: RefCell<HashMap<String, String>>,
    mitm_ca_cache: RefCell<Option<CachedCa>>,
    pub script_host: Arc<crate::scripts::ScriptHost>,
    pub http_transactions: Option<Arc<tokio::sync::Semaphore>>,
    pub http_bodies: Arc<tokio::sync::Semaphore>,
    pub http_connections: Option<Arc<tokio::sync::Semaphore>>,
    /// 已建立下游可派生多个上游，独立限制其 TCP/TLS/HTTP 建立阶段。
    pub http_upstream_establish: Arc<tokio::sync::Semaphore>,
    /// 客户端拒绝 MITM 证书（证书固定）或握手超时的主机：一段时间内直通不解密。
    pub mitm_bypass: RefCell<HashMap<(String, u16), std::time::Instant>>,
    pub stack: LwipStack,
    pub dns: Arc<DnsEngine>,
    pub geoip: Arc<GeoIp>,
    pub asn: Arc<GeoIp>,
    pub databases: [geo::DatabaseStatus; 2],
    pub database_download: Arc<tokio::sync::Mutex<()>>,
    pub maxmind: RefCell<Option<crate::options::MaxMindOptions>>,
    pub state: RefCell<Rc<RuntimeState>>,
    pub conns: Rc<ConnRegistry>,
    /// 切换策略组节点时立即结束经过该组的现有连接。
    pub close_on_policy_switch: Cell<bool>,
    /// QUIC 全局策略（`default` / `always` / `never`），可由 `apply_settings` 运行中修改。
    block_quic: Cell<&'static str>,
    pub udp: UdpManager,
    pub stats: Arc<Stats>,
    pub dns_inflight: Cell<usize>,
    /// select 策略组的选择，重载配置后保持。
    pub selections: RefCell<HashMap<String, String>>,
    pub mode_override: Cell<Option<Mode>>,
    pub public_ip_refresh: Rc<Notify>,
    pub local_proxy_abort: RefCell<Option<tokio::task::AbortHandle>>,
    /// 配置原文：代理集合更新后用它重新编译。
    pub config_source: RefCell<Option<crate::proxy_providers::ConfigSource>>,
    pub proxy_provider_status: RefCell<HashMap<String, crate::proxy_providers::Status>>,
    local_proxy: RefCell<LocalProxyOptions>,
    options: EngineOptions,
    next_id: Cell<u64>,
    pub local_ipv6: crate::local_ipv6::LocalIpv6,
}

fn block_quic_mode(value: &str) -> Option<&'static str> {
    match value {
        "default" => Some("default"),
        "always" => Some("always"),
        "never" => Some("never"),
        _ => None,
    }
}

/// MITM 握手失败后直通的时长与条目上限。
const MITM_BYPASS_TTL: std::time::Duration = std::time::Duration::from_secs(600);
const MAX_MITM_BYPASS: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyMode {
    FullReload,
    PartialUpdate,
}

impl EngineCtx {
    pub fn desktop_reload_compile(&self) -> bool {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            self.options.resource_profile == crate::options::ResourceProfile::DesktopHigh
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            false
        }
    }

    pub fn mitm_bypassed(&self, host: &str, port: u16) -> bool {
        let mut map = self.mitm_bypass.borrow_mut();
        let key = (host.to_owned(), port);
        match map.get(&key) {
            Some(at) if at.elapsed() < MITM_BYPASS_TTL => true,
            Some(_) => {
                map.remove(&key);
                false
            }
            None => false,
        }
    }

    pub fn bypass_mitm(&self, host: &str, port: u16) {
        let mut map = self.mitm_bypass.borrow_mut();
        if map.len() >= MAX_MITM_BYPASS {
            map.retain(|_, at| at.elapsed() < MITM_BYPASS_TTL);
            if map.len() >= MAX_MITM_BYPASS {
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest);
                }
            }
        }
        map.insert((host.to_owned(), port), std::time::Instant::now());
    }
    pub fn new(
        stack: LwipStack,
        config: RuntimeConfig,
        options: EngineOptions,
        stats: Arc<Stats>,
    ) -> Rc<Self> {
        let placeholder = Arc::new(RuleSetStore::new(&[]));
        let dns = Arc::new(DnsEngine::new(
            config.dns.clone(),
            config.hosts.clone(),
            placeholder,
        ));
        dns.set_target_ipv6(options.ipv6_support, options.prefer_ipv6);
        dns.set_proxy_prefer_ipv6(options.proxy_prefer_ipv6);
        dns.set_real_ip_domains(&options.real_ip_domains)
            .expect("validated real IP domains");
        dns.set_data_dir(options.data_dir.as_deref());
        dns.set_network(options.network.to_info());
        options.network.apply_interface();
        let limits = options.resource_profile.limits();
        log::info!(
            "engine resource profile {:?}: {:?}",
            options.resource_profile,
            limits
        );
        oryn_outbound::wireguard_resources::configure(oryn_outbound::wireguard_resources::Limits {
            buffer_budget: limits.wg_buffer_budget,
            workers: limits.wg_workers,
        });
        oryn_outbound::wireguard_resources::set_pressure(
            oryn_outbound::wireguard_resources::Pressure::Normal,
        );
        let health = Arc::new(HealthStore::default());
        let ctx = EngineCtx {
            admission: crate::admission::Admission::new(options.resource_profile),
            iperf: Rc::new(crate::iperf::Manager::default()),
            network_test: Rc::new(crate::network_test::Manager::default()),
            selftest: Rc::new(crate::selftest::Manager::default()),
            pending_reload: RefCell::new(None),
            reload_compiling: Cell::new(false),
            reload_provider_dirty: Cell::new(false),
            reload_modules_dirty: Cell::new(false),
            selection_revision: Cell::new(0),
            mode_revision: Cell::new(0),
            initialized: Cell::new(false),
            health: health.clone(),
            config_generation: Cell::new(0),
            resource_revision: Cell::new(0),
            proxy_provider_overrides: RefCell::new(HashMap::new()),
            mitm_ca_cache: RefCell::new(None),
            script_host: Arc::new(crate::scripts::ScriptHost::new_with_pools(
                options.data_dir.as_deref(),
                limits.script_http_workers,
                limits.script_bg_workers,
                limits.script_heap_limit,
                limits.script_bg_heap_limit,
                limits.http_max_body,
                limits.max_scripts,
            )),
            http_transactions: limits
                .http_transactions
                .map(tokio::sync::Semaphore::new)
                .map(Arc::new),
            http_bodies: Arc::new(tokio::sync::Semaphore::new(
                crate::http::body_budget_pages(limits.http_body_budget),
            )),
            http_connections: limits
                .http_connections
                .map(tokio::sync::Semaphore::new)
                .map(Arc::new),
            http_upstream_establish: Arc::new(tokio::sync::Semaphore::new(
                limits.http_upstream_establish,
            )),
            mitm_bypass: RefCell::new(HashMap::new()),
            stack,
            dns,
            geoip: Arc::new(GeoIp::default()),
            asn: Arc::new(GeoIp::default()),
            databases: Default::default(),
            database_download: Arc::new(tokio::sync::Mutex::new(())),
            maxmind: RefCell::new(options.maxmind.clone()),
            state: RefCell::new(Rc::new(empty_state(&config, &health))),
            conns: Rc::new(ConnRegistry::default()),
            close_on_policy_switch: Cell::new(options.close_connections_on_policy_switch),
            block_quic: Cell::new(block_quic_mode(&options.block_quic).unwrap_or("default")),
            udp: UdpManager::new(limits.udp_sessions),
            stats,
            dns_inflight: Cell::new(0),
            selections: RefCell::new(options.selections.clone()),
            mode_override: Cell::new(options.mode()),
            public_ip_refresh: Rc::new(Notify::new()),
            local_proxy_abort: RefCell::new(None),
            config_source: RefCell::new(None),
            proxy_provider_status: RefCell::new(HashMap::new()),
            local_proxy: RefCell::new(options.local_proxy.clone()),
            options,
            next_id: Cell::new(1),
            local_ipv6: Default::default(),
        };
        geo::load_cached(&ctx);
        let ctx = Rc::new(ctx);
        ctx.apply_config(config);
        ctx
    }

    pub fn system_version(&self) -> &str {
        &self.options.system_version
    }

    pub fn data_dir(&self) -> Option<&Path> {
        self.options.data_dir.as_deref()
    }

    pub(crate) fn resource_limits(&self) -> crate::options::ResourceLimits {
        self.options.resource_profile.limits()
    }

    /// 代理测试地址（首页「代理」一段与策略组测速共用），未设置时用配置格式的默认值。
    pub fn proxy_test_url(&self) -> &str {
        self.options
            .proxy_test_url
            .as_deref()
            .filter(|u| !u.trim().is_empty())
            .unwrap_or(oryn_config::DEFAULT_TEST_URL)
    }

    /// 手动 UDP 延迟测试的地址（`域名@DNS 服务器`），未设置时用默认值。
    pub fn udp_test_address(&self) -> &str {
        self.options
            .udp_test_url
            .as_deref()
            .filter(|a| !a.trim().is_empty())
            .unwrap_or(crate::health::DEFAULT_UDP_TEST)
    }

    pub fn local_proxy_options(&self) -> LocalProxyOptions {
        self.local_proxy.borrow().clone()
    }

    pub fn set_local_proxy(self: &Rc<Self>, options: LocalProxyOptions) {
        if *self.local_proxy.borrow() == options {
            return;
        }
        *self.local_proxy.borrow_mut() = options;
        crate::local_proxy::restart(self);
    }

    pub fn block_quic(&self) -> &'static str {
        self.block_quic.get()
    }

    /// 运行中修改 QUIC 策略，只影响之后的新 UDP 会话。
    pub fn set_block_quic(&self, value: &str) -> Result<(), String> {
        let mode = block_quic_mode(value)
            .ok_or_else(|| format!("block_quic must be default, always or never, got {value}"))?;
        self.block_quic.set(mode);
        Ok(())
    }

    pub fn state(&self) -> Rc<RuntimeState> {
        self.state.borrow().clone()
    }

    pub fn next_id(&self) -> u64 {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        id
    }

    /// 发往隧道内 DNS 地址的 53 端口，或命中宿主设置的 `dns-hijack`，交给内置 DNS。
    pub fn is_dns_target(&self, tcp: bool, ip: IpAddr, port: u16) -> bool {
        let builtin = port == 53
            && match ip {
                IpAddr::V4(v4) => v4 == self.options.dns_address,
                IpAddr::V6(v6) => v6.to_ipv4_mapped() == Some(self.options.dns_address),
            };
        builtin
            || self
                .options
                .dns_hijack()
                .iter()
                .any(|h| h.matches(tcp, ip, port))
    }

    pub fn validate_virtual_interface(&self, config: &RuntimeConfig) -> Result<(), String> {
        let next = self
            .options
            .virtual_interface
            .compile(config.dns.fake_ip_range, self.options.dns_address)?;
        let current = self.options.virtual_interface.compile(
            self.state().config.dns.fake_ip_range,
            self.options.dns_address,
        )?;
        if next != current {
            return Err(
                "virtual interface routes changed; reconnect to apply this configuration".into(),
            );
        }
        Ok(())
    }

    /// 加载一份新配置：构建出站、路由、DNS，并启动后台任务。
    pub fn apply_config(self: &Rc<Self>, config: RuntimeConfig) {
        self.apply_config_inner(ApplyMode::FullReload, config, Vec::new());
    }

    pub(crate) fn apply_prepared(self: &Rc<Self>, prepared: crate::modules::PreparedConfig) {
        let (config, plans) = prepared.into_parts();
        self.apply_config_inner(ApplyMode::FullReload, config, plans);
    }

    pub(crate) fn apply_partial(self: &Rc<Self>, config: RuntimeConfig) {
        self.apply_config_inner(ApplyMode::PartialUpdate, config, Vec::new());
    }

    pub(crate) fn apply_prepared_partial(
        self: &Rc<Self>,
        prepared: crate::modules::PreparedConfig,
    ) {
        let (config, plans) = prepared.into_parts();
        self.apply_config_inner(ApplyMode::PartialUpdate, config, plans);
    }

    fn load_or_reuse_mitm_ca(
        &self,
        warnings: &mut Vec<String>,
    ) -> Option<Rc<RefCell<oryn_mitm::CertificateAuthority>>> {
        let dir = self.data_dir()?.parent()?.join("mitm");
        let path = dir.join("identity.json");
        let meta = std::fs::metadata(&path)
            .ok()
            .map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len()));
        if let (Some(cur_meta), Some((cached_path, Some(cached_meta), ca))) =
            (meta, self.mitm_ca_cache.borrow().as_ref())
        {
            if *cached_path == path && *cached_meta == cur_meta {
                return Some(ca.clone());
            }
        }
        let load = || -> std::io::Result<oryn_mitm::CertificateAuthority> {
            use base64::Engine as _;
            let file = std::fs::read(&path)?;
            let identity: serde_json::Value = serde_json::from_slice(&file)?;
            let decode = |name: &str| {
                base64::engine::general_purpose::STANDARD
                    .decode(identity[name].as_str().unwrap_or(""))
                    .map_err(std::io::Error::other)
            };
            oryn_mitm::CertificateAuthority::from_material(oryn_mitm::CaMaterial {
                certificate_der: decode("certificate_der")?,
                private_key_der: decode("private_key_der")?,
            })
        };
        match load() {
            Ok(c) => {
                let ca = Rc::new(RefCell::new(c));
                *self.mitm_ca_cache.borrow_mut() = Some((path, meta, ca.clone()));
                Some(ca)
            }
            Err(e) => {
                *self.mitm_ca_cache.borrow_mut() = None;
                warnings.push(format!("MITM CA unavailable: {e}"));
                None
            }
        }
    }

    fn apply_config_inner(
        self: &Rc<Self>,
        mode: ApplyMode,
        config: RuntimeConfig,
        plans: Vec<(usize, HttpPlan)>,
    ) {
        if let Err(error) = self.validate_virtual_interface(&config) {
            warn!("configuration retained: {error}");
            return;
        }
        let is_reload = self.initialized.get();
        let old = self.state();
        if mode == ApplyMode::FullReload && is_reload {
            self.iperf.cancel("configuration reloaded");
            self.network_test.cancel("configuration reloaded");
            self.selftest.cancel("configuration reloaded");
            self.script_host.clear_runtime_warnings();
        }
        let base_config = config.clone();
        let mut config = config;
        if let Some(settings) = self.maxmind.borrow().as_ref() {
            config.geoip.url.clone_from(&settings.geoip_db_url);
            config.geoip.asn_url = Some(settings.asn_db_url.clone());
            config.geoip.auto_update = true;
            config.geoip.interval_hours = 168;
        }
        if let Some(url) = self.options.proxy_test_url.as_deref() {
            // 健康检查 URL 是运行时偏好，不写回订阅文件；所有需要健康检查的组
            // 统一使用本机设置中的 URL。
            for outbound in &mut config.outbounds {
                if let OutboundKind::Group(group) = &mut outbound.kind {
                    group.health.url = url.to_string();
                }
            }
        }

        let can_reuse_plan =
            is_reload && plans.is_empty() && base_config.modules == old.base_config.modules;
        let (http_plan, compiled_modules_enabled, module_compile_warnings) = if can_reuse_plan {
            for (spec, &enabled) in config
                .modules
                .iter_mut()
                .zip(&old.compiled_modules_enabled)
            {
                spec.enabled = enabled;
            }
            config
                .warnings
                .extend(old.module_compile_warnings.iter().cloned());
            (
                old.http_plan.clone(),
                old.compiled_modules_enabled.clone(),
                old.module_compile_warnings.clone(),
            )
        } else {
            let mut module_compile_warnings = Vec::new();
            for spec in &mut config.modules {
                let Some(ir) = spec.inline.as_ref().filter(|_| spec.enabled) else {
                    continue;
                };
                match crate::modules::allowed(ir, self.system_version()) {
                    Ok(warnings) => {
                        let label = spec.url.as_deref().unwrap_or("inline");
                        for w in warnings {
                            let msg = format!("module {label}: {w}");
                            module_compile_warnings.push(msg.clone());
                            config.warnings.push(msg);
                        }
                    }
                    Err(reason) => {
                        spec.enabled = false;
                        let msg = format!(
                            "module {} disabled: {reason}",
                            spec.url.as_deref().unwrap_or("inline")
                        );
                        module_compile_warnings.push(msg.clone());
                        config.warnings.push(msg);
                    }
                }
            }
            let limits = self.options.resource_profile.limits();
            let inspect_limits = limits.inspect_limits();
            let mut plans = plans.into_iter().peekable();
            let mut plan = HttpPlan::with_max_body(limits.http_max_body);
            for (index, spec) in config
                .modules
                .iter_mut()
                .enumerate()
                .filter(|(_, m)| m.enabled)
            {
                if let Some(ir) = &spec.inline {
                    // allowed 已执行；只有 prepare 接受的同一份 spec 才能携带 Plan。
                    while plans.peek().is_some_and(|(i, _)| *i < index) {
                        plans.next(); // allowed 禁用的模块不复用，也不保留其 Plan。
                    }
                    let cached = if plans.peek().is_some_and(|(i, _)| *i == index) {
                        plans.next().map(|(_, plan)| plan)
                    } else {
                        None
                    };
                    let compiled = match cached {
                        Some(plan) => Ok(plan),
                        None => oryn_http_inspect::compile_module_with_limits(
                            ir,
                            &spec.arguments.iter().cloned().collect(),
                            &spec.resources,
                            &spec.policy_map,
                            inspect_limits,
                        ),
                    };
                    match compiled {
                        Ok(p) => {
                            let env = Arc::new(spec.env.clone());
                            plan.request.extend(p.request);
                            plan.response.extend(p.response);
                            plan.scripts.extend(p.scripts.into_iter().map(|mut s| {
                                s.env = Arc::clone(&env);
                                s
                            }));
                            module_compile_warnings.extend(p.warnings.iter().cloned());
                            config.warnings.extend(p.warnings);
                        }
                        Err(e) => {
                            spec.enabled = false;
                            let msg = format!("module disabled; compile failed: {e}");
                            module_compile_warnings.push(msg.clone());
                            config.warnings.push(msg);
                        }
                    }
                }
            }
            drop(plans);
            if plan.scripts.len() > limits.max_scripts {
                plan.scripts.truncate(limits.max_scripts);
                let msg = format!("script count exceeds {}", limits.max_scripts);
                module_compile_warnings.push(msg.clone());
                config.warnings.push(msg);
            }
            plan.share_jq_programs();
            let compiled_modules_enabled = config.modules.iter().map(|m| m.enabled).collect();
            (
                Rc::new(plan),
                compiled_modules_enabled,
                module_compile_warnings,
            )
        };
        if let Err(e) = oryn_config::merge_module_patches(&mut config) {
            config.warnings.push(e.to_string());
        }
        // 模块声明了 MITM 主机却没开 MITM 时，针对 https:// 的重写与脚本不会生效，提示用户。
        if !config.mitm.enabled {
            let mut needs = vec![];
            for spec in config.modules.iter().filter(|m| m.enabled) {
                let declares = spec.inline.as_ref().is_some_and(|ir| {
                    ir.mitm.iter().any(|l| {
                        l.split_once('=').is_some_and(|(k, v)| {
                            k.trim().eq_ignore_ascii_case("hostname")
                                && v.split(',').any(|h| {
                                    !h.trim()
                                        .trim_start_matches("%INSERT%")
                                        .trim_start_matches("%APPEND%")
                                        .trim()
                                        .is_empty()
                                })
                        })
                    })
                });
                if declares {
                    needs.push(format!(
                        "module {} declares MITM hostnames but MITM is disabled; its HTTPS rewrites and scripts will not run",
                        spec.url.as_deref().unwrap_or("inline")
                    ));
                }
            }
            config.warnings.extend(needs);
        }
        let mitm_ca = if config.mitm.enabled {
            self.load_or_reuse_mitm_ca(&mut config.warnings)
        } else {
            None
        };
        for w in &config.warnings {
            warn!("config: {w}");
        }
        let prev_rules = is_reload.then(|| (&old.config, old.rule_sets.as_ref()));
        let store_build = providers::build_store(&config, prev_rules, self.data_dir());
        let store = store_build.store;
        let providers_use_geo = store_build.uses_geoip;
        let dns_rulesets_changed = store_build.dns_rulesets_changed;
        let url_changed_rule_indices = store_build.url_changed_indices;

        if !is_reload {
            self.dns
                .apply(config.dns.clone(), config.hosts.clone(), store.clone());
        } else {
            self.dns.apply_incremental(
                config.dns.clone(),
                config.hosts.clone(),
                store.clone(),
                dns_rulesets_changed,
            );
        }

        let health = self.health.clone();
        let build = BuildContext {
            proxy_resolver: Arc::new(ProxyServerResolver(self.dns.clone())),
            direct_resolver: Arc::new(DirectTargetResolver(self.dns.clone())),
            health: health.clone(),
            selections: self.selections.borrow().clone(),
            mieru_sessions: self.options.resource_profile.limits().mieru_sessions,
        };
        let prev_outbounds = is_reload.then(|| PreviousOutbounds {
            specs: &old.config.outbounds,
            outbounds: &old.routing.outbounds,
        });
        let outbounds =
            build_outbounds_reusing(&config, &build, self.data_dir(), prev_outbounds).outbounds;
        if is_reload {
            let live_names: HashSet<&str> =
                config.outbounds.iter().map(|o| o.name.as_str()).collect();
            self.health.retain_names(&live_names);
        }
        let sessions = outbounds
            .iter()
            .filter_map(|outbound| outbound.session_control())
            .collect();
        let router =
            Router::new(&config, store.clone(), self.geoip.clone()).with_asn(self.asn.clone());
        router.set_mode(self.mode_override.get().unwrap_or(config.mode));
        router.set_ipv6_support(self.dns.target_ipv6_supported());
        let routing = Arc::new(Routing { router, outbounds });
        self.dns.set_routing(Arc::downgrade(&routing));
        let needs_geo = providers_use_geo || geo::rules_need_geoip(&config);
        let scripts = self.script_host.clone();
        scripts.set_network(routing.clone(), self.dns.clone());

        let cancel_country = is_reload && old.config.geoip.url != config.geoip.url;
        let cancel_asn = is_reload && old.config.geoip.asn_url != config.geoip.asn_url;
        let mut changed_proxy_indices = Vec::new();
        if is_reload {
            let old_proxy_urls: HashMap<&str, &str> = old
                .config
                .proxy_providers
                .iter()
                .filter_map(|p| match &p.source {
                    ProxyProviderSource::Http { url, .. } => Some((p.name.as_str(), url.as_str())),
                    _ => None,
                })
                .collect();
            for (idx, p) in config.proxy_providers.iter().enumerate() {
                if let ProxyProviderSource::Http { url, .. } = &p.source {
                    if old_proxy_urls
                        .get(p.name.as_str())
                        .is_some_and(|old_u| *old_u != url.as_str())
                    {
                        changed_proxy_indices.push(idx);
                    }
                }
            }
        }
        let plan_changed = is_reload && !Rc::ptr_eq(&old.http_plan, &http_plan);

        let state = Rc::new(RuntimeState {
            base_config,
            aux_cancel: tokio::sync::watch::channel(false).0,
            compiled_modules_enabled,
            module_compile_warnings,
            config,
            routing,
            rule_sets: store,
            health,
            sessions,
            http_plan,
            scripts,
            mitm_ca,
            http_transactions: self.http_transactions.clone(),
            http_bodies: self.http_bodies.clone(),
            geo_started: Cell::new(false),
            needs_geo,
            tasks: RefCell::new(Vec::new()),
        });
        drop(old);
        let old = self.state.replace(state.clone());
        self.initialized.set(true);
        if mode == ApplyMode::FullReload {
            self.config_generation
                .set(self.config_generation.get().wrapping_add(1));
        }
        self.resource_revision
            .set(self.resource_revision.get().wrapping_add(1));
        if plan_changed {
            let _ = old.aux_cancel.send_replace(true);
        }
        // 只取消旧代维护任务，不关闭仍持旧路由的正常Flow，也不取消当前提交者pending_reload。
        old.cancel_tasks();
        if cancel_country {
            geo::cancel_in_flight(self, geo::Kind::Country);
        }
        if cancel_asn {
            geo::cancel_in_flight(self, geo::Kind::Asn);
        }
        crate::modules::schedule(self, &state);
        crate::scripts::schedule(&state);
        providers::spawn_updates_with_changed(self, &state, &url_changed_rule_indices);
        crate::proxy_providers::spawn_updates_with_changed(self, &state, &changed_proxy_indices);
        health::spawn_checks(&state);
        health::spawn_provider_checks(&state);
        public_ip::spawn(self, &state);
        if state.needs_geo || state.config.geoip.auto_update || state.config.geoip.asn_url.is_some()
        {
            geo::ensure(self, &state);
        }
    }

    pub fn set_mode(&self, mode: Mode) {
        self.mode_override.set(Some(mode));
        self.state().router().set_mode(mode);
    }
}

/// 构造期间的占位状态（立即被 `apply_config` 替换）。
fn empty_state(config: &RuntimeConfig, health: &Arc<HealthStore>) -> RuntimeState {
    // 占位状态只供首次 apply_config 校验接口计划及继承空 health/session 使用；
    // 不为尚未生效的用户规则构造 Router，也不复制整份节点/规则两次。
    let mut placeholder =
        oryn_config::parse_config("rules: ['MATCH,REJECT']").expect("static placeholder config");
    placeholder.dns.fake_ip_range = config.dns.fake_ip_range;
    let store = Arc::new(RuleSetStore::new(&[]));
    let router = Router::new(&placeholder, store.clone(), Arc::new(GeoIp::default()));
    RuntimeState {
        base_config: placeholder.clone(),
        aux_cancel: tokio::sync::watch::channel(false).0,
        compiled_modules_enabled: Vec::new(),
        module_compile_warnings: Vec::new(),
        config: placeholder,
        routing: Arc::new(Routing {
            router,
            outbounds: Vec::new(),
        }),
        rule_sets: store,
        health: health.clone(),
        sessions: Vec::new(),
        http_plan: Rc::new(HttpPlan::default()),
        scripts: Arc::new(crate::scripts::ScriptHost::new(None)),
        mitm_ca: None,
        http_transactions: Some(Arc::new(tokio::sync::Semaphore::new(32))),
        http_bodies: Arc::new(tokio::sync::Semaphore::new(
            crate::http::body_budget_pages(
                crate::options::ResourceProfile::default()
                    .limits()
                    .http_body_budget,
            ),
        )),
        geo_started: Cell::new(true),
        needs_geo: false,
        tasks: RefCell::new(Vec::new()),
    }
}
