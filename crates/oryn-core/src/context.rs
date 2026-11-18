//! 事件循环线程内共享的状态。

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use log::warn;
use oryn_config::{Mode, OutboundKind, RuntimeConfig};
use oryn_dns::{DirectTargetResolver, DnsEngine, ProxyServerResolver, Routing};
use oryn_http_inspect::Plan as HttpPlan;
use oryn_netstack::LwipStack;
use oryn_outbound::{build_outbounds_with_data_dir, BuildContext, HealthStore, SessionControl};
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
    pub inspection_cancel: tokio::sync::watch::Sender<bool>,
    pub config: RuntimeConfig,
    pub routing: Arc<Routing>,
    pub rule_sets: Arc<RuleSetStore>,
    pub health: Arc<HealthStore>,
    pub sessions: Vec<Arc<dyn SessionControl>>,
    pub http_plan: Rc<HttpPlan>,
    pub scripts: Arc<crate::scripts::ScriptHost>,
    pub mitm_ca: RefCell<Option<oryn_mitm::CertificateAuthority>>,
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
    pub database_download: tokio::sync::Mutex<()>,
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

impl EngineCtx {
    pub fn desktop_reload_compile(&self) -> bool {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        { self.options.resource_profile == crate::options::ResourceProfile::DesktopHigh }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        { false }
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
                if let Some(oldest) = map.iter().min_by_key(|(_, at)| **at).map(|(k, _)| k.clone()) {
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
        dns.set_real_ip_domains(&options.real_ip_domains).expect("validated real IP domains");
        dns.set_data_dir(options.data_dir.as_deref());
        dns.set_network(options.network.to_info());
        options.network.apply_interface();
        let limits = options.resource_profile.limits();
        log::info!("engine resource profile {:?}: {:?}", options.resource_profile, limits);
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
            script_host: Arc::new(crate::scripts::ScriptHost::new(options.data_dir.as_deref())),
            http_transactions: limits.http_transactions.map(tokio::sync::Semaphore::new).map(Arc::new),
            http_bodies: Arc::new(tokio::sync::Semaphore::new(limits.http_bodies)),
            http_connections: limits.http_connections.map(tokio::sync::Semaphore::new).map(Arc::new),
            http_upstream_establish: Arc::new(tokio::sync::Semaphore::new(limits.http_upstream_establish)),
            mitm_bypass: RefCell::new(HashMap::new()),
            stack,
            dns,
            geoip: Arc::new(GeoIp::default()),
            asn: Arc::new(GeoIp::default()),
            databases: Default::default(),
            database_download: tokio::sync::Mutex::new(()),
            maxmind: RefCell::new(options.maxmind.clone()),
            state: RefCell::new(Rc::new(empty_state(&config))),
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
        builtin || self.options.dns_hijack().iter().any(|h| h.matches(tcp, ip, port))
    }

    pub fn validate_virtual_interface(&self, config: &RuntimeConfig) -> Result<(), String> {
        let next = self.options.virtual_interface.compile(config.dns.fake_ip_range, self.options.dns_address)?;
        let current = self.options.virtual_interface.compile(self.state().config.dns.fake_ip_range, self.options.dns_address)?;
        if next != current { return Err("virtual interface routes changed; reconnect to apply this configuration".into()); }
        Ok(())
    }

    /// 加载一份新配置：构建出站、路由、DNS，并启动后台任务。
    pub fn apply_config(self: &Rc<Self>, config: RuntimeConfig) {
        self.apply_config_with_plans(config, Vec::new());
    }

    pub(crate) fn apply_prepared(self: &Rc<Self>, prepared: crate::modules::PreparedConfig) {
        let (config, plans) = prepared.into_parts();
        self.apply_config_with_plans(config, plans);
    }

    fn apply_config_with_plans(
        self: &Rc<Self>,
        config: RuntimeConfig,
        plans: Vec<(usize, HttpPlan)>,
    ) {
        if let Err(error) = self.validate_virtual_interface(&config) {
            warn!("configuration retained: {error}");
            return;
        }
        self.iperf.cancel("configuration reloaded");
        self.network_test.cancel("configuration reloaded");
        self.selftest.cancel("configuration reloaded");
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
        for spec in &mut config.modules {
            let Some(ir) = spec.inline.as_ref().filter(|_| spec.enabled) else {
                continue;
            };
            if let Err(reason) = crate::modules::allowed(ir, self.system_version()) {
                spec.enabled = false;
                config.warnings.push(format!(
                    "module {} disabled: {reason}",
                    spec.url.as_deref().unwrap_or("inline")
                ));
            }
        }
        let mut plans = plans.into_iter().peekable();
        let mut plan = HttpPlan::default();
        for (index, spec) in config.modules.iter_mut().enumerate().filter(|(_, m)| m.enabled) {
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
                    None => oryn_http_inspect::compile_module_with_policies(
                        ir,
                        &spec.arguments.iter().cloned().collect(),
                        &spec.resources,
                        &spec.policy_map,
                    ),
                };
                match compiled {
                    Ok(p) => {
                        plan.request.extend(p.request);
                        plan.response.extend(p.response);
                        plan.scripts.extend(p.scripts.into_iter().map(|mut s| {
                            s.env = spec.env.clone();
                            s
                        }));
                        config.warnings.extend(p.warnings);
                    }
                    Err(e) => {
                        spec.enabled = false;
                        config
                            .warnings
                            .push(format!("module disabled; compile failed: {e}"));
                    }
                }
            }
        }
        drop(plans);
        if plan.scripts.len() > 64 {
            plan.scripts.truncate(64);
            config.warnings.push("script count exceeds 64".into());
        }
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
        plan.share_jq_programs();
        let http_plan = Rc::new(plan);
        let mitm_ca = if config.mitm.enabled {
            self.data_dir().and_then(|p| {
                let dir = p.parent()?.join("mitm");
                let load = || -> std::io::Result<oryn_mitm::CertificateAuthority> {
                    use base64::Engine as _;
                    let file = std::fs::read(dir.join("identity.json"))?;
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
                    Ok(c) => Some(c),
                    Err(e) => {
                        config.warnings.push(format!("MITM CA unavailable: {e}"));
                        None
                    }
                }
            })
        } else {
            None
        };
        for w in &config.warnings {
            warn!("config: {w}");
        }
        let store = Arc::new(RuleSetStore::new(&config.providers));
        let providers_use_geo = providers::load_local(&config, &store, self.data_dir());
        self.dns
            .apply(config.dns.clone(), config.hosts.clone(), store.clone());
        let health = Arc::new(HealthStore::inherit_smart(&self.state().health));
        let build = BuildContext {
            proxy_resolver: Arc::new(ProxyServerResolver(self.dns.clone())),
            direct_resolver: Arc::new(DirectTargetResolver(self.dns.clone())),
            health: health.clone(),
            selections: self.selections.borrow().clone(),
        };
        // 配置切换前终止旧身份的数据面，不让旧 Flow 跨身份继续运行。
        for session in &self.state().sessions {
            session.on_config_replaced();
        }
        let outbounds = build_outbounds_with_data_dir(&config, &build, self.data_dir());
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
        let state = Rc::new(RuntimeState {
            base_config,
            inspection_cancel: tokio::sync::watch::channel(false).0,
            config,
            routing,
            rule_sets: store,
            health,
            sessions,
            http_plan,
            scripts,
            mitm_ca: RefCell::new(mitm_ca),
            http_transactions: self.http_transactions.clone(),
            http_bodies: self.http_bodies.clone(),
            geo_started: Cell::new(false),
            needs_geo,
            tasks: RefCell::new(Vec::new()),
        });
        self.script_host.cancel();
        self.state().inspection_cancel.send_replace(true);
        let old = self.state.replace(state.clone());
        // 只取消旧代维护任务，不关闭仍持旧路由的正常Flow，也不取消当前提交者pending_reload。
        old.cancel_tasks();
        crate::modules::schedule(self, &state);
        crate::scripts::schedule(&state);
        providers::spawn_updates(self, &state);
        crate::proxy_providers::spawn_updates(self, &state);
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
fn empty_state(config: &RuntimeConfig) -> RuntimeState {
    // 占位状态只供首次 apply_config 校验接口计划及继承空 health/session 使用；
    // 不为尚未生效的用户规则构造 Router，也不复制整份节点/规则两次。
    let mut placeholder = oryn_config::parse_config("rules: ['MATCH,REJECT']")
        .expect("static placeholder config");
    placeholder.dns.fake_ip_range = config.dns.fake_ip_range;
    let store = Arc::new(RuleSetStore::new(&[]));
    let router = Router::new(&placeholder, store.clone(), Arc::new(GeoIp::default()));
    RuntimeState {
        base_config: placeholder.clone(),
        inspection_cancel: tokio::sync::watch::channel(false).0,
        config: placeholder,
        routing: Arc::new(Routing {
            router,
            outbounds: Vec::new(),
        }),
        rule_sets: store,
        health: Arc::new(HealthStore::default()),
        sessions: Vec::new(),
        http_plan: Rc::new(HttpPlan::default()),
        scripts: Arc::new(crate::scripts::ScriptHost::new(None)),
        mitm_ca: RefCell::new(None),
        http_transactions: Some(Arc::new(tokio::sync::Semaphore::new(32))),
        http_bodies: Arc::new(tokio::sync::Semaphore::new(2)),
        geo_started: Cell::new(true),
        needs_geo: false,
        tasks: RefCell::new(Vec::new()),
    }
}
