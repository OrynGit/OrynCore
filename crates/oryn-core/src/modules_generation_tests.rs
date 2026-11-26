use super::*;

fn config() -> RuntimeConfig {
    let mut config =
        crate::proxy_providers::compile("rules: ['MATCH,DIRECT']", None, None).unwrap();
    config.dns.public_ip_url = None;
    config.geoip.auto_update = false;
    config.geoip.asn_url = None;
    config
}

fn jq_config() -> RuntimeConfig {
    let mut c = config();
    c.modules = crate::proxy_providers::compile("modules:\n  - format: surge\n    inline: |\n      [Body Rewrite]\n      http-response-jq ^http://example.invalid/ '. + {prepared: true}'\nrules: ['MATCH,DIRECT']", None, None).unwrap().modules;
    c
}

#[cfg(target_os = "macos")]
fn program_released(plan: &oryn_http_inspect::Plan) -> impl Fn() -> bool + use<> {
    let weak = plan.response.iter().flat_map(|r| &r.actions).find_map(|a| match a {
        oryn_http_inspect::Action::Jq(p) => Some(Rc::downgrade(p)),
        _ => None,
    }).expect("compiled jq");
    move || weak.upgrade().is_none()
}

#[cfg(target_os = "macos")]
#[test]
fn prepared_sidecar_equivalence_bounds_allowed_and_cancel() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        fn assert_send<T: Send>() {}
        assert_send::<RuntimeConfig>();
        let ctx = EngineCtx::new(oryn_netstack::LwipStack::new(1500).unwrap(), config(),
            crate::options::EngineOptions { resource_profile: crate::options::ResourceProfile::DesktopHigh, ..Default::default() },
            std::sync::Arc::new(crate::stats::Stats::default()));
        let before = ctx.state();
        let prepared = prepare_for_apply(&ctx, jq_config()).await;
        assert_eq!(prepared.plans.len(), 1);
        assert!(Rc::ptr_eq(&before, &ctx.state()));
        let fresh = validate_with(
            &prepared.config.modules[0],
            ctx.resource_limits().max_module_resources,
            ctx.resource_limits().inspect_limits(),
        )
        .unwrap();
        assert_eq!(format!("{:?}", prepared.plans[0].1), format!("{fresh:?}"));
        let released = program_released(&prepared.plans[0].1);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::task::spawn_local(async move {
            let _owner = prepared;
            tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(released(), "cancel must release compiled program");

        let mut candidate = jq_config();
        std::sync::Arc::make_mut(candidate.modules[0].inline.as_mut().unwrap()).meta.system =
            Some("unsupported".into());
        let prepared = prepare_for_apply(&ctx, candidate.clone()).await;
        let released = program_released(&prepared.plans[0].1);
        ctx.apply_prepared(prepared);
        assert!(released());
        assert!(ctx.state().http_plan.response.is_empty());
        let warnings = ctx.state().config.warnings.clone();
        ctx.apply_config(candidate);
        assert_eq!(warnings, ctx.state().config.warnings);

        let mut candidate = jq_config();
        let spec = candidate.modules[0].clone();
        candidate.modules = vec![spec.clone(); 200];
        for m in &mut candidate.modules { m.enabled = false; }
        candidate.modules.extend(vec![spec; 257]);
        let prepared = prepare_for_apply(&ctx, candidate).await;
        assert_eq!(prepared.plans.len(), 256);
        assert_eq!(prepared.plans[0].0, 200);
        assert_eq!(prepared.plans.last().unwrap().0, 455);
        assert!(prepare_inner(&ctx, jq_config(), false).await.plans.is_empty());
    });
}

#[cfg(target_os = "macos")]
#[test]
fn prepared_script_env_and_compile_warnings_match_fresh() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let dir = std::env::current_dir().unwrap().join("../../scratchpad")
            .join(format!("prepared-script-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("modules")).unwrap();
        std::fs::write(dir.join("modules/test.js"), "$done({});").unwrap();
        let ctx = EngineCtx::new(oryn_netstack::LwipStack::new(1500).unwrap(), config(),
            crate::options::EngineOptions {
                resource_profile: crate::options::ResourceProfile::DesktopHigh,
                data_dir: Some(dir.clone()), ..Default::default()
            }, std::sync::Arc::new(crate::stats::Stats::default()));
        let mut candidate = config();
        candidate.modules = crate::proxy_providers::compile("modules:\n  - format: surge\n    inline: |\n      [Script]\n      test = type=http-request, pattern=^http://example.invalid/, script-path=test.js\n      [Body Rewrite]\n      http-response-jq ^http://example.invalid/ 'invalid syntax ???'\nrules: ['MATCH,DIRECT']", None, None).unwrap().modules;
        candidate.modules[0].env.insert("prepared_env".into(), "present".into());
        let prepared = prepare_for_apply(&ctx, candidate).await;
        assert_eq!(prepared.plans.len(), 1);
        assert_eq!(prepared.plans[0].1.scripts.len(), 1);
        assert!(prepared.plans[0].1.scripts[0].env.is_empty(), "env belongs only to apply");
        let compile_warnings = prepared.plans[0].1.warnings.clone();
        assert_eq!(compile_warnings.len(), 2, "{compile_warnings:?}");
        assert!(
            compile_warnings
                .iter()
                .any(|w| w.starts_with("module:4: rewrite skipped: jq parse error:")),
            "{compile_warnings:?}"
        );
        assert!(
            compile_warnings
                .iter()
                .any(|w| w.contains("Oryn script resource limits:")),
            "{compile_warnings:?}"
        );
        let fresh_config = prepared.config.clone();
        ctx.apply_prepared(prepared);
        assert_eq!(ctx.state().http_plan.scripts[0].env["prepared_env"], "present");
        for warning in &compile_warnings {
            assert_eq!(ctx.state().config.warnings.iter().filter(|w| *w == warning).count(), 1);
        }
        let plan = format!("{:?}", ctx.state().http_plan);
        let warnings = ctx.state().config.warnings.clone();
        ctx.apply_config(fresh_config);
        assert_eq!(plan, format!("{:?}", ctx.state().http_plan));
        assert_eq!(warnings, ctx.state().config.warnings);
        drop(ctx);
        std::fs::remove_dir_all(dir).unwrap();
    });
}

#[test]
fn prepared_failed_update_uses_final_policy_not_old_plan() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let mut old = jq_config();
        old.modules[0].url = Some("missing.plugin".into());
        std::sync::Arc::make_mut(old.modules[0].inline.as_mut().unwrap())
            .rules
            .push("URL-REGEX,^http://example.invalid/,old".into());
        let ctx = EngineCtx::new(oryn_netstack::LwipStack::new(1500).unwrap(), old.clone(),
            Default::default(), std::sync::Arc::new(crate::stats::Stats::default()));
        let mut candidate = old;
        candidate.modules[0].policy_map.push(("old".into(), "REJECT".into()));
        candidate.modules[0].env.insert("environment".into(), "new".into());
        let prepared = prepare_inner(&ctx, candidate, true).await;
        assert!(prepared.plans.is_empty(), "fallback cannot reuse old policy compilation");
        assert!(prepared.config.modules[0].enabled);
        let fresh_config = prepared.config.clone();
        ctx.apply_prepared(prepared);
        assert_eq!(ctx.state().http_plan.request.len(), 1, "new policy must compile rejection");
        assert_eq!(ctx.state().config.modules[0].env["environment"], "new");
        let actual = format!("{:?}", ctx.state().http_plan);
        let warnings = ctx.state().config.warnings.clone();
        ctx.apply_config(fresh_config);
        assert_eq!(actual, format!("{:?}", ctx.state().http_plan));
        assert_eq!(warnings, ctx.state().config.warnings);
    });
}

#[test]
fn inline_prepare_allows_local_observer_without_changing_modules() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let ctx = EngineCtx::new(oryn_netstack::LwipStack::new(1500).unwrap(), config(),
            Default::default(), std::sync::Arc::new(crate::stats::Stats::default()));
        let mut yaml = String::from("rules: ['MATCH,DIRECT']\nmodules:\n");
        for i in 0..20 {
            yaml.push_str(&format!("  - format: surge\n    inline: |\n      #!name=fairness-{i}\n      [Body Rewrite]\n      http-response-jq ^http://example\\.invalid/m{i}$ '. + {{module: {i}}}'\n"));
        }
        let candidate = crate::proxy_providers::compile(&yaml, None, None).unwrap();
        assert_eq!(candidate.modules.len(), 20);
        assert!(candidate.modules.iter().all(|m| m.enabled));
        assert!(candidate.warnings.is_empty());
        let expected = format!("{:?}", candidate.modules);
        let previous = ctx.state();
        let active = Rc::new(std::cell::Cell::new(false));
        let observed = Rc::new(std::cell::Cell::new(0usize));
        let observer = {
            let active = active.clone();
            let observed = observed.clone();
            tokio::task::spawn_local(async move {
                // 此任务只在 prepare 已开始且未完成时计数，无计时阈值。
                while active.get() {
                    observed.set(observed.get() + 1);
                    tokio::task::yield_now().await;
                }
            })
        };
        active.set(true);
        let prepared = prepare(&ctx, candidate).await;
        active.set(false);
        observer.await.unwrap();
        assert!(observed.get() > 0, "prepare monopolized the local executor");
        assert_eq!(format!("{:?}", prepared.modules), expected);
        assert!(prepared.warnings.is_empty());
        assert!(Rc::ptr_eq(&previous, &ctx.state()), "prepare must not publish state");
    });
}

#[test]
fn replacing_state_cancels_maintenance_even_when_old_flow_holds_state() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let ctx = EngineCtx::new(oryn_netstack::LwipStack::new(1500).unwrap(), config(),
            Default::default(), std::sync::Arc::new(crate::stats::Stats::default()));
        let old = ctx.state();
        let weak = Rc::downgrade(&old);
        let held = old.clone();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (released, done) = tokio::sync::oneshot::channel::<()>();
        // 与provider等维护任务相同：future持有st跨await，Drop不能先来取消自身。
        old.spawn(async move {
            let _held = held;
            let _release = released;
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started.await.unwrap();
        ctx.apply_config(config());
        tokio::time::timeout(std::time::Duration::from_secs(1), done).await
            .expect("old maintenance still holds state after replacement").unwrap_err();
        assert!(weak.upgrade().is_some(), "old flow may still retain immutable state");
        assert_eq!(old.config.rules.len(), 1);
        drop(old);
        assert!(weak.upgrade().is_none(), "maintenance must not keep old state alive");
    });
}

#[test]
fn timer_refresh_respects_runtime_generation() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(tokio::task::LocalSet::new().run_until(async {
        let ctx = EngineCtx::new(
            oryn_netstack::LwipStack::new(1500).unwrap(),
            config(),
            Default::default(),
            std::sync::Arc::new(crate::stats::Stats::default()),
        );
        // 模拟旧 flow 持有旧 state：Weak 仍能 upgrade，但已不是当前配置。
        let old = ctx.state();
        ctx.apply_config(config());
        let current = ctx.state();
        assert!(ctx.pending_reload.borrow().is_none());
        refresh(&ctx, old);
        tokio::task::yield_now().await;
        assert!(
            Rc::ptr_eq(&current, &ctx.state()),
            "stale timer replaced current state"
        );
        assert!(ctx.pending_reload.borrow().is_none());

        // 唤醒时仍是当前代，但执行 prepare 前发生一次切换。
        refresh(&ctx, current);
        ctx.apply_config(config());
        let current = ctx.state();
        let pending = ctx.pending_reload.borrow_mut().take().unwrap();
        pending.await.unwrap();
        assert!(
            Rc::ptr_eq(&current, &ctx.state()),
            "queued refresh replaced newer state"
        );

        // 当前代正常刷新仍然发布。
        refresh(&ctx, current.clone());
        let pending = ctx.pending_reload.borrow_mut().take().unwrap();
        pending.await.unwrap();
        assert!(!Rc::ptr_eq(&current, &ctx.state()));
    }));
}

/// 启动时只读模块缓存：过期缓存直接使用、缺缓存的模块暂停用，都不联网，并要求启动后补刷新。
#[test]
fn startup_prepare_uses_stale_cache_and_defers_missing_without_network() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("oryn-startup-modules-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cached_url = "https://cached.invalid/a.sgmodule";
    let missing_url = "https://missing.invalid/b.sgmodule";
    let downloads = dir.join("modules/.downloads");
    std::fs::create_dir_all(&downloads).unwrap();
    let file = downloads.join(format!("{:x}", Sha256::digest(cached_url.as_bytes())));
    std::fs::write(&file, "#!name=cached\n[Rule]\nDOMAIN,cached.example,REJECT\n").unwrap();
    // 远超默认更新间隔，在线准备会尝试下载
    std::fs::File::options().write(true).open(&file).unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(30 * 86400)).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let ctx = EngineCtx::new(oryn_netstack::LwipStack::new(1500).unwrap(), config(),
            crate::options::EngineOptions { data_dir: Some(dir.clone()), ..Default::default() },
            std::sync::Arc::new(crate::stats::Stats::default()));
        let yaml = format!("rules: ['MATCH,DIRECT']\nmodules:\n  - url: {cached_url}\n  - url: {missing_url}\n");
        let candidate = crate::proxy_providers::compile(&yaml, None, None).unwrap();
        let started = std::time::Instant::now();
        let (prepared, deferred) = prepare_for_startup(&ctx, candidate).await;
        assert!(started.elapsed() < Duration::from_secs(2), "startup prepare must not wait on network");
        assert!(deferred);
        let modules = &prepared.config.modules;
        assert!(modules[0].enabled && modules[0].inline.is_some(), "stale cache must be used");
        assert!(!modules[1].enabled, "uncached module waits for the post-start refresh");
        assert!(prepared.config.warnings.iter().all(|w| !w.contains("missing.invalid")), "{:?}", prepared.config.warnings);
        // 离线启动不写已验证快照
        assert!(!dir.join("modules/.validated").exists() || std::fs::read_dir(dir.join("modules/.validated")).unwrap().next().is_none());
    });
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_external_resources_are_deduplicated_across_modules() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let dir = std::env::temp_dir().join(format!("oryn-dedup-modules-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let url = "https://dedup.invalid/shared.js";
        let downloads = dir.join("modules/.downloads");
        std::fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join(format!("{:x}", Sha256::digest(url.as_bytes())));
        // 每份 ~3 MiB；Constrained 下限为 16 MiB，若不去重 6 个模块合计 >18 MiB 会拒绝第 6 个。
        let mut script = b"$done({});//".to_vec();
        script.resize(3 * 1024 * 1024, b'a');
        std::fs::write(&file, &script).unwrap();
        let ctx = EngineCtx::new(
            oryn_netstack::LwipStack::new(1500).unwrap(),
            config(),
            crate::options::EngineOptions {
                resource_profile: crate::options::ResourceProfile::Constrained,
                data_dir: Some(dir.clone()),
                ..Default::default()
            },
            std::sync::Arc::new(crate::stats::Stats::default()),
        );
        let mut yaml = String::from("rules: ['MATCH,DIRECT']\nmodules:\n");
        for i in 0..6 {
            yaml.push_str(&format!(
                "  - format: surge\n    inline: |\n      #!name=shared-{i}\n      [Script]\n      s-{i} = type=http-request, pattern=^http://dedup\\.invalid/{i}$, script-path={url}\n"
            ));
        }
        let candidate = crate::proxy_providers::compile(&yaml, None, None).unwrap();
        let prepared = prepare_for_apply(&ctx, candidate).await;
        assert!(prepared.config.modules.iter().all(|m| m.enabled), "{:?}", prepared.config.warnings);
        let first_ptr = std::sync::Arc::as_ptr(&prepared.config.modules[0].resources[url]);
        for m in &prepared.config.modules {
            assert_eq!(std::sync::Arc::as_ptr(&m.resources[url]), first_ptr);
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
}
