use super::*;

static GATE: std::sync::Mutex<Option<(tokio::sync::oneshot::Sender<()>, std_mpsc::Receiver<()>)>> = std::sync::Mutex::new(None);

pub(super) fn barrier() {
    let gate = GATE.lock().unwrap().take();
    if let Some((entered, release)) = gate {
        let _ = entered.send(());
        release.recv().unwrap();
    }
}

#[cfg(target_os = "macos")]
#[test]
fn desktop_compile_busy_error_late_and_cancel() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let mut local = tokio::task::LocalSet::new();
    let ctx = local.block_on(&rt, async {
        let mut config = crate::proxy_providers::compile("rules: ['MATCH,DIRECT']", None, None).unwrap();
        config.dns.public_ip_url = None;
        config.geoip.auto_update = false;
        config.geoip.asn_url = None;
        EngineCtx::new(LwipStack::new(1500).unwrap(), config, EngineOptions {
            resource_profile: crate::options::ResourceProfile::DesktopHigh,
            ..Default::default()
        }, Arc::new(Stats::default()))
    });
    let request = |config: &str| json!({"cmd":"reload", "config":config, "mode":"global", "selections":{"test":"new"}});
    let gate = || {
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, wait) = std_mpsc::channel();
        *GATE.lock().unwrap() = Some((entered, wait));
        (started, release)
    };
    for (text, success) in [("[invalid", false), ("rules: ['MATCH,DIRECT']", true)] {
        let (started, release) = gate();
        local.block_on(&rt, async {
            let old_source = ctx.config_source.borrow().as_ref().map(|s| s.text.clone());
            let old_mode = ctx.mode_override.get();
            let (tx, rx) = std_mpsc::sync_channel(1);
            dispatch_command(&ctx, request(text), tx);
            started.await.unwrap();
            assert!(ctx.reload_compiling.get());
            let (tx, stats) = std_mpsc::sync_channel(1);
            dispatch_command(&ctx, json!({"cmd":"stats"}), tx);
            assert!(stats.try_recv().unwrap()["error"].is_null());
            let (tx, busy) = std_mpsc::sync_channel(1);
            dispatch_command(&ctx, request(text), tx);
            assert!(busy.try_recv().unwrap()["error"].as_str().unwrap().contains("busy"));
            crate::proxy_providers::schedule_reload(&ctx);
            crate::modules::refresh(&ctx, ctx.state());
            assert!(ctx.reload_provider_dirty.get());
            assert!(ctx.reload_modules_dirty.get());
            let (tx, settings) = std_mpsc::sync_channel(1);
            dispatch_command(&ctx, json!({"cmd":"apply_settings"}), tx);
            assert_eq!(settings.try_recv().unwrap()["error"], "engine is busy");
            if success {
                let (tx, mode) = std_mpsc::sync_channel(1);
                dispatch_command(&ctx, json!({"cmd":"set_mode", "mode":"direct"}), tx);
                assert_eq!(mode.try_recv().unwrap()["ok"], true);
            }
            assert_eq!(ctx.config_source.borrow().as_ref().map(|s| s.text.clone()), old_source);
            assert!(rx.try_recv().is_err());
            // 接收者取消/超时不能取消实际编译或本地提交。
            let rx = if success { drop(rx); None } else { Some(rx) };
            release.send(()).unwrap();
            while ctx.reload_compiling.get() { tokio::task::yield_now().await; }
            if let Some(rx) = rx { assert!(rx.try_recv().unwrap()["error"].is_string()); }
            assert!(!ctx.reload_provider_dirty.get());
            assert!(!ctx.reload_modules_dirty.get());
            if success {
                assert_eq!(ctx.config_source.borrow().as_ref().unwrap().text, text);
                assert_eq!(ctx.mode_override.get(), Some(Mode::Direct));
                assert!(ctx.pending_reload.borrow().is_some());
            } else {
                assert_eq!(ctx.config_source.borrow().as_ref().map(|s| s.text.clone()), old_source);
                assert_eq!(ctx.mode_override.get(), old_mode);
                assert!(ctx.selections.borrow().is_empty());
            }
        });
    }
    // 真实 select 成功后，revision 保护整个 selections 表，不只保护被修改的组。
    local.block_on(&rt, async {
        while ctx.pending_reload.borrow().as_ref().is_some_and(|p| !p.is_finished()) {
            tokio::task::yield_now().await;
        }
        let text = "proxy-groups:\n  - {name: G, type: select, proxies: [DIRECT, REJECT]}\n  - {name: H, type: select, proxies: [DIRECT, REJECT]}\nrules: ['MATCH,G']";
        ctx.apply_config(crate::proxy_providers::compile(text, None, None).unwrap());
        ctx.selections.borrow_mut().insert("H".into(), "DIRECT".into());
        let revision = ctx.selection_revision.get();
        let (started, release) = gate();
        let (tx, rx) = std_mpsc::sync_channel(1);
        dispatch_command(&ctx, json!({"cmd":"reload", "config":text,
            "selections":{"G":"DIRECT", "H":"REJECT", "stale":"DIRECT"}}), tx);
        started.await.unwrap();
        let (tx, selected) = std_mpsc::sync_channel(1);
        dispatch_command(&ctx, json!({"cmd":"select", "group":"G", "name":"REJECT"}), tx);
        assert_eq!(selected.try_recv().unwrap()["ok"], true);
        assert_ne!(ctx.selection_revision.get(), revision);
        release.send(()).unwrap();
        while ctx.reload_compiling.get() { tokio::task::yield_now().await; }
        assert_eq!(rx.try_recv().unwrap()["ok"], true);
        while ctx.pending_reload.borrow().as_ref().is_some_and(|p| !p.is_finished()) {
            tokio::task::yield_now().await;
        }
        assert_eq!(ctx.selections.borrow().get("G").unwrap(), "REJECT");
        assert_eq!(ctx.selections.borrow().get("H").unwrap(), "DIRECT");
        assert!(!ctx.selections.borrow().contains_key("stale"));
        // 恢复后续取消测试使用的 source。
        *ctx.config_source.borrow_mut() = Some(crate::proxy_providers::ConfigSource {
            text: "rules: ['MATCH,DIRECT']".into(), inspection: None,
        });
    });
    // 取消整个 LocalSet：blocking 仍持有进程令牌，结果不得发布。
    let (started, release) = gate();
    local.block_on(&rt, async {
        let (tx, _rx) = std_mpsc::sync_channel(1);
        dispatch_command(&ctx, request("rules: ['MATCH,REJECT']"), tx);
        started.await.unwrap();
    });
    drop(local);
    assert!(RELOAD_COMPILE.clone().try_acquire_owned().is_err());
    release.send(()).unwrap();
    local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let _permit = tokio::time::timeout(Duration::from_secs(3), RELOAD_COMPILE.clone().acquire_owned()).await.unwrap().unwrap();
        assert_eq!(ctx.config_source.borrow().as_ref().unwrap().text, "rules: ['MATCH,DIRECT']");
    });
}

#[cfg(target_os = "macos")]
#[test]
fn desktop_vif_failure_retains_pending_and_replays_dirty_cache() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let local = tokio::task::LocalSet::new();
    // 所有测试资源留在工作树 scratchpad，不访问网络。
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scratchpad/compile-offload-provider-test");
    std::fs::create_dir_all(&dir).unwrap();
    let cache = dir.join("sub.yaml");
    let body = |name: &str| format!("proxies:\n  - {{name: {name}, type: socks5, server: 127.0.0.1, port: 9}}\n");
    std::fs::write(&cache, body("Before")).unwrap();
    let text = "proxy-providers: {sub: {type: file, path: sub.yaml}}\nproxy-groups: [{name: G, type: select, use: [sub]}]\nrules: ['MATCH,G']";
    local.block_on(&rt, async {
        let mut config = crate::proxy_providers::compile(text, None, Some(&dir)).unwrap();
        config.dns.public_ip_url = None;
        config.geoip.auto_update = false;
        config.geoip.asn_url = None;
        let ctx = EngineCtx::new(LwipStack::new(1500).unwrap(), config, EngineOptions {
            resource_profile: crate::options::ResourceProfile::DesktopHigh,
            data_dir: Some(dir.clone()),
            ..Default::default()
        }, Arc::new(Stats::default()));
        *ctx.config_source.borrow_mut() = Some(crate::proxy_providers::ConfigSource {
            text: text.into(), inspection: None,
        });
        ctx.selections.borrow_mut().insert("G".into(), "Before".into());
        ctx.set_mode(Mode::Direct);
        let old_state = ctx.state();
        let (continue_old, old_wait) = tokio::sync::oneshot::channel();
        let (old_done, completion) = tokio::sync::oneshot::channel();
        *ctx.pending_reload.borrow_mut() = Some(tokio::task::spawn_local(async move {
            old_wait.await.unwrap();
            old_done.send(()).unwrap();
        }));
        let old_id = ctx.pending_reload.borrow().as_ref().unwrap().id();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, wait) = std_mpsc::channel();
        *GATE.lock().unwrap() = Some((entered, wait));
        let (tx, rx) = std_mpsc::sync_channel(1);
        dispatch_command(&ctx, json!({"cmd":"reload",
            "config":"dns:\n  fake-ip-range: 10.8.0.0/20\nrules: ['MATCH,REJECT']",
            "mode":"global", "selections":{"G":"Wrong"}}), tx);
        started.await.unwrap();
        // 模拟 provider 完成缓存写入后发出的 changed 事件。失败重载必须补偿旧有效 source。
        std::fs::write(&cache, body("After")).unwrap();
        crate::proxy_providers::schedule_reload(&ctx);
        release.send(()).unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(reply) = rx.try_recv() { break reply; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert_eq!(reply["requires_reconnect"], true, "{reply}");
        assert!(reply["error"].is_string());
        assert_eq!(ctx.config_source.borrow().as_ref().unwrap().text, text);
        assert_eq!(ctx.selections.borrow().get("G").unwrap(), "Before");
        assert_eq!(ctx.mode_override.get(), Some(Mode::Direct));
        assert!(Rc::ptr_eq(&old_state, &ctx.state()));
        assert_eq!(ctx.pending_reload.borrow().as_ref().unwrap().id(), old_id);
        assert!(!ctx.pending_reload.borrow().as_ref().unwrap().is_finished());
        continue_old.send(()).unwrap();
        completion.await.expect("failed reload aborted the previous valid prepare");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if !ctx.reload_compiling.get()
                    && ctx.pending_reload.borrow().as_ref().is_some_and(|p| p.is_finished()) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        let groups = handle_command(&ctx, &json!({"cmd":"groups"}));
        let group = groups["groups"].as_array().unwrap().iter()
            .find(|g| g["name"] == "G").unwrap();
        let members = group["members"].as_array().unwrap();
        assert!(members.iter().any(|m| m["name"] == "After"), "{groups}");
        assert!(!members.iter().any(|m| m["name"] == "Before"), "{groups}");
        assert_eq!(ctx.config_source.borrow().as_ref().unwrap().text, text);
    });
    std::fs::remove_file(cache).unwrap();
    std::fs::remove_dir(dir).unwrap();
}
