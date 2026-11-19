//! 创建政策、慢建立额度与跨代共享预算；不访问公网。
use crate::{context::EngineCtx, EngineOptions, ResourceProfile};
use std::sync::Arc;

#[test]
fn resource_profile_options_are_strict() {
    {
        let json = r#"{"resource_profile":"constrained"}"#;
        assert_eq!(
            EngineOptions::parse(json.as_bytes())
                .unwrap()
                .resource_profile,
            ResourceProfile::Constrained
        );
    }
    for value in [
        "null",
        "0",
        "true",
        "[]",
        "{}",
        "\"Desktop\"",
        "\"CONSTRAINED\"",
        "\"unknown\"",
        "\"\"",
    ] {
        assert!(
            EngineOptions::parse(format!(r#"{{"resource_profile":{value}}}"#).as_bytes()).is_err(),
            "{value}"
        );
    }
    let removed_desktop = EngineOptions::parse(br#"{"resource_profile":"desktop"}"#);
    let desktop_high = EngineOptions::parse(br#"{"resource_profile":"desktop_high"}"#);
    let mobile_plus = EngineOptions::parse(br#"{"resource_profile":"mobile_plus"}"#);
    #[cfg(target_os = "macos")]
    {
        assert!(
            removed_desktop.is_err(),
            "the removed desktop profile must not be accepted"
        );
        assert_eq!(
            desktop_high.unwrap().resource_profile,
            ResourceProfile::DesktopHigh
        );
        assert!(mobile_plus.is_err());
    }
    #[cfg(target_os = "ios")]
    {
        assert!(removed_desktop.is_err());
        assert!(desktop_high.is_err());
        assert_eq!(
            mobile_plus.unwrap().resource_profile,
            ResourceProfile::MobilePlus
        );
    }
    #[cfg(target_os = "linux")]
    {
        // Linux 桌面核心同样显式选择 desktop_high（options.rs 的 cfg any(macos, linux)）。
        assert!(removed_desktop.is_err());
        assert_eq!(
            desktop_high.unwrap().resource_profile,
            ResourceProfile::DesktopHigh
        );
        assert!(mobile_plus.is_err());
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
    {
        assert!(removed_desktop.is_err());
        assert!(desktop_high.is_err());
        assert!(mobile_plus.is_err());
    }
}

#[test]
fn resource_profile_budgets_and_reload_identity() {
    let _lock = crate::udp::performance_survey::STACK_LOCK.lock().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let profiles = [
            (ResourceProfile::Constrained, Some(256), 32, 128),
            #[cfg(target_os = "ios")]
            (ResourceProfile::MobilePlus, Some(640), 64, 512),
            #[cfg(target_os = "macos")]
            (ResourceProfile::DesktopHigh, None, 128, 192),
        ];
        for (profile, active, establishing, http) in profiles {
            let mut config = oryn_config::parse_config("rules: ['MATCH,REJECT']").unwrap();
            config.dns.public_ip_url = None;
            config.geoip.auto_update = false;
            config.geoip.asn_url = None;
            let options = EngineOptions {
                resource_profile: profile,
                ..Default::default()
            };
            let ctx = EngineCtx::new(
                oryn_netstack::LwipStack::new(1500).unwrap(),
                config.clone(),
                options,
                Arc::new(crate::stats::Stats::default()),
            );
            // 未完成握手的额度满时同步拒绝；完成一条仅归还建立额度。
            let mut pending: Vec<_> = (0..establishing)
                .map(|_| ctx.admission.try_tcp().unwrap())
                .collect();
            assert!(ctx.admission.try_tcp().is_none());
            pending[0].phase().complete();
            pending.push(ctx.admission.try_tcp().unwrap());
            assert!(ctx.admission.try_tcp().is_none());
            drop(pending);
            let active_count = active.unwrap_or(512);
            let held: Vec<_> = (0..active_count)
                .map(|_| {
                    let p = ctx.admission.try_tcp().unwrap();
                    p.phase().complete();
                    p
                })
                .collect();
            if active.is_some() {
                assert!(ctx.admission.try_tcp().is_none());
            }
            let dns: Vec<_> = (0..8).map(|_| ctx.admission.try_dns().unwrap()).collect();
            assert!(ctx.admission.try_dns().is_none());
            assert_eq!(
                ctx.udp.max_sessions(),
                match profile {
                    ResourceProfile::Constrained => 1024,
                    #[cfg(target_os = "ios")]
                    ResourceProfile::MobilePlus => 1024,
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    ResourceProfile::DesktopHigh => 4096,
                }
            );
            let old = ctx.state();
            let permits = match (ctx.http_connections.clone(), old.http_transactions.clone()) {
                (Some(connections), Some(transactions)) => {
                    let held = [
                        connections
                            .clone()
                            .try_acquire_many_owned(http as u32)
                            .unwrap(),
                        transactions
                            .clone()
                            .try_acquire_many_owned(http as u32)
                            .unwrap(),
                    ];
                    assert_eq!(connections.available_permits(), 0);
                    assert_eq!(transactions.available_permits(), 0);
                    Some((connections, transactions, held))
                }
                (None, None) => {
                    #[cfg(target_os = "macos")]
                    {
                        assert!(matches!(profile, ResourceProfile::DesktopHigh));
                    }
                    // MobilePlus 仅 iOS 编译入；Linux 上本分支不可达（DesktopHigh 不进 profiles）。
                    #[cfg(target_os = "ios")]
                    {
                        assert!(matches!(profile, ResourceProfile::MobilePlus));
                    }
                    None
                }
                _ => panic!("HTTP semaphores must be both finite or both unlimited"),
            };
            ctx.apply_config(config);
            let new = ctx.state();
            assert!(!std::rc::Rc::ptr_eq(&old, &new));
            if let Some((connections, transactions, _held)) = permits {
                assert!(Arc::ptr_eq(
                    &connections,
                    ctx.http_connections.as_ref().unwrap()
                ));
                assert!(Arc::ptr_eq(
                    &transactions,
                    new.http_transactions.as_ref().unwrap()
                ));
                assert_eq!(connections.available_permits(), 0);
                assert_eq!(transactions.available_permits(), 0);
            }
            if active.is_some() {
                assert!(ctx.admission.try_tcp().is_none());
            }
            assert!(ctx.admission.try_dns().is_none());
            drop((held, dns));
            assert!(ctx.admission.try_tcp().is_some());
            assert!(ctx.admission.try_dns().is_some());
        }
    });
}

#[test]
fn mieru_session_limits_follow_resource_profile() {
    // issue #5：Mieru 会话上限档位化，Constrained 与引擎 active=Some(64) 对齐。
    assert_eq!(ResourceProfile::Constrained.limits().mieru_sessions, 64);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    assert_eq!(ResourceProfile::DesktopHigh.limits().mieru_sessions, 512);
    #[cfg(target_os = "ios")]
    assert_eq!(ResourceProfile::MobilePlus.limits().mieru_sessions, 256);
}
