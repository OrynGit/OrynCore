//! 外部 corpus 的离线审计；绝不创建 Engine 或执行脚本。
use super::*;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf, time::Instant};

#[derive(Deserialize)]
struct Entry {
    id: u64,
    original_url: String,
    url: String,
    enabled: bool,
    #[serde(default)]
    arguments: BTreeMap<String, Value>,
    path: Option<String>,
    status: Option<u16>,
}
#[derive(Deserialize)]
struct Resource {
    url: String,
    status: Option<u16>,
    path: Option<String>,
}

// 诊断可能携带 URL、参数或源码；只输出类别和稳定指纹，不回显任意外部文本。
fn diagnostic(text: impl std::fmt::Display) -> Value {
    let text = text.to_string();
    let lower = text.to_ascii_lowercase();
    let category = if lower.contains("resource limit")
        || lower.contains("exceeds")
        || lower.contains("capped")
    {
        "resource_limit"
    } else if lower.contains("unsupported") || lower.contains("not implemented") {
        "unsupported"
    } else if lower.contains("missing")
        || lower.contains("unavailable")
        || lower.contains("not found")
    {
        "missing"
    } else if lower.contains("invalid") {
        "invalid"
    } else {
        "diagnostic"
    };
    let source_line = text
        .strip_prefix("corpus-")
        .and_then(|s| s.split(':').nth(1))
        .and_then(|s| s.parse::<usize>().ok());
    let skipped = lower.contains("skipped:");
    // 诊断可能包含正文/参数，只保留指纹。
    json!({"category": category, "source_line":source_line,"skipped":skipped,"text":null,"sha256": format!("{:x}", Sha256::digest(text.as_bytes()))})
}
fn warnings(items: &[String]) -> Vec<Value> {
    items.iter().map(diagnostic).collect()
}
fn local(root: &Path, path: &str) -> Result<PathBuf, String> {
    let p = root.join(path).canonicalize().map_err(|e| e.to_string())?;
    if !p.starts_with(root) {
        return Err("invalid corpus path".into());
    }
    Ok(p)
}
fn audit(
    root: &Path,
    e: &Entry,
    evaluate: bool,
    resources: &[Resource],
    refs: &mut Vec<Value>,
    out: &mut Value,
) -> Result<(), String> {
    if !e.status.is_some_and(|s| (200..300).contains(&s)) {
        out["status"] = json!("download_failed");
        return Ok(());
    }
    let hub = oryn_module::script_hub_source(&e.original_url);
    let source = hub
        .as_ref()
        .map(|(source, _)| source.as_str())
        .unwrap_or(&e.url);
    let source_path = source
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let text = std::fs::read_to_string(local(
        root,
        e.path.as_deref().ok_or("missing module path")?,
    )?)
    .map_err(|e| e.to_string())?;
    // 无扩展名的 Egern/YAML 也不能被 INI parser 当成空成功；这里只做保守结构识别，非 YAML 验证器。
    let yaml_body = text
        .lines()
        .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .is_some_and(|line| {
            let line = line.trim_start_matches('\u{feff}').trim();
            line == "---"
                || line.split_once(':').is_some_and(|(key, value)| {
                    !key.is_empty()
                        && key
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                        && (value.is_empty() || value.starts_with(char::is_whitespace))
                })
        });
    if source_path.ends_with(".yaml") || source_path.ends_with(".yml") || yaml_body {
        out["status"] = json!("unsupported_yaml");
        return Ok(());
    }
    let explicit = hub.as_ref().and_then(|(_, format)| *format);
    let format = explicit.unwrap_or_else(|| {
        if source_path.ends_with(".sgmodule") {
            ModuleFormat::Surge
        } else if source_path.ends_with(".plugin") || source_path.ends_with(".lpx") {
            ModuleFormat::Loon
        } else {
            oryn_module::detect_format(&text)
        }
    });
    out["format"] = json!(format);
    out["format_origin"] = json!(if explicit.is_some() {
        "script_hub_type"
    } else {
        "resolved_source_or_content"
    });
    let arguments: Vec<_> = e
        .arguments
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                v.as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| v.to_string()),
            )
        })
        .collect();
    let bound = oryn_module::bind(&text, format, &arguments).map_err(|e| e.to_string())?;
    out["binding_warnings"] = json!(warnings(&bound.warnings));
    let ir = oryn_module::parse_named(&bound.text, Some(format), &format!("corpus-{}", e.id))
        .map_err(|e| e.to_string())?;
    out["ir"] = json!({"rules":ir.rules.len(), "scripts":ir.scripts.len(), "rewrites":ir.rewrites.len(), "raw_sections":ir.raw_sections.iter().map(|(k,v)| (k.clone(),v.len())).collect::<BTreeMap<_,_>>(), "warnings":warnings(&ir.warnings)});
    let mut loaded = oryn_module::Resources::default();
    let mut missing = 0;
    for path in resource_references(&ir) {
        let url = url::Url::parse(&e.url)
            .and_then(|u| u.join(&path))
            .map_err(|e| e.to_string())?
            .to_string();
        refs.push(json!({"id":e.id, "path":path, "url":url}));
        if evaluate {
            let data = resources
                .iter()
                .find(|r| r.url == url && r.status.is_some_and(|s| (200..300).contains(&s)))
                .and_then(|r| r.path.as_deref())
                .and_then(|p| local(root, p).ok())
                .and_then(|p| std::fs::read(p).ok());
            if let Some(data) = data {
                loaded.insert(path, data.into());
            } else {
                missing += 1;
            }
        }
    }
    out["status"] = json!("discovered");
    if !evaluate {
        return Ok(());
    }
    let spec = oryn_config::ModuleSpec {
        url: Some(e.url.clone()),
        format: Some(format),
        enabled: e.enabled,
        update_interval: 0,
        arguments,
        policy_map: vec![],
        env: BTreeMap::new(),
        inline: Some(ir),
        resources: std::sync::Arc::new(loaded),
    };
    out["resource_bytes"] = json!(spec.resources.values().map(|v| v.len()).sum::<usize>());
    out["module_bytes"] = json!(module_size(&spec));
    out["missing_resources"] = json!(missing);
    let valid = validate(&spec);
    out["validation"] = match &valid {
        Ok(_) => json!({"ok":true}),
        Err(e) => json!({"ok":false,"error":diagnostic(e)}),
    };
    let compiled = oryn_http_inspect::compile_module_with_policies(
        spec.inline.as_ref().unwrap(),
        &spec.arguments.iter().cloned().collect(),
        &spec.resources,
        &spec.policy_map,
    );
    match compiled {
        Ok(plan) => {
            // 编译成功的脚本按源码顺序进入 plan.scripts；去掉被跳过的行即可对应源码行号。
            let skipped_lines: Vec<_> = plan
                .warnings
                .iter()
                .filter(|w| w.contains(": script skipped:"))
                .map(|w| diagnostic(w)["source_line"].clone())
                .collect();
            let source_lines: Vec<_> = spec
                .inline
                .as_ref()
                .unwrap()
                .scripts
                .iter()
                .map(|s| json!(s.source.line))
                .filter(|line| !skipped_lines.contains(line))
                .collect();
            let script_details: Vec<_> = plan.scripts.iter().enumerate().map(|(i,s)| json!({"name":s.name,"source_line":source_lines.get(i),"script_enabled":s.enabled})).collect();
            let skipped_scripts: Vec<_> = plan
                .warnings
                .iter()
                .filter(|w| w.contains(": script skipped:"))
                .map(|w| {
                    let d = diagnostic(w);
                    let line = d["source_line"].as_u64().unwrap_or(0) as usize;
                    let raw_name = spec
                        .inline
                        .as_ref()
                        .unwrap()
                        .scripts
                        .iter()
                        .find(|s| s.source.line == line)
                        .and_then(|s| {
                            option_value(&s.text, "tag=")
                                .or_else(|| s.text.split_once('=').map(|(name, _)| name.trim()))
                        });
                    json!({"source_line":line,"name":raw_name,"diagnostic":d})
                })
                .collect();
            out["plan"] = json!({"request":plan.request.len(), "response":plan.response.len(), "scripts":plan.scripts.len(), "script_details":script_details,"skipped_scripts":skipped_scripts,"warnings":warnings(&plan.warnings)});
            out["replay"] = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                replay(root, e.id, &plan)
            })) {
                Ok(Ok(result)) => result,
                Ok(Err(error)) => json!({"failed":true,"error":diagnostic(error)}),
                Err(_) => json!({"failed":true,"error":"assertion_panic"}),
            };
        }
        Err(e) => out["compile_error"] = diagnostic(e),
    }
    // 单模块静态合并（含 disabled）与实际 enabled 合并分开，不能把静态结果算作生效。
    for (key, enabled) in [
        ("static_merge", true),
        ("merge", e.enabled && valid.is_ok()),
    ] {
        let mut config =
            oryn_config::parse_config("rules: ['MATCH,DIRECT']\n").map_err(|e| e.to_string())?;
        let mut candidate = spec.clone();
        candidate.enabled = enabled;
        config.modules.push(candidate);
        let result = oryn_config::merge_module_patches(&mut config);
        out[key] = json!({"rules":config.rules.len(),"added_rules":config.rules.len().saturating_sub(1),"mitm":{"enabled":config.mitm.enabled,"hostname_count":config.mitm.hostnames.len(),"http2":config.mitm.http2,"skip_server_cert_verify":config.mitm.skip_server_cert_verify},"warnings":warnings(&config.warnings),"error":result.err().map(diagnostic)});
    }
    out["status"] = json!(if valid.is_ok() {
        "evaluated"
    } else {
        "validation_failed"
    });
    Ok(())
}

// 只执行 Plan 的声明式 rewrite/jq，不调用 scripts() 的执行器。
fn replay(root: &Path, id: u64, original: &oryn_http_inspect::Plan) -> Result<Value, String> {
    use oryn_http_inspect::Message;
    let message = |url: &str| Message {
        url: url.into(),
        method: "GET".into(),
        status: None,
        headers: vec![],
        body: vec![],
    };
    let variant =
        |file: &str, format, key: &str, value: &str| -> Result<oryn_http_inspect::Plan, String> {
            let text = std::fs::read_to_string(local(root, file)?).map_err(|e| e.to_string())?;
            let args = vec![(key.to_owned(), value.to_owned())];
            let bound = oryn_module::bind(&text, format, &args).map_err(|e| e.to_string())?;
            let ir = oryn_module::parse_named(&bound.text, Some(format), "synthetic-replay")
                .map_err(|e| e.to_string())?;
            oryn_http_inspect::compile_module(&ir, &args.into_iter().collect(), &Default::default())
                .map_err(|e| e.to_string())
        };
    let mut cases = vec![];
    match id {
        3 => {
            let plan = variant("modules/003.txt", ModuleFormat::Loon, "app", "ng")?;
            for (url, expected) in [
                (
                    "https://t.me/example_group",
                    "ng://resolve?domain=example_group",
                ),
                (
                    "https://t.me/+SyntheticInvite",
                    "ng://join?invite=SyntheticInvite",
                ),
            ] {
                let result = plan
                    .apply_request(&mut message(url))
                    .map_err(|e| e.to_string())?
                    .expect("Telegram redirect");
                assert_eq!(result.status, Some(307));
                assert_eq!(result.header("Location"), Some(expected));
            }
            cases.push("telegram_ng_public_and_invite");
        }
        28 => {
            for (url, expected) in [
                (
                    "https://www.google.cn/search?q=synthetic",
                    "https://www.google.com/search?q=synthetic",
                ),
                (
                    "https://maps.google.cn/maps?q=synthetic",
                    "https://maps.google.com/maps?q=synthetic",
                ),
            ] {
                let result = original
                    .apply_request(&mut message(url))
                    .map_err(|e| e.to_string())?
                    .expect("Google redirect");
                assert_eq!(result.status, Some(307));
                assert_eq!(result.header("Location"), Some(expected));
            }
            cases.push("google_search_and_maps_redirect");
        }
        21 => {
            let request =
                message("https://m-cloud.zhihu.com/api/cloud/zhihu/config/all?synthetic=1");
            let mut response = request.response(200,serde_json::to_vec(&json!({"data":{"configs":[{"configKey":"sugarQuicConfig","configValue":{}},{"configKey":"keep","configValue":{"HTTPDNS":true,"delayHttpdns":true,"dnsParser":true,"safe":42}}]}})).unwrap(),"application/json");
            original
                .apply_response(&mut response, &request)
                .map_err(|e| e.to_string())?;
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body).unwrap(),
                json!({"data":{"configs":[{"configKey":"keep","configValue":{"safe":42}}]}})
            );
            cases.push("zhihu_drop_httpdns_quic_preserve_safe_config");
            let mut request = message("https://api.zhihu.com/ad-style-service/request");
            let result = original
                .apply_request(&mut request)
                .map_err(|e| e.to_string())?
                .expect("Zhihu reject_dict");
            assert_eq!(result.status, Some(200));
            assert_eq!(
                serde_json::from_slice::<Value>(&result.body).unwrap(),
                json!({})
            );
            cases.push("zhihu_ad_reject_dict");
        }
        53 => {
            let mut user_request =
                message("https://upos-sz-mirroraliov.bilivideo.com/upgcxcode/synthetic.m4s");
            assert!(original
                .apply_request(&mut user_request)
                .map_err(|e| e.to_string())?
                .is_none());
            assert_eq!(
                user_request.url,
                "https://upos-sz-mirrorali.bilivideo.com/upgcxcode/synthetic.m4s"
            );
            assert_eq!(
                user_request.header("Host"),
                Some("upos-sz-mirrorali.bilivideo.com")
            );
            cases.push("bili_original_user_host_argument_preserves_path");
            let plan = variant(
                "modules/053.txt",
                ModuleFormat::Surge,
                "Host.OverseaVideo",
                "cdn.synthetic.test",
            )?;
            let mut request =
                message("https://upos-sz-mirroraliov.bilivideo.com/upgcxcode/synthetic.m4s");
            assert!(plan
                .apply_request(&mut request)
                .map_err(|e| e.to_string())?
                .is_none());
            assert_eq!(
                request.url,
                "https://cdn.synthetic.test/upgcxcode/synthetic.m4s"
            );
            cases.push("bili_redirect_host_argument_preserves_path");
        }
        _ => {}
    }
    Ok(json!({"passed":cases,"js_executed":false,"network_access":false}))
}

#[test]
#[ignore = "external local corpus; no downloads or script execution"]
fn corpus_modules() {
    let root =
        PathBuf::from(std::env::var_os("ORYN_MODULE_CORPUS").expect("ORYN_MODULE_CORPUS required"))
            .canonicalize()
            .unwrap();
    let mode = std::env::var("MODE").expect("MODE=discover/evaluate required");
    assert!(mode == "discover" || mode == "evaluate");
    let evaluate = mode == "evaluate";
    let entries: Vec<Entry> =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let resources: Vec<Resource> = if evaluate {
        serde_json::from_slice(&std::fs::read(root.join("resources.json")).unwrap()).unwrap()
    } else {
        vec![]
    };
    oryn_script::set_bytecode_cache_dir(Some(root.join("bytecode")));
    let mut refs = vec![];
    let mut reports = vec![];
    // 默认 panic hook 会回显外部内容；本单条 ignored 测试仅保存无凭据指纹。
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for e in entries {
        let start = Instant::now();
        let mut out = json!({"id":e.id,"enabled":e.enabled});
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            audit(&root, &e, evaluate, &resources, &mut refs, &mut out)
        })) {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                out["status"] = json!("error");
                out["error"] = diagnostic(err);
            }
            Err(_) => {
                out["status"] = json!("panic");
            }
        }
        out["milliseconds"] = json!(start.elapsed().as_secs_f64() * 1000.0);
        reports.push(out);
    }
    std::panic::set_hook(hook);
    oryn_script::set_bytecode_cache_dir(None);
    let mut admitted_bytes = 0u64;
    let mut scripts = 0u64;
    for r in &mut reports {
        let bytes = r["module_bytes"].as_u64().unwrap_or(0);
        let admitted = evaluate
            && r["enabled"] == true
            && r["status"] == "evaluated"
            && admitted_bytes + bytes <= MAX_RESOURCES as u64;
        r["group_admitted"] = json!(admitted);
        let count = r["plan"]["scripts"].as_u64().unwrap_or(0);
        let retained = if admitted {
            count.min(64u64.saturating_sub(scripts))
        } else {
            0
        };
        r["group_scripts_retained"] = json!(retained);
        r["group_scripts_dropped_limit"] = json!(if admitted { count - retained } else { 0 });
        r["group_scripts_not_admitted"] = json!(if admitted { 0 } else { count });
        if let Some(details) = r["plan"]["script_details"].as_array_mut() {
            for (i, detail) in details.iter_mut().enumerate() {
                detail["group_retained"] = json!(admitted && (i as u64) < retained);
                detail["group_drop_reason"] = json!(if !admitted {
                    "module_not_admitted"
                } else if (i as u64) >= retained {
                    "script_limit_64"
                } else {
                    "retained"
                });
            }
        }
        if admitted {
            admitted_bytes += bytes;
            scripts += count;
        }
    }
    let sum = |field: &str, enabled_only: bool| {
        reports
            .iter()
            .filter(|r| !enabled_only || r["enabled"] == true)
            .map(|r| r[field].as_u64().unwrap_or(0))
            .sum::<u64>()
    };
    let report = json!({"mode":mode,"modules":reports,"summary":{"resource_bytes":sum("resource_bytes",false),"enabled_resource_bytes":sum("resource_bytes",true),"enabled_module_bytes":sum("module_bytes",true),"resource_limit_bytes":MAX_RESOURCES,"enabled_over_8mib":sum("module_bytes",true)>MAX_RESOURCES as u64,"admitted_module_bytes":admitted_bytes,"admitted_scripts":scripts,"script_limit":64,"scripts_over_limit":scripts>64,"scripts_after_truncation":scripts.min(64)}});
    if !evaluate {
        std::fs::write(
            root.join("refs.json"),
            serde_json::to_vec_pretty(&refs).unwrap(),
        )
        .unwrap();
    }
    std::fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    assert!(
        !reports.iter().any(|r| r["replay"]["failed"] == true),
        "offline replay failed; see report.json"
    );
    println!(
        "corpus {mode}: {} modules; report.json written",
        reports.len()
    );
}
