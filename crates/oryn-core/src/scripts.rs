//! JS 在有界 blocking worker 运行，lwIP 事件循环不执行脚本计算。
use oryn_http_inspect::{Message, ScriptRule};
use oryn_outbound::Outbound;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Semaphore;
pub struct ScriptHost {
    generation: Arc<std::sync::atomic::AtomicU64>,
    network: std::sync::RwLock<Option<(Arc<oryn_dns::Routing>, Arc<oryn_dns::DnsEngine>)>>,
    pub results: Mutex<BTreeMap<String, Value>>,
    pub notifications: Mutex<std::collections::VecDeque<Value>>,
    slots: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    store: Mutex<BTreeMap<String, String>>,
    path: Option<std::path::PathBuf>,
}
impl ScriptHost {
    pub fn new(dir: Option<&std::path::Path>) -> Self {
        let path = dir.map(|d| d.join("script-store.json"));
        let store = path
            .as_ref()
            .and_then(|p| {
                std::fs::metadata(p)
                    .ok()
                    .filter(|m| m.len() <= 524288)
                    .and_then(|_| std::fs::read(p).ok())
            })
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or_default();
        Self {
            generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            network: Default::default(),
            results: Mutex::new(BTreeMap::new()),
            notifications: Mutex::new(Default::default()),
            slots: Arc::new(Semaphore::new(1)),
            pending: Arc::new(Semaphore::new(64)),
            store: Mutex::new(store),
            path,
        }
    }
    fn record_result(&self, name: &str, result: Value) {
        let mut results = self.results.lock().unwrap();
        if results.len() >= 64 && !results.contains_key(name) {
            if let Some(first) = results.keys().next().cloned() {
                results.remove(&first);
            }
        }
        let result = if result.to_string().len() <= 16384 {
            result
        } else {
            json!({"error":"script result exceeds display limit"})
        };
        results.insert(name.to_owned(), result);
    }
    pub fn cancel(&self) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn set_network(&self, routing: Arc<oryn_dns::Routing>, dns: Arc<oryn_dns::DnsEngine>) {
        *self.network.write().unwrap() = Some((routing, dns));
    }
    pub async fn execute(
        self: &Arc<Self>,
        spec: &ScriptRule,
        request: &Message,
        response: Option<&mut Message>,
        outbound: Arc<dyn Outbound>,
    ) -> io::Result<Option<Message>> {
        if spec.requires_body && response.as_deref().unwrap_or(request).body.len() > spec.max_size {
            return Err(io::Error::other("script max-size exceeded"));
        }
        let epoch = self.generation.load(std::sync::atomic::Ordering::Relaxed);
        let _pending = self
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| io::Error::other("script pending queue is full"))?;
        // 只有一个 worker（每个脚本堆最多 8 MiB，Extension 内存预算放不下并发）。排队最多等一个
        // timeout；拿到槽位后才开始计脚本自身的 timeout，排队时间不挤占执行预算。
        let permit = tokio::time::timeout(
            Duration::from_secs(spec.timeout),
            self.slots.clone().acquire_owned(),
        )
        .await
        .map_err(|_| io::Error::other("script queue timeout"))?
        .map_err(io::Error::other)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(spec.timeout);
        if self.generation.load(std::sync::atomic::Ordering::Relaxed) != epoch {
            return Err(io::Error::other("script cancelled by reload"));
        }
        let to_json = |m: &Message| {
            let mut v = json!({"url":m.url,"method":m.method,"headers":m.headers.iter().cloned().collect::<BTreeMap<_,_>>()});
            if spec.full_headers {
                v["headers"] = Value::Array(
                    m.headers
                        .iter()
                        .map(|(k, v)| json!({"field":k,"value":v}))
                        .collect(),
                );
            }
            if let Some(status) = m.status {
                v["status"] = status.into();
            }
            if spec.requires_body {
                v["body"] = if spec.binary {
                    json!(m.body)
                } else {
                    String::from_utf8_lossy(&m.body).into_owned().into()
                };
            }
            v
        };
        let decoded_request = if spec.requires_body {
            let mut r = request.clone();
            r.body = oryn_http_inspect::decode_body(&r)?;
            Some(r)
        } else {
            None
        };
        let decoded_response = if spec.requires_body {
            response
                .as_deref()
                .map(|r| {
                    let mut r = r.clone();
                    r.body = oryn_http_inspect::decode_body(&r)?;
                    Ok::<_, io::Error>(r)
                })
                .transpose()?
        } else {
            None
        };
        let input = oryn_script::Input {
            cancellation: Some((self.generation.clone(), epoch)),
            event: spec
                .event
                .clone()
                .map(|name| json!({"name":name}))
                .unwrap_or(Value::Null),
            cron: spec.cron.clone(),
            kind: spec.kind.clone(),
            loon: spec.dialect == oryn_module::ModuleFormat::Loon,
            request: to_json(decoded_request.as_ref().unwrap_or(request)),
            response: decoded_response
                .as_ref()
                .or(response.as_deref())
                .map(to_json)
                .unwrap_or(Value::Null),
            argument: spec.argument.clone(),
            env: spec.env.clone(),
            binary: spec.binary,
            timeout: deadline.saturating_duration_since(std::time::Instant::now()),
            name: spec.name.clone(),
            store: self.store.lock().unwrap().clone(),
        };
        let code = spec.code.clone();
        let handle = tokio::runtime::Handle::current();
        let (routing, dns) = self
            .network
            .read()
            .unwrap()
            .clone()
            .map(|(r, d)| (Some(r), Some(d)))
            .unwrap_or((None, None));
        let (output,_permit)=tokio::task::spawn_blocking(move||{let result=oryn_script::run(code.as_str(),input,move |options|{
            if let Some(name)=options["control"].as_str(){return control(routing.as_deref(),name,&options)}
            let url=options["url"].as_str().ok_or("script HTTP URL missing")?;
            let mut headers=options["headers"].as_object().map(|o|o.iter().filter_map(|(k,v)|Some((k.as_str(),v.as_str()?))).collect::<Vec<_>>()).unwrap_or_default();
            // 脚本未指定 UA 时与 Surge 一致，带上模块下载同款 UA（部分站点只放行 Surge / Loon / Clash 系）。
            if !headers.iter().any(|(k,_)|k.eq_ignore_ascii_case("user-agent")){headers.push(("User-Agent",crate::modules::MODULE_USER_AGENT));}
            let body=match &options["body"]{Value::String(s)=>s.as_bytes().to_vec(),Value::Null=>vec![],v=>v.to_string().into_bytes()};
            let mut selected=outbound.clone();
            if let Some(routing)=&routing {
                let parsed=url::Url::parse(url).map_err(|e|e.to_string())?;let host=parsed.host_str().ok_or("HTTP host missing")?;let port=parsed.port_or_known_default().unwrap_or(443);let target=oryn_config::TargetAddr::from_host(host,port);
                let index=if let Some(policy)=options["policy"].as_str(){routing.outbounds.iter().position(|o|o.tag()==policy).ok_or("unknown script policy")?}else{
                    let mut flow=oryn_router::FlowContext::new(0,oryn_router::Network::Tcp,"127.0.0.1:0".parse().unwrap(),std::net::SocketAddr::from(([0,0,0,0],port)));flow.set_domain(host.into(),oryn_router::DomainSource::Sniffed);
                    if routing.router.needs_ip_resolution(&flow){if let Some(dns)=&dns{if let Ok(Ok(ips))=handle.block_on(tokio::time::timeout(deadline.saturating_duration_since(std::time::Instant::now()),dns.resolve_direct_target(host))){if let Some(ip)=ips.first(){flow.destination.set_ip(*ip);}}}}
                    routing.router.route(&flow).outbound
                };
                selected=oryn_outbound::resolve(&routing.outbounds[index],&oryn_outbound::PickMeta{source:None,target:&target,network:oryn_router::Network::Tcp}).ok_or("script HTTP route rejected")?.leaf;
            }
            let req=oryn_http::Request{method:options["method"].as_str().unwrap_or("GET"),url,headers:&headers,body:&body};
            let response=handle.block_on(oryn_http::fetch(&oryn_http::OutboundConnector(selected),req,&oryn_http::Options{max_body:1024*1024,timeout:deadline.saturating_duration_since(std::time::Instant::now()).min(Duration::from_secs(5)),max_redirects:3,skip_verify:false})).map_err(|e|e.to_string())?;
            Ok(json!({"response":{"status":response.status,"headers":response.headers.into_iter().collect::<BTreeMap<_,_>>()},"binary":options["binary-mode"].as_bool().unwrap_or(false),"data":if options["binary-mode"].as_bool()==Some(true){json!(response.body)}else{Value::String(String::from_utf8_lossy(&response.body).into_owned())}}))
        });
        // 脚本堆（最多 8 MiB）在本线程分配，用完就把空页还给系统
        crate::alloc::trim();
        (result,permit)}).await.map_err(io::Error::other)?;
        let output = output.map_err(io::Error::other)?;
        if self.generation.load(std::sync::atomic::Ordering::Relaxed) != epoch {
            return Err(io::Error::other("script cancelled by reload"));
        }
        // 多数脚本不写 $persistentStore：内容没变时不落盘，避免每个请求一次同步磁盘写。
        let changed = {
            let mut store = self.store.lock().unwrap();
            let changed = *store != output.store;
            if changed {
                *store = output.store;
            }
            changed
        };
        if let (true, Some(path)) = (changed, &self.path) {
            let bytes = serde_json::to_vec(&*self.store.lock().unwrap())?;
            let temp = path.with_extension("tmp");
            std::fs::write(&temp, bytes)?;
            std::fs::rename(temp, path)?;
        }
        for line in output.logs {
            log::info!("script {}: {line}", spec.name);
        }
        for n in output.notifications {
            let mut queue = self.notifications.lock().unwrap();
            if queue.len() == 16 {
                queue.pop_front();
            }
            queue.push_back(json!({"title":n["title"],"subtitle":n["subtitle"],"body":n["body"]}));
        }
        if !matches!(spec.kind.as_str(), "http-request" | "http-response") {
            self.record_result(&spec.name, output.result.clone());
        }
        let mut result = output.result;
        if result["abort"].as_bool() == Some(true) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "script aborted HTTP request",
            ));
        }
        let mut m = response
            .as_deref()
            .cloned()
            .unwrap_or_else(|| request.clone());
        let local = result.get("response").is_some();
        if local {
            result = result["response"].clone();
            m = request.response(
                result["status"].as_u64().unwrap_or(200) as u16,
                vec![],
                "text/plain",
            );
        }
        let new_url = result["url"].as_str().filter(|u| *u != m.url).map(str::to_owned);
        if let Some(url) = &new_url {
            m.url = url.clone();
        }
        if let Some(status) = result["status"].as_u64() {
            m.status = Some(u16::try_from(status).map_err(io::Error::other)?);
        }
        if let Some(headers) = result["headers"].as_object() {
            m.headers = headers
                .iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                .collect();
        }
        if let Some(headers) = result["headers"].as_array() {
            m.headers = headers
                .iter()
                .map(|h| {
                    Ok((
                        h["field"]
                            .as_str()
                            .ok_or_else(|| io::Error::other("invalid full header field"))?
                            .into(),
                        h["value"]
                            .as_str()
                            .ok_or_else(|| io::Error::other("invalid full header value"))?
                            .into(),
                    ))
                })
                .collect::<io::Result<Vec<_>>>()?;
        }
        // 请求脚本改到别的主机时 Host 跟着改（与 URL 重写一致）；脚本常把原请求头整份传回，
        // 里面的旧 Host 会让上游按原主机处理。主机没变时尊重脚本给的 Host。
        if response.is_none() && !local {
            if let Some(url) = &new_url {
                let authority = |u: &str| {
                    u.parse::<http::Uri>()
                        .ok()
                        .and_then(|u| u.authority().map(|a| a.as_str().to_owned()))
                };
                if let Some(new) = authority(url) {
                    if authority(&request.url).as_deref() != Some(new.as_str()) {
                        m.set_header("Host", new);
                    }
                }
            }
        }
        if m.headers.len() > 128
            || m.headers
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                > 32768
        {
            return Err(io::Error::other("script headers exceed limit"));
        }
        if !local && result.get("body").is_none() {
            let original = response.as_deref().unwrap_or(request);
            for key in ["Content-Length", "Transfer-Encoding"] {
                if m.header(key) != original.header(key) {
                    return Err(io::Error::other(
                        "script cannot change framing without body",
                    ));
                }
            }
        }
        if let Some(body) = result.get("body") {
            if !spec.requires_body && !local {
                return Err(io::Error::other(
                    "script returned body without requires-body",
                ));
            }
            m.body = if let Some(s) = body.as_str() {
                s.as_bytes().to_vec()
            } else {
                body.as_array()
                    .ok_or_else(|| io::Error::other("script body is not string/bytes"))?
                    .iter()
                    .map(|v| {
                        v.as_u64()
                            .and_then(|n| u8::try_from(n).ok())
                            .ok_or_else(|| io::Error::other("invalid script body byte"))
                    })
                    .collect::<io::Result<Vec<_>>>()?
            };
            if m.body.len() > oryn_http_inspect::MAX_BODY {
                return Err(io::Error::other("script output body exceeds limit"));
            }
            m.delete_header("Content-Encoding");
            m.delete_header("Transfer-Encoding");
            m.set_header("Content-Length", m.body.len().to_string());
        }
        if let Some(response) = response {
            *response = m;
            Ok(None)
        } else {
            Ok(Some(m))
        }
    }
}

/// 网络/定时/手动脚本共用同一 worker 配额，满载时跳过本次触发，不积累待执行队列。
pub async fn auxiliary(state: std::rc::Rc<crate::context::RuntimeState>, spec: ScriptRule) {
    let target = oryn_config::TargetAddr::Domain("script.internal".into(), 443);
    let start = &state.routing.outbounds[state.config.global_index()];
    let Some(out) = oryn_outbound::resolve(
        start,
        &oryn_outbound::PickMeta {
            source: None,
            target: &target,
            network: oryn_router::Network::Tcp,
        },
    ) else {
        return;
    };
    let request = Message {
        url: spec.source.clone(),
        method: "GET".into(),
        status: None,
        headers: vec![],
        body: vec![],
    };
    if let Err(e) = state.scripts.execute(&spec, &request, None, out.leaf).await {
        if !*state.inspection_cancel.borrow() {
            state
                .scripts
                .record_result(&spec.name, json!({"error":e.to_string()}));
        }
        log::warn!("script {}: {e}", spec.name);
    }
}
pub fn event(state: &std::rc::Rc<crate::context::RuntimeState>, name: &str) {
    for spec in state
        .http_plan
        .scripts
        .iter()
        .filter(|s| s.enabled && s.kind == "event" && s.event.as_deref() == Some(name))
        .take(64)
    {
        let st = state.clone();
        let spec = spec.clone();
        state.spawn(async move { auxiliary(st, spec).await });
    }
}
pub fn schedule(state: &std::rc::Rc<crate::context::RuntimeState>) {
    use std::str::FromStr;
    for spec in state
        .http_plan
        .scripts
        .iter()
        .filter(|s| s.enabled && s.kind == "cron")
        .take(64)
    {
        let Some(expression) = &spec.cron else {
            continue;
        };
        let expression = if expression.split_whitespace().count() == 5 {
            format!("0 {expression}")
        } else {
            expression.clone()
        };
        let schedule = match cron::Schedule::from_str(&expression) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("script {} invalid cron: {e}", spec.name);
                continue;
            }
        };
        let weak = std::rc::Rc::downgrade(state);
        let spec = spec.clone();
        state.spawn(async move {
            loop {
                let now = chrono::Local::now();
                let Some(next) = schedule.after(&now).next() else {
                    break;
                };
                let delay = (next - now).to_std().unwrap_or(Duration::from_secs(1));
                tokio::time::sleep(delay.max(Duration::from_secs(1))).await;
                let Some(state) = weak.upgrade() else { break };
                auxiliary(state, spec.clone()).await;
            }
        });
    }
}
fn control(
    routing: Option<&oryn_dns::Routing>,
    name: &str,
    options: &Value,
) -> Result<Value, String> {
    let routing = routing.ok_or("script control is unavailable")?;
    match name {
        "groups" => {
            let mut groups = BTreeMap::new();
            let mut decisions = BTreeMap::new();
            for out in &routing.outbounds {
                if let Some(group) = out.as_group() {
                    let status = group.status();
                    groups.insert(
                        status.name.clone(),
                        status
                            .members
                            .into_iter()
                            .map(|m| m.name)
                            .collect::<Vec<_>>(),
                    );
                    decisions.insert(status.name, status.now);
                }
            }
            Ok(json!({"groups":groups,"decisions":decisions}))
        }
        "select" => {
            let group = options["group"].as_str().ok_or("missing group")?;
            let name = options["name"].as_str().ok_or("missing policy")?;
            let ok = routing
                .outbounds
                .iter()
                .find(|o| o.tag() == group)
                .and_then(|o| o.as_group())
                .is_some_and(|g| g.select(name));
            Ok(json!({"ok":ok}))
        }
        "mode" => {
            let mode = options["mode"].as_str().unwrap_or("");
            let mode = oryn_config::Mode::parse(if mode == "global-proxy" {
                "global"
            } else {
                mode
            })
            .ok_or("invalid outbound mode")?;
            routing.router.set_mode(mode);
            Ok(json!({"ok":true}))
        }
        _ => Err(format!("unknown script control {name}")),
    }
}
