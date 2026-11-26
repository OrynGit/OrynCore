//! JS 在有界 blocking worker 运行，lwIP 事件循环不执行脚本计算。
use oryn_http_inspect::{Message, ScriptRule};
use oryn_outbound::Outbound;
use oryn_script::{BodyData, HostReply, HttpReply};
use serde_json::{json, Value};
use std::{
    borrow::Cow,
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Semaphore;
/// 一次脚本执行的结果。请求脚本可以带出口名；内部策略头已经从消息里去掉。
pub struct ScriptDone {
    pub message: Option<Message>,
    pub policy: Option<String>,
    pub body_modified: bool,
}

pub struct ScriptHost {
    generation: Arc<std::sync::atomic::AtomicU64>,
    network: std::sync::RwLock<Option<(Arc<oryn_dns::Routing>, Arc<oryn_dns::DnsEngine>)>>,
    pub results: Mutex<BTreeMap<String, Value>>,
    pub notifications: Mutex<std::collections::VecDeque<Value>>,
    /// 前台 HTTP 脚本与后台 cron/event 脚本分池，避免后台慢 `$httpClient` 阻塞 HTTP 请求。
    http_slots: Arc<Semaphore>,
    bg_slots: Arc<Semaphore>,
    http_pending: Arc<Semaphore>,
    bg_pending: Arc<Semaphore>,
    store: Mutex<Arc<BTreeMap<String, String>>>,
    path: Option<std::path::PathBuf>,
    max_heap: usize,
    bg_max_heap: usize,
    max_body: usize,
    max_scripts: usize,
}
impl ScriptHost {
    pub fn new(dir: Option<&std::path::Path>) -> Self {
        Self::new_with_limits(
            dir,
            oryn_script::HEAP_LIMIT,
            oryn_http_inspect::MAX_BODY,
            256,
        )
    }
    pub fn new_with_limits(
        dir: Option<&std::path::Path>,
        max_heap: usize,
        max_body: usize,
        max_scripts: usize,
    ) -> Self {
        Self::new_with_pools(
            dir,
            1,
            1,
            max_heap,
            max_heap.min(8 << 20),
            max_body,
            max_scripts,
        )
    }
    pub fn new_with_pools(
        dir: Option<&std::path::Path>,
        http_workers: usize,
        bg_workers: usize,
        max_heap: usize,
        bg_max_heap: usize,
        max_body: usize,
        max_scripts: usize,
    ) -> Self {
        let path = dir.map(|d| d.join("script-store.json"));
        let store: BTreeMap<String, String> = path
            .as_ref()
            .and_then(|p| {
                std::fs::metadata(p)
                    .ok()
                    .filter(|m| m.len() <= (oryn_script::MAX_STORE_BYTES * 2) as u64)
                    .and_then(|_| std::fs::read(p).ok())
            })
            .and_then(|v| serde_json::from_slice::<BTreeMap<String, String>>(&v).ok())
            .filter(|m| {
                m.len() <= oryn_script::MAX_STORE_KEYS
                    && m.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
                        <= oryn_script::MAX_STORE_BYTES
            })
            .unwrap_or_default();
        Self {
            generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            network: Default::default(),
            results: Mutex::new(BTreeMap::new()),
            notifications: Mutex::new(Default::default()),
            http_slots: Arc::new(Semaphore::new(http_workers.max(1))),
            bg_slots: Arc::new(Semaphore::new(bg_workers.max(1))),
            http_pending: Arc::new(Semaphore::new(64)),
            bg_pending: Arc::new(Semaphore::new(32)),
            store: Mutex::new(Arc::new(store)),
            path,
            max_heap,
            bg_max_heap,
            max_body,
            max_scripts,
        }
    }
    pub fn max_scripts(&self) -> usize {
        self.max_scripts
    }
    fn record_result(&self, name: &str, result: Value) {
        let mut results = self.results.lock().unwrap();
        if results.len() >= 128 && !results.contains_key(name) {
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
    ) -> io::Result<ScriptDone> {
        let max_size = spec.max_size.min(self.max_body);
        if spec.requires_body && response.as_deref().unwrap_or(request).body.len() > max_size {
            return Err(io::Error::other("script max-size exceeded"));
        }
        let is_http = matches!(spec.kind.as_str(), "http-request" | "http-response");
        let (slots, pending, heap_limit) = if is_http {
            (&self.http_slots, &self.http_pending, self.max_heap)
        } else {
            (&self.bg_slots, &self.bg_pending, self.bg_max_heap)
        };
        let epoch = self.generation.load(std::sync::atomic::Ordering::Relaxed);
        let _pending = pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| io::Error::other("script pending queue is full"))?;
        // HTTP 与后台脚本各用独立槽位池；排队最多等一个 timeout，
        // 拿到槽位后才开始计脚本自身的 timeout，排队时间不挤占执行预算。
        let permit = tokio::time::timeout(
            Duration::from_secs(spec.timeout),
            slots.clone().acquire_owned(),
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
            v
        };
        let request_body = if spec.requires_body {
            if response.is_some() && request.body.len() > max_size {
                BodyData::None
            } else {
                body_for_script(request, max_size, spec.binary)?
            }
        } else {
            BodyData::None
        };
        let response_body = if spec.requires_body {
            response
                .as_deref()
                .map(|r| body_for_script(r, max_size, spec.binary))
                .transpose()?
                .unwrap_or(BodyData::None)
        } else {
            BodyData::None
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
            request: to_json(request),
            response: response.as_deref().map(to_json).unwrap_or(Value::Null),
            request_body,
            response_body,
            argument: spec.argument.clone(),
            env: Arc::clone(&spec.env),
            binary: spec.binary,
            timeout: deadline.saturating_duration_since(std::time::Instant::now()),
            name: spec.name.clone(),
            store: Arc::clone(&*self.store.lock().unwrap()),
            max_heap: heap_limit,
            max_body: self.max_body,
        };
        let code = spec.code.clone();
        let host_max_body = self.max_body;
        let handle = tokio::runtime::Handle::current();
        let (routing, dns) = self
            .network
            .read()
            .unwrap()
            .clone()
            .map(|(r, d)| (Some(r), Some(d)))
            .unwrap_or((None, None));
        let (output,_permit)=tokio::task::spawn_blocking(move||{let result=oryn_script::run(code.as_str(),input,move |options|{
            if let Some(name)=options["control"].as_str(){return control(routing.as_deref(),name,&options).map(HostReply::Control)}
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
            let response=handle.block_on(oryn_http::fetch(&oryn_http::OutboundConnector(selected),req,&oryn_http::Options{max_body:host_max_body,timeout:deadline.saturating_duration_since(std::time::Instant::now()).min(Duration::from_secs(30)),max_redirects:3,skip_verify:false})).map_err(|e|e.to_string())?;
            let binary=options["binary-mode"].as_bool()==Some(true);
            let body=if binary{
                BodyData::Binary(response.body)
            }else{
                let text=match String::from_utf8(response.body){
                    Ok(s)=>s,
                    Err(e)=>String::from_utf8_lossy(e.as_bytes()).into_owned(),
                };
                BodyData::Text(text)
            };
            Ok(HostReply::Http(HttpReply{status:response.status,headers:response.headers.into_iter().collect(),body,binary}))
        });
        // 脚本堆在本线程分配，用完就把空页还给系统
        crate::alloc::trim();
        (result,permit)}).await.map_err(io::Error::other)?;
        let output = output.map_err(io::Error::other)?;
        if self.generation.load(std::sync::atomic::Ordering::Relaxed) != epoch {
            return Err(io::Error::other("script cancelled by reload"));
        }
        // 仅在发生写/删键时才拷贝持久存储并落盘，避免每次执行全量拷贝与写盘。
        if !output.store_delta.is_empty() {
            let snapshot = {
                let mut guard = self.store.lock().unwrap();
                let mut next = (**guard).clone();
                for (k, v) in output.store_delta {
                    match v {
                        Some(val) => {
                            next.insert(k, val);
                        }
                        None => {
                            next.remove(&k);
                        }
                    }
                }
                let total_bytes: usize = next.iter().map(|(k, v)| k.len() + v.len()).sum();
                if next.len() <= oryn_script::MAX_STORE_KEYS
                    && total_bytes <= oryn_script::MAX_STORE_BYTES
                {
                    let arc = Arc::new(next);
                    *guard = Arc::clone(&arc);
                    Some(arc)
                } else {
                    None
                }
            };
            if let (Some(store), Some(path)) = (snapshot, &self.path) {
                let bytes = serde_json::to_vec(&*store)?;
                let temp = path.with_extension("tmp");
                std::fs::write(&temp, bytes)?;
                std::fs::rename(temp, path)?;
            }
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
        let local = result.get("response").is_some();
        let returned_body = if local {
            output.response_body
        } else {
            output.body
        };
        let has_new_body = !matches!(returned_body, BodyData::None);
        let mut m = if local {
            result = result["response"].clone();
            request.response(
                result["status"].as_u64().unwrap_or(200) as u16,
                vec![],
                "text/plain",
            )
        } else {
            let meta = response.as_deref().unwrap_or(request);
            Message {
                url: meta.url.clone(),
                method: meta.method.clone(),
                status: meta.status,
                headers: meta.headers.clone(),
                body: Vec::new(),
            }
        };
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
        if !local && !has_new_body {
            let original = response.as_deref().unwrap_or(request);
            for key in ["Content-Length", "Transfer-Encoding"] {
                if m.header(key) != original.header(key) {
                    return Err(io::Error::other(
                        "script cannot change framing without body",
                    ));
                }
            }
        }
        if has_new_body {
            if !spec.requires_body && !local {
                return Err(io::Error::other(
                    "script returned body without requires-body",
                ));
            }
            m.body = match returned_body {
                BodyData::Text(s) => s.into_bytes(),
                BodyData::Binary(b) => b,
                BodyData::None => unreachable!(),
            };
            if m.body.len() > self.max_body {
                return Err(io::Error::other("script output body exceeds limit"));
            }
            m.delete_header("Content-Encoding");
            m.delete_header("Transfer-Encoding");
            m.set_header("Content-Length", m.body.len().to_string());
        }
        let policy = if response.is_none() && !local {
            take_script_policy(&result, &mut m)
        } else {
            strip_policy_headers(&mut m);
            None
        };
        if let Some(resp) = response {
            if !has_new_body && !local {
                m.body = std::mem::take(&mut resp.body);
            }
            *resp = m;
            Ok(ScriptDone {
                message: None,
                policy: None,
                body_modified: has_new_body || local,
            })
        } else {
            Ok(ScriptDone {
                message: Some(m),
                policy,
                body_modified: has_new_body || local,
            })
        }
    }
    /// 按策略组或节点名选出这条请求的叶子出站。名称必须与 `tag` 完全一致。
    pub fn policy_outbound(&self, policy: &str, host: &str, port: u16) -> io::Result<Arc<dyn Outbound>> {
        let guard = self.network.read().unwrap();
        let routing = guard.as_ref().map(|(routing, _)| routing).ok_or_else(|| io::Error::other("script policy routing is unavailable"))?;
        let index = routing.outbounds.iter().position(|outbound| outbound.tag() == policy).ok_or_else(|| io::Error::other(format!("unknown script policy {policy}")))?;
        let target = oryn_config::TargetAddr::from_host(host, port);
        oryn_outbound::resolve(&routing.outbounds[index], &oryn_outbound::PickMeta { source: None, target: &target, network: oryn_router::Network::Tcp })
            .map(|resolved| resolved.leaf)
            .ok_or_else(|| io::Error::other(format!("script policy {policy} rejected the connection")))
    }
}

fn body_for_script(message: &Message, max_size: usize, binary: bool) -> io::Result<BodyData> {
    let decoded = oryn_http_inspect::decode_body_cow(message, max_size)?;
    if binary {
        return Ok(BodyData::Binary(decoded.into_owned()));
    }
    let text = match decoded {
        Cow::Borrowed(slice) => String::from_utf8_lossy(slice).into_owned(),
        Cow::Owned(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        },
    };
    Ok(BodyData::Text(text))
}

const POLICY_HEADERS: &[&str] = &["X-Surge-Policy", "X-Surge-Proxy", "X-Stash-Selected-Proxy"];

fn strip_policy_headers(message: &mut Message) {
    for name in POLICY_HEADERS {
        message.delete_header(name);
    }
}

/// 请求脚本用 `policy` / `node`，或 Surge / Stash / Shadowrocket 的策略头指定出口。
fn take_script_policy(result: &Value, message: &mut Message) -> Option<String> {
    let named = result.get("policy").and_then(|v| v.as_str()).or_else(|| result.get("node").and_then(|v| v.as_str())).map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned);
    let header = POLICY_HEADERS.iter().find_map(|name| message.header(name).map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned));
    strip_policy_headers(message);
    named.or(header)
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
        if !*state.aux_cancel.borrow() {
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
        .take(state.scripts.max_scripts())
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
        .take(state.scripts.max_scripts())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_policy_comes_from_field_or_header_and_is_not_forwarded() {
        let mut message = Message {
            url: "http://api.bilibili.com/x".into(),
            method: "GET".into(),
            status: None,
            headers: vec![
                ("Host".into(), "api.bilibili.com".into()),
                ("X-Surge-Policy".into(), "🇭🇰香港".into()),
            ],
            body: vec![],
        };
        let from_field = json!({"policy": "DIRECT", "headers": {"X-Surge-Policy": "🇭🇰香港"}});
        assert_eq!(take_script_policy(&from_field, &mut message).as_deref(), Some("DIRECT"));
        assert!(message.header("X-Surge-Policy").is_none());
        assert_eq!(message.header("Host"), Some("api.bilibili.com"));

        message.set_header("X-Stash-Selected-Proxy", "🇹🇼台湾".to_owned());
        assert_eq!(take_script_policy(&json!({}), &mut message).as_deref(), Some("🇹🇼台湾"));
        assert!(message.header("X-Stash-Selected-Proxy").is_none());
        assert!(take_script_policy(&json!({"policy": "  "}), &mut message).is_none());
    }

    #[tokio::test]
    async fn bg_script_pool_does_not_block_http_script_pool() {
        struct DummyOutbound;
        #[async_trait::async_trait]
        impl Outbound for DummyOutbound {
            fn tag(&self) -> &str {
                "dummy"
            }
            fn kind(&self) -> &'static str {
                "reject"
            }
            async fn connect_tcp(
                &self,
                _target: &oryn_config::TargetAddr,
            ) -> io::Result<oryn_outbound::BoxStream> {
                Err(io::Error::other("unused"))
            }
            async fn bind_udp(
                &self,
                _first_target: &oryn_config::TargetAddr,
            ) -> io::Result<Box<dyn oryn_outbound::PacketConn>> {
                Err(io::Error::other("unused"))
            }
        }

        let host = Arc::new(ScriptHost::new_with_pools(
            None,
            1,
            1,
            oryn_script::HEAP_LIMIT,
            8 << 20,
            oryn_http_inspect::MAX_BODY,
            256,
        ));
        // 占满后台脚本槽位，模拟慢 cron/event `$httpClient` 正在运行。
        let _bg_busy = host.bg_slots.clone().acquire_owned().await.unwrap();
        assert!(host.bg_slots.try_acquire().is_err());

        let http_spec = ScriptRule {
            enabled: true,
            event: None,
            cron: None,
            name: "fast_http".into(),
            kind: "http-response".into(),
            condition: oryn_http_inspect::Condition::Always,
            source: "test".into(),
            code: r#"$done({body: '{"ok":true}'});"#.into(),
            argument: Value::Null,
            env: Arc::new(BTreeMap::new()),
            requires_body: true,
            binary: false,
            full_headers: false,
            timeout: 2,
            max_size: oryn_http_inspect::MAX_BODY,
            dialect: oryn_module::ModuleFormat::Surge,
        };
        let req = Message {
            url: "https://example.test/api".into(),
            method: "GET".into(),
            status: None,
            headers: vec![],
            body: vec![],
        };
        let mut resp = Message {
            url: req.url.clone(),
            method: "GET".into(),
            status: Some(200),
            headers: vec![],
            body: br#"{"ok":false}"#.to_vec(),
        };
        let done = host
            .execute(&http_spec, &req, Some(&mut resp), Arc::new(DummyOutbound))
            .await
            .expect("http script must not be blocked by busy bg pool");
        assert!(done.body_modified);
        assert_eq!(resp.body, br#"{"ok":true}"#);
    }
}
