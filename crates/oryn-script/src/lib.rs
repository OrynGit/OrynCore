//! 每次执行独立 QuickJS 上下文；无文件、进程、Socket 模块，内存/栈/时间均有硬上限。
use rquickjs::{Context, IntoJs, Runtime};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

mod bytecode;
pub use bytecode::{set_cache_dir as set_bytecode_cache_dir, COMPILE_HEAP_LIMIT};

/// 纯解析校验堆上限（超出时编译成字节码缓存，执行时只加载字节码以降低运行时内存）。
pub const PARSE_HEAP_LIMIT: usize = 8 * 1024 * 1024;
/// 默认脚本执行堆上限（16 MiB；桌面档可由调用方放大）。
pub const HEAP_LIMIT: usize = 16 * 1024 * 1024;
/// 脚本源码上限（4 MiB）。
pub const MAX_SCRIPT_BYTES: usize = 4 * 1024 * 1024;
/// 默认正文与 `$httpClient` 响应正文上限（4 MiB）。
pub const DEFAULT_MAX_BODY: usize = 4 * 1024 * 1024;
/// `$persistentStore` 全局总容量（2 MiB）、单键值上限（256 KiB）与键数量上限（1024）。
pub const MAX_STORE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_STORE_VALUE_BYTES: usize = 256 * 1024;
pub const MAX_STORE_KEYS: usize = 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum BodyData {
    #[default]
    None,
    Text(String),
    Binary(Vec<u8>),
}

impl BodyData {
    pub fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Text(s) => s.len(),
            Self::Binary(b) => b.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct HttpReply {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: BodyData,
    pub binary: bool,
}

pub enum HostReply {
    Control(Value),
    Http(HttpReply),
}

pub struct Input {
    pub cancellation: Option<(Arc<std::sync::atomic::AtomicU64>, u64)>,
    pub event: Value,
    pub cron: Option<String>,
    pub kind: String,
    pub loon: bool,
    pub request: Value,
    pub response: Value,
    pub request_body: BodyData,
    pub response_body: BodyData,
    pub argument: Value,
    pub env: Arc<BTreeMap<String, String>>,
    pub binary: bool,
    pub timeout: Duration,
    pub name: String,
    pub store: Arc<BTreeMap<String, String>>,
    pub max_heap: usize,
    pub max_body: usize,
}

pub struct Output {
    pub result: Value,
    pub body: BodyData,
    pub response_body: BodyData,
    pub store_delta: BTreeMap<String, Option<String>>,
    pub logs: Vec<String>,
    pub notifications: Vec<Value>,
}

struct StoreOverlay {
    base: Arc<BTreeMap<String, String>>,
    delta: BTreeMap<String, Option<String>>,
    key_count: usize,
    total_bytes: usize,
}

impl StoreOverlay {
    fn new(base: Arc<BTreeMap<String, String>>) -> Self {
        let key_count = base.len();
        let total_bytes = base.iter().map(|(k, v)| k.len() + v.len()).sum();
        Self {
            base,
            delta: BTreeMap::new(),
            key_count,
            total_bytes,
        }
    }

    fn read(&self, key: &str) -> Option<String> {
        match self.delta.get(key) {
            Some(Some(v)) => Some(v.clone()),
            Some(None) => None,
            None => self.base.get(key).cloned(),
        }
    }

    fn write(&mut self, key: String, val: Option<String>) -> bool {
        if key.len() > 256 {
            return false;
        }
        let current = match self.delta.get(&key) {
            Some(Some(v)) => Some(v.as_str()),
            Some(None) => None,
            None => self.base.get(&key).map(String::as_str),
        };
        let (exists, old_bytes) = match current {
            Some(v) => (true, key.len() + v.len()),
            None => (false, 0),
        };
        match val {
            None => {
                if !exists {
                    return true;
                }
                self.key_count -= 1;
                self.total_bytes = self.total_bytes.saturating_sub(old_bytes);
                if self.base.contains_key(&key) {
                    self.delta.insert(key, None);
                } else {
                    self.delta.remove(&key);
                }
                true
            }
            Some(new_val) => {
                if new_val.len() > MAX_STORE_VALUE_BYTES {
                    return false;
                }
                if current == Some(new_val.as_str()) {
                    return true;
                }
                let new_keys = if exists { self.key_count } else { self.key_count + 1 };
                let new_bytes = self.total_bytes - old_bytes + key.len() + new_val.len();
                if new_keys > MAX_STORE_KEYS || new_bytes > MAX_STORE_BYTES {
                    return false;
                }
                self.key_count = new_keys;
                self.total_bytes = new_bytes;
                if self.base.get(&key).map(String::as_str) == Some(new_val.as_str()) {
                    self.delta.remove(&key);
                } else {
                    self.delta.insert(key, Some(new_val));
                }
                true
            }
        }
    }
}

struct DoneCapture {
    result: Value,
    body: BodyData,
    response_body: BodyData,
}

fn body_to_js<'js>(ctx: &rquickjs::Ctx<'js>, body: BodyData) -> rquickjs::Result<rquickjs::Value<'js>> {
    match body {
        BodyData::None => Ok(rquickjs::Value::new_undefined(ctx.clone())),
        BodyData::Text(s) => s.into_js(ctx),
        BodyData::Binary(bytes) => rquickjs::TypedArray::<u8>::new(ctx.clone(), bytes)?.into_js(ctx),
    }
}

fn extract_body<'js>(val: rquickjs::Value<'js>, max_body: usize) -> rquickjs::Result<BodyData> {
    if val.is_undefined() || val.is_null() {
        return Ok(BodyData::None);
    }
    if let Some(s) = val.as_string() {
        let s = s.to_string()?;
        if s.len() > max_body {
            return Err(rquickjs::Error::new_from_js_message(
                "body",
                "string",
                "script output body exceeds limit",
            ));
        }
        return Ok(BodyData::Text(s));
    }
    if let Some(ta) = val.as_object().and_then(|o| o.as_typed_array::<u8>()) {
        let bytes = unsafe { ta.as_bytes() }.ok_or_else(conversion_error)?;
        if bytes.len() > max_body {
            return Err(rquickjs::Error::new_from_js_message(
                "body",
                "Uint8Array",
                "script output body exceeds limit",
            ));
        }
        return Ok(BodyData::Binary(bytes.to_vec()));
    }
    if let Some(arr) = val.as_array() {
        let len = arr.len();
        if len > max_body {
            return Err(rquickjs::Error::new_from_js_message(
                "body",
                "bytes",
                "script output body exceeds limit",
            ));
        }
        let mut out = Vec::with_capacity(len);
        for item in arr.iter::<u32>() {
            let n = item.map_err(|_| {
                rquickjs::Error::new_from_js_message("body", "u8", "invalid script body byte")
            })?;
            let b = u8::try_from(n).map_err(|_| {
                rquickjs::Error::new_from_js_message("body", "u8", "invalid script body byte")
            })?;
            out.push(b);
        }
        return Ok(BodyData::Binary(out));
    }
    Err(rquickjs::Error::new_from_js_message(
        val.type_name(),
        "string|Uint8Array",
        "script body is not string/bytes",
    ))
}

/// 网络通过调用方给定的 Router/Outbound 适配器，脚本本身没有任何 I/O 能力。
pub fn run(
    code: &str,
    mut input: Input,
    http: impl FnMut(Value) -> Result<HostReply, String> + 'static,
) -> Result<Output, String> {
    if code.len() > MAX_SCRIPT_BYTES {
        return Err("script exceeds 4 MiB".into());
    }
    let heap_limit = if input.max_heap > 0 {
        input.max_heap
    } else {
        HEAP_LIMIT
    };
    let max_body = if input.max_body > 0 {
        input.max_body
    } else {
        DEFAULT_MAX_BODY
    };
    let runtime = Runtime::new().map_err(|e| e.to_string())?;
    runtime.set_memory_limit(heap_limit);
    runtime.set_max_stack_size(256 * 1024);
    let end = Instant::now() + input.timeout.min(Duration::from_secs(300));
    let cancellation = input.cancellation.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        Instant::now() >= end
            || cancellation
                .as_ref()
                .is_some_and(|(v, n)| v.load(std::sync::atomic::Ordering::Relaxed) != *n)
    })));
    let http = Rc::new(RefCell::new(http));
    let store_overlay = Rc::new(RefCell::new(StoreOverlay::new(Arc::clone(&input.store))));
    let done_capture: Rc<RefCell<Option<DoneCapture>>> = Rc::new(RefCell::new(None));
    let context = Context::full(&runtime).map_err(|e| e.to_string())?;

    let initial_meta = serde_json::json!({
        "event": input.event,
        "cron": input.cron,
        "kind": input.kind,
        "loon": input.loon,
        "request": input.request,
        "response": input.response,
        "argument": input.argument,
        "env": &*input.env,
        "binary": input.binary,
        "name": input.name,
    })
    .to_string();
    let req_body = std::mem::take(&mut input.request_body);
    let res_body = std::mem::take(&mut input.response_body);

    let setup_and_eval = context.with(|ctx| -> Result<(), String> {
        let handler = http.clone();
        let host = rquickjs::Function::new(ctx.clone(), move |text: String| -> String {
            let result = serde_json::from_str(&text)
                .map_err(|e| e.to_string())
                .and_then(|v| (handler.borrow_mut())(v));
            match result {
                Ok(HostReply::Control(v)) => v.to_string(),
                Ok(HostReply::Http(r)) => serde_json::json!({
                    "response": {"status": r.status, "headers": r.headers}
                })
                .to_string(),
                Err(e) => serde_json::json!({"error": e}).to_string(),
            }
        })
        .map_err(|e| e.to_string())?;
        ctx.globals()
            .set("__host", host)
            .map_err(|e| e.to_string())?;

        let done_slot = done_capture.clone();
        let finish = rquickjs::Function::new(
            ctx.clone(),
            move |meta_json: String,
                  body_val: rquickjs::Value<'_>,
                  resp_body_val: rquickjs::Value<'_>|
                  -> rquickjs::Result<()> {
                let result: Value = serde_json::from_str(&meta_json).map_err(|e| {
                    rquickjs::Error::new_from_js_message("meta", "json", e.to_string())
                })?;
                let body = extract_body(body_val, max_body)?;
                let response_body = extract_body(resp_body_val, max_body)?;
                *done_slot.borrow_mut() = Some(DoneCapture {
                    result,
                    body,
                    response_body,
                });
                Ok(())
            },
        )
        .map_err(|e| e.to_string())?;
        ctx.globals()
            .set("__finish", finish)
            .map_err(|e| e.to_string())?;

        let store_r = store_overlay.clone();
        ctx.globals()
            .set(
                "__store_read",
                rquickjs::Function::new(ctx.clone(), move |k: String| -> Option<String> {
                    store_r.borrow().read(&k)
                })
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;

        let store_w = store_overlay.clone();
        ctx.globals()
            .set(
                "__store_write",
                rquickjs::Function::new(
                    ctx.clone(),
                    move |k: String, v: Option<String>| -> bool { store_w.borrow_mut().write(k, v) },
                )
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;

        ctx.globals()
            .set(
                "__utf8encode",
                rquickjs::Function::new(ctx.clone(), move |ctx, text| {
                    utf8_encode(ctx, text, max_body)
                })
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        ctx.globals()
            .set(
                "__utf8decode",
                rquickjs::Function::new(ctx.clone(), move |data, fatal| {
                    utf8_decode(data, fatal, max_body)
                })
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        ctx.globals()
            .set(
                "__ungzip",
                rquickjs::Function::new(ctx.clone(), move |ctx, data| ungzip(ctx, data, max_body))
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        ctx.globals()
            .set(
                "__gzip",
                rquickjs::Function::new(ctx.clone(), move |ctx, data| gzip_bytes(ctx, data, max_body))
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        let max_b64 = max_body.saturating_mul(2);
        ctx.globals()
            .set(
                "__base64",
                rquickjs::Function::new(ctx.clone(), move |text, encode| {
                    base64_text(text, encode, max_b64)
                })
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        ctx.globals()
            .set(
                "__b64_bytes",
                rquickjs::Function::new(ctx.clone(), move |data| base64_bytes(data, max_body))
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;

        ctx.globals()
            .set("__input", initial_meta)
            .map_err(|e| e.to_string())?;
        if !matches!(req_body, BodyData::None) {
            let v = body_to_js(&ctx, req_body).map_err(|e| e.to_string())?;
            ctx.globals()
                .set("__req_body", v)
                .map_err(|e| e.to_string())?;
        }
        if !matches!(res_body, BodyData::None) {
            let v = body_to_js(&ctx, res_body).map_err(|e| e.to_string())?;
            ctx.globals()
                .set("__res_body", v)
                .map_err(|e| e.to_string())?;
        }

        ctx.eval::<(), _>(include_str!("runtime.js"))
            .map_err(|e| format!("script bootstrap: {e}"))?;
        // 加载模块时已为大脚本缓存字节码，执行时不再解析源码。
        // 字节码读不进来（损坏或版本不符）时删掉缓存并回退源码执行。
        match bytecode::cached(code).map(|bytes| bytecode::eval(&ctx, &bytes)) {
            Some(bytecode::Eval::Ran(result)) => result,
            Some(bytecode::Eval::Unreadable) => {
                bytecode::discard(code);
                ctx.eval::<(), _>(code)
            }
            None => ctx.eval::<(), _>(code),
        }
        .map_err(|e| format!("script execution: {e}; {:?}", ctx.catch()))
    });
    setup_and_eval?;

    loop {
        if Instant::now() >= end
            || input
                .cancellation
                .as_ref()
                .is_some_and(|(v, n)| v.load(std::sync::atomic::Ordering::Relaxed) != *n)
        {
            return Err("script execution timed out".into());
        }
        while runtime.is_job_pending() {
            runtime
                .execute_pending_job()
                .map_err(|_| "script promise failed")?;
            if Instant::now() >= end {
                return Err("script execution timed out".into());
            }
        }
        let poll_json = context
            .with(|ctx| -> rquickjs::Result<String> {
                let poll: rquickjs::Function = ctx.globals().get("__poll")?;
                poll.call(())
            })
            .map_err(|e| e.to_string())?;
        let state: Value = serde_json::from_str(&poll_json).map_err(|e| e.to_string())?;
        if state["done"].as_bool() == Some(true) {
            let logs_json = context
                .with(|ctx| -> rquickjs::Result<String> {
                    let take_logs: rquickjs::Function = ctx.globals().get("__take_logs")?;
                    take_logs.call(())
                })
                .map_err(|e| e.to_string())?;
            let aux: Value = serde_json::from_str(&logs_json).map_err(|e| e.to_string())?;
            let logs: Vec<String> =
                serde_json::from_value(aux["logs"].clone()).map_err(|e| e.to_string())?;
            let notifications = aux["notifications"].as_array().cloned().unwrap_or_default();
            // 先销毁 JS 上下文以释放闭包与 ArrayBuffer，再取回捕获结果与增量存储。
            drop(context);
            drop(runtime);
            let captured = done_capture
                .borrow_mut()
                .take()
                .ok_or_else(|| "script finished without payload".to_string())?;
            let store_delta = std::mem::take(&mut store_overlay.borrow_mut().delta);
            return Ok(Output {
                result: captured.result,
                body: captured.body,
                response_body: captured.response_body,
                store_delta,
                logs,
                notifications,
            });
        }
        if let Some(command) = state["request"].as_object() {
            let id = command["id"]
                .as_u64()
                .ok_or("invalid script HTTP request")?;
            let (meta_json, reply_body) = match (http.borrow_mut())(command["options"].clone()) {
                Ok(HostReply::Control(v)) => (v.to_string(), BodyData::None),
                Ok(HostReply::Http(reply)) => (
                    serde_json::json!({
                        "response": {"status": reply.status, "headers": reply.headers},
                        "binary": reply.binary
                    })
                    .to_string(),
                    reply.body,
                ),
                Err(e) => (serde_json::json!({"error": e}).to_string(), BodyData::None),
            };
            context
                .with(|ctx| -> rquickjs::Result<()> {
                    let deliver: rquickjs::Function = ctx.globals().get("__deliver")?;
                    let js_body = body_to_js(&ctx, reply_body)?;
                    deliver.call::<_, ()>((id, meta_json, js_body))
                })
                .map_err(|e| format!("script HTTP callback: {e}"))?;
        } else {
            let pending_job = runtime.is_job_pending();
            match state["next"].as_u64() {
                // 没有定时器、没有在途请求、也没有待执行的 Promise：脚本不可能再调用 $done。
                None if !pending_job && state["pending"].as_bool() != Some(true) => {
                    return Err("script ended without calling $done".into());
                }
                // 按最近定时器的到期时间休眠，不再 1 ms 空转；上限 20 ms 以便及时响应取消。
                next => {
                    let wait = Duration::from_millis(next.unwrap_or(20).min(20));
                    let wait = wait.min(end.saturating_duration_since(Instant::now()));
                    if !wait.is_zero() && !pending_job {
                        std::thread::sleep(wait);
                    }
                }
            }
            context
                .with(|ctx| -> rquickjs::Result<()> {
                    let timers: rquickjs::Function = ctx.globals().get("__timers")?;
                    timers.call(())
                })
                .map_err(|e| e.to_string())?;
        }
    }
}

/// 只编译语法，不执行模块代码或提供任何 I/O。超出体积或解析堆上限返回
/// `Unsupported`（加载方可只跳过该脚本），语法错误返回 `InvalidData`。
/// 设置了字节码缓存目录时，解析堆内解析不了的大脚本改用编译堆生成字节码。
pub fn validate(code: &str) -> std::io::Result<()> {
    if code.len() > MAX_SCRIPT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "script exceeds size limit",
        ));
    }
    if bytecode::cached(code).is_some() {
        return Ok(());
    }
    match parse(code) {
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            if bytecode::ensure(code)? {
                Ok(())
            } else {
                Err(e)
            }
        }
        other => other,
    }
}

fn parse(code: &str) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    let budget = |what: &str| Error::new(ErrorKind::Unsupported, format!("script exceeds {what}"));
    let rt = Runtime::new().map_err(Error::other)?;
    rt.set_memory_limit(PARSE_HEAP_LIMIT);
    rt.set_max_stack_size(256 * 1024);
    let ctx = Context::full(&rt).map_err(Error::other)?;
    ctx.with(|ctx| {
        ctx.globals().set("source", code).map_err(Error::other)?;
        match ctx.eval::<rquickjs::Function, _>("new Function(source)") {
            Ok(_) => Ok(()),
            Err(rquickjs::Error::Exception) => {
                // 内存耗尽时 QuickJS 可能连异常对象都分配不了，取到的是 null。
                let caught = ctx.catch();
                let message = caught
                    .as_exception()
                    .and_then(|e| e.message())
                    .unwrap_or_else(|| "out of memory".into());
                if message.contains("out of memory") || message.contains("stack overflow") {
                    Err(budget("the 8 MiB script heap"))
                } else {
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("JavaScript syntax: {message}"),
                    ))
                }
            }
            Err(e) => Err(Error::new(
                ErrorKind::InvalidData,
                format!("JavaScript syntax: {e}"),
            )),
        }
    })
}

fn conversion_error() -> rquickjs::Error {
    rquickjs::Error::new_from_js_message("script data", "UTF-8/bytes", "invalid input or size limit")
}

fn utf8_encode<'js>(
    ctx: rquickjs::Ctx<'js>,
    text: String,
    max_body: usize,
) -> rquickjs::Result<rquickjs::TypedArray<'js, u8>> {
    if text.len() > max_body {
        return Err(conversion_error());
    }
    rquickjs::TypedArray::new(ctx, text.into_bytes())
}

fn utf8_decode(
    data: rquickjs::TypedArray<'_, u8>,
    fatal: bool,
    max_body: usize,
) -> rquickjs::Result<String> {
    // 安全：独立单线程 runtime，借用期间不执行 JS 或改变/detach ArrayBuffer。
    let bytes = unsafe { data.as_bytes() }.ok_or_else(conversion_error)?;
    if bytes.len() > max_body {
        return Err(conversion_error());
    }
    if fatal {
        String::from_utf8(bytes.to_vec()).map_err(|_| conversion_error())
    } else {
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

fn ungzip<'js>(
    ctx: rquickjs::Ctx<'js>,
    data: rquickjs::TypedArray<'js, u8>,
    max_body: usize,
) -> rquickjs::Result<rquickjs::TypedArray<'js, u8>> {
    use std::io::Read; // 安全：独立单线程 runtime，借用期间不执行 JS 或改变/detach ArrayBuffer。
    let bytes = unsafe { data.as_bytes() }.ok_or_else(conversion_error)?;
    let mut out = vec![];
    flate2::read::GzDecoder::new(bytes)
        .take(max_body as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| conversion_error())?;
    if out.len() > max_body {
        return Err(conversion_error());
    }
    rquickjs::TypedArray::new(ctx, out)
}

fn gzip_bytes<'js>(
    ctx: rquickjs::Ctx<'js>,
    data: rquickjs::TypedArray<'js, u8>,
    max_body: usize,
) -> rquickjs::Result<rquickjs::TypedArray<'js, u8>> {
    use std::io::Write;
    let bytes = unsafe { data.as_bytes() }.ok_or_else(conversion_error)?;
    if bytes.len() > max_body {
        return Err(conversion_error());
    }
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes).map_err(|_| conversion_error())?;
    let out = enc.finish().map_err(|_| conversion_error())?;
    if out.len() > max_body {
        return Err(conversion_error());
    }
    rquickjs::TypedArray::new(ctx, out)
}

fn base64_bytes(data: rquickjs::TypedArray<'_, u8>, max_body: usize) -> rquickjs::Result<String> {
    use base64::Engine as _;
    let bytes = unsafe { data.as_bytes() }.ok_or_else(conversion_error)?;
    if bytes.len() > max_body {
        return Err(conversion_error());
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn base64_text(text: String, encode: bool, max_chars: usize) -> rquickjs::Result<String> {
    use base64::Engine as _;
    if text.len() > max_chars {
        return Err(conversion_error());
    }
    let b = base64::engine::general_purpose::STANDARD;
    if encode {
        let bytes = text
            .chars()
            .map(|c| u8::try_from(c as u32).map_err(|_| conversion_error()))
            .collect::<rquickjs::Result<Vec<_>>>()?;
        Ok(b.encode(bytes))
    } else {
        let raw = text
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>();
        let config = base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);
        let decoder = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, config);
        let bytes = decoder.decode(raw).map_err(|_| conversion_error())?;
        Ok(bytes.into_iter().map(char::from).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Input {
        Input {
            cancellation: None,
            event: Value::Null,
            cron: None,
            kind: "http-response".into(),
            loon: false,
            request: serde_json::json!({"url":"https://example.test","headers":{}}),
            response: serde_json::json!({"status":200}),
            request_body: BodyData::None,
            response_body: BodyData::Text(r#"{"ok":false}"#.into()),
            argument: Value::Null,
            env: Default::default(),
            binary: false,
            timeout: Duration::from_millis(200),
            name: "test".into(),
            store: Default::default(),
            max_heap: 0,
            max_body: 0,
        }
    }

    #[test]
    fn callbacks_and_storage() {
        let out = run(
            r#"$httpClient.get('https://fixture.test',(e,r,d)=>{$persistentStore.write(d,'key');$done({body:JSON.stringify({ok:r.status===200})});});"#,
            input(),
            |_| {
                Ok(HostReply::Http(HttpReply {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: BodyData::Text("value".into()),
                    binary: false,
                }))
            },
        )
        .unwrap();
        assert_eq!(out.body, BodyData::Text(r#"{"ok":true}"#.into()));
        assert_eq!(out.store_delta.get("key"), Some(&Some("value".into())));
    }

    #[test]
    fn http_client_binary_delivers_uint8array() {
        let mut i = input();
        i.request_body = BodyData::None;
        i.response_body = BodyData::None;
        let out = run(
            r#"$httpClient.get({url:'https://fixture.test', 'binary-mode': true},(e,r,d)=>{
                if(!(d instanceof Uint8Array)) throw Error('not uint8array');
                d[0] = 0x5a;
                $done({body: d});
            });"#,
            i,
            |opts| {
                assert_eq!(opts["binary-mode"], true);
                Ok(HostReply::Http(HttpReply {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: BodyData::Binary(vec![0x11, 0x22, 0x33]),
                    binary: true,
                }))
            },
        )
        .unwrap();
        assert_eq!(out.body, BodyData::Binary(vec![0x5a, 0x22, 0x33]));
        assert!(out.store_delta.is_empty());
    }

    #[test]
    fn four_mib_binary_round_trip() {
        let size = 4 * 1024 * 1024;
        let mut payload = vec![0x2au8; size];
        payload[0] = 0x01;
        payload[size - 1] = 0x02;
        let mut i = input();
        i.binary = true;
        i.timeout = Duration::from_secs(5);
        i.response_body = BodyData::Binary(payload);
        let out = run(
            r#"const b = $response.body;
               if (!(b instanceof Uint8Array) || b.length !== 4194304) throw Error('bad len');
               b[0] = 0x99;
               $done({body: b});"#,
            i,
            |_| unreachable!(),
        )
        .unwrap();
        let BodyData::Binary(res) = out.body else {
            panic!("expected binary output");
        };
        assert_eq!(res.len(), size);
        assert_eq!((res[0], res[size - 1]), (0x99, 0x02));
    }

    #[test]
    fn store_overlay_reads_deletes_and_enforces_bounds() {
        let base = Arc::new(BTreeMap::from([
            ("existing".into(), "alpha".into()),
            ("keep".into(), "beta".into()),
        ]));
        let mut i = input();
        i.store = base;
        let out = run(
            r#"
            const missing = $persistentStore.read('absent');
            if (missing !== null) throw Error('missing must be null');
            if ($persistentStore.read('existing') !== 'alpha') throw Error('bad existing');
            $persistentStore.write('gamma', 'added');
            $persistentStore.write(null, 'existing');
            // 超过 256 KiB 单键限制应拒绝
            const tooBig = 'x'.repeat(256 * 1024 + 1);
            if ($persistentStore.write(tooBig, 'big') !== false) throw Error('oversize should fail');
            $done({body: 'ok'});
            "#,
            i,
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(out.body, BodyData::Text("ok".into()));
        assert_eq!(out.store_delta.get("added"), Some(&Some("gamma".into())));
        assert_eq!(out.store_delta.get("existing"), Some(&None));
        assert!(!out.store_delta.contains_key("keep"));
        assert!(!out.store_delta.contains_key("big"));
    }

    #[test]
    fn utf8_ungzip_base64_support_up_to_max_body() {
        let size = 1536 * 1024;
        let payload = vec![b'a'; size];
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &payload).unwrap();
        let compressed = gz.finish().unwrap();
        let mut i = input();
        i.timeout = Duration::from_secs(5);
        i.binary = true;
        i.response_body = BodyData::Binary(compressed);
        let out = run(
            r#"
            const raw = $utils.ungzip($response.body);
            const txt = new TextDecoder().decode(raw);
            const enc = new TextEncoder().encode(txt);
            const b64 = btoa('hello');
            if (atob(b64) !== 'hello') throw Error('b64');
            $done({body: enc});
            "#,
            i,
            |_| unreachable!(),
        )
        .unwrap();
        let BodyData::Binary(res) = out.body else {
            panic!("expected binary");
        };
        assert_eq!(res.len(), size);
    }

    #[test]
    fn module_env_in_ctx() {
        let mut i = input();
        let mut env = BTreeMap::new();
        env.insert("TOKEN".into(), "abc".into());
        i.env = Arc::new(env);
        let out = run(
            r#"$done({body:ctx.env.TOKEN+(ctx.env.MISSING===undefined)})"#,
            i,
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(out.body, BodyData::Text("abctrue".into()));
    }

    #[test]
    fn script_cannot_replace_host_protocol() {
        let out = run(
            r#"try{__poll=()=>'forged';}catch(e){}
               $done({body:String(typeof __host)+String(typeof __finish)+String(typeof __input)})"#,
            input(),
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(
            out.body,
            BodyData::Text("undefinedundefinedundefined".into())
        );
    }

    #[test]
    fn idle_script_without_done_fails_fast() {
        let mut i = input();
        i.timeout = Duration::from_secs(5);
        let start = Instant::now();
        assert!(run("let x = 1;", i, |_| unreachable!()).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn timers_fire_without_busy_loop() {
        let mut i = input();
        i.timeout = Duration::from_secs(2);
        let out = run(
            "setTimeout(()=>$done({body:'late'}),50);",
            i,
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(out.body, BodyData::Text("late".into()));
    }

    #[test]
    fn runaway_is_interrupted() {
        assert!(run("while(true){}", input(), |_| unreachable!()).is_err());
    }

    /// QuickJS 改走 Rust 分配器（`rust-alloc`）后，执行堆上限仍然生效。
    #[test]
    fn heap_limit_still_enforced() {
        let mut i = input();
        i.timeout = Duration::from_secs(2);
        let code = "const a = []; while (true) { a.push('x'.repeat(65536) + a.length); }";
        assert!(run(code, i, |_| unreachable!()).is_err());
        let ok = run(
            "const s = 'x'.repeat(1 << 20); $done({body: String(s.length)});",
            input(),
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(ok.body, BodyData::Text("1048576".into()));
    }

    #[test]
    fn no_host_filesystem() {
        let out = run("$done({body:typeof require});", input(), |_| unreachable!()).unwrap();
        assert_eq!(out.body, BodyData::Text("undefined".into()));
    }

    #[test]
    fn text_binary_headers_and_base64() {
        let mut i = input();
        i.request["headers"] = serde_json::json!({"Content-Type":"application/json"});
        let out = run(
            r#"
            const text = '中文🙂';
            const decoded = new TextDecoder().decode(new TextEncoder().encode(text));
            $request.headers['content-type'] = 'text/plain';
            $done({decoded, bytes:atob(btoa('A\xff')), header:$request.headers['CONTENT-TYPE'], keys:Object.keys($request.headers).length});
        "#,
            i,
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(out.result["decoded"], "中文🙂");
        assert_eq!(out.result["bytes"], "Aÿ");
        assert_eq!(out.result["header"], "text/plain");
        assert_eq!(out.result["keys"], 1);
    }

    #[test]
    fn loon_bare_done_aborts_but_empty_object_passes() {
        let mut i = input();
        i.kind = "http-request".into();
        i.loon = true;
        assert_eq!(
            run("$done();", i, |_| unreachable!()).unwrap().result["abort"],
            true
        );
        let mut i = input();
        i.kind = "http-request".into();
        i.loon = true;
        assert_eq!(
            run("$done({});", i, |_| unreachable!()).unwrap().result,
            serde_json::json!({})
        );
    }

    #[test]
    fn reload_interrupts_running_script() {
        let epoch = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut i = input();
        i.timeout = Duration::from_secs(5);
        i.cancellation = Some((epoch.clone(), 0));
        let worker = std::thread::spawn(move || run("while(true){}", i, |_| unreachable!()));
        std::thread::sleep(Duration::from_millis(20));
        epoch.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(worker.join().unwrap().is_err());
    }

    #[test]
    fn compat_globals_url_bodybytes_statuscode_and_gzip() {
        // 1. Surge 请求脚本不应在 globalThis 挂载 $loon / $response / $argument
        let mut req_input = input();
        req_input.kind = "http-request".into();
        req_input.loon = false;
        req_input.response = Value::Null;
        req_input.response_body = BodyData::None;
        req_input.argument = Value::Null;
        let out = run(
            r#"
            if ('$loon' in globalThis) throw Error('polluted $loon');
            if ('$response' in globalThis) throw Error('polluted $response');
            if ('$argument' in globalThis) throw Error('polluted $argument');
            if (typeof $script.startTime !== 'number' || $script.startTime <= 0) throw Error('bad startTime');
            if (!$environment['surge-version'] || !$environment.system) throw Error('bad env');
            console.info('info');
            console.debug('debug');
            const u = new URL('https://api.example.com:443/v1/feed?a=1&b=two');
            if (u.host !== 'api.example.com' || u.searchParams.get('b') !== 'two') throw Error('bad URL');
            u.searchParams.set('c', '3');
            u.searchParams.delete('a');
            if (u.href !== 'https://api.example.com/v1/feed?b=two&c=3') throw Error('bad mutated URL: ' + u.href);
            const rel = new URL('/v2/ok?x=1', u);
            if (rel.href !== 'https://api.example.com/v2/ok?x=1') throw Error('bad relative URL');
            const gz = $utils.gzip(new TextEncoder().encode('hello-oryn'));
            const dec = new TextDecoder().decode($utils.ungzip(gz));
            if (dec !== 'hello-oryn') throw Error('bad gzip roundtrip');
            $done({url: u.href, body: null});
            "#,
            req_input,
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(out.result["url"], "https://api.example.com/v1/feed?b=two&c=3");
        assert_eq!(out.body, BodyData::None);

        // 2. 二进制 bodyBytes + statusCode + 二进制 $httpClient POST
        let mut bin_input = input();
        bin_input.binary = true;
        bin_input.response_body = BodyData::Binary(vec![1, 2, 3]);
        let out = run(
            r#"
            if ($response.statusCode !== 200) throw Error('bad statusCode');
            if (!($response.bodyBytes instanceof Uint8Array) || $response.bodyBytes[1] !== 2) throw Error('bad bodyBytes');
            $httpClient.post({url: 'https://fixture.test/bin', 'binary-mode': true, bodyBytes: new Uint8Array([9, 8])}, (err, resp, data) => {
                if (resp.statusCode !== 201 || !(resp.bodyBytes instanceof Uint8Array)) throw Error('bad httpClient binary');
                $done({bodyBytes: new Uint8Array([7, 6, 5])});
            });
            "#,
            bin_input,
            |opts| {
                assert_eq!(opts["body_base64"], "CQg=");
                Ok(HostReply::Http(HttpReply {
                    status: 201,
                    headers: BTreeMap::new(),
                    body: BodyData::Binary(vec![0xaa, 0xbb]),
                    binary: true,
                }))
            },
        )
        .unwrap();
        assert_eq!(out.body, BodyData::Binary(vec![7, 6, 5]));
        assert!(out.result.get("bodyBytes").is_none());
    }
}

#[cfg(test)]
mod third_party {
    use super::*;

    #[test]
    fn maasea_weread_changes_only_profile_fields() {
        let code = include_str!("../../../Tests/Fixtures/modules/maasea/weread.js");
        let input = Input {
            cancellation: None,
            event: Value::Null,
            cron: None,
            kind: "http-response".into(),
            loon: false,
            request: serde_json::json!({"url":"https://i.weread.qq.com/user/profile"}),
            response: serde_json::json!({}),
            request_body: BodyData::None,
            response_body: BodyData::Text(r#"{"showMedal":1,"keep":42}"#.into()),
            argument: Value::Null,
            env: Default::default(),
            binary: false,
            timeout: Duration::from_secs(1),
            name: "WeRead".into(),
            store: Default::default(),
            max_heap: 0,
            max_body: 0,
        };
        let out = run(code, input, |_| Err("network disabled in fixture".into())).unwrap();
        let BodyData::Text(text) = out.body else {
            panic!("expected text body");
        };
        let body: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["showMedal"], 0);
        assert_eq!(body["keep"], 42);
    }
}

#[cfg(test)]
mod large_scripts {
    use super::*;

    /// 约 600 KiB、解析时需要超过 8 MiB 堆的脚本：大量小函数。
    fn large_script() -> String {
        let mut code = String::from("var total = 0;\n");
        for i in 0..12000 {
            code.push_str(&format!(
                "function f{i}(a){{return a+{i}}}\ntotal=f{i}(total);\n"
            ));
        }
        code.push_str("$done({body:String(total)});\n");
        code
    }

    #[test]
    fn large_script_runs_from_cached_bytecode() {
        let code = large_script();
        assert!(code.len() > 128 * 1024);
        assert_eq!(
            parse(&code).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported,
            "fixture must exceed the execution heap"
        );
        let dir = std::env::temp_dir().join(format!("oryn-bytecode-{}", std::process::id()));
        set_bytecode_cache_dir(Some(dir.clone()));
        validate(&code).unwrap();
        assert!(bytecode::cached(&code).is_some());
        let out = run(&code, tests_input(), |_| unreachable!()).unwrap();
        assert_eq!(
            out.body,
            BodyData::Text((0..12000u64).sum::<u64>().to_string())
        );
        // 损坏的缓存不进入 JS_ReadObject：校验失败即删除，重新加载时重新编译。
        let path = bytecode::path_for_test(&code).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, bytes).unwrap();
        assert!(bytecode::cached(&code).is_none());
        assert!(!path.exists());
        validate(&code).unwrap();
        let out = run(&code, tests_input(), |_| unreachable!()).unwrap();
        assert_eq!(
            out.body,
            BodyData::Text((0..12000u64).sum::<u64>().to_string())
        );
        set_bytecode_cache_dir(None);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn tests_input() -> Input {
        Input {
            cancellation: None,
            event: Value::Null,
            cron: None,
            kind: "generic".into(),
            loon: false,
            request: Value::Null,
            response: Value::Null,
            request_body: BodyData::None,
            response_body: BodyData::None,
            argument: Value::Null,
            env: Default::default(),
            binary: false,
            timeout: Duration::from_secs(10),
            name: "large".into(),
            store: Default::default(),
            max_heap: 0,
            max_body: 0,
        }
    }
}
