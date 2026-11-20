//! 每次执行独立 QuickJS 上下文；无文件、进程、Socket 模块，内存/栈/时间均有硬上限。
use rquickjs::{Context, Runtime};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
mod bytecode;
pub use bytecode::{set_cache_dir as set_bytecode_cache_dir, COMPILE_HEAP_LIMIT};
pub const HEAP_LIMIT: usize = 8 * 1024 * 1024;
pub struct Input {
    pub cancellation: Option<(std::sync::Arc<std::sync::atomic::AtomicU64>, u64)>,
    pub event: Value,
    pub cron: Option<String>,
    pub kind: String,
    pub loon: bool,
    pub request: Value,
    pub response: Value,
    pub argument: Value,
    pub env: BTreeMap<String, String>,
    pub binary: bool,
    pub timeout: Duration,
    pub name: String,
    pub store: BTreeMap<String, String>,
}
pub struct Output {
    pub result: Value,
    pub store: BTreeMap<String, String>,
    pub logs: Vec<String>,
    pub notifications: Vec<Value>,
}
/// 网络通过调用方给定的 Router/Outbound 适配器，脚本本身没有任何 I/O 能力。
pub fn run(
    code: &str,
    input: Input,
    http: impl FnMut(Value) -> Result<Value, String> + 'static,
) -> Result<Output, String> {
    if code.len() > 2 * 1024 * 1024 {
        return Err("script exceeds 2 MiB".into());
    }
    let runtime = Runtime::new().map_err(|e| e.to_string())?;
    runtime.set_memory_limit(HEAP_LIMIT);
    runtime.set_max_stack_size(256 * 1024);
    let end = Instant::now() + input.timeout.min(Duration::from_secs(300));
    let cancellation = input.cancellation.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        Instant::now() >= end
            || cancellation
                .as_ref()
                .is_some_and(|(v, n)| v.load(std::sync::atomic::Ordering::Relaxed) != *n)
    })));
    let http = std::rc::Rc::new(std::cell::RefCell::new(http));
    let context = Context::full(&runtime).map_err(|e| e.to_string())?;
    let initial = serde_json::json!({"event":input.event,"cron":input.cron,"kind":input.kind,"loon":input.loon,"request":input.request,"response":input.response,"argument":input.argument,"env":input.env,"binary":input.binary,"name":input.name,"store":input.store});
    context.with(|ctx| -> Result<(), String> {
        let handler = http.clone();
        let host = rquickjs::Function::new(ctx.clone(), move |text: String| -> String {
            let result = serde_json::from_str(&text)
                .map_err(|e| e.to_string())
                .and_then(|v| (handler.borrow_mut())(v));
            result
                .unwrap_or_else(|e| serde_json::json!({"error":e}))
                .to_string()
        })
        .map_err(|e| e.to_string())?;
        ctx.globals()
            .set("__host", host)
            .map_err(|e| e.to_string())?;
        ctx.globals()
            .set(
                "__utf8encode",
                rquickjs::Function::new(ctx.clone(), utf8_encode).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        ctx.globals()
            .set(
                "__utf8decode",
                rquickjs::Function::new(ctx.clone(), utf8_decode).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        ctx.globals()
            .set(
                "__ungzip",
                rquickjs::Function::new(ctx.clone(), ungzip).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        ctx.globals()
            .set(
                "__base64",
                rquickjs::Function::new(ctx.clone(), base64_text).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        ctx.globals()
            .set("__input", initial.to_string())
            .map_err(|e| e.to_string())?;
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
    })?;
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
        let state = context
            .with(|ctx| ctx.eval::<String, _>("JSON.stringify(__state())"))
            .map_err(|e| e.to_string())?;
        let state: Value = serde_json::from_str(&state).map_err(|e| e.to_string())?;
        if state["done"].as_bool() == Some(true) {
            return Ok(Output {
                result: state["result"].clone(),
                store: serde_json::from_value(state["store"].clone()).map_err(|e| e.to_string())?,
                logs: serde_json::from_value(state["logs"].clone()).map_err(|e| e.to_string())?,
                notifications: state["notifications"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            });
        }
        if let Some(command) = state["request"].as_object() {
            let id = command["id"]
                .as_u64()
                .ok_or("invalid script HTTP request")?;
            let answer = match (http.borrow_mut())(command["options"].clone()) {
                Ok(v) => v,
                Err(e) => serde_json::json!({"error":e}),
            };
            context
                .with(|ctx| {
                    ctx.globals().set("__reply", answer.to_string())?;
                    ctx.eval::<(), _>(format!("__deliver({id},JSON.parse(__reply));"))
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
                .with(|ctx| ctx.eval::<(), _>("__timers();"))
                .map_err(|e| e.to_string())?;
        }
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
            response: serde_json::json!({"status":200,"body":"{\"ok\":false}"}),
            argument: Value::Null,
            env: Default::default(),
            binary: false,
            timeout: Duration::from_millis(100),
            name: "test".into(),
            store: Default::default(),
        }
    }
    #[test]
    fn callbacks_and_storage() {
        let out=run(r#"$httpClient.get('https://fixture.test',(e,r,d)=>{$persistentStore.write(d,'key');$done({body:JSON.stringify({ok:r.status===200})});});"#,input(),|_|Ok(serde_json::json!({"response":{"status":200},"data":"value"}))).unwrap();
        assert_eq!(out.result["body"], r#"{"ok":true}"#);
        assert_eq!(out.store["key"], "value");
    }
    #[test]
    fn module_env_in_ctx() {
        let mut i = input();
        i.env.insert("TOKEN".into(), "abc".into());
        let out = run(
            r#"$done({body:ctx.env.TOKEN+(ctx.env.MISSING===undefined)})"#,
            i,
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(out.result["body"], "abctrue");
    }
    #[test]
    fn script_cannot_replace_host_protocol() {
        let out = run(
            r#"try{__state=()=>({done:true,result:{body:'forged'}});}catch(e){}
               $done({body:String(typeof __host)+String(typeof __input)})"#,
            input(),
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(out.result["body"], "undefinedundefined");
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
        assert_eq!(out.result["body"], "late");
    }
    #[test]
    fn runaway_is_interrupted() {
        assert!(run("while(true){}", input(), |_| unreachable!()).is_err());
    }
    /// QuickJS 改走 Rust 分配器（`rust-alloc`）后，执行堆上限仍然生效。
    #[test]
    fn heap_limit_still_enforced() {
        let code = "const a = []; while (true) { a.push('x'.repeat(65536) + a.length); }";
        assert!(run(code, input(), |_| unreachable!()).is_err());
        let ok = run("const s = 'x'.repeat(1 << 20); $done({body: String(s.length)});", input(), |_| unreachable!()).unwrap();
        assert_eq!(ok.result["body"], "1048576");
    }
    #[test]
    fn no_host_filesystem() {
        let out = run("$done({body:typeof require});", input(), |_| unreachable!()).unwrap();
        assert_eq!(out.result["body"], "undefined");
    }
    #[test]
    fn text_binary_headers_and_base64() {
        let mut i = input();
        i.request["headers"] = serde_json::json!({"Content-Type":"application/json"});
        let out = run(r#"
            const text = '中文🙂';
            const decoded = new TextDecoder().decode(new TextEncoder().encode(text));
            $request.headers['content-type'] = 'text/plain';
            $done({decoded, bytes:atob(btoa('A\xff')), header:$request.headers['CONTENT-TYPE'], keys:Object.keys($request.headers).length});
        "#, i, |_| unreachable!()).unwrap();
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
        let epoch = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut i = input();
        i.timeout = Duration::from_secs(5);
        i.cancellation = Some((epoch.clone(), 0));
        let worker = std::thread::spawn(move || run("while(true){}", i, |_| unreachable!()));
        std::thread::sleep(Duration::from_millis(20));
        epoch.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(worker.join().unwrap().is_err());
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
            response: serde_json::json!({"body":"{\"showMedal\":1,\"keep\":42}"}),
            argument: Value::Null,
            env: Default::default(),
            binary: false,
            timeout: Duration::from_secs(1),
            name: "WeRead".into(),
            store: Default::default(),
        };
        let out = run(code, input, |_| Err("network disabled in fixture".into())).unwrap();
        let body: Value = serde_json::from_str(out.result["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["showMedal"], 0);
        assert_eq!(body["keep"], 42);
    }
}

/// 只编译语法，不执行模块代码或提供任何 I/O。超出体积或脚本堆上限返回
/// `Unsupported`（加载方可只跳过该脚本），语法错误返回 `InvalidData`。
/// 设置了字节码缓存目录时，执行堆内解析不了的大脚本改用编译堆生成字节码。
pub fn validate(code: &str) -> std::io::Result<()> {
    if code.len() > 2 * 1024 * 1024 {
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
    rt.set_memory_limit(HEAP_LIMIT);
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
    rquickjs::Error::new_from_js_message(
        "script data",
        "UTF-8/bytes",
        "invalid input or size limit",
    )
}
fn utf8_encode<'js>(
    ctx: rquickjs::Ctx<'js>,
    text: String,
) -> rquickjs::Result<rquickjs::TypedArray<'js, u8>> {
    if text.len() > 1024 * 1024 {
        return Err(conversion_error());
    }
    rquickjs::TypedArray::new(ctx, text.into_bytes())
}
fn utf8_decode(data: rquickjs::TypedArray<'_, u8>, fatal: bool) -> rquickjs::Result<String> {
    // 安全：独立单线程 runtime，借用期间不执行 JS 或改变/detach ArrayBuffer。
    let bytes = unsafe { data.as_bytes() }.ok_or_else(conversion_error)?;
    if bytes.len() > 1024 * 1024 {
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
) -> rquickjs::Result<rquickjs::TypedArray<'js, u8>> {
    use std::io::Read; // 安全：独立单线程 runtime，借用期间不执行 JS 或改变/detach ArrayBuffer。
    let bytes = unsafe { data.as_bytes() }.ok_or_else(conversion_error)?;
    let mut out = vec![];
    flate2::read::GzDecoder::new(bytes)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut out)
        .map_err(|_| conversion_error())?;
    if out.len() > 1024 * 1024 {
        return Err(conversion_error());
    }
    rquickjs::TypedArray::new(ctx, out)
}
fn base64_text(text: String, encode: bool) -> rquickjs::Result<String> {
    use base64::Engine as _;
    if text.len() > 2 * 1024 * 1024 {
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
        assert_eq!(out.result["body"], (0..12000u64).sum::<u64>().to_string());
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
        assert_eq!(out.result["body"], (0..12000u64).sum::<u64>().to_string());
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
            argument: Value::Null,
            env: Default::default(),
            binary: false,
            timeout: Duration::from_secs(10),
            name: "large".into(),
            store: Default::default(),
        }
    }
}
