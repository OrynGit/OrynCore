//! 大脚本的字节码缓存。
//!
//! QuickJS 解析 600 KiB 级的压缩脚本时临时需要 10 MiB 以上的堆，执行时却只常驻约 2 MiB。
//! 执行堆超限的大脚本在加载模块时用更大的堆只编译一次（同一时刻只编译一个），字节码按
//! QuickJS 版本与源码 SHA-256 存到 Core 私有目录；之后每次执行直接读字节码，执行堆仍为
//! [`HEAP_LIMIT`](crate::HEAP_LIMIT)。没有设置目录时行为与原来一致：超限脚本被跳过。
use rquickjs::{qjs, Context, Ctx, Runtime};
use sha2::{Digest, Sha256};
use std::{
    io::{Error, ErrorKind, Read},
    path::{Path, PathBuf},
    sync::Mutex,
    time::SystemTime,
};

/// 只编译不执行时的堆上限。
pub const COMPILE_HEAP_LIMIT: usize = 24 * 1024 * 1024;
/// 小于此大小的脚本在执行堆内总能解析，不查缓存。
const MIN_SOURCE: usize = 128 * 1024;
const MAX_BYTECODE: usize = 12 * 1024 * 1024;
const MAX_CACHE: u64 = 64 * 1024 * 1024;
/// 缓存文件头：魔数 + 键哈希（QuickJS 版本与源码）+ 字节码内容哈希。读取时两者都核对，
/// 被截断、篡改或跨版本残留的文件不会进入 `JS_ReadObject`。
const MAGIC: &[u8; 8] = b"ORYNQBC1";
const HEADER: usize = 8 + 32 + 32;

static DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
/// 串行化编译，避免多个大堆同时存在。
static COMPILING: Mutex<()> = Mutex::new(());

/// 设置字节码缓存目录（Core 在加载模块前调用）；`None` 关闭缓存。
pub fn set_cache_dir(dir: Option<PathBuf>) {
    *DIR.lock().unwrap() = dir;
}

fn key_for(code: &str) -> Option<(PathBuf, [u8; 32])> {
    if code.len() < MIN_SOURCE {
        return None;
    }
    let dir = DIR.lock().unwrap().clone()?;
    // 字节码格式随 QuickJS 版本变化，版本号进入键。
    let version = unsafe { std::ffi::CStr::from_ptr(qjs::JS_GetVersion()) };
    let mut hash = Sha256::new();
    hash.update(version.to_bytes());
    hash.update([0]);
    hash.update(code.as_bytes());
    let key: [u8; 32] = hash.finalize().into();
    let name = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Some((dir.join(format!("{name}.qjsbc")), key))
}

fn path_for(code: &str) -> Option<PathBuf> {
    key_for(code).map(|(p, _)| p)
}

fn encode(key: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(key);
    out.extend_from_slice(&Sha256::digest(body));
    out.extend_from_slice(body);
    out
}

/// 校验文件头并取出字节码；任何不符都返回 `None`。
fn decode(key: &[u8; 32], mut bytes: Vec<u8>) -> Option<Vec<u8>> {
    if bytes.len() <= HEADER || bytes.len() > HEADER + MAX_BYTECODE {
        return None;
    }
    if &bytes[..8] != MAGIC || &bytes[8..40] != key {
        return None;
    }
    let digest: [u8; 32] = Sha256::digest(&bytes[HEADER..]).into();
    if bytes[40..HEADER] != digest {
        return None;
    }
    bytes.drain(..HEADER);
    Some(bytes)
}

/// 已缓存且校验通过的字节码；没有时返回 `None`，调用方按源码执行。
/// 文件存在但校验失败时删除它，下次加载模块会重新编译。
pub(crate) fn cached(code: &str) -> Option<Vec<u8>> {
    let (path, key) = key_for(code)?;
    let bytes = read_bounded(&path).ok()?;
    let body = decode(&key, bytes);
    if body.is_none() {
        let _ = std::fs::remove_file(&path);
    }
    body
}

// decode的长度检查之前也必须有界，避免损坏的超大缓存先占满Extension堆。
fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let limit = HEADER + MAX_BYTECODE;
    let size = file.metadata()?.len();
    if size > limit as u64 {
        return Ok(Vec::new()); // 交给decode判无效并删除，保持源码回退。
    }
    let mut bytes = vec![0; size as usize];
    match file.read_exact(&mut bytes) {
        Ok(()) => {},
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(Vec::new()),
        Err(e) => return Err(e),
    }
    // 同一个fd在metadata之后增长也拒绝，不扩容、不接受旧前缀。
    let mut tail = [0];
    loop {
        match file.read(&mut tail) {
            Ok(0) => return Ok(bytes),
            Ok(_) => return Ok(Vec::new()),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
pub(crate) fn path_for_test(code: &str) -> Option<PathBuf> {
    path_for(code)
}

/// 删除某脚本的缓存（字节码读取失败时调用）。
pub(crate) fn discard(code: &str) {
    if let Some(path) = path_for(code) {
        let _ = std::fs::remove_file(path);
    }
}

/// 执行堆内解析失败的大脚本：用编译堆生成字节码并写入缓存。已有缓存直接返回成功。
/// 未设置目录或脚本太小时返回 `Ok(false)`，由调用方报告原来的超限错误。
pub(crate) fn ensure(code: &str) -> std::io::Result<bool> {
    let Some((path, key)) = key_for(code) else {
        return Ok(false);
    };
    if cached(code).is_some() {
        return Ok(true);
    }
    let _guard = COMPILING.lock().unwrap_or_else(|e| e.into_inner());
    if cached(code).is_some() {
        return Ok(true);
    }
    let bytes = encode(&key, &compile(code)?);
    let dir = path
        .parent()
        .ok_or_else(|| Error::other("bad cache path"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path)?;
    // 有效缓存已写入；淘汰旧文件失败不影响本脚本。
    let _ = trim(dir, &path);
    Ok(true)
}

fn compile(code: &str) -> std::io::Result<Vec<u8>> {
    let source = std::ffi::CString::new(code)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "script contains a NUL byte"))?;
    let rt = Runtime::new().map_err(Error::other)?;
    rt.set_memory_limit(COMPILE_HEAP_LIMIT);
    rt.set_max_stack_size(512 * 1024);
    let ctx = Context::full(&rt).map_err(Error::other)?;
    ctx.with(|ctx| {
        // 安全：source 以 NUL 结尾且在调用期间存活；返回值与缓冲区在本作用域内释放。
        unsafe {
            let raw = ctx.as_raw().as_ptr();
            qjs::JS_UpdateStackTop(qjs::JS_GetRuntime(raw));
            let name = c"script";
            let func = qjs::JS_Eval(
                raw,
                source.as_ptr(),
                code.len() as _,
                name.as_ptr(),
                (qjs::JS_EVAL_TYPE_GLOBAL | qjs::JS_EVAL_FLAG_COMPILE_ONLY) as i32,
            );
            if qjs::JS_IsException(func) {
                return Err(compile_error(&ctx));
            }
            let mut len = 0;
            let buf = qjs::JS_WriteObject(raw, &mut len, func, qjs::JS_WRITE_OBJ_BYTECODE as i32);
            qjs::JS_FreeValue(raw, func);
            if buf.is_null() {
                return Err(Error::other("failed to serialize script bytecode"));
            }
            let len = len as usize;
            let out = (len <= MAX_BYTECODE).then(|| std::slice::from_raw_parts(buf, len).to_vec());
            qjs::js_free(raw, buf as _);
            out.ok_or_else(|| Error::new(ErrorKind::Unsupported, "script bytecode exceeds 12 MiB"))
        }
    })
}

fn compile_error(ctx: &Ctx) -> Error {
    let message = ctx
        .catch()
        .as_exception()
        .and_then(|e| e.message())
        .unwrap_or_else(|| "out of memory".into());
    if message.contains("out of memory") || message.contains("stack overflow") {
        Error::new(
            ErrorKind::Unsupported,
            "script exceeds the 24 MiB compile heap",
        )
    } else {
        Error::new(
            ErrorKind::InvalidData,
            format!("JavaScript syntax: {message}"),
        )
    }
}

/// 字节码执行结果：`Unreadable` 表示 `JS_ReadObject` 拒绝了字节码（尚未执行任何脚本代码），
/// 调用方可以删掉缓存改用源码；`Ran` 是脚本执行本身的结果。
pub(crate) enum Eval {
    Unreadable,
    Ran(rquickjs::Result<()>),
}

/// 在当前上下文里执行字节码，与 `ctx.eval(源码)` 等价。
pub(crate) fn eval(ctx: &Ctx, bytes: &[u8]) -> Eval {
    // 安全：字节码由本模块在同一 QuickJS 版本下写入 Core 私有目录；返回值在此释放。
    unsafe {
        let raw = ctx.as_raw().as_ptr();
        let func = qjs::JS_ReadObject(
            raw,
            bytes.as_ptr(),
            bytes.len() as _,
            qjs::JS_READ_OBJ_BYTECODE as i32,
        );
        if qjs::JS_IsException(func) {
            // 清掉挂起的异常，回退源码执行时不受影响。
            let _ = ctx.catch();
            return Eval::Unreadable;
        }
        // JS_EvalFunction 接管 func 的引用。
        let result = qjs::JS_EvalFunction(raw, func);
        if qjs::JS_IsException(result) {
            return Eval::Ran(Err(rquickjs::Error::Exception));
        }
        qjs::JS_FreeValue(raw, result);
    }
    Eval::Ran(Ok(()))
}

/// 按修改时间淘汰旧字节码，目录总量不超过 64 MiB；保留刚写入的文件。
fn trim(dir: &Path, keep: &Path) -> std::io::Result<()> {
    let mut files = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            m.is_file().then(|| {
                (
                    e.path(),
                    m.len(),
                    m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                )
            })
        })
        .collect::<Vec<_>>();
    let mut total = files.iter().map(|f| f.1).sum::<u64>();
    files.sort_by_key(|f| f.2);
    for (path, len, _) in files {
        if total <= MAX_CACHE {
            break;
        }
        if path != keep {
            std::fs::remove_file(path)?;
            total = total.saturating_sub(len);
        }
    }
    Ok(())
}

#[cfg(test)]
mod bounded_read_tests {
    use super::*;
    #[test]
    fn bytecode_read_rejects_oversize_and_preserves_validation() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/bytecode-bounds");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{}.qjsbc", std::process::id()));
        let key = [42; 32];
        let encoded = encode(&key, b"synthetic-bytecode");
        std::fs::write(&path, &encoded).unwrap();
        assert_eq!(decode(&key, read_bounded(&path).unwrap()).unwrap(), b"synthetic-bytecode");
        std::fs::write(&path, &encoded[..encoded.len()-1]).unwrap();
        assert!(decode(&key, read_bounded(&path).unwrap()).is_none());
        std::fs::File::create(&path).unwrap().set_len((HEADER + MAX_BYTECODE + 1) as u64).unwrap();
        let start = std::time::Instant::now();
        let bytes = read_bounded(&path).unwrap();
        assert_eq!(bytes.capacity(), 0);
        println!("bytecode_oversize returned_capacity=0 elapsed_us={}", start.elapsed().as_micros());
        assert!(decode(&key, bytes).is_none());
        std::fs::remove_file(path).unwrap();
    }
}
