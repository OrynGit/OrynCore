//! 受限、可复用的 jq 编译与执行封装。

use jaq_core::{
    compile,
    data::JustLut,
    load::{Arena, File, Loader},
    unwrap_valr, Ctx, Native, Vars,
};
use jaq_json::Val;
use serde::Deserialize;
use std::io;

mod conversion;

pub const MAX_FILTER_BYTES: usize = 256 * 1024;

type Filter = compile::Filter<Native<JustLut<Val>>>;

/// 编译过的 jq 程序。`jaq-core` 编译后自动按入口可达性裁剪未使用的标准库节点；
/// 模块里的 jq 改写仍按需延迟编译：[`Program::compile`] 只校验，
/// 第一次 [`Program::run`] / [`Program::run_bytes`] 时才编译并缓存紧凑后的 LUT。
pub struct Program {
    source: String,
    filter: std::cell::OnceCell<Filter>,
}

impl Program {
    /// 校验 filter 能否编译；编译结果先丢掉，第一次执行时再编译。
    pub fn compile(source: &str) -> Result<Self, String> {
        build(source)?;
        Ok(Self {
            source: source.to_owned(),
            filter: std::cell::OnceCell::new(),
        })
    }

    /// 原始源码借读；共享时仅按完整源码比较，不归一化。
    pub fn source(&self) -> &str {
        &self.source
    }

    fn filter(&self) -> Result<&Filter, String> {
        if let Some(f) = self.filter.get() {
            return Ok(f);
        }
        let f = build(&self.source)?;
        Ok(self.filter.get_or_init(|| f))
    }

    fn with_budget<T>(&self, max_body: usize, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        jaq_core::oryn_budget::start_with(max_body);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        jaq_core::oryn_budget::clear();
        result.unwrap_or_else(|payload| {
            if payload.is::<jaq_core::oryn_budget::Exhausted>() {
                Err("jq execution quota exceeded".into())
            } else {
                let what = payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown".into());
                Err(format!("jq internal error: {what}"))
            }
        })
    }

    pub fn run(&self, input: &serde_json::Value) -> Result<serde_json::Value, String> {
        self.run_with_limit(input, jaq_core::oryn_budget::DEFAULT_MAX_VALUE_BYTES)
    }

    pub fn run_with_limit(
        &self,
        input: &serde_json::Value,
        max_body: usize,
    ) -> Result<serde_json::Value, String> {
        // 延迟编译与输入解码不计入单次 jq 解释器超时预算，避免冷启动或大 JSON 解析误触超时。
        let filter = self.filter()?;
        let value: Val = Val::deserialize(input).map_err(|e| format!("jq input: {e}"))?;
        let first = self.with_budget(max_body, || Self::eval_single(filter, value))?;
        match first {
            Some(v) => conversion::to_json(&v),
            None => Ok(input.clone()),
        }
    }

    /// 直接从 JSON 字节解码为 `Val` 并流式写出 JSON 字节，省去两棵 `serde_json::Value` 树，
    /// 同时把执行预算对齐到 `max_output` 并在输出超限时提前中止。
    pub fn run_bytes(&self, input: &[u8], max_output: usize) -> Result<Vec<u8>, String> {
        let filter = self.filter()?;
        let value: Val = serde_json::from_slice(input).map_err(|e| format!("jq input: {e}"))?;
        let first = self.with_budget(max_output, || Self::eval_single(filter, value))?;
        match first {
            Some(v) => conversion::to_json_bytes(&v, max_output, input.len()),
            None => {
                if input.len() > max_output {
                    return Err("jq output exceeds limit".into());
                }
                Ok(input.to_vec())
            }
        }
    }

    fn eval_single(filter: &Filter, value: Val) -> Result<Option<Val>, String> {
        let ctx = Ctx::<JustLut<Val>>::new(&filter.lut, Vars::new([]));
        let mut outputs = filter.id.run((ctx, value)).map(unwrap_valr);
        let Some(first) = outputs.next() else {
            return Ok(None);
        };
        let first = first.map_err(|_| "jq runtime error".to_string())?;
        if outputs.next().is_some() {
            return Err(
                "jq produced multiple outputs; body rewrite requires one JSON value".into(),
            );
        }
        Ok(Some(first))
    }
}

fn build(source: &str) -> Result<Filter, String> {
    if source.len() > MAX_FILTER_BYTES {
        return Err("jq filter exceeds 256 KiB".into());
    }
    // jq 的流成员判断；jaq 3 标准库未提供 IN/1，补齐 Surge/Loon 常用契约。
    // 用户自己定义了 IN 时不再补，避免重复定义导致编译失败。
    let source = if source.contains("def IN(") {
        source.to_owned()
    } else {
        format!("def IN(s): . as $item | any(s; . == $item);\n{source}")
    };
    let source = source.as_str();
    let arena = Arena::default();
    let loader = Loader::new(
        jaq_core::defs()
            .chain(jaq_std::defs())
            .chain(jaq_json::defs()),
    );
    let modules = loader
        .load(
            &arena,
            File {
                path: (),
                code: source,
            },
        )
        .map_err(|errs| describe("jq parse error", &errs))?;
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());
    let filter = jaq_core::Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|errs| describe("jq compile error", &errs))?;
    Ok(filter)
}

/// 错误列表的简短描述（含出错位置附近的源码片段），截断到 512 字节。
fn describe(kind: &str, errs: &impl std::fmt::Debug) -> String {
    let mut text = format!("{kind}: {errs:?}");
    if text.len() > 512 {
        let mut end = 512;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
    text
}

/// 一次性改写：每次调用都会重新编译 filter，规则路径应预先 [`Program::compile`] 后复用。
pub fn rewrite_json(source: &str, input: &[u8]) -> io::Result<Vec<u8>> {
    let program = Program::compile(source).map_err(io::Error::other)?;
    program
        .run_bytes(
            input,
            input
                .len()
                .max(jaq_core::oryn_budget::DEFAULT_MAX_VALUE_BYTES),
        )
        .map_err(|e| {
            if e.starts_with("jq input:") {
                io::Error::new(io::ErrorKind::InvalidData, e)
            } else {
                io::Error::other(e)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filters_common_module_operations() {
        let input = serde_json::json!({"data":{"items":[{"type":"ad"},{"type":"news"}]}});
        let program = Program::compile(r#".data.items |= map(select(.type != "ad"))"#).unwrap();
        let out = program.run(&input).unwrap();
        assert_eq!(out["data"]["items"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn compiled_filter_is_compacted_and_preserves_stdlib_and_tco() {
        let p = Program::compile(r#"del(.ad) | .items |= map(select(.is_ad != true))"#).unwrap();
        let f = p.filter().unwrap();
        // 未裁剪前完整标准库含 2000+ term 与 100+ native fun；裁剪后应远小于此。
        assert!(
            f.lut.term_count() < 120,
            "expected compacted terms < 120, got {}",
            f.lut.term_count()
        );
        assert!(
            f.lut.fun_count() < 20,
            "expected compacted funs < 20, got {}",
            f.lut.fun_count()
        );

        // 验证尾递归（TCO）与注入的 IN/1 在压缩重排 TermId 后行为不变。
        let tco = Program::compile(
            r#"def countdown: if . <= 0 then 0 else (. - 1) | countdown end; countdown"#,
        )
        .unwrap();
        assert_eq!(tco.run(&serde_json::json!(2000)).unwrap(), serde_json::json!(0));

        let in_prog = Program::compile(r#"[.[] | select(IN("a", "c"))]"#).unwrap();
        assert_eq!(
            in_prog.run(&serde_json::json!(["a", "b", "c"])).unwrap(),
            serde_json::json!(["a", "c"])
        );
    }

    // 旧桥接作为语义oracle，不用于生产；比较完整filter结果及最终JSON表示。
    fn legacy_run(
        program: &Program,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let filter = program.filter()?;
        let value: Val = serde_json::from_value(input.clone()).unwrap();
        let ctx = Ctx::<JustLut<Val>>::new(&filter.lut, Vars::new([]));
        let mut outputs = filter.id.run((ctx, value)).map(unwrap_valr);
        let Some(first) = outputs.next() else {
            return Ok(input.clone());
        };
        let first = first.map_err(|_| "runtime".to_string())?;
        if outputs.next().is_some() {
            return Err("multiple".into());
        }
        serde_json::from_str(&first.to_string()).map_err(|e| e.to_string())
    }

    #[test]
    fn bridge_matches_legacy_filter_results() {
        let input_str = r#"{"text":"中文🙂\\n\\u0000\\u007f", "numbers":[-0.0,1.0,1.2345678901234567,1e-308,1e308,-9223372036854775808,18446744073709551615],"data":{"remove":true,"keep":null}}"#;
        let input: serde_json::Value = serde_json::from_str(input_str).unwrap();
        for source in [
            ".",
            "empty",
            "., .",
            "del(.data.remove)",
            ".numbers | map(. + 1)",
            "[null,true,false,{},[]]",
            "{z: .text, a: .numbers}",
            "nan",
            "infinite",
            "18446744073709551616",
            "reduce range(0;127) as $i (null; [.])",
            "reduce range(0;128) as $i (null; [.])",
        ] {
            let program = Program::compile(source).unwrap();
            let before = legacy_run(&program, &input);
            let after = program.run(&input);
            let bytes = program.run_bytes(input_str.as_bytes(), 1024 * 1024);
            assert_eq!(before.is_ok(), after.is_ok(), "{source}");
            assert_eq!(before.is_ok(), bytes.is_ok(), "bytes {source}: {bytes:?}");
            if let (Ok(a), Ok(b), Ok(raw)) = (before, after, bytes) {
                assert_eq!(
                    serde_json::to_vec(&a).unwrap(),
                    serde_json::to_vec(&b).unwrap(),
                    "{source}"
                );
                let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                assert_eq!(
                    serde_json::to_vec(&a).unwrap(),
                    serde_json::to_vec(&parsed).unwrap(),
                    "bytes {source}"
                );
            }
        }
        // 多种结构而非只有大字符串；输出对象排序及整数/浮点表示须一致。
        let rows: Vec<_> = (0..256)
            .map(|i| {
                serde_json::json!({"id": i, "text": format!("item-{i}\\\"\n中文"), "f": (i as f64 - 128.0) / 7.0})
            })
            .collect();
        let value = serde_json::json!({"rows": rows});
        let p = Program::compile(".rows |= map(select(.id % 3 == 0))").unwrap();
        assert_eq!(p.run(&value).unwrap(), legacy_run(&p, &value).unwrap());
    }

    #[test]
    fn run_bytes_handles_2mib_payload_and_respects_output_limit() {
        let mut raw = String::from(r#"{"ad":1,"items":["#);
        let pad = "p".repeat(200);
        for i in 0..8_000usize {
            if i > 0 {
                raw.push(',');
            }
            raw.push_str(&format!(
                r#"{{"id":{i},"is_ad":{},"title":"item-{i}-{pad}"}}"#,
                i % 4 == 0
            ));
        }
        raw.push_str("]}");
        assert!(raw.len() > 1_800_000, "len={}", raw.len());

        let p = Program::compile(r#"del(.ad) | .items |= map(select(.is_ad != true))"#).unwrap();
        let out = p.run_bytes(raw.as_bytes(), 4 * 1024 * 1024).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(parsed.get("ad").is_none());
        assert_eq!(parsed["items"].as_array().unwrap().len(), 6_000);

        // 输出超过 max_output 时报错中止。
        assert!(p.run_bytes(raw.as_bytes(), 1024).is_err());
    }

    #[test]
    fn user_defined_in_does_not_conflict() {
        let p = Program::compile("def IN(s): any(s; . == 1); [1 | IN(1, 2)]").unwrap();
        assert_eq!(
            p.run(&serde_json::Value::Null).unwrap(),
            serde_json::json!([true])
        );
        let err = Program::compile(".a | ").unwrap_err();
        assert!(err.starts_with("jq parse error: "), "{err}");
    }

    #[test]
    fn path_update_and_delete_match_jq_on_missing_and_null_paths() {
        let cases: &[(&str, &str, &str)] = &[
            ("{}", "del(.a.b)", "{}"),
            ("{}", "del(.a.b.c)", "{}"),
            (r#"{"a":null}"#, "del(.a.b)", r#"{"a":null}"#),
            (r#"{"a":{"b":1}}"#, "del(.a.b)", r#"{"a":{}}"#),
            ("{}", ".a.b = 1", r#"{"a":{"b":1}}"#),
            ("{}", ".a.b = null", r#"{"a":{"b":null}}"#),
            ("{}", ".a.b |= .", r#"{"a":{"b":null}}"#),
            ("{}", ".a |= .", r#"{"a":null}"#),
            ("{}", "del(.a[]?.b)", "{}"),
            ("{}", ".a[]?.b |= 1", "{}"),
            (r#"{"data":{}}"#, "del(.data.tab_nav[]?.tab_param)", r#"{"data":{}}"#),
            (r#"{"a":[null]}"#, "del(.a[0].b)", r#"{"a":[null]}"#),
            ("[1]", "del(.[5])", "[1]"),
            ("[1]", "del(.[5].a)", "[1]"),
            ("[1]", ".[2] = 9", "[1,null,9]"),
            ("[1]", r#".[2].a = 1"#, r#"[1,null,{"a":1}]"#),
            ("null", "del(.a)", "null"),
            ("null", "del(.[0])", "null"),
            ("null", ".a = 1", r#"{"a":1}"#),
            ("null", ".[1] = 1", "[null,1]"),
            ("null", ".[]? |= 1", "null"),
            (
                "{}",
                ".data.hotReplyRows |= if . then map(select(.id != 1)) else . end",
                r#"{"data":{"hotReplyRows":null}}"#,
            ),
        ];
        for (input, filter, expected) in cases {
            let p = Program::compile(filter).unwrap();
            let out = p.run_bytes(input.as_bytes(), 1024 * 1024).unwrap_or_else(|e| {
                panic!("filter `{filter}` on `{input}` failed: {e}");
            });
            let got: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let want: serde_json::Value = serde_json::from_str(expected).unwrap();
            assert_eq!(got, want, "input={input} filter={filter}");
        }
        // 非对象/非 null 路径上的 del 仍报错（与 jq 一致）。
        let err = Program::compile("del(.a.b)")
            .unwrap()
            .run_bytes(br#"{"a":1}"#, 1024 * 1024);
        assert!(err.is_err());
    }
}

impl std::fmt::Debug for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CompiledJq")
    }
}

#[cfg(test)]
mod quota_tests {
    use super::*;
    #[test]
    fn oversized_string_repeat_is_cancelled() {
        let p = Program::compile(r#""x" * 1000000000"#).unwrap();
        assert!(p.run(&serde_json::Value::Null).is_err());
    }
    #[test]
    fn infinite_filter_is_cancelled() {
        let p = Program::compile("[range(0;1000000000)]").unwrap();
        assert!(p.run(&serde_json::Value::Null).is_err());
    }
    #[test]
    fn empty_keeps_original() {
        let p = Program::compile("empty").unwrap();
        assert_eq!(
            p.run(&serde_json::json!({"ok":1})).unwrap(),
            serde_json::json!({"ok":1})
        );
    }
}

#[cfg(test)]
mod recursion_tests {
    use super::*;
    #[test]
    fn recursive_filter_is_cancelled() {
        let p = Program::compile("def f: f; f").unwrap();
        assert!(p.run(&serde_json::Value::Null).is_err());
    }
    #[test]
    fn expanding_value_is_cancelled() {
        let p = Program::compile("reduce range(0;100) as $i (null; [.,.])").unwrap();
        assert!(p.run(&serde_json::Value::Null).is_err());
    }
    #[test]
    fn expanding_integer_is_cancelled() {
        let p = Program::compile("reduce range(0;100) as $i (2; . * .)").unwrap();
        assert!(p.run(&serde_json::Value::Null).is_err());
    }
}
