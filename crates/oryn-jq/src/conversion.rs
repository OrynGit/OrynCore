//! 省去大正文的 Display -> String -> JSON 往返；特殊值保留原来的解析语义。
use jaq_json::{Num, Val};
use serde_json::Value;
use std::io::Write;

fn legacy(value: &Val) -> Result<Value, String> {
    serde_json::from_str(&value.to_string()).map_err(|e| format!("jq output: {e}"))
}

pub(super) fn to_json(value: &Val) -> Result<Value, String> {
    convert(value, 0)
}

/// 直接把 `jaq_json::Val` 流式写为严格 JSON 字节，避免构造第二棵 `serde_json::Value` 树；
/// 写出超过 `max_output` 时立即中止。
pub(super) fn to_json_bytes(
    value: &Val,
    max_output: usize,
    initial_cap: usize,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(initial_cap.min(max_output));
    write_val(value, 0, &mut out, max_output)?;
    if out.len() > max_output {
        return Err("jq output exceeds limit".into());
    }
    if out.capacity() > out.len().saturating_add(64 * 1024) && out.capacity() > out.len() * 2 {
        out.shrink_to_fit();
    }
    Ok(out)
}

fn check_out_len(out: &[u8], max_output: usize) -> Result<(), String> {
    if out.len() > max_output {
        Err("jq output exceeds limit".into())
    } else {
        Ok(())
    }
}

fn write_val(value: &Val, depth: usize, out: &mut Vec<u8>, max_output: usize) -> Result<(), String> {
    match value {
        Val::Null => out.extend_from_slice(b"null"),
        Val::Bool(true) => out.extend_from_slice(b"true"),
        Val::Bool(false) => out.extend_from_slice(b"false"),
        Val::Num(Num::Int(i)) => {
            write!(out, "{i}").map_err(|e| format!("jq output: {e}"))?;
        }
        Val::Num(Num::Float(f)) => {
            if !f.is_finite() {
                return Err("jq output: non-finite number".into());
            }
            serde_json::to_writer(&mut *out, f).map_err(|e| format!("jq output: {e}"))?;
        }
        Val::Num(Num::BigInt(_)) | Val::Num(Num::Dec(_)) => {
            let v = legacy(value)?;
            serde_json::to_writer(&mut *out, &v).map_err(|e| format!("jq output: {e}"))?;
        }
        Val::BStr(_) => return Err("jq output: byte string is not valid JSON".into()),
        Val::TStr(s) => match std::str::from_utf8(s) {
            Ok(text) => {
                serde_json::to_writer(&mut *out, text).map_err(|e| format!("jq output: {e}"))?;
            }
            Err(_) => {
                let v = legacy(value)?;
                serde_json::to_writer(&mut *out, &v).map_err(|e| format!("jq output: {e}"))?;
            }
        },
        Val::Arr(a) => {
            check_depth(depth)?;
            out.push(b'[');
            for (idx, item) in a.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_val(item, depth + 1, out, max_output)?;
                check_out_len(out, max_output)?;
            }
            out.push(b']');
        }
        Val::Obj(o) => {
            check_depth(depth)?;
            // 仅当存在非文本键或非法 UTF-8 键（可能碰撞为 U+FFFD）时回退到 Value 路径，保证去重与报错完全一致。
            let fast_keys = o
                .keys()
                .all(|k| matches!(k, Val::TStr(s) if std::str::from_utf8(s).is_ok()));
            if !fast_keys {
                let v = convert(value, depth)?;
                serde_json::to_writer(&mut *out, &v).map_err(|e| format!("jq output: {e}"))?;
                return check_out_len(out, max_output);
            }
            out.push(b'{');
            for (idx, (key, val)) in o.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                let Val::TStr(bytes) = key else {
                    unreachable!("checked all keys are valid UTF-8 TStr")
                };
                let text = std::str::from_utf8(bytes).expect("checked valid UTF-8");
                serde_json::to_writer(&mut *out, text).map_err(|e| format!("jq output: {e}"))?;
                out.push(b':');
                write_val(val, depth + 1, out, max_output)?;
                check_out_len(out, max_output)?;
            }
            out.push(b'}');
        }
    }
    check_out_len(out, max_output)
}

fn convert(value: &Val, depth: usize) -> Result<Value, String> {
    match value {
        Val::Null => Ok(Value::Null),
        Val::Bool(b) => Ok(Value::Bool(*b)),
        // 浮点文本解析可能改变末位舍入/负零的表示；保留旧路径，不直接 from_f64。
        Val::Num(_) | Val::BStr(_) => legacy(value),
        Val::TStr(s) => match std::str::from_utf8(s) {
            Ok(s) => Ok(Value::String(s.to_owned())),
            // jaq Display 对非法 UTF-8 的替代方式仍由旧实现决定。
            Err(_) => legacy(value),
        },
        Val::Arr(a) => {
            check_depth(depth)?;
            a.iter()
                .map(|v| convert(v, depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        Val::Obj(o) => {
            check_depth(depth)?;
            let mut map = serde_json::Map::new();
            for (key, value) in o.iter() {
                let key = match key {
                    Val::TStr(s) => match std::str::from_utf8(s) {
                        Ok(s) => s.to_owned(),
                        Err(_) => match legacy(key)? {
                            Value::String(s) => s,
                            _ => unreachable!("text string must decode to JSON string"),
                        },
                    },
                    // 非字符串键原先产生非法 JSON，不能悄悄字符串化它。
                    _ => return legacy(&Val::Obj(o.clone())),
                };
                map.insert(key, convert(value, depth + 1)?);
            }
            Ok(Value::Object(map))
        }
    }
}

fn check_depth(depth: usize) -> Result<(), String> {
    // serde_json 默认预算128：进入第128层容器时拒绝（标量不递减预算）。
    if depth >= 127 {
        Err("jq output: recursion limit exceeded".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(value: &Val) {
        let before = legacy(value);
        let after = to_json(value);
        let bytes = to_json_bytes(value, 1024 * 1024, 64);
        assert_eq!(before.is_ok(), after.is_ok(), "{value:?}");
        assert_eq!(before.is_ok(), bytes.is_ok(), "bytes {value:?}: {bytes:?}");
        if let (Ok(a), Ok(b), Ok(raw)) = (before, after, bytes) {
            assert_eq!(
                serde_json::to_vec(&a).unwrap(),
                serde_json::to_vec(&b).unwrap()
            );
            let parsed: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(
                serde_json::to_vec(&a).unwrap(),
                serde_json::to_vec(&parsed).unwrap(),
                "bytes mismatch for {value:?}"
            );
        }
    }

    #[test]
    fn conversion_preserves_scalar_and_special_values() {
        for text in [
            "null",
            "true",
            "false",
            "0",
            "-0.0",
            "1.2345678901234567",
            "1e-308",
            "1e308",
            "-9223372036854775808",
            "18446744073709551615",
            "18446744073709551616",
            "NaN",
            "Infinity",
            "-Infinity",
        ] {
            // 数字全部沿用原有Display/parse，覆盖BigInt/Dec/Float不同分支。
            let value = if let Ok(n) = text.parse::<f64>() {
                Val::from(n)
            } else {
                Val::Null
            };
            same(&value);
            same(&Val::Num(jaq_json::Num::Dec(text.to_string().into())));
        }
        same(&Val::Num(jaq_json::Num::from_integral(u64::MAX)));
        for bytes in [
            b"plain".as_slice(),
            "中文🙂\n\t\0\"\\\u{7f}".as_bytes(),
            &[0xff, b'x', 0xc3],
        ] {
            same(&Val::utf8_str(bytes.to_vec()));
        }
    }

    #[test]
    fn conversion_preserves_containers_and_depth_limit() {
        use serde::Deserialize;
        let input = serde_json::json!({"z":[null, true, 1, "中文"], "a":{"\n":"\u{7f}"}});
        same(&Val::deserialize(&input).unwrap());
        let mut deep = Val::Null;
        for _ in 0..130 {
            deep = Val::Arr(vec![deep].into());
            same(&deep);
        }
        let mut object = jaq_json::Map::default();
        object.insert(Val::from(1isize), Val::Null);
        same(&Val::obj(object));
    }

    #[test]
    fn conversion_preserves_binary_keys_collisions_and_mixed_depth() {
        same(&Val::byte_str(vec![0, 0xff, b'x']));
        same(&Val::Arr(
            vec![Val::from(1isize), Val::from(f64::INFINITY)].into(),
        ));
        same(&Val::Arr(vec![Val::byte_str(vec![0xff])].into()));
        let mut object = jaq_json::Map::default();
        object.insert(Val::utf8_str(vec![0xff]), Val::from(1isize));
        object.insert(Val::utf8_str(vec![0xfe]), Val::from(2isize));
        same(&Val::obj(object)); // 两个非法UTF-8键都变成替代字符，后一个覆盖前一个。
        let mut deep = Val::Null;
        for depth in 0..130 {
            if depth % 2 == 0 {
                let mut object = jaq_json::Map::default();
                object.insert(Val::from("key".to_string()), deep);
                deep = Val::obj(object);
            } else {
                deep = Val::Arr(vec![deep].into());
            }
            same(&deep);
        }
    }

    #[test]
    fn to_json_bytes_enforces_max_output() {
        let arr = Val::Arr((0..100).map(|i| Val::from(i as isize)).collect::<Vec<_>>().into());
        assert!(to_json_bytes(&arr, 32, 16).is_err());
        assert!(to_json_bytes(&arr, 4096, 16).is_ok());
    }
}
