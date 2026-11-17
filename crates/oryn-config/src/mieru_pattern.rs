// 移植自 enfein/mieru apis/trafficpattern/config.go、pkg/appctl/appctlpb/base.pb.go
// @ a366b4a2d08a42178704f3126d71f82a27e014a5；Copyright (C) 2026 mieru authors.
// Modified for Oryn: 有界 protobuf 读取，不引入代码生成器或运行时。
// SPDX-License-Identifier: GPL-3.0-or-later
use crate::ConfigError;
use base64::Engine;
#[derive(Debug, Clone, Default)]
pub struct MieruTrafficPattern {
    pub seed: Option<i32>,
    pub unlock: bool,
    pub fragment: Option<bool>,
    pub sleep_ms: Option<u8>,
    pub nonce_type: Option<u8>,
    pub nonce_all: Option<bool>,
    pub nonce_min: Option<u8>,
    pub nonce_max: Option<u8>,
    pub prefixes: Vec<Vec<u8>>,
    pub padding_middle: Option<u8>,
    pub padding_end: Option<u8>,
    pub low_mode: Option<u8>,
    pub low_rotation: Option<u8>,
}
fn invalid() -> ConfigError {
    ConfigError("invalid Mieru traffic-pattern".into())
}
fn varint(input: &mut &[u8]) -> Result<u64, ConfigError> {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let (&b, rest) = input.split_first().ok_or_else(invalid)?;
        *input = rest;
        if shift == 63 && b > 1 {
            return Err(invalid());
        }
        value |= u64::from(b & 127) << shift;
        if b < 128 {
            return Ok(value);
        }
    }
    Err(invalid())
}
enum Value<'a> {
    Int(u64),
    Bytes(&'a [u8]),
}
fn fields(mut input: &[u8]) -> Result<Vec<(u32, Value<'_>)>, ConfigError> {
    let mut fields = Vec::new();
    while !input.is_empty() {
        if fields.len() >= 128 {
            return Err(invalid());
        }
        let key = varint(&mut input)?;
        let tag = u32::try_from(key >> 3).map_err(|_| invalid())?;
        if tag == 0 {
            return Err(invalid());
        }
        let value = match key & 7 {
            0 => Value::Int(varint(&mut input)?),
            2 => {
                let len = usize::try_from(varint(&mut input)?).map_err(|_| invalid())?;
                let bytes = input.get(..len).ok_or_else(invalid)?;
                input = &input[len..];
                Value::Bytes(bytes)
            }
            _ => return Err(invalid()),
        };
        fields.push((tag, value));
    }
    Ok(fields)
}
fn number(v: Value<'_>, max: u64) -> Result<u8, ConfigError> {
    match v {
        Value::Int(n) if n <= max => Ok(n as u8),
        _ => Err(invalid()),
    }
}
impl MieruTrafficPattern {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        if text.len() > 4096 {
            return Err(invalid());
        }
        let mut p = Self::default();
        if text.is_empty() {
            return Ok(p);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|_| invalid())?;
        for (tag, v) in fields(&bytes)? {
            match (tag, v) {
                (1, Value::Int(n)) => p.seed = Some(n as i32),
                (2, v) => p.unlock = number(v, 1)? != 0,
                (3..=6, Value::Bytes(b)) => {
                    for (field, v) in fields(b)? {
                        match (tag, field) {
                            (3, 1) => p.fragment = Some(number(v, 1)? != 0),
                            (3, 2) => p.sleep_ms = Some(number(v, 100)?),
                            (4, 1) => p.nonce_type = Some(number(v, 3)?),
                            (4, 2) => p.nonce_all = Some(number(v, 1)? != 0),
                            (4, 3) => p.nonce_min = Some(number(v, 12)?),
                            (4, 4) => p.nonce_max = Some(number(v, 12)?),
                            (4, 5) => {
                                let Value::Bytes(b) = v else {
                                    return Err(invalid());
                                };
                                if b.len() > 24 || b.len() % 2 != 0 || p.prefixes.len() >= 32 {
                                    return Err(invalid());
                                }
                                let mut decoded = Vec::new();
                                for pair in b.chunks_exact(2) {
                                    let s = std::str::from_utf8(pair).map_err(|_| invalid())?;
                                    decoded.push(u8::from_str_radix(s, 16).map_err(|_| invalid())?);
                                }
                                p.prefixes.push(decoded);
                            }
                            (5, 1) => p.padding_middle = Some(number(v, 255)?),
                            (5, 2) => p.padding_end = Some(number(v, 255)?),
                            (6, 1) => p.low_mode = Some(number(v, 4)?),
                            (6, 2) => {
                                let n = number(v, 240)?;
                                if n > 15 && n % 16 != 0 {
                                    return Err(invalid());
                                }
                                p.low_rotation = Some(n);
                            }
                            _ => return Err(invalid()),
                        }
                    }
                }
                _ => return Err(invalid()),
            }
        }
        if matches!((p.nonce_min,p.nonce_max),(Some(a),Some(b)) if a>b) {
            return Err(invalid());
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protobuf_bounds_and_field_types() {
        let p = MieruTrafficPattern::parse("MgQIARAH").unwrap();
        assert_eq!((p.low_mode, p.low_rotation), (Some(1), Some(7)));
        for data in [
            vec![0x32, 2, 8, 5],
            vec![0x32, 2, 16, 17],
            vec![0x22, 4, 24, 12, 32, 1],
            vec![0x1a, 2, 16, 101],
            vec![0x0a, 0],
            vec![0xff; 20],
            vec![0x32, 255, 255],
        ] {
            let text = base64::engine::general_purpose::STANDARD.encode(data);
            assert!(MieruTrafficPattern::parse(&text).is_err(), "{text}");
        }
        assert!(MieruTrafficPattern::parse(&"A".repeat(4097)).is_err());
    }
}
