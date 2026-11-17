//! 读取 YAML 值的辅助函数。

use yaml_rust2::Yaml;

pub fn get<'a>(y: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    match y {
        Yaml::Hash(h) => h
            .get(&Yaml::String(key.to_string()))
            .filter(|v| !v.is_null()),
        _ => None,
    }
}

/// 标量转字符串（字符串、整数、浮点、布尔）。
pub fn scalar(y: &Yaml) -> Option<String> {
    match y {
        Yaml::String(s) | Yaml::Real(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn str_of(y: &Yaml, key: &str) -> Option<String> {
    get(y, key)
        .and_then(scalar)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn bool_of(y: &Yaml, key: &str) -> Option<bool> {
    match get(y, key)? {
        Yaml::Boolean(b) => Some(*b),
        Yaml::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" => Some(true),
            "false" | "no" | "off" => Some(false),
            _ => None,
        },
        Yaml::Integer(i) => Some(*i != 0),
        _ => None,
    }
}

pub fn int_of(y: &Yaml, key: &str) -> Option<i64> {
    match get(y, key)? {
        Yaml::Integer(i) => Some(*i),
        Yaml::String(s) | Yaml::Real(s) => s.trim().parse::<f64>().ok().map(|f| f as i64),
        _ => None,
    }
}

/// 字符串列表：接受列表，也接受单个标量。
pub fn list_of(y: &Yaml, key: &str) -> Vec<String> {
    match get(y, key) {
        Some(v) => list_value(v),
        None => Vec::new(),
    }
}

pub fn list_value(v: &Yaml) -> Vec<String> {
    match v {
        Yaml::Array(a) => a
            .iter()
            .filter_map(scalar)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        other => scalar(other)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .into_iter()
            .collect(),
    }
}

/// 映射的键值对（保持书写顺序）。
pub fn entries(y: &Yaml) -> Vec<(String, &Yaml)> {
    match y {
        Yaml::Hash(h) => h
            .iter()
            .filter_map(|(k, v)| scalar(k).map(|k| (k, v)))
            .collect(),
        _ => Vec::new(),
    }
}
