use crate::invalid;
use serde_json::Value;
use std::io;
#[derive(Debug)]
enum Part {
    Key(String),
    Index(usize),
}
fn parts(path: &str) -> io::Result<Vec<Part>> {
    let mut out = vec![];
    let mut s = path;
    while !s.is_empty() {
        if let Some(r) = s.strip_prefix('[') {
            let n = r.find(']').ok_or_else(|| invalid("unclosed JSON index"))?;
            let i = r[..n].parse().map_err(invalid)?;
            out.push(Part::Index(i));
            s = &r[n + 1..];
        } else {
            let n = s.find(['.', '[']).unwrap_or(s.len());
            if n == 0 {
                return Err(invalid("empty JSON path key"));
            }
            out.push(Part::Key(s[..n].into()));
            s = &s[n..];
        }
        if let Some(r) = s.strip_prefix('.') {
            if r.is_empty() {
                return Err(invalid("empty JSON path key"));
            }
            s = r;
        }
        if out.len() > 64 {
            return Err(invalid("JSON path too deep"));
        }
    }
    if out.is_empty() {
        return Err(invalid("empty JSON path"));
    }
    Ok(out)
}
fn parent<'a>(root: &'a mut Value, parts: &[Part], create: bool) -> Option<&'a mut Value> {
    let mut cur = root;
    for (n, p) in parts.iter().take(parts.len() - 1).enumerate() {
        if cur.is_null() && create {
            *cur = match p {
                Part::Key(_) => serde_json::json!({}),
                Part::Index(_) => serde_json::json!([]),
            }
        }
        cur = match p {
            Part::Key(k) => {
                let obj = cur.as_object_mut()?;
                if create {
                    obj.entry(k).or_insert_with(|| match parts.get(n + 1) {
                        Some(Part::Index(_)) => serde_json::json!([]),
                        _ => serde_json::json!({}),
                    })
                } else {
                    obj.get_mut(k)?
                }
            }
            Part::Index(i) => {
                let a = cur.as_array_mut()?;
                if create && *i == a.len() {
                    a.push(match parts.get(n + 1) {
                        Some(Part::Index(_)) => serde_json::json!([]),
                        _ => serde_json::json!({}),
                    });
                }
                a.get_mut(*i)?
            }
        };
    }
    Some(cur)
}
pub fn set(root: &mut Value, path: &str, value: Value, create: bool) -> io::Result<()> {
    let parts = parts(path)?;
    let Some(cur) = parent(root, &parts, create) else {
        return Ok(());
    };
    match parts.last().unwrap() {
        Part::Key(k) => {
            if cur.is_null() && create {
                *cur = serde_json::json!({})
            }
            if let Some(o) = cur.as_object_mut() {
                if create || o.contains_key(k) {
                    o.insert(k.clone(), value);
                }
            }
        }
        Part::Index(i) => {
            if let Some(a) = cur.as_array_mut() {
                if *i < a.len() {
                    a[*i] = value
                } else if create && *i == a.len() {
                    a.push(value)
                }
            }
        }
    }
    Ok(())
}
pub fn delete(root: &mut Value, path: &str) -> io::Result<()> {
    let parts = parts(path)?;
    let Some(cur) = parent(root, &parts, false) else {
        return Ok(());
    };
    match parts.last().unwrap() {
        Part::Key(k) => {
            if let Some(o) = cur.as_object_mut() {
                o.remove(k);
            }
        }
        Part::Index(i) => {
            if let Some(a) = cur.as_array_mut() {
                if *i < a.len() {
                    a.remove(*i);
                }
            }
        }
    }
    Ok(())
}
