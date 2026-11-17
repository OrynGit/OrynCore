//! 本机全局真实 IP 域名列表，不修改订阅的 Fake-IP 黑白名单。
use std::net::IpAddr;

pub fn normalize_real_ip_domains(values: &[String]) -> Result<Vec<String>, String> {
    if values.len() > 128 {
        return Err("real IP domains exceed 128 entries".into());
    }
    let mut result = Vec::with_capacity(values.len());
    for raw in values {
        let trimmed = raw.trim();
        let name = trimmed.strip_suffix('.').unwrap_or(trimmed).to_ascii_lowercase();
        if name.is_empty() || name.len() > 253
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || b".-_*?".contains(&c))
            || name.split('.').any(|label| label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-'))
            || name.parse::<IpAddr>().is_ok()
        {
            return Err("invalid real IP domain; use a hostname or an ASCII wildcard pattern".into());
        }
        if result.contains(&name) {
            return Err("duplicate real IP domain".into());
        }
        result.push(name);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_ip_validation_and_limits() {
        assert_eq!(normalize_real_ip_domains(&[" Example.COM. ".into(), "?chaoxing".into(), "*.example".into()]).unwrap(), ["example.com", "?chaoxing", "*.example"]);
        for bad in ["", "https://example.com", "example.com:80", "127.0.0.1", "::1", "a..test", "-a.test", "a-.test", "a/test", "a test", "域名.test", "a.test.."] {
            assert!(normalize_real_ip_domains(&[bad.into()]).is_err(), "{bad}");
        }
        assert!(normalize_real_ip_domains(&["A.test".into(), "a.test.".into()]).is_err());
        assert!(normalize_real_ip_domains(&[format!("{}.test", "a".repeat(64))]).is_err());
        assert!(normalize_real_ip_domains(&(0..129).map(|n| format!("n{n}.test")).collect::<Vec<_>>()).is_err());
    }
}
