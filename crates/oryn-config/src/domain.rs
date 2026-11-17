//! 域名匹配的基础工具：mihomo 通配写法与 glob 通配符。

/// 规范化域名：去掉首尾空白与末尾的点，转小写。
pub fn normalize_domain(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// `domain` 是否等于 `suffix` 或是其子域名。
pub fn suffix_match(domain: &str, suffix: &str) -> bool {
    if domain.len() == suffix.len() {
        return domain == suffix;
    }
    domain.len() > suffix.len()
        && domain.ends_with(suffix)
        && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
}

/// mihomo 的域名写法（用于 hosts、规则集 `domain`、`nameserver-policy`、嗅探的域名列表）。
///
/// - `+.a.com`：`a.com` 及其所有子域名
/// - `.a.com`：`a.com` 的所有子域名（不含 `a.com`）
/// - `*.a.com`：`a.com` 的一级子域名；`*` 可出现在任意标签位置，每个 `*` 匹配一级
/// - 其它：完整匹配
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPattern {
    Exact(String),
    Suffix(String),
    Subdomains(String),
    Wildcard(Vec<String>),
}

impl DomainPattern {
    pub fn parse(s: &str) -> Option<DomainPattern> {
        let raw = s.trim().to_ascii_lowercase();
        if let Some(rest) = raw.strip_prefix("+.") {
            let rest = normalize_domain(rest);
            return (!rest.is_empty()).then_some(DomainPattern::Suffix(rest));
        }
        if let Some(rest) = raw.strip_prefix('.') {
            let rest = normalize_domain(rest);
            return (!rest.is_empty()).then_some(DomainPattern::Subdomains(rest));
        }
        let s = normalize_domain(&raw);
        if s.is_empty() {
            return None;
        }
        if s.split('.').any(|l| l == "*") {
            return Some(DomainPattern::Wildcard(
                s.split('.').map(str::to_string).collect(),
            ));
        }
        Some(DomainPattern::Exact(s))
    }

    /// Surge 域名集写法：`.a.com` 匹配 `a.com` 及其子域名，其它为完整匹配。
    pub fn parse_surge(s: &str) -> Option<DomainPattern> {
        let s = normalize_domain(s);
        if s.is_empty() {
            return None;
        }
        match s.strip_prefix('.') {
            Some(rest) if !rest.is_empty() => Some(DomainPattern::Suffix(rest.to_string())),
            Some(_) => None,
            None => Some(DomainPattern::Exact(s)),
        }
    }

    /// `domain` 须已规范化。
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            DomainPattern::Exact(d) => domain == d,
            DomainPattern::Suffix(d) => suffix_match(domain, d),
            DomainPattern::Subdomains(d) => domain.len() > d.len() && suffix_match(domain, d),
            DomainPattern::Wildcard(labels) => {
                let parts: Vec<&str> = domain.split('.').collect();
                parts.len() == labels.len()
                    && parts.iter().zip(labels).all(|(p, l)| l == "*" || p == l)
            }
        }
    }
}

/// glob 通配：`*` 匹配任意长度字符（含 `.`），`?` 匹配单个字符，不区分大小写。
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mihomo_patterns() {
        let plus = DomainPattern::parse("+.Baidu.com.").unwrap();
        assert!(
            plus.matches("baidu.com")
                && plus.matches("a.b.baidu.com")
                && !plus.matches("xbaidu.com")
        );
        let dot = DomainPattern::parse(".baidu.com").unwrap();
        assert!(
            !dot.matches("baidu.com")
                && dot.matches("tieba.baidu.com")
                && dot.matches("1.tieba.baidu.com")
        );
        let star = DomainPattern::parse("*.baidu.com").unwrap();
        assert!(
            star.matches("tieba.baidu.com")
                && !star.matches("1.tieba.baidu.com")
                && !star.matches("baidu.com")
        );
        let mid = DomainPattern::parse("*.*.microsoft.com").unwrap();
        assert!(mid.matches("a.b.microsoft.com") && !mid.matches("a.microsoft.com"));
        assert!(DomainPattern::parse("*").unwrap().matches("localhost"));
        assert_eq!(
            DomainPattern::parse("a.com"),
            Some(DomainPattern::Exact("a.com".into()))
        );
        assert_eq!(DomainPattern::parse("+."), None);
    }

    #[test]
    fn surge_patterns() {
        let p = DomainPattern::parse_surge(".apple.com").unwrap();
        assert!(p.matches("apple.com") && p.matches("www.apple.com"));
        assert!(DomainPattern::parse_surge("a.com")
            .unwrap()
            .matches("a.com"));
    }

    #[test]
    fn glob() {
        assert!(glob_match("*.google.com", "www.google.com"));
        assert!(glob_match("*.google.com", "a.b.google.com"));
        assert!(!glob_match("*.google.com", "google.com"));
        assert!(glob_match("Home*", "home-5G"));
        assert!(glob_match("a?c", "abc") && !glob_match("a?c", "ac"));
        assert!(glob_match("*", "") && glob_match("aa:bb:*", "AA:BB:CC:DD"));
        assert!(!glob_match("nr", "LTE"));
    }
}
