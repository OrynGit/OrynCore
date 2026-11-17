//! 需求表达式只接受变量、数值/字符串、比较与布尔组合，不执行 JS。
use crate::ParseError;
use std::collections::BTreeMap;
#[derive(Debug, Clone)]
enum Token {
    Value(String),
    Op(String),
}
pub fn evaluate(source: &str, env: &BTreeMap<String, String>) -> Result<bool, ParseError> {
    if source.len() > 4096 {
        return Err(ParseError("requirement too large".into()));
    }
    let lex = regex::Regex::new(
        r#"\s*(?:([A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)*)|'([^']*)'|"([^"]*)"|(&&|\|\||>=|<=|!=|==|[()=<>!]))"#,
    )
    .unwrap();
    let mut tokens = vec![];
    let mut end = 0;
    for c in lex.captures_iter(source) {
        let m = c.get(0).unwrap();
        if m.start() != end {
            return Err(ParseError("invalid requirement token".into()));
        }
        end = m.end();
        if let Some(v) = c.get(1) {
            // 全大写的是变量；其余裸词（`SYSTEM = iOS`）按字符串字面量处理，与带引号写法等价。
            let word = v.as_str();
            let value = if let Some(value) = env.get(word) {
                value.clone()
            } else if word.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                return Err(ParseError(format!("unknown requirement variable {word}")));
            } else {
                word.into()
            };
            tokens.push(Token::Value(value))
        } else if let Some(v) = c.get(2).or_else(|| c.get(3)) {
            tokens.push(Token::Value(v.as_str().into()))
        } else {
            tokens.push(Token::Op(c[4].into()))
        }
    }
    if !source[end..].trim().is_empty() {
        return Err(ParseError("invalid requirement expression".into()));
    }
    let mut p = Parser {
        tokens,
        pos: 0,
        depth: 0,
    };
    let result = p.or()?;
    if p.pos != p.tokens.len() {
        return Err(ParseError("trailing requirement expression".into()));
    }
    Ok(result)
}
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
}
impl Parser {
    fn eat(&mut self, s: &str) -> bool {
        if matches!(self.tokens.get(self.pos),Some(Token::Op(x)) if x==s) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn or(&mut self) -> Result<bool, ParseError> {
        let mut a = self.and()?;
        while self.eat("||") {
            let b = self.and()?;
            a |= b;
        }
        Ok(a)
    }
    fn and(&mut self) -> Result<bool, ParseError> {
        let mut a = self.atom()?;
        while self.eat("&&") {
            let b = self.atom()?;
            a &= b;
        }
        Ok(a)
    }
    fn atom(&mut self) -> Result<bool, ParseError> {
        self.depth += 1;
        if self.depth > 32 {
            return Err(ParseError("requirement nesting limit".into()));
        }
        let r = if self.eat("!") {
            !self.atom()?
        } else if self.eat("(") {
            let r = self.or()?;
            if !self.eat(")") {
                return Err(ParseError("unclosed requirement".into()));
            }
            r
        } else {
            let a = self.val()?;
            let op = match self.tokens.get(self.pos) {
                Some(Token::Op(s)) => s.clone(),
                _ => return Err(ParseError("requirement needs comparison".into())),
            };
            self.pos += 1;
            let b = self.val()?;
            let order = compare(&a, &b);
            match op.as_str() {
                "=" | "==" => order == Some(std::cmp::Ordering::Equal),
                "!=" => order != Some(std::cmp::Ordering::Equal),
                ">=" => matches!(
                    order,
                    Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
                ),
                "<=" => matches!(
                    order,
                    Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
                ),
                ">" => order == Some(std::cmp::Ordering::Greater),
                "<" => order == Some(std::cmp::Ordering::Less),
                _ => return Err(ParseError("invalid requirement operator".into())),
            }
        };
        self.depth -= 1;
        Ok(r)
    }
    fn val(&mut self) -> Result<String, ParseError> {
        let Some(Token::Value(s)) = self.tokens.get(self.pos) else {
            return Err(ParseError("requirement needs value".into()));
        };
        self.pos += 1;
        Ok(s.clone())
    }
}
/// 两侧都是点分数字（`17`、`9.3.1`）时按版本逐段比较（缺段视为 0）；
/// 否则按字符串比较。不经 f64，避免 "9.3.1" 解析失败后退化为字典序。
fn compare(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    fn segments(s: &str) -> Option<Vec<u64>> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        s.split('.').map(|p| p.parse::<u64>().ok()).collect()
    }
    match (segments(a), segments(b)) {
        (Some(x), Some(y)) => {
            let n = x.len().max(y.len());
            for i in 0..n {
                let (l, r) = (x.get(i).copied().unwrap_or(0), y.get(i).copied().unwrap_or(0));
                if l != r {
                    return Some(l.cmp(&r));
                }
            }
            Some(std::cmp::Ordering::Equal)
        }
        _ => Some(a.cmp(b)),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn constraints() {
        let env = BTreeMap::from([
            ("SYSTEM".into(), "iOS".into()),
            ("CORE_VERSION".into(), "20".into()),
        ]);
        assert!(evaluate(
            "CORE_VERSION>=20 && (SYSTEM = 'iOS' || SYSTEM = 'tvOS')",
            &env
        )
        .unwrap());
        assert!(!evaluate("CORE_VERSION>=99", &env).unwrap());
        assert!(evaluate("SYSTEM = iOS", &env).unwrap());
        assert!(!evaluate("SYSTEM == macOS", &env).unwrap());
        assert!(evaluate("UNKNOWN_VAR = 1", &env).is_err());
        assert!(evaluate("process.exit()", &env).is_err());
    }
    #[test]
    fn dotted_versions_compare_numerically() {
        let env = BTreeMap::from([
            ("SYSTEM_VERSION".into(), "9.3.1".into()),
            ("CORE_VERSION".into(), "17.4.1".into()),
        ]);
        assert!(!evaluate("SYSTEM_VERSION>=10", &env).unwrap());
        assert!(evaluate("CORE_VERSION>=9", &env).unwrap());
        assert!(evaluate("CORE_VERSION>=17.4", &env).unwrap());
        assert!(evaluate("CORE_VERSION<17.10", &env).unwrap());
        assert!(evaluate("SYSTEM_VERSION=9.3.1", &env).unwrap());
    }
}
