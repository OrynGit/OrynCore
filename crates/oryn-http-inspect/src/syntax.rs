//! Loon DSL 的词法器：引号和正则内的管道永远不是动作分隔符。
use crate::invalid;
use std::io;
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Word(String),
    Text(Vec<crate::TemplatePart>),
    Raw(String),
    Var(String),
    Regex(String, String),
    Sym(String),
}
fn template_parts(s: &str, quote: char) -> io::Result<Vec<crate::TemplatePart>> {
    use crate::TemplatePart;
    let mut out = Vec::new();
    let mut literal = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let n = chars.next().ok_or_else(|| invalid("trailing template escape"))?;
            match n {
                '$' if chars.peek() == Some(&'{') => { literal.push_str("${"); chars.next(); },
                'n' => literal.push('\n'), 'r' => literal.push('\r'), 't' => literal.push('\t'),
                '\\' => literal.push('\\'), x if x == quote => literal.push(x),
                x => { literal.push('\\'); literal.push(x); },
            }
        } else if c == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut name = String::new();
            loop {
                match chars.next() {
                    Some('}') => break,
                    Some(c) => name.push(c),
                    None => return Err(invalid("unterminated template variable")),
                }
            }
            if !literal.is_empty() { out.push(TemplatePart::Literal(std::mem::take(&mut literal))); }
            out.push(TemplatePart::Variable(name));
        } else { literal.push(c); }
    }
    if !literal.is_empty() { out.push(TemplatePart::Literal(literal)); }
    Ok(out)
}

pub fn lex(s: &str) -> io::Result<Vec<Token>> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut out = vec![];
    while i < b.len() {
        if out.len() >= 8192 { return Err(invalid("DSL token limit exceeded")); }
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if matches!(b[i], b'"' | b'\'' | b'`') {
            let q = b[i];
            let start = i;
            i += 1;
            let mut escaped = false;
            while i < b.len() {
                if q == b'`' && b[i] == q && b.get(i + 1) == Some(&q) {
                    i += 2;
                    continue;
                }
                if b[i] == q && !escaped {
                    break;
                }
                escaped = q != b'`' && b[i] == b'\\' && !escaped;
                i += 1;
            }
            if i == b.len() {
                return Err(invalid("unterminated DSL string"));
            }
            i += 1;
            out.push(if q == b'`' {
                Token::Raw(oryn_module::unquote(&s[start..i]).map_err(invalid)?)
            } else {
                Token::Text(template_parts(&s[start + 1..i - 1], q as char)?)
            });
            continue;
        }
        if b[i] == b'$' && b.get(i + 1) == Some(&b'{') {
            let start = i + 2;
            i = start;
            let mut quote = false;
            while i < b.len() {
                if b[i] == b'\'' {
                    quote = !quote;
                }
                if b[i] == b'}' && !quote {
                    break;
                }
                i += 1;
            }
            if i == b.len() {
                return Err(invalid("unterminated DSL variable"));
            }
            out.push(Token::Var(s[start..i].into()));
            i += 1;
            continue;
        }
        if b[i] == b'/' {
            i += 1;
            let mut p = String::new();
            let mut class = false;
            let mut closed = false;
            while i < b.len() {
                let c = s[i..].chars().next().unwrap();
                i += c.len_utf8();
                if c == '\\' {
                    let n = s[i..]
                        .chars()
                        .next()
                        .ok_or_else(|| invalid("trailing regex escape"))?;
                    i += n.len_utf8();
                    if n != '/' {
                        p.push('\\')
                    }
                    p.push(n);
                    continue;
                }
                if c == '[' {
                    class = true
                }
                if c == ']' {
                    class = false
                }
                if c == '/' && !class {
                    closed = true;
                    break;
                }
                p.push(c);
            }
            if !closed {
                return Err(invalid("unterminated DSL regex"));
            }
            let start = i;
            while i < b.len() && b[i].is_ascii_alphabetic() {
                i += 1
            }
            out.push(Token::Regex(p, s[start..i].into()));
            continue;
        }
        if i + 1 < b.len() && matches!(&b[i..i + 2], b"==" | b"~=" | b"&&" | b"||") {
            out.push(Token::Sym(s[i..i + 2].into()));
            i += 2;
            continue;
        }
        if b"(),[]{}|=".contains(&b[i]) {
            out.push(Token::Sym((b[i] as char).to_string()));
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !b"(),[]{}|=\"'`".contains(&b[i]) {
            i += 1;
        }
        if i == start {
            return Err(invalid("invalid DSL token"));
        }
        out.push(Token::Word(s[start..i].into()));
        if out.len() > 8192 {
            return Err(invalid("DSL token limit exceeded"));
        }
    }
    Ok(out)
}
