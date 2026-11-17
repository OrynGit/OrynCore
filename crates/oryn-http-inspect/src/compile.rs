use crate::{
    syntax::{lex, Token},
    *,
};
pub use oryn_module::Resources;
use oryn_module::{split_top, unquote, ModuleFormat, ModuleIR};
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    args: BTreeMap<String, Value>,
    depth: usize,
    conditions: usize,
}
impl Parser {
    fn next(&mut self) -> io::Result<Token> {
        let t = self
            .tokens
            .get(self.pos)
            .cloned()
            .ok_or_else(|| invalid("unexpected end of DSL"))?;
        self.pos += 1;
        Ok(t)
    }
    fn eat(&mut self, s: &str) -> bool {
        if matches!(self.tokens.get(self.pos),Some(Token::Word(x)|Token::Sym(x)) if x==s) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, s: &str) -> io::Result<()> {
        if self.eat(s) {
            Ok(())
        } else {
            Err(invalid(format!("expected {s}")))
        }
    }
    fn expr(&mut self) -> io::Result<Expr> {
        if self.depth >= 32 { return Err(invalid("DSL nesting exceeds 32")); }
        self.depth += 1;
        let result = self.expr_inner();
        self.depth -= 1;
        result
    }
    fn expr_inner(&mut self) -> io::Result<Expr> {
        match self.next()? {
            Token::Text(s) => {
                for (name, value) in &self.args {
                    if value.is_null() && s.iter().any(|part| matches!(part, TemplatePart::Variable(v) if v == name)) {
                        return Err(invalid(
                            "missing plugin value is only permitted in an argument Object",
                        ));
                    }
                }
                Ok(crate::bound_template(s, &self.args))
            }
            Token::Raw(s) => Ok(Expr::Literal(s.into())),
            Token::Regex(p, f) => Ok(Expr::Regex(Pattern::new(&p, &f)?)),
            Token::Var(v) => Ok(self
                .args
                .get(&v)
                .cloned()
                .map(Expr::Literal)
                .unwrap_or(Expr::Variable(v))),
            Token::Word(s) => serde_json::from_str(&s).map(Expr::Literal).map_err(invalid),
            Token::Sym(s) if s == "{" => {
                let mut o = serde_json::Map::new();
                loop {
                    let Token::Var(k) = self.next()? else {
                        return Err(invalid("script argument object requires plugin variables"));
                    };
                    let v = self
                        .args
                        .get(&k)
                        .ok_or_else(|| invalid(format!("undeclared plugin argument {k}")))?;
                    if o.insert(k, v.clone()).is_some() {
                        return Err(invalid("duplicate plugin argument"));
                    }
                    if self.eat("}") {
                        break;
                    }
                    self.expect(",")?;
                }
                Ok(Expr::Literal(Value::Object(o)))
            }
            Token::Sym(s) if s == "[" => {
                let mut xs = vec![];
                if self.eat("]") {
                    return Err(invalid("empty batch array"));
                }
                loop {
                    xs.push(self.expr()?);
                    if self.eat("]") {
                        break;
                    }
                    self.expect(",")?;
                }
                Ok(Expr::Array(xs))
            }
            _ => Err(invalid("invalid expression")),
        }
    }
    fn cond(&mut self) -> io::Result<Condition> {
        let mut a = self.and()?;
        while self.eat("||") {
            a = Condition::Or(Box::new(a), Box::new(self.and()?));
        }
        Ok(a)
    }
    fn and(&mut self) -> io::Result<Condition> {
        let mut a = self.atom()?;
        while self.eat("&&") {
            a = Condition::And(Box::new(a), Box::new(self.atom()?));
        }
        Ok(a)
    }
    fn atom(&mut self) -> io::Result<Condition> {
        self.conditions += 1;
        if self.depth >= 32 || self.conditions > 128 { return Err(invalid("DSL condition depth or count exceeded")); }
        self.depth += 1;
        let result = self.atom_inner();
        self.depth -= 1;
        result
    }
    fn atom_inner(&mut self) -> io::Result<Condition> {
        if self.eat("(") {
            let c = self.cond()?;
            self.expect(")")?;
            return Ok(c);
        }
        let l = self.expr()?;
        if self.eat("==") {
            let r = self.expr()?;
            if matches!(l, Expr::Regex(_) | Expr::Array(_))
                || matches!(r, Expr::Regex(_) | Expr::Array(_))
            {
                return Err(invalid(
                    "equality requires scalar values, not Regex or Array",
                ));
            }
            return Ok(Condition::Eq(l, r));
        }
        self.expect("~=")?;
        if !matches!(
            self.tokens.get(self.pos),
            Some(Token::Regex(..) | Token::Var(_))
        ) {
            return Err(invalid(
                "regex condition requires Regex or string plugin parameter",
            ));
        }
        let r = self.expr()?;
        let p = match r {
            Expr::Regex(p) => p,
            Expr::Literal(Value::String(s)) => Pattern::new(&s, "")?,
            _ => return Err(invalid("regex condition needs regex or string parameter")),
        };
        let name = if self.eat("as") {
            match self.next()? {
                Token::Word(s) => Some(s),
                _ => return Err(invalid("capture needs name")),
            }
        } else {
            None
        };
        Ok(Condition::Match(l, p, name))
    }
}
// 捕获必须在每条成功路径出现，AND 右侧可引用左侧必经捕获。
fn validate_condition(
    c: &Condition,
    response: bool,
    args: &BTreeMap<String, Value>,
) -> io::Result<BTreeMap<String, usize>> {
    use std::collections::BTreeSet;
    fn walk(
        c: &Condition,
        response: bool,
        args: &BTreeMap<String, Value>,
        seen: &mut BTreeSet<String>,
        available: &BTreeMap<String, usize>,
    ) -> io::Result<BTreeMap<String, usize>> {
        let mut out = available.clone();
        match c {
            Condition::Always => {}
            Condition::Eq(a, b) => {
                validate_expr(a, response, available)?;
                validate_expr(b, response, available)?;
            }
            Condition::Match(e, pattern, name) => {
                validate_expr(e, response, available)?;
                if let Some(n) = name {
                    if n.is_empty()
                        || !n.bytes().enumerate().all(|(i, b)| {
                            b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                        })
                    {
                        return Err(invalid("invalid capture identifier"));
                    }
                    if args.contains_key(n) || !seen.insert(n.clone()) {
                        return Err(invalid("duplicate capture or plugin argument conflict"));
                    }
                    out.insert(n.clone(), pattern.capture_count());
                }
            }
            Condition::And(a, b) => {
                let left = walk(a, response, args, seen, available)?;
                return walk(b, response, args, seen, &left);
            }
            Condition::Or(a, b) => {
                let left = walk(a, response, args, seen, available)?;
                let right = walk(b, response, args, seen, available)?;
                return Ok(left.into_iter().filter(|(key, _)| right.contains_key(key)).collect());
            }
        }
        Ok(out)
    }
    walk(c, response, args, &mut BTreeSet::new(), &BTreeMap::new())
}
fn validate_expr(
    e: &Expr,
    response: bool,
    captures: &BTreeMap<String, usize>,
) -> io::Result<()> {
    match e {
        Expr::Variable(v) => {
            let builtin = v == "url"
                || v == "request.method"
                || v.starts_with("request.header[")
                || (response && (v == "response.status" || v.starts_with("response.header[")));
            let capture = v
                .rsplit_once('.')
                .is_some_and(|(n, i)| !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit()) && captures.get(n).is_some_and(|&count| i.parse::<usize>().is_ok_and(|index| index < count)));
            if !builtin && !capture {
                return Err(invalid(format!("unavailable variable or capture {v}")));
            }
        }
        Expr::BoundTemplate(parts) => {
            for part in parts {
                if let TemplatePart::Variable(v) = part {
                    validate_expr(&Expr::Variable(v.clone()), response, captures)?;
                }
            }
        }
        Expr::Template(s) => {
            let mut rest = s.as_str();
            while let Some(i) = rest.find("${") {
                let escaped = rest[..i].ends_with('\\');
                rest = &rest[i + 2..];
                let j = rest
                    .find('}')
                    .ok_or_else(|| invalid("unterminated template variable"))?;
                if !escaped {
                    validate_expr(&Expr::Variable(rest[..j].into()), response, captures)?;
                }
                rest = &rest[j + 1..];
            }
        }
        Expr::Array(xs) => {
            for x in xs {
                validate_expr(x, response, captures)?;
            }
        }
        Expr::Literal(Value::Null) => {
            return Err(invalid(
                "missing plugin value is only permitted in an argument Object",
            ))
        }
        _ => {}
    }
    Ok(())
}
fn literal(e: &Expr) -> io::Result<String> {
    match e {
        Expr::Literal(Value::String(s)) | Expr::Template(s) => Ok(s.clone()),
        _ => Err(invalid("expected fixed string")),
    }
}
fn number(e: &Expr) -> io::Result<u16> {
    match e {
        Expr::Literal(v) => v
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| (100..=599).contains(n))
            .ok_or_else(|| invalid("invalid HTTP status")),
        _ => Err(invalid("expected status number")),
    }
}
fn regex(e: &Expr) -> io::Result<Pattern> {
    if let Expr::Regex(p) = e {
        Ok(p.clone())
    } else {
        Err(invalid("expected regex"))
    }
}
fn has_url_guard(c: &Condition) -> bool {
    match c {
        Condition::Match(Expr::Variable(v), _, _) => v == "url",
        Condition::And(a,b) => has_url_guard(a) || has_url_guard(b),
        Condition::Or(a,b) => has_url_guard(a) && has_url_guard(b),
        _ => false,
    }
}
fn url_guard(c: &Condition) -> Option<Pattern> {
    match c {
        Condition::Match(Expr::Variable(v), p, _) if v == "url" => Some(p.clone()),
        Condition::And(a, b) => match (url_guard(a), url_guard(b)) {
            (Some(_), Some(_)) => None,
            (a, b) => a.or(b),
        },
        _ => None,
    }
}
fn mime(s: &str) -> String {
    match s {
        "json" => "application/json",
        "text" | "plain" => "text/plain",
        "html" => "text/html",
        "css" => "text/css",
        "javascript" => "application/javascript",
        "png" => "image/png",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        _ => "application/octet-stream",
    }
    .into()
}
fn load(resources: &Resources, path: &str) -> io::Result<std::sync::Arc<[u8]>> {
    resources.get(path).cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing module resource {path}"),
        )
    })
}
fn jq(filter: &str) -> io::Result<Action> {
    Ok(Action::Jq(Rc::new(
        oryn_jq::Program::compile(filter).map_err(invalid)?,
    )))
}
fn action(name: &str, args: &[Expr], cond: &Condition, res: &Resources) -> io::Result<Vec<Action>> {
    let short = name
        .strip_prefix("request.")
        .or_else(|| name.strip_prefix("response."))
        .unwrap_or(name);
    fn contains_regex(e: &Expr) -> bool { match e { Expr::Regex(_) => true, Expr::Array(a) => a.iter().any(contains_regex), _ => false } }
    for (i, arg) in args.iter().enumerate() {
        let regex_position = (short == "header.replace" && i == 1) || (short == "body.replace" && i == 0);
        if !regex_position && contains_regex(arg) { return Err(invalid("Regex is only valid in a regex argument")); }
    }
    let counts = match short {
        "url.replace" | "header.del" | "json.delete" | "json.jq" | "json.jq_file"
        | "reject_dict" | "reject_array" | "reject_img" => 1..=1,
        "redirect" | "header.add" | "header.set" | "body.replace" | "json.add" | "json.replace" => {
            2..=2
        }
        "header.replace" => 3..=3,
        "reject" => 1..=2,
        "body.mock" | "body.mock_file" => {
            if name.starts_with("response.") {
                2..=4
            } else {
                2..=3
            }
        }
        _ => return Err(invalid(format!("unsupported rewrite action {name}"))),
    };
    if !counts.contains(&args.len()) {
        return Err(invalid(format!("invalid {name} argument count")));
    }
    if args.iter().any(|a| matches!(a, Expr::Array(_))) {
        if !matches!(
            short,
            "header.add"
                | "header.set"
                | "header.del"
                | "header.replace"
                | "body.replace"
                | "json.add"
                | "json.delete"
                | "json.replace"
        ) {
            return Err(invalid("action does not accept batch arguments"));
        }
        let n = match args.first() {
            Some(Expr::Array(a)) => a.len(),
            _ => return Err(invalid("cannot mix batch and scalar arguments")),
        };
        if n == 0
            || args.iter().any(
                |a| matches!(a,Expr::Array(xs) if xs.iter().any(|v|matches!(v,Expr::Array(_)))),
            )
        {
            return Err(invalid("batch arguments must be nonempty and not nested"));
        }
        if args
            .iter()
            .any(|a| !matches!(a,Expr::Array(xs) if xs.len()==n))
        {
            return Err(invalid("unequal batch arguments"));
        }
        let mut out = vec![];
        for i in 0..n {
            let a = args
                .iter()
                .map(|x| match x {
                    Expr::Array(v) => v[i].clone(),
                    _ => unreachable!(),
                })
                .collect::<Vec<_>>();
            out.extend(action(name, &a, cond, res)?);
        }
        return Ok(out);
    }
    let get = |i: usize| {
        args.get(i)
            .ok_or_else(|| invalid(format!("missing {name} argument {i}")))
    };
    let s = |i| literal(get(i)?);
    let a = match name {
        "url.replace" => Action::Url(
            url_guard(cond).ok_or_else(|| invalid("URL replacement needs mandatory URL regex"))?,
            get(0)?.clone(),
        ),
        "redirect" => Action::Redirect(
            {
                let status = number(get(0)?)?;
                if !matches!(status, 302 | 307) {
                    return Err(invalid("Loon redirect supports 302 or 307"));
                }
                status
            },
            url_guard(cond).ok_or_else(|| invalid("redirect needs mandatory URL regex"))?,
            get(1)?.clone(),
        ),
        "reject" if args.len() == 2 => Action::RejectText(number(get(0)?)?, s(1)?),
        "reject" | "reject_dict" | "reject_array" | "reject_img" => Action::Reject(
            if args.is_empty() {
                404
            } else {
                number(get(0)?)?
            },
            name.strip_prefix("reject_").unwrap_or("").into(),
        ),
        n if n.ends_with(".header.add") => Action::HeaderAdd(s(0)?, get(1)?.clone()),
        n if n.ends_with(".header.set") => Action::HeaderSet(s(0)?, get(1)?.clone()),
        n if n.ends_with(".header.del") => Action::HeaderDelete(s(0)?),
        n if n.ends_with(".header.replace") => {
            Action::HeaderRegex(s(0)?, regex(get(1)?)?, get(2)?.clone())
        }
        n if n.ends_with(".body.replace") => Action::BodyRegex(regex(get(0)?)?, get(1)?.clone()),
        n if n.ends_with(".json.add") => Action::JsonAdd(s(0)?, get(1)?.clone()),
        n if n.ends_with(".json.replace") => Action::JsonReplace(s(0)?, get(1)?.clone()),
        n if n.ends_with(".json.delete") => Action::JsonDelete(s(0)?),
        n if n.ends_with(".json.jq") => jq(&s(0)?)?,
        n if n.ends_with(".json.jq_file") => {
            let bytes = load(res, &s(0)?)?;
            let bad_resource = |e: String| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid jq resource: {e}"));
            let source = std::str::from_utf8(&bytes).map_err(|e| bad_resource(e.to_string()))?;
            jq(source).map_err(|e| bad_resource(e.to_string()))?
        }
        n if n.ends_with(".body.mock") || n.ends_with(".body.mock_file") => {
            let mut body = if n.ends_with("_file") {
                load(res, &s(1)?)?.to_vec()
            } else {
                s(1)?.into_bytes()
            };
            let response = n.starts_with("response");
            let flag = if response { 3 } else { 2 };
            if args
                .get(flag)
                .is_some_and(|e| !matches!(e, Expr::Literal(Value::Bool(_))))
            {
                return Err(invalid("mock base64 flag must be Boolean"));
            }
            if matches!(args.get(flag), Some(Expr::Literal(Value::Bool(true)))) {
                body = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
                    .map_err(|e| if n.ends_with("_file") {
                        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid mock resource: {e}"))
                    } else { invalid(e) })?;
            }
            Action::Mock {
                status: if response {
                    Some(args.get(2).map(number).transpose()?.unwrap_or(200))
                } else {
                    None
                },
                body,
                content_type: mime(&s(0)?),
                headers: vec![],
            }
        }
        _ => return Err(invalid(format!("unsupported rewrite action {name}"))),
    };
    Ok(vec![a])
}
fn loon(
    line: &str,
    args: &BTreeMap<String, Value>,
    res: &Resources,
) -> io::Result<(bool, Condition, Vec<Action>)> {
    let mut p = Parser {
        tokens: lex(line)?,
        pos: 0,
        args: args.clone(),
        depth: 0, conditions: 0,
    };
    let response = p.eat("response");
    if !response {
        p.expect("request")?
    }
    p.expect("if")?;
    let c = p.cond()?;
    p.expect("then")?;
    let captures = validate_condition(&c, response, args)?;
    let mut actions = vec![];
    let mut names = vec![];
    loop {
        let Token::Word(n) = p.next()? else {
            return Err(invalid("expected action"));
        };
        let mut args = vec![];
        if p.eat("(") && !p.eat(")") {
            loop {
                args.push(p.expr()?);
                if p.eat(")") {
                    break;
                }
                p.expect(",")?;
            }
        }
        if (response
            && (n.starts_with("request.")
                || matches!(n.as_str(), "url.replace" | "redirect")
                || n.starts_with("reject")))
            || (!response && n.starts_with("response."))
        {
            return Err(invalid("action is not available in this stage"));
        }
        for e in &args {
            validate_expr(e, response, &captures)?;
        }
        names.push(n.clone());
        actions.extend(action(&n, &args, &c, res)?);
        if !p.eat("|") {
            break;
        }
    }
    if p.pos != p.tokens.len() {
        return Err(invalid("unexpected text after rewrite"));
    }
    let mock_count = names
        .iter()
        .filter(|n| matches!(n.as_str(), "response.body.mock" | "response.body.mock_file"))
        .count();
    if mock_count > 0
        && (mock_count != 1
            || names.iter().any(|n| {
                !n.starts_with("response.header.")
                    && !matches!(n.as_str(), "response.body.mock" | "response.body.mock_file")
            }))
    {
        return Err(invalid(
            "response mock only permits response header actions",
        ));
    }
    if mock_count > 0 {
        validate_condition(&c, false, args)?;
    }
    let mock = actions.iter().any(|a| {
        matches!(
            a,
            Action::Mock {
                status: Some(_),
                ..
            }
        )
    });
    Ok((response && !mock, c, actions))
}
fn legacy(
    section: &str,
    line: &str,
    dialect: ModuleFormat,
    res: &Resources,
) -> io::Result<(bool, Condition, Vec<Action>)> {
    let mut v = Vec::new();
    let mut rest = line.trim();
    let head_count = if rest.starts_with("http-") { 2 } else { 1 };
    for _ in 0..head_count {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        v.push(&rest[..end]);
        rest = rest[end..].trim_start();
    }
    v.extend(split_top(rest, ' ').map_err(invalid)?);
    if v.len() < 2 {
        return Err(invalid("incomplete rewrite"));
    }
    let mut response = false;
    let mut i = 0;
    if v[0].starts_with("http-") {
        response = v[0].starts_with("http-response");
        i = 1;
    }
    let pat = Pattern::new(
        v[i],
        if dialect == ModuleFormat::Loon {
            "i"
        } else {
            ""
        },
    )?;
    let c = Condition::Match(Expr::Variable("url".into()), pat.clone(), None);
    i += 1;
    let e = |s: &str| {
        unquote(s)
            .map(|s| Expr::Literal(Value::String(s)))
            .map_err(invalid)
    };
    let mut actions = vec![];
    if v[0].ends_with("-jq") {
        actions.push(jq(&unquote(
            v.get(i).ok_or_else(|| invalid("missing jq filter"))?,
        )
        .map_err(invalid)?)?);
        return Ok((response, c, actions));
    }
    if section == "body rewrite" {
        let pairs = &v[i..];
        if pairs.len() % 2 != 0 {
            return Err(invalid("body rewrite requires pairs"));
        }
        for p in pairs.chunks(2) {
            actions.push(Action::BodyRegex(Pattern::new(p[0], "m")?, e(p[1])?));
        }
        return Ok((response, c, actions));
    }
    if section == "map local" {
        let mut fields = BTreeMap::new();
        for part in &v[i..] {
            if let Some((k, x)) = part.split_once('=') {
                if !matches!(k, "data" | "data-type" | "header" | "status-code")
                    || fields.insert(k, unquote(x).map_err(invalid)?).is_some()
                {
                    return Err(invalid("unknown or duplicate Map Local field"));
                }
            } else {
                return Err(invalid("Map Local field requires key=value"));
            }
        }
        let status = fields
            .get("status-code")
            .map(|s| s.parse::<u16>().map_err(invalid))
            .transpose()?
            .unwrap_or(200);
        if !(100..=599).contains(&status) {
            return Err(invalid("invalid Map Local HTTP status"));
        }
        let headers: Vec<(String, String)> = fields
            .get("header")
            .map(|s| {
                s.split('|')
                    .map(|p| {
                        let (k, v) = p
                            .split_once(':')
                            .ok_or_else(|| invalid("invalid Map Local header"))?;
                        if k.is_empty()
                            || !k.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
                            })
                            || v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
                        {
                            return Err(invalid("invalid Map Local header"));
                        }
                        Ok((k.to_owned(), v.to_owned()))
                    })
                    .collect::<io::Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let data = fields.get("data").cloned().unwrap_or_default();
        let kind = fields
            .get("data-type")
            .map(String::as_str)
            .unwrap_or("file");
        let body = match kind {
            "text" => data.into_bytes(),
            "base64" => base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data)
                .map_err(invalid)?,
            "file" => load(res, &data)?.to_vec(),
            "tiny-gif" => return Ok((false, c, vec![Action::Reject(200, "img".into())])),
            _ => return Err(invalid("unknown map local type")),
        };

        return Ok((
            false,
            c,
            vec![Action::Mock {
                status: Some(status),
                body,
                content_type: mime(if kind == "text" { "text" } else { "binary" }),
                headers,
            }],
        ));
    }
    if i >= v.len() {
        return Err(invalid("rewrite has no action"));
    }
    let (op, params) = if section == "url rewrite"
        && (dialect == ModuleFormat::Surge
            || v.get(i + 1)
                .is_some_and(|op| matches!(*op, "header" | "302" | "307" | "reject")))
    {
        if v.len() > i + 2 {
            return Err(invalid("unexpected URL rewrite trailing fields"));
        }
        (v.get(i + 1).copied().unwrap_or("header"), vec![v[i]])
    } else {
        (v[i], v[i + 1..].to_vec())
    };
    let op = if let Some(s) = op.strip_prefix("response-") {
        response = true;
        s
    } else if let Some(s) = op.strip_prefix("request-") {
        s
    } else {
        op
    };
    match op {
        "header" => actions.push(Action::Url(
            pat,
            e(params.first().ok_or_else(|| invalid("missing URL"))?)?,
        )),
        "302" | "307" | "301" | "308" => actions.push(Action::Redirect(
            op.parse().unwrap(),
            pat,
            e(params.first().ok_or_else(|| invalid("missing redirect"))?)?,
        )),
        "reject" | "reject-200" | "reject-dict" | "reject-array" | "reject-img"
        | "reject-video" => actions.push(Action::Reject(
            if op == "reject" { 404 } else { 200 },
            op.strip_prefix("reject-").unwrap_or("").into(),
        )),
        "mock-response-body" | "mock-request-body" => {
            let mut fields = BTreeMap::new();
            for p in params {
                if let Some((k, v)) = p.split_once('=') {
                    fields.insert(k, unquote(v).map_err(invalid)?);
                }
            }
            let mut body = if let Some(path) = fields.get("data-path") {
                load(res, path)?.to_vec()
            } else {
                fields.get("data").cloned().unwrap_or_default().into_bytes()
            };
            if fields
                .get("mock-data-is-base64")
                .is_some_and(|v| v == "true")
            {
                body = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
                    .map_err(|e| if fields.contains_key("data-path") {
                        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid mock resource: {e}"))
                    } else { invalid(e) })?;
            }
            let status = if op == "mock-response-body" {
                Some(
                    fields
                        .get("status-code")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(200),
                )
            } else {
                None
            };
            actions.push(Action::Mock {
                status,
                body,
                content_type: mime(
                    fields
                        .get("data-type")
                        .map(String::as_str)
                        .unwrap_or("text"),
                ),
                headers: vec![],
            });
            response = false;
        }
        "body-json-jq" => actions.push(jq(&unquote(
            params.first().ok_or_else(|| invalid("missing jq"))?,
        )
        .map_err(invalid)?)?),
        "header-del" | "body-json-del" => {
            for x in params {
                actions.push(if op == "header-del" {
                    Action::HeaderDelete(x.into())
                } else {
                    Action::JsonDelete(x.into())
                })
            }
        }
        "header-add" | "header-replace" | "body-json-add" | "body-json-replace"
        | "body-replace-regex" => {
            if params.len() % 2 != 0 {
                return Err(invalid("rewrite requires pairs"));
            }
            for p in params.chunks(2) {
                let val = e(p[1])?;
                actions.push(match op {
                    "header-add" => Action::HeaderAdd(p[0].into(), val),
                    "header-replace" => {
                        if dialect == ModuleFormat::Surge {
                            Action::HeaderReplace(p[0].into(), val)
                        } else {
                            Action::HeaderSet(p[0].into(), val)
                        }
                    }
                    "body-replace-regex" => Action::BodyRegex(Pattern::new(p[0], "")?, val),
                    "body-json-add" => Action::JsonAdd(
                        p[0].into(),
                        Expr::Literal(
                            serde_json::from_str(p[1]).unwrap_or(Value::String(p[1].into())),
                        ),
                    ),
                    _ => Action::JsonReplace(
                        p[0].into(),
                        Expr::Literal(
                            serde_json::from_str(p[1]).unwrap_or(Value::String(p[1].into())),
                        ),
                    ),
                });
            }
        }
        "header-replace-regex" => {
            if params.len() % 3 != 0 {
                return Err(invalid("header regex requires triples"));
            }
            for p in params.chunks(3) {
                actions.push(Action::HeaderRegex(
                    p[0].into(),
                    Pattern::new(p[1], "")?,
                    e(p[2])?,
                ));
            }
        }
        _ => return Err(invalid(format!("unsupported legacy action {op}"))),
    }
    Ok((response, c, actions))
}
pub fn compile_module(
    m: &ModuleIR,
    overrides: &BTreeMap<String, String>,
    res: &Resources,
) -> io::Result<Plan> {
    compile_module_with_policies(m, overrides, res, &[])
}

/// 同 [`compile_module`]，`policy_map` 是模块配置的 `policy-map`：`[Rule]` 的 URL-REGEX
/// 策略经映射后为拒绝类时同样编译为拒绝重写，与配置合并（`oryn-config`）的判断一致。
pub fn compile_module_with_policies(
    m: &ModuleIR,
    overrides: &BTreeMap<String, String>,
    res: &Resources,
    policy_map: &[(String, String)],
) -> io::Result<Plan> {
    if let Some(warning) = m
        .warnings
        .iter()
        .find(|w| w.contains("invalid argument declaration:"))
    {
        return Err(invalid(warning.clone()));
    }
    if m.meta.module_type.as_deref() == Some("parser") {
        return Err(invalid("Loon resource parser plugins are not implemented"));
    }
    let mut args = BTreeMap::new();
    let mut arg_types = BTreeMap::new();
    for a in &m.arguments {
        let raw = overrides
            .get(&a.name)
            .cloned()
            .or_else(|| a.default.clone());
        let ty = a
            .typed
            .as_deref()
            .unwrap_or(if a.kind == "switch" {
                "boolean"
            } else {
                "string"
            })
            .to_ascii_lowercase();
        arg_types.insert(a.name.clone(), ty.clone());
        let v = match raw {
            None => Value::Null,
            Some(raw) => match ty.as_str() {
                "string" => Value::String(raw),
                "number" | "boolean" => {
                    let v: Value = serde_json::from_str(&raw).map_err(invalid)?;
                    if (ty == "number" && !v.is_number()) || (ty == "boolean" && !v.is_boolean()) {
                        return Err(invalid(format!("argument {} requires {ty}", a.name)));
                    }
                    v
                }
                _ => return Err(invalid(format!("unknown argument type {ty}"))),
            },
        };
        args.insert(a.name.clone(), v);
    }
    let mut plan = Plan::default();
    for r in &m.rewrites {
        let compiled = if r.text.starts_with("request if ") || r.text.starts_with("response if ") {
            loon(&r.text, &args, res)
        } else {
            legacy(&r.section, &r.text, m.format, res)
        };
        // 行语法/参数与缺失资源隔离；资源内容验证使用独立错误种类，不吞整模块错误。
        let (response, condition, actions) = match compiled {
            Ok(v) => v,
            Err(e) if matches!(e.kind(), io::ErrorKind::InvalidData | io::ErrorKind::Unsupported | io::ErrorKind::NotFound) => {
                plan.warnings.push(format!(
                    "{}:{}: rewrite skipped: {e}",
                    r.source.name, r.source.line
                ));
                continue;
            }
            Err(e) => return Err(io::Error::new(e.kind(), format!("{}:{}: {e}", r.source.name, r.source.line))),
        };
        let rule = CompiledRule {
            condition,
            actions,
            dialect: m.format,
            source: format!("{}:{}", r.source.name, r.source.line),
        };
        if response {
            plan.response.push(rule)
        } else {
            plan.request.push(rule)
        }
    }
    // 模块 `[Rule]` 里的 URL-REGEX 拒绝规则：Router 只看到主机名，改由 HTTP 检查按 URL 拒绝
    // （明文 HTTP 与 MITM 主机）。其他策略的 URL-REGEX 由配置合并给出不支持的警告。
    for rule in &m.rules {
        let Ok(fields) = oryn_module::split_top(rule, ',') else {
            continue;
        };
        let fields: Vec<_> = fields.iter().map(|f| f.trim()).collect();
        if fields.len() < 3 || !fields[0].eq_ignore_ascii_case("URL-REGEX") {
            continue;
        }
        let policy = policy_map
            .iter()
            .find(|(k, _)| k == fields[2])
            .map_or(fields[2], |(_, v)| v.as_str());
        let Some((status, kind)) = oryn_module::reject_status(policy) else {
            continue;
        };
        // 引号只是包裹，正则里的反斜杠原样保留。
        let raw = fields[1]
            .strip_prefix('"')
            .and_then(|p| p.strip_suffix('"'))
            .unwrap_or(fields[1]);
        let flags = if m.format == ModuleFormat::Loon {
            "i"
        } else {
            ""
        };
        let pattern = Pattern::new(raw, flags);
        match pattern {
            Ok(pat) => plan.request.push(CompiledRule {
                condition: Condition::Match(Expr::Variable("url".into()), pat, None),
                actions: vec![Action::Reject(status, kind.into())],
                dialect: m.format,
                source: rule.clone(),
            }),
            Err(e) => plan
                .warnings
                .push(format!("module rule `{rule}` skipped: {e}")),
        }
    }
    for script in &m.scripts {
        let mut warnings = Vec::new();
        let result = script_rule(&script.text, m.format, &args, &arg_types, res, &mut warnings);
        let script_name = result.as_ref().map(|rule| rule.name.as_str()).unwrap_or("<invalid>");
        plan.warnings.extend(warnings.into_iter().map(|w| format!("{}:{}: script {script_name}: {w}", script.source.name, script.source.line)));
        match result {
            Ok(rule) => {
                plan.warnings.push(format!("{}:{}: Oryn script resource limits: default timeout 5s, maximum 30s; body size capped at {MAX_BODY} bytes", script.source.name, script.source.line));
                plan.scripts.push(rule)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::Unsupported | io::ErrorKind::NotFound
                ) =>
            {
                plan.warnings.push(format!(
                    "{}:{}: script skipped: {e}",
                    script.source.name, script.source.line
                ))
            }
            Err(e) => return Err(io::Error::new(e.kind(), format!("{}:{}: {e}", script.source.name, script.source.line))),
        }
    }
    plan.share_jq_programs();
    Ok(plan)
}

fn condition_has_capture(c: &Condition) -> bool {
    match c {
        Condition::Match(_, _, n) => n.is_some(),
        Condition::And(a, b) | Condition::Or(a, b) => {
            condition_has_capture(a) || condition_has_capture(b)
        }
        _ => false,
    }
}
fn script_rule(
    line: &str,
    dialect: ModuleFormat,
    args: &BTreeMap<String, Value>,
    arg_types: &BTreeMap<String, String>,
    resources: &Resources,
    warnings: &mut Vec<String>,
) -> io::Result<ScriptRule> {
    let mut options = BTreeMap::<String, String>::new();
    let mut argument = Value::Null;
    let dsl = line.starts_with("request if ")
        || line.starts_with("response if ")
        || line.contains(" then script(");
    let (name, kind, condition, path) = if dsl {
        let mut p = Parser {
            tokens: lex(line)?,
            pos: 0,
            args: args.clone(),
            depth: 0, conditions: 0,
        };
        let kind = if p.eat("response") {
            "http-response"
        } else if p.eat("request") {
            "http-request"
        } else if p.eat("cron") {
            let e = p.expr()?;
            if !matches!(&e, Expr::Literal(Value::String(_)) | Expr::Template(_)) {
                return Err(invalid("cron requires a bound string value"));
            }
            options.insert("cronexp".into(), literal(&e)?);
            "cron"
        } else if p.eat("network-changed") {
            options.insert("event-name".into(), "network-changed".into());
            "event"
        } else {
            p.expect("generic")?;
            "generic"
        };
        let cond = if p.eat("if") {
            p.cond()?
        } else {
            Condition::Always
        };
        p.expect("then")?;
        p.expect("script")?;
        p.expect("(")?;
        if !matches!(p.tokens.get(p.pos), Some(Token::Raw(_)))
            && !matches!(p.tokens.get(p.pos), Some(Token::Text(s)) if s.iter().all(|p| matches!(p, TemplatePart::Literal(_))))
        {
            return Err(invalid("script path must be a fixed non-template string"));
        }
        let captures = validate_condition(&cond, kind == "http-response", args)?;
        if !captures.is_empty() || condition_has_capture(&cond) {
            return Err(invalid("script conditions cannot capture"));
        }
        if kind == "http-response" && !has_url_guard(&cond) {
            return Err(invalid("response script requires mandatory URL guard"));
        }
        let path = literal(&p.expr()?)?;
        if p.eat(",") {
            let e = p.expr()?;
            validate_expr(&e, kind == "http-response", &captures)?;
            argument = match e {
                Expr::Literal(v) => v,
                Expr::Template(s) => Value::String(s),
                _ => return Err(invalid("unsupported script argument expression")),
            };
        }
        p.expect(")")?;
        if p.eat("with") {
            loop {
                let Token::Word(k) = p.next()? else {
                    return Err(invalid("script option name"));
                };
                p.expect("=")?;
                let key = k.replace('_', "-");
                let token = p.tokens.get(p.pos).cloned();
                if matches!(key.as_str(), "tag" | "img-url" | "requires-body" | "binary-body-mode")
                    && (matches!(&token, Some(Token::Var(_)))
                        || matches!(&token, Some(Token::Text(parts)) if parts.iter().any(|part| !matches!(part, TemplatePart::Literal(_))))) {
                    return Err(invalid(format!("script option {k} must be static (no variables or templates)")));
                }
                let mut v = p.expr()?;
                if dialect == ModuleFormat::Loon && matches!(key.as_str(), "enable" | "timeout" | "debug") {
                    if let Some(Token::Var(name)) = token {
                        let expected = if key == "timeout" { "number|string" } else { "boolean" };
                        let ty = arg_types.get(&name).map(String::as_str);
                        if !(if key == "timeout" { matches!(ty, Some("number" | "string")) } else { ty == Some("boolean") }) {
                            return Err(invalid(format!("script option {k} requires a declared {expected} argument: {name}")));
                        }
                        if matches!(&v, Expr::Literal(Value::Null)) {
                            let default = match key.as_str() {
                                "enable" => Value::Bool(true),
                                "debug" => Value::Bool(false),
                                _ => Value::from(5),
                            };
                            warnings.push(format!("script option {k}: missing argument {name}; using Oryn default {default}"));
                            v = Expr::Literal(default);
                        }
                    }
                }
                let valid = match key.as_str() {
                    "enable" | "debug" | "requires-body" | "binary-body-mode" | "full-header-mode"
                    | "wake-system" => matches!(&v, Expr::Literal(Value::Bool(_))),
                    "timeout" => matches!(&v, Expr::Literal(Value::Number(_) | Value::String(_))),
                    "max-size" => {
                        matches!(&v, Expr::Literal(Value::Number(n)) if n.as_u64().is_some_and(|n| n > 0))
                    }
                    "tag" | "img-url" | "engine" => {
                        matches!(&v, Expr::Template(_) | Expr::Literal(Value::String(_)))
                    }
                    _ => false,
                };
                if !valid {
                    return Err(invalid(format!("invalid or unknown script option {k}")));
                }
                let v = match v {
                    Expr::Literal(v) => string(v),
                    Expr::Template(s) => s,
                    _ => return Err(invalid("script option must be bound value")),
                };
                if options.insert(key, v).is_some() {
                    return Err(invalid("duplicate script option"));
                }
                if !p.eat(",") {
                    break;
                }
            }
        }
        if p.pos != p.tokens.len() {
            return Err(invalid("trailing script options"));
        }
        (path.clone(), kind.to_owned(), cond, path)
    } else {
        let legacy = line.starts_with("http-")
            || line.starts_with("cron ")
            || line.starts_with("generic ")
            || line.starts_with("network-changed ");
        let (name, body) = if legacy {
            ("", line)
        } else {
            line.split_once('=').unwrap_or(("", line))
        };
        let body = if legacy {
            let tokens = split_top(body, ' ').map_err(invalid)?;
            if tokens.len() < 2 {
                return Err(invalid("incomplete script"));
            }
            options.insert(
                "type".into(),
                if tokens[0] == "network-changed" {
                    "event".into()
                } else {
                    tokens[0].into()
                },
            );
            if tokens[0].starts_with("http-") {
                options.insert("pattern".into(), tokens[1].into());
            }
            if tokens[0] == "cron" {
                options.insert("cronexp".into(), unquote(tokens[1]).map_err(invalid)?);
            }
            if tokens[0] == "network-changed" {
                options.insert("event-name".into(), "network-changed".into());
            }
            // 类型与 pattern / cron 之后的全部内容都是选项，`requires-body`、`tag` 等可能写在
            // `script-path=` 之前，不能只取 script-path 之后的部分。
            let skip = if tokens[0].starts_with("http-") || tokens[0] == "cron" {
                2
            } else {
                1
            };
            tokens[skip.min(tokens.len())..].join(" ")
        } else {
            body.to_owned()
        };
        for item in split_top(&body, ',').map_err(invalid)? {
            if let Some((k, v)) = item.split_once('=') {
                let mut key = k.trim().replace('_', "-");
                if dialect == ModuleFormat::Loon && key == "enabled" { key = "enable".into(); }
                let mut value = unquote(v.trim()).map_err(invalid)?;
                if dialect == ModuleFormat::Loon && matches!(key.as_str(), "enable" | "timeout" | "debug") {
                    if let Some(name) = value.strip_prefix("${").or_else(|| value.strip_prefix('{')).and_then(|v| v.strip_suffix('}')) {
                        let expected = if key == "timeout" { "number|string" } else { "boolean" };
                        let ty = arg_types.get(name).map(String::as_str);
                        if !(if key == "timeout" { matches!(ty, Some("number" | "string")) } else { ty == Some("boolean") }) {
                            return Err(invalid(format!("script option {key} requires a declared {expected} argument: {name}")));
                        }
                        value = match args.get(name) {
                            Some(Value::Null) => {
                                let default = match key.as_str() { "enable" => "true", "debug" => "false", _ => "5" };
                                warnings.push(format!("script option {key}: missing argument {name}; using Oryn default {default}"));
                                default.into()
                            }
                            Some(v) => string(v.clone()),
                            None => return Err(invalid(format!("undeclared plugin argument {name}"))),
                        };
                    }
                }
                if options
                    .insert(key, value)
                    .is_some()
                {
                    return Err(invalid("duplicate script option"));
                }
            } else {
                return Err(invalid("script option requires key=value"));
            }
        }
        let kind = options
            .get("type")
            .cloned()
            .unwrap_or_else(|| "generic".into());
        let cond = if let Some(pattern) = options.get("pattern") {
            Condition::Match(
                Expr::Variable("url".into()),
                Pattern::new(
                    pattern,
                    if dialect == ModuleFormat::Loon {
                        "i"
                    } else {
                        ""
                    },
                )?,
                None,
            )
        } else {
            Condition::Always
        };
        let path = options
            .get("script-path")
            .cloned()
            .ok_or_else(|| invalid("missing script-path"))?;
        if let Some(a) = options.get("argument") {
            argument = Value::String(a.clone());
        }
        (name.trim().to_owned(), kind, cond, path)
    };
    if !matches!(
        kind.as_str(),
        "http-request" | "http-response" | "generic" | "cron" | "event"
    ) {
        return Err(unsupported(format!(
            "script kind {kind} is not implemented"
        )));
    }
    for (k, v) in &options {
        let valid = match k.as_str() {
            "enable" | "debug" | "requires-body" | "binary-body-mode" | "full-header-mode"
            | "wake-system" => matches!(v.as_str(), "true" | "false" | "1" | "0"),
            "timeout" => v.parse::<f64>().is_ok_and(|n| n.is_finite() && n > 0.0),
            "max-size" => v.parse::<u64>().is_ok(),
            "type" | "pattern" | "script-path" | "argument" | "tag" | "engine" | "cronexp"
            | "event-name" | "img-url" => true,
            _ => false,
        };
        if !valid {
            return Err(invalid(format!("invalid or unknown script option {k}")));
        }
    }
    if dialect == ModuleFormat::Loon
        && ((!dsl && path.contains("${"))
            || (kind == "http-response" && !has_url_guard(&condition)))
    {
        return Err(invalid(
            "Loon script requires fixed path and response URL guard",
        ));
    }
    if kind == "cron" && options.get("cronexp").is_some_and(|v| v.contains("${")) {
        return Err(invalid("cron requires a bound string value; unresolved variables are not supported"));
    }
    // `engine=webview` 只是 Surge 的执行引擎偏好；脚本仍按同一 API 在隔离运行时中执行。
    if options
        .get("wake-system")
        .is_some_and(|s| s == "true" || s == "1")
    {
        return Err(unsupported(
            "wake-system requires an unavailable iOS scheduling API",
        ));
    }
    for key in ["tag", "img-url", "requires-body", "binary-body-mode"] {
        // DSL已在原token上检查；raw字符串的字面量${...}不能再次被当模板。
        if !dsl && options.get(key).is_some_and(|v| v.contains("${")) {
            return Err(invalid(format!("script option {key} must be static (no variables or templates)")));
        }
    }
    for key in ["debug", "img-url"] {
        if options.contains_key(key) {
            warnings.push(format!("script option {key} is unsupported by Oryn runtime and has no effect"));
        }
    }
    // 验证后仅做显式转换，不能把小数/字符串解析失败偷偷回退到 5 秒。
    let timeout = match options.get("timeout") {
        None => 5,
        Some(raw) => {
            let seconds = raw.parse::<f64>().map_err(|_| invalid("timeout requires a finite positive number"))?;
            if !seconds.is_finite() || seconds <= 0.0 {
                return Err(invalid("timeout requires a finite positive number"));
            }
            let bounded = seconds.ceil().clamp(1.0, 30.0) as u64;
            if seconds != bounded as f64 {
                warnings.push(format!("script timeout {raw}s rounded up and capped to Oryn limit: {bounded}s (maximum 30s)"));
            }
            bounded
        }
    };
    // 源码/字节资源验证绝不能降级为行语法 warning。
    let resource_error = |e: io::Error| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid script resource {path}: {e}"));
    let code = crate::ScriptCode::new(load(resources, &path)?).map_err(resource_error)?;
    oryn_script::validate(code.as_str()).map_err(|e| {
        // 预算不足仍只跳过该脚本；真正源码损坏才保留整模块快照回退。
        if e.kind() == io::ErrorKind::Unsupported { e } else { resource_error(e) }
    })?;
    let boolean = |k: &str| {
        options
            .get(k)
            .is_some_and(|s| matches!(s.as_str(), "true" | "1"))
    };
    Ok(ScriptRule {
        enabled: options
            .get("enable")
            .is_none_or(|v| v != "false" && v != "0"),
        event: options.get("event-name").cloned(),
        cron: options.get("cronexp").cloned(),
        name: options.get("tag").cloned().unwrap_or(name),
        kind,
        condition,
        source: path,
        code,
        argument,
        env: Default::default(),
        requires_body: boolean("requires-body"),
        binary: boolean("binary-body-mode"),
        full_headers: boolean("full-header-mode"),
        max_size: options
            .get("max-size")
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(MAX_BODY)
            .min(MAX_BODY),
        timeout,
        dialect,
    })
}
