//! 外部模块语料扫描：模块原文留在传入目录，不打包进产品。不下载或执行脚本。
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
fn files(p: &Path, out: &mut Vec<PathBuf>) {
    if p.is_dir() {
        for e in std::fs::read_dir(p).unwrap().flatten() {
            files(&e.path(), out)
        }
    } else if matches!(
        p.extension().and_then(|s| s.to_str()),
        Some("sgmodule" | "plugin" | "lpx" | "plx")
    ) {
        out.push(p.into());
    }
}
fn main() {
    let mut all = vec![];
    for root in std::env::args().skip(1) {
        files(Path::new(&root), &mut all)
    }
    all.sort();
    let mut rules = 0;
    let mut compiled = 0;
    let mut scripts = 0;
    let mut errors = BTreeMap::new();
    let mut rows = vec![];
    for path in &all {
        let text = std::fs::read_to_string(path).unwrap();
        let format = if path.extension().is_some_and(|e| e == "sgmodule") {
            oryn_module::ModuleFormat::Surge
        } else {
            oryn_module::ModuleFormat::Loon
        };
        let text = if format == oryn_module::ModuleFormat::Surge {
            oryn_module::bind_surge(&text, &[]).unwrap_or(text)
        } else {
            text
        };
        let ir =
            oryn_module::parse_named(&text, Some(format), &path.display().to_string()).unwrap();
        scripts += ir.scripts.len();
        for rule in &ir.rewrites {
            rules += 1;
            let mut m = ir.clone();
            m.rewrites = vec![rule.clone()];
            m.scripts.clear();
            match oryn_http_inspect::compile_module(&m, &Default::default(), &Default::default()) {
                Ok(_) => compiled += 1,
                Err(e) => {
                    let full = e.to_string();
                    let reason = full.split(": ").last().unwrap_or(&full).to_owned();
                    *errors.entry(reason).or_insert(0) += 1;
                    rows.push(
                        serde_json::json!({"file":path,"line":rule.source.line,"error":full}),
                    );
                }
            }
        }
    }
    println!(
        "{}",
        serde_json::json!({"files":all.len(),"rewrite_lines":rules,"compiled_lines":compiled,"scripts_not_executed":scripts,"failures":rows,"summary":errors})
    );
}
