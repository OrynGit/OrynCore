//! 编译 lwIP 与胶水层。

use std::path::Path;

fn collect(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "c") {
            out.push(path);
        }
    }
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lwip = root.join("lwip");
    let csrc = root.join("csrc");

    let mut files = Vec::new();
    collect(&lwip.join("core"), &mut files);
    files.sort();

    let mut build = cc::Build::new();
    build
        .files(&files)
        .file(csrc.join("oryn_lwip_shim.c"))
        .include(&csrc)
        .include(lwip.join("include"))
        .define("ORYN_ACCEPT_ALL", None)
        // lwIP 的大数组若成为 common 符号，链接器会因对齐过大而告警
        .flag("-fno-common")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-address")
        .flag_if_supported("-Wno-unused-but-set-variable")
        .warnings(false)
        .opt_level(2);
    build.compile("oryn_lwip");

    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=lwip");
    println!("cargo:rerun-if-changed=build.rs");
}
