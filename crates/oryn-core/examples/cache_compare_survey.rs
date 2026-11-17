//! 旧缓存整块读与有界比较的独立对照（不联网）。
#[path = "../src/cache_compare.rs"]
mod cache_compare;
use std::time::Instant;
#[global_allocator]
static ALLOC: oryn_core::alloc::Counting<std::alloc::System> =
    oryn_core::alloc::Counting(std::alloc::System);
fn main() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/cache-compare-survey");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.bin", std::process::id()));
    for size in [1024 * 1024, 16 * 1024 * 1024] {
        let data = vec![0x5a; size];
        std::fs::write(&path, &data).unwrap();
        let mut old = Vec::new();
        let mut new = Vec::new();
        let mut allocation = 0;
        for _ in 0..7 {
            let before = oryn_core::alloc::heap_usage().unwrap().0;
            let start = Instant::now();
            let cached = std::fs::read(&path).unwrap();
            assert_eq!(cached, data);
            old.push(start.elapsed().as_micros());
            allocation = oryn_core::alloc::heap_usage().unwrap().0 - before;
            drop(cached);
            let start = Instant::now();
            assert!(cache_compare::matches(&path, &data).unwrap());
            new.push(start.elapsed().as_micros());
        }
        old.sort();
        new.sort();
        println!("cache bytes={size} old_median_us={} bounded_median_us={} old_live_extra={allocation} bounded_scratch_stack=16384", old[3], new[3]);
    }
    std::fs::remove_file(path).unwrap();
}
