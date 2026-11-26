# Oryn 修改

上游 jaq-core 3.1.1，MIT，commit 4229c5fad8470773f961fbb106e0634da8bf744d，路径 jaq-core。

增加 oryn_budget.rs；ValT.oryn_size 默认实现；filter.rs 在 run/iterator/update 路径检查步数、时长、128 深度与累计中间值预算。预算失败通过 resume_unwind 退出，宿主必须 catch_unwind 并 clear。使用 std 特性。测试包含大 range 与字符串 repeat 取消。

补充（2026-11-26）：
- `compile.rs` 增加 `Filter::compact()` 及 `Lut::{term_count, fun_count}`，在 `Compiler::compile` 末尾按入口可达性裁剪未用到的标准库 `Term` 与原生函数并密集重排下标，显著降低常驻内存。
- `oryn_budget.rs` 增加 `start_with(max_body)` 与 `max_value_bytes()`，使单值上限随移动（4 MiB）/ 桌面（8 MiB）正文上限联动（2_000_000 步、500 ms 并每 256 步采样时钟、单值 2×max_body 至少 8 MiB、累计 8×单值上限），不再对 1–4 MiB JSON 误报配额超限。
