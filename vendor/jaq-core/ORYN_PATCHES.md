# Oryn 修改

上游 jaq-core 3.1.1，MIT，commit 4229c5fad8470773f961fbb106e0634da8bf744d，路径 jaq-core。

增加 oryn_budget.rs；ValT.oryn_size 默认实现；filter.rs 在 run/iterator/update 路径检查 200000 步、100ms、128 深度、8MiB 累计中间值预算。预算失败通过 resume_unwind 退出，宿主必须 catch_unwind 并 clear。使用 std 特性。测试包含大 range 与字符串 repeat 取消。
