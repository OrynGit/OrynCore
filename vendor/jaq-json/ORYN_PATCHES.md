# Oryn 修改

上游 jaq-json 2.0.3，MIT，commit 4229c5fad8470773f961fbb106e0634da8bf744d，路径 jaq-json。

实现 ValT.oryn_size；字符串 repeat 在分配前计费。配合 jaq-core 的线程局部预算使用。

补充：BigInt/Decimal 按位数/文本长度计费；乘法开始前预扣输入大小；逻辑中间值超过 1 MiB 立即退出，避免共享数组形成指数展开后才检查。测试覆盖递归、指数数组和连续大整数平方。
