/*
 * OrynCore C ABI
 *
 * 本文件由 cbindgen 根据 crates/oryn-ffi/src/lib.rs 生成，不要手动修改。
 *
 * 约定：
 * - 只暴露不透明指针、字节、长度与状态码，不暴露任何 Rust 类型。
 * - 返回的 char* 必须用 oryn_string_free 释放。
 */

#ifndef ORYN_CORE_H
#define ORYN_CORE_H

#include <stddef.h>
#include <stdint.h>

// 成功。
#define ORYN_OK 0

// 参数无效（如空指针）。
#define ORYN_ERR_INVALID_ARGUMENT -1

// 配置解析或校验失败。
#define ORYN_ERR_CONFIG -2

// 已在运行，或另一个 Engine 占用了协议栈。
#define ORYN_ERR_BUSY -3

// Engine 未运行。
#define ORYN_ERR_NOT_RUNNING -4

// 输入队列已满，本批数据已丢弃。
#define ORYN_ERR_QUEUE_FULL -5

// 内部错误。
#define ORYN_ERR_INTERNAL -6

// 日志级别：错误。
#define ORYN_LOG_ERROR 1

// 日志级别：警告。
#define ORYN_LOG_WARN 2

// 日志级别：信息。
#define ORYN_LOG_INFO 3

// 日志级别：调试。
#define ORYN_LOG_DEBUG 4

// 日志级别：跟踪。
#define ORYN_LOG_TRACE 5

// Engine 句柄（不透明）。
typedef struct OrynEngine OrynEngine;

// 日志回调，可能在任意线程调用。`message` 只在回调期间有效。
typedef void (*OrynLogFn)(void *context,
                          int32_t level,
                          const char *message);

// 平台层保护 Core 自己创建的出站 socket，避免 Android VPN 回流。
typedef int32_t (*OrynSocketProtectFn)(void *context,
                                       int32_t fd);

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Core 版本号（静态字符串，不需要释放）。
const char *oryn_version(void);

// 生成一份新的 MITM CA，返回 JSON，其中两个字段是 Base64 DER。
// 私钥只应由 PacketTunnel 写入受 Data Protection 保护的 App Group 文件。
char *oryn_mitm_generate_ca(void);

// 设置全局日志回调；`callback` 为 NULL 时取消。
void oryn_set_log_callback(OrynLogFn callback,
                           void *context);

// 解析配置并创建 Engine。
//
// `config` 为类 mihomo 格式的 YAML 配置；`options` 为 JSON 运行参数（可为空），字段见 `EngineOptions`：
// `data_dir`、`dns_address`、`mtu`、`selections`、`mode`、`network`。
//
// 失败返回 NULL，`*status` 为错误码，`*error_message`（可为 NULL）为错误说明，需用
// `oryn_string_free` 释放。create / start / stop / destroy 由调用方保证不并发。
// 设置平台层的出站 socket 保护回调；传 NULL 清除。
void oryn_set_socket_protect_callback(OrynSocketProtectFn callback,
                                      void *context);

struct OrynEngine *oryn_engine_create(const uint8_t *config,
                                      size_t config_len,
                                      const uint8_t *options,
                                      size_t options_len,
                                      int32_t *status,
                                      char **error_message);

// 启动事件循环，并让 Rust 直接收发 utun 描述符上的 IP 包。
// 描述符由平台层取得并验证；Core 在线程内 dup 一个副本，调用方仍保留原句柄。
// 失败时 `*error_message`（可为 NULL）为错误说明。
int32_t oryn_engine_start(struct OrynEngine *engine,
                          int32_t fd,
                          char **error_message);

// 不带 utun 启动事件循环（macOS 系统代理模式）：只运行本地 HTTP / SOCKS5 入站与控制命令。
// 失败时 `*error_message`（可为 NULL）为错误说明。
int32_t oryn_engine_start_proxy(struct OrynEngine *engine,
                                char **error_message);

// 事件循环是否仍在运行；供平台层处理实验 I/O 后端的异步失败。
int32_t oryn_engine_is_running(struct OrynEngine *engine);

// 执行控制命令，`request` 为 JSON，如 `{"cmd":"stats"}`。可在任意线程调用。
// 返回 JSON 字符串（需 `oryn_string_free` 释放），失败时包含 `error` 字段。
char *oryn_engine_command(struct OrynEngine *engine,
                          const uint8_t *request,
                          size_t request_len);

// 停止事件循环并释放所有连接。可重复调用。
void oryn_engine_stop(struct OrynEngine *engine);

// 停止并释放 Engine。
void oryn_engine_destroy(struct OrynEngine *engine);

// 释放 Core 返回的字符串。
void oryn_string_free(char *s);

// 验证导入的 MITM CA 和 PKCS#8 私钥是否有效且匹配，不保存、不输出私钥。
int32_t oryn_mitm_validate_ca(const uint8_t *cert,
                              size_t cert_len,
                              const uint8_t *key,
                              size_t key_len);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* ORYN_CORE_H */
