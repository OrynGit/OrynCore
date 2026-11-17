//! 日志：固定大小的环形缓冲 + 可选的外部回调（Swift 侧转发到 OSLog）。

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{Level, LevelFilter, Log, Metadata, Record};
use serde::Serialize;

const RING_CAPACITY: usize = 500;
/// 单条日志的最大长度，超出部分截断，避免异常大的错误信息占满缓冲。
const MAX_MESSAGE_LEN: usize = 2000;

pub type LogCallback = Box<dyn Fn(Level, &str) + Send + Sync>;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// Unix 时间（秒，含小数）。
    pub time: f64,
    pub level: &'static str,
    pub message: String,
}

struct OrynLogger {
    ring: Mutex<VecDeque<LogEntry>>,
    callback: Mutex<Option<LogCallback>>,
}

fn logger() -> &'static OrynLogger {
    static LOGGER: OnceLock<OrynLogger> = OnceLock::new();
    LOGGER.get_or_init(|| OrynLogger {
        ring: Mutex::new(VecDeque::new()),
        callback: Mutex::new(None),
    })
}

/// 安装全局 logger（可重复调用）。
pub fn init() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = log::set_logger(logger());
        log::set_max_level(LevelFilter::Info);
    });
}

pub fn set_callback(cb: Option<LogCallback>) {
    init();
    *logger().callback.lock().unwrap() = cb;
}

fn parse_level(level: &str) -> LevelFilter {
    match level.to_ascii_lowercase().as_str() {
        "error" => LevelFilter::Error,
        "warn" | "warning" => LevelFilter::Warn,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        "off" => LevelFilter::Off,
        _ => LevelFilter::Info,
    }
}

/// 配置文件的 `log-level` 与 App 诊断日志的覆盖级别；覆盖存在时以覆盖为准。
static LEVELS: Mutex<(LevelFilter, Option<LevelFilter>)> = Mutex::new((LevelFilter::Info, None));

fn apply_levels() {
    let (base, over) = *LEVELS.lock().unwrap();
    log::set_max_level(over.unwrap_or(base));
}

/// 配置文件指定的级别（重载配置时也走这里，不会清除覆盖）。
pub fn set_level(level: &str) {
    init();
    LEVELS.lock().unwrap().0 = parse_level(level);
    apply_levels();
}

/// App 的诊断日志级别覆盖；`None` 恢复为配置文件的级别。
pub fn set_level_override(level: Option<&str>) {
    init();
    LEVELS.lock().unwrap().1 = level.map(parse_level);
    apply_levels();
}

pub fn recent(limit: usize) -> Vec<LogEntry> {
    let ring = logger().ring.lock().unwrap();
    ring.iter().rev().take(limit).rev().cloned().collect()
}

impl Log for OrynLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut message = record.args().to_string();
        if message.len() > MAX_MESSAGE_LEN {
            let mut end = MAX_MESSAGE_LEN;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
            message.push('…');
        }
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        {
            let mut ring = self.ring.lock().unwrap();
            if ring.len() >= RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(LogEntry {
                time,
                level: level_str(record.level()),
                message: message.clone(),
            });
        }
        if let Some(cb) = self.callback.lock().unwrap().as_ref() {
            cb(record.level(), &message);
        }
    }

    fn flush(&self) {}
}

fn level_str(l: Level) -> &'static str {
    match l {
        Level::Error => "error",
        Level::Warn => "warn",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins_over_config_level_until_cleared() {
        set_level("warn");
        assert_eq!(log::max_level(), LevelFilter::Warn);
        set_level_override(Some("debug"));
        assert_eq!(log::max_level(), LevelFilter::Debug);
        // 重载配置只更新配置级别，不清除覆盖
        set_level("error");
        assert_eq!(log::max_level(), LevelFilter::Debug);
        set_level_override(None);
        assert_eq!(log::max_level(), LevelFilter::Error);
        set_level("info");
    }
}
