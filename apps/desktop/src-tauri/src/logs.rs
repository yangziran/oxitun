//! 内存日志捕获：在保留 stderr 输出的同时，把最近日志写入环形缓冲供诊断页查看

use std::collections::VecDeque;
use std::sync::Mutex;

const MAX_ENTRIES: usize = 300;

#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEntry {
    /// HH:MM:SS 本地时间
    pub time: String,
    pub level: String,
    pub message: String,
}

pub struct LogStore {
    entries: Mutex<VecDeque<LogEntry>>,
}

impl Default for LogStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LogStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(MAX_ENTRIES)),
        }
    }

    fn push(&self, level: &str, message: String) {
        let now = chrono_now();
        let mut entries = self.entries.lock().expect("log store lock");
        if entries.len() >= MAX_ENTRIES {
            entries.pop_front();
        }
        entries.push_back(LogEntry {
            time: now,
            level: level.to_string(),
            message,
        });
    }

    pub fn snapshot(&self) -> Vec<LogEntry> {
        self.entries
            .lock()
            .expect("log store lock")
            .iter()
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        self.entries.lock().expect("log store lock").clear();
    }
}

/// 本地时间 HH:MM:SS
fn chrono_now() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// 同时输出到 stderr 与内存缓冲的 logger
pub struct TeeLogger {
    store: std::sync::Arc<LogStore>,
    inner: env_logger::Logger,
}

impl TeeLogger {
    pub fn new(store: std::sync::Arc<LogStore>) -> Self {
        let inner =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                .build();
        Self { store, inner }
    }

    pub fn init(self) {
        let max = self.inner.filter();
        log::set_max_level(max);
        log::set_boxed_logger(Box::new(self)).expect("logger 只能初始化一次");
    }
}

impl log::Log for TeeLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            self.store
                .push(record.level().as_str(), record.args().to_string());
            self.inner.log(record);
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}
