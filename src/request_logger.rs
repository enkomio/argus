//! Per-request file logger.
//!
//! Each intercepted request is saved to:
//!   `<log_dir>/<process_name>/<pid>/<listener_name>/<yyyymmdd>_<HHMMSS>_<NNNN>.log`
//!
//! The 4-digit counter (`NNNN`) is global per PID and increments with
//! every file written for that PID, across all listener types.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use chrono::Local;

pub struct RequestLogger {
    log_dir: PathBuf,
    /// Counter per PID: incremented on every `log()` call for that PID.
    counters: Mutex<HashMap<u32, u32>>,
}

impl RequestLogger {
    pub fn new(log_dir: impl Into<PathBuf>) -> Self {
        Self {
            log_dir: log_dir.into(),
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Allocate and return the next counter value for `pid`.
    ///
    /// Call this once per transaction to get a shared counter, then pass the
    /// returned value to every `log()` call that belongs to the same transaction
    /// (e.g. both the `"req"` and `"rsp"` of the same HTTP request).
    pub fn alloc_counter(&self, pid: u32) -> u32 {
        let mut map = self.counters.lock().unwrap();
        let c = map.entry(pid).or_insert(0);
        *c += 1;
        *c
    }

    /// Write `content` to a new log file.
    ///
    /// * `pid`           — PID of the originating process (0 = unknown)
    /// * `process_name`  — executable name (e.g. `"malware.exe"`); use `"unknown"` if unavailable
    /// * `listener_name` — protocol name (e.g. `"http"`, `"smtp"`)
    /// * `counter`       — transaction counter from `alloc_counter()`; shared between req and rsp
    /// * `action`        — `"req"` for an incoming request, `"rsp"` for the outgoing response
    /// * `content`       — raw bytes to persist
    ///
    /// The file is written to:
    ///   `<log_dir>/<process_name>/<pid>/<listener_name>/<yyyymmdd>_<HHMMSS>_<NNNN>_<action>.log`
    ///
    /// Returns the path that was written.
    pub fn log(
        &self,
        pid: u32,
        process_name: &str,
        listener_name: &str,
        counter: u32,
        action: &str,
        content: &[u8],
    ) -> Result<PathBuf> {
        let now = Local::now();
        let timestamp = now.format("%Y%m%d_%H%M%S");

        let sanitise = |s: &str, fallback: &str| -> String {
            if s.is_empty() {
                fallback.to_string()
            } else {
                s.chars()
                    .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
                    .collect()
            }
        };

        let safe_process  = sanitise(process_name, "unknown");
        let safe_listener = sanitise(listener_name, "unknown");
        let safe_action   = sanitise(action, "req");

        let dir = self.log_dir
            .join(&safe_process)
            .join(pid.to_string())
            .join(&safe_listener);
        std::fs::create_dir_all(&dir)?;

        let filename = format!("{}_{:07}_{:07}_{}.log", timestamp, pid, counter, safe_action);
        let path = dir.join(&filename);
        std::fs::write(&path, content)?;
        Ok(path)
    }
}

pub type SharedRequestLogger = Arc<RequestLogger>;

/// Create a new shared `RequestLogger` that writes to `log_dir`.
pub fn new_request_logger(log_dir: impl Into<PathBuf>) -> SharedRequestLogger {
    Arc::new(RequestLogger::new(log_dir))
}
