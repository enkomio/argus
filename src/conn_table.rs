//! Shared connection table — bridges the diverter and the listeners.
//!
//! The diverter writes one entry per new intercepted connection;
//! listeners read the entry to discover the original destination and
//! decide whether to respond with fake data or pass through to the real host.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

use regex::Regex;

/// Everything a listener needs to know about an intercepted connection.
#[derive(Clone, Debug)]
pub struct ConnInfo {
    /// The app's real source IP.
    pub orig_src_ip: IpAddr,
    /// The external destination IP the app was trying to reach.
    pub orig_dst_ip: IpAddr,
    /// The external destination port.
    pub orig_dst_port: u16,
    /// Executable name of the originating process (e.g. `"curl.exe"`).
    pub process_name: Option<String>,
    /// PID of the originating process.
    pub pid: Option<u32>,
}

impl ConnInfo {
    /// Returns the original destination as a socket-address string suitable
    /// for `TcpStream::connect`:
    ///   IPv4 → `"1.2.3.4:80"`
    ///   IPv6 → `"[::1]:80"`
    pub fn orig_dst_addr(&self) -> String {
        match self.orig_dst_ip {
            IpAddr::V4(ip) => format!("{}:{}", ip, self.orig_dst_port),
            IpAddr::V6(ip) => format!("[{}]:{}", ip, self.orig_dst_port),
        }
    }

    /// A human-readable label: `"curl.exe (PID 1234)"` or `"PID 1234"`.
    pub fn process_label(&self) -> String {
        match (&self.process_name, self.pid) {
            (Some(name), Some(pid)) => format!("{} (PID {})", name, pid),
            (Some(name), None)      => name.clone(),
            (None,       Some(pid)) => format!("PID {}", pid),
            (None,       None)      => "unknown".to_string(),
        }
    }

    /// Returns `true` if this connection matches the passthrough `list`.
    ///
    /// Each entry in `list` can be:
    ///
    /// | Entry type        | Example                          | Matched against         |
    /// |-------------------|----------------------------------|-------------------------|
    /// | Process name      | `curl.exe`, `curl.*`             | originating process     |
    /// | PID               | `1234`                           | originating process     |
    /// | IPv4 address      | `93.184.216.34`                  | original destination IP |
    /// | IPv6 address      | `2606:2800:220:1:248:1893:25c8:1946` | original destination IP |
    ///
    /// Process-name entries are treated as **case-insensitive regex patterns**
    /// anchored at the start (`^`).  A plain name like `curl.exe` still works
    /// (the `.` in regex matches any char, which is fine in practice).  Use
    /// `curl\.exe` for a precise literal-dot match.
    ///
    /// An empty list means "never pass through".
    ///
    /// > **Note**: IPv6 destination matching requires the diverter to support
    /// > IPv6 packets (currently IPv4-only).
    pub fn matches_passthrough_list(&self, list: &[String]) -> bool {
        if list.is_empty() {
            return false;
        }

        for entry in list {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }

            // ── Numeric (no dots / colons) → PID ─────────────────────────
            if !entry.contains('.') && !entry.contains(':') {
                if let Ok(pid_val) = entry.parse::<u32>() {
                    if self.pid == Some(pid_val) {
                        return true;
                    }
                    // It was a number — don't fall through to process-name match.
                    continue;
                }
            }

            // ── IPv4 address ──────────────────────────────────────────────
            if let Ok(ip4) = entry.parse::<Ipv4Addr>() {
                if self.orig_dst_ip == IpAddr::V4(ip4) {
                    return true;
                }
                continue;
            }

            // ── IPv6 address ──────────────────────────────────────────────
            if let Ok(ip6) = entry.parse::<Ipv6Addr>() {
                if self.orig_dst_ip == IpAddr::V6(ip6) {
                    return true;
                }
                continue;
            }

            // ── Process name — regex (case-insensitive, anchored at start) ──
            if let Some(ref name) = self.process_name {
                let pattern = format!("(?i)^{}", entry);
                match Regex::new(&pattern) {
                    Ok(re) => {
                        if re.is_match(name) {
                            return true;
                        }
                    }
                    Err(_) => {
                        // Invalid regex: fall back to plain case-insensitive match.
                        if name.eq_ignore_ascii_case(entry) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

/// Shared connection table: **client source port → `ConnInfo`**.
///
/// Written once per new connection by the diverter thread.
/// Read (without blocking) by listener async tasks.
pub type SharedConnTable = Arc<RwLock<HashMap<u16, ConnInfo>>>;

/// Creates a new, empty shared connection table.
pub fn new_shared_table() -> SharedConnTable {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Returns `true` when the connection on `port` matches any entry in `no_log`,
/// meaning log files should **not** be written for this connection.
///
/// Uses the same matching logic as [`ConnInfo::matches_passthrough_list`]:
/// process-name regex, PID, IPv4, and IPv6.  Returns `false` when `no_log`
/// is empty, when no conn-table entry exists for `port`, or when nothing
/// matches.
pub fn should_skip_log(table: &SharedConnTable, port: u16, no_log: &[String]) -> bool {
    if no_log.is_empty() {
        return false;
    }
    table
        .read()
        .ok()
        .and_then(|tbl| tbl.get(&port).map(|info| info.matches_passthrough_list(no_log)))
        .unwrap_or(false)
}

/// Look up the `(pid, process_name)` pair for a connection identified by its
/// **client source port**.  Returns `(0, "unknown")` when no entry is found.
pub fn get_process_info(table: &SharedConnTable, port: u16) -> (u32, String) {
    table
        .read()
        .ok()
        .and_then(|tbl| {
            tbl.get(&port).map(|info| (
                info.pid.unwrap_or(0),
                info.process_name
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            ))
        })
        .unwrap_or((0, "unknown".to_string()))
}
