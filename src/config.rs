//! Configuration management for Argus

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgusConfig {
    pub argus: ArgusSection,
    pub diverter: DiverterSection,
    pub listeners: Vec<ListenerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgusSection {
    pub divert_traffic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiverterSection {
    pub network_mode: String,
    pub dump_packets: bool,
    pub dump_packets_file_prefix: String,
    pub redirect_all_traffic: bool,
    pub default_tcp_listener: String,
    pub default_udp_listener: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub listener_type: String,
    pub enabled: bool,
    /// Port WinDivert intercepts (traffic destined for this port is captured).
    pub service_port: u16,
    /// Port Argus binds the listener on. Defaults to `service_port` when absent from config.
    pub listener_port: u16,
    pub protocol: String,
    pub use_ssl: bool,
    pub timeout: u64,
    pub webroot: Option<String>,
    pub response_a: Option<String>,
    pub response_mx: Option<String>,
    pub response_txt: Option<String>,
    pub banner: Option<String>,
    pub custom_responses: HashMap<String, String>,
    /// Process filter for passthrough.
    ///
    /// When non-empty, connections whose originating process matches one of
    /// the entries are passed through transparently to the real destination;
    /// all other connections receive the usual fake response.
    ///
    /// Each entry is either a process name (`"curl.exe"`) or a numeric PID
    /// (`"1234"`), case-insensitive.  Multiple values are comma-separated:
    ///
    /// ```ini
    /// Passthrough: curl.exe, wget.exe, 5678
    /// ```
    ///
    /// An empty or absent `Passthrough` key disables passthrough entirely.
    pub passthrough: Vec<String>,

    /// Logging suppression filter.
    ///
    /// Accepts the same entry types as `Passthrough` (process name / regex, PID,
    /// IPv4, IPv6, domain, domain+path, URL).  When a connection matches any
    /// entry, request and response log files are **not** written for that
    /// connection.  All other connections are logged normally.
    ///
    /// An empty or absent `NoLog` key means every connection is logged.
    pub no_log: Vec<String>,

    /// Optional external modifier endpoint (`"IP:PORT"`).
    ///
    /// When set, every intercepted request and response is forwarded to this
    /// TCP endpoint before being processed or sent back to the client.  The
    /// endpoint receives a framed message (JSON metadata + raw payload) and
    /// must reply with the (possibly modified) payload bytes.
    ///
    /// See `src/forward_to.rs` for the exact wire format and a minimal Python
    /// example.
    pub forward_to: Option<String>,
}

impl Default for ArgusConfig {
    fn default() -> Self {
        Self {
            argus: ArgusSection {
                divert_traffic: true,
            },
            diverter: DiverterSection {
                network_mode: "auto".to_string(),
                dump_packets: true,
                dump_packets_file_prefix: "packets".to_string(),
                redirect_all_traffic: true,
                default_tcp_listener: "RawTCPListener".to_string(),
                default_udp_listener: "RawUDPListener".to_string(),
            },
            listeners: Self::default_listeners(),
        }
    }
}

impl ArgusConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;

        Self::parse_ini(&content)
    }

    fn parse_ini(content: &str) -> Result<Self> {
        let mut config = Self::default();
        let mut current_section = String::new();
        let mut section_data: HashMap<String, HashMap<String, String>> = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                current_section = line[1..line.len()-1].to_string();
                section_data.entry(current_section.clone()).or_default();
                continue;
            }

            if let Some(pos) = line.find(':').or_else(|| line.find('=')) {
                let key = line[..pos].trim().to_lowercase().replace(' ', "_");
                let value = line[pos+1..].trim().to_string();
                if !current_section.is_empty() {
                    section_data
                        .entry(current_section.clone())
                        .or_default()
                        .insert(key, value);
                }
            }
        }

        // Parse Argus section
        if let Some(argus) = section_data.get("Argus") {
            config.argus.divert_traffic = argus
                .get("diverttraffic")
                .map(|v| v.to_lowercase() == "yes")
                .unwrap_or(true);
        }

        // Parse Diverter section
        if let Some(diverter) = section_data.get("Diverter") {
            config.diverter.network_mode = diverter
                .get("networkmode")
                .cloned()
                .unwrap_or("auto".to_string());
            config.diverter.dump_packets = diverter
                .get("dumppackets")
                .map(|v| v.to_lowercase() == "yes")
                .unwrap_or(false);
        }

        // Parse listener sections.
        // `found_any` is true whenever the config file contained at least one
        // listener section (even if all are disabled).  The default listener
        // list is only used as a fallback when the config file has NO listener
        // sections at all — it is never used to override explicit Enabled: False.
        config.listeners.clear();
        let mut found_any = false;
        for (section, data) in &section_data {
            if section == "Argus" || section == "Diverter" {
                continue;
            }

            let enabled = data
                .get("enabled")
                .map(|v| v.to_lowercase() == "true" || v.to_lowercase() == "yes")
                .unwrap_or(false);

            found_any = true;

            if !enabled {
                continue;
            }

            let listener_type = data
                .get("listener")
                .cloned()
                .unwrap_or_default();

            let service_port: u16 = data
                .get("serviceport")
                .or_else(|| data.get("port"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let listener_port: u16 = data
                .get("listenerport")
                .and_then(|v| v.parse().ok())
                .unwrap_or(service_port);

            let protocol = data
                .get("protocol")
                .cloned()
                .unwrap_or("tcp".to_string())
                .to_lowercase();

            let use_ssl = data
                .get("usessl")
                .map(|v| v.to_lowercase() == "yes")
                .unwrap_or(false);

            let timeout: u64 = data
                .get("timeout")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10);

            let listener = ListenerConfig {
                name: section.clone(),
                listener_type: listener_type.clone(),
                enabled,
                service_port,
                listener_port,
                protocol,
                use_ssl,
                timeout,
                webroot: data.get("webroot").cloned(),
                response_a: data.get("responsea").cloned(),
                response_mx: data.get("responsemx").cloned(),
                response_txt: data.get("responsetxt").cloned(),
                banner: data.get("banner").cloned(),
                custom_responses: HashMap::new(),
                passthrough: data
                    .get("passthrough")
                    .map(|v| {
                        v.split(',')
                         .map(|s| s.trim().to_string())
                         .filter(|s| !s.is_empty())
                         .collect()
                    })
                    .unwrap_or_default(),
                no_log: data
                    .get("nolog")
                    .map(|v| {
                        v.split(',')
                         .map(|s| s.trim().to_string())
                         .filter(|s| !s.is_empty())
                         .collect()
                    })
                    .unwrap_or_default(),
                forward_to: data.get("forwardto").cloned(),
            };

            config.listeners.push(listener);
        }

        if config.listeners.is_empty() {
            if found_any {
                info!("All listeners are disabled in config — none will be started.");
            } else {
                info!("No listener sections found in config, using defaults");
                config.listeners = Self::default_listeners();
            }
        }

        Ok(config)
    }

    fn default_listeners() -> Vec<ListenerConfig> {
        vec![
            ListenerConfig {
                name: "HTTPListener".to_string(),
                listener_type: "HTTPListener".to_string(),
                enabled: true,
                service_port: 80,
                listener_port: 18080,
                protocol: "tcp".to_string(),
                use_ssl: false,
                timeout: 10,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: None,
                custom_responses: HashMap::new(),
                passthrough: vec![],
                no_log: vec![],
                forward_to: None,
            },
            ListenerConfig {
                name: "HTTPSListener".to_string(),
                listener_type: "HTTPListener".to_string(),
                enabled: true,
                service_port: 443,
                listener_port: 18443,
                protocol: "tcp".to_string(),
                use_ssl: true,
                timeout: 10,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: None,
                custom_responses: HashMap::new(),
                passthrough: vec![],
                no_log: vec![],
                forward_to: None,
            },
            ListenerConfig {
                name: "DNSListener".to_string(),
                listener_type: "DNSListener".to_string(),
                enabled: true,
                service_port: 53,
                listener_port: 10053,
                protocol: "udp".to_string(),
                use_ssl: false,
                timeout: 5,
                webroot: None,
                response_a: Some("127.0.0.1".to_string()),
                response_mx: Some("mail.argus.local".to_string()),
                response_txt: Some("ARGUS".to_string()),
                banner: None,
                custom_responses: HashMap::new(),
                passthrough: vec![],
                no_log: vec![],
                forward_to: None,
            },
            ListenerConfig {
                name: "SMTPListener".to_string(),
                listener_type: "SMTPListener".to_string(),
                enabled: true,
                service_port: 25,
                listener_port: 10025,
                protocol: "tcp".to_string(),
                use_ssl: false,
                timeout: 30,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: Some("220 argus SMTP Service Ready".to_string()),
                custom_responses: HashMap::new(),
                passthrough: vec![],
                no_log: vec![],
                forward_to: None,
            },
            ListenerConfig {
                name: "RawTCPListener".to_string(),
                listener_type: "RawListener".to_string(),
                enabled: true,
                service_port: 1337,
                listener_port: 11337,
                protocol: "tcp".to_string(),
                use_ssl: false,
                timeout: 5,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: None,
                custom_responses: HashMap::new(),
                passthrough: vec![],
                no_log: vec![],
                forward_to: None,
            },
            ListenerConfig {
                name: "POPListener".to_string(),
                listener_type: "POPListener".to_string(),
                enabled: true,
                service_port: 110,
                listener_port: 10110,
                protocol: "tcp".to_string(),
                use_ssl: false,
                timeout: 30,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: Some("+OK Argus POP3 Server Ready".to_string()),
                custom_responses: HashMap::new(),
                passthrough: vec![],
                no_log: vec![],
                forward_to: None,
            },
        ]
    }
}
