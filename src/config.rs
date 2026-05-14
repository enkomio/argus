//! Configuration management for Argus

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
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
    pub port: u16,
    pub protocol: String,
    pub use_ssl: bool,
    pub timeout: u64,
    pub webroot: Option<String>,
    pub response_a: Option<String>,
    pub response_mx: Option<String>,
    pub response_txt: Option<String>,
    pub banner: Option<String>,
    pub custom_responses: HashMap<String, String>,
    pub dump_http_posts: bool,
    pub dump_http_posts_prefix: String,
    /// Process filter for forwarding.
    ///
    /// When non-empty, connections whose originating process matches one of
    /// the entries are forwarded transparently to the real destination;
    /// all other connections receive the usual fake response.
    ///
    /// Each entry is either a process name (`"curl.exe"`) or a numeric PID
    /// (`"1234"`), case-insensitive.  Multiple values are comma-separated:
    ///
    /// ```ini
    /// Forward: curl.exe, wget.exe, 5678
    /// ```
    ///
    /// An empty or absent `Forward` key disables forwarding entirely.
    pub forward: Vec<String>,
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

        // Parse listener sections
        config.listeners.clear();
        for (section, data) in &section_data {
            if section == "Argus" || section == "Diverter" {
                continue;
            }

            let enabled = data
                .get("enabled")
                .map(|v| v.to_lowercase() == "true" || v.to_lowercase() == "yes")
                .unwrap_or(false);

            if !enabled {
                continue;
            }

            let listener_type = data
                .get("listener")
                .cloned()
                .unwrap_or_default();

            let port: u16 = data
                .get("port")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

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
                port,
                protocol,
                use_ssl,
                timeout,
                webroot: data.get("webroot").cloned(),
                response_a: data.get("responsea").cloned(),
                response_mx: data.get("responsemx").cloned(),
                response_txt: data.get("responsetxt").cloned(),
                banner: data.get("banner").cloned(),
                custom_responses: HashMap::new(),
                dump_http_posts: data
                    .get("dumphttpposts")
                    .map(|v| v.to_lowercase() == "yes")
                    .unwrap_or(false),
                dump_http_posts_prefix: data
                    .get("dumphttppostsfileprefix")
                    .cloned()
                    .unwrap_or("http".to_string()),
                forward: data
                    .get("forward")
                    .map(|v| {
                        v.split(',')
                         .map(|s| s.trim().to_string())
                         .filter(|s| !s.is_empty())
                         .collect()
                    })
                    .unwrap_or_default(),
            };

            config.listeners.push(listener);
        }

        if config.listeners.is_empty() {
            info!("No listeners found in config, using defaults");
            config.listeners = Self::default_listeners();
        }

        Ok(config)
    }

    fn default_listeners() -> Vec<ListenerConfig> {
        vec![
            ListenerConfig {
                name: "HTTPListener".to_string(),
                listener_type: "HTTPListener".to_string(),
                enabled: true,
                port: 80,
                protocol: "tcp".to_string(),
                use_ssl: false,
                timeout: 10,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: None,
                custom_responses: HashMap::new(),
                dump_http_posts: false,
                dump_http_posts_prefix: "http".to_string(),
                forward: vec![],
            },
            ListenerConfig {
                name: "HTTPSListener".to_string(),
                listener_type: "HTTPListener".to_string(),
                enabled: true,
                port: 443,
                protocol: "tcp".to_string(),
                use_ssl: true,
                timeout: 10,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: None,
                custom_responses: HashMap::new(),
                dump_http_posts: false,
                dump_http_posts_prefix: "https".to_string(),
                forward: vec![],
            },
            ListenerConfig {
                name: "DNSListener".to_string(),
                listener_type: "DNSListener".to_string(),
                enabled: true,
                port: 53,
                protocol: "udp".to_string(),
                use_ssl: false,
                timeout: 5,
                webroot: None,
                response_a: Some("127.0.0.1".to_string()),
                response_mx: Some("mail.argus.local".to_string()),
                response_txt: Some("ARGUS".to_string()),
                banner: None,
                custom_responses: HashMap::new(),
                dump_http_posts: false,
                dump_http_posts_prefix: String::new(),
                forward: vec![],
            },
            ListenerConfig {
                name: "SMTPListener".to_string(),
                listener_type: "SMTPListener".to_string(),
                enabled: true,
                port: 25,
                protocol: "tcp".to_string(),
                use_ssl: false,
                timeout: 30,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: Some("220 argus SMTP Service Ready".to_string()),
                custom_responses: HashMap::new(),
                dump_http_posts: false,
                dump_http_posts_prefix: String::new(),
                forward: vec![],
            },
            ListenerConfig {
                name: "FTPListener".to_string(),
                listener_type: "FTPListener".to_string(),
                enabled: true,
                port: 21,
                protocol: "tcp".to_string(),
                use_ssl: false,
                timeout: 30,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: Some("220 Argus FTP Server".to_string()),
                custom_responses: HashMap::new(),
                dump_http_posts: false,
                dump_http_posts_prefix: String::new(),
                forward: vec![],
            },
            ListenerConfig {
                name: "RawTCPListener".to_string(),
                listener_type: "RawListener".to_string(),
                enabled: true,
                port: 1337,
                protocol: "tcp".to_string(),
                use_ssl: false,
                timeout: 5,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: None,
                custom_responses: HashMap::new(),
                dump_http_posts: false,
                dump_http_posts_prefix: String::new(),
                forward: vec![],
            },
            ListenerConfig {
                name: "IRCListener".to_string(),
                listener_type: "IRCListener".to_string(),
                enabled: true,
                port: 6667,
                protocol: "tcp".to_string(),
                use_ssl: false,
                timeout: 30,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: Some(":argus 001 user :Welcome to Argus IRC".to_string()),
                custom_responses: HashMap::new(),
                dump_http_posts: false,
                dump_http_posts_prefix: String::new(),
                forward: vec![],
            },
            ListenerConfig {
                name: "POPListener".to_string(),
                listener_type: "POPListener".to_string(),
                enabled: true,
                port: 110,
                protocol: "tcp".to_string(),
                use_ssl: false,
                timeout: 30,
                webroot: None,
                response_a: None,
                response_mx: None,
                response_txt: None,
                banner: Some("+OK Argus POP3 Server Ready".to_string()),
                custom_responses: HashMap::new(),
                dump_http_posts: false,
                dump_http_posts_prefix: String::new(),
                forward: vec![],
            },
        ]
    }
}
