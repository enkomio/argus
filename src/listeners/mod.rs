//! Listener module - manages all network listeners

pub mod http;
pub mod dns;
pub mod raw;
pub mod smtp;
pub mod pop;

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, error};
use colored::*;

use crate::config::ArgusConfig;
use crate::conn_table::SharedConnTable;
use crate::request_logger::SharedRequestLogger;

pub struct ListenerManager {
    config: Arc<ArgusConfig>,
    bind_addr: String,
    handles: Vec<tokio::task::JoinHandle<()>>,
    conn_table: SharedConnTable,
    request_logger: Option<SharedRequestLogger>,
}

impl ListenerManager {
    pub async fn new(
        config: Arc<ArgusConfig>,
        bind_addr: String,
        conn_table: SharedConnTable,
        request_logger: Option<SharedRequestLogger>,
    ) -> Result<Self> {
        Ok(Self {
            config,
            bind_addr,
            handles: Vec::new(),
            conn_table,
            request_logger,
        })
    }

    pub async fn start_all(&mut self) -> Result<()> {
        info!("Starting all listeners...");
        println!();
        println!("{}", "Starting listeners:".bright_green().bold());
        println!("{}", "─".repeat(60).dimmed());

        let listeners = self.config.listeners.clone();

        for listener_cfg in listeners {
            if !listener_cfg.enabled {
                continue;
            }

            let bind = self.bind_addr.clone();
            let cfg = listener_cfg.clone();

            let handle = match cfg.listener_type.as_str() {
                "HTTPListener" => {
                    let port_str = if cfg.listener_port != cfg.service_port {
                        format!("{} (intercepts :{})", cfg.listener_port, cfg.service_port)
                    } else {
                        cfg.listener_port.to_string()
                    };
                    println!(
                        "  {} {} on {}:{} [{}{}]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        port_str,
                        cfg.protocol.to_uppercase().bright_cyan(),
                        if cfg.use_ssl { "/SSL".bright_yellow().to_string() } else { String::new() }
                    );
                    let ct = self.conn_table.clone();
                    let rl = self.request_logger.clone();
                    tokio::spawn(async move {
                        if let Err(e) = http::start(cfg, bind, ct, rl).await {
                            error!("HTTPListener error: {}", e);
                        }
                    })
                }
                "DNSListener" => {
                    let port_str = if cfg.listener_port != cfg.service_port {
                        format!("{} (intercepts :{})", cfg.listener_port, cfg.service_port)
                    } else {
                        cfg.listener_port.to_string()
                    };
                    println!(
                        "  {} {} on {}:{} [{}]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        port_str,
                        cfg.protocol.to_uppercase().bright_cyan()
                    );
                    let ct = self.conn_table.clone();
                    let rl = self.request_logger.clone();
                    tokio::spawn(async move {
                        if let Err(e) = dns::start(cfg, bind, ct, rl).await {
                            error!("DNSListener error: {}", e);
                        }
                    })
                }
                "SMTPListener" => {
                    let port_str = if cfg.listener_port != cfg.service_port {
                        format!("{} (intercepts :{})", cfg.listener_port, cfg.service_port)
                    } else {
                        cfg.listener_port.to_string()
                    };
                    println!(
                        "  {} {} on {}:{} [TCP]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        port_str
                    );
                    let ct = self.conn_table.clone();
                    let rl = self.request_logger.clone();
                    tokio::spawn(async move {
                        if let Err(e) = smtp::start(cfg, bind, ct, rl).await {
                            error!("SMTPListener error: {}", e);
                        }
                    })
                }
                "POPListener" => {
                    let port_str = if cfg.listener_port != cfg.service_port {
                        format!("{} (intercepts :{})", cfg.listener_port, cfg.service_port)
                    } else {
                        cfg.listener_port.to_string()
                    };
                    println!(
                        "  {} {} on {}:{} [TCP]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        port_str
                    );
                    let ct = self.conn_table.clone();
                    let rl = self.request_logger.clone();
                    tokio::spawn(async move {
                        if let Err(e) = pop::start(cfg, bind, ct, rl).await {
                            error!("POPListener error: {}", e);
                        }
                    })
                }
                "RawListener" => {
                    let port_str = if cfg.listener_port != cfg.service_port {
                        format!("{} (intercepts :{})", cfg.listener_port, cfg.service_port)
                    } else {
                        cfg.listener_port.to_string()
                    };
                    println!(
                        "  {} {} on {}:{} [{}]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        port_str,
                        cfg.protocol.to_uppercase().bright_cyan()
                    );
                    let ct = self.conn_table.clone();
                    let rl = self.request_logger.clone();
                    tokio::spawn(async move {
                        if let Err(e) = raw::start(cfg, bind, ct, rl).await {
                            error!("RawListener error: {}", e);
                        }
                    })
                }
                unknown => {
                    warn!("Unknown listener type: {}", unknown);
                    continue;
                }
            };

            self.handles.push(handle);
        }

        println!("{}", "─".repeat(60).dimmed());
        info!("All listeners started ({} total)", self.handles.len());
        Ok(())
    }

    pub async fn stop_all(&mut self) {
        info!("Stopping all listeners...");
        for handle in self.handles.drain(..) {
            handle.abort();
        }
        info!("All listeners stopped");
    }
}
