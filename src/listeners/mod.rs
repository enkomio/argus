//! Listener module - manages all network listeners

pub mod http;
pub mod dns;
pub mod raw;
pub mod smtp;
pub mod ftp;
pub mod irc;
pub mod pop;

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, error};
use colored::*;

use crate::config::{ArgusConfig, ListenerConfig};
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
                    println!(
                        "  {} {} on {}:{} [{}{}]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        cfg.port,
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
                    println!(
                        "  {} {} on {}:{} [{}]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        cfg.port,
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
                    println!(
                        "  {} {} on {}:{} [TCP]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        cfg.port
                    );
                    let ct = self.conn_table.clone();
                    let rl = self.request_logger.clone();
                    tokio::spawn(async move {
                        if let Err(e) = smtp::start(cfg, bind, ct, rl).await {
                            error!("SMTPListener error: {}", e);
                        }
                    })
                }
                "FTPListener" => {
                    println!(
                        "  {} {} on {}:{} [TCP]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        cfg.port
                    );
                    let ct = self.conn_table.clone();
                    let rl = self.request_logger.clone();
                    tokio::spawn(async move {
                        if let Err(e) = ftp::start(cfg, bind, ct, rl).await {
                            error!("FTPListener error: {}", e);
                        }
                    })
                }
                "IRCListener" => {
                    println!(
                        "  {} {} on {}:{} [TCP]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        cfg.port
                    );
                    let ct = self.conn_table.clone();
                    let rl = self.request_logger.clone();
                    tokio::spawn(async move {
                        if let Err(e) = irc::start(cfg, bind, ct, rl).await {
                            error!("IRCListener error: {}", e);
                        }
                    })
                }
                "POPListener" => {
                    println!(
                        "  {} {} on {}:{} [TCP]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        cfg.port
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
                    println!(
                        "  {} {} on {}:{} [{}]",
                        "●".bright_green(),
                        cfg.name.bright_white().bold(),
                        bind,
                        cfg.port,
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
