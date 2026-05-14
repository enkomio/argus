//! POP3 listener — intercepts POP3 email retrieval

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{warn, debug};
use chrono::Local;
use colored::*;

use crate::config::ListenerConfig;

fn log_pop(event: &str, detail: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "{} {} {} {} {} {}",
        format!("[{}]", timestamp).dimmed(),
        "POP3".bright_green().bold(),
        format!("[{}]", config.name).bright_magenta(),
        format!("{}", src_addr).yellow(),
        event.bright_white().bold(),
        detail.bright_cyan()
    );
}

const FAKE_EMAIL: &str = "From: admin@argus.local\r\n\
Subject: Argus Analysis\r\n\
Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n\
\r\n\
This is an Argus intercepted POP3 session.\r\nFor malware analysis purposes.\r\n";

async fn handle_pop(
    stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    config: ListenerConfig,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let banner = config.banner.as_deref().unwrap_or("+OK Argus POP3 Server Ready");
    writer.write_all(format!("{}\r\n", banner).as_bytes()).await?;

    let mut line = String::new();
    let mut authenticated = false;
    let mut username = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let parts: Vec<&str> = line.trim().splitn(2, ' ').collect();
        let cmd = parts[0].to_uppercase();
        let arg = parts.get(1).cloned().unwrap_or("");

        match cmd.as_str() {
            "USER" => {
                username = arg.to_string();
                log_pop("USER", &username, &src_addr, &config);
                writer.write_all(b"+OK User accepted\r\n").await?;
            }
            "PASS" => {
                log_pop("PASS", &format!("user={} pass={}", username, arg), &src_addr, &config);
                authenticated = true;
                writer.write_all(b"+OK Maildrop ready, 1 message\r\n").await?;
            }
            "STAT" => {
                if authenticated {
                    let size = FAKE_EMAIL.len();
                    writer.write_all(format!("+OK 1 {}\r\n", size).as_bytes()).await?;
                } else {
                    writer.write_all(b"-ERR Not authenticated\r\n").await?;
                }
            }
            "LIST" => {
                if authenticated {
                    let size = FAKE_EMAIL.len();
                    writer.write_all(format!("+OK 1 message\r\n1 {}\r\n.\r\n", size).as_bytes()).await?;
                } else {
                    writer.write_all(b"-ERR Not authenticated\r\n").await?;
                }
            }
            "RETR" => {
                log_pop("RETR", arg, &src_addr, &config);
                if authenticated {
                    writer.write_all(format!("+OK {} octets\r\n{}\r\n.\r\n", FAKE_EMAIL.len(), FAKE_EMAIL).as_bytes()).await?;
                } else {
                    writer.write_all(b"-ERR Not authenticated\r\n").await?;
                }
            }
            "DELE" => {
                writer.write_all(b"+OK Message deleted\r\n").await?;
            }
            "NOOP" => {
                writer.write_all(b"+OK\r\n").await?;
            }
            "RSET" => {
                writer.write_all(b"+OK\r\n").await?;
            }
            "QUIT" => {
                log_pop("QUIT", "", &src_addr, &config);
                writer.write_all(b"+OK Goodbye\r\n").await?;
                break;
            }
            _ => {
                debug!("Unknown POP3 command: {}", cmd);
                writer.write_all(b"-ERR Unknown command\r\n").await?;
            }
        }
    }

    Ok(())
}

pub async fn start(config: ListenerConfig, bind_addr: String) -> Result<()> {
    let addr = format!("{}:{}", bind_addr, config.port);
    let listener = TcpListener::bind(&addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind POP3 on {}: {}", addr, e))?;

    debug!("POP3 listener on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, src_addr)) => {
                let cfg = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_pop(stream, src_addr, cfg).await {
                        debug!("POP3 error: {}", e);
                    }
                });
            }
            Err(e) => warn!("POP3 accept error: {}", e),
        }
    }
}
