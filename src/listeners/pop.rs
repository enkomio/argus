//! POP3 listener — intercepts POP3 email retrieval

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn, debug};

use crate::config::ListenerConfig;
use crate::conn_table::SharedConnTable;
use crate::request_logger::SharedRequestLogger;

fn log_pop(event: &str, detail: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    info!("POP3 [{}] {} {} {}", config.name, src_addr, event, detail);
}

/// Write `data` to `writer`, also appending it to `resp`.
macro_rules! send {
    ($writer:expr, $resp:expr, $data:expr) => {{
        $resp.extend_from_slice($data);
        $writer.write_all($data).await?
    }};
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
    conn_table: SharedConnTable,
    request_logger: Option<SharedRequestLogger>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let should_log = !crate::conn_table::should_skip_log(
        &conn_table, src_addr.port(), &config.no_log,
    );
    let (log_pid, log_name) = crate::conn_table::get_process_info(&conn_table, src_addr.port());
    let log_counter = if should_log {
        request_logger.as_ref().map(|l| l.alloc_counter(log_pid)).unwrap_or(0)
    } else {
        0
    };
    let mut req_transcript:  Vec<u8> = Vec::new();
    let mut resp_transcript: Vec<u8> = Vec::new();

    let banner = config.banner.as_deref().unwrap_or("+OK Argus POP3 Server Ready");
    let banner_line = format!("{}\r\n", banner);
    send!(writer, resp_transcript, banner_line.as_bytes());

    let mut line = String::new();
    let mut authenticated = false;
    let mut username = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        req_transcript.extend_from_slice(line.as_bytes());

        let parts: Vec<&str> = line.trim().splitn(2, ' ').collect();
        let cmd = parts[0].to_uppercase();
        let arg = parts.get(1).cloned().unwrap_or("");

        match cmd.as_str() {
            "USER" => {
                username = arg.to_string();
                log_pop("USER", &username, &src_addr, &config);
                send!(writer, resp_transcript, b"+OK User accepted\r\n");
            }
            "PASS" => {
                log_pop("PASS", &format!("user={} pass={}", username, arg), &src_addr, &config);
                authenticated = true;
                send!(writer, resp_transcript, b"+OK Maildrop ready, 1 message\r\n");
            }
            "STAT" => {
                if authenticated {
                    let msg = format!("+OK 1 {}\r\n", FAKE_EMAIL.len());
                    send!(writer, resp_transcript, msg.as_bytes());
                } else {
                    send!(writer, resp_transcript, b"-ERR Not authenticated\r\n");
                }
            }
            "LIST" => {
                if authenticated {
                    let msg = format!("+OK 1 message\r\n1 {}\r\n.\r\n", FAKE_EMAIL.len());
                    send!(writer, resp_transcript, msg.as_bytes());
                } else {
                    send!(writer, resp_transcript, b"-ERR Not authenticated\r\n");
                }
            }
            "RETR" => {
                log_pop("RETR", arg, &src_addr, &config);
                if authenticated {
                    let msg = format!("+OK {} octets\r\n{}\r\n.\r\n", FAKE_EMAIL.len(), FAKE_EMAIL);
                    send!(writer, resp_transcript, msg.as_bytes());
                } else {
                    send!(writer, resp_transcript, b"-ERR Not authenticated\r\n");
                }
            }
            "DELE" => {
                send!(writer, resp_transcript, b"+OK Message deleted\r\n");
            }
            "NOOP" => {
                send!(writer, resp_transcript, b"+OK\r\n");
            }
            "RSET" => {
                send!(writer, resp_transcript, b"+OK\r\n");
            }
            "QUIT" => {
                log_pop("QUIT", "", &src_addr, &config);
                send!(writer, resp_transcript, b"+OK Goodbye\r\n");
                break;
            }
            _ => {
                debug!("Unknown POP3 command: {}", cmd);
                send!(writer, resp_transcript, b"-ERR Unknown command\r\n");
            }
        }
    }

    if should_log {
        if let Some(ref logger) = request_logger {
            if !req_transcript.is_empty() {
                if let Err(e) = logger.log(log_pid, &log_name, "pop", log_counter, "req", &req_transcript) {
                    debug!("Request log write failed: {}", e);
                }
            }
            if !resp_transcript.is_empty() {
                if let Err(e) = logger.log(log_pid, &log_name, "pop", log_counter, "rsp", &resp_transcript) {
                    debug!("Response log write failed: {}", e);
                }
            }
        }
    }

    Ok(())
}

pub async fn start(config: ListenerConfig, bind_addr: String, conn_table: SharedConnTable, request_logger: Option<SharedRequestLogger>) -> Result<()> {
    let addr = format!("{}:{}", bind_addr, config.listener_port);
    let listener = TcpListener::bind(&addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind POP3 on {}: {}", addr, e))?;

    debug!("POP3 listener on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, src_addr)) => {
                let cfg = config.clone();
                let ct = conn_table.clone();
                let rl = request_logger.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_pop(stream, src_addr, cfg, ct, rl).await {
                        debug!("POP3 error: {}", e);
                    }
                });
            }
            Err(e) => warn!("POP3 accept error: {}", e),
        }
    }
}
