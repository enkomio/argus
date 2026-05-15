//! IRC listener — intercepts IRC traffic (common C2 channel)

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn, debug};

use crate::config::ListenerConfig;
use crate::conn_table::SharedConnTable;
use crate::request_logger::SharedRequestLogger;

fn log_irc(event: &str, detail: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    info!("IRC  [{}] {} {} {}", config.name, src_addr, event, detail);
}

/// Write `data` to `writer`, also appending it to `resp`.
macro_rules! send {
    ($writer:expr, $resp:expr, $data:expr) => {{
        $resp.extend_from_slice($data);
        $writer.write_all($data).await?
    }};
}

async fn handle_irc(
    stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    config: ListenerConfig,
    conn_table: SharedConnTable,
    request_logger: Option<SharedRequestLogger>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let mut nick = "user".to_string();
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
    let mut line = String::new();
    let server = "argus.local";

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        req_transcript.extend_from_slice(line.as_bytes());

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        log_irc("RECV", trimmed, &src_addr, &config);

        let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
        let cmd = parts[0].to_uppercase();
        let args = parts.get(1).cloned().unwrap_or("");

        match cmd.as_str() {
            "NICK" => {
                nick = args.to_string();
                log_irc("NICK", &nick, &src_addr, &config);
            }
            "USER" => {
                log_irc("USER", args, &src_addr, &config);
                let msg = format!(
                    ":{} 001 {} :Welcome to Argus IRC Network\r\n\
                     :{} 002 {} :Your host is {}\r\n\
                     :{} 003 {} :This server was created for malware analysis\r\n\
                     :{} 004 {} {} argus o o\r\n",
                    server, nick, server, nick, server,
                    server, nick,
                    server, nick, server
                );
                send!(writer, resp_transcript, msg.as_bytes());
            }
            "JOIN" => {
                let channel = args.splitn(2, ' ').next().unwrap_or("#argus");
                log_irc("JOIN", channel, &src_addr, &config);
                let msg = format!(
                    ":{}!user@{} JOIN {}\r\n\
                     :{} 332 {} {} :Argus analysis channel\r\n\
                     :{} 353 {} = {} :@argus {}\r\n\
                     :{} 366 {} {} :End of /NAMES list\r\n",
                    nick, src_addr.ip(), channel,
                    server, nick, channel,
                    server, nick, channel, nick,
                    server, nick, channel
                );
                send!(writer, resp_transcript, msg.as_bytes());
            }
            "PRIVMSG" => {
                log_irc("PRIVMSG", args, &src_addr, &config);
                let chan_parts: Vec<&str> = args.splitn(2, ' ').collect();
                let target = chan_parts.get(0).cloned().unwrap_or("#argus");
                let msg = format!(
                    ":{} PRIVMSG {} :Message received by Argus analysis\r\n",
                    server, target
                );
                send!(writer, resp_transcript, msg.as_bytes());
            }
            "PING" => {
                let msg = format!(":{} PONG {} :{}\r\n", server, server, args);
                send!(writer, resp_transcript, msg.as_bytes());
            }
            "QUIT" => {
                log_irc("QUIT", args, &src_addr, &config);
                send!(writer, resp_transcript, b"ERROR :Closing connection\r\n");
                break;
            }
            "MODE" | "WHO" | "WHOIS" | "NAMES" => {
                let msg = format!(":{} 221 {} +\r\n", server, nick);
                send!(writer, resp_transcript, msg.as_bytes());
            }
            _ => {
                debug!("Unknown IRC command: {}", cmd);
            }
        }
    }

    if should_log {
        if let Some(ref logger) = request_logger {
            if !req_transcript.is_empty() {
                if let Err(e) = logger.log(log_pid, &log_name, "irc", log_counter, "req", &req_transcript) {
                    debug!("Request log write failed: {}", e);
                }
            }
            if !resp_transcript.is_empty() {
                if let Err(e) = logger.log(log_pid, &log_name, "irc", log_counter, "rsp", &resp_transcript) {
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
        .map_err(|e| anyhow::anyhow!("Failed to bind IRC on {}: {}", addr, e))?;

    debug!("IRC listener on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, src_addr)) => {
                let cfg = config.clone();
                let ct = conn_table.clone();
                let rl = request_logger.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_irc(stream, src_addr, cfg, ct, rl).await {
                        debug!("IRC error: {}", e);
                    }
                });
            }
            Err(e) => warn!("IRC accept error: {}", e),
        }
    }
}
