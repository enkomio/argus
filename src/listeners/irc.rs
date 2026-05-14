//! IRC listener — intercepts IRC traffic (common C2 channel)

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{warn, debug};
use chrono::Local;
use colored::*;

use crate::config::ListenerConfig;

fn log_irc(event: &str, detail: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "{} {} {} {} {} {}",
        format!("[{}]", timestamp).dimmed(),
        "IRC ".bright_blue().bold(),
        format!("[{}]", config.name).bright_magenta(),
        format!("{}", src_addr).yellow(),
        event.bright_white().bold(),
        detail.bright_cyan()
    );
}

async fn handle_irc(
    stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    config: ListenerConfig,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let mut nick = "user".to_string();
    let mut line = String::new();
    let server = "argus.local";

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

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
                writer.write_all(format!(
                    ":{} 001 {} :Welcome to Argus IRC Network\r\n\
                     :{} 002 {} :Your host is {}\r\n\
                     :{} 003 {} :This server was created for malware analysis\r\n\
                     :{} 004 {} {} argus o o\r\n",
                    server, nick, server, nick, server,
                    server, nick,
                    server, nick, server
                ).as_bytes()).await?;
            }
            "JOIN" => {
                let channel = args.splitn(2, ' ').next().unwrap_or("#argus");
                log_irc("JOIN", channel, &src_addr, &config);
                writer.write_all(format!(
                    ":{}!user@{} JOIN {}\r\n\
                     :{} 332 {} {} :Argus analysis channel\r\n\
                     :{} 353 {} = {} :@argus {}\r\n\
                     :{} 366 {} {} :End of /NAMES list\r\n",
                    nick, src_addr.ip(), channel,
                    server, nick, channel,
                    server, nick, channel, nick,
                    server, nick, channel
                ).as_bytes()).await?;
            }
            "PRIVMSG" => {
                log_irc("PRIVMSG", args, &src_addr, &config);
                // C2 command - log and respond with OK
                let chan_parts: Vec<&str> = args.splitn(2, ' ').collect();
                let target = chan_parts.get(0).cloned().unwrap_or("#argus");
                writer.write_all(format!(
                    ":{} PRIVMSG {} :Message received by Argus analysis\r\n",
                    server, target
                ).as_bytes()).await?;
            }
            "PING" => {
                writer.write_all(format!(":{} PONG {} :{}\r\n", server, server, args).as_bytes()).await?;
            }
            "QUIT" => {
                log_irc("QUIT", args, &src_addr, &config);
                writer.write_all(format!("ERROR :Closing connection\r\n").as_bytes()).await?;
                break;
            }
            "MODE" | "WHO" | "WHOIS" | "NAMES" => {
                // Silently accept
                writer.write_all(format!(":{} 221 {} +\r\n", server, nick).as_bytes()).await?;
            }
            _ => {
                debug!("Unknown IRC command: {}", cmd);
            }
        }
    }

    Ok(())
}

pub async fn start(config: ListenerConfig, bind_addr: String) -> Result<()> {
    let addr = format!("{}:{}", bind_addr, config.port);
    let listener = TcpListener::bind(&addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind IRC on {}: {}", addr, e))?;

    debug!("IRC listener on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, src_addr)) => {
                let cfg = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_irc(stream, src_addr, cfg).await {
                        debug!("IRC error: {}", e);
                    }
                });
            }
            Err(e) => warn!("IRC accept error: {}", e),
        }
    }
}
