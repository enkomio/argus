//! SMTP listener — intercepts email sending attempts

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{warn, debug};
use chrono::Local;
use colored::*;

use crate::config::ListenerConfig;

fn log_smtp(event: &str, detail: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "{} {} {} {} {} {}",
        format!("[{}]", timestamp).dimmed(),
        "SMTP".bright_yellow().bold(),
        format!("[{}]", config.name).bright_magenta(),
        format!("{}", src_addr).yellow(),
        event.bright_white().bold(),
        detail.bright_cyan()
    );
}

async fn handle_smtp(
    stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    config: ListenerConfig,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let banner = config.banner.as_deref()
        .unwrap_or("220 argus.local SMTP Service Ready");
    writer.write_all(format!("{}\r\n", banner).as_bytes()).await?;

    let mut mail_from = String::new();
    let mut rcpt_to = Vec::new();
    let mut in_data = false;
    let mut email_data = Vec::new();

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let cmd = line.trim().to_uppercase();

        if in_data {
            if line.trim() == "." {
                in_data = false;
                log_smtp("DATA received", &format!("{} bytes", email_data.len()), &src_addr, &config);
                // Log email content
                let email_str = String::from_utf8_lossy(&email_data);
                for data_line in email_str.lines().take(20) {
                    println!("             {}", data_line.dimmed());
                }
                email_data.clear();
                writer.write_all(b"250 OK: Message accepted\r\n").await?;
            } else {
                email_data.extend_from_slice(line.as_bytes());
            }
            continue;
        }

        if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
            let domain = line.trim()[4..].trim().to_string();
            log_smtp(&cmd[..4], &domain, &src_addr, &config);
            writer.write_all(b"250-argus.local\r\n").await?;
            writer.write_all(b"250-SIZE 10240000\r\n").await?;
            writer.write_all(b"250-AUTH LOGIN PLAIN\r\n").await?;
            writer.write_all(b"250 HELP\r\n").await?;
        } else if cmd.starts_with("MAIL FROM:") {
            mail_from = line[10..].trim().trim_matches(|c| c == '<' || c == '>').to_string();
            log_smtp("MAIL FROM", &mail_from, &src_addr, &config);
            writer.write_all(b"250 OK\r\n").await?;
        } else if cmd.starts_with("RCPT TO:") {
            let rcpt = line[8..].trim().trim_matches(|c| c == '<' || c == '>').to_string();
            log_smtp("RCPT TO", &rcpt, &src_addr, &config);
            rcpt_to.push(rcpt);
            writer.write_all(b"250 OK\r\n").await?;
        } else if cmd.starts_with("DATA") {
            log_smtp("DATA", "starting message body", &src_addr, &config);
            in_data = true;
            writer.write_all(b"354 Start input, end with <CRLF>.<CRLF>\r\n").await?;
        } else if cmd.starts_with("AUTH") {
            log_smtp("AUTH", line.trim(), &src_addr, &config);
            writer.write_all(b"235 Authentication successful\r\n").await?;
        } else if cmd.starts_with("QUIT") {
            log_smtp("QUIT", "", &src_addr, &config);
            writer.write_all(b"221 Bye\r\n").await?;
            break;
        } else if cmd.starts_with("RSET") {
            mail_from.clear();
            rcpt_to.clear();
            writer.write_all(b"250 OK\r\n").await?;
        } else if cmd.starts_with("NOOP") {
            writer.write_all(b"250 OK\r\n").await?;
        } else {
            debug!("Unknown SMTP command: {}", cmd);
            writer.write_all(b"500 Command not recognized\r\n").await?;
        }
    }

    Ok(())
}

pub async fn start(config: ListenerConfig, bind_addr: String) -> Result<()> {
    let addr = format!("{}:{}", bind_addr, config.port);
    let listener = TcpListener::bind(&addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind SMTP on {}: {}", addr, e))?;

    debug!("SMTP listener on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, src_addr)) => {
                let cfg = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_smtp(stream, src_addr, cfg).await {
                        debug!("SMTP error: {}", e);
                    }
                });
            }
            Err(e) => warn!("SMTP accept error: {}", e),
        }
    }
}
