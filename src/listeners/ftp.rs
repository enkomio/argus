//! FTP listener — intercepts FTP traffic

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{warn, debug};
use chrono::Local;
use colored::*;

use crate::config::ListenerConfig;

fn log_ftp(event: &str, detail: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "{} {} {} {} {} {}",
        format!("[{}]", timestamp).dimmed(),
        "FTP ".bright_magenta().bold(),
        format!("[{}]", config.name).bright_magenta(),
        format!("{}", src_addr).yellow(),
        event.bright_white().bold(),
        detail.bright_cyan()
    );
}

async fn handle_ftp(
    stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    config: ListenerConfig,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let banner = config.banner.as_deref().unwrap_or("220 Argus FTP Server");
    writer.write_all(format!("{}\r\n", banner).as_bytes()).await?;

    let mut username = String::new();
    let mut line = String::new();

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
                log_ftp("USER", &username, &src_addr, &config);
                writer.write_all(b"331 Password required\r\n").await?;
            }
            "PASS" => {
                log_ftp("PASS", &format!("user={} pass={}", username, arg), &src_addr, &config);
                writer.write_all(b"230 User logged in\r\n").await?;
            }
            "SYST" => {
                writer.write_all(b"215 UNIX Type: L8\r\n").await?;
            }
            "FEAT" => {
                writer.write_all(b"211-Features:\r\n PASV\r\n SIZE\r\n211 End\r\n").await?;
            }
            "PWD" => {
                writer.write_all(b"257 \"/\" is the current directory\r\n").await?;
            }
            "CWD" | "CDUP" => {
                log_ftp(&cmd, arg, &src_addr, &config);
                writer.write_all(b"250 Directory changed\r\n").await?;
            }
            "LIST" | "NLST" => {
                log_ftp(&cmd, arg, &src_addr, &config);
                writer.write_all(b"150 Opening data connection\r\n").await?;
                writer.write_all(b"226 Transfer complete\r\n").await?;
            }
            "RETR" => {
                log_ftp("RETR", arg, &src_addr, &config);
                writer.write_all(b"150 Opening data connection\r\n").await?;
                writer.write_all(b"226 Transfer complete\r\n").await?;
            }
            "STOR" | "STOU" => {
                log_ftp("STOR", arg, &src_addr, &config);
                writer.write_all(b"150 Opening data connection\r\n").await?;
                writer.write_all(b"226 Transfer complete\r\n").await?;
            }
            "SIZE" => {
                log_ftp("SIZE", arg, &src_addr, &config);
                writer.write_all(b"213 0\r\n").await?;
            }
            "PASV" => {
                writer.write_all(b"227 Entering Passive Mode (127,0,0,1,200,1)\r\n").await?;
            }
            "TYPE" => {
                writer.write_all(b"200 Type set\r\n").await?;
            }
            "PORT" => {
                log_ftp("PORT", arg, &src_addr, &config);
                writer.write_all(b"200 PORT command successful\r\n").await?;
            }
            "QUIT" | "BYE" => {
                log_ftp("QUIT", "", &src_addr, &config);
                writer.write_all(b"221 Goodbye\r\n").await?;
                break;
            }
            "NOOP" => {
                writer.write_all(b"200 OK\r\n").await?;
            }
            _ => {
                debug!("Unknown FTP command: {}", cmd);
                writer.write_all(b"500 Command not recognized\r\n").await?;
            }
        }
    }

    Ok(())
}

pub async fn start(config: ListenerConfig, bind_addr: String) -> Result<()> {
    let addr = format!("{}:{}", bind_addr, config.port);
    let listener = TcpListener::bind(&addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind FTP on {}: {}", addr, e))?;

    debug!("FTP listener on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, src_addr)) => {
                let cfg = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_ftp(stream, src_addr, cfg).await {
                        debug!("FTP error: {}", e);
                    }
                });
            }
            Err(e) => warn!("FTP accept error: {}", e),
        }
    }
}
