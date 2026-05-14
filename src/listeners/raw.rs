//! Raw TCP/UDP listener — captures any traffic on a port

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{warn, debug};
use chrono::Local;
use colored::*;

use crate::config::ListenerConfig;

fn hexdump(data: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
        let ascii: String = chunk.iter().map(|&b| {
            if b > 31 && b < 127 { b as char } else { '.' }
        }).collect();
        lines.push(format!("{:04X}: {:<48} {}", i * 16, hex.join(" "), ascii));
    }
    lines
}

fn log_raw(data: &[u8], src_addr: &SocketAddr, config: &ListenerConfig, proto: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "{} {} {} {} {} {} bytes",
        format!("[{}]", timestamp).dimmed(),
        proto.bright_red().bold(),
        format!("[{}]", config.name).bright_magenta(),
        format!("{}", src_addr).yellow(),
        "→".dimmed(),
        data.len().to_string().bright_white()
    );

    // Show up to first 256 bytes as hexdump
    let dump_data = if data.len() > 256 { &data[..256] } else { data };
    for line in hexdump(dump_data) {
        println!("             {}", line.dimmed());
    }

    if data.len() > 256 {
        println!("             {} ({} more bytes)", "...".dimmed(), data.len() - 256);
    }
}

async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    config: ListenerConfig,
) -> Result<()> {
    let timeout = tokio::time::Duration::from_secs(config.timeout);
    let mut buf = vec![0u8; 4096];

    loop {
        let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                debug!("Read error from {}: {}", src_addr, e);
                break;
            }
            Err(_) => {
                debug!("Connection timeout from {}", src_addr);
                break;
            }
        };

        let data = &buf[..n];
        log_raw(data, &src_addr, &config, "RAW-TCP");

        // Echo back
        if let Err(e) = stream.write_all(data).await {
            debug!("Write error to {}: {}", src_addr, e);
            break;
        }
    }

    Ok(())
}

pub async fn start(config: ListenerConfig, bind_addr: String) -> Result<()> {
    let addr = format!("{}:{}", bind_addr, config.port);

    if config.protocol.to_lowercase() == "tcp" {
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| anyhow::anyhow!("Failed to bind Raw TCP on {}: {}", addr, e))?;

        debug!("Raw TCP listener on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, src_addr)) => {
                    let cfg = config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_connection(stream, src_addr, cfg).await {
                            debug!("Raw TCP error: {}", e);
                        }
                    });
                }
                Err(e) => warn!("Accept error: {}", e),
            }
        }
    } else {
        // UDP
        let socket = tokio::net::UdpSocket::bind(&addr).await
            .map_err(|e| anyhow::anyhow!("Failed to bind Raw UDP on {}: {}", addr, e))?;

        debug!("Raw UDP listener on {}", addr);

        let mut buf = vec![0u8; 4096];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, src_addr)) => {
                    let data = buf[..n].to_vec();
                    log_raw(&data, &src_addr, &config, "RAW-UDP");
                    let _ = socket.send_to(&data, src_addr).await;
                }
                Err(e) => warn!("UDP recv error: {}", e),
            }
        }
    }
}
