//! Raw TCP/UDP listener — captures any traffic on a port

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, debug};

use crate::config::ListenerConfig;
use crate::conn_table::SharedConnTable;
use crate::forward_to::{self, Direction, Meta};
use crate::request_logger::SharedRequestLogger;

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
    info!("{} [{}] {} -> {} bytes", proto, config.name, src_addr, data.len());
    let dump_data = if data.len() > 256 { &data[..256] } else { data };
    for line in hexdump(dump_data) {
        info!("    {}", line);
    }
    if data.len() > 256 {
        info!("    ... ({} more bytes)", data.len() - 256);
    }
}

async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    config: ListenerConfig,
    conn_table: SharedConnTable,
    request_logger: Option<SharedRequestLogger>,
) -> Result<()> {
    let should_log = !crate::conn_table::should_skip_log(
        &conn_table, src_addr.port(), &config.no_log,
    );
    let (log_pid, log_name) = crate::conn_table::get_process_info(&conn_table, src_addr.port());
    let log_counter = if should_log {
        request_logger.as_ref().map(|l| l.alloc_counter(log_pid)).unwrap_or(0)
    } else {
        0
    };
    let timeout = tokio::time::Duration::from_secs(config.timeout);
    let mut buf = vec![0u8; 4096];
    let mut req_transcript:  Vec<u8> = Vec::new();
    let mut resp_transcript: Vec<u8> = Vec::new();

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
        req_transcript.extend_from_slice(data);
        log_raw(data, &src_addr, &config, "RAW-TCP");

        // ── ForwardTo: request + response ─────────────────────────────────
        let echo_bytes: Vec<u8> = if let Some(ref ft_addr) = config.forward_to {
            let (pid, proc_name) = crate::conn_table::get_process_info(&conn_table, src_addr.port());
            let ci = conn_table.read().ok().and_then(|t| t.get(&src_addr.port()).cloned());
            let (dst_ip, dst_port) = ci.as_ref()
                .map(|i| (i.orig_dst_ip.to_string(), i.orig_dst_port))
                .unwrap_or_default();
            let ft_request_id = forward_to::next_request_id();
            let req_meta = Meta::new(ft_request_id, Direction::Request, "raw", src_addr, &dst_ip, dst_port, &proc_name, pid);
            let modified_req = forward_to::call(ft_addr, &req_meta, data).await;
            let rsp_meta = Meta::new(ft_request_id, Direction::Response, "raw", src_addr, &dst_ip, dst_port, &proc_name, pid);
            forward_to::call(ft_addr, &rsp_meta, &modified_req).await
        } else {
            data.to_vec()
        };

        // Echo back (modified if ForwardTo is set, original otherwise)
        if let Err(e) = stream.write_all(&echo_bytes).await {
            debug!("Write error to {}: {}", src_addr, e);
            break;
        }
        resp_transcript.extend_from_slice(&echo_bytes);
    }

    if should_log {
        if let Some(ref logger) = request_logger {
            if !req_transcript.is_empty() {
                if let Err(e) = logger.log(log_pid, &log_name, "raw", log_counter, "req", &req_transcript) {
                    debug!("Request log write failed: {}", e);
                }
            }
            if !resp_transcript.is_empty() {
                if let Err(e) = logger.log(log_pid, &log_name, "raw", log_counter, "rsp", &resp_transcript) {
                    debug!("Response log write failed: {}", e);
                }
            }
        }
    }

    Ok(())
}

pub async fn start(config: ListenerConfig, bind_addr: String, conn_table: SharedConnTable, request_logger: Option<SharedRequestLogger>) -> Result<()> {
    let addr = format!("{}:{}", bind_addr, config.listener_port);

    if config.protocol.to_lowercase() == "tcp" {
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| anyhow::anyhow!("Failed to bind Raw TCP on {}: {}", addr, e))?;

        debug!("Raw TCP listener on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, src_addr)) => {
                    let cfg = config.clone();
                    let ct = conn_table.clone();
                    let rl = request_logger.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_connection(stream, src_addr, cfg, ct, rl).await {
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

                    // Echo back
                    let _ = socket.send_to(&data, src_addr).await;

                    // Log request and echoed response
                    let udp_should_log = !crate::conn_table::should_skip_log(
                        &conn_table, src_addr.port(), &config.no_log,
                    );
                    if udp_should_log {
                        if let Some(ref logger) = request_logger {
                            let (pid, name) = crate::conn_table::get_process_info(&conn_table, src_addr.port());
                            let counter = logger.alloc_counter(pid);
                            if let Err(e) = logger.log(pid, &name, "raw", counter, "req", &data) {
                                debug!("Request log write failed: {}", e);
                            }
                            if let Err(e) = logger.log(pid, &name, "raw", counter, "rsp", &data) {
                                debug!("Response log write failed: {}", e);
                            }
                        }
                    }
                }
                Err(e) => warn!("UDP recv error: {}", e),
            }
        }
    }
}
