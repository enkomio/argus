//! FTP listener — intercepts FTP traffic

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn, debug};

use crate::config::ListenerConfig;
use crate::conn_table::SharedConnTable;
use crate::request_logger::SharedRequestLogger;

fn log_ftp(event: &str, detail: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    info!("FTP  [{}] {} {} {}", config.name, src_addr, event, detail);
}

/// Write `data` to `writer`, also appending it to `resp`.
macro_rules! send {
    ($writer:expr, $resp:expr, $data:expr) => {{
        $resp.extend_from_slice($data);
        $writer.write_all($data).await?
    }};
}

async fn handle_ftp(
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

    let banner = config.banner.as_deref().unwrap_or("220 Argus FTP Server");
    let banner_line = format!("{}\r\n", banner);
    send!(writer, resp_transcript, banner_line.as_bytes());

    let mut username = String::new();
    let mut line = String::new();

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
                log_ftp("USER", &username, &src_addr, &config);
                send!(writer, resp_transcript, b"331 Password required\r\n");
            }
            "PASS" => {
                log_ftp("PASS", &format!("user={} pass={}", username, arg), &src_addr, &config);
                send!(writer, resp_transcript, b"230 User logged in\r\n");
            }
            "SYST" => {
                send!(writer, resp_transcript, b"215 UNIX Type: L8\r\n");
            }
            "FEAT" => {
                send!(writer, resp_transcript, b"211-Features:\r\n PASV\r\n SIZE\r\n211 End\r\n");
            }
            "PWD" => {
                send!(writer, resp_transcript, b"257 \"/\" is the current directory\r\n");
            }
            "CWD" | "CDUP" => {
                log_ftp(&cmd, arg, &src_addr, &config);
                send!(writer, resp_transcript, b"250 Directory changed\r\n");
            }
            "LIST" | "NLST" => {
                log_ftp(&cmd, arg, &src_addr, &config);
                send!(writer, resp_transcript, b"150 Opening data connection\r\n");
                send!(writer, resp_transcript, b"226 Transfer complete\r\n");
            }
            "RETR" => {
                log_ftp("RETR", arg, &src_addr, &config);
                send!(writer, resp_transcript, b"150 Opening data connection\r\n");
                send!(writer, resp_transcript, b"226 Transfer complete\r\n");
            }
            "STOR" | "STOU" => {
                log_ftp("STOR", arg, &src_addr, &config);
                send!(writer, resp_transcript, b"150 Opening data connection\r\n");
                send!(writer, resp_transcript, b"226 Transfer complete\r\n");
            }
            "SIZE" => {
                log_ftp("SIZE", arg, &src_addr, &config);
                send!(writer, resp_transcript, b"213 0\r\n");
            }
            "PASV" => {
                send!(writer, resp_transcript, b"227 Entering Passive Mode (127,0,0,1,200,1)\r\n");
            }
            "TYPE" => {
                send!(writer, resp_transcript, b"200 Type set\r\n");
            }
            "PORT" => {
                log_ftp("PORT", arg, &src_addr, &config);
                send!(writer, resp_transcript, b"200 PORT command successful\r\n");
            }
            "QUIT" | "BYE" => {
                log_ftp("QUIT", "", &src_addr, &config);
                send!(writer, resp_transcript, b"221 Goodbye\r\n");
                break;
            }
            "NOOP" => {
                send!(writer, resp_transcript, b"200 OK\r\n");
            }
            _ => {
                debug!("Unknown FTP command: {}", cmd);
                send!(writer, resp_transcript, b"500 Command not recognized\r\n");
            }
        }
    }

    if should_log {
        if let Some(ref logger) = request_logger {
            if !req_transcript.is_empty() {
                if let Err(e) = logger.log(log_pid, &log_name, "ftp", log_counter, "req", &req_transcript) {
                    debug!("Request log write failed: {}", e);
                }
            }
            if !resp_transcript.is_empty() {
                if let Err(e) = logger.log(log_pid, &log_name, "ftp", log_counter, "rsp", &resp_transcript) {
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
        .map_err(|e| anyhow::anyhow!("Failed to bind FTP on {}: {}", addr, e))?;

    debug!("FTP listener on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, src_addr)) => {
                let cfg = config.clone();
                let ct = conn_table.clone();
                let rl = request_logger.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_ftp(stream, src_addr, cfg, ct, rl).await {
                        debug!("FTP error: {}", e);
                    }
                });
            }
            Err(e) => warn!("FTP accept error: {}", e),
        }
    }
}
