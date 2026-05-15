//! SMTP listener — intercepts email sending attempts

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn, debug};

use crate::config::ListenerConfig;
use crate::conn_table::SharedConnTable;
use crate::request_logger::SharedRequestLogger;

fn log_smtp(event: &str, detail: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    info!("SMTP [{}] {} {} {}", config.name, src_addr, event, detail);
}

/// Write `data` to `writer`, also appending it to `resp`.
macro_rules! send {
    ($writer:expr, $resp:expr, $data:expr) => {{
        $resp.extend_from_slice($data);
        $writer.write_all($data).await?
    }};
}

async fn handle_smtp(
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

    let banner = config.banner.as_deref()
        .unwrap_or("220 argus.local SMTP Service Ready");
    let banner_line = format!("{}\r\n", banner);
    send!(writer, resp_transcript, banner_line.as_bytes());

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
        req_transcript.extend_from_slice(line.as_bytes());

        let cmd = line.trim().to_uppercase();

        if in_data {
            if line.trim() == "." {
                in_data = false;
                log_smtp("DATA received", &format!("{} bytes", email_data.len()), &src_addr, &config);
                let email_str = String::from_utf8_lossy(&email_data);
                for data_line in email_str.lines().take(20) {
                    info!("    {}", data_line);
                }
                email_data.clear();
                send!(writer, resp_transcript, b"250 OK: Message accepted\r\n");
            } else {
                email_data.extend_from_slice(line.as_bytes());
            }
            continue;
        }

        if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
            let domain = line.trim()[4..].trim().to_string();
            log_smtp(&cmd[..4], &domain, &src_addr, &config);
            send!(writer, resp_transcript, b"250-argus.local\r\n");
            send!(writer, resp_transcript, b"250-SIZE 10240000\r\n");
            send!(writer, resp_transcript, b"250-AUTH LOGIN PLAIN\r\n");
            send!(writer, resp_transcript, b"250 HELP\r\n");
        } else if cmd.starts_with("MAIL FROM:") {
            mail_from = line[10..].trim().trim_matches(|c| c == '<' || c == '>').to_string();
            log_smtp("MAIL FROM", &mail_from, &src_addr, &config);
            send!(writer, resp_transcript, b"250 OK\r\n");
        } else if cmd.starts_with("RCPT TO:") {
            let rcpt = line[8..].trim().trim_matches(|c| c == '<' || c == '>').to_string();
            log_smtp("RCPT TO", &rcpt, &src_addr, &config);
            rcpt_to.push(rcpt);
            send!(writer, resp_transcript, b"250 OK\r\n");
        } else if cmd.starts_with("DATA") {
            log_smtp("DATA", "starting message body", &src_addr, &config);
            in_data = true;
            send!(writer, resp_transcript, b"354 Start input, end with <CRLF>.<CRLF>\r\n");
        } else if cmd.starts_with("AUTH") {
            log_smtp("AUTH", line.trim(), &src_addr, &config);
            send!(writer, resp_transcript, b"235 Authentication successful\r\n");
        } else if cmd.starts_with("QUIT") {
            log_smtp("QUIT", "", &src_addr, &config);
            send!(writer, resp_transcript, b"221 Bye\r\n");
            break;
        } else if cmd.starts_with("RSET") {
            mail_from.clear();
            rcpt_to.clear();
            send!(writer, resp_transcript, b"250 OK\r\n");
        } else if cmd.starts_with("NOOP") {
            send!(writer, resp_transcript, b"250 OK\r\n");
        } else {
            debug!("Unknown SMTP command: {}", cmd);
            send!(writer, resp_transcript, b"500 Command not recognized\r\n");
        }
    }

    if should_log {
        if let Some(ref logger) = request_logger {
            if !req_transcript.is_empty() {
                if let Err(e) = logger.log(log_pid, &log_name, "smtp", log_counter, "req", &req_transcript) {
                    debug!("Request log write failed: {}", e);
                }
            }
            if !resp_transcript.is_empty() {
                if let Err(e) = logger.log(log_pid, &log_name, "smtp", log_counter, "rsp", &resp_transcript) {
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
        .map_err(|e| anyhow::anyhow!("Failed to bind SMTP on {}: {}", addr, e))?;

    debug!("SMTP listener on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, src_addr)) => {
                let cfg = config.clone();
                let ct = conn_table.clone();
                let rl = request_logger.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_smtp(stream, src_addr, cfg, ct, rl).await {
                        debug!("SMTP error: {}", e);
                    }
                });
            }
            Err(e) => warn!("SMTP accept error: {}", e),
        }
    }
}
