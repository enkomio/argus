//! HTTP/HTTPS listener — intercepts and responds to HTTP requests

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{info, warn, debug};
use chrono::Local;
use colored::*;

use regex::Regex;

use crate::config::ListenerConfig;
use crate::conn_table::SharedConnTable;

const FAKE_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>Argus</title></head>
<body>
<h1>Argus</h1>
<p>This is an Argus response. Your malware sample is being analyzed.</p>
</body>
</html>"#;

const FAKE_XML: &str = r#"<?xml version="1.0"?><argus><status>intercepted</status></argus>"#;

/// Log NBI (Network-Based Indicator) for HTTP requests
fn log_nbi(method: &str, uri: &str, host: &str, user_agent: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "{} {} {} {} {} {} {} {}",
        format!("[{}]", timestamp).dimmed(),
        "HTTP".bright_cyan().bold(),
        format!("[{}]", config.name).bright_magenta(),
        format!("{}", src_addr).yellow(),
        "→".dimmed(),
        method.bright_green().bold(),
        uri.bright_white(),
        if !host.is_empty() { format!("(Host: {})", host).dimmed().to_string() } else { String::new() }
    );
    if !user_agent.is_empty() {
        println!("             {} {}", "User-Agent:".dimmed(), user_agent.bright_white());
    }
}

/// Returns `true` when any entry in `forward` matches the HTTP request's
/// `Host` header and URI.
///
/// Entries are treated as **case-insensitive regex patterns** anchored at
/// the start (`^`), matched against the string `"host/uri"` (port stripped).
///
/// Examples:
///   - `example\.com`          — exact host, any path
///   - `example\.com/api`      — exact host, paths starting with `/api`
///   - `example\..*`           — any host starting with `example.`  (e.g. `example.com`, `example.it`)
///   - `http://example\.com`   — scheme is stripped before matching
///   - `.*\.evil\.com`         — any subdomain of `evil.com`
///
/// For invalid regex patterns the function falls back to a plain
/// case-insensitive host comparison with optional path-prefix matching.
fn matches_forward_domain(forward: &[String], host: &str, uri: &str) -> bool {
    // Strip port from Host header ("example.com:8080" → "example.com").
    let req_host = host.split(':').next().unwrap_or(host);
    // Build the target string the regex is matched against: "host/uri"
    // e.g. "example.com/api/v1/resource"
    let target = format!("{}{}", req_host, uri);

    for entry in forward {
        let s = entry.trim();
        if s.is_empty() {
            continue;
        }

        // Strip scheme prefix if present.
        let s = s.strip_prefix("https://")
            .or_else(|| s.strip_prefix("http://"))
            .unwrap_or(s);

        // Try the entry as a case-insensitive regex anchored at the start.
        let pattern = format!("(?i)^{}", s);
        match Regex::new(&pattern) {
            Ok(re) => {
                if re.is_match(&target) {
                    return true;
                }
            }
            Err(_) => {
                // Invalid regex: fall back to plain host + path-prefix matching.
                let (entry_host, entry_path) = match s.find('/') {
                    Some(i) => (&s[..i], &s[i..]),
                    None    => (s, ""),
                };
                if req_host.eq_ignore_ascii_case(entry_host) {
                    if entry_path.is_empty() || uri.starts_with(entry_path) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Determine MIME type from file extension
fn get_mime_type(path: &str) -> &'static str {
    let path = path.to_lowercase();
    if path.ends_with(".html") || path.ends_with(".htm") || path == "/" {
        "text/html"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
        "image/jpeg"
    } else if path.ends_with(".gif") {
        "image/gif"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".js") {
        "application/javascript"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".xml") {
        "application/xml"
    } else if path.ends_with(".pdf") {
        "application/pdf"
    } else if path.ends_with(".exe") || path.ends_with(".dll") {
        "application/octet-stream"
    } else if path.ends_with(".zip") {
        "application/zip"
    } else if path.ends_with(".txt") {
        "text/plain"
    } else {
        "text/html"
    }
}

/// Handle a single HTTP connection
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    config: ListenerConfig,
    conn_table: SharedConnTable,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Resolve connection info once; reused for both forward phases below.
    let conn_info = if !config.forward.is_empty() {
        conn_table
            .read()
            .ok()
            .and_then(|tbl| tbl.get(&src_addr.port()).cloned())
    } else {
        None
    };

    // ── Forward phase 1: PID / process name / IP ─────────────────────────────
    // Checked before reading HTTP data so the stream is untouched and
    // copy_bidirectional gets a clean bidirectional channel.
    if !config.forward.is_empty() {
        if let Some(ref info) = conn_info {
            if info.matches_forward_list(&config.forward) {
                let dst_addr = info.orig_dst_addr();
                println!(
                    "{} {} → {} {} [{}]",
                    format!("[{}]", config.name).bright_magenta(),
                    src_addr.to_string().yellow(),
                    dst_addr.bright_white(),
                    "FORWARDED".bright_blue().bold(),
                    info.process_label().dimmed(),
                );
                match tokio::net::TcpStream::connect(&dst_addr).await {
                    Ok(mut remote) => {
                        if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut remote).await {
                            debug!("Forward proxy closed ({}): {}", dst_addr, e);
                        }
                    }
                    Err(e) => warn!("Forward: could not connect to {}: {}", dst_addr, e),
                }
                return Ok(());
            }
        } else {
            debug!("Forward: no conn_table entry for port {}, falling back to intercept", src_addr.port());
        }
    }

    // ── Read HTTP request ─────────────────────────────────────────────────────
    let timeout = tokio::time::Duration::from_secs(config.timeout);
    let mut buf = vec![0u8; 8192];
    let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            debug!("Read error from {}: {}", src_addr, e);
            return Ok(());
        }
        Err(_) => {
            debug!("Connection timeout from {}", src_addr);
            return Ok(());
        }
    };

    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let lines: Vec<&str> = request.lines().collect();

    if lines.is_empty() {
        return Ok(());
    }

    // Parse request line
    let request_line = lines[0];
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let uri = parts[1];

    // Parse headers
    let mut host = String::new();
    let mut user_agent = String::new();
    let mut content_length: usize = 0;

    for line in &lines[1..] {
        if line.is_empty() {
            break;
        }
        let lower = line.to_lowercase();
        if lower.starts_with("host:") {
            host = line[5..].trim().to_string();
        } else if lower.starts_with("user-agent:") {
            user_agent = line[11..].trim().to_string();
        } else if lower.starts_with("content-length:") {
            content_length = line[15..].trim().parse().unwrap_or(0);
        }
    }

    // ── Forward phase 2: domain / URL ─────────────────────────────────────────
    // Run after parsing HTTP headers so we have the Host header and URI.
    // The already-read request bytes are replayed to the real server before
    // handing the connection off to copy_bidirectional.
    if !config.forward.is_empty() {
        if let Some(ref info) = conn_info {
            if matches_forward_domain(&config.forward, &host, uri) {
                let dst_addr = info.orig_dst_addr();
                println!(
                    "{} {} → {} {} (Host: {})",
                    format!("[{}]", config.name).bright_magenta(),
                    src_addr.to_string().yellow(),
                    dst_addr.bright_white(),
                    "FORWARDED".bright_blue().bold(),
                    host.bright_white(),
                );
                match tokio::net::TcpStream::connect(&dst_addr).await {
                    Ok(mut remote) => {
                        // Replay the already-buffered request to the real server.
                        if let Err(e) = remote.write_all(&buf[..n]).await {
                            warn!("Forward: write error to {}: {}", dst_addr, e);
                            return Ok(());
                        }
                        // Proxy any remaining data (response + possible pipelining).
                        if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut remote).await {
                            debug!("Forward proxy closed ({}): {}", dst_addr, e);
                        }
                    }
                    Err(e) => warn!("Forward: could not connect to {}: {}", dst_addr, e),
                }
                return Ok(());
            }
        }
    }

    // ── Intercept mode: fake response ─────────────────────────────────────────
    log_nbi(method, uri, &host, &user_agent, &src_addr, &config);

    // Determine response
    let mime_type = get_mime_type(uri);
    let (body, content_type) = match mime_type {
        "text/html" => (FAKE_HTML.as_bytes().to_vec(), "text/html; charset=utf-8"),
        "application/xml" => (FAKE_XML.as_bytes().to_vec(), "application/xml"),
        _ => (FAKE_HTML.as_bytes().to_vec(), "text/html; charset=utf-8"),
    };

    let server_name = "Argus/1.0";
    let date = Local::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

    let mut response = format!(
        "HTTP/1.1 200 OK\r\nServer: {}\r\nDate: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        server_name,
        date,
        content_type,
        body.len()
    ).into_bytes();

    if method != "HEAD" {
        response.extend_from_slice(&body);
    }

    // Log POST body if present
    if method == "POST" && content_length > 0 {
        if let Some(body_start) = request.find("\r\n\r\n") {
            let post_body = &request[body_start + 4..];
            if !post_body.is_empty() {
                println!("             {} {}", "POST body:".dimmed(), post_body.chars().take(200).collect::<String>().bright_white());
            }
        }
    }

    let _ = stream.write_all(&response).await;
    let _ = stream.flush().await;

    Ok(())
}

/// Start the HTTP listener
pub async fn start(config: ListenerConfig, bind_addr: String, conn_table: SharedConnTable) -> Result<()> {
    let addr = format!("{}:{}", bind_addr, config.port);
    let listener = TcpListener::bind(&addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind HTTP listener on {}: {}", addr, e))?;

    debug!("HTTP listener started on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, src_addr)) => {
                let cfg = config.clone();
                let ct  = conn_table.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, src_addr, cfg, ct).await {
                        debug!("HTTP connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                warn!("Accept error: {}", e);
            }
        }
    }
}
