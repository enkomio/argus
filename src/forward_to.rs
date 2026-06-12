//! ForwardTo — pipe request/response bytes through an external modifier endpoint.
//!
//! When a listener has `ForwardTo: IP:PORT` in its config, every intercepted
//! request and response is sent through the external endpoint before being
//! processed or forwarded to the client.  The endpoint can inspect and modify
//! the bytes; whatever it returns is used in place of the original payload.
//!
//! # Wire format
//!
//! **Argus → ForwardTo**
//! ```text
//! [4 bytes BE u32 : header JSON length]
//! [N bytes        : header JSON (UTF-8)]
//! [4 bytes BE u32 : payload length]
//! [M bytes        : raw payload]
//! ```
//!
//! **ForwardTo → Argus**
//! ```text
//! [4 bytes BE u32 : payload length]
//! [K bytes        : raw payload (modified or unchanged)]
//! ```
//!
//! On any error the **original payload is returned unchanged** so traffic is
//! never silently dropped.
//!
//! # Minimal Python example
//!
//! ```python
//! import struct, socket, json
//!
//! def recv_exact(s, n):
//!     buf = b""
//!     while len(buf) < n:
//!         buf += s.recv(n - len(buf))
//!     return buf
//!
//! srv = socket.socket(); srv.bind(("0.0.0.0", 9999)); srv.listen(8)
//! while True:
//!     conn, _ = srv.accept()
//!     hlen = struct.unpack(">I", recv_exact(conn, 4))[0]
//!     meta = json.loads(recv_exact(conn, hlen))
//!     plen = struct.unpack(">I", recv_exact(conn, 4))[0]
//!     payload = recv_exact(conn, plen)
//!     # meta["request_id"] is shared between a request and its response,
//!     # so the two can be correlated.
//!     print(meta["request_id"], meta["direction"], meta["protocol"], len(payload), "bytes")
//!     # Return payload unchanged
//!     conn.sendall(struct.pack(">I", len(payload)) + payload)
//!     conn.close()
//! ```

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Whether the payload is a request (client → Argus) or a response (Argus → client).
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Request,
    Response,
}

/// Global counter used to generate unique request/exchange identifiers.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a new unique exchange ID. Call once per request/response cycle
/// and pass the same value to both the request and response `Meta` so the
/// ForwardTo endpoint can correlate them.
pub fn next_request_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

/// Metadata serialised as JSON and prepended to every frame sent to the
/// ForwardTo endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct Meta {
    /// Unique ID shared by the request and its associated response, so the
    /// ForwardTo endpoint can correlate the two.
    pub request_id: u64,
    /// `"request"` or `"response"`.
    pub direction: Direction,
    /// Listener protocol: `"http"`, `"https"`, `"dns"`, `"smtp"`, `"pop3"`, `"raw"`.
    pub protocol: &'static str,
    /// Source IP of the originating client.
    pub src_ip: String,
    /// Source port of the originating client.
    pub src_port: u16,
    /// Original destination IP (before WinDivert rewrote it), or `""` if unknown.
    pub dst_ip: String,
    /// Original destination port, or `0` if unknown.
    pub dst_port: u16,
    /// Executable name of the originating process (e.g. `"malware.exe"`), or `"unknown"`.
    pub process: String,
    /// PID of the originating process (`0` = unknown).
    pub pid: u32,
}

impl Meta {
    pub fn new(
        request_id: u64,
        direction: Direction,
        protocol: &'static str,
        src_addr: SocketAddr,
        dst_ip: impl Into<String>,
        dst_port: u16,
        process: impl Into<String>,
        pid: u32,
    ) -> Self {
        Self {
            request_id,
            direction,
            protocol,
            src_ip: src_addr.ip().to_string(),
            src_port: src_addr.port(),
            dst_ip: dst_ip.into(),
            dst_port,
            process: process.into(),
            pid,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Send `payload` to the ForwardTo endpoint at `addr` and return the
/// (possibly modified) payload.
///
/// Falls back to the **original payload unchanged** on any network or protocol
/// error so traffic is never silently dropped.
pub async fn call(addr: &str, meta: &Meta, payload: &[u8]) -> Vec<u8> {
    match try_call(addr, meta, payload).await {
        Ok(modified) => {
            if modified.len() != payload.len() {
                debug!(
                    "ForwardTo [{}] {:?} {} bytes → {} bytes (modified)",
                    addr, meta.direction, payload.len(), modified.len()
                );
            }
            modified
        }
        Err(e) => {
            warn!("ForwardTo [{}] error: {:#} — using original payload", addr, e);
            println!(
                "{} {} {:?}: {:#} — using original payload",
                "[ForwardTo]".bright_red().bold(),
                format!("{} unreachable or returned invalid data", addr).yellow(),
                meta.direction,
                e,
            );
            payload.to_vec()
        }
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

async fn try_call(addr: &str, meta: &Meta, payload: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await
        .with_context(|| format!("connect to {}", addr))?;

    // Serialise header as JSON
    let header_json = serde_json::to_vec(meta)
        .context("serialise ForwardTo header")?;

    // ── Send: [header_len(4)][header][payload_len(4)][payload] ────────────
    stream.write_all(&(header_json.len() as u32).to_be_bytes()).await?;
    stream.write_all(&header_json).await?;
    stream.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;

    // ── Receive: [payload_len(4)][payload] ────────────────────────────────
    let mut rlen_buf = [0u8; 4];
    stream.read_exact(&mut rlen_buf).await
        .context("read response length")?;
    let rlen = u32::from_be_bytes(rlen_buf) as usize;

    // Sanity cap: 64 MB
    anyhow::ensure!(rlen <= 64 * 1024 * 1024, "response too large ({} bytes)", rlen);

    let mut result = vec![0u8; rlen];
    if rlen > 0 {
        stream.read_exact(&mut result).await
            .context("read response payload")?;
    }

    Ok(result)
}
