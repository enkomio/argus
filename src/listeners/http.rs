//! HTTP/HTTPS listener -- intercepts and responds to HTTP requests
//!
//! In HTTPS mode the listener performs TLS termination (MITM): it presents a
//! self-signed certificate to the connecting client, decrypts the traffic, and
//! logs the plaintext request/response.  When in passthrough mode, a new TLS
//! connection is opened to the real server (certificate errors on the upstream
//! side are intentionally ignored so that malware using self-signed or expired
//! certs is also passed through correctly).
//!
//! The self-signed CA certificate is printed to stdout at startup so the
//! analyst can import it into the analysis VM's trust store.

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls_pemfile;
use tracing::{info, warn, debug};
use chrono::Local;
use colored::*;
use regex::Regex;

use crate::config::ListenerConfig;
use crate::conn_table::SharedConnTable;
use crate::forward_to::{self, Direction, Meta};
use crate::request_logger::SharedRequestLogger;

// ---------------------------------------------------------------------------
// Static content
// ---------------------------------------------------------------------------

/// Built-in fallback HTML -- used when `default_files/index.html` is missing.
const FAKE_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>Argus</title></head>
<body>
<h1>Argus</h1>
<p>This is an Argus response.</p>
</body>
</html>"#;

const FAKE_XML: &str = r#"<?xml version="1.0"?><argus><status>intercepted</status></argus>"#;

/// Directory that contains the files served as fake responses.
const DEFAULT_FILES_DIR: &str = "default_files";

// ---------------------------------------------------------------------------
// Default-files helpers
// ---------------------------------------------------------------------------

fn load_from_default_files(uri: &str) -> Option<Vec<u8>> {
    let sanitised: std::path::PathBuf = uri
        .trim_start_matches('/')
        .split('/')
        .filter(|c| !c.is_empty() && *c != "..")
        .collect();
    let file_path = if sanitised.as_os_str().is_empty() {
        std::path::PathBuf::from(DEFAULT_FILES_DIR).join("index.html")
    } else {
        std::path::PathBuf::from(DEFAULT_FILES_DIR).join(sanitised)
    };
    std::fs::read(file_path).ok()
}

fn fake_response_body(uri: &str, mime_type: &str) -> Vec<u8> {
    if let Some(bytes) = load_from_default_files(uri) {
        return bytes;
    }
    if mime_type == "text/html" {
        if let Ok(bytes) = std::fs::read(
            std::path::Path::new(DEFAULT_FILES_DIR).join("index.html"),
        ) {
            return bytes;
        }
    }
    match mime_type {
        "application/xml" => FAKE_XML.as_bytes().to_vec(),
        _                 => FAKE_HTML.as_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Console logging
// ---------------------------------------------------------------------------

fn log_http(method: &str, uri: &str, host: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    let proto = if config.use_ssl { "HTTPS" } else { "HTTP " };
    if host.is_empty() {
        info!("{} [{}] {} -> {} {}", proto, config.name, src_addr, method, uri);
    } else {
        info!("{} [{}] {} -> {} {} (Host: {})", proto, config.name, src_addr, method, uri, host);
    }
}

// ---------------------------------------------------------------------------
// Passthrough / NoLog domain matching
// ---------------------------------------------------------------------------

fn matches_passthrough_domain(passthrough: &[String], host: &str, uri: &str) -> bool {
    let req_host = host.split(':').next().unwrap_or(host);
    let target   = format!("{}{}", req_host, uri);

    for entry in passthrough {
        let s = entry.trim();
        if s.is_empty() { continue; }
        let s = s.strip_prefix("https://")
            .or_else(|| s.strip_prefix("http://"))
            .unwrap_or(s);
        let pattern = format!("(?i)^{}", s);
        match Regex::new(&pattern) {
            Ok(re) => {
                if re.is_match(&target) { return true; }
            }
            Err(_) => {
                let (entry_host, entry_path) = match s.find('/') {
                    Some(i) => (&s[..i], &s[i..]),
                    None    => (s, ""),
                };
                if req_host.eq_ignore_ascii_case(entry_host) &&
                   (entry_path.is_empty() || uri.starts_with(entry_path))
                {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// MIME type
// ---------------------------------------------------------------------------

fn get_mime_type(path: &str) -> &'static str {
    let path = path.to_lowercase();
    if path.ends_with(".html") || path.ends_with(".htm") || path == "/" { "text/html" }
    else if path.ends_with(".png")  { "image/png" }
    else if path.ends_with(".jpg") || path.ends_with(".jpeg") { "image/jpeg" }
    else if path.ends_with(".gif")  { "image/gif" }
    else if path.ends_with(".ico")  { "image/x-icon" }
    else if path.ends_with(".css")  { "text/css" }
    else if path.ends_with(".js")   { "application/javascript" }
    else if path.ends_with(".json") { "application/json" }
    else if path.ends_with(".xml")  { "application/xml" }
    else if path.ends_with(".pdf")  { "application/pdf" }
    else if path.ends_with(".exe") || path.ends_with(".dll") { "application/octet-stream" }
    else if path.ends_with(".zip")  { "application/zip" }
    else if path.ends_with(".txt")  { "text/plain" }
    else { "text/html" }
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

/// Path of the CA certificate and private key (PEM format).
fn ca_cert_path() -> std::path::PathBuf { std::path::Path::new("configs").join("argus-ca.crt") }
fn ca_key_path()  -> std::path::PathBuf { std::path::Path::new("configs").join("argus-ca.key") }

// ---------------------------------------------------------------------------
// Argus CA: generates per-host leaf certificates signed by a local root CA
// ---------------------------------------------------------------------------

/// Holds the CA certificate/key used to issue per-host leaf certificates, plus
/// a cache so each hostname is only signed once per process lifetime.
struct ArgusCA {
    signing_cert: rcgen::Certificate,
    signing_key:  rcgen::KeyPair,
    /// DER of the CA cert that was shown to the user; included in leaf chains.
    cert_der: CertificateDer<'static>,
    cache: std::sync::Mutex<std::collections::HashMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

impl std::fmt::Debug for ArgusCA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArgusCA").finish_non_exhaustive()
    }
}

impl ArgusCA {
    /// Build the `CertificateParams` for the CA cert.  Same params are used
    /// both on first generation and when reconstructing from a saved key.
    fn ca_params() -> rcgen::CertificateParams {
        let now = time::OffsetDateTime::now_utc();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca      = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params.not_before = now;
        params.not_after  = now + time::Duration::days(365);
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName,       "Argus CA");
        dn.push(rcgen::DnType::OrganizationName, "argus");
        params.distinguished_name = dn;
        params
    }

    /// Generate a brand-new CA, persist it, and print the PEM for the analyst.
    fn generate() -> Result<Self> {
        let signing_key  = rcgen::KeyPair::generate()
            .map_err(|e| anyhow::anyhow!("CA keygen: {}", e))?;
        let signing_cert = Self::ca_params().self_signed(&signing_key)
            .map_err(|e| anyhow::anyhow!("CA self_signed: {}", e))?;

        let cert_pem = signing_cert.pem();
        let key_pem  = signing_key.serialize_pem();

        if let Some(dir) = ca_cert_path().parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        std::fs::write(ca_cert_path(), &cert_pem)
            .map_err(|e| anyhow::anyhow!("write {}: {}", ca_cert_path().display(), e))?;
        std::fs::write(ca_key_path(), &key_pem)
            .map_err(|e| anyhow::anyhow!("write {}: {}", ca_key_path().display(), e))?;

        println!("{}", "[Argus HTTPS] Generated new CA certificate (install as trusted root):".bright_yellow());
        println!("{}", cert_pem.dimmed());

        let cert_der = CertificateDer::from(signing_cert.der().to_vec());
        Ok(Self { signing_cert, signing_key, cert_der, cache: Default::default() })
    }

    /// Load CA from disk.  The stored CA cert DER is kept for chain inclusion;
    /// a fresh signing `Certificate` is rebuilt from the same params + loaded
    /// key so that leaf certs validate against the installed trusted root.
    fn load() -> Result<Self> {
        let cert_pem_str = std::fs::read_to_string(ca_cert_path())
            .map_err(|e| anyhow::anyhow!("read {}: {}", ca_cert_path().display(), e))?;
        let key_pem_str  = std::fs::read_to_string(ca_key_path())
            .map_err(|e| anyhow::anyhow!("read {}: {}", ca_key_path().display(), e))?;

        let cert_der = rustls_pemfile::certs(&mut cert_pem_str.as_bytes())
            .filter_map(|r| r.ok())
            .next()
            .map(|d| CertificateDer::from(d.to_vec()))
            .ok_or_else(|| anyhow::anyhow!("no cert in {}", ca_cert_path().display()))?;

        let signing_key = rcgen::KeyPair::from_pem(&key_pem_str)
            .map_err(|e| anyhow::anyhow!("CA key: {}", e))?;
        let signing_cert = Self::ca_params().self_signed(&signing_key)
            .map_err(|e| anyhow::anyhow!("CA cert reconstruct: {}", e))?;

        Ok(Self { signing_cert, signing_key, cert_der, cache: Default::default() })
    }

    pub fn load_or_create() -> Result<Arc<Self>> {
        if ca_cert_path().exists() && ca_key_path().exists() {
            match Self::load() {
                Ok(ca) => {
                    println!("{}", format!(
                        "[Argus HTTPS] Using CA certificate from {}",
                        ca_cert_path().display()
                    ).bright_yellow());
                    warn_if_ca_cert_expired(&ca.cert_der);
                    return Ok(Arc::new(ca));
                }
                Err(e) => println!("{}", format!(
                    "[Argus HTTPS] Could not load CA ({e}) — generating a new one"
                ).bright_yellow()),
            }
        }
        Ok(Arc::new(Self::generate()?))
    }

    /// Return (and cache) a per-host `CertifiedKey` signed by this CA.
    fn cert_for_host(&self, host: &str) -> Result<Arc<rustls::sign::CertifiedKey>> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some(ck) = cache.get(host) {
                return Ok(ck.clone());
            }
        }

        let now = time::OffsetDateTime::now_utc();
        let leaf_key = rcgen::KeyPair::generate()
            .map_err(|e| anyhow::anyhow!("leaf keygen: {}", e))?;

        let mut params = rcgen::CertificateParams::new(vec![host.to_string()])
            .map_err(|e| anyhow::anyhow!("leaf params: {}", e))?;
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, host);
        params.distinguished_name = dn;
        params.not_before = now;
        params.not_after  = now + time::Duration::days(7);

        let leaf_cert = params.signed_by(&leaf_key, &self.signing_cert, &self.signing_key)
            .map_err(|e| anyhow::anyhow!("leaf sign: {}", e))?;

        let leaf_cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| anyhow::anyhow!("sign key: {}", e))?;

        let certified = Arc::new(rustls::sign::CertifiedKey::new(
            vec![leaf_cert_der],
            signing_key,
        ));
        self.cache.lock().unwrap().insert(host.to_string(), certified.clone());
        Ok(certified)
    }
}

/// Print a warning if the CA certificate has already expired.
fn warn_if_ca_cert_expired(cert_der: &CertificateDer<'_>) {
    match x509_parser::parse_x509_certificate(cert_der.as_ref()) {
        Ok((_, cert)) => {
            let not_after = cert.validity().not_after.to_datetime();
            if not_after < time::OffsetDateTime::now_utc() {
                println!("{}", format!(
                    "[Argus HTTPS] WARNING: CA certificate at {} EXPIRED (not after: {}). \
                     Delete it and restart Argus to generate a fresh one.",
                    ca_cert_path().display(),
                    not_after.date()
                ).bright_red().bold());
            }
        }
        Err(_) => {}
    }
}

// ---------------------------------------------------------------------------
// Dynamic SNI resolver — picks a per-host cert at handshake time
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ArgusResolvesServerCert {
    ca: Arc<ArgusCA>,
}

impl rustls::server::ResolvesServerCert for ArgusResolvesServerCert {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let host = client_hello.server_name().unwrap_or("argus.local");
        self.ca.cert_for_host(host).ok()
    }
}

// ---------------------------------------------------------------------------
// TLS acceptor / connector builders
// ---------------------------------------------------------------------------

/// A TLS server-certificate verifier that accepts everything.
/// Used when Argus opens an outbound TLS connection to a real server.
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn build_tls_acceptor(ca: Arc<ArgusCA>) -> Result<TlsAcceptor> {
    let resolver = Arc::new(ArgusResolvesServerCert { ca });
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // Force HTTP/1.1 — without this a browser may negotiate HTTP/2 (binary framing).
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Build a TLS connector that skips certificate verification on the upstream
/// side (intentional for a malware analysis / MITM tool).
fn build_tls_connector() -> Result<TlsConnector> {
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

// ---------------------------------------------------------------------------
// HTTP response capture helpers
// ---------------------------------------------------------------------------

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(headers).ok()?;
    for line in s.lines() {
        if line.to_ascii_lowercase().starts_with("content-length:") {
            return line["content-length:".len()..].trim().parse().ok();
        }
    }
    None
}

fn is_chunked(headers: &[u8]) -> bool {
    let s = match std::str::from_utf8(headers) { Ok(s) => s, Err(_) => return false };
    s.lines().any(|l| {
        let lower = l.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    })
}

fn status_has_no_body(headers: &[u8]) -> bool {
    let s = match std::str::from_utf8(headers) { Ok(s) => s, Err(_) => return false };
    let code: u16 = s.split_whitespace().nth(1)
        .and_then(|c| c.parse().ok()).unwrap_or(200);
    code < 200 || code == 204 || code == 304
}

fn parse_next_chunk_size(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
    let slice = &buf[pos..];
    let crlf  = slice.windows(2).position(|w| w == b"\r\n")?;
    let line  = std::str::from_utf8(&slice[..crlf]).ok()?;
    let hex   = line.split(';').next()?.trim();
    let size  = usize::from_str_radix(hex, 16).ok()?;
    Some((size, pos + crlf + 2))
}

// ---------------------------------------------------------------------------
// Generic bidirectional proxy helpers
// ---------------------------------------------------------------------------

/// Read exactly one complete HTTP response from `server_r`, forwarding every
/// byte to `client_w` as it arrives.  Returns immediately when the response
/// body is complete; falls back to waiting for TCP FIN when Content-Length /
/// chunked encoding cannot be determined.
async fn capture_http_response<R1, W1, R2, W2>(
    client_r: &mut R1,
    client_w: &mut W1,
    server_r: &mut R2,
    server_w: &mut W2,
) -> Vec<u8>
where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let mut rsp   = Vec::new();
    let mut s_buf = vec![0u8; 8192];
    let mut c_buf = vec![0u8; 8192];

    // -- Phase 1: buffer until headers complete --------------------------------
    let headers_end = loop {
        if let Some(pos) = find_headers_end(&rsp) { break pos; }
        tokio::select! {
            res = server_r.read(&mut s_buf) => match res {
                Ok(0) | Err(_) => return rsp,
                Ok(n) => {
                    rsp.extend_from_slice(&s_buf[..n]);
                    if client_w.write_all(&s_buf[..n]).await.is_err() { return rsp; }
                }
            },
            res = client_r.read(&mut c_buf) => match res {
                Ok(0) | Err(_) => return rsp,
                Ok(n) => { let _ = server_w.write_all(&c_buf[..n]).await; }
            },
        }
    };

    let header_block = &rsp[..headers_end];
    if status_has_no_body(header_block) { return rsp; }

    if let Some(content_len) = parse_content_length(header_block) {
        // -- Strategy A: Content-Length ----------------------------------------
        let target = headers_end + content_len;
        while rsp.len() < target {
            tokio::select! {
                res = server_r.read(&mut s_buf) => match res {
                    Ok(0) | Err(_) => return rsp,
                    Ok(n) => {
                        rsp.extend_from_slice(&s_buf[..n]);
                        if client_w.write_all(&s_buf[..n]).await.is_err() { return rsp; }
                    }
                },
                res = client_r.read(&mut c_buf) => match res {
                    Ok(0) | Err(_) => return rsp,
                    Ok(n) => { let _ = server_w.write_all(&c_buf[..n]).await; }
                },
            }
        }
        rsp

    } else if is_chunked(header_block) {
        // -- Strategy B: chunked -----------------------------------------------
        let mut parse_pos = headers_end;
        loop {
            let (chunk_size, data_start) = loop {
                if let Some(p) = parse_next_chunk_size(&rsp, parse_pos) { break p; }
                tokio::select! {
                    res = server_r.read(&mut s_buf) => match res {
                        Ok(0) | Err(_) => return rsp,
                        Ok(n) => {
                            rsp.extend_from_slice(&s_buf[..n]);
                            if client_w.write_all(&s_buf[..n]).await.is_err() { return rsp; }
                        }
                    },
                    res = client_r.read(&mut c_buf) => match res {
                        Ok(0) | Err(_) => return rsp,
                        Ok(n) => { let _ = server_w.write_all(&c_buf[..n]).await; }
                    },
                }
            };
            if chunk_size == 0 {
                let need = data_start + 2;
                while rsp.len() < need {
                    tokio::select! {
                        res = server_r.read(&mut s_buf) => match res {
                            Ok(0) | Err(_) => return rsp,
                            Ok(n) => {
                                rsp.extend_from_slice(&s_buf[..n]);
                                if client_w.write_all(&s_buf[..n]).await.is_err() { return rsp; }
                            }
                        },
                        res = client_r.read(&mut c_buf) => match res {
                            Ok(0) | Err(_) => return rsp,
                            Ok(n) => { let _ = server_w.write_all(&c_buf[..n]).await; }
                        },
                    }
                }
                return rsp;
            }
            let need = data_start + chunk_size + 2;
            while rsp.len() < need {
                tokio::select! {
                    res = server_r.read(&mut s_buf) => match res {
                        Ok(0) | Err(_) => return rsp,
                        Ok(n) => {
                            rsp.extend_from_slice(&s_buf[..n]);
                            if client_w.write_all(&s_buf[..n]).await.is_err() { return rsp; }
                        }
                    },
                    res = client_r.read(&mut c_buf) => match res {
                        Ok(0) | Err(_) => return rsp,
                        Ok(n) => { let _ = server_w.write_all(&c_buf[..n]).await; }
                    },
                }
            }
            parse_pos = need;
        }

    } else {
        // -- Strategy C: fallback -- wait for TCP FIN --------------------------
        loop {
            tokio::select! {
                res = server_r.read(&mut s_buf) => match res {
                    Ok(0) | Err(_) => return rsp,
                    Ok(n) => {
                        rsp.extend_from_slice(&s_buf[..n]);
                        if client_w.write_all(&s_buf[..n]).await.is_err() { return rsp; }
                    }
                },
                res = client_r.read(&mut c_buf) => match res {
                    Ok(0) | Err(_) => return rsp,
                    Ok(n) => { let _ = server_w.write_all(&c_buf[..n]).await; }
                },
            }
        }
    }
}

/// Continue proxying bidirectionally until either side closes the connection
/// (transparent keep-alive support).  No bytes are captured.
async fn drain_connection<R1, W1, R2, W2>(
    mut client_r: R1,
    mut client_w: W1,
    mut server_r: R2,
    mut server_w: W2,
)
where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let mut s_buf = vec![0u8; 8192];
    let mut c_buf = vec![0u8; 8192];
    loop {
        tokio::select! {
            res = server_r.read(&mut s_buf) => match res {
                Ok(0) | Err(_) => break,
                Ok(n) => { if client_w.write_all(&s_buf[..n]).await.is_err() { break; } }
            },
            res = client_r.read(&mut c_buf) => match res {
                Ok(0) | Err(_) => break,
                Ok(n) => { if server_w.write_all(&c_buf[..n]).await.is_err() { break; } }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Connection handler (generic: works with plain TCP and TLS streams)
// ---------------------------------------------------------------------------

async fn handle_connection<R, W>(
    mut stream_r: R,
    mut stream_w: W,
    src_addr: SocketAddr,
    config: ListenerConfig,
    conn_table: SharedConnTable,
    request_logger: Option<SharedRequestLogger>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    debug!("handle_connection: {} proto={}", src_addr, if config.use_ssl { "https" } else { "http" });
    let conn_info = if !config.passthrough.is_empty() {
        conn_table.read().ok().and_then(|tbl| tbl.get(&src_addr.port()).cloned())
    } else {
        None
    };

    // -- Read HTTP request -----------------------------------------------------
    let timeout = tokio::time::Duration::from_secs(config.timeout);
    let mut buf = vec![0u8; 8192];
    let n = match tokio::time::timeout(timeout, stream_r.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => { debug!("Read error from {}: {}", src_addr, e); return Ok(()); }
        Err(_)    => { debug!("Connection timeout from {}", src_addr); return Ok(()); }
    };
    if n == 0 { return Ok(()); }

    // -- Process identity + log counter (phase 1: before header parsing) -------
    // These must be computed here so the request is always logged even if
    // parsing later fails (malformed request, HTTP/2 binary frames, etc.).
    let proto = if config.use_ssl { "https" } else { "http" };
    let (log_pid, log_name) = crate::conn_table::get_process_info(&conn_table, src_addr.port());
    // Phase-1 should_log: conn_table / port-based check only (no host/URI yet).
    let mut should_log = !crate::conn_table::should_skip_log(
        &conn_table, src_addr.port(), &config.no_log,
    );
    let log_counter = if should_log {
        request_logger.as_ref().map(|l| l.alloc_counter(log_pid)).unwrap_or(0)
    } else {
        0
    };

    // -- ForwardTo: request ----------------------------------------------------
    let ft_ci = conn_table.read().ok().and_then(|t| t.get(&src_addr.port()).cloned());
    let (ft_dst_ip, ft_dst_port) = ft_ci.as_ref()
        .map(|i| (i.orig_dst_ip.to_string(), i.orig_dst_port))
        .unwrap_or_default();
    let req_bytes = if let Some(ref ft_addr) = config.forward_to {
        let meta = Meta::new(Direction::Request, proto, src_addr,
            &ft_dst_ip, ft_dst_port, &log_name, log_pid);
        forward_to::call(ft_addr, &meta, &buf[..n]).await
    } else {
        buf[..n].to_vec()
    };
    let req_slice = &req_bytes;

    // -- Log request (always, even when parsing fails below) -------------------
    if should_log {
        if let Some(ref logger) = request_logger {
            if let Err(e) = logger.log(log_pid, &log_name, proto, log_counter, "req", req_slice) {
                warn!("Request log write failed: {}", e);
            }
        }
    }

    // -- Parse request line and headers ----------------------------------------
    let request = String::from_utf8_lossy(req_slice);
    let lines: Vec<&str> = request.lines().collect();
    if lines.is_empty() { return Ok(()); }

    let parts: Vec<&str> = lines[0].splitn(3, ' ').collect();
    if parts.len() < 2 { return Ok(()); }
    let method = parts[0];
    let uri    = parts[1];

    let mut host = String::new();
    for line in &lines[1..] {
        if line.is_empty() { break; }
        let lower = line.to_lowercase();
        if lower.starts_with("host:") { host = line[5..].trim().to_string(); }
    }

    // -- Phase-2 should_log: refine with host/URI domain matching --------------
    // Only affects response logging; the request is already logged above.
    if should_log && !config.no_log.is_empty() {
        if matches_passthrough_domain(&config.no_log, &host, uri) {
            should_log = false;
        }
    }

    // -- Passthrough destination -----------------------------------------------
    let passthrough_dst: Option<String> = if !config.passthrough.is_empty() {
        if let Some(ref info) = conn_info {
            if info.matches_passthrough_list(&config.passthrough) {
                Some(info.orig_dst_addr())
            } else if matches_passthrough_domain(&config.passthrough, &host, uri) {
                Some(info.orig_dst_addr())
            } else {
                None
            }
        } else {
            debug!("Passthrough: no conn_table entry for port {}, falling back to intercept", src_addr.port());
            None
        }
    } else {
        None
    };

    // -- ForwardTo: response meta (used by both passthrough and intercept paths)
    let ft_meta_rsp = Meta::new(Direction::Response, proto, src_addr,
        &ft_dst_ip, ft_dst_port, &log_name, log_pid);

    // -- Passthrough path ------------------------------------------------------
    if let Some(ref dst_addr) = passthrough_dst {
        let label = conn_info.as_ref().map(|info| {
            if info.matches_passthrough_list(&config.passthrough) {
                format!("[{}]", info.process_label())
            } else {
                format!("(Host: {})", host)
            }
        }).unwrap_or_default();

        println!(
            "{} {} -> {} {} {}",
            format!("[{}]", config.name).bright_magenta(),
            src_addr.to_string().yellow(),
            dst_addr.bright_white(),
            "PASSTHROUGH".bright_blue().bold(),
            label.dimmed(),
        );

        match tokio::net::TcpStream::connect(dst_addr).await {
            Ok(tcp_remote) => {
                if config.use_ssl {
                    // Upgrade outbound connection to TLS (MITM passthrough).
                    let sni_host = host.split(':').next().filter(|h| !h.is_empty())
                        .unwrap_or_else(|| dst_addr.split(':').next().unwrap_or("unknown"));
                    match ServerName::try_from(sni_host.to_string()) {
                        Ok(server_name) => {
                            match build_tls_connector() {
                                Ok(connector) => {
                                    match connector.connect(server_name, tcp_remote).await {
                                        Ok(tls_remote) => {
                                            if let Err(e) = passthrough_and_log(
                                                tls_remote, &mut stream_r, &mut stream_w,
                                                req_slice, should_log,
                                                &request_logger, log_pid, &log_name, proto, log_counter,
                                                &config.forward_to, ft_meta_rsp.clone(),
                                            ).await {
                                                debug!("TLS passthrough error: {}", e);
                                            }
                                        }
                                        Err(e) => warn!("TLS handshake to {}: {}", dst_addr, e),
                                    }
                                }
                                Err(e) => warn!("build_tls_connector: {}", e),
                            }
                        }
                        Err(_) => warn!("Invalid SNI hostname: {}", sni_host),
                    }
                } else {
                    // Plain TCP passthrough.
                    if let Err(e) = passthrough_and_log(
                        tcp_remote, &mut stream_r, &mut stream_w,
                        req_slice, should_log,
                        &request_logger, log_pid, &log_name, proto, log_counter,
                        &config.forward_to, ft_meta_rsp.clone(),
                    ).await {
                        debug!("TCP passthrough error: {}", e);
                    }
                }
            }
            Err(e) => warn!("Passthrough: could not connect to {}: {}", dst_addr, e),
        }
        return Ok(());
    }

    // -- Intercept mode --------------------------------------------------------
    log_http(method, uri, &host, &src_addr, &config);

    let mime_type    = get_mime_type(uri);
    let content_type = match mime_type {
        "application/xml" => "application/xml",
        _                 => "text/html; charset=utf-8",
    };
    let body = fake_response_body(uri, mime_type);
    let date = Local::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

    let mut response = format!(
        "HTTP/1.1 200 OK\r\nServer: Argus/1.0\r\nDate: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        date, content_type, body.len()
    ).into_bytes();

    if method != "HEAD" {
        response.extend_from_slice(&body);
    }

    // -- ForwardTo: response ---------------------------------------------------
    let response = if let Some(ref ft_addr) = config.forward_to {
        forward_to::call(ft_addr, &ft_meta_rsp, &response).await
    } else {
        response
    };

    let _ = stream_w.write_all(&response).await;
    let _ = stream_w.flush().await;

    if should_log {
        if let Some(ref logger) = request_logger {
            if let Err(e) = logger.log(log_pid, &log_name, proto, log_counter, "rsp", &response) {
                warn!("Response log write failed: {}", e);
            }
        }
    }

    Ok(())
}

/// Helper: write `req_bytes` to `remote`, then capture/log the response, then
/// drain for keep-alive.  Extracted to avoid code duplication between the
/// plain-TCP and TLS passthrough branches.
///
/// When `ft_addr` is `Some`, the response is first buffered (not streamed),
/// passed through the ForwardTo endpoint, and then sent to the client.
/// This ensures ForwardTo sees passthrough traffic too.
async fn passthrough_and_log<S, R, W>(
    remote: S,
    client_r: &mut R,
    client_w: &mut W,
    req_bytes: &[u8],
    should_log: bool,
    request_logger: &Option<SharedRequestLogger>,
    log_pid: u32,
    log_name: &str,
    proto: &str,
    log_counter: u32,
    ft_addr: &Option<String>,
    ft_meta_rsp: Meta,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut s_r, mut s_w) = tokio::io::split(remote);

    if let Err(e) = s_w.write_all(req_bytes).await {
        warn!("Forward: write error to remote: {}", e);
        return Ok(());
    }

    if should_log || ft_addr.is_some() {
        // Buffer the full response without streaming it to the client yet —
        // we need to optionally pass it through ForwardTo first.
        let mut sink = tokio::io::sink();
        let rsp_bytes = capture_http_response(client_r, &mut sink, &mut s_r, &mut s_w).await;

        // Apply ForwardTo to the (possibly buffered) response.
        let rsp_bytes = if let Some(ref addr) = ft_addr {
            forward_to::call(addr, &ft_meta_rsp, &rsp_bytes).await
        } else {
            rsp_bytes
        };

        // Send (possibly modified) response to client.
        let _ = client_w.write_all(&rsp_bytes).await;

        // Log the final response bytes.
        if should_log {
            if let Some(ref logger) = request_logger {
                if !rsp_bytes.is_empty() {
                    if let Err(e) = logger.log(log_pid, log_name, proto, log_counter, "rsp", &rsp_bytes) {
                        warn!("Response log write failed: {}", e);
                    }
                }
            }
        }
    }

    drain_connection(client_r, client_w, s_r, s_w).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Listener entry point
// ---------------------------------------------------------------------------

pub async fn start(
    config: ListenerConfig,
    bind_addr: String,
    conn_table: SharedConnTable,
    request_logger: Option<SharedRequestLogger>,
) -> Result<()> {
    let addr     = format!("{}:{}", bind_addr, config.listener_port);
    let listener = TcpListener::bind(&addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind HTTP listener on {}: {}", addr, e))?;

    // Build TLS acceptor once if HTTPS mode (CA is created/loaded here).
    let tls_acceptor: Option<TlsAcceptor> = if config.use_ssl {
        let ca = ArgusCA::load_or_create()?;
        Some(build_tls_acceptor(ca)?)
    } else {
        None
    };

    let proto = if config.use_ssl { "HTTPS" } else { "HTTP" };
    debug!("{} listener started on {}", proto, addr);

    loop {
        match listener.accept().await {
            Ok((tcp_stream, src_addr)) => {
                let cfg        = config.clone();
                let ct         = conn_table.clone();
                let rl         = request_logger.clone();
                let acceptor   = tls_acceptor.clone();

                tokio::spawn(async move {
                    if let Some(tls) = acceptor {
                        // HTTPS: perform TLS handshake, then handle plaintext.
                        match tls.accept(tcp_stream).await {
                            Ok(tls_stream) => {
                                let (r, w) = tokio::io::split(tls_stream);
                                if let Err(e) = handle_connection(r, w, src_addr, cfg, ct, rl).await {
                                    debug!("HTTPS connection error: {}", e);
                                }
                            }
                            Err(e) => debug!("TLS handshake failed from {}: {}", src_addr, e),
                        }
                    } else {
                        // Plain HTTP.
                        let (r, w) = tokio::io::split(tcp_stream);
                        if let Err(e) = handle_connection(r, w, src_addr, cfg, ct, rl).await {
                            debug!("HTTP connection error: {}", e);
                        }
                    }
                });
            }
            Err(e) => warn!("Accept error: {}", e),
        }
    }
}
