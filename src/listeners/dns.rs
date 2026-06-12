//! DNS listener — intercepts DNS queries and returns fake responses, with
//! optional passthrough to the real resolver.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{info, warn, debug};

use crate::config::ListenerConfig;
use crate::conn_table::SharedConnTable;
use crate::forward_to::{self, Direction, Meta};
use crate::request_logger::SharedRequestLogger;

const DNS_QR_RESPONSE: u16 = 0x8000;
const DNS_AA: u16 = 0x0400;
const DNS_RA: u16 = 0x0080;

const QTYPE_A:    u16 = 1;
const QTYPE_NS:   u16 = 2;
const QTYPE_CNAME:u16 = 5;
const QTYPE_MX:   u16 = 15;
const QTYPE_TXT:  u16 = 16;
const QTYPE_AAAA: u16 = 28;
const QTYPE_ANY:  u16 = 255;

#[derive(Debug)]
struct DnsQuestion {
    name:   String,
    qtype:  u16,
    qclass: u16,
}

struct DnsHeader {
    id:      u16,
    flags:   u16,
    qdcount: u16,
}

fn parse_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut parts   = Vec::new();
    let mut pos     = offset;
    let mut jumped  = false;
    let mut end_pos = offset;
    let mut jumps   = 0;

    loop {
        if pos >= data.len() { return None; }
        let len = data[pos] as usize;
        if len == 0 {
            if !jumped { end_pos = pos + 1; }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() { return None; }
            if !jumped { end_pos = pos + 2; }
            let ptr = (((data[pos] as usize) & 0x3F) << 8) | (data[pos + 1] as usize);
            pos = ptr;
            jumped = true;
            jumps += 1;
            if jumps > 10 { return None; }
            continue;
        }
        pos += 1;
        if pos + len > data.len() { return None; }
        parts.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }
    Some((parts.join("."), end_pos))
}

fn parse_dns_request(data: &[u8]) -> Option<(DnsHeader, Vec<DnsQuestion>)> {
    if data.len() < 12 { return None; }
    let header = DnsHeader {
        id:      u16::from_be_bytes([data[0], data[1]]),
        flags:   u16::from_be_bytes([data[2], data[3]]),
        qdcount: u16::from_be_bytes([data[4], data[5]]),
    };
    if header.flags & 0x8000 != 0 { return None; } // not a query
    let mut questions = Vec::new();
    let mut offset = 12;
    for _ in 0..header.qdcount {
        let (name, new_off) = parse_dns_name(data, offset)?;
        offset = new_off;
        if offset + 4 > data.len() { return None; }
        let qtype  = u16::from_be_bytes([data[offset],     data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
        questions.push(DnsQuestion { name, qtype, qclass });
    }
    Some((header, questions))
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for part in name.split('.') {
        if part.is_empty() { continue; }
        out.push(part.len() as u8);
        out.extend_from_slice(part.as_bytes());
    }
    out.push(0);
    out
}

fn build_dns_response(header: &DnsHeader, questions: &[DnsQuestion], config: &ListenerConfig) -> Vec<u8> {
    let flags = DNS_QR_RESPONSE | DNS_AA | DNS_RA;
    let mut rsp = Vec::new();
    rsp.extend_from_slice(&header.id.to_be_bytes());
    rsp.extend_from_slice(&flags.to_be_bytes());
    rsp.extend_from_slice(&(questions.len() as u16).to_be_bytes()); // QDCOUNT
    rsp.extend_from_slice(&(questions.len() as u16).to_be_bytes()); // ANCOUNT
    rsp.extend_from_slice(&0u16.to_be_bytes());                      // NSCOUNT
    rsp.extend_from_slice(&0u16.to_be_bytes());                      // ARCOUNT
    // Echo questions
    for q in questions {
        rsp.extend_from_slice(&encode_dns_name(&q.name));
        rsp.extend_from_slice(&q.qtype.to_be_bytes());
        rsp.extend_from_slice(&q.qclass.to_be_bytes());
    }
    // Answers
    for q in questions {
        let name_enc = encode_dns_name(&q.name);
        match q.qtype {
            QTYPE_A | QTYPE_ANY => {
                let ip: Ipv4Addr = config.response_a.as_deref().unwrap_or("127.0.0.1")
                    .parse().unwrap_or(Ipv4Addr::LOCALHOST);
                rsp.extend_from_slice(&name_enc);
                rsp.extend_from_slice(&QTYPE_A.to_be_bytes());
                rsp.extend_from_slice(&1u16.to_be_bytes()); // IN
                rsp.extend_from_slice(&60u32.to_be_bytes());
                rsp.extend_from_slice(&4u16.to_be_bytes());
                rsp.extend_from_slice(&ip.octets());
            }
            QTYPE_AAAA => {
                rsp.extend_from_slice(&name_enc);
                rsp.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
                rsp.extend_from_slice(&1u16.to_be_bytes());
                rsp.extend_from_slice(&60u32.to_be_bytes());
                rsp.extend_from_slice(&16u16.to_be_bytes());
                rsp.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
            }
            QTYPE_MX => {
                let mx = config.response_mx.as_deref().unwrap_or("mail.argus.local");
                let mx_enc = encode_dns_name(mx);
                rsp.extend_from_slice(&name_enc);
                rsp.extend_from_slice(&QTYPE_MX.to_be_bytes());
                rsp.extend_from_slice(&1u16.to_be_bytes());
                rsp.extend_from_slice(&60u32.to_be_bytes());
                rsp.extend_from_slice(&((2 + mx_enc.len()) as u16).to_be_bytes());
                rsp.extend_from_slice(&10u16.to_be_bytes()); // preference
                rsp.extend_from_slice(&mx_enc);
            }
            QTYPE_TXT => {
                let txt = config.response_txt.as_deref().unwrap_or("ARGUS");
                let tb  = txt.as_bytes();
                rsp.extend_from_slice(&name_enc);
                rsp.extend_from_slice(&QTYPE_TXT.to_be_bytes());
                rsp.extend_from_slice(&1u16.to_be_bytes());
                rsp.extend_from_slice(&60u32.to_be_bytes());
                rsp.extend_from_slice(&((1 + tb.len()) as u16).to_be_bytes());
                rsp.push(tb.len() as u8);
                rsp.extend_from_slice(tb);
            }
            _ => {
                // Unknown type: answer with A record
                let ip: Ipv4Addr = config.response_a.as_deref().unwrap_or("127.0.0.1")
                    .parse().unwrap_or(Ipv4Addr::LOCALHOST);
                rsp.extend_from_slice(&name_enc);
                rsp.extend_from_slice(&QTYPE_A.to_be_bytes());
                rsp.extend_from_slice(&1u16.to_be_bytes());
                rsp.extend_from_slice(&60u32.to_be_bytes());
                rsp.extend_from_slice(&4u16.to_be_bytes());
                rsp.extend_from_slice(&ip.octets());
            }
        }
    }
    rsp
}

fn qtype_to_str(qtype: u16) -> &'static str {
    match qtype {
        QTYPE_A    => "A",
        QTYPE_NS   => "NS",
        QTYPE_CNAME => "CNAME",
        QTYPE_MX   => "MX",
        QTYPE_TXT  => "TXT",
        QTYPE_AAAA => "AAAA",
        QTYPE_ANY  => "ANY",
        _          => "UNKNOWN",
    }
}

/// Returns the fake response value string for a given query type (for logging).
fn fake_response_value(qtype: u16, config: &ListenerConfig) -> String {
    match qtype {
        QTYPE_A | QTYPE_ANY => config.response_a.as_deref().unwrap_or("127.0.0.1").to_string(),
        QTYPE_AAAA          => "::1".to_string(),
        QTYPE_MX            => config.response_mx.as_deref().unwrap_or("mail.argus.local").to_string(),
        QTYPE_TXT           => config.response_txt.as_deref().unwrap_or("ARGUS").to_string(),
        _                   => config.response_a.as_deref().unwrap_or("127.0.0.1").to_string(),
    }
}

/// Returns `true` if `domain` matches any domain-pattern entry in `list`.
///
/// Entries that are pure numbers (PIDs) or IP addresses are skipped — those are
/// handled by `ConnInfo::matches_passthrough_list`.  Everything else is treated
/// as a case-insensitive pattern: plain names match exactly or as a suffix
/// (subdomain), and regex syntax is supported for wildcard patterns.
fn domain_matches_passthrough(domain: &str, list: &[String]) -> bool {
    for entry in list {
        let entry = entry.trim();
        if entry.is_empty()                        { continue; }
        if entry.parse::<u32>().is_ok()            { continue; }
        if entry.parse::<Ipv4Addr>().is_ok()       { continue; }
        if entry.parse::<Ipv6Addr>().is_ok()       { continue; }

        // Strip scheme / path to obtain just the host pattern.
        let pat = entry
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let pat = pat.split('/').next().unwrap_or(pat);

        let d = domain.to_lowercase();
        let p = pat.to_lowercase();

        // Exact match or subdomain (e.g. "example.com" matches "api.example.com").
        if d == p || d.ends_with(&format!(".{}", p)) {
            return true;
        }

        // Regex match (e.g. ".*\\.microsoft\\.com").
        if let Ok(re) = regex::Regex::new(&format!("(?i)^{}", entry)) {
            if re.is_match(domain) {
                return true;
            }
        }
    }
    false
}

/// Forward a raw DNS query to `dst_ip:dst_port` and return the real response.
/// Returns `None` on timeout or network error.
async fn passthrough_dns(query: &[u8], dst_ip: IpAddr, dst_port: u16, timeout_secs: u64) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let dst_addr = match dst_ip {
        IpAddr::V4(ip) => format!("{}:{}", ip, dst_port),
        IpAddr::V6(ip) => format!("[{}]:{}", ip, dst_port),
    };
    socket.connect(&dst_addr).await.ok()?;
    socket.send(query).await.ok()?;
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        socket.recv(&mut buf),
    ).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Build the human-readable request log line.
fn format_req_log(src_addr: &SocketAddr, proc_label: &str, questions: &[DnsQuestion]) -> String {
    let mut s = format!("DNS QUERY from {} [{}]\n", src_addr, proc_label);
    for q in questions {
        s.push_str(&format!("  {} {}\n", qtype_to_str(q.qtype), q.name));
    }
    s
}

/// Build the human-readable fake-response log.
fn format_fake_rsp_log(questions: &[DnsQuestion], config: &ListenerConfig) -> String {
    let mut s = String::from("DNS RESPONSE [FAKE]\n");
    for q in questions {
        s.push_str(&format!(
            "  {} {} -> {}\n",
            qtype_to_str(q.qtype),
            q.name,
            fake_response_value(q.qtype, config),
        ));
    }
    s
}

pub async fn start(
    config: ListenerConfig,
    bind_addr: String,
    conn_table: SharedConnTable,
    request_logger: Option<SharedRequestLogger>,
) -> Result<()> {
    let addr   = format!("{}:{}", bind_addr, config.listener_port);
    let socket = UdpSocket::bind(&addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind DNS listener on {}: {}", addr, e))?;

    debug!("DNS listener started on {}", addr);

    let mut buf = vec![0u8; 4096];

    loop {
        let (n, src_addr) = match socket.recv_from(&mut buf).await {
            Ok(v)  => v,
            Err(e) => { warn!("DNS recv error: {}", e); continue; }
        };

        let raw_data = buf[..n].to_vec();
        let cfg  = config.clone();
        let ft_request_id = forward_to::next_request_id();

        // ── ForwardTo: request ────────────────────────────────────────────
        let data = if let Some(ref ft_addr) = cfg.forward_to {
            let (pid, proc_name) = crate::conn_table::get_process_info(&conn_table, src_addr.port());
            let ci = conn_table.read().ok().and_then(|t| t.get(&src_addr.port()).cloned());
            let (dst_ip, dst_port) = ci.as_ref()
                .map(|i| (i.orig_dst_ip.to_string(), i.orig_dst_port))
                .unwrap_or_default();
            let meta = Meta::new(ft_request_id, Direction::Request, "dns", src_addr, dst_ip, dst_port, proc_name, pid);
            forward_to::call(ft_addr, &meta, &raw_data).await
        } else {
            raw_data
        };

        let (header, questions) = match parse_dns_request(&data) {
            Some(v) => v,
            None    => { debug!("Failed to parse DNS request from {}", src_addr); continue; }
        };

        // ── Logging setup ─────────────────────────────────────────────────────
        let should_log = !crate::conn_table::should_skip_log(
            &conn_table, src_addr.port(), &config.no_log,
        );
        let (pid, proc_name) = crate::conn_table::get_process_info(&conn_table, src_addr.port());
        let log_counter = if should_log {
            request_logger.as_ref().map(|l| l.alloc_counter(pid)).unwrap_or(0)
        } else {
            0
        };

        // Look up the original destination for passthrough.
        let conn_info = conn_table.read().ok()
            .and_then(|tbl| tbl.get(&src_addr.port()).cloned());

        let proc_label = conn_info.as_ref()
            .map(|i| i.process_label())
            .unwrap_or_else(|| proc_name.clone());

        // ── Passthrough check ─────────────────────────────────────────────────
        let is_passthrough = !cfg.passthrough.is_empty() && {
            let by_process = conn_info.as_ref()
                .map(|i| i.matches_passthrough_list(&cfg.passthrough))
                .unwrap_or(false);
            let by_domain = questions.iter()
                .any(|q| domain_matches_passthrough(&q.name, &cfg.passthrough));
            by_process || by_domain
        };

        if is_passthrough {
            if let Some(ref info) = conn_info {
                let q0 = &questions[0];
                info!(
                    "DNS  [{}] {} [{}] {} {} → PASSTHROUGH {}:{}",
                    cfg.name, src_addr, proc_label,
                    qtype_to_str(q0.qtype), q0.name,
                    info.orig_dst_ip, info.orig_dst_port,
                );
                match passthrough_dns(&data, info.orig_dst_ip, info.orig_dst_port, cfg.timeout).await {
                    Some(real_rsp) => {
                        if should_log {
                            if let Some(ref logger) = request_logger {
                                let req_text = format_req_log(&src_addr, &proc_label, &questions);
                                let rsp_text = format!(
                                    "DNS RESPONSE [PASSTHROUGH -> {}:{}]\n{} bytes\n",
                                    info.orig_dst_ip, info.orig_dst_port, real_rsp.len(),
                                );
                                if let Err(e) = logger.log(pid, &proc_name, "dns", log_counter, "req", req_text.as_bytes()) {
                                    warn!("DNS request log write failed: {}", e);
                                }
                                if let Err(e) = logger.log(pid, &proc_name, "dns", log_counter, "rsp", rsp_text.as_bytes()) {
                                    warn!("DNS response log write failed: {}", e);
                                }
                            }
                        }
                        if let Err(e) = socket.send_to(&real_rsp, src_addr).await {
                            warn!("DNS passthrough send failed: {}", e);
                        }
                    }
                    None => {
                        warn!(
                            "DNS  [{}] passthrough to {}:{} timed out — falling back to fake response",
                            cfg.name, info.orig_dst_ip, info.orig_dst_port,
                        );
                        let fake = build_dns_response(&header, &questions, &cfg);
                        let _ = socket.send_to(&fake, src_addr).await;
                    }
                }
            } else {
                // No conn_table entry — forward as fake and log anyway.
                debug!("DNS passthrough: no conn_table entry for port {}, using fake", src_addr.port());
                let fake = build_dns_response(&header, &questions, &cfg);
                if should_log {
                    if let Some(ref logger) = request_logger {
                        let req_text = format_req_log(&src_addr, &proc_label, &questions);
                        let rsp_text = format_fake_rsp_log(&questions, &cfg);
                        if let Err(e) = logger.log(pid, &proc_name, "dns", log_counter, "req", req_text.as_bytes()) {
                            warn!("DNS request log write failed: {}", e);
                        }
                        if let Err(e) = logger.log(pid, &proc_name, "dns", log_counter, "rsp", rsp_text.as_bytes()) {
                            warn!("DNS response log write failed: {}", e);
                        }
                    }
                }
                let _ = socket.send_to(&fake, src_addr).await;
            }
            continue;
        }

        // ── Fake response ─────────────────────────────────────────────────────
        for q in &questions {
            info!(
                "DNS  [{}] {} [{}] {} {} -> {}",
                cfg.name, src_addr, proc_label,
                qtype_to_str(q.qtype), q.name,
                fake_response_value(q.qtype, &cfg),
            );
        }

        let fake = build_dns_response(&header, &questions, &cfg);

        // ── ForwardTo: response ───────────────────────────────────────────
        let response = if let Some(ref ft_addr) = cfg.forward_to {
            let meta = Meta::new(ft_request_id, Direction::Response, "dns", src_addr,
                &proc_label, 53, &proc_name, pid);
            forward_to::call(ft_addr, &meta, &fake).await
        } else {
            fake
        };

        if should_log {
            if let Some(ref logger) = request_logger {
                let req_text = format_req_log(&src_addr, &proc_label, &questions);
                let rsp_text = format_fake_rsp_log(&questions, &cfg);
                if let Err(e) = logger.log(pid, &proc_name, "dns", log_counter, "req", req_text.as_bytes()) {
                    warn!("DNS request log write failed: {}", e);
                }
                if let Err(e) = logger.log(pid, &proc_name, "dns", log_counter, "rsp", rsp_text.as_bytes()) {
                    warn!("DNS response log write failed: {}", e);
                }
            }
        }

        if let Err(e) = socket.send_to(&response, src_addr).await {
            warn!("Failed to send DNS response: {}", e);
        }
    }
}
