//! DNS listener — intercepts DNS queries and returns fake responses

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::{info, warn, debug, error};
use chrono::Local;
use colored::*;

use crate::config::ListenerConfig;

// DNS constants
const DNS_QR_RESPONSE: u16 = 0x8000;
const DNS_AA: u16 = 0x0400;
const DNS_RA: u16 = 0x0080;
const DNS_OPCODE_QUERY: u16 = 0;

// Query types
const QTYPE_A: u16 = 1;
const QTYPE_NS: u16 = 2;
const QTYPE_CNAME: u16 = 5;
const QTYPE_MX: u16 = 15;
const QTYPE_AAAA: u16 = 28;
const QTYPE_TXT: u16 = 16;
const QTYPE_ANY: u16 = 255;

#[derive(Debug)]
struct DnsQuestion {
    name: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug)]
struct DnsHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

fn parse_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut name_parts = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut jump_count = 0;
    let mut end_pos = offset;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len = data[pos] as usize;

        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }

        // Check for compression pointer
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            if !jumped {
                end_pos = pos + 2;
            }
            let ptr = (((data[pos] as usize) & 0x3F) << 8) | (data[pos + 1] as usize);
            pos = ptr;
            jumped = true;
            jump_count += 1;
            if jump_count > 10 {
                return None; // Prevent infinite loops
            }
            continue;
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
        name_parts.push(label);
        pos += len;
    }

    let name = name_parts.join(".");
    Some((name, end_pos))
}

fn parse_dns_request(data: &[u8]) -> Option<(DnsHeader, Vec<DnsQuestion>)> {
    if data.len() < 12 {
        return None;
    }

    let header = DnsHeader {
        id: u16::from_be_bytes([data[0], data[1]]),
        flags: u16::from_be_bytes([data[2], data[3]]),
        qdcount: u16::from_be_bytes([data[4], data[5]]),
        ancount: u16::from_be_bytes([data[6], data[7]]),
        nscount: u16::from_be_bytes([data[8], data[9]]),
        arcount: u16::from_be_bytes([data[10], data[11]]),
    };

    // Only handle queries (QR bit = 0)
    if header.flags & 0x8000 != 0 {
        return None;
    }

    let mut questions = Vec::new();
    let mut offset = 12;

    for _ in 0..header.qdcount {
        let (name, new_offset) = parse_dns_name(data, offset)?;
        offset = new_offset;

        if offset + 4 > data.len() {
            return None;
        }

        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;

        questions.push(DnsQuestion { name, qtype, qclass });
    }

    Some((header, questions))
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for part in name.split('.') {
        if part.is_empty() {
            continue;
        }
        encoded.push(part.len() as u8);
        encoded.extend_from_slice(part.as_bytes());
    }
    encoded.push(0); // Root label
    encoded
}

fn build_dns_response(
    header: &DnsHeader,
    questions: &[DnsQuestion],
    config: &ListenerConfig,
) -> Vec<u8> {
    let mut response = Vec::new();

    // Response flags
    let flags = DNS_QR_RESPONSE | DNS_AA | DNS_RA;

    let answer_count = questions.len() as u16;

    // Header
    response.extend_from_slice(&header.id.to_be_bytes());
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&(questions.len() as u16).to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&answer_count.to_be_bytes());             // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes());                     // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes());                     // ARCOUNT

    // Questions (echo back)
    for q in questions {
        response.extend_from_slice(&encode_dns_name(&q.name));
        response.extend_from_slice(&q.qtype.to_be_bytes());
        response.extend_from_slice(&q.qclass.to_be_bytes());
    }

    // Answers
    for q in questions {
        let name_encoded = encode_dns_name(&q.name);

        match q.qtype {
            QTYPE_A => {
                let ip_str = config.response_a.as_deref().unwrap_or("127.0.0.1");
                let ip: std::net::Ipv4Addr = ip_str.parse().unwrap_or(std::net::Ipv4Addr::LOCALHOST);
                let octets = ip.octets();

                response.extend_from_slice(&name_encoded);
                response.extend_from_slice(&QTYPE_A.to_be_bytes());  // Type A
                response.extend_from_slice(&1u16.to_be_bytes());      // Class IN
                response.extend_from_slice(&60u32.to_be_bytes());     // TTL 60s
                response.extend_from_slice(&4u16.to_be_bytes());      // RDLENGTH
                response.extend_from_slice(&octets);                   // RDATA
            }
            QTYPE_MX => {
                let mx_str = config.response_mx.as_deref().unwrap_or("mail.argus.local");
                let mx_encoded = encode_dns_name(mx_str);

                response.extend_from_slice(&name_encoded);
                response.extend_from_slice(&QTYPE_MX.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&60u32.to_be_bytes());
                let rdlen = (2 + mx_encoded.len()) as u16;
                response.extend_from_slice(&rdlen.to_be_bytes());
                response.extend_from_slice(&10u16.to_be_bytes()); // Preference
                response.extend_from_slice(&mx_encoded);
            }
            QTYPE_TXT => {
                let txt = config.response_txt.as_deref().unwrap_or("ARGUS");
                let txt_bytes = txt.as_bytes();

                response.extend_from_slice(&name_encoded);
                response.extend_from_slice(&QTYPE_TXT.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&60u32.to_be_bytes());
                let rdlen = (1 + txt_bytes.len()) as u16;
                response.extend_from_slice(&rdlen.to_be_bytes());
                response.push(txt_bytes.len() as u8);
                response.extend_from_slice(txt_bytes);
            }
            QTYPE_AAAA => {
                // Return loopback IPv6
                let ipv6 = std::net::Ipv6Addr::LOCALHOST;
                response.extend_from_slice(&name_encoded);
                response.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&60u32.to_be_bytes());
                response.extend_from_slice(&16u16.to_be_bytes());
                response.extend_from_slice(&ipv6.octets());
            }
            _ => {
                // For unknown types, return A record
                let ip_str = config.response_a.as_deref().unwrap_or("127.0.0.1");
                let ip: std::net::Ipv4Addr = ip_str.parse().unwrap_or(std::net::Ipv4Addr::LOCALHOST);
                let octets = ip.octets();

                response.extend_from_slice(&name_encoded);
                response.extend_from_slice(&QTYPE_A.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&60u32.to_be_bytes());
                response.extend_from_slice(&4u16.to_be_bytes());
                response.extend_from_slice(&octets);
            }
        }
    }

    response
}

fn qtype_to_str(qtype: u16) -> &'static str {
    match qtype {
        QTYPE_A => "A",
        QTYPE_NS => "NS",
        QTYPE_CNAME => "CNAME",
        QTYPE_MX => "MX",
        QTYPE_TXT => "TXT",
        QTYPE_AAAA => "AAAA",
        QTYPE_ANY => "ANY",
        _ => "UNKNOWN",
    }
}

fn log_dns_query(question: &DnsQuestion, response_val: &str, src_addr: &SocketAddr, config: &ListenerConfig) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "{} {} {} {} {} {} {} {} {}",
        format!("[{}]", timestamp).dimmed(),
        "DNS ".bright_blue().bold(),
        format!("[{}]", config.name).bright_magenta(),
        format!("{}", src_addr).yellow(),
        "→".dimmed(),
        qtype_to_str(question.qtype).bright_cyan(),
        question.name.bright_white().bold(),
        "→".dimmed(),
        response_val.bright_green()
    );
}

/// Start the DNS listener (UDP)
pub async fn start(config: ListenerConfig, bind_addr: String) -> Result<()> {
    let addr = format!("{}:{}", bind_addr, config.port);
    let socket = UdpSocket::bind(&addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind DNS listener on {}: {}", addr, e))?;

    debug!("DNS listener started on {}", addr);

    let mut buf = vec![0u8; 4096];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src_addr)) => {
                let data = buf[..n].to_vec();
                let cfg = config.clone();

                if let Some((header, questions)) = parse_dns_request(&data) {
                    // Log queries
                    for q in &questions {
                        let response_val = match q.qtype {
                            QTYPE_A => cfg.response_a.as_deref().unwrap_or("127.0.0.1").to_string(),
                            QTYPE_MX => cfg.response_mx.as_deref().unwrap_or("mail.argus.local").to_string(),
                            QTYPE_TXT => cfg.response_txt.as_deref().unwrap_or("ARGUS").to_string(),
                            QTYPE_AAAA => "::1".to_string(),
                            _ => cfg.response_a.as_deref().unwrap_or("127.0.0.1").to_string(),
                        };
                        log_dns_query(q, &response_val, &src_addr, &cfg);
                    }

                    let response = build_dns_response(&header, &questions, &cfg);
                    if let Err(e) = socket.send_to(&response, src_addr).await {
                        warn!("Failed to send DNS response: {}", e);
                    }
                } else {
                    debug!("Failed to parse DNS request from {}", src_addr);
                }
            }
            Err(e) => {
                warn!("DNS recv error: {}", e);
            }
        }
    }
}
