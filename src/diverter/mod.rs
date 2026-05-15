//! Diverter — transparent bidirectional NAT using WinDivert
//!
//! ## How the NAT works
//!
//! **Outbound (app → external host)**
//!   Rewrite *both* src and dst to 127.0.0.1.
//!   Store a connection entry: app_src_port → { orig_src_ip, orig_dst_ip }.
//!   Re-inject outbound → Windows routes the packet via loopback →
//!   the local Argus listener receives it.
//!
//! **Loopback response (listener → app)**
//!   The listener's reply has src=127.0.0.1:port and dst=127.0.0.1:app_port.
//!   WinDivert captures it.  Restore:
//!     src  → orig_dst_ip (the external host the app wanted)
//!     dst  → orig_src_ip (the app's real IP)
//!   Re-inject → the app's TCP stack sees the expected addresses.
//!
//! ## Process identification
//!
//! For every *new* outbound connection WinDivert resolves the originating
//! process by calling GetExtendedTcpTable / GetExtendedUdpTable (maps
//! source port → PID) and then QueryFullProcessImageNameW (PID → path).
//! This is logged alongside the connection details.

use std::collections::HashMap;

use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};
use windivert::prelude::*;
use windivert_sys::ChecksumFlags;

use crate::config::ArgusConfig;
use crate::conn_table::{ConnInfo, SharedConnTable};

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const RECV_BUF: usize = 65535;

/// Per-connection mapping stored when an outbound packet is redirected.
#[derive(Clone, Copy)]
struct ConnEntry {
    orig_src_ip: [u8; 4], // app's real source IP
    orig_dst_ip: [u8; 4], // external host the app wanted to reach
    /// True when this connection originates from Argus itself (passthrough mode).
    bypass: bool,
}

pub struct Diverter;

impl Diverter {
    pub fn new() -> Self { Self }

    pub fn start(config: &ArgusConfig, conn_table: SharedConnTable) -> Result<()> {
        let filter = build_filter(config);

        if filter.is_empty() {
            info!("Diverter: no enabled listeners — skipping traffic redirection.");
            return Ok(());
        }

        info!("Diverter filter: {}", filter);

        let handle = WinDivert::network(&filter, 0i16, WinDivertFlags::new())
            .with_context(|| {
                "Failed to open WinDivert handle.\n\
                 Ensure that:\n  \
                 \u{2022} Argus is running as Administrator\n  \
                 \u{2022} WinDivert64.dll and WinDivert64.sys are in the same folder as argus.exe"
            })?;

        info!("Diverter: active — full bidirectional NAT enabled");

        let port_maps = PortMaps::from_config(config);
        std::thread::Builder::new()
            .name("argus-diverter".to_string())
            .spawn(move || packet_loop(handle, conn_table, port_maps))
            .context("Failed to spawn diverter thread")?;

        Ok(())
    }
}

// ── Filter builder ────────────────────────────────────────────────────────────

/// Port mapping: service_port → listener_port (outbound rewrite) and vice versa.
struct PortMaps {
    /// service_port → listener_port  (used when app packet arrives, to redirect to listener)
    svc_to_lst: HashMap<u16, u16>,
    /// listener_port → service_port  (used when listener response arrives, to restore original port)
    lst_to_svc: HashMap<u16, u16>,
}

impl PortMaps {
    fn from_config(config: &ArgusConfig) -> Self {
        let mut svc_to_lst = HashMap::new();
        let mut lst_to_svc = HashMap::new();
        for l in &config.listeners {
            if !l.enabled { continue; }
            svc_to_lst.insert(l.service_port, l.listener_port);
            lst_to_svc.insert(l.listener_port, l.service_port);
        }
        Self { svc_to_lst, lst_to_svc }
    }
}

fn build_filter(config: &ArgusConfig) -> String {
    // Outbound (app → external): intercept by DstPort == service_port.
    // Loopback (listener → app): intercept by SrcPort == listener_port.
    let mut tcp_svc:  Vec<u16> = Vec::new();
    let mut udp_svc:  Vec<u16> = Vec::new();
    let mut tcp_lst:  Vec<u16> = Vec::new();
    let mut udp_lst:  Vec<u16> = Vec::new();

    for l in &config.listeners {
        if !l.enabled { continue; }
        match l.protocol.to_lowercase().as_str() {
            "tcp" => { tcp_svc.push(l.service_port); tcp_lst.push(l.listener_port); }
            "udp" => { udp_svc.push(l.service_port); udp_lst.push(l.listener_port); }
            _ => {}
        }
    }

    let mut out_clauses: Vec<String> = Vec::new();
    let mut lb_clauses:  Vec<String> = Vec::new();

    if !tcp_svc.is_empty() {
        let dst = tcp_svc.iter().map(|p| format!("tcp.DstPort == {p}")).collect::<Vec<_>>().join(" || ");
        let src = tcp_lst.iter().map(|p| format!("tcp.SrcPort == {p}")).collect::<Vec<_>>().join(" || ");
        out_clauses.push(format!("(tcp && ({dst}))"));
        lb_clauses.push(format!("(tcp && ({src}))"));
    }

    if !udp_svc.is_empty() {
        let dst = udp_svc.iter().map(|p| format!("udp.DstPort == {p}")).collect::<Vec<_>>().join(" || ");
        let src = udp_lst.iter().map(|p| format!("udp.SrcPort == {p}")).collect::<Vec<_>>().join(" || ");
        out_clauses.push(format!("(udp && ({dst}))"));
        lb_clauses.push(format!("(udp && ({src}))"));
    }

    if out_clauses.is_empty() { return String::new(); }

    format!(
        "(outbound && !loopback && ({out})) || (outbound && loopback && ({lb}))",
        out = out_clauses.join(" || "),
        lb  = lb_clauses.join(" || "),
    )
}

// ── Packet loop ───────────────────────────────────────────────────────────────

fn packet_loop(handle: WinDivert<NetworkLayer>, shared_table: SharedConnTable, port_maps: PortMaps) {
    let mut conn_table: HashMap<u16, ConnEntry> = HashMap::new();
    let mut buf = vec![0u8; RECV_BUF];
    // Our own PID — connections originating from Argus itself (passthrough mode) must
    // bypass the NAT so they reach the real destination instead of looping back.
    let own_pid = std::process::id();

    loop {
        let packet = match handle.recv(Some(&mut buf)) {
            Ok(p)  => p,
            Err(e) => { error!("Diverter recv error: {e}"); break; }
        };

        let mut pkt = packet.into_owned();

        if !is_ipv4(&pkt.data) {
            let _ = handle.send(&pkt);
            continue;
        }

        // Set to true when the packet should be forwarded as-is (no NAT rewrite).
        let mut should_bypass = false;

        {
            let data = pkt.data.to_mut();
            let ihl  = (data[0] & 0x0F) as usize * 4;

            if data.len() < ihl + 4 {
                should_bypass = true;
            } else {
                let is_listener_response = data[12] == 127;

                if !is_listener_response {
                    // ── App → external ───────────────────────────────────────────
                    let orig_src = [data[12], data[13], data[14], data[15]];
                    let orig_dst = [data[16], data[17], data[18], data[19]];
                    let src_port = u16::from_be_bytes([data[ihl],     data[ihl + 1]]);
                    let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                    let is_tcp   = data[9] == 6;

                    if let Some(existing) = conn_table.get(&src_port) {
                        // Already-known connection: check bypass flag.
                        if existing.bypass {
                            should_bypass = true;
                        } else {
                            let listener_port = port_maps.svc_to_lst
                                .get(&dst_port).copied().unwrap_or(dst_port);
                            debug!(
                                "Diverter NAT out: port:{} → {}.{}.{}.{}:{} (listener:{})",
                                src_port,
                                orig_dst[0], orig_dst[1], orig_dst[2], orig_dst[3], dst_port,
                                listener_port,
                            );
                            data[12..16].copy_from_slice(&LOOPBACK);
                            data[16..20].copy_from_slice(&LOOPBACK);
                            data[ihl + 2..ihl + 4].copy_from_slice(&listener_port.to_be_bytes());
                        }
                    } else {
                        // New connection: resolve the owning process.
                        let (proc_name, proc_pid) = resolve_process(src_port, is_tcp);
                        let is_argus = proc_pid == Some(own_pid);

                        conn_table.insert(src_port, ConnEntry {
                            orig_src_ip: orig_src,
                            orig_dst_ip: orig_dst,
                            bypass: is_argus,
                        });

                        if is_argus {
                            // Argus is passing through this connection to the real server —
                            // let the packet through unchanged so it doesn't loop back.
                            debug!(
                                "Diverter: argus passthrough port:{} → {}.{}.{}.{}:{} bypassed",
                                src_port,
                                orig_dst[0], orig_dst[1], orig_dst[2], orig_dst[3], dst_port,
                            );
                            should_bypass = true;
                        } else {
                            let listener_port = port_maps.svc_to_lst
                                .get(&dst_port).copied().unwrap_or(dst_port);
                            let label_str = match (&proc_name, proc_pid) {
                                (Some(n), Some(p)) => format!("{} (PID {})", n, p),
                                (None,    Some(p)) => format!("PID {}", p),
                                _                  => "unknown".to_string(),
                            };
                            info!(
                                "Diverter: [{}] {}.{}.{}.{}:{} → {}.{}.{}.{}:{} intercepted",
                                label_str,
                                orig_src[0], orig_src[1], orig_src[2], orig_src[3], src_port,
                                orig_dst[0], orig_dst[1], orig_dst[2], orig_dst[3], dst_port,
                            );
                            // Publish to shared table so listeners can read the original destination.
                            if let Ok(mut tbl) = shared_table.write() {
                                use std::net::{IpAddr, Ipv4Addr};
                                tbl.insert(src_port, ConnInfo {
                                    orig_src_ip: IpAddr::V4(Ipv4Addr::from(orig_src)),
                                    orig_dst_ip: IpAddr::V4(Ipv4Addr::from(orig_dst)),
                                    orig_dst_port: dst_port,
                                    process_name: proc_name,
                                    pid: proc_pid,
                                });
                            }
                            data[12..16].copy_from_slice(&LOOPBACK);
                            data[16..20].copy_from_slice(&LOOPBACK);
                            data[ihl + 2..ihl + 4].copy_from_slice(&listener_port.to_be_bytes());
                        }
                    }

                } else {
                    // ── Listener → app ───────────────────────────────────────────
                    let src_port = u16::from_be_bytes([data[ihl],     data[ihl + 1]]);
                    let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);

                    if let Some(entry) = conn_table.get(&dst_port) {
                        if !entry.bypass {
                            let orig_src = entry.orig_src_ip;
                            let orig_dst = entry.orig_dst_ip;
                            // Restore src port: listener_port → service_port.
                            let svc_port = port_maps.lst_to_svc
                                .get(&src_port).copied().unwrap_or(src_port);
                            data[12..16].copy_from_slice(&orig_dst); // src IP → original dst IP
                            data[16..20].copy_from_slice(&orig_src); // dst IP → app's real IP
                            data[ihl..ihl + 2].copy_from_slice(&svc_port.to_be_bytes());
                            debug!(
                                "Diverter NAT in:  port:{} → {}.{}.{}.{}",
                                dst_port,
                                orig_src[0], orig_src[1], orig_src[2], orig_src[3],
                            );
                        }
                    }
                }
            }
        } // data borrow released here

        if should_bypass {
            let _ = handle.send(&pkt);
            continue;
        }

        if let Err(e) = pkt.recalculate_checksums(ChecksumFlags::default()) {
            warn!("Diverter: checksum error: {e}");
            continue;
        }

        if let Err(e) = handle.send(&pkt) {
            warn!("Diverter: send error: {e}");
        }
    }

    info!("Diverter: packet loop stopped.");
}

// ── Process identification ────────────────────────────────────────────────────

/// Returns `(process_name, pid)` for the process that owns `src_port`.
/// Either field may be `None` if the lookup fails.
fn resolve_process(src_port: u16, is_tcp: bool) -> (Option<String>, Option<u32>) {
    let pid = if is_tcp {
        pid_from_tcp_port(src_port)
    } else {
        pid_from_udp_port(src_port)
    };
    let name = pid.and_then(process_name);
    (name, pid)
}

/// Looks up the PID that owns the given TCP source port via GetExtendedTcpTable.
fn pid_from_tcp_port(src_port: u16) -> Option<u32> {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };

    unsafe {
        let mut size: u32 = 0;
        // First call: get required buffer size.
        GetExtendedTcpTable(None, &mut size, BOOL(0), 2 /*AF_INET*/, TCP_TABLE_OWNER_PID_ALL, 0);

        let mut buf = vec![0u8; size as usize];
        let rc = GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            BOOL(0),
            2,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if rc != 0 { return None; }

        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr(),
            table.dwNumEntries as usize,
        );
        for row in rows {
            // dwLocalPort is in network byte order (big-endian).
            if u16::from_be(row.dwLocalPort as u16) == src_port {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

/// Looks up the PID that owns the given UDP source port via GetExtendedUdpTable.
fn pid_from_udp_port(src_port: u16) -> Option<u32> {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };

    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(None, &mut size, BOOL(0), 2 /*AF_INET*/, UDP_TABLE_OWNER_PID, 0);

        let mut buf = vec![0u8; size as usize];
        let rc = GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            BOOL(0),
            2,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if rc != 0 { return None; }

        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr(),
            table.dwNumEntries as usize,
        );
        for row in rows {
            if u16::from_be(row.dwLocalPort as u16) == src_port {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

/// Returns the executable name (e.g. `"curl.exe"`) for the given PID,
/// using QueryFullProcessImageNameW.
fn process_name(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::{CloseHandle, BOOL};
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::core::PWSTR;

    unsafe {
        // In windows 0.48 OpenProcess returns Result<HANDLE>.
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, BOOL(0), pid).ok()?;

        let mut buf  = vec![0u16; 512];
        let mut size = buf.len() as u32;

        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(handle);

        if !ok.as_bool() { return None; }

        // Convert wide chars to String and extract the last path component.
        let full_path = String::from_utf16_lossy(&buf[..size as usize]);
        let name = full_path
            .split('\\')
            .last()
            .unwrap_or(&full_path)
            .to_string();
        Some(name)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn is_ipv4(data: &[u8]) -> bool {
    data.len() >= 20 && (data[0] >> 4) == 4
}
