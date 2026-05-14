# Argus 🦀

A Windows network traffic interception tool for malware analysis, written in Rust.

## What is Argus?

Argus intercepts all outgoing network traffic from a system and responds with fake but plausible responses. This tricks malware into thinking it has successfully connected to its C2 server, allowing analysts to observe its behaviour in a controlled environment.

Key capabilities:
- **Automatic traffic redirection** — WinDivert rewrites packet destinations at kernel level; no manual DNS or proxy configuration needed
- **Protocol-aware listeners** — HTTP, DNS, SMTP, FTP, IRC, POP3, raw TCP/UDP
- **Process identification** — every intercepted connection is attributed to the originating process name and PID
- **Selective forwarding** — chosen processes, IPs, domains, or URL patterns are forwarded transparently to the real destination instead of receiving a fake response

## Requirements

- Windows 10/11 or Windows Server 2016+
- **Administrator privileges** (required for WinDivert and privileged ports)
- [WinDivert](https://reqrypt.org/windivert.html) — `WinDivert.dll` and `WinDivert64.sys` must be in the same folder as `argus.exe` (included in the repository)

## Usage

Argus requires an elevated terminal or UAC prompt (the embedded manifest requests `requireAdministrator` automatically).

```powershell
# Run with default config
.\target\release\argus.exe

# Custom config file
.\target\release\argus.exe -c configs\default.ini

# Verbose / debug logging
.\target\release\argus.exe -v

# Bind listeners to a specific address
.\target\release\argus.exe -b 0.0.0.0

# Write log output to file
.\target\release\argus.exe -l argus.log

# List available listener types
.\target\release\argus.exe --list-listeners
```

## Configuration

Edit `configs\default.ini` to enable/disable listeners and customise responses.

### Global options

```ini
[Argus]
DivertTraffic: Yes          # Enable WinDivert automatic traffic redirection
```

### Listener example — HTTP

```ini
[HTTPListener80]
Enabled: True
Listener: HTTPListener
Port: 80
Protocol: TCP
Timeout: 10
DumpHTTPPosts: Yes

# Optional: forward matching connections to the real destination
# instead of returning a fake response.
# Forward: curl.exe, 1234, 93.184.216.34, example\.com, http://evil\.com/payload
```

### Listener example — DNS

```ini
[DNSListener]
Enabled: True
Listener: DNSListener
Port: 53
Protocol: UDP
ResponseA: 127.0.0.1        # IP returned for A queries
ResponseMX: mail.argus.local
ResponseTXT: ARGUS
```

### Selective forwarding

The `Forward` key accepts a comma-separated list of entries. A connection is forwarded to the real destination when **any** entry matches. Supported entry types:

| Entry type   | Example                              | Matched against              |
|--------------|--------------------------------------|------------------------------|
| Process name | `curl.exe`, `curl.*`                 | originating process name     |
| PID          | `1234`                               | originating process PID      |
| IPv4 address | `93.184.216.34`                      | original destination IP      |
| IPv6 address | `2606:2800:220:1:248:1893:25c8:1946` | original destination IP      |
| Domain       | `example\.com`, `example\..*`        | HTTP `Host` header           |
| Domain+path  | `example\.com/api/v1`                | HTTP `Host` + URI prefix     |
| URL          | `http://example\.com/path`           | scheme stripped, then above  |

**Process names and domain/URL entries are treated as case-insensitive regular expressions** anchored at the start (`^`). A plain name like `curl.exe` still works — the `.` in regex matches any character, which is harmless in practice. Use `curl\.exe` for a precise literal-dot match.

```ini
# Forward any process whose name starts with "curl"
Forward: curl.*

# Forward requests to any .example TLD
Forward: .*\.example\.(com|it|org)

# Forward requests to a specific path only
Forward: updates\.vendor\.com/v2/check

# Mix multiple entry types
Forward: malware_loader.exe, 93.184.216.34, c2\.evil\.io
```

When a connection is forwarded:
- **Phase 1** (before reading data): PID, process name, and IP entries are checked. If matched, the raw TCP stream is proxied transparently (`copy_bidirectional`).
- **Phase 2** (after reading HTTP headers): domain and URL entries are checked against the `Host` header and URI. The already-read request bytes are replayed to the real server before proxying the rest.

Argus's own outbound connections (created during forwarding) are automatically excluded from WinDivert interception to prevent redirect loops.

## Listeners

| Listener      | Port  | Protocol | Description                              |
|---------------|-------|----------|------------------------------------------|
| HTTPListener  | 80    | TCP      | HTTP traffic — serves fake HTML/XML      |
| HTTPSListener | 443   | TCP      | HTTPS — SSL passthrough or fake response |
| DNSListener   | 53    | UDP      | DNS queries → configurable fake records  |
| SMTPListener  | 25    | TCP      | Email sending — logs credentials         |
| FTPListener   | 21    | TCP      | FTP — logs credentials and file ops      |
| IRCListener   | 6667  | TCP      | IRC C2 channels                          |
| POPListener   | 110   | TCP      | POP3 email retrieval                     |
| RawListener   | 1337  | TCP/UDP  | Any other port — hexdump logging         |

## Architecture

```
argus/
├── src/
│   ├── main.rs              # Entry point, CLI, admin check, startup
│   ├── config.rs            # INI config parser
│   ├── conn_table.rs        # Shared connection table (diverter → listeners)
│   ├── logger.rs            # Logging setup (tracing)
│   ├── diverter/
│   │   └── mod.rs           # WinDivert symmetric NAT + process identification
│   └── listeners/
│       ├── mod.rs           # Listener manager
│       ├── http.rs          # HTTP/HTTPS interception + forward mode
│       ├── dns.rs           # DNS query interception
│       ├── smtp.rs          # SMTP email interception
│       ├── ftp.rs           # FTP interception
│       ├── irc.rs           # IRC C2 channel interception
│       ├── pop.rs           # POP3 interception
│       └── raw.rs           # Raw TCP/UDP fallback
├── configs/
│   └── default.ini          # Default configuration
├── Cargo.toml
├── build.rs                 # WinDivert linker setup + UAC manifest embedding
└── README.md
```

## How it works

### Traffic diversion

Argus uses [WinDivert](https://reqrypt.org/windivert.html) to intercept outbound packets at the network layer before they leave the machine.

For each intercepted packet (outbound, non-loopback, matching a listener port):

1. **Symmetric NAT**: both source and destination IPs are rewritten to `127.0.0.1`. The original addresses are stored in an in-memory connection table keyed by the client's source port.
2. **Re-injection**: the modified packet is re-injected. Windows routes it via the loopback interface to the local listener.
3. **Reverse NAT**: when the listener replies (outbound loopback packet with a matching source port), both IPs are restored to their original values before re-injection, so the application's TCP stack sees the expected addresses.

This symmetric approach ensures the TCP three-way handshake completes correctly regardless of the machine's real IP address.

### Process identification

For every **new** connection, Argus calls `GetExtendedTcpTable` / `GetExtendedUdpTable` to map the client source port to a PID, then `QueryFullProcessImageNameW` to resolve the executable name. This information is stored in the shared connection table and logged alongside the intercepted traffic.

### Listeners

Each listener is a Tokio async task that binds to a port and speaks the relevant protocol. Intercepted connections arrive from `127.0.0.1` (loopback) because of the symmetric NAT. Listeners read the original destination from the shared connection table to support selective forwarding.

### Selective forwarding

When a connection matches the `Forward` list, the listener acts as a transparent TCP proxy (`tokio::io::copy_bidirectional`) to the real destination. Argus's own outbound connections are recognised by PID and bypass the WinDivert filter, preventing redirect loops.

## Building

### 1. Install Rust

```powershell
winget install Rustlang.Rustup
# or download the installer from https://rustup.rs
```

### 2. Build

```powershell
cargo build --release
```

The `build.rs` script automatically:
- Adds `WinDivert-2.2.2-A/x64/` to the linker search path so `WinDivert.lib` is found at compile time
- Copies `WinDivert.dll` and `WinDivert64.sys` next to `argus.exe`
- Embeds a UAC manifest requesting `requireAdministrator`

Binary location: `.\target\release\argus.exe`

## Why Rust?

| Feature          | Typical Python tool | Argus (Rust)      |
|------------------|---------------------|-------------------|
| Memory usage     | ~80–150 MB          | ~5–15 MB          |
| Startup time     | 2–5 seconds         | <100 ms           |
| Concurrent conns | Limited by GIL      | Millions (async)  |
| Binary size      | ~50 MB (PyInstaller)| ~5 MB (static)    |
| Dependencies     | Python + 20+ pkgs   | Single binary     |
| Memory safety    | GC managed          | Compile-time safe |

## Legal Notice

This tool is intended for legitimate malware analysis and security research. Use only in isolated lab environments. Do not use on production networks.

## License

Apache 2.0
