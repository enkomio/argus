# Argus

<p align="center">
  <img src="media/logo.png" alt="Argus logo" width="500"/>
</p>

A Windows network traffic interception tool for malware analysis, written in Rust.

## What is Argus?

Argus intercepts all outgoing network traffic from a system and responds with fake but plausible responses. This tricks malware into thinking it has successfully connected to its C2 server, allowing analysts to observe its behaviour in a controlled environment.

Key capabilities:
- **Automatic traffic redirection** — WinDivert rewrites packet destinations at kernel level; no manual DNS or proxy configuration needed
- **Protocol-aware listeners** — HTTP/HTTPS, DNS, SMTP, POP3, raw TCP/UDP
- **Per-host HTTPS interception** — automatic CA generation with dynamic per-hostname leaf certificates (mitmproxy-style); install the CA once and all TLS traffic is decryptable
- **Process identification** — every intercepted connection is attributed to the originating process name and PID
- **Selective passthrough** — chosen processes, PIDs, IPs, domains, or URL patterns are passed through transparently to the real destination instead of receiving a fake response
- **Selective logging suppression** — `NoLog` entries exclude matching connections from capture files
- **Request/response capture** — every intercepted transaction is saved to disk under `capture/<process>/<pid>/<protocol>/`
- **Customisable fake responses** — drop files into `default_files/` to serve custom content per path; built-in fallback if the directory or file is absent

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

# Override capture directory (default: capture\)
.\target\release\argus.exe --log-dir D:\analysis\run1

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

### Listener example — HTTP / HTTPS

```ini
[HTTPListener]
Enabled: True
Listener: HTTPListener
ServicePort: 80
ListenerPort: 18080
Protocol: TCP
UseSSL: No
Timeout: 10

[HTTPSListener]
Enabled: True
Listener: HTTPListener
ServicePort: 443
ListenerPort: 18443
Protocol: TCP
UseSSL: Yes
Timeout: 10

# Optional: pass through matching connections to the real destination.
# Passthrough: curl.exe, 1234, 93.184.216.34, example\.com, http://evil\.com/payload

# Optional: suppress capture files for matching connections.
# NoLog: curl.exe, 1234, 93.184.216.34, analytics\.example\.com
```

### HTTPS interception (MITM)

On first run, Argus generates a CA key pair in `configs/`:

```
configs/
├── argus-ca.crt   ← install this in Windows Certificate Store (Trusted Root CAs)
└── argus-ca.key   ← private key — keep secret
```

For each TLS connection, Argus dynamically generates a leaf certificate for the requested hostname, signed by the CA. Once the CA is trusted by the OS, browsers and HTTP clients accept the leaf certificates without errors.

**Installing the CA on Windows:**

```powershell
certutil -addstore -f "Root" configs\argus-ca.crt
```

**Removing the CA:**

```
certmgr.msc → Trusted Root Certification Authorities → Certificates → right-click "Argus CA" → Delete
```

The CA certificate expires after one year. Argus warns at startup if the loaded CA is expired.

### Customising fake HTTP responses

The HTTP listener looks for files in the `default_files/` directory before falling back to the built-in response.

Resolution order for each incoming request:

| Priority | Path tried | Example for `GET /login.html` |
|----------|-----------|-------------------------------|
| 1 | `default_files/{uri}` | `default_files/login.html` |
| 2 | `default_files/index.html` | generic HTML fallback |
| 3 | Built-in constant | always available |

Place any file in `default_files/` and it will be served automatically when the URI matches. The URI path is sanitised before use (leading `/` stripped, `..` components removed) to prevent directory traversal.

```
default_files/
├── index.html        ← served for "/" and any unmatched HTML request
├── login.html        ← served for "/login.html"
├── api/
│   └── status.json   ← served for "/api/status.json"
└── update.exe        ← served for "/update.exe"
```

### Listener example — DNS

```ini
[DNSListener]
Enabled: True
Listener: DNSListener
ServicePort: 53
ListenerPort: 10053
Protocol: UDP
ResponseA: 127.0.0.1        # IP returned for A queries
ResponseMX: mail.argus.local
ResponseTXT: ARGUS

# Optional: forward matching queries to the real DNS server.
# Passthrough: curl.exe, 1234, 93.184.216.34, example.com, .*\.microsoft\.com

# Optional: suppress capture files for matching queries.
# NoLog: curl.exe, 1234, 93.184.216.34, analytics\.example\.com
```

Supported record types: `A`, `AAAA` (returns `::1`), `MX`, `TXT`. Any other query type receives an `A` record fallback.

**Testing the DNS listener:**

```powershell
# Query directly (requires WinDivert to be redirecting port 53)
nslookup evil.example.com 127.0.0.1

# Query the listener port directly (no WinDivert needed)
nslookup evil.example.com 127.0.0.1 -port=10053
```

### Listener example — SMTP / POP3

```ini
[SMTPListener]
Enabled: True
Listener: SMTPListener
ServicePort: 25
ListenerPort: 10025
Protocol: TCP
Banner: 220 argus.local SMTP Service Ready

[POPListener]
Enabled: True
Listener: POPListener
ServicePort: 110
ListenerPort: 10110
Protocol: TCP
Banner: +OK Argus POP3 Server Ready
```

Each listener logs credentials (USER/PASS) and protocol commands, and replies with plausible success responses to keep the malware running.

### Listener example — Raw TCP/UDP

```ini
[RawTCPListener]
Enabled: True
Listener: RawListener
ServicePort: 1337
ListenerPort: 11337
Protocol: TCP
Timeout: 5

[RawUDPListener]
Enabled: True
Listener: RawListener
ServicePort: 1338
ListenerPort: 11338
Protocol: UDP
Timeout: 5
```

Accepts any traffic, echoes it back, and logs a hex dump of up to 256 bytes per packet. Used as the default catch-all for ports with no dedicated listener.

### Selective passthrough

The `Passthrough` key accepts a comma-separated list of entries. A connection is passed through to the real destination when **any** entry matches. Supported entry types:

| Entry type   | Example                              | Matched against              |
|--------------|--------------------------------------|------------------------------|
| Process name | `curl.exe`, `curl.*`                 | originating process name     |
| PID          | `1234`                               | originating process PID      |
| IPv4 address | `93.184.216.34`                      | original destination IP      |
| IPv6 address | `2606:2800:220:1:248:1893:25c8:1946` | original destination IP      |
| Domain       | `example.com`, `.*\.microsoft\.com`  | HTTP `Host` / DNS query name |
| Domain+path  | `example.com/api/v1`                 | HTTP `Host` + URI prefix     |
| URL          | `http://example.com/path`            | scheme stripped, then above  |

**Process names and domain/URL entries are treated as case-insensitive regular expressions** anchored at the start (`^`). A plain name like `curl.exe` still works — the `.` in regex matches any character, which is harmless in practice. Use `curl\.exe` for a precise literal-dot match.

```ini
# Pass through any process whose name starts with "curl"
Passthrough: curl.*

# Pass through DNS queries for any Microsoft domain
Passthrough: .*\.microsoft\.com

# Pass through requests to a specific path only
Passthrough: updates\.vendor\.com/v2/check

# Mix multiple entry types
Passthrough: malware_loader.exe, 93.184.216.34, c2\.evil\.io
```

When an HTTP connection is passed through:
- **Phase 1** (before reading data): PID, process name, and IP entries are checked. If matched, the raw TCP stream is proxied transparently (`copy_bidirectional`).
- **Phase 2** (after reading HTTP headers): domain and URL entries are checked against the `Host` header and URI. The already-read request bytes are replayed to the real server before proxying the rest.

Argus's own outbound connections (created during passthrough) are automatically excluded from WinDivert interception to prevent redirect loops.

### Selective logging suppression

The `NoLog` key uses the same entry format as `Passthrough`. Matching connections are not written to capture files (they are still logged to the console/log file at `info` level).

```ini
NoLog: analytics\.example\.com, telemetry\.microsoft\.com
```

## ForwardTo — external traffic modifier

The `ForwardTo` key lets you route every intercepted request and response through an external TCP endpoint before Argus processes or returns it. The endpoint can inspect and modify the bytes; whatever it returns is used in place of the original payload. If the endpoint is unreachable or returns an error, Argus falls back to the original payload — traffic is never dropped.

### Wire protocol

```
Argus → endpoint:
  [4 bytes BE uint32]  length of JSON metadata header
  [N bytes UTF-8]      JSON metadata
  [4 bytes BE uint32]  length of raw payload
  [M bytes]            raw payload

endpoint → Argus:
  [4 bytes BE uint32]  length of (possibly modified) payload
  [K bytes]            payload to use in place of the original
```

**JSON metadata fields:**

| Field      | Type   | Description                                          |
|------------|--------|------------------------------------------------------|
| `direction`| string | `"request"` or `"response"`                         |
| `protocol` | string | `"http"`, `"https"`, `"dns"`, `"smtp"`, `"pop3"`, `"raw"` |
| `src_ip`   | string | Client source IP                                     |
| `src_port` | number | Client source port                                   |
| `dst_ip`   | string | Original destination IP (before WinDivert)           |
| `dst_port` | number | Original destination port                            |
| `process`  | string | Originating executable name (e.g. `"malware.exe"`)  |
| `pid`      | number | Originating PID (`0` = unknown)                     |

### Configuration

Add `ForwardTo` to any listener section in `configs\default.ini`:

```ini
[HTTPListener]
Enabled: True
Listener: HTTPListener
ServicePort: 80
ListenerPort: 18080
Protocol: TCP
ForwardTo: 127.0.0.1:9999

[DNSListener]
Enabled: True
Listener: DNSListener
ServicePort: 53
ListenerPort: 10053
Protocol: UDP
ForwardTo: 127.0.0.1:9999
```

Multiple listeners can point to the same endpoint, or each to a different one.

### Running the example Python forwarder

A ready-to-use example is provided in `python/example_interceptor.py`. It requires no external dependencies (standard library only).

**Terminal 1 — start the forwarder first:**

```bash
cd python
python example_interceptor.py                  # listens on 0.0.0.0:9999
python example_interceptor.py --port 8888      # custom port
python example_interceptor.py --debug          # verbose output
```

**Terminal 2 — start Argus (elevated):**

```powershell
.\target\release\argus.exe -c configs\default.ini
```

**Expected output (interceptor terminal):**

```
12:34:01  INFO     Argus interceptor listening on 0.0.0.0:9999
12:34:01  INFO     Handling protocols: http, https, dns, smtp, raw
12:34:01  INFO     Add  'ForwardTo: 127.0.0.1:9999'  to any listener in configs/default.ini
12:34:01  INFO     ────────────────────────────────────────────────────────────
12:34:45  INFO     [HTTP req]  malware.exe  →  GET /c2/beacon
12:34:45  INFO     [HTTP rsp]  200 OK  (1024 bytes)  title tag patched
12:34:46  INFO     [DNS  req]  malware.exe  →  A evil-c2.example.com
12:34:46  INFO     [DNS  rsp]  evil-c2.example.com A TTL=60 127.0.0.1
```

### Python library (`argus_interceptor`)

`python/argus_interceptor.py` is a zero-dependency library that handles all socket framing. Implement only the handlers you need:

```python
from argus_interceptor import (
    create_interceptor,
    http_request, http_response,
    dns_message,
    smtp_response, smtp_command,
)

def handle_http(meta, payload):
    if meta.direction == "response":
        resp = http_response(payload)
        resp.body = resp.body.replace(b"foo", b"bar")
        return resp.to_bytes()   # Content-Length auto-updated
    return payload

def handle_dns(meta, payload):
    msg = dns_message(payload)
    for q in msg.questions:
        print(f"{q.type_name} query for {q.name}")
    return payload

interceptor = create_interceptor(
    http_handler=handle_http,
    https_handler=handle_http,
    dns_handler=handle_dns,
)
interceptor.serve()
```

**Built-in protocol parsers:**

| Function | Returns | Key fields |
|---|---|---|
| `http_request(payload)` | `HttpRequest` | `.method`, `.path`, `.headers`, `.body` |
| `http_response(payload)` | `HttpResponse` | `.status_code`, `.status_text`, `.headers`, `.body` |
| `dns_message(payload)` | `DnsMessage` | `.questions`, `.answers`, `.is_query`, `.rcode` |
| `smtp_response(payload)` | `SmtpResponse` | `.code`, `.lines` |
| `smtp_command(payload)` | `SmtpCommand` | `.command`, `.args` |

`Headers` is a case-insensitive dict; `HttpRequest.to_bytes()` and `HttpResponse.to_bytes()` rebuild the raw message and update `Content-Length` automatically.

`DnsRecord.address` returns the decoded IP for A/AAAA records; `DnsRecord.text` returns the decoded string for TXT records. `DnsMessage.to_bytes()` re-serialises the DNS wire format.

The interceptor can also be implemented in any other language — the wire protocol is language-agnostic (see wire format above). ForwardTo is called for both intercepted **and** passthrough connections, so the endpoint sees all traffic regardless of whether Argus is returning a fake response or proxying to the real server.

## Request/response capture

Every intercepted transaction is saved to disk. The directory layout is:

```
capture/
└── <process_name>/
    └── <pid>/
        └── <protocol>/
            ├── 20260515_143201_0001_req.log
            ├── 20260515_143201_0001_rsp.log
            ├── 20260515_143205_0002_req.log
            └── ...
```

- **`<process_name>`** — sanitised executable name (e.g. `malware.exe`)
- **`<pid>`** — numeric PID; a new subdirectory is created if the process restarts
- **`<protocol>`** — `http`, `https`, `smtp`, `pop`, `dns`, `raw`
- **filename** — `<yyyymmdd>_<HHMMSS>_<NNNN>_<req|rsp>.log` where `NNNN` is a per-PID transaction counter

The default capture directory is `capture\` relative to the working directory. Override with `--log-dir`.

## Listeners

| Listener      | Port  | Protocol | Description                                         |
|---------------|-------|----------|-----------------------------------------------------|
| HTTPListener  | 80    | TCP      | HTTP — serves fake HTML/files, passthrough on match |
| HTTPSListener | 443   | TCP      | HTTPS — per-host MITM certs, decrypted capture      |
| DNSListener   | 53    | UDP      | DNS — configurable A/AAAA/MX/TXT, passthrough       |
| SMTPListener  | 25    | TCP      | Email sending — logs credentials and message body   |
| POPListener   | 110   | TCP      | POP3 email retrieval — logs credentials             |
| RawListener   | any   | TCP/UDP  | Catch-all — hex dump logging, echo response         |

## Architecture

```
argus/
├── src/
│   ├── main.rs              # Entry point, CLI, admin check, startup
│   ├── config.rs            # INI config parser
│   ├── conn_table.rs        # Shared connection table (diverter → listeners)
│   ├── logger.rs            # tracing setup (terminal + optional file)
│   ├── request_logger.rs    # Per-transaction capture file writer
│   ├── forward_to.rs        # ForwardTo wire protocol (external traffic modifier)
│   ├── diverter/
│   │   └── mod.rs           # WinDivert symmetric NAT + process identification
│   └── listeners/
│       ├── mod.rs           # Listener manager
│       ├── http.rs          # HTTP/HTTPS interception, MITM TLS, passthrough
│       ├── dns.rs           # DNS query interception, passthrough, logging
│       ├── smtp.rs          # SMTP email interception
│       ├── pop.rs           # POP3 interception
│       └── raw.rs           # Raw TCP/UDP fallback
├── python/
│   ├── argus_interceptor.py # Reusable ForwardTo endpoint library + protocol parsers
│   └── example_interceptor.py  # Example: HTTP title patching, DNS logging
├── configs/
│   └── default.ini          # Default configuration
├── default_files/
│   └── index.html           # Default HTTP fake response (customisable)
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

For every new connection, Argus calls `GetExtendedTcpTable` / `GetExtendedUdpTable` to map the client source port to a PID, then `QueryFullProcessImageNameW` to resolve the executable name. This information is stored in the shared connection table and logged alongside the intercepted traffic.

### HTTPS interception

Argus acts as a transparent TLS MITM proxy using a locally-generated CA:

1. At startup, `configs/argus-ca.crt` and `configs/argus-ca.key` are loaded (or generated if absent). The CA is valid for one year; Argus warns if it is expired.
2. For each incoming TLS connection, the SNI hostname from the `ClientHello` is used to generate a leaf certificate on the fly, signed by the CA. Leaf certificates are cached in memory per hostname.
3. The TLS handshake completes with the leaf certificate. Argus decrypts the plaintext request, logs it, and returns a fake HTTP response (or passes through to the real server if the hostname matches a `Passthrough` rule).

### Selective passthrough

When a connection matches the `Passthrough` list, the listener acts as a transparent TCP proxy (`tokio::io::copy_bidirectional`) to the real destination. Argus's own outbound connections are recognised by PID and bypass the WinDivert filter, preventing redirect loops.

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
