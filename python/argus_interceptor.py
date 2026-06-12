"""
argus_interceptor — high-level library for Argus ForwardTo endpoints.

Handles all socket framing and protocol routing so you only need to
implement the handler functions for the protocols you care about.

Quick start
───────────
    from argus_interceptor import create_interceptor

    def handle_http(meta, payload: bytes) -> bytes:
        if meta.direction == "response":
            payload = payload.replace(b"foo", b"bar")
        return payload

    def handle_dns(meta, payload: bytes) -> bytes:
        print(f"DNS {meta.direction} from {meta.process} ({meta.pid})")
        return payload  # pass through unchanged

    interceptor = create_interceptor(
        http_handler=handle_http,
        dns_handler=handle_dns,
    )
    interceptor.serve()          # blocks; Ctrl+C to stop

Decorator style
───────────────
    from argus_interceptor import ArgusInterceptor

    interceptor = ArgusInterceptor(host="127.0.0.1", port=9999)

    @interceptor.on("http", "https")
    def handle_http(meta, payload: bytes) -> bytes:
        return payload

    @interceptor.on("dns")
    def handle_dns(meta, payload: bytes) -> bytes:
        return payload

    interceptor.serve()

Handler signature
─────────────────
    def handler(meta: Meta, payload: bytes) -> bytes

    meta fields:
        meta.request_id unique ID shared by a request and its response (int)
        meta.direction  "request" | "response"
        meta.protocol   "http" | "https" | "dns" | "smtp" | "pop3" | "raw"
        meta.src_ip     client source IP (str)
        meta.src_port   client source port (int)
        meta.dst_ip     original destination IP (str)
        meta.dst_port   original destination port (int)
        meta.process    originating process name, e.g. "malware.exe"
        meta.pid        originating PID (int, 0 = unknown)

    Return the (possibly modified) payload bytes.
    Raising an exception or returning None falls back to the original payload.
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

__all__ = [
    # Core
    "Meta", "ArgusInterceptor", "create_interceptor",
    # HTTP
    "Headers", "HttpRequest", "HttpResponse", "http_request", "http_response",
    # DNS
    "DnsQuestion", "DnsRecord", "DnsMessage", "dns_message",
    # SMTP / POP3
    "SmtpResponse", "SmtpCommand", "smtp_response", "smtp_command",
]

log = logging.getLogger(__name__)

# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class Meta:
    """Metadata attached to every intercepted payload."""
    request_id: int  # shared by a request and its associated response
    direction: str   # "request" | "response"
    protocol:  str   # "http" | "https" | "dns" | "smtp" | "pop3" | "raw"
    src_ip:    str
    src_port:  int
    dst_ip:    str
    dst_port:  int
    process:   str
    pid:       int

    @classmethod
    def _from_dict(cls, d: dict) -> "Meta":
        return cls(
            request_id = int(d.get("request_id", 0)),
            direction = d.get("direction", ""),
            protocol  = d.get("protocol",  ""),
            src_ip    = d.get("src_ip",    ""),
            src_port  = int(d.get("src_port", 0)),
            dst_ip    = d.get("dst_ip",    ""),
            dst_port  = int(d.get("dst_port", 0)),
            process   = d.get("process",   "unknown"),
            pid       = int(d.get("pid",   0)),
        )

    def __str__(self) -> str:
        arrow = "→" if self.direction == "request" else "←"
        proc  = f"{self.process}({self.pid})" if self.pid else self.process
        return (f"{arrow} [{self.protocol.upper()}] {proc} "
                f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}")

# ── Handler type ──────────────────────────────────────────────────────────────

Handler = Callable[[Meta, bytes], bytes]

# ── Wire protocol helpers ─────────────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _read_frame(sock: socket.socket) -> Tuple[Meta, bytes]:
    hlen    = struct.unpack(">I", _recv_exact(sock, 4))[0]
    meta    = Meta._from_dict(json.loads(_recv_exact(sock, hlen)))
    plen    = struct.unpack(">I", _recv_exact(sock, 4))[0]
    payload = _recv_exact(sock, plen) if plen else b""
    return meta, payload


def _send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)

# ── Main class ────────────────────────────────────────────────────────────────

class ArgusInterceptor:
    """
    TCP server that implements the Argus ForwardTo wire protocol.

    Register handlers with :meth:`on` or pass them to :func:`create_interceptor`.
    Call :meth:`serve` to start accepting connections (blocking).
    Call :meth:`start` to start in a background thread (non-blocking).
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 9999):
        self.host = host
        self.port = port
        self._handlers: Dict[str, Handler] = {}
        self._default_handler: Optional[Handler] = None

    # ── Handler registration ──────────────────────────────────────────────────

    def on(self, *protocols: str) -> Callable[[Handler], Handler]:
        """
        Decorator: register a handler for one or more protocols.

            @interceptor.on("http", "https")
            def handle(meta, payload):
                return payload
        """
        def decorator(fn: Handler) -> Handler:
            for proto in protocols:
                self._handlers[proto.lower()] = fn
            return fn
        return decorator

    def set_default_handler(self, fn: Handler) -> None:
        """Fallback handler called when no protocol-specific handler matches."""
        self._default_handler = fn

    # ── Internal dispatch ─────────────────────────────────────────────────────

    def _dispatch(self, meta: Meta, payload: bytes) -> bytes:
        handler = self._handlers.get(meta.protocol) or self._default_handler
        if handler is None:
            return payload
        try:
            result = handler(meta, payload)
            return result if isinstance(result, bytes) else payload
        except Exception as exc:
            log.warning("Handler error for %s: %s — using original payload", meta, exc)
            return payload

    def _handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        try:
            meta, payload = _read_frame(conn)
            log.debug("%s  (%d bytes)", meta, len(payload))
            result = self._dispatch(meta, payload)
            _send_frame(conn, result)
        except EOFError as exc:
            log.debug("Connection from %s closed early: %s", addr, exc)
        except Exception as exc:
            log.warning("Error from %s: %s", addr, exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ── Server ────────────────────────────────────────────────────────────────

    def serve(self) -> None:
        """Start accepting connections. Blocks until KeyboardInterrupt."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(64)

        protocols = list(self._handlers) or ["(none registered)"]
        log.info("Argus interceptor listening on %s:%d", self.host, self.port)
        log.info("Handling protocols: %s", ", ".join(protocols))
        log.info("Add  'ForwardTo: %s:%d'  to any listener in configs/default.ini",
                 self.host if self.host != "0.0.0.0" else "127.0.0.1", self.port)
        log.info("─" * 60)

        while True:
            try:
                conn, addr = srv.accept()
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
            except KeyboardInterrupt:
                log.info("Shutting down.")
                break
            except Exception as exc:
                log.warning("Accept error: %s", exc)

    def start(self) -> threading.Thread:
        """Start the server in a background daemon thread. Returns the thread."""
        t = threading.Thread(target=self.serve, daemon=True, name="argus-interceptor")
        t.start()
        return t

# ── Factory function ──────────────────────────────────────────────────────────

def create_interceptor(
    *,
    host: str = "0.0.0.0",
    port: int = 9999,
    http_handler:    Optional[Handler] = None,
    https_handler:   Optional[Handler] = None,
    dns_handler:     Optional[Handler] = None,
    smtp_handler:    Optional[Handler] = None,
    pop3_handler:    Optional[Handler] = None,
    raw_handler:     Optional[Handler] = None,
    default_handler: Optional[Handler] = None,
) -> ArgusInterceptor:
    """
    Create and configure an :class:`ArgusInterceptor` from keyword arguments.

    Each ``*_handler`` receives ``(meta: Meta, payload: bytes) -> bytes``.
    Omit a handler to pass that protocol through unchanged.

    Example::

        interceptor = create_interceptor(
            http_handler=handle_http,
            dns_handler=handle_dns,
        )
        interceptor.serve()
    """
    ic = ArgusInterceptor(host=host, port=port)

    mapping = {
        "http":  http_handler,
        "https": https_handler,
        "dns":   dns_handler,
        "smtp":  smtp_handler,
        "pop3":  pop3_handler,
        "raw":   raw_handler,
    }
    for proto, handler in mapping.items():
        if handler is not None:
            ic._handlers[proto] = handler

    if default_handler is not None:
        ic.set_default_handler(default_handler)

    return ic

# ══════════════════════════════════════════════════════════════════════════════
# Protocol parsers
# ══════════════════════════════════════════════════════════════════════════════
#
# Each parser takes raw bytes and returns a structured object that can be
# inspected and modified.  Call  .to_bytes()  on the object to get the
# (possibly modified) payload back to return from your handler.
#
# Example:
#
#     def handle_http(meta, payload):
#         if meta.direction == "response":
#             resp = http_response(payload)
#             resp.body = resp.body.replace(b"foo", b"bar")
#             return resp.to_bytes()           # Content-Length auto-updated
#         return payload
#
# ══════════════════════════════════════════════════════════════════════════════

# ── HTTP ──────────────────────────────────────────────────────────────────────

class Headers:
    """
    Case-insensitive, order-preserving HTTP headers container.

    Behaves like a dict for get/set/delete/in, but preserves the original
    header name casing and supports duplicate names (e.g. Set-Cookie).
    Duplicate names added via ``__setitem__`` replace the first occurrence;
    use :meth:`add` to append a second value.
    """

    def __init__(self) -> None:
        self._items: List[List[str]] = []   # [[original_name, value], ...]

    # ── dict-like interface ───────────────────────────────────────────────────

    def __setitem__(self, key: str, value: str) -> None:
        kl = key.lower()
        for entry in self._items:
            if entry[0].lower() == kl:
                entry[1] = str(value)
                return
        self._items.append([key, str(value)])

    def __getitem__(self, key: str) -> str:
        kl = key.lower()
        for k, v in self._items:
            if k.lower() == kl:
                return v
        raise KeyError(key)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        kl = key.lower()
        return any(k.lower() == kl for k, _ in self._items)

    def __delitem__(self, key: str) -> None:
        kl = key.lower()
        self._items = [e for e in self._items if e[0].lower() != kl]

    def add(self, key: str, value: str) -> None:
        """Append a header without replacing an existing one (e.g. Set-Cookie)."""
        self._items.append([key, str(value)])

    def items(self) -> List[Tuple[str, str]]:
        return [(k, v) for k, v in self._items]

    def __repr__(self) -> str:
        return "Headers(" + repr(self._items) + ")"


def _split_head_body(raw: bytes) -> Tuple[bytes, bytes]:
    """Split an HTTP message into the header block and the body."""
    for sep, sep_len in ((b"\r\n\r\n", 4), (b"\n\n", 2)):
        pos = raw.find(sep)
        if pos != -1:
            return raw[:pos], raw[pos + sep_len:]
    return raw, b""


def _parse_headers(header_block: bytes) -> Headers:
    """Parse lines 1..N of an HTTP header block into a Headers object."""
    headers = Headers()
    lines = header_block.split(b"\n")[1:]       # skip the request/status line
    for line in lines:
        line = line.rstrip(b"\r")
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.decode(errors="replace").strip()] = v.decode(errors="replace").strip()
    return headers


@dataclass
class HttpRequest:
    """
    Parsed HTTP request.

    Attributes:
        method   -- "GET", "POST", …
        path     -- "/index.html?q=1"
        version  -- "HTTP/1.1"
        headers  -- :class:`Headers` (case-insensitive dict)
        body     -- raw body bytes
    """
    method:  str
    path:    str
    version: str
    headers: Headers
    body:    bytes

    def to_bytes(self) -> bytes:
        """
        Serialize back to raw bytes.
        If ``body`` is non-empty, ``Content-Length`` is updated automatically.
        """
        if self.body:
            self.headers["Content-Length"] = str(len(self.body))
        head = f"{self.method} {self.path} {self.version}\r\n"
        for k, v in self.headers.items():
            head += f"{k}: {v}\r\n"
        head += "\r\n"
        return head.encode() + self.body

    def __str__(self) -> str:
        return f"{self.method} {self.path} {self.version} ({len(self.body)} body bytes)"


@dataclass
class HttpResponse:
    """
    Parsed HTTP response.

    Attributes:
        version     -- "HTTP/1.1"
        status_code -- 200, 404, …
        status_text -- "OK", "Not Found", …
        headers     -- :class:`Headers` (case-insensitive dict)
        body        -- raw body bytes
    """
    version:     str
    status_code: int
    status_text: str
    headers:     Headers
    body:        bytes

    def to_bytes(self) -> bytes:
        """
        Serialize back to raw bytes.
        If ``body`` is non-empty, ``Content-Length`` is updated automatically.
        """
        if self.body:
            self.headers["Content-Length"] = str(len(self.body))
        head = f"{self.version} {self.status_code} {self.status_text}\r\n"
        for k, v in self.headers.items():
            head += f"{k}: {v}\r\n"
        head += "\r\n"
        return head.encode() + self.body

    def __str__(self) -> str:
        return f"{self.version} {self.status_code} {self.status_text} ({len(self.body)} body bytes)"


def http_request(payload: bytes) -> HttpRequest:
    """
    Parse raw HTTP request bytes into an :class:`HttpRequest`.

    Raises :class:`ValueError` if the first line is malformed.

    Example::

        def handle_http(meta, payload):
            if meta.direction == "request":
                req = http_request(payload)
                print(req.method, req.path)          # GET /index.html
                req.headers["X-Injected"] = "yes"
                return req.to_bytes()
            return payload
    """
    head_block, body = _split_head_body(payload)
    first_line = head_block.split(b"\n", 1)[0].rstrip(b"\r")
    parts = first_line.decode(errors="replace").split(None, 2)
    if len(parts) < 2:
        raise ValueError(f"Invalid HTTP request line: {first_line!r}")
    method  = parts[0]
    path    = parts[1]
    version = parts[2].strip() if len(parts) > 2 else "HTTP/1.0"
    headers = _parse_headers(head_block)
    return HttpRequest(method=method, path=path, version=version,
                       headers=headers, body=body)


def http_response(payload: bytes) -> HttpResponse:
    """
    Parse raw HTTP response bytes into an :class:`HttpResponse`.

    Raises :class:`ValueError` if the first line is malformed.

    Example::

        def handle_http(meta, payload):
            if meta.direction == "response":
                resp = http_response(payload)
                if resp.status_code == 200:
                    resp.body = resp.body.replace(b"foo", b"bar")
                return resp.to_bytes()   # Content-Length auto-updated
            return payload
    """
    head_block, body = _split_head_body(payload)
    first_line = head_block.split(b"\n", 1)[0].rstrip(b"\r")
    parts = first_line.decode(errors="replace").split(None, 2)
    if len(parts) < 2:
        raise ValueError(f"Invalid HTTP response line: {first_line!r}")
    version     = parts[0]
    status_code = int(parts[1])
    status_text = parts[2].strip() if len(parts) > 2 else ""
    headers = _parse_headers(head_block)
    return HttpResponse(version=version, status_code=status_code,
                        status_text=status_text, headers=headers, body=body)


# ── DNS ───────────────────────────────────────────────────────────────────────

_DNS_TYPE_NAMES: Dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


@dataclass
class DnsQuestion:
    """A single DNS question entry."""
    name:   str
    qtype:  int    # numeric QTYPE  (1 = A, 28 = AAAA, …)
    qclass: int    # numeric QCLASS (1 = IN)

    @property
    def type_name(self) -> str:
        """Human-readable type string, e.g. ``"A"``, ``"MX"``."""
        return _DNS_TYPE_NAMES.get(self.qtype, str(self.qtype))

    def __str__(self) -> str:
        return f"{self.name} {self.type_name}"


@dataclass
class DnsRecord:
    """A single DNS resource record (answer / authority / additional)."""
    name:   str
    rtype:  int
    rclass: int
    ttl:    int
    rdata:  bytes  # raw RDATA bytes

    @property
    def type_name(self) -> str:
        return _DNS_TYPE_NAMES.get(self.rtype, str(self.rtype))

    @property
    def address(self) -> Optional[str]:
        """
        Decoded IP address for **A** (type 1) and **AAAA** (type 28) records.
        Returns ``None`` for any other type.
        """
        if self.rtype == 1 and len(self.rdata) == 4:
            return socket.inet_ntoa(self.rdata)
        if self.rtype == 28 and len(self.rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, self.rdata)
        return None

    @property
    def text(self) -> Optional[str]:
        """Decoded string for **TXT** (type 16) records, ``None`` otherwise."""
        if self.rtype != 16 or not self.rdata:
            return None
        # TXT rdata: one or more length-prefixed strings
        parts, off = [], 0
        while off < len(self.rdata):
            ln = self.rdata[off]; off += 1
            parts.append(self.rdata[off:off + ln].decode(errors="replace"))
            off += ln
        return "".join(parts)

    def __str__(self) -> str:
        extra = self.address or self.text or self.rdata.hex()
        return f"{self.name} {self.type_name} TTL={self.ttl} {extra}"


@dataclass
class DnsMessage:
    """
    Parsed DNS message — works for both queries and responses.

    Attributes:
        transaction_id  -- 16-bit message ID
        flags           -- raw 16-bit flags word
        questions       -- list of :class:`DnsQuestion`
        answers         -- list of :class:`DnsRecord` (empty in queries)
        authority       -- list of :class:`DnsRecord`
        additional      -- list of :class:`DnsRecord`
    """
    transaction_id: int
    flags:          int
    questions:      List[DnsQuestion]  = field(default_factory=list)
    answers:        List[DnsRecord]    = field(default_factory=list)
    authority:      List[DnsRecord]    = field(default_factory=list)
    additional:     List[DnsRecord]    = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def is_query(self) -> bool:
        return not self.is_response

    @property
    def rcode(self) -> int:
        """Response code (lower 4 bits of flags). 0 = NOERROR."""
        return self.flags & 0x000F

    def to_bytes(self) -> bytes:
        """
        Serialize back to DNS wire format (labels are written without
        compression, which is valid but slightly larger than the original).
        """
        out = struct.pack(">HHHHHH",
            self.transaction_id, self.flags,
            len(self.questions), len(self.answers),
            len(self.authority), len(self.additional),
        )
        for q in self.questions:
            out += _dns_encode_name(q.name)
            out += struct.pack(">HH", q.qtype, q.qclass)
        for rr in (*self.answers, *self.authority, *self.additional):
            out += _dns_encode_name(rr.name)
            out += struct.pack(">HHIH", rr.rtype, rr.rclass, rr.ttl, len(rr.rdata))
            out += rr.rdata
        return out

    def __str__(self) -> str:
        kind = "response" if self.is_response else "query"
        qs = ", ".join(str(q) for q in self.questions)
        return f"DNS {kind} id={self.transaction_id:#06x} [{qs}]"


def _dns_read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Return ``(domain_name, offset_after_name)`` with pointer compression."""
    parts: List[str] = []
    end_offset = -1
    visited: set = set()
    for _ in range(128):               # guard against infinite loops
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:   # compression pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if end_offset == -1:
                end_offset = offset + 2
            if ptr in visited:
                break
            visited.add(ptr)
            offset = ptr
            continue
        offset += 1
        parts.append(data[offset:offset + length].decode(errors="replace"))
        offset += length
    return ".".join(parts), (end_offset if end_offset != -1 else offset)


def _dns_encode_name(name: str) -> bytes:
    """Encode a domain name as DNS wire-format labels (no compression)."""
    if not name or name == ".":
        return b"\x00"
    out = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode()
        out += bytes([len(enc)]) + enc
    return out + b"\x00"


def dns_message(payload: bytes) -> DnsMessage:
    """
    Parse raw DNS wire-format bytes into a :class:`DnsMessage`.

    Works for both queries (``meta.direction == "request"``) and
    responses (``meta.direction == "response"``).

    Raises :class:`ValueError` if the payload is too short.

    Example::

        def handle_dns(meta, payload):
            msg = dns_message(payload)
            for q in msg.questions:
                print(f"DNS {q.type_name} query for {q.name}")
            # block a specific domain
            if any(q.name == "evil.example.com" for q in msg.questions):
                msg.flags |= 0x8003   # QR=1, RCODE=NXDOMAIN
                return msg.to_bytes()
            return payload
    """
    if len(payload) < 12:
        raise ValueError(f"DNS payload too short ({len(payload)} bytes)")

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", payload[:12])
    offset = 12

    questions: List[DnsQuestion] = []
    for _ in range(qdcount):
        name, offset = _dns_read_name(payload, offset)
        if offset + 4 > len(payload):
            break
        qtype, qclass = struct.unpack(">HH", payload[offset:offset + 4])
        offset += 4
        questions.append(DnsQuestion(name=name, qtype=qtype, qclass=qclass))

    def _read_rrs(count: int) -> List[DnsRecord]:
        nonlocal offset
        rrs: List[DnsRecord] = []
        for _ in range(count):
            if offset >= len(payload):
                break
            name, offset = _dns_read_name(payload, offset)
            if offset + 10 > len(payload):
                break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", payload[offset:offset + 10])
            offset += 10
            rdata = payload[offset:offset + rdlen]
            offset += rdlen
            rrs.append(DnsRecord(name=name, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata))
        return rrs

    answers    = _read_rrs(ancount)
    authority  = _read_rrs(nscount)
    additional = _read_rrs(arcount)

    return DnsMessage(
        transaction_id=txid, flags=flags,
        questions=questions, answers=answers,
        authority=authority, additional=additional,
    )


# ── SMTP / POP3 ───────────────────────────────────────────────────────────────

@dataclass
class SmtpResponse:
    """
    Parsed SMTP (or POP3) server response, including multi-line responses.

    Attributes:
        code   -- numeric response code (220, 250, 550, …)
        lines  -- one string per continuation line (without the leading code)
    """
    code:  int
    lines: List[str]

    @property
    def text(self) -> str:
        """All lines joined with newline."""
        return "\n".join(self.lines)

    def to_bytes(self) -> bytes:
        """
        Serialize back to SMTP wire format.
        Multi-line responses use ``"NNN-text\\r\\n"`` for all but the last line,
        which uses ``"NNN text\\r\\n"``.
        """
        out = b""
        for i, line in enumerate(self.lines):
            sep = "-" if i < len(self.lines) - 1 else " "
            out += f"{self.code}{sep}{line}\r\n".encode()
        return out

    def __str__(self) -> str:
        return f"{self.code} {self.lines[0] if self.lines else ''}"


@dataclass
class SmtpCommand:
    """
    Parsed SMTP client command.

    Attributes:
        command  -- verb in uppercase, e.g. ``"EHLO"``, ``"MAIL"``, ``"QUIT"``
        args     -- everything after the verb (may be empty)
    """
    command: str
    args:    str

    def to_bytes(self) -> bytes:
        if self.args:
            return f"{self.command} {self.args}\r\n".encode()
        return f"{self.command}\r\n".encode()

    def __str__(self) -> str:
        return f"{self.command} {self.args}".strip()


def smtp_response(payload: bytes) -> SmtpResponse:
    """
    Parse a (possibly multi-line) SMTP server response.

    Raises :class:`ValueError` if the payload is empty or the code is not numeric.

    Example::

        def handle_smtp(meta, payload):
            if meta.direction == "response":
                resp = smtp_response(payload)
                if resp.code == 220:
                    resp.lines = ["mail.example.com Custom SMTP"]
                return resp.to_bytes()
            return payload
    """
    text = payload.decode(errors="replace")
    raw_lines = [l.rstrip("\r") for l in text.splitlines() if l.strip()]
    if not raw_lines:
        raise ValueError("Empty SMTP response")
    code = int(raw_lines[0][:3])
    lines = [l[4:] if len(l) > 4 else "" for l in raw_lines]
    return SmtpResponse(code=code, lines=lines)


def smtp_command(payload: bytes) -> SmtpCommand:
    """
    Parse an SMTP client command line.

    Example::

        def handle_smtp(meta, payload):
            if meta.direction == "request":
                cmd = smtp_command(payload)
                if cmd.command == "MAIL":
                    print(f"Mail from: {cmd.args}")
            return payload
    """
    text = payload.decode(errors="replace").strip()
    parts = text.split(None, 1)
    return SmtpCommand(
        command=parts[0].upper() if parts else "",
        args=parts[1] if len(parts) > 1 else "",
    )
