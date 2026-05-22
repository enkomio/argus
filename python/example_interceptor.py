"""
Argus ForwardTo example — uses argus_interceptor library.

Demonstrates how to intercept and modify HTTP responses and DNS queries
with minimal boilerplate.  Edit the handler functions below to suit your
analysis needs.

Usage
─────
    python example_interceptor.py [--host 0.0.0.0] [--port 9999] [--debug]

Then add to configs/default.ini inside any listener section:
    ForwardTo: 127.0.0.1:9999
"""

import argparse
import logging
import re

from argus_interceptor import (
    Meta, create_interceptor,
    http_request, http_response,
    dns_message,
    smtp_response, smtp_command,
)

logging.basicConfig(
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger("interceptor")

# ── Handlers ──────────────────────────────────────────────────────────────────

def handle_http(meta: Meta, payload: bytes) -> bytes:
    """Intercept HTTP and HTTPS traffic."""

    if meta.direction == "request":
        try:
            req = http_request(payload)
            log.info("[HTTP req]  %s  →  %s %s", meta.process, req.method, req.path)
        except ValueError:
            log.info("[HTTP req]  %s  (unparseable)", meta.process)

    if meta.direction == "response":
        try:
            resp = http_response(payload)
            new_body, n = re.subn(
                rb"(<title[^>]*>)(.*?)(</title>)",
                rb"\1\2 - INTERCEPTED\3",
                resp.body,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if n:
                resp.body = new_body
                log.info("[HTTP rsp]  %s %s  title tag patched",
                         resp.status_code, resp.status_text)
                return resp.to_bytes()   # Content-Length updated automatically
            log.info("[HTTP rsp]  %s %s  (%d bytes)",
                     resp.status_code, resp.status_text, len(resp.body))
        except ValueError:
            log.info("[HTTP rsp]  %s  (unparseable)", meta.process)

    return payload


def handle_dns(meta: Meta, payload: bytes) -> bytes:
    """Intercept DNS queries and responses."""
    try:
        msg = dns_message(payload)
        if msg.is_query:
            for q in msg.questions:
                log.info("[DNS  req]  %s  →  %s %s", meta.process, q.type_name, q.name)
        else:
            for a in msg.answers:
                log.info("[DNS  rsp]  %s", a)
    except (ValueError, Exception):
        pass

    return payload  # pass through unchanged


def handle_smtp(meta: Meta, payload: bytes) -> bytes:
    """Log SMTP commands and responses."""
    try:
        if meta.direction == "response":
            resp = smtp_response(payload)
            log.info("[SMTP rsp]  %s", resp)
        else:
            cmd = smtp_command(payload)
            log.info("[SMTP cmd]  %s  →  %s", meta.process, cmd)
    except (ValueError, Exception):
        pass
    return payload


def handle_raw(meta: Meta, payload: bytes) -> bytes:
    """Hex-dump raw TCP/UDP traffic."""
    log.info("[RAW  %s]  %s  %d bytes  %s",
             meta.direction[:3], meta.process, len(payload),
             payload[:32].hex(" "))
    return payload


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argus ForwardTo example interceptor")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    interceptor = create_interceptor(
        host=args.host,
        port=args.port,
        http_handler=handle_http,
        https_handler=handle_http,   # reuse the same handler for HTTPS
        dns_handler=handle_dns,
        smtp_handler=handle_smtp,
        raw_handler=handle_raw,
    )
    interceptor.serve()
