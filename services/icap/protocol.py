"""
ICAP protocol parser and response builder.

Implements RFC 3507 (ICAP) with support for REQMOD and RESPMOD.

Key objects:
  ICAPRequest  – parsed inbound ICAP request
  ICAPResponse – outbound ICAP response builder
"""
import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


# ICAP status codes
ICAP_CONTINUE  = 100
ICAP_OK        = 200
ICAP_NO_CONTENT = 204
ICAP_BAD_REQUEST = 400
ICAP_NOT_FOUND  = 404
ICAP_NOT_ALLOWED = 405
ICAP_TIMEOUT    = 408
ICAP_SERVER_ERR = 500
ICAP_NOT_IMPLEMENTED = 501
ICAP_SERVICE_OVERLOADED = 503

ICAP_STATUS_MESSAGES = {
    100: "Continue",
    200: "OK",
    204: "No Modifications Needed",
    400: "Bad Request",
    404: "ICAP Service Not Found",
    405: "Method Not Allowed For Service",
    408: "Request Timeout",
    500: "Internal Server Error",
    501: "Method Not Implemented",
    503: "Service Overloaded",
}

ICAP_VERSION = "ICAP/1.0"

CRLF = b"\r\n"
DOUBLE_CRLF = b"\r\n\r\n"


@dataclass
class ICAPRequest:
    method: str = ""
    uri: str = ""
    version: str = "ICAP/1.0"
    headers: Dict[str, str] = field(default_factory=dict)
    # The encapsulated HTTP request headers
    req_headers: Dict[str, str] = field(default_factory=dict)
    req_body: bytes = b""
    # The encapsulated HTTP response headers
    res_headers: Dict[str, str] = field(default_factory=dict)
    res_body: bytes = b""
    # Raw encapsulated section
    encapsulated_body: bytes = b""

    @property
    def service(self) -> str:
        """Extract service name from ICAP URI (e.g. icap://host/reqmod → reqmod)."""
        parts = self.uri.rstrip("/").split("/")
        return parts[-1].lower() if parts else ""

    @property
    def host(self) -> str:
        return self.headers.get("host", "")

    @property
    def preview_size(self) -> Optional[int]:
        v = self.headers.get("preview")
        if v is not None:
            try:
                return int(v)
            except ValueError:
                pass
        return None


def parse_icap_request(data: bytes) -> Tuple[Optional[ICAPRequest], int]:
    """
    Parse a raw ICAP request from bytes.
    Returns (ICAPRequest, bytes_consumed) or (None, 0) if incomplete.
    """
    # Find end of ICAP headers
    header_end = data.find(DOUBLE_CRLF)
    if header_end == -1:
        return None, 0

    header_section = data[:header_end]
    body_start = header_end + 4
    lines = header_section.split(CRLF)

    if not lines:
        return None, 0

    # Parse request line: METHOD uri ICAP/1.0
    request_line = lines[0].decode("utf-8", errors="replace").strip()
    parts = request_line.split(" ", 2)
    if len(parts) != 3:
        return None, body_start

    req = ICAPRequest(
        method=parts[0].upper(),
        uri=parts[1],
        version=parts[2],
    )

    # Parse ICAP headers
    for line in lines[1:]:
        text = line.decode("utf-8", errors="replace").strip()
        if ":" in text:
            k, _, v = text.partition(":")
            req.headers[k.strip().lower()] = v.strip()

    # Parse Encapsulated header to find encapsulated section offsets
    encapsulated = req.headers.get("encapsulated", "")
    offsets = _parse_encapsulated_offsets(encapsulated)
    body = data[body_start:]

    # Extract req-hdr
    if "req-hdr" in offsets:
        start = offsets["req-hdr"]
        end = offsets.get("req-body", offsets.get("res-hdr", offsets.get("res-body", len(body))))
        _parse_http_headers(body[start:end], req.req_headers)

    # Extract res-hdr
    if "res-hdr" in offsets:
        start = offsets["res-hdr"]
        end = offsets.get("res-body", len(body))
        _parse_http_headers(body[start:end], req.res_headers)

    # Extract request or response body (chunked-encoded per ICAP spec)
    body_key = "req-body" if "req-body" in offsets else "res-body" if "res-body" in offsets else None
    if body_key and body_key in offsets:
        body_data = body[offsets[body_key]:]
        req.encapsulated_body = _decode_chunked(body_data)

    return req, len(data)


def _parse_encapsulated_offsets(encapsulated: str) -> Dict[str, int]:
    offsets = {}
    for part in encapsulated.split(","):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            try:
                offsets[k.strip()] = int(v.strip())
            except ValueError:
                pass
    return offsets


def _parse_http_headers(data: bytes, target: Dict[str, str]) -> None:
    text = data.decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    for line in lines[1:]:  # Skip request/status line
        if ":" in line:
            k, _, v = line.partition(":")
            target[k.strip().lower()] = v.strip()


def _decode_chunked(data: bytes) -> bytes:
    """Decode chunked transfer encoding as used by ICAP body sections."""
    result = bytearray()
    pos = 0
    while pos < len(data):
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            break
        size_str = data[pos:line_end].decode("ascii", errors="replace").strip()
        if not size_str:
            break
        try:
            chunk_size = int(size_str, 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        chunk_start = line_end + 2
        result.extend(data[chunk_start:chunk_start + chunk_size])
        pos = chunk_start + chunk_size + 2  # skip trailing CRLF
    return bytes(result)


class ICAPResponseBuilder:
    """Builds ICAP response messages."""

    def options_response(self, service: str, methods: list) -> bytes:
        headers = {
            "Methods": ", ".join(methods),
            "Service": f"TI Platform ICAP {service.upper()} 1.0",
            "ISTag": '"TI-PLATFORM-001"',
            "Max-Connections": "100",
            "Options-TTL": "3600",
            "Allow": "204",
            "Preview": "0",
            "Transfer-Complete": "*",
            "Transfer-Ignore": "jpg,gif,png,ico,css,js,woff,woff2,ttf",
            "Transfer-Preview": "*",
        }
        return self._build(ICAP_OK, headers)

    def no_modification(self) -> bytes:
        """204 No Modifications Needed – passthrough without copying body."""
        return self._build(ICAP_NO_CONTENT, {"ISTag": '"TI-PLATFORM-001"'})

    def block_response(self, reason: str = "Threat Intelligence Match") -> bytes:
        """
        Return a 200 OK with a synthetic HTTP 403 response body.
        The proxy will serve this block page to the client.
        """
        block_html = (
            "<!DOCTYPE html><html><head><title>Access Blocked</title></head>"
            "<body><h1>Access Blocked</h1>"
            f"<p>This resource has been blocked by the Threat Intelligence Platform.</p>"
            f"<p>Reason: {reason}</p>"
            "</body></html>"
        ).encode()

        http_response = (
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Content-Length: " + str(len(block_html)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + block_html
        )

        body_offset = 0
        icap_headers = {
            "ISTag": '"TI-PLATFORM-001"',
            "Encapsulated": f"res-hdr=0, res-body={len(http_response) - len(block_html)}",
        }
        return self._build(ICAP_OK, icap_headers, body=http_response)

    def error_response(self, status: int = ICAP_SERVER_ERR) -> bytes:
        msg = ICAP_STATUS_MESSAGES.get(status, "Error")
        return self._build(status, {"ISTag": '"TI-PLATFORM-001"'})

    def _build(self, status: int, headers: Dict[str, str], body: bytes = b"") -> bytes:
        msg = ICAP_STATUS_MESSAGES.get(status, "Unknown")
        lines = [f"{ICAP_VERSION} {status} {msg}\r\n".encode()]

        # Standard headers
        import datetime
        lines.append(f"Date: {datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\n".encode())

        for k, v in headers.items():
            lines.append(f"{k}: {v}\r\n".encode())

        lines.append(b"\r\n")
        if body:
            lines.append(body)

        return b"".join(lines)
