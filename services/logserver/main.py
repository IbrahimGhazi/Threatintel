"""
TI Platform Log Server

Provides two ingest paths for external security devices:

  UDP 514  — Syslog (RFC 3164 + 5424 + CEF)
  TCP 514  — Syslog (same formats, stream-based)
  HTTP 9514 POST /ingest — JSON or plain-text log lines

All received logs are forwarded to the API for IOC extraction and TI matching.
"""
import asyncio
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from aiohttp import web
import aiohttp

from parsers import try_vendor_parse, try_netflow_parse

# ── Config ─────────────────────────────────────────────────────────────────────

API_URL      = os.getenv("API_URL", "http://api:8000")
API_KEY      = os.getenv("API_KEY", "")
UDP_PORT     = int(os.getenv("SYSLOG_UDP_PORT", "514"))
TCP_PORT     = int(os.getenv("SYSLOG_TCP_PORT", "514"))
HTTP_PORT    = int(os.getenv("LOGSERVER_HTTP_PORT", "9514"))
NETFLOW_PORT = int(os.getenv("NETFLOW_PORT", "2055"))
LOG_LEVEL    = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=LOG_LEVEL,
    format='{"time":"%(asctime)s","level":"%(levelname)s","service":"logserver","msg":"%(message)s"}',
    stream=sys.stdout,
)
log = logging.getLogger("logserver")

# ── Syslog parsing ─────────────────────────────────────────────────────────────

# RFC 3164: <PRI>TIMESTAMP HOSTNAME PROGRAM[PID]: MESSAGE
_RE_3164 = re.compile(
    r'^<(\d{1,3})>'
    r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(\S+)\s+'
    r'(?:([^\[:]+?)(?:\[(\d+)\])?:\s*)?'
    r'(.*)',
    re.DOTALL,
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
_RE_5424 = re.compile(
    r'^<(\d{1,3})>1\s+'
    r'(\S+)\s+'       # timestamp
    r'(\S+)\s+'       # hostname
    r'(\S+)\s+'       # app-name
    r'(\S+)\s+'       # procid
    r'(\S+)\s+'       # msgid
    r'(.*)',
    re.DOTALL,
)

# CEF: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
_RE_CEF = re.compile(r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)', re.DOTALL)


def parse_syslog(raw: str, source_ip: str) -> Dict[str, Any]:
    """Parse syslog message and return normalized dict.

    Processing order:
      1. Try vendor-specific parsers (Palo Alto, etc.) on the full raw message.
      2. Fall back to format-specific parsing (CEF → RFC 5424 → RFC 3164 → raw).
    """
    raw = raw.strip()

    # ── Phase 1: Try vendor-specific parsers first ──────────────────────
    # This handles Palo Alto CSV logs and other vendor formats that may
    # be embedded inside syslog wrappers.  Vendor parsers extract the
    # actual traffic src_ip, keeping device_ip as the syslog sender.
    vendor_result = try_vendor_parse(raw, source_ip)
    if vendor_result:
        real_src = vendor_result.get("src_ip")
        stype = "firewall"
        sname = vendor_result.get("hostname") or vendor_result.get("vendor") or source_ip
        return {
            "source_type": stype,
            "source_name": sname,
            "source_ip":   real_src or source_ip,
            "raw_log":     raw,
            "parsed":      vendor_result,
        }

    # ── Phase 2: Format-specific parsing ────────────────────────────────

    # CEF detection
    m = _RE_CEF.match(raw)
    if m:
        ext = _parse_cef_extension(m.group(8))
        # CEF src/dst fields: use CEF extension keys, fallback to extracted
        real_src = ext.get("src") or ext.get("sourceAddress")
        real_dst = ext.get("dst") or ext.get("destinationAddress")
        parsed_fields = {
            "format":     "CEF",
            "vendor":     m.group(2),
            "product":    m.group(3),
            "sig_id":     m.group(5),
            "event_name": m.group(6),
            "severity":   m.group(7),
            "device_ip":  source_ip,
            **ext,
        }
        if real_src:
            parsed_fields["src_ip"] = real_src
        if real_dst:
            parsed_fields["dst_ip"] = real_dst
        return {
            "source_type": "firewall",
            "source_name": m.group(2),          # vendor
            "source_ip":   real_src or source_ip,
            "raw_log":     raw,
            "parsed":      parsed_fields,
        }

    # RFC 5424
    m = _RE_5424.match(raw)
    if m:
        message = m.group(7).strip()
        stype = _guess_source_type(m.group(4))
        parsed_fields = {
            "format":    "RFC5424",
            "facility":  int(m.group(1)) >> 3,
            "severity":  int(m.group(1)) & 0x07,
            "timestamp": m.group(2),
            "hostname":  m.group(3),
            "appname":   m.group(4),
            "procid":    m.group(5),
            "message":   message,
            "device_ip": source_ip,
        }
        # Try vendor-specific parser on just the message body
        vendor_msg = try_vendor_parse(message, source_ip, parsed_fields)
        if vendor_msg:
            parsed_fields.update(vendor_msg)
            real_src = vendor_msg.get("src_ip")
            return {
                "source_type": "firewall",
                "source_name": m.group(3),
                "source_ip":   real_src or source_ip,
                "raw_log":     raw,
                "parsed":      parsed_fields,
            }
        # Extract real src/dst IPs from the message body (firewall-forwarded logs)
        fw_fields = _extract_fw_fields(message)
        parsed_fields.update(fw_fields)
        # Use extracted src_ip as the real source, not the forwarding device
        real_src = fw_fields.get("src_ip")
        return {
            "source_type": stype,
            "source_name": m.group(3),
            "source_ip":   real_src or source_ip,
            "raw_log":     raw,
            "parsed":      parsed_fields,
        }

    # RFC 3164
    m = _RE_3164.match(raw)
    if m:
        prog = m.group(4) or ""
        message = m.group(6).strip()
        stype = _guess_source_type(prog)
        parsed_fields = {
            "format":    "RFC3164",
            "facility":  int(m.group(1)) >> 3,
            "severity":  int(m.group(1)) & 0x07,
            "timestamp": m.group(2),
            "hostname":  m.group(3),
            "program":   prog,
            "pid":       m.group(5) or "",
            "message":   message,
            "device_ip": source_ip,
        }
        # Try vendor-specific parser on just the message body
        vendor_msg = try_vendor_parse(message, source_ip, parsed_fields)
        if vendor_msg:
            parsed_fields.update(vendor_msg)
            real_src = vendor_msg.get("src_ip")
            return {
                "source_type": "firewall",
                "source_name": m.group(3),
                "source_ip":   real_src or source_ip,
                "raw_log":     raw,
                "parsed":      parsed_fields,
            }
        # Extract real src/dst IPs from the message body
        fw_fields = _extract_fw_fields(message)
        parsed_fields.update(fw_fields)
        real_src = fw_fields.get("src_ip")
        return {
            "source_type": stype,
            "source_name": m.group(3),
            "source_ip":   real_src or source_ip,
            "raw_log":     raw,
            "parsed":      parsed_fields,
        }

    # Unknown — try to extract IPs from raw content
    fw_fields = _extract_fw_fields(raw)
    parsed_fields = {"format": "raw", "device_ip": source_ip}
    parsed_fields.update(fw_fields)
    real_src = fw_fields.get("src_ip")
    return {
        "source_type": "syslog",
        "source_name": None,
        "source_ip":   real_src or source_ip,
        "raw_log":     raw,
        "parsed":      parsed_fields,
    }


def _parse_cef_extension(ext: str) -> Dict[str, str]:
    """Parse CEF key=value extension string."""
    result = {}
    for m in re.finditer(r'(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)', ext):
        result[m.group(1)] = m.group(2).strip()
    return result


# ── Firewall log IP extraction ────────────────────────────────────────────────
# Common firewall formats embed real src/dst IPs in the message body.
# The socket peer (source_ip from UDP/TCP) is the firewall itself.

_RE_IP = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Named field patterns for src/dst extraction from firewall messages
_FW_SRC_PATTERNS = [
    re.compile(r'\bSRC\s*=\s*(' + _RE_IP.pattern + r')', re.I),
    re.compile(r'\bsrc(?:_ip|_addr|ip)?\s*[=:]\s*(' + _RE_IP.pattern + r')', re.I),
    re.compile(r'\bsource(?:_ip|_addr|Address)?\s*[=:]\s*(' + _RE_IP.pattern + r')', re.I),
    re.compile(r'\bclient(?:_ip|_addr)?\s*[=:]\s*(' + _RE_IP.pattern + r')', re.I),
    re.compile(r'\bfrom\s+(' + _RE_IP.pattern + r')', re.I),
]

_FW_DST_PATTERNS = [
    re.compile(r'\bDST\s*=\s*(' + _RE_IP.pattern + r')', re.I),
    re.compile(r'\bdst(?:_ip|_addr|ip)?\s*[=:]\s*(' + _RE_IP.pattern + r')', re.I),
    re.compile(r'\bdest(?:ination)?(?:_ip|_addr|Address)?\s*[=:]\s*(' + _RE_IP.pattern + r')', re.I),
    re.compile(r'\bserver(?:_ip|_addr)?\s*[=:]\s*(' + _RE_IP.pattern + r')', re.I),
    re.compile(r'\bto\s+(' + _RE_IP.pattern + r')', re.I),
]

_FW_SRC_PORT_PATTERNS = [
    re.compile(r'\bSPT\s*=\s*(\d{1,5})\b', re.I),
    re.compile(r'\bsrc_?port\s*[=:]\s*(\d{1,5})\b', re.I),
    re.compile(r'\bsource_?port\s*[=:]\s*(\d{1,5})\b', re.I),
    re.compile(r'\bsport\s*[=:]\s*(\d{1,5})\b', re.I),
]

_FW_DST_PORT_PATTERNS = [
    re.compile(r'\bDPT\s*=\s*(\d{1,5})\b', re.I),
    re.compile(r'\bdst_?port\s*[=:]\s*(\d{1,5})\b', re.I),
    re.compile(r'\bdest(?:ination)?_?port\s*[=:]\s*(\d{1,5})\b', re.I),
    re.compile(r'\bdport\s*[=:]\s*(\d{1,5})\b', re.I),
]

_FW_ACTION_PATTERN = re.compile(
    r'\b(allow(?:ed)?|deny|denied|block(?:ed)?|accept(?:ed)?|reject(?:ed)?|drop(?:ped)?|permit(?:ted)?|pass(?:ed)?)\b',
    re.I,
)

_FW_PROTO_PATTERN = re.compile(r'\bPROTO\s*=\s*(\w+)', re.I)


def _extract_fw_fields(message: str) -> Dict[str, Any]:
    """Extract real src/dst IPs and ports from firewall log message body."""
    fields: Dict[str, Any] = {}
    for pat in _FW_SRC_PATTERNS:
        m = pat.search(message)
        if m:
            fields["src_ip"] = m.group(1)
            break
    for pat in _FW_DST_PATTERNS:
        m = pat.search(message)
        if m:
            fields["dst_ip"] = m.group(1)
            break
    for pat in _FW_SRC_PORT_PATTERNS:
        m = pat.search(message)
        if m:
            fields["src_port"] = m.group(1)
            break
    for pat in _FW_DST_PORT_PATTERNS:
        m = pat.search(message)
        if m:
            fields["dst_port"] = m.group(1)
            break
    m = _FW_ACTION_PATTERN.search(message)
    if m:
        fields["action"] = m.group(1).lower()
    m = _FW_PROTO_PATTERN.search(message)
    if m:
        fields["protocol"] = m.group(1).lower()
    return fields


def _guess_source_type(program: str) -> str:
    prog = (program or "").lower()
    if any(k in prog for k in ("firewall", "fw", "iptables", "pf", "fortigate", "palo", "checkpoint")):
        return "firewall"
    if any(k in prog for k in ("squid", "proxy", "zscaler", "bluecoat", "mimecast")):
        return "proxy"
    if any(k in prog for k in ("edr", "sentinel", "defender", "crowdstrike", "carbon")):
        return "edr"
    if any(k in prog for k in ("mail", "smtp", "postfix", "exim", "exchange")):
        return "email"
    return "syslog"


# ── API forwarding ─────────────────────────────────────────────────────────────

async def forward_to_api(session: aiohttp.ClientSession, payload: Dict) -> None:
    try:
        async with session.post(
            f"{API_URL}/logs",
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            if resp.status not in (200, 202):
                body = await resp.text()
                log.warning("API ingest returned %d: %s", resp.status, body[:100])
    except Exception as exc:
        log.debug("Failed to forward log: %s", exc)


# ── UDP Syslog Server ──────────────────────────────────────────────────────────

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, session: aiohttp.ClientSession):
        self._session = session

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        try:
            raw = data.decode("utf-8", errors="replace")
            source_ip = addr[0]
            try:
                payload = parse_syslog(raw, source_ip)
            except Exception as exc:
                log.warning("Syslog parse failed, forwarding as raw: %s", exc)
                payload = {
                    "source_type": "syslog",
                    "source_name": None,
                    "source_ip": source_ip,
                    "raw_log": raw,
                    "parsed": {"format": "raw", "device_ip": source_ip, "parse_error": str(exc)},
                }
            asyncio.ensure_future(forward_to_api(self._session, payload))
        except Exception as exc:
            log.debug("UDP receive error: %s", exc)

    def error_received(self, exc):
        log.debug("UDP error: %s", exc)


# ── UDP NetFlow Server ────────────────────────────────────────────────────────

class NetflowUDPProtocol(asyncio.DatagramProtocol):
    """Receive Cisco NetFlow v5/v9 datagrams and forward each flow record to the API."""

    def __init__(self, session: aiohttp.ClientSession):
        self._session = session

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        try:
            device_ip = addr[0]
            records = try_netflow_parse(data, device_ip)
            if records is None:
                log.debug("Non-NetFlow UDP packet from %s (ignored)", device_ip)
                return
            if not records:
                log.debug("NetFlow packet from %s contained 0 parseable records", device_ip)
                return

            log.debug("NetFlow: %d flow records from %s", len(records), device_ip)
            for rec in records:
                payload = {
                    "source_type": "netflow",
                    "source_name": device_ip,
                    "source_ip":   rec.get("src_ip", device_ip),
                    "raw_log":     json.dumps(rec),
                    "parsed":      rec,
                }
                asyncio.ensure_future(forward_to_api(self._session, payload))
        except Exception as exc:
            log.debug("NetFlow receive error: %s", exc)

    def error_received(self, exc):
        log.debug("NetFlow UDP error: %s", exc)


# ── TCP Syslog Server ──────────────────────────────────────────────────────────

async def handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    session: aiohttp.ClientSession,
):
    peer = writer.get_extra_info("peername", ("unknown", 0))
    source_ip = peer[0]
    try:
        buffer = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=60)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                raw     = line.decode("utf-8", errors="replace").strip()
                if raw:
                    payload = parse_syslog(raw, source_ip)
                    await forward_to_api(session, payload)
    except asyncio.TimeoutError:
        pass
    except Exception as exc:
        log.debug("TCP client error: %s", exc)
    finally:
        writer.close()


# ── HTTP Ingest Server ─────────────────────────────────────────────────────────

async def handle_http(request: aiohttp.web.Request, session: aiohttp.ClientSession):
    """
    POST /ingest  — accepts JSON body or plain-text log lines.

    JSON body: {"source_type": "...", "source_name": "...", "raw_log": "..."}
    Plain text: one log line per request
    """
    source_ip = request.remote or "unknown"

    content_type = request.content_type or ""
    try:
        if "json" in content_type:
            body    = await request.json()
            payload = {
                "source_type": body.get("source_type", "http"),
                "source_name": body.get("source_name"),
                "source_ip":   body.get("source_ip") or source_ip,
                "raw_log":     body.get("raw_log") or json.dumps(body),
                "parsed":      body.get("parsed"),
            }
        else:
            raw     = await request.text()
            payload = parse_syslog(raw.strip(), source_ip)

        await forward_to_api(session, payload)
        return aiohttp.web.Response(text='{"status":"accepted"}', content_type="application/json")
    except Exception as exc:
        log.error("HTTP ingest error: %s", exc)
        return aiohttp.web.Response(
            status=500, text=f'{{"error":"{exc}"}}', content_type="application/json"
        )


# ── Main ───────────────────────────────────────────────────────────────────────

async def main():
    session = aiohttp.ClientSession()

    loop = asyncio.get_event_loop()

    # UDP 514
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(session),
            local_addr=("0.0.0.0", UDP_PORT),
        )
        log.info("Syslog UDP listener on :%d", UDP_PORT)
    except PermissionError:
        log.warning("Cannot bind UDP %d (permission denied — run as root or use port > 1024)", UDP_PORT)
        transport = None
    except Exception as exc:
        log.warning("UDP listener failed: %s", exc)
        transport = None

    # TCP 514
    try:
        tcp_server = await asyncio.start_server(
            lambda r, w: handle_tcp_client(r, w, session),
            "0.0.0.0", TCP_PORT,
        )
        log.info("Syslog TCP listener on :%d", TCP_PORT)
    except PermissionError:
        log.warning("Cannot bind TCP %d (permission denied)", TCP_PORT)
        tcp_server = None
    except Exception as exc:
        log.warning("TCP listener failed: %s", exc)
        tcp_server = None

    # NetFlow UDP 2055
    netflow_transport = None
    try:
        netflow_transport, _ = await loop.create_datagram_endpoint(
            lambda: NetflowUDPProtocol(session),
            local_addr=("0.0.0.0", NETFLOW_PORT),
        )
        log.info("NetFlow UDP listener on :%d", NETFLOW_PORT)
    except PermissionError:
        log.warning("Cannot bind NetFlow UDP %d (permission denied — run as root or use port > 1024)", NETFLOW_PORT)
    except Exception as exc:
        log.warning("NetFlow UDP listener failed: %s", exc)

    # HTTP 9514
    app = web.Application()
    app.router.add_post("/ingest", lambda req: handle_http(req, session))
    app.router.add_get("/health",  lambda _: aiohttp.web.Response(text='{"status":"ok"}'))

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site   = aiohttp.web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    log.info("HTTP ingest listener on :%d/ingest", HTTP_PORT)

    log.info(
        "Log server ready — UDP:%d  TCP:%d  HTTP:%d  NetFlow:%d",
        UDP_PORT, TCP_PORT, HTTP_PORT, NETFLOW_PORT,
    )

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("Shutting down log server")
    finally:
        await session.close()
        if transport:
            transport.close()
        if netflow_transport:
            netflow_transport.close()
        if tcp_server:
            tcp_server.close()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
