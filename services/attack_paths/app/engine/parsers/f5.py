"""
F5 BIG-IP `bigip.conf` parser.

Parses the brace-delimited TMOS config syntax for the LTM objects we care
about for path analysis:

  ltm virtual <name> { destination <ip>:<port>  ip-protocol <p>  pool <pool>  ... }
  ltm pool    <name> { load-balancing-mode <m>  members { <m1>:<port> { ... } ... } }
  ltm node    <name> { address <ip>  ... }                 (members can reference nodes)
  ltm monitor <type> <name> { ... }
  ltm nat     <name> { translation-address <ip>  originating-address <ip>  ... }

Tested against TMOS 15.x/16.x exports. Stanza scanning is parenthesis-aware
so deeply nested configs don't confuse the top-level scanner.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from app.engine.ir import (
    DeviceConfig,
    Device,
    HealthMonitor,
    NatRule,
    ParseWarning,
    Pool,
    PoolMember,
    SourceRef,
    VIP,
)

log = logging.getLogger(__name__)

_DEST_RE = re.compile(
    r"^\s*destination\s+"
    r"(?P<addr>[\d\.]+|[a-fA-F\d:]+)"           # IPv4 or IPv6
    r":(?P<port>\d+|[A-Za-z][\w\-]*|\*)"        # numeric port, service name, or '*'
    r"\s*$"
)
_ALT_DEST_RE = _DEST_RE                          # alias kept for backward compat

# F5 BIG-IP renders well-known ports by IANA service name in `destination`
# fields. We need a numeric port for the VIP node + EXPOSES edge, so resolve
# common names here. Anything unknown gets warned + skipped.
_F5_SERVICE_PORTS = {
    "*": 0, "any": 0,
    "http": 80, "https": 443, "ftp": 21, "ftp-data": 20, "ssh": 22,
    "telnet": 23, "smtp": 25, "domain": 53, "tftp": 69, "http-alt": 8080,
    "kerberos": 88, "pop3": 110, "rpcbind": 111, "imap": 143, "snmp": 161,
    "snmptrap": 162, "ldap": 389, "https-alt": 8443, "smtps": 465,
    "syslog": 514, "rip": 520, "ldaps": 636, "msdp": 639, "imaps": 993,
    "pop3s": 995, "msft-gc": 3268, "mssql": 1433, "ms-sql-s": 1433,
    "oracle": 1521, "nfs": 2049, "mysql": 3306, "rdp": 3389, "ms-wbt-server": 3389,
    "postgres": 5432, "postgresql": 5432, "amqp": 5672, "vnc": 5900,
    "redis": 6379, "memcache": 11211, "mongo": 27017,
    # F5-specific aliases occasionally seen
    "tcp-domain": 53, "tcp-https": 443, "tcp-http": 80,
}


def _resolve_port(token: str) -> Optional[int]:
    """Return an int port for `token` (numeric, service-name, or '*')."""
    if not token:
        return None
    try:
        return int(token)
    except ValueError:
        return _F5_SERVICE_PORTS.get(token.lower())
_MEMBER_HEAD_RE = re.compile(
    r"(?m)^\s*(?P<name>[A-Za-z_][\w\-.]*):"
    r"(?P<port>\d+|[a-zA-Z][\w\-]*|\*)\s*\{"
)
_NODE_ADDR_RE = re.compile(r"^\s*address\s+(?P<addr>[\d\.:a-fA-F]+)\s*$")
_TRANSLATION_RE = re.compile(r"^\s*translation-address\s+(?P<addr>[\d\.:a-fA-F]+)\s*$")
_ORIGINATING_RE = re.compile(r"^\s*originating-address\s+(?P<addr>[\d\.:a-fA-F]+)\s*$")
_LB_MODE_RE = re.compile(r"^\s*load-balancing-mode\s+(?P<mode>\S+)\s*$")
_PROTO_RE = re.compile(r"^\s*ip-protocol\s+(?P<proto>\S+)\s*$")
_POOL_REF_RE = re.compile(r"^\s*pool\s+(?P<pool>\S+)\s*$")
_STATE_RE = re.compile(r"^\s*state\s+(?P<state>\S+)\s*$")
_SESSION_RE = re.compile(r"^\s*session\s+(?P<session>\S+)\s*$")


def parse_f5_config(path: str | Path, *,
                    hostname_hint: Optional[str] = None) -> List[DeviceConfig]:
    """
    Parse a single bigip.conf. Returns a list with a single DeviceConfig
    (F5 has no vsys equivalent — one config = one logical device).
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.error("F5 config read failed for %s: %s", path, exc)
        return []

    hostname = hostname_hint or path.stem
    device_id = f"{hostname}:default"

    cfg = DeviceConfig(
        device=Device(
            id=device_id,
            vendor="f5",
            role="loadbalancer",
            hostname=hostname,
            source_ref=SourceRef(file=str(path)),
        ),
    )

    # node name → IP map; populated first so pool members can resolve.
    node_addr: Dict[str, str] = {}

    for header, body, line_no in _iter_top_level_stanzas(text):
        try:
            if header.startswith("ltm node "):
                _parse_node(header, body, node_addr)
            elif header.startswith("ltm pool "):
                _parse_pool(header, body, line_no, device_id, str(path),
                            node_addr, cfg)
            elif header.startswith("ltm virtual "):
                _parse_virtual(header, body, line_no, device_id, str(path), cfg)
            elif header.startswith("ltm nat "):
                _parse_nat(header, body, line_no, device_id, str(path), cfg)
            elif header.startswith("ltm monitor "):
                _parse_monitor(header, body, line_no, device_id, str(path), cfg)
        except Exception as exc:                                # noqa: BLE001
            cfg.warnings.append(ParseWarning(
                file=str(path), line=line_no, severity="warn",
                message=f"stanza '{header.strip()}' parse skipped: {exc}",
            ))
    return [cfg]


# ── Stanza scanner ────────────────────────────────────────────────────────────

def _iter_top_level_stanzas(text: str) -> Iterator[Tuple[str, str, int]]:
    """
    Yield (header, body, line_number) for every top-level stanza.
    Header is the text before the opening '{'. Body excludes the braces.
    Counts braces to find the matching close even with nested stanzas.
    """
    i = 0
    n = len(text)
    line = 1
    while i < n:
        # Skip whitespace and comments
        if text[i] in " \t":
            i += 1; continue
        if text[i] == "\n":
            line += 1; i += 1; continue
        if text[i] == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue

        # Read header up to '{' or newline (some stanzas may be one-liners).
        start = i
        header_line = line
        while i < n and text[i] != "{" and text[i] != "\n":
            i += 1
        if i >= n:
            break
        if text[i] == "\n":
            line += 1
            i += 1
            continue
        header = text[start:i]
        # consume '{'
        i += 1
        depth = 1
        body_start = i
        while i < n and depth > 0:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            elif c == "\n":
                line += 1
            i += 1
        body = text[body_start:i]
        # consume '}'
        if i < n:
            i += 1
        yield header, body, header_line


def _scan_inner(body: str, head_re: re.Pattern[str]) -> Iterator[Tuple[re.Match[str], str]]:
    """Yield (match-of-head, inner-body) for nested stanzas inside a body."""
    i = 0
    n = len(body)
    while i < n:
        m = head_re.search(body, i)
        if not m:
            return
        # find matching '{'
        brace = body.find("{", m.start())
        if brace < 0:
            return
        depth = 1
        j = brace + 1
        while j < n and depth > 0:
            c = body[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            j += 1
            if depth == 0:
                break
        yield m, body[brace + 1:j - 1]
        i = j


# ── Stanza handlers ───────────────────────────────────────────────────────────

def _parse_node(header: str, body: str, node_addr: Dict[str, str]) -> None:
    parts = header.strip().split()
    if len(parts) < 3:
        return
    name = parts[2]
    for line in body.splitlines():
        m = _NODE_ADDR_RE.match(line)
        if m:
            node_addr[name] = m.group("addr")
            return


def _parse_pool(header: str, body: str, line_no: int, device_id: str,
                file: str, node_addr: Dict[str, str], cfg: DeviceConfig) -> None:
    parts = header.strip().split()
    if len(parts) < 3:
        return
    name = parts[2]
    lb_mode = "round-robin"

    for line in body.splitlines():
        m = _LB_MODE_RE.match(line)
        if m:
            lb_mode = m.group("mode")
            break

    members: List[PoolMember] = []
    # Members live under `members { name:port { addr ... } ... }`
    # We scan for the inner stanzas keyed by NAME:PORT { ... }.
    members_block_match = re.search(r"members\s*\{", body)
    if members_block_match:
        # Slice to the members block
        start = members_block_match.end()
        depth = 1
        j = start
        while j < len(body) and depth > 0:
            c = body[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            j += 1
            if depth == 0:
                break
        members_body = body[start:j - 1]

        for m, inner in _scan_inner(members_body, _MEMBER_HEAD_RE):
            mname = m.group("name")
            mport_resolved = _resolve_port(m.group("port"))
            if mport_resolved is None:
                cfg.warnings.append(ParseWarning(
                    file=file, line=line_no,
                    message=(f"pool '{name}' member '{mname}' has unknown "
                             f"service '{m.group('port')}' — skipping"),
                ))
                continue
            mport = mport_resolved
            # Resolve node-ref to IP if necessary
            address = node_addr.get(mname, mname)
            state = "unknown"
            for line in inner.splitlines():
                ms = _STATE_RE.match(line)
                if ms:
                    state = ms.group("state")
                    break
                msession = _SESSION_RE.match(line)
                if msession:
                    state = msession.group("session")
            members.append(PoolMember(
                address=address, port=mport, monitor_state=state,
            ))

    cfg.pools.append(Pool(
        device_id=device_id, name=name, lb_method=lb_mode, members=members,
        source_ref=SourceRef(file=file, line=line_no),
    ))


def _parse_virtual(header: str, body: str, line_no: int, device_id: str,
                   file: str, cfg: DeviceConfig) -> None:
    parts = header.strip().split()
    if len(parts) < 3:
        return
    name = parts[2]
    address: Optional[str] = None
    port: Optional[int] = None
    proto = "tcp"
    pool_name: Optional[str] = None

    raw_port: Optional[str] = None
    for line in body.splitlines():
        m = _DEST_RE.match(line)
        if m:
            address = m.group("addr")
            raw_port = m.group("port")
            port = _resolve_port(raw_port)
            continue
        m2 = _PROTO_RE.match(line)
        if m2:
            proto = m2.group("proto")
            continue
        m3 = _POOL_REF_RE.match(line)
        if m3:
            pool_name = m3.group("pool")
            continue

    if not address:
        cfg.warnings.append(ParseWarning(
            file=file, line=line_no,
            message=f"virtual '{name}' missing destination address",
        ))
        return
    if port is None:
        cfg.warnings.append(ParseWarning(
            file=file, line=line_no,
            message=(f"virtual '{name}' has unrecognised service '{raw_port}' — "
                     f"add to _F5_SERVICE_PORTS in parsers/f5.py"),
        ))
        return
    cfg.vips.append(VIP(
        device_id=device_id, name=name,
        address=address, port=port, protocol=proto,
        pool_name=pool_name,
        source_ref=SourceRef(file=file, line=line_no),
    ))


def _parse_nat(header: str, body: str, line_no: int, device_id: str,
               file: str, cfg: DeviceConfig) -> None:
    parts = header.strip().split()
    if len(parts) < 3:
        return
    name = parts[2]
    pre = None
    post = None
    for line in body.splitlines():
        m = _ORIGINATING_RE.match(line)
        if m:
            pre = m.group("addr")
            continue
        m2 = _TRANSLATION_RE.match(line)
        if m2:
            post = m2.group("addr")
            continue
    cfg.nat_rules.append(NatRule(
        device_id=device_id, name=name, position=len(cfg.nat_rules) + 1,
        kind="snat", pre_src=pre, post_src=post,
        source_ref=SourceRef(file=file, line=line_no),
    ))


def _parse_monitor(header: str, body: str, line_no: int, device_id: str,
                   file: str, cfg: DeviceConfig) -> None:
    parts = header.strip().split()
    if len(parts) < 4:
        return
    mtype = parts[2]
    name = parts[3]
    cfg.monitors.append(HealthMonitor(
        device_id=device_id, name=name, type=mtype,
        source_ref=SourceRef(file=file, line=line_no),
    ))
