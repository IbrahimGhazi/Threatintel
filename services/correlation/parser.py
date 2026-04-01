"""
Log parser – extracts structured fields and IOC indicators from log entries.

Supports common log formats from firewalls, proxies, Windows event logs,
EDR agents, and syslog sources.
Extraction is regex-based with validation to minimise false positives.
"""
import ipaddress
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import tldextract

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
URL_PATTERN = re.compile(r"https?://[^\s'\"<>|,;]+", re.IGNORECASE)
MD5_PATTERN = re.compile(r"\b[0-9a-fA-F]{32}\b")
SHA1_PATTERN = re.compile(r"\b[0-9a-fA-F]{40}\b")
SHA256_PATTERN = re.compile(r"\b[0-9a-fA-F]{64}\b")

_IP = IP_PATTERN.pattern

USERNAME_PATTERNS: List[re.Pattern] = [
    re.compile(r"Account\s+Name\s*:\s*(\S+)", re.I),
    re.compile(r"Invalid\s+user\s+(\S+)", re.I),
    re.compile(r"(?:Accepted|Failed)\s+\S+\s+for\s+(\S+)\s+from", re.I),
    re.compile(r"(?:user|username)\s*[=:]\s*([^\s,;\"'>\]]+)", re.I),
    re.compile(r"for\s+user\s+(\S+)", re.I),
    re.compile(r"Logon\s+User\s*:\s*(\S+)", re.I),
    re.compile(r"uid=\d+\((\w+)\)", re.I),
    re.compile(r"\bsu\b.*?\bto\s+(\S+)", re.I),
]

SRC_PORT_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bS(?:RC_)?P(?:ORT|T)\s*[=:]\s*(\d{1,5})\b", re.I),
    re.compile(r"\bsport\s*[=:]\s*(\d{1,5})\b", re.I),
    re.compile(r"\bsrc_port\s*[=:]\s*(\d{1,5})\b", re.I),
    re.compile(r"\bsource_port\s*[=:]\s*(\d{1,5})\b", re.I),
]

DST_PORT_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bD(?:ST_)?P(?:ORT|T)\s*[=:]\s*(\d{1,5})\b", re.I),
    re.compile(r"\bdport\s*[=:]\s*(\d{1,5})\b", re.I),
    re.compile(r"\bdst_port\s*[=:]\s*(\d{1,5})\b", re.I),
    re.compile(r"\bdest(?:ination)?_port\s*[=:]\s*(\d{1,5})\b", re.I),
    re.compile(r"\bport\s*[=:]\s*(\d{1,5})\b", re.I),
]

IP_PORT_PATTERN = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b")

SRC_IP_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bSRC\s*=\s*(" + _IP + r")", re.I),
    re.compile(r"\bsrc(?:_ip|_addr)?\s*[=:]\s*(" + _IP + r")", re.I),
    re.compile(r"\bfrom\s+(" + _IP + r")", re.I),
    re.compile(r"\bclient(?:_ip|_addr)?\s*[=:]\s*(" + _IP + r")", re.I),
    re.compile(r"\bremote(?:_ip|_addr)?\s*[=:]\s*(" + _IP + r")", re.I),
    re.compile(r"\bsource(?:_ip|_addr)?\s*[=:]\s*(" + _IP + r")", re.I),
]

DST_IP_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bDST\s*=\s*(" + _IP + r")", re.I),
    re.compile(r"\bdst(?:_ip|_addr)?\s*[=:]\s*(" + _IP + r")", re.I),
    re.compile(r"\bdest(?:ination)?(?:_ip|_addr)?\s*[=:]\s*(" + _IP + r")", re.I),
    re.compile(r"\bto\s+(" + _IP + r")", re.I),
    re.compile(r"\bserver(?:_ip|_addr)?\s*[=:]\s*(" + _IP + r")", re.I),
]

PROCESS_PATTERNS: List[re.Pattern] = [
    re.compile(r"Process\s+(?:Name|Image)\s*:\s*(\S+)", re.I),
    re.compile(r"(?:Image|Exec(?:utable)?)\s*[=:]\s*([^\s,;'\"]+)", re.I),
    re.compile(r"(?:process|proc)\s*[=:]\s*([^\s,;'\"]+)", re.I),
    re.compile(r"^([\w][\w\-\.]+)\[\d+\]:", re.MULTILINE),
]

HOSTNAME_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bhostname\s*[=:]\s*([^\s,;\"']+)", re.I),
    re.compile(r"\bhost\s*[=:]\s*([^\s,;\"']+)", re.I),
    re.compile(r"\bcomputername\s*[=:]\s*([^\s,;\"']+)", re.I),
    re.compile(r"\bdevice\s*[=:]\s*([^\s,;\"']+)", re.I),
]

PROTOCOL_PATTERN = re.compile(r"\b(tcp|udp|icmp|http|https|dns|rdp|ssh|smb|winrm)\b", re.I)

ACTION_PATTERN = re.compile(
    r"\b(allow(?:ed)?|deny|denied|block(?:ed)?|accept(?:ed)?|reject(?:ed)?|drop(?:ped)?|permit(?:ted)?|pass(?:ed)?)\b",
    re.I,
)
STATUS_PATTERN = re.compile(
    r"\b(success(?:ful(?:ly)?)?|fail(?:ed|ure)?|error|timeout|refused|reset|invalid)\b",
    re.I,
)
BYTES_PATTERN = re.compile(
    r"(?:bytes?_?(?:sent|out|transferred|written)|sent|transferred)\s*[=:]\s*(\d+)",
    re.I,
)

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("240.0.0.0/4"),
]

ALLOWLISTED_DOMAINS = {
    "localhost",
    "local",
    "internal",
    "corp",
    "lan",
    "example.com",
    "example.org",
    "example.net",
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "windowsazure.com",
    "apple.com",
    "icloud.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "akamai.com",
    "akamaiedge.net",
    "cloudflare.com",
    "cloudflare-dns.com",
    "amazonaws.com",
    "azure.com",
    "azureedge.net",
    "office365.com",
    "office.com",
    "live.com",
    "msedge.net",
}

# Well-known infrastructure IPs that should never trigger TI alerts.
# These are public DNS resolvers, CDN anycast IPs, and cloud provider IPs
# that commonly appear in logs and would generate false positives.
ALLOWLISTED_IPS = {
    # Google Public DNS
    "8.8.8.8",
    "8.8.4.4",
    # Cloudflare DNS
    "1.1.1.1",
    "1.0.0.1",
    # Quad9 DNS
    "9.9.9.9",
    "149.112.112.112",
    # OpenDNS / Cisco Umbrella
    "208.67.222.222",
    "208.67.220.220",
    # Comodo Secure DNS
    "8.26.56.26",
    "8.20.247.20",
    # Verisign DNS
    "64.6.64.6",
    "64.6.65.6",
    # Level3 / CenturyLink DNS
    "4.2.2.1",
    "4.2.2.2",
    # CleanBrowsing DNS
    "185.228.168.9",
    "185.228.169.9",
    # AdGuard DNS
    "94.140.14.14",
    "94.140.15.15",
    # NTP pool common IPs (time.google.com, time.windows.com anycast)
    "216.239.35.0",
    "216.239.35.4",
    "216.239.35.8",
    "216.239.35.12",
}

# CIDR ranges for well-known infrastructure that should not trigger TI alerts
ALLOWLISTED_CIDRS = [
    ipaddress.ip_network("8.8.8.0/24"),         # Google DNS
    ipaddress.ip_network("1.1.1.0/24"),          # Cloudflare DNS
    ipaddress.ip_network("1.0.0.0/24"),          # Cloudflare DNS
    ipaddress.ip_network("9.9.9.0/24"),          # Quad9
]

# Known network device IPs (firewalls, routers, switches) that forward logs to
# this platform. These IPs should NEVER appear as src_ip in behavioral rules —
# they are log forwarders, not attackers.
# Populated from env var KNOWN_DEVICE_IPS (comma-separated).
# Example: KNOWN_DEVICE_IPS=192.168.3.19,10.0.0.1
KNOWN_DEVICE_IPS: Set[str] = set(
    ip.strip()
    for ip in os.getenv("KNOWN_DEVICE_IPS", "").split(",")
    if ip.strip()
)


def is_allowlisted_ip(ip_str: str) -> bool:
    """Check if an IP is a known infrastructure IP that should not trigger TI alerts."""
    if ip_str in ALLOWLISTED_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in ALLOWLISTED_CIDRS)
    except ValueError:
        return False


def is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    domain = domain.lower()
    for allow in ALLOWLISTED_DOMAINS:
        if domain == allow or domain.endswith("." + allow):
            return False
    ext = tldextract.extract(domain)
    return bool(ext.domain and ext.suffix and len(ext.suffix) >= 2)


def _first_match(patterns: List[re.Pattern], text: str) -> Optional[str]:
    for pat in patterns:
        match = pat.search(text)
        if match:
            return match.group(1)
    return None


def _valid_port(val: Optional[Any]) -> Optional[int]:
    if val is None:
        return None
    try:
        port = int(val)
        return port if 1 <= port <= 65535 else None
    except (TypeError, ValueError):
        return None


def _normalize_timestamp(value: Optional[Any]) -> float:
    if value is None:
        return time.time()
    if isinstance(value, (float, int)):
        return float(value)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return time.time()
        try:
            return float(raw)
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return time.time()
    return time.time()


@dataclass
class ParsedLog:
    log_id: str
    raw: str
    source_type: str
    timestamp: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    program: Optional[str] = None
    file_path: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    protocol: Optional[str] = None
    bytes_out: Optional[int] = None
    iocs: List[Tuple[str, str]] = field(default_factory=list)


class LogParser:
    """Extracts structured fields and IOC indicators from log entries."""

    def parse(
        self,
        log_id: str,
        raw_log: str = "",
        parsed: Dict[str, Any] = None,
        source_type: str = "unknown",
        timestamp: float = None,
    ) -> ParsedLog:
        parsed = parsed or {}
        text = raw_log or ""
        ts = _normalize_timestamp(timestamp or parsed.get("timestamp"))

        extra: List[str] = []
        for field_name in (
            "src_ip",
            "dst_ip",
            "url",
            "domain",
            "sha256",
            "md5",
            "file_hash",
            "destination",
            "source",
            "hostname",
            "host",
            "computer_name",
            "uri",
            "username",
            "user",
            "process",
            "program",
            "cmd",
            "message",
        ):
            if field_name in parsed and parsed[field_name] is not None:
                extra.append(str(parsed[field_name]))
        full = text + (" " + " ".join(extra) if extra else "")

        result = ParsedLog(log_id=log_id, raw=raw_log, source_type=source_type, timestamp=ts)

        # Track the device/forwarder IP so we don't misattribute it as attacker
        device_ip = parsed.get("device_ip")

        if "src_ip" in parsed:
            result.src_ip = str(parsed["src_ip"])
        if "dst_ip" in parsed:
            result.dst_ip = str(parsed["dst_ip"])
        if "src_port" in parsed:
            result.src_port = _valid_port(parsed["src_port"])
        if "dst_port" in parsed:
            result.dst_port = _valid_port(parsed["dst_port"])
        if "destination_port" in parsed and not result.dst_port:
            result.dst_port = _valid_port(parsed["destination_port"])
        for key in ("username", "user"):
            if key in parsed and parsed[key] is not None:
                result.username = str(parsed[key])
                break
        for key in ("hostname", "host", "computer_name", "device"):
            if key in parsed and parsed[key] is not None:
                result.hostname = str(parsed[key])
                break
        for key in ("process", "process_name", "program"):
            if key in parsed and parsed[key] is not None:
                result.process_name = str(parsed[key])
                result.program = result.process_name
                break
        if "action" in parsed and parsed["action"] is not None:
            result.action = str(parsed["action"]).lower()
        if "status" in parsed and parsed["status"] is not None:
            result.status = str(parsed["status"]).lower()
        if "protocol" in parsed and parsed["protocol"] is not None:
            result.protocol = str(parsed["protocol"]).lower()

        if not result.src_ip:
            result.src_ip = _first_match(SRC_IP_PATTERNS, full)
            if not result.src_ip:
                match = IP_PATTERN.search(full)
                if match:
                    result.src_ip = match.group()

        if not result.dst_ip:
            result.dst_ip = _first_match(DST_IP_PATTERNS, full)
            if not result.dst_ip:
                seen: List[str] = []
                for match in IP_PATTERN.finditer(full):
                    ip_value = match.group()
                    if ip_value not in seen:
                        seen.append(ip_value)
                    if len(seen) == 2:
                        result.dst_ip = seen[1]
                        break

        # Firewall attribution fix: if src_ip equals the forwarding device IP
        # (either from the parsed dict or from the KNOWN_DEVICE_IPS env var),
        # the firewall is being blamed for traffic it only forwarded.
        # Try to find the real source from the raw log; if we can't, set None
        # so behavioral rules don't fire against the forwarder.
        effective_device_ip = device_ip or (result.src_ip if result.src_ip in KNOWN_DEVICE_IPS else None)
        if effective_device_ip and result.src_ip == effective_device_ip:
            real_src = _first_match(SRC_IP_PATTERNS, full)
            if real_src and real_src != effective_device_ip:
                result.src_ip = real_src
            else:
                # Scan all IPs in the log; pick one that isn't the device
                found_real = None
                for match in IP_PATTERN.finditer(full):
                    candidate = match.group()
                    if candidate != effective_device_ip and candidate != result.dst_ip:
                        found_real = candidate
                        break
                # If no real source found, clear src_ip so rules don't fire
                result.src_ip = found_real

        if result.dst_ip and not result.dst_port:
            for match in IP_PORT_PATTERN.finditer(full):
                if match.group(1) == result.dst_ip:
                    result.dst_port = _valid_port(match.group(2))
                    break
        if result.src_ip and not result.src_port:
            for match in IP_PORT_PATTERN.finditer(full):
                if match.group(1) == result.src_ip:
                    result.src_port = _valid_port(match.group(2))
                    break

        if not result.src_port:
            result.src_port = _valid_port(_first_match(SRC_PORT_PATTERNS, full))
        if not result.dst_port:
            result.dst_port = _valid_port(_first_match(DST_PORT_PATTERNS, full))

        if not result.username:
            raw_user = _first_match(USERNAME_PATTERNS, full)
            if raw_user:
                username = raw_user.strip().strip("\"'").rstrip(".,;")
                if username and len(username) <= 64 and username not in {"-", "N/A", "unknown", "null"}:
                    result.username = username

        if not result.hostname:
            raw_host = _first_match(HOSTNAME_PATTERNS, full)
            if raw_host:
                result.hostname = raw_host.strip().strip("\"'").rstrip(".,;")

        if not result.process_name:
            raw_process = _first_match(PROCESS_PATTERNS, full)
            if raw_process:
                process = raw_process.strip()
                if process and len(process) <= 256:
                    result.process_name = process
                    result.program = process

        protocol_match = PROTOCOL_PATTERN.search(full)
        if protocol_match and not result.protocol:
            result.protocol = protocol_match.group(1).lower()

        action_match = ACTION_PATTERN.search(full)
        if action_match and not result.action:
            result.action = action_match.group(1).lower()

        status_match = STATUS_PATTERN.search(full)
        if status_match and not result.status:
            status = status_match.group(1).lower()
            if status.startswith("success"):
                result.status = "success"
            elif status.startswith("fail"):
                result.status = "failed"
            else:
                result.status = status

        bytes_match = BYTES_PATTERN.search(full)
        if bytes_match:
            try:
                result.bytes_out = int(bytes_match.group(1))
            except ValueError:
                result.bytes_out = None

        found: Set[Tuple[str, str]] = set()

        for match in IP_PATTERN.finditer(full):
            ip_val = match.group()
            if is_public_ip(ip_val) and not is_allowlisted_ip(ip_val):
                found.add(("ip", ip_val))

        for match in URL_PATTERN.finditer(full):
            url = match.group().rstrip(".,;)")
            found.add(("url", url))
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                domain = f"{ext.domain}.{ext.suffix}"
                if is_valid_domain(domain):
                    found.add(("domain", domain))

        url_stripped = URL_PATTERN.sub("", full)
        for match in DOMAIN_PATTERN.finditer(url_stripped):
            domain = match.group().lower().rstrip(".")
            if is_valid_domain(domain):
                found.add(("domain", domain))

        for match in SHA256_PATTERN.finditer(full):
            found.add(("sha256", match.group().lower()))

        for match in SHA1_PATTERN.finditer(full):
            value = match.group().lower()
            if not any(value in sha for kind, sha in found if kind == "sha256"):
                found.add(("sha1", value))

        for match in MD5_PATTERN.finditer(full):
            value = match.group().lower()
            if not any(value in other for kind, other in found if kind in ("sha1", "sha256")):
                found.add(("md5", value))

        result.iocs = list(found)
        if not result.program:
            result.program = result.process_name
        return result

    def extract(
        self,
        raw_log: str = "",
        parsed: Dict[str, Any] = None,
        source_type: str = "unknown",
    ) -> List[Tuple[str, str]]:
        return self.parse("", raw_log=raw_log, parsed=parsed, source_type=source_type).iocs