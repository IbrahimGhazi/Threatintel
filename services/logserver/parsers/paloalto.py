"""
Palo Alto Networks firewall log parser.

Handles TRAFFIC and THREAT log types forwarded via syslog (RFC 3164/5424).
Palo Alto CSV log format reference:
  https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions

TRAFFIC log fields (comma-separated, 0-indexed):
  0: FUTURE_USE  1: receive_time  2: serial  3: type  4: type/subtype
  5: FUTURE_USE  6: generated_time  7: src_ip  8: dst_ip  9: nat_src_ip
  10: nat_dst_ip  11: rule_name  12: src_user  13: dst_user
  14: application  15: vsys  16: src_zone  17: dst_zone
  18: inbound_if  19: outbound_if  20: log_action  21: FUTURE_USE
  22: session_id  23: repeat_count  24: src_port  25: dst_port
  26: nat_src_port  27: nat_dst_port  28: flags  29: protocol
  30: action  31: bytes  32: bytes_sent  33: bytes_received
  34: packets  35: start_time  36: elapsed  37: category
  38: FUTURE_USE  39: sequence_number  40: action_flags  41: src_location
  42: dst_location  43: FUTURE_USE  44: pkts_sent  45: pkts_received
  ...

THREAT log fields:
  Similar to TRAFFIC but field 3 = "THREAT" and additional threat fields at higher indices.
"""
import re
from typing import Any, Dict, Optional

# Detect Palo Alto logs by looking for characteristic patterns
_PA_TYPE_RE = re.compile(
    r',TRAFFIC,|,THREAT,|,SYSTEM,|,CONFIG,|,GLOBALPROTECT,',
    re.IGNORECASE,
)
# Also detect by PAN-OS syslog header patterns
_PA_HEADER_RE = re.compile(
    r'(?:PAN-OS|Palo\s*Alto)',
    re.IGNORECASE,
)

# Action normalization map
_ACTION_MAP = {
    "allow": "allow",
    "deny": "deny",
    "drop": "drop",
    "drop-all-packets": "drop",
    "reset-client": "reset",
    "reset-server": "reset",
    "reset-both": "reset",
    "block-url": "block",
    "block-ip": "block",
    "block": "block",
    "alert": "alert",
    "continue": "allow",
    "override": "allow",
    "sinkhole": "sinkhole",
}

# Protocol number to name map (common ones)
_PROTO_MAP = {
    "6": "tcp",
    "17": "udp",
    "1": "icmp",
    "58": "icmpv6",
    "47": "gre",
    "50": "esp",
    "51": "ah",
}


def detect(message: str, parsed: Dict[str, Any]) -> bool:
    """Return True if the message looks like a Palo Alto log."""
    # Check parsed fields first (faster)
    product = parsed.get("product", "")
    vendor = parsed.get("vendor", "")
    if "palo" in product.lower() or "palo" in vendor.lower():
        return True
    appname = parsed.get("appname", "")
    if "palo" in appname.lower() or appname.lower() == "pan-os":
        return True
    # Check the message body
    if _PA_TYPE_RE.search(message):
        return True
    if _PA_HEADER_RE.search(message[:200]):
        return True
    return False


def _safe_field(fields: list, index: int) -> str:
    """Safely get a CSV field by index, returning empty string if out of range."""
    if 0 <= index < len(fields):
        return fields[index].strip()
    return ""


def _normalize_action(raw_action: str) -> str:
    """Normalize Palo Alto action to a standard action string."""
    return _ACTION_MAP.get(raw_action.lower(), raw_action.lower())


def _normalize_protocol(raw_proto: str) -> str:
    """Normalize protocol number or name to lowercase name."""
    return _PROTO_MAP.get(raw_proto, raw_proto.lower())


def _safe_port(val: str) -> Optional[int]:
    """Parse port string to int, return None if invalid."""
    try:
        port = int(val)
        return port if 1 <= port <= 65535 else None
    except (ValueError, TypeError):
        return None


def parse(message: str, device_ip: str, parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse a Palo Alto syslog message into structured fields.

    Returns a dict with standardized field names:
      device_ip, src_ip, dst_ip, src_port, dst_port, protocol, action,
      src_zone, dst_zone, application, rule_name, src_user, dst_user,
      session_id, bytes_sent, bytes_received, vendor, product, log_type, log_subtype
    """
    result: Dict[str, Any] = {
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "device_ip": device_ip,
        "format": parsed.get("format", "PaloAlto"),
    }

    # Preserve syslog envelope fields
    for key in ("facility", "severity", "timestamp", "hostname"):
        if key in parsed:
            result[key] = parsed[key]

    # Find the CSV payload — may be the entire message or after the syslog header
    csv_body = message
    # Strip syslog PRI/header if present before the CSV
    # Look for the first field that starts the PAN-OS CSV (FUTURE_USE or date)
    comma_count = csv_body.count(",")
    if comma_count < 10:
        # Not enough commas for a PA log, might be wrapped
        return _fallback_parse(message, device_ip, parsed, result)

    fields = csv_body.split(",")

    # Determine log type
    log_type = _safe_field(fields, 3).upper()
    log_subtype = _safe_field(fields, 4)
    result["log_type"] = log_type
    result["log_subtype"] = log_subtype

    if log_type == "TRAFFIC":
        return _parse_traffic(fields, device_ip, result)
    elif log_type == "THREAT":
        return _parse_threat(fields, device_ip, result)
    else:
        # SYSTEM, CONFIG, etc. — extract what we can
        return _parse_generic_pa(fields, device_ip, result)


def _parse_traffic(fields: list, device_ip: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Palo Alto TRAFFIC log."""
    result["src_ip"] = _safe_field(fields, 7)
    result["dst_ip"] = _safe_field(fields, 8)
    result["nat_src_ip"] = _safe_field(fields, 9)
    result["nat_dst_ip"] = _safe_field(fields, 10)
    result["rule_name"] = _safe_field(fields, 11)
    result["src_user"] = _safe_field(fields, 12) or None
    result["dst_user"] = _safe_field(fields, 13) or None
    result["application"] = _safe_field(fields, 14)
    result["vsys"] = _safe_field(fields, 15)
    result["src_zone"] = _safe_field(fields, 16)
    result["dst_zone"] = _safe_field(fields, 17)
    result["inbound_if"] = _safe_field(fields, 18)
    result["outbound_if"] = _safe_field(fields, 19)
    result["session_id"] = _safe_field(fields, 22)

    src_port = _safe_port(_safe_field(fields, 24))
    dst_port = _safe_port(_safe_field(fields, 25))
    if src_port:
        result["src_port"] = src_port
    if dst_port:
        result["dst_port"] = dst_port

    raw_proto = _safe_field(fields, 29)
    if raw_proto:
        result["protocol"] = _normalize_protocol(raw_proto)

    raw_action = _safe_field(fields, 30)
    if raw_action:
        result["action"] = _normalize_action(raw_action)

    bytes_total = _safe_field(fields, 31)
    bytes_sent = _safe_field(fields, 32)
    bytes_recv = _safe_field(fields, 33)
    try:
        if bytes_sent:
            result["bytes_sent"] = int(bytes_sent)
        if bytes_recv:
            result["bytes_received"] = int(bytes_recv)
        if bytes_total:
            result["bytes_total"] = int(bytes_total)
    except ValueError:
        pass

    result["category"] = _safe_field(fields, 37)
    result["src_location"] = _safe_field(fields, 41)
    result["dst_location"] = _safe_field(fields, 42)

    # Set username from src_user if available
    if result.get("src_user"):
        user = result["src_user"]
        # PAN-OS may format as "domain\user"
        if "\\" in user:
            user = user.split("\\", 1)[1]
        result["username"] = user

    return result


def _parse_threat(fields: list, device_ip: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Palo Alto THREAT log.

    THREAT logs share fields 0-30 with TRAFFIC (network info) but differ after:
      [30] action
      [31] url_or_filename  — the URL (for subtype=url) or filename (for subtype=file/virus)
      [32] threat_content_type  — e.g. "(9999)"
      [33] threat_name  — e.g. "WildCardPAN", "Whatsapp File transfer Block"
      [34] severity  — "informational", "medium", "high", "critical"
      [35] direction  — "client-to-server", "server-to-client"
      [38] src_location
      [39] dst_location
    Ref: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields
    """
    # Reuse TRAFFIC parser for common network fields (0-30)
    result = _parse_traffic(fields, device_ip, result)

    # Threat-specific fields (override TRAFFIC fields that don't apply)
    url_or_file = _safe_field(fields, 31).strip('"')
    if url_or_file:
        result["url"] = url_or_file
    result["threat_content_type"] = _safe_field(fields, 32)
    result["threat_name"] = _safe_field(fields, 33)
    result["severity_label"] = _safe_field(fields, 34)
    result["direction"] = _safe_field(fields, 35)

    # Fix locations (positions differ from TRAFFIC)
    result["src_location"] = _safe_field(fields, 38)
    result["dst_location"] = _safe_field(fields, 39)

    # Remove misassigned TRAFFIC category field (field 37 = action_flags in THREAT)
    result.pop("category", None)

    return result


def _parse_generic_pa(fields: list, device_ip: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Parse non-TRAFFIC/THREAT Palo Alto logs with best-effort field extraction."""
    # Try to extract IPs from known positions
    for idx in (7, 8):
        val = _safe_field(fields, idx)
        if val and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', val):
            if "src_ip" not in result:
                result["src_ip"] = val
            elif "dst_ip" not in result:
                result["dst_ip"] = val
    return result


def _fallback_parse(
    message: str,
    device_ip: str,
    parsed: Dict[str, Any],
    result: Dict[str, Any],
) -> Dict[str, Any]:
    """Fallback for PA logs that aren't in standard CSV format."""
    # Try key=value extraction
    kv_re = re.compile(r'(\w+)=("[^"]*"|[^\s,]+)')
    for m in kv_re.finditer(message):
        key = m.group(1).lower()
        val = m.group(2).strip('"')
        if key in ("src", "srcip", "source", "sourceaddress"):
            result["src_ip"] = val
        elif key in ("dst", "dstip", "destination", "destinationaddress"):
            result["dst_ip"] = val
        elif key in ("sport", "srcport", "sourceport"):
            port = _safe_port(val)
            if port:
                result["src_port"] = port
        elif key in ("dport", "dstport", "destinationport"):
            port = _safe_port(val)
            if port:
                result["dst_port"] = port
        elif key in ("proto", "protocol"):
            result["protocol"] = _normalize_protocol(val)
        elif key in ("action",):
            result["action"] = _normalize_action(val)
        elif key in ("app", "application"):
            result["application"] = val
    return result
