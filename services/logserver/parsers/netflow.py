"""
Cisco NetFlow v5 / v9 parser.

Handles raw NetFlow UDP datagrams on port 2055 (default).  Extracts flow
records and normalises them into the same dict structure used by other
vendor parsers so the log server can forward them to the API.

NetFlow v5 reference:
  https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html

NetFlow v9 reference (RFC 3954):
  https://www.ietf.org/rfc/rfc3954.txt

Exported dict keys per flow record:
  src_ip, dst_ip, src_port, dst_port, protocol, bytes_sent, bytes_received,
  packets, tcp_flags, input_interface, output_interface, flow_duration
"""
import struct
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Protocol number → name ───────────────────────────────────────────────────

_PROTO_MAP: Dict[int, str] = {
    1:   "icmp",
    2:   "igmp",
    6:   "tcp",
    17:  "udp",
    41:  "ipv6",
    47:  "gre",
    50:  "esp",
    51:  "ah",
    58:  "icmpv6",
    89:  "ospf",
    132: "sctp",
}

# ── TCP flag bit names ───────────────────────────────────────────────────────

_TCP_FLAGS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]


def _tcp_flags_str(flags: int) -> str:
    """Convert a TCP flags bitmask to a human-readable string like 'SYN,ACK'."""
    names = [name for bit, name in _TCP_FLAGS if flags & bit]
    return ",".join(names) if names else str(flags)


def _proto_name(proto_num: int) -> str:
    return _PROTO_MAP.get(proto_num, str(proto_num))


def _ip_from_u32(val: int) -> str:
    """Convert a 32-bit unsigned integer to dotted-quad IPv4 string."""
    return socket.inet_ntoa(struct.pack("!I", val))


# ── NetFlow v5 ───────────────────────────────────────────────────────────────

# v5 header: 24 bytes
_V5_HEADER_FMT = "!HHIIIIHbbH"
_V5_HEADER_SIZE = struct.calcsize(_V5_HEADER_FMT)

# v5 flow record: 48 bytes each
_V5_RECORD_FMT = "!IIIHHIIIIHHBBBBHHBBH"
_V5_RECORD_SIZE = struct.calcsize(_V5_RECORD_FMT)


def _parse_v5(data: bytes, device_ip: str) -> List[Dict[str, Any]]:
    """Parse a NetFlow v5 packet and return a list of flow record dicts."""
    if len(data) < _V5_HEADER_SIZE:
        return []

    (
        version, count, sys_uptime_ms, unix_secs, unix_nsecs,
        flow_sequence, engine_type, engine_id, sampling_interval,
    ) = struct.unpack(_V5_HEADER_FMT, data[:_V5_HEADER_SIZE])

    if version != 5:
        return []

    records: List[Dict[str, Any]] = []
    offset = _V5_HEADER_SIZE

    for _ in range(count):
        if offset + _V5_RECORD_SIZE > len(data):
            break

        (
            src_addr, dst_addr, nexthop, input_if, output_if,
            d_pkts, d_octets, first_uptime, last_uptime,
            src_port, dst_port,
            _pad1, tcp_flags, prot, tos,
            src_as, dst_as, src_mask, dst_mask, _pad2,
        ) = struct.unpack(_V5_RECORD_FMT, data[offset:offset + _V5_RECORD_SIZE])

        # Flow duration in milliseconds (uptime counters)
        duration_ms = max(last_uptime - first_uptime, 0)

        records.append({
            "src_ip":           _ip_from_u32(src_addr),
            "dst_ip":           _ip_from_u32(dst_addr),
            "src_port":         src_port,
            "dst_port":         dst_port,
            "protocol":         _proto_name(prot),
            "protocol_number":  prot,
            "bytes_sent":       d_octets,
            "bytes_received":   0,       # v5 is unidirectional; only sender octets
            "packets":          d_pkts,
            "tcp_flags":        _tcp_flags_str(tcp_flags),
            "tcp_flags_raw":    tcp_flags,
            "input_interface":  input_if,
            "output_interface": output_if,
            "flow_duration":    duration_ms,
            "tos":              tos,
            "src_as":           src_as,
            "dst_as":           dst_as,
            "nexthop":          _ip_from_u32(nexthop),
            "device_ip":        device_ip,
            "netflow_version":  5,
        })
        offset += _V5_RECORD_SIZE

    return records


# ── NetFlow v9 ───────────────────────────────────────────────────────────────

# v9 header: 20 bytes
_V9_HEADER_FMT = "!HHIII"
_V9_HEADER_SIZE = struct.calcsize(_V9_HEADER_FMT)

# v9 FlowSet header: 4 bytes (flowset_id, length)
_V9_FLOWSET_HEADER_FMT = "!HH"
_V9_FLOWSET_HEADER_SIZE = struct.calcsize(_V9_FLOWSET_HEADER_FMT)

# Well-known v9 field type IDs (RFC 3954)
_V9_FIELD_SRC_ADDR       = 8
_V9_FIELD_DST_ADDR       = 12
_V9_FIELD_INPUT_SNMP      = 10
_V9_FIELD_OUTPUT_SNMP     = 14
_V9_FIELD_IN_PKTS         = 2
_V9_FIELD_IN_BYTES        = 1
_V9_FIELD_OUT_BYTES       = 23
_V9_FIELD_OUT_PKTS        = 24
_V9_FIELD_FIRST_SWITCHED  = 22
_V9_FIELD_LAST_SWITCHED   = 21
_V9_FIELD_L4_SRC_PORT     = 7
_V9_FIELD_L4_DST_PORT     = 11
_V9_FIELD_TCP_FLAGS       = 6
_V9_FIELD_PROTOCOL        = 4
_V9_FIELD_SRC_TOS         = 5
_V9_FIELD_SRC_AS          = 16
_V9_FIELD_DST_AS          = 17

# Templates are cached per (device_ip, source_id, template_id)
# dict of (device_ip, source_id, template_id) -> list of (field_type, field_length)
_v9_templates: Dict[Tuple[str, int, int], List[Tuple[int, int]]] = {}


def _parse_v9_template_flowset(data: bytes, device_ip: str, source_id: int) -> None:
    """Parse a v9 template FlowSet (flowset_id == 0) and cache the templates."""
    offset = 0
    while offset + 4 <= len(data):
        if offset + 4 > len(data):
            break
        template_id, field_count = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4

        fields: List[Tuple[int, int]] = []
        for _ in range(field_count):
            if offset + 4 > len(data):
                break
            ftype, flength = struct.unpack("!HH", data[offset:offset + 4])
            fields.append((ftype, flength))
            offset += 4

        _v9_templates[(device_ip, source_id, template_id)] = fields


def _read_v9_uint(data: bytes, length: int) -> int:
    """Read an unsigned integer of 1/2/4/8 bytes from raw bytes."""
    if length == 1:
        return data[0]
    elif length == 2:
        return struct.unpack("!H", data[:2])[0]
    elif length == 4:
        return struct.unpack("!I", data[:4])[0]
    elif length == 8:
        return struct.unpack("!Q", data[:8])[0]
    # Fallback: interpret as big-endian int
    return int.from_bytes(data[:length], "big")


def _parse_v9_data_flowset(
    data: bytes,
    device_ip: str,
    source_id: int,
    flowset_id: int,
) -> List[Dict[str, Any]]:
    """Parse a v9 data FlowSet using cached templates."""
    template_key = (device_ip, source_id, flowset_id)
    template = _v9_templates.get(template_key)
    if not template:
        return []  # template not yet received — silently skip

    record_len = sum(fl for _, fl in template)
    if record_len == 0:
        return []

    records: List[Dict[str, Any]] = []
    offset = 0

    while offset + record_len <= len(data):
        raw_fields: Dict[int, bytes] = {}
        pos = offset
        for ftype, flength in template:
            if pos + flength > len(data):
                break
            raw_fields[ftype] = data[pos:pos + flength]
            pos += flength
        offset += record_len

        # Extract known fields
        rec: Dict[str, Any] = {
            "device_ip": device_ip,
            "netflow_version": 9,
        }

        # IP addresses
        if _V9_FIELD_SRC_ADDR in raw_fields and len(raw_fields[_V9_FIELD_SRC_ADDR]) == 4:
            rec["src_ip"] = socket.inet_ntoa(raw_fields[_V9_FIELD_SRC_ADDR])
        if _V9_FIELD_DST_ADDR in raw_fields and len(raw_fields[_V9_FIELD_DST_ADDR]) == 4:
            rec["dst_ip"] = socket.inet_ntoa(raw_fields[_V9_FIELD_DST_ADDR])

        # Ports
        if _V9_FIELD_L4_SRC_PORT in raw_fields:
            rec["src_port"] = _read_v9_uint(raw_fields[_V9_FIELD_L4_SRC_PORT], len(raw_fields[_V9_FIELD_L4_SRC_PORT]))
        if _V9_FIELD_L4_DST_PORT in raw_fields:
            rec["dst_port"] = _read_v9_uint(raw_fields[_V9_FIELD_L4_DST_PORT], len(raw_fields[_V9_FIELD_L4_DST_PORT]))

        # Protocol
        if _V9_FIELD_PROTOCOL in raw_fields:
            prot = _read_v9_uint(raw_fields[_V9_FIELD_PROTOCOL], len(raw_fields[_V9_FIELD_PROTOCOL]))
            rec["protocol"] = _proto_name(prot)
            rec["protocol_number"] = prot

        # Byte counts
        if _V9_FIELD_IN_BYTES in raw_fields:
            rec["bytes_sent"] = _read_v9_uint(raw_fields[_V9_FIELD_IN_BYTES], len(raw_fields[_V9_FIELD_IN_BYTES]))
        if _V9_FIELD_OUT_BYTES in raw_fields:
            rec["bytes_received"] = _read_v9_uint(raw_fields[_V9_FIELD_OUT_BYTES], len(raw_fields[_V9_FIELD_OUT_BYTES]))

        # Packets
        if _V9_FIELD_IN_PKTS in raw_fields:
            rec["packets"] = _read_v9_uint(raw_fields[_V9_FIELD_IN_PKTS], len(raw_fields[_V9_FIELD_IN_PKTS]))

        # TCP flags
        if _V9_FIELD_TCP_FLAGS in raw_fields:
            flags = _read_v9_uint(raw_fields[_V9_FIELD_TCP_FLAGS], len(raw_fields[_V9_FIELD_TCP_FLAGS]))
            rec["tcp_flags"] = _tcp_flags_str(flags)
            rec["tcp_flags_raw"] = flags

        # Interfaces
        if _V9_FIELD_INPUT_SNMP in raw_fields:
            rec["input_interface"] = _read_v9_uint(raw_fields[_V9_FIELD_INPUT_SNMP], len(raw_fields[_V9_FIELD_INPUT_SNMP]))
        if _V9_FIELD_OUTPUT_SNMP in raw_fields:
            rec["output_interface"] = _read_v9_uint(raw_fields[_V9_FIELD_OUTPUT_SNMP], len(raw_fields[_V9_FIELD_OUTPUT_SNMP]))

        # Flow duration (first/last switched are uptime counters in ms)
        first_ms = None
        last_ms = None
        if _V9_FIELD_FIRST_SWITCHED in raw_fields:
            first_ms = _read_v9_uint(raw_fields[_V9_FIELD_FIRST_SWITCHED], len(raw_fields[_V9_FIELD_FIRST_SWITCHED]))
        if _V9_FIELD_LAST_SWITCHED in raw_fields:
            last_ms = _read_v9_uint(raw_fields[_V9_FIELD_LAST_SWITCHED], len(raw_fields[_V9_FIELD_LAST_SWITCHED]))
        if first_ms is not None and last_ms is not None:
            rec["flow_duration"] = max(last_ms - first_ms, 0)

        # Defaults for missing optional fields
        rec.setdefault("bytes_sent", 0)
        rec.setdefault("bytes_received", 0)
        rec.setdefault("packets", 0)
        rec.setdefault("tcp_flags", "")
        rec.setdefault("input_interface", 0)
        rec.setdefault("output_interface", 0)
        rec.setdefault("flow_duration", 0)

        records.append(rec)

    return records


def _parse_v9(data: bytes, device_ip: str) -> List[Dict[str, Any]]:
    """Parse a NetFlow v9 packet and return a list of flow record dicts."""
    if len(data) < _V9_HEADER_SIZE:
        return []

    version, count, sys_uptime, unix_secs, sequence, source_id = struct.unpack(
        _V9_HEADER_FMT, data[:_V9_HEADER_SIZE]
    )
    if version != 9:
        return []

    records: List[Dict[str, Any]] = []
    offset = _V9_HEADER_SIZE

    while offset + _V9_FLOWSET_HEADER_SIZE <= len(data):
        flowset_id, flowset_length = struct.unpack(
            _V9_FLOWSET_HEADER_FMT, data[offset:offset + _V9_FLOWSET_HEADER_SIZE]
        )
        if flowset_length < _V9_FLOWSET_HEADER_SIZE:
            break  # malformed

        flowset_data = data[offset + _V9_FLOWSET_HEADER_SIZE:offset + flowset_length]

        if flowset_id == 0:
            # Template FlowSet
            _parse_v9_template_flowset(flowset_data, device_ip, source_id)
        elif flowset_id == 1:
            # Options Template FlowSet — skip (not needed for basic flow data)
            pass
        elif flowset_id >= 256:
            # Data FlowSet — parse using cached template
            recs = _parse_v9_data_flowset(flowset_data, device_ip, source_id, flowset_id)
            records.extend(recs)

        offset += flowset_length

    return records


# ── Public interface ─────────────────────────────────────────────────────────

def detect(data: bytes) -> Optional[int]:
    """
    Detect whether *data* is a NetFlow packet.

    Returns the NetFlow version (5 or 9) if detected, or None otherwise.
    Unlike syslog vendor parsers (which receive a string), this receives
    raw bytes from the UDP socket.
    """
    if len(data) < 4:
        return None
    version = struct.unpack("!H", data[:2])[0]
    if version == 5 and len(data) >= _V5_HEADER_SIZE:
        return 5
    if version == 9 and len(data) >= _V9_HEADER_SIZE:
        return 9
    return None


def parse(data: bytes, device_ip: str) -> List[Dict[str, Any]]:
    """
    Parse a raw NetFlow UDP datagram and return a list of normalised
    flow record dicts.

    Each dict contains at minimum:
      src_ip, dst_ip, src_port, dst_port, protocol, bytes_sent,
      bytes_received, packets, tcp_flags, input_interface,
      output_interface, flow_duration, device_ip, netflow_version
    """
    version = detect(data)
    if version == 5:
        return _parse_v5(data, device_ip)
    elif version == 9:
        return _parse_v9(data, device_ip)
    return []
