"""
Vendor-specific log parsers.

Each parser module exposes:
  - detect(message: str, parsed: dict) -> bool
  - parse(message: str, device_ip: str, parsed: dict) -> dict

The registry tries each parser's detect() in order and delegates to the
first match.  If nothing matches, the caller falls back to generic parsing.

The netflow module has a different interface (binary UDP datagrams) and is
accessed via :func:`try_netflow_parse` rather than the syslog chain.
"""
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import paloalto
from . import netflow

# Ordered list of (detect_func, parse_func) — first match wins
_PARSERS: List[Tuple[Callable, Callable]] = [
    (paloalto.detect, paloalto.parse),
]


def try_vendor_parse(
    message: str,
    device_ip: str,
    parsed: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Try vendor-specific parsers; return enriched parsed dict or None."""
    parsed = parsed or {}
    for detect_fn, parse_fn in _PARSERS:
        try:
            if detect_fn(message, parsed):
                return parse_fn(message, device_ip, parsed)
        except Exception:
            continue
    return None


def try_netflow_parse(data: bytes, device_ip: str) -> Optional[List[Dict[str, Any]]]:
    """
    Try to parse raw UDP bytes as a Cisco NetFlow packet.

    Returns a list of flow record dicts if the data is valid NetFlow v5/v9,
    or None if the data is not a recognised NetFlow packet.
    """
    try:
        version = netflow.detect(data)
        if version is not None:
            return netflow.parse(data, device_ip)
    except Exception:
        pass
    return None
