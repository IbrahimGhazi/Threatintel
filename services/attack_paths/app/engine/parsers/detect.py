"""
Vendor detection from filename + first ~4KB of file content.

Detection is best-effort: we err on the side of returning a vendor when
there's a strong signal, and `unknown` otherwise. The orchestrator will
mark unknown uploads as parse_status='failed' with a clear message.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

Vendor = Literal["panos", "f5", "fortinet", "unknown"]

_PROBE_BYTES = 4096


def detect_vendor(path: str | Path) -> Vendor:
    p = Path(path)
    name = p.name.lower()

    # Strong filename signals first
    if "bigip" in name or name.endswith(".conf") and _looks_like_f5(p):
        return "f5"
    if name.endswith(".xml") and _looks_like_panos(p):
        return "panos"

    # Content-based fallback
    try:
        head = p.read_bytes()[:_PROBE_BYTES].decode("utf-8", errors="replace")
    except OSError:
        return "unknown"

    if _looks_like_panos_text(head):
        return "panos"
    if _looks_like_f5_text(head):
        return "f5"
    if "config-version=FGT" in head or "config system " in head:
        return "fortinet"
    return "unknown"


def _looks_like_panos(p: Path) -> bool:
    try:
        head = p.read_bytes()[:_PROBE_BYTES].decode("utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_panos_text(head)


def _looks_like_panos_text(text: str) -> bool:
    return ("<config" in text and "<devices" in text) or "PAN-OS" in text


def _looks_like_f5(p: Path) -> bool:
    try:
        head = p.read_bytes()[:_PROBE_BYTES].decode("utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_f5_text(head)


def _looks_like_f5_text(text: str) -> bool:
    # bigip.conf always has either ltm/sys/security stanzas
    return any(s in text for s in ("ltm virtual ", "ltm pool ", "sys global-settings"))
