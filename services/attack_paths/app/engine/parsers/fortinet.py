"""
Fortinet FortiGate config parser — Phase 4 starter.

FortiOS config syntax:
    config <section>
        edit <name-or-id>
            set <key> <value>
            ...
        next
    end

Supports nested `config` blocks (e.g. `config dynamic_mapping` inside an entry).
This MVP covers:
  - `config system zone`              → Zone
  - `config firewall address`         → AddressObject (subnet / iprange / fqdn)
  - `config firewall addrgrp`         → AddressGroup
  - `config firewall service custom`  → ServiceObject
  - `config firewall service group`   → ServiceGroup
  - `config firewall policy`          → Rule

Out of scope (warnings emitted, no edges produced):
  - `config firewall vip`             — DNAT-style VIPs (Phase 4.1)
  - `config firewall ippool`          — SNAT pools
  - VDOMs                              — only the global/root VDOM is parsed
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from app.engine.ir import (
    AddressGroup,
    AddressObject,
    DeviceConfig,
    Device,
    ParseWarning,
    Rule,
    ServiceGroup,
    ServiceObject,
    SourceRef,
    Zone,
)

log = logging.getLogger(__name__)

_INDENT_RE = re.compile(r"^(\s*)(.*)$")
_SET_RE    = re.compile(r"^\s*set\s+(?P<key>\S+)\s+(?P<val>.*?)\s*$")
_QUOTED_RE = re.compile(r'"([^"]*)"')


def parse_fortinet_config(path: str | Path, *,
                          hostname_hint: Optional[str] = None) -> List[DeviceConfig]:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.error("Fortinet config read failed for %s: %s", path, exc)
        return []

    hostname = hostname_hint or _hostname_from_text(text) or path.stem
    cfg = DeviceConfig(
        device=Device(
            id=f"{hostname}:root",
            vendor="fortinet", role="firewall", hostname=hostname,
            source_ref=SourceRef(file=str(path)),
        ),
    )

    sections = _walk_sections(text)
    for section, entries in sections.items():
        try:
            if section == "system zone":
                _parse_zones(entries, cfg, str(path))
            elif section == "firewall address":
                _parse_addresses(entries, cfg, str(path))
            elif section == "firewall addrgrp":
                _parse_address_groups(entries, cfg, str(path))
            elif section == "firewall service custom":
                _parse_services(entries, cfg, str(path))
            elif section == "firewall service group":
                _parse_service_groups(entries, cfg, str(path))
            elif section == "firewall policy":
                _parse_policies(entries, cfg, str(path))
            elif section in ("firewall vip", "firewall ippool"):
                cfg.warnings.append(ParseWarning(
                    file=str(path), severity="info",
                    message=f"section '{section}' is not yet supported",
                ))
        except Exception as exc:                                # noqa: BLE001
            cfg.warnings.append(ParseWarning(
                file=str(path), severity="warn",
                message=f"section '{section}' parse aborted: {exc}",
            ))
    return [cfg]


# ── Section walker ────────────────────────────────────────────────────────────

def _walk_sections(text: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Return { 'firewall policy': [{<key>:<value>,...}, ...], ... }
    Each entry is keyed by `set` lines plus a synthetic 'edit' = entry name/id.
    """
    out: Dict[str, List[Dict[str, str]]] = {}
    config_stack: List[str] = []
    cur_entries: Optional[List[Dict[str, str]]] = None
    cur_entry: Optional[Dict[str, str]] = None
    nested_depth = 0       # depth of 'config' inside an active 'edit'

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        token = line.lstrip()
        if token.startswith("config "):
            section = token[len("config "):].strip()
            if cur_entry is not None:
                # Nested config inside an edit — skip its contents.
                nested_depth += 1
                continue
            config_stack.append(section)
            cur_entries = out.setdefault(section, [])
            continue
        if token == "end":
            if nested_depth > 0:
                nested_depth -= 1
                continue
            if config_stack:
                config_stack.pop()
            cur_entries = None
            continue
        if nested_depth > 0:
            continue        # inside nested config; ignore
        if token.startswith("edit "):
            name = token[len("edit "):].strip().strip('"')
            cur_entry = {"_name": name}
            if cur_entries is not None:
                cur_entries.append(cur_entry)
            continue
        if token == "next":
            cur_entry = None
            continue
        m = _SET_RE.match(line)
        if m and cur_entry is not None:
            val = m.group("val").strip()
            # Strip a single pair of surrounding quotes for scalar values
            # (multi-token list values are handled later by _split_quoted).
            if len(val) >= 2 and val[0] == '"' and val[-1] == '"' and val.count('"') == 2:
                val = val[1:-1]
            cur_entry[m.group("key")] = val
    return out


# ── Section handlers ──────────────────────────────────────────────────────────

def _parse_zones(entries: List[Dict[str, str]], cfg: DeviceConfig, file: str) -> None:
    for e in entries:
        name = e.get("_name") or ""
        if not name:
            continue
        ifs = _split_quoted(e.get("interface", ""))
        cfg.zones.append(Zone(
            device_id=cfg.device.id, name=name, interfaces=ifs,
            source_ref=SourceRef(file=file),
        ))


def _parse_addresses(entries: List[Dict[str, str]], cfg: DeviceConfig, file: str) -> None:
    for e in entries:
        name = e.get("_name") or ""
        if not name:
            continue
        kind: str = "host"
        value: Optional[str] = None
        if "subnet" in e:
            # FortiOS uses "1.2.3.0 255.255.255.0"
            parts = e["subnet"].split()
            if len(parts) == 2:
                cidr = _ip_mask_to_cidr(parts[0], parts[1])
                if cidr:
                    kind = "subnet" if not cidr.endswith("/32") else "host"
                    value = cidr
        elif e.get("type") == "iprange":
            value = f"{e.get('start-ip','')}-{e.get('end-ip','')}"
            kind = "range"
        elif e.get("type") == "fqdn" or "fqdn" in e:
            value = e.get("fqdn") or e.get("_name")
            kind = "fqdn"
        if not value:
            cfg.warnings.append(ParseWarning(
                file=file, message=f"address '{name}' has no resolvable value",
            ))
            continue
        cfg.address_objects.append(AddressObject(
            device_id=cfg.device.id, name=name, type=kind,        # type: ignore[arg-type]
            value=value, source_ref=SourceRef(file=file),
        ))


def _parse_address_groups(entries: List[Dict[str, str]], cfg: DeviceConfig, file: str) -> None:
    for e in entries:
        name = e.get("_name") or ""
        if not name:
            continue
        members = _split_quoted(e.get("member", ""))
        cfg.address_groups.append(AddressGroup(
            device_id=cfg.device.id, name=name, members=members,
            source_ref=SourceRef(file=file),
        ))


def _parse_services(entries: List[Dict[str, str]], cfg: DeviceConfig, file: str) -> None:
    for e in entries:
        name = e.get("_name") or ""
        if not name:
            continue
        proto = (e.get("protocol") or "TCP").lower()
        ports: List[str] = []
        for k in ("tcp-portrange", "udp-portrange", "sctp-portrange"):
            if k in e:
                ports.extend(e[k].split())
                proto = k.split("-", 1)[0]
                break
        cfg.service_objects.append(ServiceObject(
            device_id=cfg.device.id, name=name, protocol=proto, ports=ports,
            source_ref=SourceRef(file=file),
        ))


def _parse_service_groups(entries: List[Dict[str, str]], cfg: DeviceConfig, file: str) -> None:
    for e in entries:
        name = e.get("_name") or ""
        if not name:
            continue
        members = _split_quoted(e.get("member", ""))
        cfg.service_groups.append(ServiceGroup(
            device_id=cfg.device.id, name=name, members=members,
            source_ref=SourceRef(file=file),
        ))


def _parse_policies(entries: List[Dict[str, str]], cfg: DeviceConfig, file: str) -> None:
    for position, e in enumerate(entries, start=1):
        name = e.get("name") or e.get("_name") or f"policy-{position}"
        action = (e.get("action") or "deny").lower()
        if action == "accept":
            action = "allow"
        if action not in ("allow", "deny", "drop", "reject"):
            action = "deny"
        cfg.rules.append(Rule(
            device_id=cfg.device.id,
            name=name, position=position,
            action=action,                                  # type: ignore[arg-type]
            disabled=(e.get("status") == "disable"),
            src_zones=_split_quoted(e.get("srcintf", "")),
            dst_zones=_split_quoted(e.get("dstintf", "")),
            src_addrs=_split_quoted(e.get("srcaddr", "")),
            dst_addrs=_split_quoted(e.get("dstaddr", "")),
            services=_split_quoted(e.get("service", "")),
            applications=_split_quoted(e.get("application-list", "")),
            source_ref=SourceRef(file=file),
        ))


# ── Small helpers ─────────────────────────────────────────────────────────────

def _hostname_from_text(text: str) -> Optional[str]:
    """Best-effort hostname extraction from `config system global`."""
    in_global = False
    for line in text.splitlines():
        s = line.strip()
        if s == "config system global":
            in_global = True
            continue
        if in_global:
            if s == "end":
                break
            m = _SET_RE.match(line)
            if m and m.group("key") == "hostname":
                return m.group("val").strip().strip('"')
    return None


def _split_quoted(value: str) -> List[str]:
    """FortiOS list values look like:  "any"  "internal" "dmz"
    Returns the unquoted tokens. Falls back to whitespace split."""
    if not value:
        return []
    found = _QUOTED_RE.findall(value)
    return found if found else value.split()


def _ip_mask_to_cidr(ip: str, mask: str) -> Optional[str]:
    try:
        import ipaddress
        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        return str(net)
    except ValueError:
        return None
