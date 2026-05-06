"""
PAN-OS XML config parser.

Targets the canonical "running config" XML exported from PAN-OS firewalls
(`show config running` saved to file, or the `running-config.xml` from the
appliance). The shape we care about lives under:

  config/devices/entry/vsys/entry/
    zone/entry
    address/entry
    address-group/entry
    service/entry
    service-group/entry
    rulebase/security/rules/entry
    rulebase/nat/rules/entry

Multi-vsys configs are walked vsys-by-vsys; objects from each vsys carry a
unique device_id of the form '<hostname>:<vsys-name>' so cross-vsys naming
collisions (the same name in two vsys is legal) don't merge in Neo4j.

Set-format configs are not handled in this MVP — convert via `set format
xml` first, or use the panos.set_format module added in Phase 4.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, List, Optional
from xml.etree import ElementTree as ET

from app.engine.ir import (
    AddressGroup,
    AddressObject,
    DeviceConfig,
    Device,
    NatRule,
    ParseWarning,
    Rule,
    ServiceGroup,
    ServiceObject,
    SourceRef,
    Zone,
)

log = logging.getLogger(__name__)


def parse_panos_config(path: str | Path, *,
                       hostname_hint: Optional[str] = None) -> List[DeviceConfig]:
    """
    Parse a PAN-OS running-config XML file. Returns one DeviceConfig per vsys
    (typical configs have a single vsys1).
    """
    path = Path(path)
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        log.error("PAN-OS XML parse failed for %s: %s", path, exc)
        return []

    root = tree.getroot()
    devices: List[DeviceConfig] = []

    hostname = hostname_hint or _extract_hostname(root) or path.stem

    # devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']
    for vsys in root.findall("./devices/entry/vsys/entry"):
        vsys_name = vsys.get("name") or "vsys1"
        device_id = f"{hostname}:{vsys_name}"
        dev_cfg = DeviceConfig(
            device=Device(
                id=device_id,
                vendor="panos",
                role="firewall",
                hostname=hostname,
                source_ref=SourceRef(file=str(path)),
            ),
        )
        try:
            _parse_zones(vsys, device_id, str(path), dev_cfg)
            _parse_addresses(vsys, device_id, str(path), dev_cfg)
            _parse_services(vsys, device_id, str(path), dev_cfg)
            _parse_security_rules(vsys, device_id, str(path), dev_cfg)
            _parse_nat_rules(vsys, device_id, str(path), dev_cfg)
        except Exception as exc:                                # noqa: BLE001
            dev_cfg.warnings.append(ParseWarning(
                file=str(path), severity="error",
                message=f"vsys {vsys_name} parse aborted: {exc}",
            ))
        devices.append(dev_cfg)
    return devices


# ── private helpers ───────────────────────────────────────────────────────────

def _extract_hostname(root: ET.Element) -> Optional[str]:
    el = root.find("./devices/entry/deviceconfig/system/hostname")
    return el.text.strip() if el is not None and el.text else None


def _members(parent: ET.Element, tag: str = "member") -> List[str]:
    return [m.text.strip() for m in parent.findall(tag) if m.text]


def _parse_zones(vsys: ET.Element, device_id: str, file: str,
                 cfg: DeviceConfig) -> None:
    for entry in vsys.findall("./zone/entry"):
        name = entry.get("name") or ""
        if not name:
            continue
        # Interfaces nested under ./network/<layer>/member
        ifaces: List[str] = []
        for member in entry.findall(".//network//member"):
            if member.text:
                ifaces.append(member.text.strip())
        cfg.zones.append(Zone(
            device_id=device_id, name=name, interfaces=ifaces,
            source_ref=SourceRef(file=file),
        ))


def _parse_addresses(vsys: ET.Element, device_id: str, file: str,
                     cfg: DeviceConfig) -> None:
    for entry in vsys.findall("./address/entry"):
        name = entry.get("name") or ""
        if not name:
            continue
        ip_netmask = entry.findtext("ip-netmask")
        ip_range = entry.findtext("ip-range")
        fqdn = entry.findtext("fqdn")
        if ip_netmask:
            kind = "subnet" if "/" in ip_netmask and not ip_netmask.endswith("/32") else "host"
            value = ip_netmask
        elif ip_range:
            kind = "range"
            value = ip_range
        elif fqdn:
            kind = "fqdn"
            value = fqdn
        else:
            cfg.warnings.append(ParseWarning(
                file=file, message=f"address '{name}' has no resolvable value",
            ))
            continue
        cfg.address_objects.append(AddressObject(
            device_id=device_id, name=name, type=kind, value=value,
            source_ref=SourceRef(file=file),
        ))

    for entry in vsys.findall("./address-group/entry"):
        name = entry.get("name") or ""
        if not name:
            continue
        static_el = entry.find("static")
        members = _members(static_el) if static_el is not None else []
        cfg.address_groups.append(AddressGroup(
            device_id=device_id, name=name, members=members,
            source_ref=SourceRef(file=file),
        ))


def _parse_services(vsys: ET.Element, device_id: str, file: str,
                    cfg: DeviceConfig) -> None:
    for entry in vsys.findall("./service/entry"):
        name = entry.get("name") or ""
        if not name:
            continue
        proto_el = entry.find("protocol")
        if proto_el is None:
            cfg.warnings.append(ParseWarning(
                file=file, message=f"service '{name}' has no protocol",
            ))
            continue
        # protocol is one of <tcp>/<udp>/<icmp>/<sctp>
        proto, port_el = next(
            ((p.tag, p.find("port")) for p in proto_el if p.tag in ("tcp", "udp", "sctp")),
            (None, None),
        )
        if proto is None:
            proto = "icmp"
            ports: List[str] = []
        else:
            ports = [port_el.text.strip()] if (port_el is not None and port_el.text) else []
        cfg.service_objects.append(ServiceObject(
            device_id=device_id, name=name, protocol=proto, ports=ports,
            source_ref=SourceRef(file=file),
        ))

    for entry in vsys.findall("./service-group/entry"):
        name = entry.get("name") or ""
        if not name:
            continue
        members_el = entry.find("members")
        members = _members(members_el) if members_el is not None else []
        cfg.service_groups.append(ServiceGroup(
            device_id=device_id, name=name, members=members,
            source_ref=SourceRef(file=file),
        ))


def _parse_security_rules(vsys: ET.Element, device_id: str, file: str,
                          cfg: DeviceConfig) -> None:
    rules_root = vsys.find("./rulebase/security/rules")
    if rules_root is None:
        return
    for position, entry in enumerate(rules_root.findall("./entry"), start=1):
        name = entry.get("name") or f"rule-{position}"
        action_text = (entry.findtext("action") or "deny").lower()
        action = action_text if action_text in ("allow", "deny", "drop", "reject") else "deny"
        disabled = (entry.findtext("disabled") or "no").lower() == "yes"

        cfg.rules.append(Rule(
            device_id=device_id, name=name, position=position,
            action=action, disabled=disabled,
            src_zones=_members_at(entry, "from"),
            dst_zones=_members_at(entry, "to"),
            src_addrs=_members_at(entry, "source"),
            dst_addrs=_members_at(entry, "destination"),
            services=_members_at(entry, "service"),
            applications=_members_at(entry, "application"),
            source_ref=SourceRef(file=file),
        ))


def _parse_nat_rules(vsys: ET.Element, device_id: str, file: str,
                     cfg: DeviceConfig) -> None:
    rules_root = vsys.find("./rulebase/nat/rules")
    if rules_root is None:
        return
    for position, entry in enumerate(rules_root.findall("./entry"), start=1):
        name = entry.get("name") or f"nat-{position}"
        kind: str = "static"
        post_dst = None
        post_dst_port = None

        # destination-translation = DNAT
        dt = entry.find("destination-translation")
        if dt is not None:
            kind = "dnat"
            post_dst = dt.findtext("translated-address")
            post_dst_port = dt.findtext("translated-port")

        # source-translation = SNAT (multiple shapes)
        st = entry.find("source-translation")
        post_src = None
        if st is not None:
            kind = "snat" if dt is None else kind  # dnat takes precedence in mixed
            for child in st:
                addr = child.findtext("translated-address")
                if addr:
                    post_src = addr
                    break

        # pre-translation source/dest are address objects (lists)
        pre_src_list = _members_at(entry, "source")
        pre_dst_list = _members_at(entry, "destination")
        pre_service = (entry.findtext("service") or "any").strip()

        cfg.nat_rules.append(NatRule(
            device_id=device_id, name=name, position=position,
            kind=kind,                                          # type: ignore[arg-type]
            pre_src=",".join(pre_src_list) if pre_src_list else None,
            pre_dst=",".join(pre_dst_list) if pre_dst_list else None,
            pre_service=pre_service,
            post_src=post_src,
            post_dst=post_dst,
            post_dst_port=post_dst_port,
            src_zones=_members_at(entry, "from"),
            dst_zones=_members_at(entry, "to"),
            source_ref=SourceRef(file=file),
        ))


def _members_at(entry: ET.Element, child: str) -> List[str]:
    """Read <child><member>X</member><member>Y</member></child>."""
    el = entry.find(child)
    if el is None:
        return []
    out = _members(el)
    if not out:
        # Some PAN-OS configs use plain text <child>any</child>
        if el.text and el.text.strip():
            out = [el.text.strip()]
    return out
