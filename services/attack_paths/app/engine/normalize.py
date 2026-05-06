"""
IR normalization.

Three jobs:
  1. Flatten address-groups and service-groups (recursive, cycle-safe).
  2. Canonicalize CIDRs ('10.0.0.0/255.255.255.0' → '10.0.0.0/24').
  3. Provide a `ResolvedRule` per Rule with concrete CIDR/host lists, so the
     loader can emit clean Neo4j edges without recursing.

We keep the original IR untouched and emit a parallel ResolvedConfig.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from app.engine.ir import (
    AddressGroup,
    AddressObject,
    DeviceConfig,
    IRSnapshot,
    NatRule,
    ParseWarning,
    Pool,
    PoolMember,
    Rule,
    ServiceGroup,
    ServiceObject,
    VIP,
)

log = logging.getLogger(__name__)

ANY_TOKENS = {"any", "any4", "any6"}


@dataclass
class ResolvedAddress:
    """A concrete address atom — either a CIDR or an FQDN."""
    cidr: Optional[str] = None
    fqdn: Optional[str] = None

    def is_any(self) -> bool:
        return self.cidr == "0.0.0.0/0"


@dataclass
class ResolvedService:
    protocol: str
    ports: List[str] = field(default_factory=list)

    def label(self) -> str:
        if not self.ports:
            return self.protocol
        return f"{self.protocol}/{','.join(self.ports)}"


@dataclass
class ResolvedRule:
    device_id: str
    name: str
    position: int
    action: str
    disabled: bool
    src_zones: List[str]
    dst_zones: List[str]
    src_addrs: List[ResolvedAddress]
    dst_addrs: List[ResolvedAddress]
    services: List[ResolvedService]


@dataclass
class ResolvedConfig:
    device_id: str
    rules: List[ResolvedRule]
    nat_rules: List[NatRule]            # NATs are passed through; loader handles
    vips: List[VIP]
    pools: List[Pool]


@dataclass
class NormalizeResult:
    configs: List[ResolvedConfig]
    warnings: List[ParseWarning]


def normalize(snapshot: IRSnapshot) -> NormalizeResult:
    out: List[ResolvedConfig] = []
    warnings: List[ParseWarning] = list(snapshot.warnings)

    for dev in snapshot.devices:
        addr_index = _AddressIndex(dev)
        svc_index = _ServiceIndex(dev)

        resolved_rules: List[ResolvedRule] = []
        for rule in dev.rules:
            try:
                resolved_rules.append(ResolvedRule(
                    device_id=rule.device_id,
                    name=rule.name,
                    position=rule.position,
                    action=rule.action,
                    disabled=rule.disabled,
                    src_zones=_normalize_zones(rule.src_zones),
                    dst_zones=_normalize_zones(rule.dst_zones),
                    src_addrs=addr_index.resolve(rule.src_addrs, warnings, dev.device.id),
                    dst_addrs=addr_index.resolve(rule.dst_addrs, warnings, dev.device.id),
                    services=svc_index.resolve(rule.services, warnings, dev.device.id),
                ))
            except Exception as exc:                            # noqa: BLE001
                warnings.append(ParseWarning(
                    file=(rule.source_ref.file if rule.source_ref else dev.device.id),
                    severity="error",
                    message=f"rule '{rule.name}' normalize failed: {exc}",
                ))
        out.append(ResolvedConfig(
            device_id=dev.device.id,
            rules=resolved_rules,
            nat_rules=list(dev.nat_rules),
            vips=list(dev.vips),
            pools=list(dev.pools),
        ))
        warnings.extend(dev.warnings)
    return NormalizeResult(configs=out, warnings=warnings)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize_zones(zones: List[str]) -> List[str]:
    out: List[str] = []
    for z in zones:
        z = z.strip()
        if not z:
            continue
        if z.lower() in ANY_TOKENS:
            out.append("any")
        else:
            out.append(z)
    return out or ["any"]


def _canonicalize_cidr(value: str) -> Optional[str]:
    """Return canonical 'cidr/prefix' (lowercase, prefix-only). None if invalid."""
    try:
        net = ipaddress.ip_network(value, strict=False)
        return str(net)
    except ValueError:
        return None


def _ip_to_cidr(value: str) -> Optional[str]:
    """Lone IP → /32 (or /128 for v6)."""
    try:
        ip = ipaddress.ip_address(value)
        return f"{ip}/{32 if ip.version == 4 else 128}"
    except ValueError:
        return None


class _AddressIndex:
    """Resolve names → list of ResolvedAddress, recursively flattening groups."""

    def __init__(self, dev: DeviceConfig):
        self.objs: Dict[str, AddressObject] = {a.name: a for a in dev.address_objects}
        self.groups: Dict[str, AddressGroup] = {g.name: g for g in dev.address_groups}

    def resolve(self, names: List[str], warnings: List[ParseWarning],
                device_id: str) -> List[ResolvedAddress]:
        out: List[ResolvedAddress] = []
        seen: Set[str] = set()
        for n in names:
            self._resolve_one(n, out, seen, warnings, device_id, depth=0)
        # If empty after resolution, treat as 'any'
        if not out:
            out.append(ResolvedAddress(cidr="0.0.0.0/0"))
        return out

    def _resolve_one(self, name: str, out: List[ResolvedAddress],
                     seen: Set[str], warnings: List[ParseWarning],
                     device_id: str, *, depth: int) -> None:
        n = name.strip()
        if not n or n in seen:
            return
        seen.add(n)
        if depth > 20:
            warnings.append(ParseWarning(
                file=device_id, severity="warn",
                message=f"address resolution depth >20 at '{n}' (cycle?)",
            ))
            return

        if n.lower() in ANY_TOKENS:
            out.append(ResolvedAddress(cidr="0.0.0.0/0"))
            return

        # Direct address object
        if n in self.objs:
            a = self.objs[n]
            if a.type in ("subnet", "host"):
                cidr = _canonicalize_cidr(a.value) or _ip_to_cidr(a.value)
                if cidr:
                    out.append(ResolvedAddress(cidr=cidr))
                else:
                    warnings.append(ParseWarning(
                        file=device_id, severity="warn",
                        message=f"address '{n}' has unparseable value '{a.value}'",
                    ))
            elif a.type == "range":
                # 10.0.0.5-10.0.0.10 → enumerate as a CIDR cover (cheap approximation)
                cidrs = _range_to_cidrs(a.value)
                if cidrs:
                    for c in cidrs:
                        out.append(ResolvedAddress(cidr=c))
                else:
                    warnings.append(ParseWarning(
                        file=device_id, severity="warn",
                        message=f"range '{n}' value '{a.value}' could not be summarised",
                    ))
            elif a.type == "fqdn":
                out.append(ResolvedAddress(fqdn=a.value))
            return

        # Group → recurse
        if n in self.groups:
            for member in self.groups[n].members:
                self._resolve_one(member, out, seen, warnings, device_id,
                                  depth=depth + 1)
            return

        # Literal CIDR/IP supplied inline (rare in PAN-OS but possible)
        cidr = _canonicalize_cidr(n) or _ip_to_cidr(n)
        if cidr:
            out.append(ResolvedAddress(cidr=cidr))
            return

        warnings.append(ParseWarning(
            file=device_id, severity="warn",
            message=f"unresolved address reference '{n}'",
        ))


def _range_to_cidrs(value: str) -> List[str]:
    try:
        a, b = [s.strip() for s in value.split("-", 1)]
        ip_a = ipaddress.ip_address(a)
        ip_b = ipaddress.ip_address(b)
        if ip_a.version != ip_b.version or ip_a > ip_b:
            return []
        nets = list(ipaddress.summarize_address_range(ip_a, ip_b))     # type: ignore[arg-type]
        return [str(n) for n in nets]
    except ValueError:
        return []


class _ServiceIndex:
    def __init__(self, dev: DeviceConfig):
        self.objs: Dict[str, ServiceObject] = {s.name: s for s in dev.service_objects}
        self.groups: Dict[str, ServiceGroup] = {g.name: g for g in dev.service_groups}

    def resolve(self, names: List[str], warnings: List[ParseWarning],
                device_id: str) -> List[ResolvedService]:
        out: List[ResolvedService] = []
        seen: Set[str] = set()
        for n in names:
            self._resolve_one(n, out, seen, warnings, device_id, depth=0)
        if not out:
            out.append(ResolvedService(protocol="any"))
        return _dedup_services(out)

    def _resolve_one(self, name: str, out: List[ResolvedService],
                     seen: Set[str], warnings: List[ParseWarning],
                     device_id: str, *, depth: int) -> None:
        n = name.strip()
        if not n or n in seen:
            return
        seen.add(n)
        if depth > 20:
            return
        if n.lower() in ANY_TOKENS or n.lower() in ("application-default", "service-default"):
            out.append(ResolvedService(protocol="any"))
            return
        if n in self.objs:
            o = self.objs[n]
            out.append(ResolvedService(protocol=o.protocol.lower(),
                                       ports=list(o.ports)))
            return
        if n in self.groups:
            for m in self.groups[n].members:
                self._resolve_one(m, out, seen, warnings, device_id,
                                  depth=depth + 1)
            return
        warnings.append(ParseWarning(
            file=device_id, severity="info",
            message=f"unresolved service reference '{n}' (treated as any)",
        ))
        out.append(ResolvedService(protocol="any"))


def _dedup_services(items: List[ResolvedService]) -> List[ResolvedService]:
    seen: Set[Tuple[str, Tuple[str, ...]]] = set()
    out: List[ResolvedService] = []
    for it in items:
        key = (it.protocol, tuple(it.ports))
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out
