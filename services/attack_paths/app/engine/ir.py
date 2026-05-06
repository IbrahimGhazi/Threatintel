"""
Intermediate Representation — the unified vendor-neutral schema.

Vendor parsers emit IR; the normaliser flattens groups + canonicalises
CIDRs; the Neo4j loader consumes IR. Keeping IR as Pydantic v2 models
gives us free JSON serialisation for `topology_runs.ir_snapshot`.
"""
from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


Vendor = Literal["panos", "f5", "fortinet", "unknown"]
Role = Literal["firewall", "loadbalancer", "unknown"]
RuleAction = Literal["allow", "deny", "drop", "reject"]
NatKind = Literal["snat", "dnat", "static"]
AddrType = Literal["host", "subnet", "range", "fqdn", "any"]


class SourceRef(BaseModel):
    """Pointer back to the original config line for traceability."""
    file: str
    line: Optional[int] = None


class Device(BaseModel):
    id: str                      # canonical identifier used in Neo4j
    vendor: Vendor
    role: Role
    hostname: Optional[str] = None
    source_ref: Optional[SourceRef] = None


class Zone(BaseModel):
    device_id: str
    name: str
    interfaces: List[str] = Field(default_factory=list)
    trust_level: Optional[str] = None       # informational; not enforced
    source_ref: Optional[SourceRef] = None


class AddressObject(BaseModel):
    device_id: str
    name: str
    type: AddrType
    value: str                              # CIDR, IP, IP-IP range, or FQDN
    source_ref: Optional[SourceRef] = None


class AddressGroup(BaseModel):
    device_id: str
    name: str
    members: List[str]                      # names of address objects/groups
    source_ref: Optional[SourceRef] = None


class ServiceObject(BaseModel):
    device_id: str
    name: str
    protocol: str                           # 'tcp'|'udp'|'icmp'|'any'|'<num>'
    ports: List[str] = Field(default_factory=list)  # '443','80-89','any'
    source_ref: Optional[SourceRef] = None


class ServiceGroup(BaseModel):
    device_id: str
    name: str
    members: List[str]
    source_ref: Optional[SourceRef] = None


class Rule(BaseModel):
    device_id: str
    name: str
    position: int                           # 1-based ordering for shadow analysis
    action: RuleAction
    disabled: bool = False
    src_zones: List[str] = Field(default_factory=list)
    dst_zones: List[str] = Field(default_factory=list)
    src_addrs: List[str] = Field(default_factory=list)   # names; flattened later
    dst_addrs: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)    # names; 'any' allowed
    applications: List[str] = Field(default_factory=list)
    source_ref: Optional[SourceRef] = None


class NatRule(BaseModel):
    device_id: str
    name: str
    position: int
    kind: NatKind
    pre_src: Optional[str] = None
    pre_dst: Optional[str] = None
    pre_service: Optional[str] = None
    post_src: Optional[str] = None
    post_dst: Optional[str] = None
    post_dst_port: Optional[str] = None
    src_zones: List[str] = Field(default_factory=list)
    dst_zones: List[str] = Field(default_factory=list)
    source_ref: Optional[SourceRef] = None


class PoolMember(BaseModel):
    address: str
    port: int
    monitor_state: str = "unknown"          # 'up'|'down'|'disabled'|'unknown'


class Pool(BaseModel):
    device_id: str
    name: str
    lb_method: str = "round-robin"
    members: List[PoolMember] = Field(default_factory=list)
    source_ref: Optional[SourceRef] = None


class VIP(BaseModel):
    device_id: str
    name: str
    address: str                            # IPv4/IPv6
    port: int
    protocol: str = "tcp"
    pool_name: Optional[str] = None
    source_ref: Optional[SourceRef] = None


class HealthMonitor(BaseModel):
    device_id: str
    name: str
    type: str                               # http|tcp|icmp|...
    target: Optional[str] = None
    source_ref: Optional[SourceRef] = None


class ParseWarning(BaseModel):
    file: str
    line: Optional[int] = None
    severity: Literal["info", "warn", "error"] = "warn"
    message: str


class DeviceConfig(BaseModel):
    """All IR objects extracted from a single uploaded config file."""
    device: Device
    zones: List[Zone] = Field(default_factory=list)
    address_objects: List[AddressObject] = Field(default_factory=list)
    address_groups: List[AddressGroup] = Field(default_factory=list)
    service_objects: List[ServiceObject] = Field(default_factory=list)
    service_groups: List[ServiceGroup] = Field(default_factory=list)
    rules: List[Rule] = Field(default_factory=list)
    nat_rules: List[NatRule] = Field(default_factory=list)
    vips: List[VIP] = Field(default_factory=list)
    pools: List[Pool] = Field(default_factory=list)
    monitors: List[HealthMonitor] = Field(default_factory=list)
    warnings: List[ParseWarning] = Field(default_factory=list)


class IRSnapshot(BaseModel):
    """Aggregate IR across all uploads in a single run."""
    devices: List[DeviceConfig] = Field(default_factory=list)
    warnings: List[ParseWarning] = Field(default_factory=list)
