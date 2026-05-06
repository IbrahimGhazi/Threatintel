"""
Smoke tests for parser → normalize round-trip.

Run: `python -m pytest services/attack_paths/tests -v`
(pytest is a dev-only dep; not in requirements.txt.)

These tests do NOT touch Neo4j or Postgres — they exercise pure-Python
transforms only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.engine.ir import IRSnapshot
from app.engine.normalize import ResolvedAddress, normalize
from app.engine.parsers.detect import detect_vendor
from app.engine.parsers.f5 import parse_f5_config
from app.engine.parsers.fortinet import parse_fortinet_config
from app.engine.parsers.panos import parse_panos_config
from app.engine.scoring import Weights, severity_from_score

FIXTURES = Path(__file__).parent / "fixtures"


# ── PAN-OS ────────────────────────────────────────────────────────────────────

def test_panos_parser_extracts_zones_and_rules():
    devs = parse_panos_config(FIXTURES / "sample_panos.xml")
    assert len(devs) == 1
    dev = devs[0]
    assert dev.device.vendor == "panos"
    assert dev.device.role == "firewall"
    assert dev.device.id == "pa-edge-01:vsys1"

    zone_names = {z.name for z in dev.zones}
    assert {"untrust", "dmz", "inside"}.issubset(zone_names)

    rule_names = [r.name for r in dev.rules]
    assert rule_names == ["allow-web-in", "allow-dmz-to-inside", "deny-all"]
    # Position is preserved for shadow analysis
    assert [r.position for r in dev.rules] == [1, 2, 3]
    assert dev.rules[0].action == "allow"
    assert dev.rules[2].action == "deny"

    assert any(n.kind == "dnat" and n.post_dst == "10.20.30.40"
               for n in dev.nat_rules)


def test_panos_address_groups_and_service_groups():
    devs = parse_panos_config(FIXTURES / "sample_panos.xml")
    dev = devs[0]
    grp = next(g for g in dev.address_groups if g.name == "all-servers")
    assert set(grp.members) == {"web-srv", "db-srv"}
    sgrp = next(g for g in dev.service_groups if g.name == "web-services")
    assert set(sgrp.members) == {"http", "https"}


# ── F5 ────────────────────────────────────────────────────────────────────────

def test_f5_parser_extracts_virtual_pool_members():
    devs = parse_f5_config(FIXTURES / "sample_f5.conf")
    assert len(devs) == 1
    dev = devs[0]
    assert dev.device.vendor == "f5"
    assert dev.device.role == "loadbalancer"

    vips = {v.name: v for v in dev.vips}
    assert "app-prod-vs" in vips
    vip = vips["app-prod-vs"]
    assert vip.address == "203.0.113.20"
    assert vip.port == 443
    assert vip.pool_name == "app-prod-pool"

    pool = next(p for p in dev.pools if p.name == "app-prod-pool")
    assert pool.lb_method == "round-robin"
    assert len(pool.members) == 3
    member_ips = {m.address for m in pool.members}
    assert {"10.20.30.41", "10.20.30.42", "10.20.30.43"}.issubset(member_ips)
    # state down should be preserved verbatim
    states = {m.address: m.monitor_state for m in pool.members}
    assert states["10.20.30.43"] == "down"


# ── Vendor detection ──────────────────────────────────────────────────────────

def test_detect_vendor_recognizes_panos_and_f5():
    assert detect_vendor(FIXTURES / "sample_panos.xml") == "panos"
    assert detect_vendor(FIXTURES / "sample_f5.conf") == "f5"


def test_detect_vendor_recognizes_fortinet():
    assert detect_vendor(FIXTURES / "sample_fortinet.conf") == "fortinet"


# ── Fortinet ─────────────────────────────────────────────────────────────────

def test_fortinet_parser_extracts_zones_addresses_policies():
    devs = parse_fortinet_config(FIXTURES / "sample_fortinet.conf")
    assert len(devs) == 1
    dev = devs[0]
    assert dev.device.vendor == "fortinet"
    assert dev.device.role == "firewall"
    assert dev.device.hostname == "fgt-edge-01"

    zone_names = {z.name for z in dev.zones}
    assert {"untrust", "dmz", "inside"}.issubset(zone_names)

    addrs = {a.name: a for a in dev.address_objects}
    assert "web-srv" in addrs and addrs["web-srv"].value == "10.20.30.40/32"
    assert "dmz-net" in addrs and addrs["dmz-net"].value == "10.20.30.0/24"

    grp = next(g for g in dev.address_groups if g.name == "all-servers")
    assert set(grp.members) == {"web-srv", "dmz-net"}

    rule_names = [r.name for r in dev.rules]
    assert "allow-web-in" in rule_names
    assert dev.rules[0].action == "allow"   # accept normalised to allow
    assert dev.rules[-1].action == "deny"
    assert "untrust" in dev.rules[0].src_zones
    assert "dmz" in dev.rules[0].dst_zones


# ── Normalizer ────────────────────────────────────────────────────────────────

def test_normalizer_flattens_groups_and_canonicalizes_cidrs():
    devs = parse_panos_config(FIXTURES / "sample_panos.xml")
    snapshot = IRSnapshot(devices=devs)
    out = normalize(snapshot)
    assert len(out.configs) == 1
    cfg = out.configs[0]

    # Find the rule that uses the "web-services" service group
    rule = next(r for r in cfg.rules if r.name == "allow-web-in")
    proto_pairs = {(s.protocol, tuple(s.ports)) for s in rule.services}
    assert ("tcp", ("443",)) in proto_pairs
    assert ("tcp", ("80",))  in proto_pairs

    # Single-host destination should canonicalize to /32
    dst_cidrs = {a.cidr for a in rule.dst_addrs}
    assert "10.20.30.40/32" in dst_cidrs

    # The deny-all rule should normalize 'any' → 0.0.0.0/0
    deny = next(r for r in cfg.rules if r.name == "deny-all")
    assert any(a.is_any() for a in deny.src_addrs)


def test_normalizer_handles_bare_ip_value():
    """Address objects defined as bare IPs should still get a /32."""
    devs = parse_panos_config(FIXTURES / "sample_panos.xml")
    snapshot = IRSnapshot(devices=devs)
    out = normalize(snapshot)
    cfg = out.configs[0]
    rule = next(r for r in cfg.rules if r.name == "allow-dmz-to-inside")
    cidrs = [a.cidr for a in rule.dst_addrs]
    assert "10.50.60.10/32" in cidrs


# ── Scoring ───────────────────────────────────────────────────────────────────

def test_severity_buckets_match_plan():
    assert severity_from_score(85) == "critical"
    assert severity_from_score(70) == "high"
    assert severity_from_score(45) == "medium"
    assert severity_from_score(20) == "low"
    assert severity_from_score(5)  == "info"


def test_weights_default_sum_to_one():
    w = Weights()
    assert pytest.approx(w.exposure + w.proximity + w.branching + w.criticality, 1e-6) == 1.0


def test_weights_load_from_settings_map():
    w = Weights.from_platform_settings({
        "attack_path_weight_exposure":    "0.5",
        "attack_path_weight_proximity":   "0.2",
        "attack_path_weight_branching":   "0.2",
        "attack_path_weight_criticality": "0.1",
    })
    assert w.exposure == 0.5
    assert w.proximity == 0.2
