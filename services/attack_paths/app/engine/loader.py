"""
Neo4j loader — translates ResolvedConfig (post-normalize) into MERGE
Cypher batched per-device.

Idempotency: every node is MERGEd by a stable composite key (`device_id` +
`name`/`ip`/`address+port`). Re-runs of the same device wipe the device's
*owned* nodes (Zone, Rule, NatRule, VIP, Pool) before re-creating them;
`:Host` and `:Internet` are shared across devices and never deleted.

Indexes are created on first call (idempotent).
"""
from __future__ import annotations

import logging
from typing import Dict, Sequence

from neo4j import AsyncDriver

from app.engine.ir import NatRule, ParseWarning, Pool, VIP
from app.engine.normalize import (
    NormalizeResult,
    ResolvedAddress,
    ResolvedConfig,
    ResolvedRule,
    ResolvedService,
)

log = logging.getLogger(__name__)

INTERNET_ID = "internet"

# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA_STMTS: Sequence[str] = (
    "CREATE INDEX host_ip       IF NOT EXISTS FOR (h:Host)   ON (h.ip)",
    "CREATE INDEX subnet_cidr   IF NOT EXISTS FOR (s:Subnet) ON (s.cidr)",
    "CREATE INDEX vip_addr_port IF NOT EXISTS FOR (v:VIP)    ON (v.address, v.port)",
    "CREATE INDEX zone_dn_name  IF NOT EXISTS FOR (z:Zone)   ON (z.device_id, z.name)",
    "CREATE INDEX pool_dn_name  IF NOT EXISTS FOR (p:Pool)   ON (p.device_id, p.name)",
    "CREATE INDEX rule_dn_name  IF NOT EXISTS FOR (r:Rule)   ON (r.device_id, r.name)",
)


async def ensure_schema(driver: AsyncDriver, database: str) -> None:
    async with driver.session(database=database) as s:
        for stmt in _SCHEMA_STMTS:
            await s.run(stmt)
        # The Internet sentinel
        await s.run("MERGE (i:Internet {id: $id})", id=INTERNET_ID)


# ── Per-device load ───────────────────────────────────────────────────────────

async def load_device(driver: AsyncDriver, database: str,
                      cfg: ResolvedConfig) -> Dict[str, int]:
    """
    Idempotently replace `cfg.device_id`'s owned graph state. Returns
    rough counts for run telemetry.
    """
    counts = {"zones": 0, "rules": 0, "nat_rules": 0, "vips": 0, "pools": 0,
              "subnets": 0, "hosts": 0}

    async with driver.session(database=database) as s:
        # 1) Wipe device-owned nodes first (Zones/Rules/NatRules/VIPs/Pools).
        #    Hosts and Subnets are shared across devices — never deleted here.
        await s.run("""
        MATCH (n)
        WHERE (n:Zone OR n:Rule OR n:NatRule OR n:VIP OR n:Pool)
          AND n.device_id = $device_id
        DETACH DELETE n
        """, device_id=cfg.device_id)

        # 2) Zones (and a synthetic 'any' zone for catch-all rules)
        zone_names = sorted({z for r in cfg.rules
                             for z in (*r.src_zones, *r.dst_zones)} | {"any"})
        for name in zone_names:
            await s.run("""
            MERGE (z:Zone {device_id: $device_id, name: $name})
            """, device_id=cfg.device_id, name=name)
            counts["zones"] += 1

        # 3) Rules → :Rule node + :ALLOWS / :DENIES edges per zone-pair.
        for rule in cfg.rules:
            if rule.disabled:
                # Persist disabled rules for audit, but no edges.
                await s.run("""
                MERGE (r:Rule {device_id: $device_id, name: $name})
                SET r.position = $position, r.action = $action,
                    r.disabled = true,
                    r.services = $services
                """, device_id=cfg.device_id, name=rule.name,
                     position=rule.position, action=rule.action,
                     services=[svc.label() for svc in rule.services])
                counts["rules"] += 1
                continue

            await s.run("""
            MERGE (r:Rule {device_id: $device_id, name: $name})
            SET r.position = $position, r.action = $action,
                r.disabled = false,
                r.services = $services
            """, device_id=cfg.device_id, name=rule.name,
                 position=rule.position, action=rule.action,
                 services=[svc.label() for svc in rule.services])
            counts["rules"] += 1

            for sz in rule.src_zones:
                for dz in rule.dst_zones:
                    await s.run(f"""
                    MATCH (sz:Zone {{device_id: $device_id, name: $sz}})
                    MATCH (dz:Zone {{device_id: $device_id, name: $dz}})
                    MERGE (sz)-[e:{_edge_type_for(rule.action)} {{
                        rule_id: $rule_id, position: $position
                    }}]->(dz)
                    SET e.services = $services,
                        e.action    = $action
                    """, device_id=cfg.device_id, sz=sz, dz=dz,
                         rule_id=rule.name, position=rule.position,
                         services=[svc.label() for svc in rule.services],
                         action=rule.action)

            # 3a) Materialize destination Hosts/Subnets so reachability has
            #     concrete leaves. Each dst zone gets a CONTAINS edge.
            for dst_addr in rule.dst_addrs:
                if dst_addr.is_any() or dst_addr.cidr is None:
                    continue
                if dst_addr.cidr.endswith("/32") or dst_addr.cidr.endswith("/128"):
                    ip = dst_addr.cidr.rsplit("/", 1)[0]
                    for dz in rule.dst_zones:
                        await s.run("""
                        MERGE (h:Host {ip: $ip})
                        WITH h
                        MATCH (z:Zone {device_id: $device_id, name: $dz})
                        MERGE (z)-[:CONTAINS]->(h)
                        """, ip=ip, device_id=cfg.device_id, dz=dz)
                        counts["hosts"] += 1
                else:
                    for dz in rule.dst_zones:
                        await s.run("""
                        MERGE (s:Subnet {cidr: $cidr})
                        WITH s
                        MATCH (z:Zone {device_id: $device_id, name: $dz})
                        MERGE (z)-[:CONTAINS]->(s)
                        """, cidr=dst_addr.cidr, device_id=cfg.device_id, dz=dz)
                        counts["subnets"] += 1

        # 4) NAT rules: Internet-facing DNAT becomes EXPOSES + DNAT_TO.
        for nat in cfg.nat_rules:
            await _load_nat(s, cfg.device_id, nat, counts)

        # 5) VIPs (F5 + PAN-OS DNAT-derived) — `EXPOSES` from Internet,
        #    `FORWARDS_TO` to Pool. Pool members add `MEMBER_OF` from Host.
        pool_index: Dict[str, Pool] = {p.name: p for p in cfg.pools}
        for vip in cfg.vips:
            await s.run("""
            MERGE (v:VIP {device_id: $device_id, address: $address, port: $port})
            SET v.name = $name, v.protocol = $protocol
            WITH v
            MATCH (i:Internet {id: $internet})
            MERGE (i)-[e:EXPOSES {port: $port, proto: $protocol}]->(v)
            """, device_id=cfg.device_id, name=vip.name,
                 address=vip.address, port=vip.port, protocol=vip.protocol,
                 internet=INTERNET_ID)
            counts["vips"] += 1

            if vip.pool_name and vip.pool_name in pool_index:
                pool = pool_index[vip.pool_name]
                await _load_pool(s, cfg.device_id, pool, counts)
                await s.run("""
                MATCH (v:VIP {device_id: $device_id, address: $address, port: $port})
                MATCH (p:Pool {device_id: $device_id, name: $pool_name})
                MERGE (v)-[:FORWARDS_TO {lb_method: $lb}]->(p)
                """, device_id=cfg.device_id, address=vip.address, port=vip.port,
                     pool_name=pool.name, lb=pool.lb_method)

    return counts


async def _load_pool(s, device_id: str, pool: Pool, counts: Dict[str, int]) -> None:
    await s.run("""
    MERGE (p:Pool {device_id: $device_id, name: $name})
    SET p.lb_method   = $lb,
        p.member_count = $count
    """, device_id=device_id, name=pool.name, lb=pool.lb_method,
         count=len(pool.members))
    counts["pools"] += 1
    for member in pool.members:
        # Pool members can be "node-name:port" or "ip:port"; normalize to IP.
        addr = member.address
        await s.run("""
        MERGE (h:Host {ip: $ip})
        WITH h
        MATCH (p:Pool {device_id: $device_id, name: $pool})
        MERGE (h)-[m:MEMBER_OF {port: $port}]->(p)
        SET m.monitor_state = $state
        """, ip=addr, device_id=device_id, pool=pool.name,
             port=member.port, state=member.monitor_state)
        counts["hosts"] += 1


async def _load_nat(s, device_id: str, nat: NatRule,
                    counts: Dict[str, int]) -> None:
    """
    For DNAT (1.2.3.4:443 → 10.0.0.5:443), produce:
      (Internet)-[EXPOSES]->(VIP {1.2.3.4,443})-[DNAT_TO]->(Host {10.0.0.5})
    SNAT/static are persisted as Rule-style nodes for traceability but don't
    contribute reachability edges in the MVP (they primarily affect identity,
    not access).
    """
    await s.run("""
    MERGE (n:NatRule {device_id: $device_id, name: $name})
    SET n.kind = $kind, n.position = $position,
        n.pre_dst = $pre_dst, n.post_dst = $post_dst
    """, device_id=device_id, name=nat.name, kind=nat.kind,
         position=nat.position, pre_dst=nat.pre_dst, post_dst=nat.post_dst)
    counts["nat_rules"] += 1

    if nat.kind != "dnat" or not nat.post_dst:
        return

    # pre_dst can be a comma-joined list; expand each entry that looks like ip[:port].
    pre_targets = [t.strip() for t in (nat.pre_dst or "").split(",") if t.strip()]
    for pre in pre_targets:
        addr, port = _split_addr_port(pre, nat.post_dst_port)
        if addr is None or port is None:
            continue
        await s.run("""
        MERGE (v:VIP {device_id: $device_id, address: $addr, port: $port})
        SET v.name = $name, v.protocol = $protocol
        WITH v
        MATCH (i:Internet {id: $internet})
        MERGE (i)-[e:EXPOSES {port: $port, proto: $protocol}]->(v)
        WITH v
        MERGE (h:Host {ip: $post})
        MERGE (v)-[:DNAT_TO {rule_id: $name}]->(h)
        """, device_id=device_id, addr=addr, port=port, name=nat.name,
             protocol="tcp", internet=INTERNET_ID, post=nat.post_dst)
        counts["vips"] += 1
        counts["hosts"] += 1


def _split_addr_port(value: str, fallback_port: str | None) -> tuple[str | None, int | None]:
    if ":" in value:
        addr, port_s = value.rsplit(":", 1)
        try:
            return addr, int(port_s)
        except ValueError:
            pass
    if fallback_port:
        try:
            return value, int(fallback_port)
        except ValueError:
            return None, None
    return None, None


def _edge_type_for(action: str) -> str:
    # Cypher relationship types must be uppercase identifiers.
    return "ALLOWS" if action == "allow" else "DENIES"


# ── Run-level entry point ─────────────────────────────────────────────────────

async def load_run(driver: AsyncDriver, database: str,
                   normalized: NormalizeResult) -> Dict[str, int]:
    """Load all devices in a run. Returns aggregated counts."""
    await ensure_schema(driver, database)

    totals: Dict[str, int] = {}
    for cfg in normalized.configs:
        try:
            counts = await load_device(driver, database, cfg)
            for k, v in counts.items():
                totals[k] = totals.get(k, 0) + v
        except Exception as exc:                                # noqa: BLE001
            log.exception("device %s load failed", cfg.device_id)
            normalized.warnings.append(ParseWarning(
                file=cfg.device_id, severity="error",
                message=f"load failed: {exc}",
            ))
    return totals
