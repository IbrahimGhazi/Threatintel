"""
Analysis engine — reachability, attack-paths, and fan-out detection.

All queries operate on the canonical graph in Neo4j. Results are pure
Python dicts ready for scoring + findings writing.

The plan's submodule split is preserved here in three top-level functions:
  - reachability_from_internet
  - attack_paths_to_assets
  - detect_fan_out_nodes
"""
from __future__ import annotations

import logging
from typing import Dict, List, Sequence, Tuple

from neo4j import AsyncDriver

from app.engine.types import FanOutCandidate, PathCandidate

log = logging.getLogger(__name__)

# ── Cypher query constants ────────────────────────────────────────────────────

# Reachability: BFS-flavour subgraph traversal with edge whitelist + maxLevel.
_Q_REACH = """
MATCH (i:Internet {id: 'internet'})
CALL apoc.path.subgraphNodes(i, {
    relationshipFilter: 'EXPOSES>|DNAT_TO>|FORWARDS_TO>|MEMBER_OF<|ALLOWS>|CONTAINS>',
    labelFilter: '+Host|+VIP|+Zone|+Pool|+Subnet',
    maxLevel: $max_depth
})
YIELD node
WHERE node:Host
RETURN DISTINCT node.ip AS ip
"""

# Attack paths: enumerate simple paths Internet → Host(:Asset) up to maxDepth.
# We dedupe by (asset, ordered list of node-kinds) post-hoc in Python.
_Q_PATHS = """
MATCH (i:Internet {id: 'internet'})
MATCH (h:Host)
WHERE h.ip IN $asset_ips
CALL apoc.algo.allSimplePaths(i, h,
    'EXPOSES>|DNAT_TO>|FORWARDS_TO>|MEMBER_OF<|ALLOWS>|CONTAINS>',
    $max_depth) YIELD path
WITH h, path, length(path) AS hops
RETURN h.ip AS asset_ip, hops,
       [n IN nodes(path) | { labels: labels(n), props: properties(n) }] AS path_nodes,
       [r IN relationships(path) | { type: type(r), props: properties(r) }] AS path_edges
ORDER BY hops ASC
LIMIT $hard_limit
"""

# Fan-out: nodes with high outbound branching but few Internet ingresses.
_Q_FANOUT = """
MATCH (n)-[r]->(t:Host)
WHERE NOT n:Internet
WITH n, count(DISTINCT t) AS outdeg
WHERE outdeg >= $out_min
WITH collect({n: n, outdeg: outdeg}) AS cand
UNWIND cand AS c
MATCH (i:Internet {id: 'internet'})
OPTIONAL MATCH p = shortestPath((i)-[*..6]->(c.n))
WITH c.n AS n, c.outdeg AS outdeg, count(p) AS ingress_paths
WHERE ingress_paths <= $in_max
RETURN labels(n)[0] AS kind,
       properties(n) AS props,
       outdeg, ingress_paths
ORDER BY (1.0 * outdeg / (ingress_paths + 1)) DESC
LIMIT 50
"""


# ── Public functions ──────────────────────────────────────────────────────────

async def reachability_from_internet(driver: AsyncDriver, database: str,
                                     *, max_depth: int = 6) -> List[str]:
    async with driver.session(database=database, default_access_mode="READ") as s:
        result = await s.run(_Q_REACH, max_depth=max_depth)
        return [record["ip"] async for record in result if record["ip"]]


async def attack_paths_to_assets(
    driver: AsyncDriver, database: str,
    asset_ips: Sequence[str], *,
    max_depth: int = 6,
    top_k_per_asset: int = 5,
    hard_limit: int = 500,
) -> List[PathCandidate]:
    """
    Returns ranked, shadow-filtered, dedup'd candidate paths. Top-K per
    asset is applied after rule-shadow filtering.
    """
    if not asset_ips:
        return []
    async with driver.session(database=database, default_access_mode="READ") as s:
        result = await s.run(_Q_PATHS,
                             asset_ips=list(asset_ips),
                             max_depth=max_depth,
                             hard_limit=hard_limit)
        raw: List[PathCandidate] = []
        async for rec in result:
            raw.append(PathCandidate(
                asset_ip=rec["asset_ip"],
                hops=rec["hops"],
                nodes=list(rec["path_nodes"]),
                edges=list(rec["path_edges"]),
            ))

    filtered = await _filter_shadowed_paths(driver, database, raw)
    deduped = _dedup_paths(filtered)
    return _top_k_per_asset(deduped, top_k_per_asset)


async def detect_fan_out_nodes(
    driver: AsyncDriver, database: str, *,
    out_min: int = 5, in_max: int = 3,
) -> List[FanOutCandidate]:
    async with driver.session(database=database, default_access_mode="READ") as s:
        result = await s.run(_Q_FANOUT, out_min=out_min, in_max=in_max)
        out: List[FanOutCandidate] = []
        async for rec in result:
            out.append(FanOutCandidate(
                kind=rec["kind"], props=dict(rec["props"]),
                outdeg=rec["outdeg"], ingress_paths=rec["ingress_paths"],
            ))
        return out


# ── Private helpers ───────────────────────────────────────────────────────────

async def _filter_shadowed_paths(
    driver: AsyncDriver, database: str,
    paths: List[PathCandidate],
) -> List[PathCandidate]:
    """
    For each path's :ALLOWS edges, drop the path if a lower-position :DENIES
    rule on the same (device_id, src_zone, dst_zone) exists. PAN-OS evaluates
    rules first-match, so an earlier deny shadows a later allow.
    """
    if not paths:
        return []

    # Collect ((device_id, src_zone, dst_zone) → minimum allow position) lookups
    # we need, then load deny positions in one query.
    keys: set[Tuple[str, str, str]] = set()
    for p in paths:
        for i, edge in enumerate(p.edges):
            if edge.get("type") != "ALLOWS":
                continue
            src = p.nodes[i]
            dst = p.nodes[i + 1] if i + 1 < len(p.nodes) else None
            if not src or not dst:
                continue
            if "Zone" not in src.get("labels", []) or "Zone" not in dst.get("labels", []):
                continue
            device_id = src["props"].get("device_id")
            if not device_id:
                continue
            keys.add((device_id, src["props"].get("name"), dst["props"].get("name")))

    if not keys:
        return paths

    deny_by_key: Dict[Tuple[str, str, str], int] = {}
    async with driver.session(database=database, default_access_mode="READ") as s:
        for device_id, sz, dz in keys:
            result = await s.run("""
            MATCH (sz:Zone {device_id: $d, name: $sz})-[e:DENIES]->(dz:Zone {device_id: $d, name: $dz})
            RETURN min(e.position) AS pos
            """, d=device_id, sz=sz, dz=dz)
            rec = await result.single()
            if rec and rec["pos"] is not None:
                deny_by_key[(device_id, sz, dz)] = int(rec["pos"])

    if not deny_by_key:
        return paths

    out: List[PathCandidate] = []
    for p in paths:
        shadowed = False
        for i, edge in enumerate(p.edges):
            if edge.get("type") != "ALLOWS":
                continue
            allow_pos = edge.get("props", {}).get("position")
            if allow_pos is None:
                continue
            src = p.nodes[i]
            dst = p.nodes[i + 1] if i + 1 < len(p.nodes) else None
            if not src or not dst:
                continue
            device_id = src["props"].get("device_id")
            sz = src["props"].get("name")
            dz = dst["props"].get("name")
            deny_pos = deny_by_key.get((device_id, sz, dz))
            if deny_pos is not None and deny_pos < int(allow_pos):
                shadowed = True
                break
        if not shadowed:
            out.append(p)
    return out


def _dedup_paths(paths: List[PathCandidate]) -> List[PathCandidate]:
    """Collapse paths that differ only by which pool member they hit."""
    seen: Dict[Tuple, PathCandidate] = {}
    for p in paths:
        kinds = []
        for n in p.nodes:
            labels = n.get("labels") or []
            kind = labels[0] if labels else "?"
            kinds.append(kind)
        edge_types = [e.get("type", "?") for e in p.edges]
        key = (p.asset_ip, tuple(kinds), tuple(edge_types))
        if key not in seen:
            seen[key] = p
    return list(seen.values())


def _top_k_per_asset(paths: List[PathCandidate], k: int) -> List[PathCandidate]:
    grouped: Dict[str, List[PathCandidate]] = {}
    for p in paths:
        grouped.setdefault(p.asset_ip, []).append(p)
    out: List[PathCandidate] = []
    for asset_ip, ps in grouped.items():
        ps.sort(key=lambda x: x.hops)
        out.extend(ps[:k])
    return out
