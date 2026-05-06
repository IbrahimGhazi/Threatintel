"""
Curated subgraph reads for the UI.

Returns nodes + edges in a Cytoscape-friendly shape. Always parameter-clamped
(maxLevel + truncated flag) so a malformed query can't dump the whole graph.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from app.db import get_neo4j

log = logging.getLogger(__name__)

_HARD_NODE_LIMIT = 2000
_HARD_EDGE_LIMIT = 5000


async def build_subgraph(
    asset_ip: Optional[str] = None,
    max_hops: int = 6,
    include_internet: bool = True,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], bool]:
    driver = get_neo4j()
    from app.config import get_settings
    db = get_settings().neo4j_database

    if asset_ip:
        cypher = """
        MATCH (i:Internet {id:'internet'}), (h:Host {ip:$asset_ip})
        MATCH p = allShortestPaths((i)-[*..%(max_hops)d]->(h))
        UNWIND nodes(p) AS n
        WITH collect(DISTINCT n) AS ns
        MATCH (a)-[r]->(b)
        WHERE a IN ns AND b IN ns
        RETURN ns AS nodes, collect(DISTINCT r) AS rels
        """ % {"max_hops": max_hops}
        params = {"asset_ip": asset_ip}
    else:
        cypher = """
        MATCH (i:Internet {id:'internet'})
        CALL apoc.path.subgraphAll(i, {
            relationshipFilter: 'EXPOSES>|DNAT_TO>|FORWARDS_TO>|MEMBER_OF<|ALLOWS>|CONTAINS>',
            maxLevel: $max_hops
        }) YIELD nodes, relationships
        RETURN nodes, relationships AS rels
        """
        params = {"max_hops": max_hops}

    nodes_out: List[Dict[str, Any]] = []
    edges_out: List[Dict[str, Any]] = []
    truncated = False

    async with driver.session(database=db, default_access_mode="READ") as s:
        rec = await (await s.run(cypher, **params)).single()
        if not rec:
            return nodes_out, edges_out, truncated

        ns = rec.get("nodes") or []
        rs = rec.get("rels") or []

        for n in ns[:_HARD_NODE_LIMIT]:
            labels = list(n.labels)
            if not include_internet and "Internet" in labels:
                continue
            nodes_out.append({
                "id": n.element_id,
                "kind": labels[0] if labels else "Unknown",
                "labels": labels,
                "props": dict(n.items()),
            })
        if len(ns) > _HARD_NODE_LIMIT:
            truncated = True

        for r in rs[:_HARD_EDGE_LIMIT]:
            edges_out.append({
                "id": r.element_id,
                "type": r.type,
                "source": r.start_node.element_id,
                "target": r.end_node.element_id,
                "props": dict(r.items()),
            })
        if len(rs) > _HARD_EDGE_LIMIT:
            truncated = True

    return nodes_out, edges_out, truncated
