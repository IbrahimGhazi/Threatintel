"""
Network Investigation Graph – Attack-centric visualization API.

Replaces the raw connection topology with a hierarchical, threat-scored,
attack-chain-aware investigation tool.

GET /network/graph      → full investigation graph (clusters, nodes, edges,
                           attack chains, timeline buckets)
GET /network/stats      → summary counts for dashboard widget
GET /network/node/{ip}  → deep-dive detail for a single IP
"""
from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, Body, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key

router = APIRouter(prefix="/network", tags=["Network"])

# ── Host metadata schemas ────────────────────────────────────────────────────

class HostMetaIn(BaseModel):
    name: Optional[str] = None
    device_type: str = "unknown"
    x_position: Optional[float] = None
    y_position: Optional[float] = None
    notes: Optional[str] = None

# ── Helpers ───────────────────────────────────────────────────────────────────

_SEV_SCORE = {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 0}
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Well-known infrastructure ports used for noise detection
_INFRA_PORTS = {53, 67, 68, 123, 443, 80, 8080, 8443}
# Management ports → lateral movement indicator
_MGMT_PORTS = {22, 135, 139, 445, 3389, 5985, 5986, 1433, 3306, 5432}
# Recon ports
_RECON_PORTS = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445}

# MITRE ATT&CK stage ordering for attack chain reconstruction
_STAGE_ORDER = {
    "reconnaissance": 0, "resource_development": 1, "initial_access": 2,
    "execution": 3, "persistence": 4, "privilege_escalation": 5,
    "defense_evasion": 6, "credential_access": 7, "discovery": 8,
    "lateral_movement": 9, "collection": 10, "command_and_control": 11,
    "exfiltration": 12, "impact": 13,
}

# Rule → attack stage mapping
_RULE_STAGE: Dict[str, str] = {
    "port_scan":                     "reconnaissance",
    "host_discovery":                "reconnaissance",
    "service_scan":                  "reconnaissance",
    "repeated_connection_attempts":  "reconnaissance",
    "repeated_blocked_connections":  "reconnaissance",
    "brute_force":                   "credential_access",
    "password_spray":                "credential_access",
    "lateral_movement":              "lateral_movement",
    "malicious_ip_connection":       "command_and_control",
    "c2_beaconing":                  "command_and_control",
    "dns_tunneling":                 "exfiltration",
    "outbound_data_burst":           "exfiltration",
    "suspicious_rdp_burst":          "lateral_movement",
    "multi_stage_attack":            "initial_access",
    "ti_match":                      "initial_access",
}

# Semantic edge classification
_EDGE_TYPE_RECON = "recon"
_EDGE_TYPE_LATERAL = "lateral"
_EDGE_TYPE_C2 = "c2"
_EDGE_TYPE_EXFIL = "exfil"
_EDGE_TYPE_NORMAL = "normal"
_EDGE_TYPE_INFRA = "infra"


def _is_internal(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            return False
        a, b = parts[0], parts[1]
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 127)
        )
    except Exception:
        return False


def _subnet_key(ip: str) -> str:
    """Return /24 subnet key for clustering."""
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return "unknown"


def _compute_threat_score(
    alert_count: int,
    severity: str,
    ti_match: bool,
    rule_names: List[str],
    malicious_conn_count: int,
    is_internal: bool,
) -> float:
    """
    Dynamic threat score 0-100 combining:
    - Alert severity weight
    - Alert volume
    - TI match bonus
    - Attack stage diversity bonus
    - Malicious connection ratio
    - Internal amplifier (compromised internal hosts are worse)
    """
    score = 0.0
    # Severity base
    score += _SEV_SCORE.get(severity, 0)
    # Alert volume (log scale)
    if alert_count > 0:
        score += min(15, math.log2(alert_count + 1) * 5)
    # TI match
    if ti_match:
        score += 15
    # Attack stage diversity
    stages = set()
    for r in rule_names:
        stage = _RULE_STAGE.get(r)
        if stage:
            stages.add(stage)
    score += min(15, len(stages) * 5)
    # Malicious connections
    if malicious_conn_count > 0:
        score += min(10, math.log2(malicious_conn_count + 1) * 4)
    # Internal amplifier
    if is_internal and score > 20:
        score *= 1.15
    return min(100.0, round(score, 1))


def _classify_edge(
    src_ip: str,
    dst_ip: str,
    top_port: Optional[int],
    top_protocol: Optional[str],
    is_malicious: bool,
    src_rules: List[str],
    dst_rules: List[str],
) -> str:
    """Classify an edge into a semantic attack type."""
    all_rules = src_rules + dst_rules
    src_internal = _is_internal(src_ip)
    dst_internal = _is_internal(dst_ip)

    # C2: internal→external with c2/malicious_ip rules
    if src_internal and not dst_internal:
        if any(r in ("c2_beaconing", "malicious_ip_connection") for r in all_rules):
            return _EDGE_TYPE_C2

    # Exfiltration: internal→external with exfil rules or data burst
    if src_internal and not dst_internal:
        if any(r in ("dns_tunneling", "outbound_data_burst") for r in all_rules):
            return _EDGE_TYPE_EXFIL

    # Lateral movement: internal→internal on management ports
    if src_internal and dst_internal:
        if top_port and top_port in _MGMT_PORTS:
            return _EDGE_TYPE_LATERAL
        if any(r in ("lateral_movement", "suspicious_rdp_burst") for r in all_rules):
            return _EDGE_TYPE_LATERAL

    # Recon: scanning rules
    if any(r in ("port_scan", "host_discovery", "service_scan",
                 "repeated_connection_attempts") for r in all_rules):
        return _EDGE_TYPE_RECON

    # Infrastructure: DNS, NTP, HTTP to well-known ports
    if top_port and top_port in _INFRA_PORTS and not is_malicious:
        return _EDGE_TYPE_INFRA

    if is_malicious:
        return _EDGE_TYPE_RECON  # generic suspicious

    return _EDGE_TYPE_NORMAL


def _detect_attack_chains(
    alerts_by_ip: Dict[str, List[Dict]],
    edges: List[Dict],
) -> List[Dict[str, Any]]:
    """
    Reconstruct attack chains by finding sequences of correlated alerts
    across IPs that follow a logical attack progression.
    """
    chains: List[Dict[str, Any]] = []

    # Build adjacency: src → [dst]
    adj: Dict[str, Set[str]] = defaultdict(set)
    for e in edges:
        adj[e["source"]].add(e["target"])

    # For each IP with alerts, try to build a chain
    visited_chains: Set[str] = set()

    for start_ip, alerts in alerts_by_ip.items():
        if not _is_internal(start_ip):
            continue

        # Get stages for this IP
        start_stages = set()
        for a in alerts:
            stage = _RULE_STAGE.get(a.get("rule_name", ""))
            if stage:
                start_stages.add(stage)

        # Only start chains from early-stage activity
        if not start_stages & {"reconnaissance", "credential_access", "initial_access"}:
            continue

        # BFS to find connected IPs with later-stage activity
        chain_nodes = [start_ip]
        chain_stages = {start_ip: start_stages}
        all_stages = set(start_stages)
        frontier = [start_ip]
        seen = {start_ip}

        for _ in range(5):  # max depth
            next_frontier = []
            for ip in frontier:
                for neighbor in adj.get(ip, set()):
                    if neighbor in seen:
                        continue
                    n_alerts = alerts_by_ip.get(neighbor, [])
                    n_stages = set()
                    for a in n_alerts:
                        stage = _RULE_STAGE.get(a.get("rule_name", ""))
                        if stage:
                            n_stages.add(stage)
                    if n_stages:
                        seen.add(neighbor)
                        chain_nodes.append(neighbor)
                        chain_stages[neighbor] = n_stages
                        all_stages |= n_stages
                        next_frontier.append(neighbor)
            frontier = next_frontier
            if not frontier:
                break

        # Only emit if chain spans 2+ distinct stages and 2+ nodes
        if len(all_stages) >= 2 and len(chain_nodes) >= 2:
            chain_key = "|".join(sorted(chain_nodes))
            if chain_key in visited_chains:
                continue
            visited_chains.add(chain_key)

            # Sort by attack stage order
            ordered_stages = sorted(all_stages, key=lambda s: _STAGE_ORDER.get(s, 99))
            severity = "critical" if len(all_stages) >= 4 else (
                "high" if len(all_stages) >= 3 else "medium"
            )

            # Build path with stage info
            path = []
            for ip in chain_nodes:
                ip_stages = sorted(
                    chain_stages.get(ip, set()),
                    key=lambda s: _STAGE_ORDER.get(s, 99),
                )
                ip_alerts = alerts_by_ip.get(ip, [])
                path.append({
                    "ip": ip,
                    "stages": ip_stages,
                    "alert_count": len(ip_alerts),
                    "rules": list(set(a.get("rule_name", "") for a in ip_alerts)),
                })

            chains.append({
                "id": f"chain-{len(chains)}",
                "path": path,
                "stages": ordered_stages,
                "severity": severity,
                "node_count": len(chain_nodes),
                "stage_count": len(all_stages),
                "description": (
                    f"Attack progression: {' → '.join(s.replace('_', ' ').title() for s in ordered_stages)}"
                ),
            })

    # Sort chains by severity and stage count
    chains.sort(
        key=lambda c: (_SEV_ORDER.get(c["severity"], 0), c["stage_count"]),
        reverse=True,
    )
    return chains[:20]  # top 20 chains


# ── Main graph endpoint ───────────────────────────────────────────────────────

@router.get("/graph")
async def get_network_graph(
    hours: int = Query(24, ge=1, le=168, description="Look-back window in hours"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    severity: Optional[str] = Query(None, description="Min severity filter"),
    node_type: Optional[str] = Query(None, description="'internal' or 'external'"),
    show_infra: bool = Query(False, description="Include collapsed infrastructure nodes"),
    timeline_buckets: int = Query(12, ge=4, le=48, description="Number of timeline buckets"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # ── 1. Edges with protocol/port metadata ──────────────────────────────────
    edge_filters = [
        "COALESCE(log_timestamp, processed_at) >= :since",
        "parsed->>'src_ip' IS NOT NULL",
        "parsed->>'dst_ip' IS NOT NULL",
        "parsed->>'src_ip' <> ''",
        "parsed->>'dst_ip' <> ''",
        "parsed->>'src_ip' <> parsed->>'dst_ip'",
    ]
    edge_params: Dict[str, Any] = {"since": since}
    if src_ip:
        edge_filters.append(
            "(parsed->>'src_ip' = :src_ip OR parsed->>'dst_ip' = :src_ip)"
        )
        edge_params["src_ip"] = src_ip

    edge_sql = text(f"""
        SELECT
            parsed->>'src_ip'    AS src_ip,
            parsed->>'dst_ip'    AS dst_ip,
            COUNT(*)              AS connection_count,
            SUM(CASE WHEN is_malicious THEN 1 ELSE 0 END) AS malicious_count,
            MAX(COALESCE(log_timestamp, processed_at)) AS last_seen,
            MIN(COALESCE(log_timestamp, processed_at)) AS first_seen,
            MODE() WITHIN GROUP (ORDER BY parsed->>'protocol')   AS top_protocol,
            MODE() WITHIN GROUP (ORDER BY parsed->>'dst_port')   AS top_port,
            MODE() WITHIN GROUP (ORDER BY parsed->>'action')     AS top_action,
            SUM(COALESCE((parsed->>'bytes_sent')::bigint, 0))    AS total_bytes_sent,
            SUM(COALESCE((parsed->>'bytes_received')::bigint,0)) AS total_bytes_recv
        FROM log_entries
        WHERE {" AND ".join(edge_filters)}
        GROUP BY parsed->>'src_ip', parsed->>'dst_ip'
        ORDER BY malicious_count DESC, connection_count DESC
        LIMIT 2000
    """)
    edge_rows = (await db.execute(edge_sql, edge_params)).fetchall()

    # ── 2. Alerts with full context per IP ────────────────────────────────────
    alert_sql = text("""
        SELECT
            COALESCE(
                CASE WHEN indicator_type = 'ip' THEN indicator_value END,
                context->>'source_ip'
            )                     AS ip,
            id                    AS alert_id,
            severity,
            rule_name,
            context->>'mitre_attack' AS mitre_json,
            context->>'stages'       AS stages_json,
            created_at
        FROM alerts
        WHERE created_at >= :since
          AND status != 'false_positive'
        ORDER BY created_at DESC
    """)
    alert_rows = (await db.execute(alert_sql, {"since": since})).fetchall()

    # Build per-IP alert data
    alerts_by_ip: Dict[str, List[Dict]] = defaultdict(list)
    ip_alert_summary: Dict[str, Dict] = {}

    for row in alert_rows:
        ip = row.ip
        if not ip:
            continue
        alerts_by_ip[ip].append({
            "alert_id": str(row.alert_id),
            "severity": row.severity,
            "rule_name": row.rule_name,
            "mitre_json": row.mitre_json,
            "stages_json": row.stages_json,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        })

        if ip not in ip_alert_summary:
            ip_alert_summary[ip] = {
                "severity": row.severity,
                "alert_count": 0,
                "rules": set(),
                "mitre_techniques": set(),
                "stages": set(),
                "last_alert_at": row.created_at,
                "ti_match": False,
            }
        summary = ip_alert_summary[ip]
        summary["alert_count"] += 1
        if row.rule_name:
            summary["rules"].add(row.rule_name)
        if _SEV_ORDER.get(row.severity, 0) > _SEV_ORDER.get(summary["severity"], 0):
            summary["severity"] = row.severity
        if row.rule_name in ("malicious_ip_connection", "ti_match"):
            summary["ti_match"] = True

        # Parse MITRE
        if row.mitre_json:
            try:
                import json
                mitre_list = json.loads(row.mitre_json) if isinstance(row.mitre_json, str) else row.mitre_json
                for m in mitre_list:
                    tid = m.get("technique_id", "")
                    if tid:
                        summary["mitre_techniques"].add(tid)
            except Exception:
                pass

        # Parse stages
        stage = _RULE_STAGE.get(row.rule_name or "")
        if stage:
            summary["stages"].add(stage)

    # ── 3. Build IP set from edges ────────────────────────────────────────────
    ip_conn_count: Dict[str, int] = defaultdict(int)
    ip_malicious_conn: Dict[str, int] = defaultdict(int)
    for row in edge_rows:
        if row.src_ip:
            ip_conn_count[row.src_ip] += int(row.connection_count)
        if row.dst_ip:
            ip_conn_count[row.dst_ip] += int(row.connection_count)
        if int(row.malicious_count) > 0:
            ip_malicious_conn[row.src_ip] += int(row.malicious_count)
            ip_malicious_conn[row.dst_ip] += int(row.malicious_count)

    all_ips = set(ip_conn_count.keys())

    # ── 3b. Host metadata (user-assigned names, types, positions) ──────────
    host_meta_map: Dict[str, Dict] = {}
    try:
        hm_rows = (await db.execute(text(
            "SELECT ip, name, device_type, x_position, y_position FROM host_metadata"
        ))).fetchall()
        for r in hm_rows:
            host_meta_map[r.ip] = {
                "name": r.name,
                "device_type": r.device_type,
                "x_position": r.x_position,
                "y_position": r.y_position,
            }
    except Exception:
        pass  # table may not exist yet

    # ── 3c. GeoIP country enrichment ─────────────────────────────────────────
    geo_map: Dict[str, Dict[str, str]] = {}  # ip → {country_code, country_name}
    if all_ips:
        geo_sql = text("""
            SELECT value AS ip,
                   enrichment->'geoip'->>'country_code' AS cc,
                   enrichment->'geoip'->>'country_name' AS cn
            FROM indicators
            WHERE type = 'ip'
              AND enrichment->'geoip'->>'country_code' IS NOT NULL
        """)
        geo_rows = (await db.execute(geo_sql)).fetchall()
        for r in geo_rows:
            geo_map[r.ip] = {"country_code": r.cc, "country_name": r.cn}

    # ── 4. Noise reduction: detect infrastructure nodes ───────────────────────
    infra_ips: Set[str] = set()
    for ip in all_ips:
        if ip in ip_alert_summary:
            continue  # never collapse alerted nodes
        conn = ip_conn_count.get(ip, 0)
        # High fan-in/out with no alerts → likely infrastructure
        if conn > 100 and not _is_internal(ip):
            infra_ips.add(ip)

    # ── 5. Build nodes with threat scores ─────────────────────────────────────
    SEV_FILTER = severity.lower() if severity and severity != "all" else None
    nodes: List[Dict[str, Any]] = []
    collapsed_infra: Dict[str, Dict] = {}  # subnet → summary

    for ip in all_ips:
        n_type = "internal" if _is_internal(ip) else "external"
        if node_type and n_type != node_type:
            continue

        summary = ip_alert_summary.get(ip, {})
        sev = summary.get("severity", "info")
        alert_count = summary.get("alert_count", 0)
        rules = list(summary.get("rules", set()))
        ti_match = summary.get("ti_match", False)
        mitre = list(summary.get("mitre_techniques", set()))
        stages = sorted(
            summary.get("stages", set()),
            key=lambda s: _STAGE_ORDER.get(s, 99),
        )

        threat_score = _compute_threat_score(
            alert_count, sev, ti_match, rules,
            ip_malicious_conn.get(ip, 0), n_type == "internal",
        )

        # Apply severity filter
        if SEV_FILTER:
            min_sev = _SEV_ORDER.get(SEV_FILTER, 0)
            if _SEV_ORDER.get(sev, 0) < min_sev and threat_score < 20:
                continue

        # Noise reduction: collapse infra nodes
        if ip in infra_ips and not show_infra:
            subnet = _subnet_key(ip)
            if subnet not in collapsed_infra:
                collapsed_infra[subnet] = {
                    "id": f"infra-{subnet}",
                    "label": subnet,
                    "type": "infrastructure",
                    "collapsed": True,
                    "member_count": 0,
                    "members": [],
                    "total_connections": 0,
                    "threat_score": 0,
                    "severity": "info",
                }
            c = collapsed_infra[subnet]
            c["member_count"] += 1
            c["members"].append(ip)
            c["total_connections"] += ip_conn_count.get(ip, 0)
            continue

        geo = geo_map.get(ip, {})
        hm = host_meta_map.get(ip, {})
        nodes.append({
            "id": ip,
            "ip": ip,
            "type": n_type,
            "subnet": _subnet_key(ip),
            "country_code": geo.get("country_code", ""),
            "country_name": geo.get("country_name", ""),
            "threat_score": threat_score,
            "alert_count": alert_count,
            "severity": sev,
            "has_alert": alert_count > 0,
            "ti_match": ti_match,
            "rules_triggered": rules,
            "mitre_techniques": mitre,
            "attack_stages": stages,
            "connection_count": ip_conn_count.get(ip, 0),
            "malicious_connections": ip_malicious_conn.get(ip, 0),
            "last_alert_at": (
                summary["last_alert_at"].isoformat()
                if summary.get("last_alert_at") else None
            ),
            # Host metadata (user-defined)
            "host_name": hm.get("name"),
            "device_type": hm.get("device_type", "unknown"),
            "saved_x": hm.get("x_position"),
            "saved_y": hm.get("y_position"),
        })

    # Add collapsed infra nodes
    for c in collapsed_infra.values():
        nodes.append(c)

    # ── 6. Build clusters (hierarchical grouping) ─────────────────────────────
    cluster_map: Dict[str, Dict] = {}
    for node in nodes:
        if node.get("collapsed"):
            continue
        subnet = node.get("subnet", "unknown")
        ip = node["id"]
        n_type = node.get("type", "external")

        # Cluster key: subnet for internal, "external" bucket for external
        cluster_key = subnet if n_type == "internal" else "external"

        if cluster_key not in cluster_map:
            cluster_map[cluster_key] = {
                "id": f"cluster-{cluster_key}",
                "label": cluster_key,
                "type": "internal" if _is_internal(cluster_key.split("/")[0]) else "external",
                "node_ids": [],
                "threat_score": 0,
                "max_severity": "info",
                "alert_count": 0,
                "has_attack_chain": False,
            }
        c = cluster_map[cluster_key]
        c["node_ids"].append(ip)
        c["threat_score"] = max(c["threat_score"], node.get("threat_score", 0))
        c["alert_count"] += node.get("alert_count", 0)
        node_sev = node.get("severity", "info")
        if _SEV_ORDER.get(node_sev, 0) > _SEV_ORDER.get(c["max_severity"], 0):
            c["max_severity"] = node_sev

    clusters = list(cluster_map.values())

    # ── 7. Build edges with semantic types ────────────────────────────────────
    node_ids = {n["id"] for n in nodes}
    # Map collapsed IPs to their infra node
    infra_ip_to_node: Dict[str, str] = {}
    for c in collapsed_infra.values():
        for member_ip in c.get("members", []):
            infra_ip_to_node[member_ip] = c["id"]

    edges: List[Dict[str, Any]] = []
    for row in edge_rows:
        src, dst = row.src_ip, row.dst_ip
        # Resolve collapsed nodes
        src_id = infra_ip_to_node.get(src, src)
        dst_id = infra_ip_to_node.get(dst, dst)
        if src_id not in node_ids or dst_id not in node_ids:
            continue

        src_rules = list(ip_alert_summary.get(src, {}).get("rules", set()))
        dst_rules = list(ip_alert_summary.get(dst, {}).get("rules", set()))
        top_port = None
        try:
            top_port = int(row.top_port) if row.top_port else None
        except (ValueError, TypeError):
            pass

        edge_type = _classify_edge(
            src, dst, top_port, row.top_protocol,
            int(row.malicious_count) > 0, src_rules, dst_rules,
        )

        edges.append({
            "source": src_id,
            "target": dst_id,
            "count": int(row.connection_count),
            "malicious": int(row.malicious_count) > 0,
            "malicious_count": int(row.malicious_count),
            "edge_type": edge_type,
            "protocol": row.top_protocol or "unknown",
            "port": top_port,
            "action": row.top_action or "unknown",
            "bytes_sent": int(row.total_bytes_sent or 0),
            "bytes_recv": int(row.total_bytes_recv or 0),
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        })

    # ── 8. Attack chain reconstruction ────────────────────────────────────────
    attack_chains = _detect_attack_chains(alerts_by_ip, edges)

    # Mark clusters with attack chains
    chain_ips = set()
    for chain in attack_chains:
        for node in chain["path"]:
            chain_ips.add(node["ip"])
    for c in clusters:
        if any(ip in chain_ips for ip in c["node_ids"]):
            c["has_attack_chain"] = True

    # ── 9. Timeline buckets ───────────────────────────────────────────────────
    bucket_interval = timedelta(hours=hours) / timeline_buckets
    bucket_seconds = max(int(bucket_interval.total_seconds()), 60)

    timeline_sql = text(f"""
        SELECT
            TO_TIMESTAMP(
                FLOOR(EXTRACT(EPOCH FROM COALESCE(log_timestamp, processed_at)) / :bucket) * :bucket
            ) AT TIME ZONE 'UTC' AS bucket_start,
            COUNT(*) AS total,
            SUM(CASE WHEN is_malicious THEN 1 ELSE 0 END) AS malicious,
            COUNT(DISTINCT parsed->>'src_ip') AS unique_sources,
            COUNT(DISTINCT parsed->>'dst_ip') AS unique_dests
        FROM log_entries
        WHERE COALESCE(log_timestamp, processed_at) >= :since
          AND parsed->>'src_ip' IS NOT NULL
        GROUP BY bucket_start
        ORDER BY bucket_start
    """)
    tl_rows = (await db.execute(
        timeline_sql, {"since": since, "bucket": bucket_seconds}
    )).fetchall()

    timeline = [
        {
            "timestamp": row.bucket_start.isoformat() if row.bucket_start else None,
            "total": int(row.total),
            "malicious": int(row.malicious),
            "unique_sources": int(row.unique_sources),
            "unique_dests": int(row.unique_dests),
        }
        for row in tl_rows
    ]

    # ── 10. Country breakdown ─────────────────────────────────────────────────
    country_stats: Dict[str, Dict] = {}
    for n in nodes:
        cc = n.get("country_code")
        if not cc:
            continue
        if cc not in country_stats:
            country_stats[cc] = {
                "country_code": cc,
                "country_name": n.get("country_name", cc),
                "node_count": 0,
                "alert_count": 0,
                "malicious_connections": 0,
                "max_severity": "info",
                "threat_score": 0,
            }
        cs = country_stats[cc]
        cs["node_count"] += 1
        cs["alert_count"] += n.get("alert_count", 0)
        cs["malicious_connections"] += n.get("malicious_connections", 0)
        cs["threat_score"] = max(cs["threat_score"], n.get("threat_score", 0))
        nsev = n.get("severity", "info")
        if _SEV_ORDER.get(nsev, 0) > _SEV_ORDER.get(cs["max_severity"], 0):
            cs["max_severity"] = nsev

    countries = sorted(
        country_stats.values(),
        key=lambda c: (c["alert_count"], c["threat_score"]),
        reverse=True,
    )

    # ── 11. Summary stats ─────────────────────────────────────────────────────
    total_threat = sum(n.get("threat_score", 0) for n in nodes if not n.get("collapsed"))
    active_nodes = [n for n in nodes if not n.get("collapsed")]

    return {
        "nodes": nodes,
        "edges": edges,
        "clusters": clusters,
        "attack_chains": attack_chains,
        "timeline": timeline,
        "countries": countries,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hours": hours,
        "node_count": len(active_nodes),
        "edge_count": len(edges),
        "cluster_count": len(clusters),
        "chain_count": len(attack_chains),
        "infra_collapsed": len(collapsed_infra),
        "avg_threat_score": round(total_threat / max(len(active_nodes), 1), 1),
        "country_count": len(countries),
    }


# ── Node deep-dive ────────────────────────────────────────────────────────────

@router.get("/node/{ip}")
async def get_node_detail(
    ip: str,
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """Full investigation detail for a single IP address."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Alerts for this IP
    alerts_sql = text("""
        SELECT id, title, severity, status, rule_name,
               context->>'mitre_attack' AS mitre_json,
               context->>'source_ip' AS ctx_src_ip,
               context->>'stages' AS stages_json,
               created_at
        FROM alerts
        WHERE (
            (indicator_type = 'ip' AND indicator_value = :ip)
            OR context->>'source_ip' = :ip
        )
        AND created_at >= :since
        ORDER BY created_at DESC
        LIMIT 50
    """)
    alert_rows = (await db.execute(alerts_sql, {"ip": ip, "since": since})).fetchall()

    alerts = []
    mitre_set = set()
    for row in alert_rows:
        a = {
            "id": str(row.id),
            "title": row.title,
            "severity": row.severity,
            "status": row.status,
            "rule_name": row.rule_name,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        if row.mitre_json:
            try:
                import json
                mitre = json.loads(row.mitre_json) if isinstance(row.mitre_json, str) else row.mitre_json
                a["mitre"] = mitre
                for m in mitre:
                    tid = m.get("technique_id", "")
                    tactic = m.get("tactic", "")
                    if tid:
                        mitre_set.add(f"{tactic} ({tid})")
            except Exception:
                pass
        alerts.append(a)

    # Connection stats
    conn_sql = text("""
        SELECT
            CASE WHEN parsed->>'src_ip' = :ip THEN 'outbound' ELSE 'inbound' END AS direction,
            COUNT(*) AS total,
            COUNT(DISTINCT CASE
                WHEN parsed->>'src_ip' = :ip THEN parsed->>'dst_ip'
                ELSE parsed->>'src_ip'
            END) AS unique_peers,
            SUM(CASE WHEN is_malicious THEN 1 ELSE 0 END) AS malicious
        FROM log_entries
        WHERE COALESCE(log_timestamp, processed_at) >= :since
          AND (parsed->>'src_ip' = :ip OR parsed->>'dst_ip' = :ip)
        GROUP BY direction
    """)
    conn_rows = (await db.execute(conn_sql, {"ip": ip, "since": since})).fetchall()
    connections = {
        row.direction: {
            "total": int(row.total),
            "unique_peers": int(row.unique_peers),
            "malicious": int(row.malicious),
        }
        for row in conn_rows
    }

    # Top peers
    peers_sql = text("""
        SELECT
            CASE WHEN parsed->>'src_ip' = :ip THEN parsed->>'dst_ip'
                 ELSE parsed->>'src_ip' END AS peer_ip,
            COUNT(*) AS conn_count,
            SUM(CASE WHEN is_malicious THEN 1 ELSE 0 END) AS malicious
        FROM log_entries
        WHERE COALESCE(log_timestamp, processed_at) >= :since
          AND (parsed->>'src_ip' = :ip OR parsed->>'dst_ip' = :ip)
        GROUP BY peer_ip
        ORDER BY malicious DESC, conn_count DESC
        LIMIT 15
    """)
    peer_rows = (await db.execute(peers_sql, {"ip": ip, "since": since})).fetchall()
    top_peers = [
        {"ip": r.peer_ip, "connections": int(r.conn_count), "malicious": int(r.malicious)}
        for r in peer_rows
    ]

    # Recent logs
    logs_sql = text("""
        SELECT id, source_type, parsed->>'protocol' AS protocol,
               parsed->>'dst_port' AS port, parsed->>'action' AS action,
               is_malicious,
               COALESCE(log_timestamp, processed_at) AS ts
        FROM log_entries
        WHERE COALESCE(log_timestamp, processed_at) >= :since
          AND (parsed->>'src_ip' = :ip OR parsed->>'dst_ip' = :ip)
        ORDER BY ts DESC
        LIMIT 20
    """)
    log_rows = (await db.execute(logs_sql, {"ip": ip, "since": since})).fetchall()
    recent_logs = [
        {
            "id": str(r.id),
            "source_type": r.source_type,
            "protocol": r.protocol,
            "port": r.port,
            "action": r.action,
            "is_malicious": r.is_malicious,
            "timestamp": r.ts.isoformat() if r.ts else None,
        }
        for r in log_rows
    ]

    # Enrichment from indicators table
    enrich_sql = text("""
        SELECT enrichment FROM indicators
        WHERE type = 'ip' AND value = :ip
        LIMIT 1
    """)
    enrich_row = (await db.execute(enrich_sql, {"ip": ip})).fetchone()
    enrichment = {}
    if enrich_row and enrich_row.enrichment:
        enrichment = dict(enrich_row.enrichment) if enrich_row.enrichment else {}

    return {
        "ip": ip,
        "type": "internal" if _is_internal(ip) else "external",
        "subnet": _subnet_key(ip),
        "alerts": alerts,
        "alert_count": len(alerts),
        "mitre_techniques": sorted(mitre_set),
        "connections": connections,
        "top_peers": top_peers,
        "recent_logs": recent_logs,
        "enrichment": enrichment,
    }


# ── Stats endpoint (unchanged API contract) ──────────────────────────────────

@router.get("/stats")
async def get_network_stats(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """Summary connection statistics for the dashboard widget."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    sql = text("""
        SELECT
            COUNT(DISTINCT parsed->>'src_ip')                              AS unique_sources,
            COUNT(DISTINCT parsed->>'dst_ip')                              AS unique_destinations,
            COUNT(*)                                                        AS total_connections,
            SUM(CASE WHEN is_malicious THEN 1 ELSE 0 END)                 AS malicious_connections,
            COUNT(DISTINCT
                CASE WHEN is_malicious THEN parsed->>'src_ip' END)         AS malicious_sources
        FROM log_entries
        WHERE COALESCE(log_timestamp, processed_at) >= :since
          AND parsed->>'src_ip' IS NOT NULL
    """)
    row = (await db.execute(sql, {"since": since})).fetchone()

    top_sql = text("""
        SELECT
            parsed->>'src_ip'  AS src_ip,
            COUNT(*)            AS conn_count,
            SUM(CASE WHEN is_malicious THEN 1 ELSE 0 END) AS malicious_count
        FROM log_entries
        WHERE COALESCE(log_timestamp, processed_at) >= :since
          AND parsed->>'src_ip' IS NOT NULL
        GROUP BY src_ip
        ORDER BY conn_count DESC
        LIMIT 5
    """)
    top_rows = (await db.execute(top_sql, {"since": since})).fetchall()

    return {
        "unique_sources": int(row.unique_sources or 0),
        "unique_destinations": int(row.unique_destinations or 0),
        "total_connections": int(row.total_connections or 0),
        "malicious_connections": int(row.malicious_connections or 0),
        "malicious_sources": int(row.malicious_sources or 0),
        "top_sources": [
            {
                "ip": r.src_ip,
                "connections": int(r.conn_count),
                "malicious": int(r.malicious_count),
            }
            for r in top_rows
        ],
        "hours": hours,
    }


# ── Host metadata CRUD ──────────────────────────────────────────────────────

@router.get("/hosts")
async def list_hosts(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> List[Dict[str, Any]]:
    """Return all user-defined host metadata."""
    rows = (await db.execute(text(
        "SELECT ip, name, device_type, x_position, y_position, notes, "
        "created_at, updated_at FROM host_metadata ORDER BY ip"
    ))).fetchall()
    return [
        {
            "ip": r.ip,
            "name": r.name,
            "device_type": r.device_type,
            "x_position": r.x_position,
            "y_position": r.y_position,
            "notes": r.notes,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in rows
    ]


@router.put("/hosts/{ip}")
async def upsert_host(
    ip: str,
    body: HostMetaIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """Create or update host metadata (name, type, position)."""
    await db.execute(text("""
        INSERT INTO host_metadata (ip, name, device_type, x_position, y_position, notes)
        VALUES (:ip, :name, :device_type, :x, :y, :notes)
        ON CONFLICT (ip) DO UPDATE SET
            name        = COALESCE(EXCLUDED.name, host_metadata.name),
            device_type = EXCLUDED.device_type,
            x_position  = COALESCE(EXCLUDED.x_position, host_metadata.x_position),
            y_position  = COALESCE(EXCLUDED.y_position, host_metadata.y_position),
            notes       = COALESCE(EXCLUDED.notes, host_metadata.notes),
            updated_at  = NOW()
    """), {
        "ip": ip,
        "name": body.name,
        "device_type": body.device_type,
        "x": body.x_position,
        "y": body.y_position,
        "notes": body.notes,
    })
    await db.commit()
    return {"ip": ip, "status": "saved", **body.model_dump()}


@router.delete("/hosts/{ip}")
async def delete_host(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, str]:
    """Delete host metadata."""
    await db.execute(text("DELETE FROM host_metadata WHERE ip = :ip"), {"ip": ip})
    await db.commit()
    return {"ip": ip, "status": "deleted"}
