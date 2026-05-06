"""
Persist analysis output to Postgres `attack_path_findings`.

Dedup key (`fingerprint`) survives across runs — re-runs UPSERT, refreshing
`last_seen_run_id`/`last_seen_at` and updating score/severity, while
preserving acknowledged/suppressed status.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Any, Dict, List, Optional

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.types import FanOutCandidate, PathCandidate

log = logging.getLogger(__name__)


def fingerprint_for_path(p: PathCandidate) -> str:
    kinds = []
    for n in p.nodes:
        labels = n.get("labels") or []
        kinds.append(labels[0] if labels else "?")
    edge_types = [e.get("type", "?") for e in p.edges]
    payload = {
        "asset_ip": p.asset_ip,
        "kinds": kinds,
        "edge_types": edge_types,
        "ingress": "internet",
    }
    return hashlib.sha1(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def fingerprint_for_fanout(c: FanOutCandidate) -> str:
    payload = {
        "kind": c.kind,
        "device_id": c.props.get("device_id"),
        "name": c.props.get("name") or c.props.get("ip") or c.props.get("address"),
        "fanout": True,
    }
    return hashlib.sha1(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def build_path_payload(p: PathCandidate, score_info: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "asset": {"ip": p.asset_ip},
        "score": score_info["score"],
        "severity": score_info["severity"],
        "hops": p.hops,
        "ingress": "internet",
        "nodes": p.nodes,
        "edges": p.edges,
        "rules_cited": p.rules_cited,
        "weights_used": score_info.get("weights_used", {}),
    }


def build_fanout_payload(c: FanOutCandidate, score_info: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "node": {"kind": c.kind, **c.props},
        "score": score_info["score"],
        "severity": score_info["severity"],
        "ingress_paths": c.ingress_paths,
        "outbound_targets": c.outdeg,
    }


# ── Upsert ────────────────────────────────────────────────────────────────────

_UPSERT_PATH_SQL = sa.text("""
INSERT INTO attack_path_findings (
    id, fingerprint, kind, severity, score, status,
    asset_ip, asset_hostname, asset_criticality, ingress, hops,
    path_json, score_breakdown, rules_cited,
    first_seen_run_id, last_seen_run_id, first_seen_at, last_seen_at
) VALUES (
    :id, :fingerprint, 'path', :severity::severity_level, :score, 'open',
    :asset_ip, :asset_hostname, :asset_criticality, :ingress, :hops,
    CAST(:path_json AS jsonb), CAST(:score_breakdown AS jsonb), CAST(:rules_cited AS jsonb),
    :run_id, :run_id, NOW(), NOW()
)
ON CONFLICT (fingerprint) DO UPDATE SET
    severity         = EXCLUDED.severity,
    score            = EXCLUDED.score,
    asset_ip         = EXCLUDED.asset_ip,
    asset_hostname   = EXCLUDED.asset_hostname,
    asset_criticality= EXCLUDED.asset_criticality,
    hops             = EXCLUDED.hops,
    path_json        = EXCLUDED.path_json,
    score_breakdown  = EXCLUDED.score_breakdown,
    rules_cited      = EXCLUDED.rules_cited,
    last_seen_run_id = EXCLUDED.last_seen_run_id,
    last_seen_at     = NOW(),
    updated_at       = NOW()
""")

_UPSERT_FANOUT_SQL = sa.text("""
INSERT INTO attack_path_findings (
    id, fingerprint, kind, severity, score, status,
    ingress, fanout_json, score_breakdown,
    first_seen_run_id, last_seen_run_id, first_seen_at, last_seen_at
) VALUES (
    :id, :fingerprint, 'fanout', :severity::severity_level, :score, 'open',
    :ingress, CAST(:fanout_json AS jsonb), CAST(:score_breakdown AS jsonb),
    :run_id, :run_id, NOW(), NOW()
)
ON CONFLICT (fingerprint) DO UPDATE SET
    severity         = EXCLUDED.severity,
    score            = EXCLUDED.score,
    fanout_json      = EXCLUDED.fanout_json,
    score_breakdown  = EXCLUDED.score_breakdown,
    last_seen_run_id = EXCLUDED.last_seen_run_id,
    last_seen_at     = NOW(),
    updated_at       = NOW()
""")


async def upsert_path_finding(db: AsyncSession, run_id: uuid.UUID,
                              p: PathCandidate, score_info: Dict[str, Any],
                              criticality: Optional[str]) -> str:
    fp = fingerprint_for_path(p)
    payload = build_path_payload(p, score_info)
    await db.execute(_UPSERT_PATH_SQL, {
        "id": str(uuid.uuid4()),
        "fingerprint": fp,
        "severity": score_info["severity"],
        "score": score_info["score"],
        "asset_ip": p.asset_ip,
        "asset_hostname": None,
        "asset_criticality": criticality,
        "ingress": "internet",
        "hops": p.hops,
        "path_json": json.dumps(payload),
        "score_breakdown": json.dumps(score_info.get("breakdown", {})),
        "rules_cited": json.dumps(p.rules_cited),
        "run_id": str(run_id),
    })
    return fp


async def upsert_fanout_finding(db: AsyncSession, run_id: uuid.UUID,
                                c: FanOutCandidate,
                                score_info: Dict[str, Any]) -> str:
    fp = fingerprint_for_fanout(c)
    payload = build_fanout_payload(c, score_info)
    await db.execute(_UPSERT_FANOUT_SQL, {
        "id": str(uuid.uuid4()),
        "fingerprint": fp,
        "severity": score_info["severity"],
        "score": score_info["score"],
        "ingress": "internet" if c.ingress_paths > 0 else f"internal:{c.kind}",
        "fanout_json": json.dumps(payload),
        "score_breakdown": json.dumps(score_info.get("breakdown", {})),
        "run_id": str(run_id),
    })
    return fp
