"""
RunOrchestrator — drives a single analysis run from end to end:

  pending → parsing → loading → analyzing → completed | failed

State transitions are persisted to `topology_runs` so the api service can
poll without relying on in-process state.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import sqlalchemy as sa

from app.config import get_settings
from app.db import AsyncSessionLocal, get_neo4j
from app.engine.analysis import (
    attack_paths_to_assets,
    detect_fan_out_nodes,
    reachability_from_internet,
)
from app.engine.findings import upsert_fanout_finding, upsert_path_finding
from app.engine.ir import IRSnapshot
from app.engine.loader import load_run
from app.engine.normalize import normalize
from app.engine.parsers.detect import detect_vendor
from app.engine.parsers.f5 import parse_f5_config
from app.engine.parsers.fortinet import parse_fortinet_config
from app.engine.parsers.panos import parse_panos_config
from app.engine.scoring import Weights, score_fanout, score_path

log = logging.getLogger(__name__)

_RUNTIME_KEYS = (
    "attack_path_weight_exposure",
    "attack_path_weight_proximity",
    "attack_path_weight_branching",
    "attack_path_weight_criticality",
    "attack_path_max_depth",
    "attack_path_top_k",
    "attack_path_fanout_out_min",
    "attack_path_fanout_in_max",
)


class RunOrchestrator:

    # ── Public API ────────────────────────────────────────────────────────────

    async def create_run(self, *, upload_ids: Sequence[uuid.UUID],
                         triggered_by: Optional[str]) -> uuid.UUID:
        run_id = uuid.uuid4()
        async with AsyncSessionLocal() as db:
            await db.execute(sa.text("""
                INSERT INTO topology_runs (id, status, triggered_by)
                VALUES (:id, 'pending', :tb)
            """), {"id": str(run_id), "tb": triggered_by})
            # Bind uploads to this run
            await db.execute(sa.text("""
                UPDATE topology_config_uploads
                SET run_id = :rid
                WHERE id = ANY(:ids)
            """), {"rid": str(run_id),
                   "ids": [str(u) for u in upload_ids]})
            await db.commit()
        return run_id

    async def get_run(self, run_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        async with AsyncSessionLocal() as db:
            row = (await db.execute(sa.text("""
                SELECT id, status, started_at, finished_at, duration_ms,
                       device_count, neo4j_node_count, neo4j_rel_count,
                       findings_count, error_message
                FROM topology_runs WHERE id = :id
            """), {"id": str(run_id)})).fetchone()
            return dict(row._mapping) if row else None

    async def execute(self, run_id: uuid.UUID) -> None:
        """Run the full pipeline. Wraps every stage in try/except to keep
        Postgres state consistent even on failure."""
        started = time.time()
        try:
            await self._set_status(run_id, "parsing")
            uploads = await self._fetch_uploads(run_id)
            snapshot = await self._parse_uploads(run_id, uploads)

            await self._set_status(run_id, "loading")
            counts = await self._load_graph(run_id, snapshot)

            await self._set_status(run_id, "analyzing")
            findings_count = await self._analyze_and_persist(run_id)

            duration_ms = int((time.time() - started) * 1000)
            await self._finalize(run_id, status="completed",
                                 findings_count=findings_count,
                                 counts=counts, duration_ms=duration_ms,
                                 ir_snapshot=snapshot.model_dump())
        except Exception as exc:                                # noqa: BLE001
            log.exception("run %s failed", run_id)
            await self._finalize(run_id, status="failed",
                                 findings_count=0, counts={},
                                 duration_ms=int((time.time() - started) * 1000),
                                 ir_snapshot={},
                                 error_message=str(exc))

    # ── Stages ────────────────────────────────────────────────────────────────

    async def _fetch_uploads(self, run_id: uuid.UUID) -> List[Dict[str, Any]]:
        async with AsyncSessionLocal() as db:
            result = await db.execute(sa.text("""
                SELECT id, vendor, role, hostname, original_filename,
                       stored_path, sha256
                FROM topology_config_uploads
                WHERE run_id = :rid
            """), {"rid": str(run_id)})
            return [dict(r._mapping) for r in result.fetchall()]

    async def _parse_uploads(self, run_id: uuid.UUID,
                             uploads: List[Dict[str, Any]]) -> IRSnapshot:
        snapshot = IRSnapshot()
        for u in uploads:
            path = Path(u["stored_path"])
            vendor = u["vendor"] or detect_vendor(path)
            try:
                if vendor == "panos":
                    devs = parse_panos_config(path, hostname_hint=u["hostname"])
                elif vendor == "f5":
                    devs = parse_f5_config(path, hostname_hint=u["hostname"])
                elif vendor == "fortinet":
                    devs = parse_fortinet_config(path, hostname_hint=u["hostname"])
                else:
                    devs = []
                    raise ValueError(f"unsupported vendor: {vendor}")
                snapshot.devices.extend(devs)
                await self._mark_upload(u["id"], "ok", None)
            except Exception as exc:                            # noqa: BLE001
                log.warning("parse failed for upload %s: %s", u["id"], exc)
                await self._mark_upload(u["id"], "failed", str(exc))
        return snapshot

    async def _load_graph(self, run_id: uuid.UUID,
                          snapshot: IRSnapshot) -> Dict[str, int]:
        normalized = normalize(snapshot)
        settings = get_settings()
        driver = get_neo4j()
        counts = await load_run(driver, settings.neo4j_database, normalized)

        # Fold normalize warnings back into the run
        async with AsyncSessionLocal() as db:
            await db.execute(sa.text("""
                UPDATE topology_runs
                SET parse_warnings = CAST(:w AS jsonb),
                    device_count   = :dc
                WHERE id = :id
            """), {"w": json.dumps([w.model_dump() for w in normalized.warnings]),
                   "dc": len(snapshot.devices),
                   "id": str(run_id)})
            await db.commit()
        return counts

    async def _analyze_and_persist(self, run_id: uuid.UUID) -> int:
        settings_map = await self._fetch_runtime_settings()
        weights = Weights.from_platform_settings(settings_map)
        max_depth = int(settings_map.get("attack_path_max_depth", "6"))
        top_k = int(settings_map.get("attack_path_top_k", "5"))
        out_min = int(settings_map.get("attack_path_fanout_out_min", "5"))
        in_max = int(settings_map.get("attack_path_fanout_in_max", "3"))

        driver = get_neo4j()
        db_name = get_settings().neo4j_database

        # Persist effective weights for this run
        async with AsyncSessionLocal() as db:
            await db.execute(sa.text("""
                UPDATE topology_runs SET weights = CAST(:w AS jsonb) WHERE id = :id
            """), {"w": json.dumps(weights.as_json()), "id": str(run_id)})
            await db.commit()

        # Tagged assets only — `attack_path_assets` is the source of truth.
        asset_rows = await self._fetch_assets()
        asset_ips = [r["ip"] for r in asset_rows]
        criticality_by_ip = {r["ip"]: r["criticality"] for r in asset_rows}

        path_candidates = []
        if asset_ips:
            path_candidates = await attack_paths_to_assets(
                driver, db_name, asset_ips,
                max_depth=max_depth, top_k_per_asset=top_k,
            )

        fanout_candidates = await detect_fan_out_nodes(
            driver, db_name, out_min=out_min, in_max=in_max,
        )

        count = 0
        async with AsyncSessionLocal() as db:
            for p in path_candidates:
                crit = criticality_by_ip.get(p.asset_ip)
                score_info = score_path(p, weights=weights, criticality=crit)
                score_info["weights_used"] = weights.as_json()
                await upsert_path_finding(db, run_id, p, score_info, crit)
                count += 1
            for c in fanout_candidates:
                score_info = score_fanout(
                    c, weights=weights, internet_reachable=c.ingress_paths > 0,
                )
                await upsert_fanout_finding(db, run_id, c, score_info)
                count += 1
            await db.commit()
        return count

    # ── DB helpers ────────────────────────────────────────────────────────────

    async def _set_status(self, run_id: uuid.UUID, status: str) -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(sa.text("""
                UPDATE topology_runs SET status = :s WHERE id = :id
            """), {"s": status, "id": str(run_id)})
            await db.commit()

    async def _mark_upload(self, upload_id: uuid.UUID, status: str,
                           err: Optional[str]) -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(sa.text("""
                UPDATE topology_config_uploads
                SET parse_status = :s, parse_error = :e
                WHERE id = :id
            """), {"s": status, "e": err, "id": str(upload_id)})
            await db.commit()

    async def _fetch_runtime_settings(self) -> Dict[str, str]:
        async with AsyncSessionLocal() as db:
            result = await db.execute(sa.text("""
                SELECT key, value FROM platform_settings WHERE key = ANY(:keys)
            """), {"keys": list(_RUNTIME_KEYS)})
            return {r.key: r.value for r in result.fetchall()}

    async def _fetch_assets(self) -> List[Dict[str, Any]]:
        async with AsyncSessionLocal() as db:
            result = await db.execute(sa.text("""
                SELECT host(ip)::text AS ip, criticality, hostname
                FROM attack_path_assets
            """))
            return [dict(r._mapping) for r in result.fetchall()]

    async def _finalize(self, run_id: uuid.UUID, *,
                        status: str, findings_count: int,
                        counts: Dict[str, int], duration_ms: int,
                        ir_snapshot: Dict[str, Any],
                        error_message: Optional[str] = None) -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(sa.text("""
                UPDATE topology_runs SET
                    status            = :s,
                    finished_at       = NOW(),
                    duration_ms       = :ms,
                    findings_count    = :fc,
                    neo4j_node_count  = :nc,
                    neo4j_rel_count   = :rc,
                    ir_snapshot       = CAST(:ir AS jsonb),
                    error_message     = :err
                WHERE id = :id
            """), {
                "s": status, "ms": duration_ms, "fc": findings_count,
                "nc": sum(counts.values()),
                "rc": counts.get("rules", 0) + counts.get("vips", 0)
                       + counts.get("pools", 0) + counts.get("nat_rules", 0),
                "ir": json.dumps(ir_snapshot),
                "err": error_message, "id": str(run_id),
            })
            await db.commit()
