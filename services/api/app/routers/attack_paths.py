"""
/api/attack-paths/* — public surface for the Attack Path & Fan-Out
Analysis Engine. Postgres-backed reads happen in-process; anything that
touches Neo4j (subgraph) or kicks off a run is proxied to the
attack-paths worker.

Endpoints:
  POST /attack-paths/configs              upload one config file
  POST /attack-paths/runs                 trigger a run over upload_ids[]
  GET  /attack-paths/runs                 list recent runs
  GET  /attack-paths/runs/{id}            run status + summary
  GET  /attack-paths/runs/{id}/findings   findings for one run (paginated)
  GET  /attack-paths/findings             paginated findings list (cross-run)
  GET  /attack-paths/findings/{id}        full payload
  POST /attack-paths/findings/{id}/ack    acknowledge
  POST /attack-paths/findings/{id}/suppress  suppress
  GET  /attack-paths/graph/subgraph       curated subgraph (proxied)
  GET  /attack-paths/assets               list tagged assets
  PUT  /attack-paths/assets/{ip}          set/update criticality
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import sqlalchemy as sa
from fastapi import (
    APIRouter, Depends, File, Form, HTTPException, Query, Response,
    UploadFile, status,
)
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key
from app.services.attack_paths_client import AttackPathsClient

log = logging.getLogger(__name__)

router = APIRouter(prefix="/attack-paths", tags=["Attack Paths"],
                   dependencies=[Depends(require_api_key)])

# Same on-disk PVC as the worker — both pods mount it at this path.
_CONFIG_DIR = Path(os.environ.get("ATTACK_PATHS_CONFIG_DIR", "/var/lib/ti/configs"))


# ── Schemas ───────────────────────────────────────────────────────────────────

class UploadOut(BaseModel):
    id: uuid.UUID
    vendor: str
    hostname: Optional[str] = None
    original_filename: str
    sha256: str
    size_bytes: int


class TriggerRunIn(BaseModel):
    upload_ids: List[uuid.UUID]
    triggered_by: Optional[str] = None


class TriggerRunOut(BaseModel):
    run_id: uuid.UUID
    status: str


class RunSummary(BaseModel):
    id: uuid.UUID
    status: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    device_count: int = 0
    findings_count: int = 0
    error_message: Optional[str] = None


class FindingSummary(BaseModel):
    id: uuid.UUID
    kind: str
    severity: str
    score: float
    status: str
    asset_ip: Optional[str] = None
    asset_hostname: Optional[str] = None
    asset_criticality: Optional[str] = None
    ingress: str
    hops: Optional[int] = None
    fingerprint: str
    last_seen_at: datetime


class FindingDetail(FindingSummary):
    path_json: Optional[Dict[str, Any]] = None
    fanout_json: Optional[Dict[str, Any]] = None
    rules_cited: List[Dict[str, Any]] = Field(default_factory=list)
    score_breakdown: Dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None


class AckIn(BaseModel):
    actor: str = "unknown"
    notes: Optional[str] = None


class SuppressIn(BaseModel):
    actor: str = "unknown"
    reason: Optional[str] = None


class AssetIn(BaseModel):
    hostname: Optional[str] = None
    criticality: str
    business_unit: Optional[str] = None
    notes: Optional[str] = None


class AssetOut(BaseModel):
    ip: str
    hostname: Optional[str] = None
    criticality: str
    business_unit: Optional[str] = None
    notes: Optional[str] = None


# ── Uploads ───────────────────────────────────────────────────────────────────

@router.post("/configs", response_model=UploadOut)
async def upload_config(
    file: UploadFile = File(...),
    vendor: str = Form(..., description="panos | f5 | fortinet | unknown"),
    hostname: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
) -> UploadOut:
    if vendor not in ("panos", "f5", "fortinet", "unknown"):
        raise HTTPException(400, detail="vendor must be one of panos|f5|fortinet|unknown")

    upload_id = uuid.uuid4()
    contents = await file.read()
    if not contents:
        raise HTTPException(400, detail="empty upload")
    sha = hashlib.sha256(contents).hexdigest()

    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = f"{upload_id}-{Path(file.filename or 'config').name}"
    stored = _CONFIG_DIR / safe_name
    stored.write_bytes(contents)

    role = "firewall" if vendor in ("panos", "fortinet") else "loadbalancer"
    await db.execute(sa.text("""
        INSERT INTO topology_config_uploads (
            id, vendor, role, hostname, original_filename,
            sha256, size_bytes, stored_path, parse_status
        ) VALUES (
            :id, :v, :r, :h, :fn, :sha, :sz, :sp, 'pending'
        )
    """), {
        "id": str(upload_id), "v": vendor, "r": role, "h": hostname,
        "fn": file.filename or safe_name,
        "sha": sha, "sz": len(contents), "sp": str(stored),
    })
    return UploadOut(
        id=upload_id, vendor=vendor, hostname=hostname,
        original_filename=file.filename or safe_name,
        sha256=sha, size_bytes=len(contents),
    )


# ── Runs ──────────────────────────────────────────────────────────────────────

@router.post("/runs", response_model=TriggerRunOut)
async def trigger_run(payload: TriggerRunIn) -> TriggerRunOut:
    client = AttackPathsClient()
    if not client.enabled:
        raise HTTPException(503,
            detail="attack-paths service not configured (ATTACK_PATHS_URL unset)")
    body = await client.trigger_run(
        upload_ids=[str(u) for u in payload.upload_ids],
        triggered_by=payload.triggered_by,
    )
    return TriggerRunOut(run_id=body["run_id"], status=body["status"])


@router.get("/runs", response_model=List[RunSummary])
async def list_runs(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> List[RunSummary]:
    rows = (await db.execute(sa.text("""
        SELECT id, status, started_at, finished_at, duration_ms,
               device_count, findings_count, error_message
        FROM topology_runs
        ORDER BY started_at DESC
        LIMIT :lim
    """), {"lim": limit})).fetchall()
    return [RunSummary(**dict(r._mapping)) for r in rows]


@router.get("/runs/{run_id}", response_model=RunSummary)
async def get_run(run_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> RunSummary:
    row = (await db.execute(sa.text("""
        SELECT id, status, started_at, finished_at, duration_ms,
               device_count, findings_count, error_message
        FROM topology_runs WHERE id = :id
    """), {"id": str(run_id)})).fetchone()
    if not row:
        raise HTTPException(404, detail="run not found")
    return RunSummary(**dict(row._mapping))


# ── Findings ──────────────────────────────────────────────────────────────────

_FINDINGS_BASE_SQL = """
    SELECT id, kind, severity::text AS severity, score::float8 AS score,
           status::text AS status, host(asset_ip) AS asset_ip,
           asset_hostname, asset_criticality, ingress, hops,
           fingerprint, last_seen_at
    FROM attack_path_findings
"""


@router.get("/findings", response_model=List[FindingSummary])
async def list_findings(
    kind: Optional[str] = Query(None, regex="^(path|fanout)$"),
    severity: Optional[str] = Query(None, regex="^(critical|high|medium|low|info)$"),
    status_filter: Optional[str] = Query(None, alias="status",
        regex="^(open|acknowledged|suppressed)$"),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> List[FindingSummary]:
    where: List[str] = []
    params: Dict[str, Any] = {"lim": limit}
    if kind:
        where.append("kind = :kind"); params["kind"] = kind
    if severity:
        where.append("severity = :sev::severity_level"); params["sev"] = severity
    if status_filter:
        where.append("status = :st::attack_path_finding_status"); params["st"] = status_filter
    sql = _FINDINGS_BASE_SQL
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY score DESC, last_seen_at DESC LIMIT :lim"
    rows = (await db.execute(sa.text(sql), params)).fetchall()
    return [FindingSummary(**dict(r._mapping)) for r in rows]


@router.get("/runs/{run_id}/findings", response_model=List[FindingSummary])
async def list_run_findings(
    run_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    limit: int = Query(200, ge=1, le=1000),
) -> List[FindingSummary]:
    rows = (await db.execute(sa.text(_FINDINGS_BASE_SQL + """
        WHERE last_seen_run_id = :rid
        ORDER BY score DESC LIMIT :lim
    """), {"rid": str(run_id), "lim": limit})).fetchall()
    return [FindingSummary(**dict(r._mapping)) for r in rows]


@router.get("/findings/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: uuid.UUID, db: AsyncSession = Depends(get_db),
) -> FindingDetail:
    row = (await db.execute(sa.text("""
        SELECT id, kind, severity::text AS severity, score::float8 AS score,
               status::text AS status, host(asset_ip) AS asset_ip,
               asset_hostname, asset_criticality, ingress, hops,
               fingerprint, last_seen_at,
               path_json, fanout_json, rules_cited, score_breakdown, notes
        FROM attack_path_findings WHERE id = :id
    """), {"id": str(finding_id)})).fetchone()
    if not row:
        raise HTTPException(404, detail="finding not found")
    return FindingDetail(**dict(row._mapping))


@router.post("/findings/{finding_id}/ack", response_model=FindingSummary)
async def ack_finding(finding_id: uuid.UUID, payload: AckIn,
                      db: AsyncSession = Depends(get_db)) -> FindingSummary:
    row = (await db.execute(sa.text("""
        UPDATE attack_path_findings
        SET status = 'acknowledged', acknowledged_at = NOW(),
            acknowledged_by = :actor, notes = COALESCE(:notes, notes)
        WHERE id = :id
        RETURNING id, kind, severity::text AS severity, score::float8 AS score,
                  status::text AS status, host(asset_ip) AS asset_ip,
                  asset_hostname, asset_criticality, ingress, hops,
                  fingerprint, last_seen_at
    """), {"id": str(finding_id), "actor": payload.actor,
           "notes": payload.notes})).fetchone()
    if not row:
        raise HTTPException(404, detail="finding not found")
    return FindingSummary(**dict(row._mapping))


@router.post("/findings/{finding_id}/suppress", response_model=FindingSummary)
async def suppress_finding(finding_id: uuid.UUID, payload: SuppressIn,
                           db: AsyncSession = Depends(get_db)) -> FindingSummary:
    row = (await db.execute(sa.text("""
        UPDATE attack_path_findings
        SET status = 'suppressed', suppressed_at = NOW(),
            suppressed_by = :actor, suppression_reason = :reason
        WHERE id = :id
        RETURNING id, kind, severity::text AS severity, score::float8 AS score,
                  status::text AS status, host(asset_ip) AS asset_ip,
                  asset_hostname, asset_criticality, ingress, hops,
                  fingerprint, last_seen_at
    """), {"id": str(finding_id), "actor": payload.actor,
           "reason": payload.reason})).fetchone()
    if not row:
        raise HTTPException(404, detail="finding not found")
    return FindingSummary(**dict(row._mapping))


# ── Graph (proxied) ───────────────────────────────────────────────────────────

@router.get("/graph/subgraph")
async def graph_subgraph(
    asset_ip: Optional[str] = Query(None),
    max_hops: int = Query(6, ge=1, le=10),
    include_internet: bool = Query(True),
) -> Dict[str, Any]:
    client = AttackPathsClient()
    if not client.enabled:
        raise HTTPException(503,
            detail="attack-paths service not configured (ATTACK_PATHS_URL unset)")
    return await client.fetch_subgraph(
        asset_ip=asset_ip, max_hops=max_hops, include_internet=include_internet,
    )


# ── Assets ────────────────────────────────────────────────────────────────────

@router.get("/assets", response_model=List[AssetOut])
async def list_assets(db: AsyncSession = Depends(get_db)) -> List[AssetOut]:
    rows = (await db.execute(sa.text("""
        SELECT host(ip) AS ip, hostname, criticality, business_unit, notes
        FROM attack_path_assets ORDER BY criticality, ip
    """))).fetchall()
    return [AssetOut(**dict(r._mapping)) for r in rows]


@router.put("/assets/{ip}", response_model=AssetOut)
async def upsert_asset(ip: str, payload: AssetIn,
                       db: AsyncSession = Depends(get_db)) -> AssetOut:
    if payload.criticality not in ("crown_jewel", "high", "medium", "low"):
        raise HTTPException(400, detail="criticality must be crown_jewel|high|medium|low")
    row = (await db.execute(sa.text("""
        INSERT INTO attack_path_assets (ip, hostname, criticality, business_unit, notes)
        VALUES (:ip::inet, :host, :crit, :bu, :notes)
        ON CONFLICT (ip) DO UPDATE SET
            hostname      = EXCLUDED.hostname,
            criticality   = EXCLUDED.criticality,
            business_unit = EXCLUDED.business_unit,
            notes         = EXCLUDED.notes
        RETURNING host(ip) AS ip, hostname, criticality, business_unit, notes
    """), {"ip": ip, "host": payload.hostname, "crit": payload.criticality,
           "bu": payload.business_unit, "notes": payload.notes})).fetchone()
    return AssetOut(**dict(row._mapping))


# ── Devices (proxied to attack-paths worker) ─────────────────────────────────

class DeviceCredentialsIn(BaseModel):
    api_key: Optional[str] = None      # PA only
    user: Optional[str] = None         # PA fallback or F5
    password: Optional[str] = None


class DeviceCreateIn(BaseModel):
    vendor: str
    hostname: str
    address: str
    port: int = 443
    verify_tls: bool = False
    poll_interval_seconds: int = 3600
    enabled: bool = True
    notes: Optional[str] = None
    created_by: Optional[str] = None
    credentials: DeviceCredentialsIn


class DevicePatchIn(BaseModel):
    hostname: Optional[str] = None
    address: Optional[str] = None
    port: Optional[int] = None
    verify_tls: Optional[bool] = None
    poll_interval_seconds: Optional[int] = None
    enabled: Optional[bool] = None
    notes: Optional[str] = None
    credentials: Optional[DeviceCredentialsIn] = None


@router.get("/devices")
async def list_devices() -> List[Dict[str, Any]]:
    client = AttackPathsClient()
    if not client.enabled:
        raise HTTPException(503,
            detail="attack-paths service not configured (ATTACK_PATHS_URL unset)")
    return await client.list_devices()


@router.post("/devices")
async def create_device(payload: DeviceCreateIn) -> Dict[str, Any]:
    client = AttackPathsClient()
    if not client.enabled:
        raise HTTPException(503,
            detail="attack-paths service not configured (ATTACK_PATHS_URL unset)")
    body = payload.model_dump(exclude_none=True)
    # Strip null/empty credential fields so the inner validator gets a clean dict
    creds = body.get("credentials") or {}
    body["credentials"] = {k: v for k, v in creds.items() if v}
    try:
        return await client.create_device(body)
    except Exception as exc:                                     # noqa: BLE001
        raise HTTPException(400, detail=str(exc)) from exc


@router.get("/devices/{device_id}")
async def get_device(device_id: uuid.UUID) -> Dict[str, Any]:
    client = AttackPathsClient()
    if not client.enabled:
        raise HTTPException(503,
            detail="attack-paths service not configured (ATTACK_PATHS_URL unset)")
    try:
        return await client.get_device(str(device_id))
    except Exception as exc:                                     # noqa: BLE001
        raise HTTPException(404, detail=str(exc)) from exc


@router.patch("/devices/{device_id}")
async def patch_device(device_id: uuid.UUID, payload: DevicePatchIn) -> Dict[str, Any]:
    client = AttackPathsClient()
    if not client.enabled:
        raise HTTPException(503,
            detail="attack-paths service not configured (ATTACK_PATHS_URL unset)")
    body = payload.model_dump(exclude_none=True)
    if "credentials" in body:
        creds = body["credentials"] or {}
        body["credentials"] = {k: v for k, v in creds.items() if v}
    return await client.patch_device(str(device_id), body)


@router.delete("/devices/{device_id}", status_code=204, response_class=Response)
async def delete_device(device_id: uuid.UUID):
    client = AttackPathsClient()
    if not client.enabled:
        raise HTTPException(503,
            detail="attack-paths service not configured (ATTACK_PATHS_URL unset)")
    await client.delete_device(str(device_id))
    return Response(status_code=204)


@router.post("/devices/{device_id}/fetch")
async def fetch_device_now(device_id: uuid.UUID) -> Dict[str, Any]:
    client = AttackPathsClient()
    if not client.enabled:
        raise HTTPException(503,
            detail="attack-paths service not configured (ATTACK_PATHS_URL unset)")
    return await client.fetch_device_now(str(device_id))
