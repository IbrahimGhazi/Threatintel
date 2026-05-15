"""Firewall config-audit endpoints.

Endpoints (mounted under ``/firewall``):
    POST   /devices                  Register a new firewall (encrypts api_key)
    GET    /devices                  List registered firewalls
    GET    /devices/{id}             Show one
    DELETE /devices/{id}             Remove (cascades configs+findings)
    POST   /devices/{id}/test        Live test_connection — does NOT mutate
    POST   /devices/{id}/sync        Manual fetch → redact → persist snapshot

Out of scope for this slice (next deploys):
    POST   /devices/check-credential  (preview an unsaved key)
    GET    /findings                  rule eval is in a later batch
    GET    /advisories                advisory catalog endpoints
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key
from app.models.vendor_audit import (
    VendorAdvisory, VendorConfig, VendorConfigFinding, VendorDevice,
)
from app.security import crypto
from app.services.vendor_audit.pa_client import PaApiError, PaloAltoClient
from app.services.vendor_audit.pa_parser import (
    extract_facts, extract_facts_with_warnings, hash_xml, redact_secrets,
)
from app.services.vendor_audit.rule_engine import Verdict, evaluate_rule
from app.services.vendor_audit import csaf_ingest, pa_scrape_ingest
from app.services.vendor_audit import scheduler as _vendor_scheduler

logger = logging.getLogger("ti.api.firewall_audit")
router = APIRouter(prefix="/firewall", tags=["Firewall Audit"])


# ── Schemas ────────────────────────────────────────────────────────────

class DeviceCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=200)
    hostname:     str = Field(min_length=1, max_length=255)
    port:         int = Field(default=443, ge=1, le=65535)
    api_key:      str = Field(min_length=8, max_length=4096)
    verify_cert:  bool = True
    custom_ca_pem: Optional[str] = None
    vendor:       str = "palo_alto"
    product:      str = "pan-os"


class DeviceOut(BaseModel):
    id: uuid.UUID
    vendor: str
    product: str
    display_name: str
    hostname: str
    port: int
    verify_cert: bool
    has_custom_ca: bool
    enabled: bool
    api_key_masked: str
    created_at: Any
    last_sync_at: Optional[Any]
    last_sync_status: Optional[str]
    last_sync_error: Optional[str]
    last_software_version: Optional[str]
    last_serial: Optional[str]
    last_model: Optional[str]


class TestConnectionResult(BaseModel):
    ok: bool
    hostname: Optional[str] = None
    serial: Optional[str] = None
    model: Optional[str] = None
    sw_version: Optional[str] = None
    family: Optional[str] = None
    uptime: Optional[str] = None
    error: Optional[str] = None


class SyncResult(BaseModel):
    ok: bool
    config_id: Optional[uuid.UUID] = None
    snapshot_changed: bool = False
    raw_xml_size: Optional[int] = None
    raw_xml_sha256: Optional[str] = None
    redaction_stats: Dict[str, int] = Field(default_factory=dict)
    facts: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class FindingOut(BaseModel):
    id: uuid.UUID
    config_id: uuid.UUID
    device_id: uuid.UUID
    advisory_id: uuid.UUID
    cve_id: Optional[str]
    title: Optional[str]
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    status: str
    severity: str
    evidence: Dict[str, Any]
    recommendation: Optional[str]
    references_urls: Optional[List[str]] = None
    workaround: Optional[str] = None
    evaluated_at: Any
    acknowledged_at: Optional[Any]
    dismissed_at: Optional[Any]


class EvaluateResult(BaseModel):
    ok: bool
    config_id: Optional[uuid.UUID] = None
    rules_evaluated: int = 0
    findings: Dict[str, int] = Field(default_factory=dict)   # {applies: n, ...}
    error: Optional[str] = None


class AdvisoryOut(BaseModel):
    id: uuid.UUID
    vendor: str
    cve_id: str
    vendor_advisory_id: Optional[str]
    title: str
    cvss_score: Optional[float]
    cvss_severity: str
    published_at: Any
    updated_at: Any
    affected_products: List[str]
    affected_versions: List[str]
    fixed_versions: Optional[List[str]]
    has_preconditions: bool
    curation_status: str
    curated_at: Optional[Any]
    curated_by: Optional[str]
    references_urls: Optional[List[str]] = None
    workaround: Optional[str] = None


class AdvisoryStats(BaseModel):
    total: int
    curated: int
    uncurated: int
    drafted: int
    by_severity: Dict[str, int]
    last_updated: Optional[Any]


class CsafIngestResult(BaseModel):
    ok: bool
    fetched: int = 0
    parse_failed: int = 0
    too_old: int = 0
    inserted: int = 0
    refreshed_uncurated: int = 0
    preserved_curated: int = 0
    sources: List[str] = Field(default_factory=list)
    elapsed_ms: int = 0
    error: Optional[str] = None


# ── Helpers ────────────────────────────────────────────────────────────

def _to_out(d: VendorDevice) -> DeviceOut:
    """SQLA model → response DTO. Never includes the encrypted api key."""
    decrypted_for_mask = ""
    try:
        if d.api_key_was_encrypted:
            decrypted_for_mask = crypto.decrypt(d.api_key_encrypted)
        else:
            decrypted_for_mask = d.api_key_encrypted
    except Exception:
        # If master key is rotated we can't decrypt — still safe to render.
        decrypted_for_mask = ""
    return DeviceOut(
        id=d.id, vendor=d.vendor, product=d.product,
        display_name=d.display_name, hostname=d.hostname, port=d.port,
        verify_cert=d.verify_cert, has_custom_ca=bool(d.custom_ca_pem),
        enabled=d.enabled, api_key_masked=crypto.mask(decrypted_for_mask),
        created_at=d.created_at,
        last_sync_at=d.last_sync_at, last_sync_status=d.last_sync_status,
        last_sync_error=d.last_sync_error,
        last_software_version=d.last_software_version,
        last_serial=d.last_serial, last_model=d.last_model,
    )


def _make_client(d: VendorDevice) -> PaloAltoClient:
    """Build a PA client for a stored device, decrypting the api key just
    in time. The plaintext key never leaves this function call."""
    if d.api_key_was_encrypted:
        api_key = crypto.decrypt(d.api_key_encrypted)
    else:
        api_key = d.api_key_encrypted
    return PaloAltoClient(
        hostname     = d.hostname,
        port         = d.port,
        api_key      = api_key,
        verify_cert  = d.verify_cert,
        custom_ca_pem= d.custom_ca_pem,
    )


# ── Endpoints ──────────────────────────────────────────────────────────

@router.post("/devices/check", response_model=TestConnectionResult)
async def check_device_connection(
    body: DeviceCreate,
    _:  str = Depends(require_api_key),
):
    """Test a (hostname, port, api_key) trio without persisting anything.

    Used by the Add Firewall wizard's 'Test connection' step so the
    analyst can verify the credential before saving. No DB writes; the
    plaintext key never leaves this request handler."""
    if body.vendor != "palo_alto":
        return TestConnectionResult(ok=False, error="Only vendor='palo_alto' supported in MVP")
    client = PaloAltoClient(
        hostname     = body.hostname,
        port         = body.port,
        api_key      = body.api_key,
        verify_cert  = body.verify_cert,
        custom_ca_pem= body.custom_ca_pem,
    )
    try:
        info = await client.test_connection()
    except PaApiError as exc:
        return TestConnectionResult(ok=False, error=str(exc))
    return TestConnectionResult(
        ok=True, hostname=info.hostname, serial=info.serial, model=info.model,
        sw_version=info.sw_version, family=info.family, uptime=info.uptime,
    )


@router.post("/devices", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
async def register_device(
    body: DeviceCreate,
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    if body.vendor != "palo_alto":
        raise HTTPException(400, "Only vendor='palo_alto' is supported in this MVP.")
    if body.product != "pan-os":
        raise HTTPException(400, "Only product='pan-os' is supported in this MVP.")

    # Encrypt the api key at rest with the platform master key (Fernet).
    enc, was_enc = crypto.encrypt(body.api_key)
    if not was_enc:
        logger.warning(
            "MASTER_ENCRYPTION_KEY not set — vendor_devices.api_key_encrypted "
            "row %s stored in PLAINTEXT. Provision the key for production.",
            body.hostname,
        )

    dev = VendorDevice(
        vendor=body.vendor, product=body.product,
        display_name=body.display_name, hostname=body.hostname, port=body.port,
        api_key_encrypted=enc, api_key_was_encrypted=was_enc,
        verify_cert=body.verify_cert, custom_ca_pem=body.custom_ca_pem,
    )
    db.add(dev)
    try:
        await db.flush()
    except Exception as exc:
        # Most likely uq_vendor_host_port collision
        await db.rollback()
        raise HTTPException(409, f"Device already registered: {exc}") from exc
    await db.commit()
    return _to_out(dev)


@router.get("/devices", response_model=List[DeviceOut])
async def list_devices(
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    rows = (await db.execute(
        select(VendorDevice).order_by(desc(VendorDevice.created_at))
    )).scalars().all()
    return [_to_out(d) for d in rows]


@router.get("/devices/{device_id}", response_model=DeviceOut)
async def get_device(
    device_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    d = (await db.execute(
        select(VendorDevice).where(VendorDevice.id == device_id)
    )).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Device not found")
    return _to_out(d)


@router.delete("/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    d = (await db.execute(
        select(VendorDevice).where(VendorDevice.id == device_id)
    )).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Device not found")
    await db.delete(d)
    await db.commit()


@router.post("/devices/{device_id}/test", response_model=TestConnectionResult)
async def test_device(
    device_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """Live ``show system info`` against the device. No DB mutation — useful
    for the 'Add firewall' wizard's verify step and for ad-hoc liveness checks."""
    d = (await db.execute(
        select(VendorDevice).where(VendorDevice.id == device_id)
    )).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Device not found")
    client = _make_client(d)
    try:
        info = await client.test_connection()
    except PaApiError as exc:
        return TestConnectionResult(ok=False, error=str(exc))
    return TestConnectionResult(
        ok=True, hostname=info.hostname, serial=info.serial, model=info.model,
        sw_version=info.sw_version, family=info.family, uptime=info.uptime,
    )


@router.post("/devices/{device_id}/sync", response_model=SyncResult)
async def sync_device(
    device_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """Manual fetch → redact → persist snapshot. Returns the parsed fact
    dict so the analyst can see what was extracted. No rule evaluation
    yet — that's the next batch."""
    d = (await db.execute(
        select(VendorDevice).where(VendorDevice.id == device_id)
    )).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Device not found")
    client = _make_client(d)

    try:
        # 1. Identity check (also gives us last-seen sw_version + serial)
        info = await client.test_connection()
        # 2. Pull running config
        raw = await client.fetch_running_config()
    except PaApiError as exc:
        d.last_sync_at = None  # leave the previous successful timestamp
        d.last_sync_status = "auth_failed" if "Not Authenticated" in str(exc) else "unreachable"
        d.last_sync_error  = str(exc)[:500]
        await db.commit()
        return SyncResult(ok=False, error=str(exc))

    # 3. Redact + extract facts
    try:
        redacted, redact_stats = redact_secrets(raw)
        facts, parse_warnings = extract_facts_with_warnings(redacted)
    except Exception as exc:
        d.last_sync_status = "parse_error"
        d.last_sync_error  = str(exc)[:500]
        await db.commit()
        return SyncResult(ok=False, error=f"parse error: {exc}")

    sha = hash_xml(redacted)

    # 4. Dedupe — if last snapshot for this device matches sha, just bump
    #    last_sync_at on the device and skip writing a new vendor_configs row.
    last_cfg = (await db.execute(
        select(VendorConfig)
        .where(VendorConfig.device_id == d.id)
        .order_by(desc(VendorConfig.fetched_at))
        .limit(1)
    )).scalar_one_or_none()

    snapshot_changed = (last_cfg is None or last_cfg.raw_xml_sha256 != sha)
    config_id: Optional[uuid.UUID] = last_cfg.id if last_cfg else None

    if snapshot_changed:
        # Encrypt redacted XML at rest (fall back to plaintext if no master key)
        from app.security.crypto import _get_fernet
        f = _get_fernet()
        if f is not None:
            xml_blob = f.encrypt(redacted)
            xml_was_enc = True
        else:
            xml_blob = redacted
            xml_was_enc = False
            logger.warning(
                "MASTER_ENCRYPTION_KEY not set — vendor_configs.raw_xml_encrypted "
                "stored as PLAINTEXT bytes."
            )

        cfg = VendorConfig(
            device_id            = d.id,
            # Prefer info.sw_version: it includes hotfix suffix (e.g. '11.1.10-h1').
            # facts.software_version comes from <config detail-version> which
            # only carries major.minor.patch, missing hotfixes. The version-
            # range engine cares about hotfixes for borderline cases (e.g.
            # affected=<=11.1.10-h1 vs running 11.1.10-h2).
            software_version     = info.sw_version or facts.get("software_version"),
            content_version      = None,   # PA doesn't ship content version in running config
            hostname             = facts.get("hostname") or info.hostname,
            facts                = facts,
            raw_xml_sha256       = sha,
            raw_xml_encrypted    = xml_blob,
            raw_xml_was_encrypted= xml_was_enc,
            raw_xml_size         = len(redacted),
            parse_warnings       = parse_warnings,
        )
        db.add(cfg)
        await db.flush()
        config_id = cfg.id
    elif last_cfg is not None and (last_cfg.facts or {}) != facts:
        # 2026-05-05: snapshot SHA hasn't changed (config XML identical) but
        # the freshly-extracted facts dict differs from the stored one — most
        # commonly because the parser was upgraded with new fact extractors
        # since the snapshot was first captured.  Update the existing row's
        # facts AND parse_warnings in place so rule evaluation sees the new
        # keys, and refresh software_version (caller's deploy may have
        # shipped the day-6 fix that prefers `info.sw_version` with hotfix
        # suffix).
        last_cfg.facts            = facts
        last_cfg.parse_warnings   = parse_warnings
        last_cfg.software_version = info.sw_version or facts.get("software_version")
        last_cfg.hostname         = facts.get("hostname") or info.hostname
        await db.flush()
        logger.info(
            "vendor_audit: snapshot sha unchanged but facts dict differs (parser "
            "upgrade detected); updated cfg.facts in place (warnings=%d)",
            len(parse_warnings),
        )

    # 5. Update device sync metadata
    from datetime import datetime, timezone
    d.last_sync_at = datetime.now(timezone.utc)
    d.last_sync_status = "ok"
    d.last_sync_error  = None
    d.last_software_version = info.sw_version or facts.get("software_version")
    d.last_serial = info.serial
    d.last_model  = info.model

    await db.commit()

    return SyncResult(
        ok=True, config_id=config_id,
        snapshot_changed=snapshot_changed,
        raw_xml_size=len(redacted), raw_xml_sha256=sha,
        redaction_stats=redact_stats, facts=facts,
    )


# ── Rule evaluation ────────────────────────────────────────────────────

@router.post("/devices/{device_id}/evaluate", response_model=EvaluateResult)
async def evaluate_device(
    device_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """Run all curated advisories against the device's most recent config
    snapshot. Persists a finding row per (config × advisory) pair."""
    from datetime import datetime, timezone

    d = (await db.execute(
        select(VendorDevice).where(VendorDevice.id == device_id)
    )).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Device not found")

    cfg = (await db.execute(
        select(VendorConfig)
        .where(VendorConfig.device_id == d.id)
        .order_by(desc(VendorConfig.fetched_at))
        .limit(1)
    )).scalar_one_or_none()
    if cfg is None:
        return EvaluateResult(ok=False,
                              error="no config snapshot for this device — run /sync first")

    advisories = (await db.execute(
        select(VendorAdvisory).where(VendorAdvisory.vendor == d.vendor)
    )).scalars().all()

    counts: Dict[str, int] = {"applies": 0, "not_applicable": 0, "uncertain": 0}
    for adv in advisories:
        adv_dict = {
            "cve_id":            adv.cve_id,
            "cvss_severity":     adv.cvss_severity,
            "affected_versions": adv.affected_versions or [],
            "preconditions":     adv.preconditions or {},
        }
        verdict: Verdict = evaluate_rule(
            facts=cfg.facts or {},
            software_version=cfg.software_version,
            advisory=adv_dict,
        )
        counts[verdict.status] = counts.get(verdict.status, 0) + 1

        # Build evidence payload for the row
        ev = dict(verdict.evidence)
        if verdict.reasons:
            ev["reasons"] = verdict.reasons

        # Compose human-friendly recommendation
        rec_parts = []
        fixed = adv.fixed_versions or []
        if isinstance(fixed, list) and fixed:
            rec_parts.append(f"Fixed in: {', '.join(map(str, fixed))}.")
        if adv.workaround:
            rec_parts.append(f"Workaround: {adv.workaround.strip()}")
        recommendation = " ".join(rec_parts) or None

        # Upsert finding (one per config × advisory)
        from sqlalchemy.dialects.postgresql import insert
        stmt = insert(VendorConfigFinding).values(
            config_id     = cfg.id,
            device_id     = d.id,
            advisory_id   = adv.id,
            evaluated_at  = datetime.now(timezone.utc),
            status        = verdict.status,
            severity      = verdict.severity,
            evidence      = ev,
            recommendation= recommendation,
        ).on_conflict_do_update(
            index_elements=["config_id", "advisory_id"],
            set_={
                "evaluated_at":   datetime.now(timezone.utc),
                "status":         verdict.status,
                "severity":       verdict.severity,
                "evidence":       ev,
                "recommendation": recommendation,
            },
        )
        await db.execute(stmt)

    await db.commit()

    return EvaluateResult(
        ok=True, config_id=cfg.id,
        rules_evaluated=len(advisories), findings=counts,
    )


@router.get("/devices/{device_id}/findings", response_model=List[FindingOut])
async def list_device_findings(
    device_id: uuid.UUID,
    status_filter: Optional[str] = None,    # 'applies' | 'not_applicable' | 'uncertain'
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """List the most recent findings for a device, joined with advisory text."""
    # Anchor on the latest config — only return findings against THAT snapshot
    cfg = (await db.execute(
        select(VendorConfig)
        .where(VendorConfig.device_id == device_id)
        .order_by(desc(VendorConfig.fetched_at))
        .limit(1)
    )).scalar_one_or_none()
    if cfg is None:
        return []

    from sqlalchemy import text as sa_text
    sev_order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " \
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    where_status = "AND f.status = :sf" if status_filter else ""
    rows = (await db.execute(sa_text(f"""
        SELECT f.id, f.config_id, f.device_id, f.advisory_id,
               f.status, f.severity, f.evidence, f.recommendation,
               f.evaluated_at, f.acknowledged_at, f.dismissed_at,
               a.cve_id, a.title, a.cvss_score, a.cvss_severity,
               a.references_urls, a.workaround
          FROM vendor_config_findings f
          JOIN vendor_advisories a ON a.id = f.advisory_id
         WHERE f.config_id = :cid {where_status}
         ORDER BY {sev_order}, a.cve_id
    """), {"cid": str(cfg.id), "sf": status_filter} if status_filter else {"cid": str(cfg.id)})
    ).mappings().all()

    return [
        FindingOut(
            id=r["id"], config_id=r["config_id"], device_id=r["device_id"],
            advisory_id=r["advisory_id"], cve_id=r["cve_id"], title=r["title"],
            cvss_score=float(r["cvss_score"]) if r["cvss_score"] is not None else None,
            cvss_severity=r["cvss_severity"], status=r["status"], severity=r["severity"],
            evidence=dict(r["evidence"] or {}),
            recommendation=r["recommendation"],
            references_urls=list(r["references_urls"] or []),
            workaround=r["workaround"],
            evaluated_at=r["evaluated_at"],
            acknowledged_at=r["acknowledged_at"], dismissed_at=r["dismissed_at"],
        )
        for r in rows
    ]


# ── Advisory catalog ───────────────────────────────────────────────────

@router.get("/advisories", response_model=List[AdvisoryOut])
async def list_advisories(
    curation_status: Optional[str] = None,
    severity:        Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """List all known advisories with their curation status. Useful for
    the curation UI ("which CSAF rows still need preconditions written?")."""
    stmt = select(VendorAdvisory)
    if curation_status:
        stmt = stmt.where(VendorAdvisory.curation_status == curation_status)
    if severity:
        stmt = stmt.where(VendorAdvisory.cvss_severity == severity)
    stmt = stmt.order_by(desc(VendorAdvisory.published_at))
    rows = (await db.execute(stmt)).scalars().all()
    return [
        AdvisoryOut(
            id=a.id, vendor=a.vendor, cve_id=a.cve_id,
            vendor_advisory_id=a.vendor_advisory_id, title=a.title,
            cvss_score=float(a.cvss_score) if a.cvss_score is not None else None,
            cvss_severity=a.cvss_severity,
            published_at=a.published_at, updated_at=a.updated_at,
            affected_products=list(a.affected_products or []),
            affected_versions=list(a.affected_versions or []),
            fixed_versions=list(a.fixed_versions or []) if a.fixed_versions else None,
            has_preconditions=bool(a.preconditions),
            curation_status=a.curation_status,
            curated_at=a.curated_at, curated_by=a.curated_by,
            references_urls=list(a.references_urls or []),
            workaround=a.workaround,
        )
        for a in rows
    ]


@router.get("/advisories/stats", response_model=AdvisoryStats)
async def advisory_stats(
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """Catalog rollup — count by curation status + severity. Drives the
    'Curation queue: 14 advisories need preconditions' banner in the UI."""
    from sqlalchemy import func
    by_status = dict((await db.execute(
        select(VendorAdvisory.curation_status, func.count())
        .group_by(VendorAdvisory.curation_status)
    )).all())
    by_sev = dict((await db.execute(
        select(VendorAdvisory.cvss_severity, func.count())
        .group_by(VendorAdvisory.cvss_severity)
    )).all())
    last_upd = (await db.execute(
        select(func.max(VendorAdvisory.updated_at))
    )).scalar_one_or_none()
    total = sum(by_status.values())
    return AdvisoryStats(
        total=total,
        curated=int(by_status.get("curated", 0)),
        uncurated=int(by_status.get("uncurated", 0)),
        drafted=int(by_status.get("drafted", 0)),
        by_severity={k: int(v) for k, v in by_sev.items()},
        last_updated=last_upd,
    )


@router.post("/advisories/refresh", response_model=CsafIngestResult)
async def refresh_csaf(
    _:  str = Depends(require_api_key),
):
    """Manually trigger a CSAF ingest. Same code path as the daily
    background loop. Honors the same env-var configuration."""
    try:
        result = await csaf_ingest.ingest()
    except Exception as exc:
        return CsafIngestResult(ok=False, error=str(exc))
    return CsafIngestResult(**result)


class PaRefreshResult(BaseModel):
    """Response shape for the force-refresh endpoint.  Operators use this to
    confirm the fetcher ran and see what changed in one request, instead of
    waiting 24h for the next scheduled cycle."""
    status:        str                       # 'ok' | 'error' | 'skipped'
    fetched_count: int = 0
    new_count:     int = 0
    rows:          int = 0
    elapsed_ms:    int = 0
    error:         Optional[str] = None      # filled on status='error'
    reason:        Optional[str] = None      # filled on status='skipped' (e.g. PA_SCRAPE_DISABLED)
    details:       Dict[str, Any] = Field(default_factory=dict)


@router.post("/advisories/refresh-now", response_model=PaRefreshResult)
async def refresh_pa_now(
    _:  str = Depends(require_api_key),
):
    """Force-refresh the Palo Alto advisory catalog by running
    ``pa_scrape_ingest.ingest()`` directly (NOT via the daily scheduler).

    Lets operators retry the catalog refresh on-demand without waiting for
    the next 10:00-customer-local slot.  Returns the structured stats so
    you can see fetched_count, new_count, and any error reason in a single
    request.

    Auth: ``X-API-Key`` (same as other /firewall endpoints)."""
    try:
        result = await pa_scrape_ingest.ingest()
    except Exception as exc:
        # Defensive: ingest() is supposed to catch its own exceptions, but if
        # something escapes (e.g. import-time error), surface it cleanly here
        # instead of returning a 500 with an opaque traceback.
        logger.exception("pa_scrape: refresh-now hit unexpected error")
        return PaRefreshResult(status="error", error=str(exc))

    if not result.get("ok", False):
        return PaRefreshResult(
            status="error",
            fetched_count=int(result.get("fetched", 0)),
            elapsed_ms=int(result.get("elapsed_ms", 0)),
            error=result.get("error") or "unknown error",
            details=result,
        )

    if "skipped" in result:
        return PaRefreshResult(
            status="skipped",
            elapsed_ms=int(result.get("elapsed_ms", 0)),
            reason=result.get("skipped"),
            details=result,
        )

    return PaRefreshResult(
        status="ok",
        fetched_count=int(result.get("fetched", 0)),
        new_count=int(result.get("inserted", 0)),
        rows=int(result.get("rows", 0)),
        elapsed_ms=int(result.get("elapsed_ms", 0)),
        details=result,
    )


@router.get("/advisories/health")
async def advisory_health(
    _:  str = Depends(require_api_key),
):
    """Return the PA scrape ingest's last-run snapshot — fetched/new counts,
    timestamp, and any error from the most recent ``ingest()`` call.

    Surfaces silent failures (network blocks, parse-failure spikes) so
    operators don't have to grep pod logs to know whether the catalog is
    healthy.  Returns ``{"last_run": null}`` when ingest hasn't run yet in
    this process (e.g. fresh pod start)."""
    last = pa_scrape_ingest.get_last_run()
    return {"last_run": last}


@router.post("/sync-all")
async def sync_all_now(
    _:  str = Depends(require_api_key),
):
    """Manual on-demand trigger for the daily orchestrator: CSAF refresh
    → per-device sync → re-eval → alert bridge. Returns the same stats
    dict the background loop logs.

    Useful for: testing the pipeline mid-day, after registering a new
    firewall, or when fresh advisories need to be picked up immediately
    rather than waiting for the next 10:00 customer-local slot."""
    return await _vendor_scheduler.run_daily_cycle()


# ── Finding actions (ack / dismiss) ────────────────────────────────────

class FindingActionIn(BaseModel):
    note:    Optional[str] = None
    actor:   Optional[str] = None  # username; defaults to 'analyst'


@router.post("/findings/{finding_id}/acknowledge", response_model=FindingOut)
async def acknowledge_finding(
    finding_id: uuid.UUID,
    body: FindingActionIn = FindingActionIn(),
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """Acknowledge a finding: stamp acknowledged_at + acknowledged_by but
    leave the finding live (status unchanged). Use for 'I'm aware, working it'."""
    f = (await db.execute(
        select(VendorConfigFinding).where(VendorConfigFinding.id == finding_id)
    )).scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")
    from datetime import datetime, timezone
    f.acknowledged_at = datetime.now(timezone.utc)
    f.acknowledged_by = body.actor or "analyst"
    if body.note:
        f.notes = (f.notes + "\n\n" if f.notes else "") + body.note
    await db.commit()
    return await _finding_to_out(db, f.id)


@router.post("/findings/{finding_id}/dismiss", response_model=FindingOut)
async def dismiss_finding(
    finding_id: uuid.UUID,
    body: FindingActionIn = FindingActionIn(),
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """Dismiss a finding (analyst's call: 'doesn't apply / accepted risk').
    Sets dismissed_at + clears any bridged alert."""
    from datetime import datetime, timezone
    from sqlalchemy import update as _update
    from app.models.alert import Alert

    f = (await db.execute(
        select(VendorConfigFinding).where(VendorConfigFinding.id == finding_id)
    )).scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")

    now = datetime.now(timezone.utc)
    f.dismissed_at = now
    f.dismiss_reason = body.note
    # If the finding is bridged to an alert, mark it resolved with this reason.
    if f.alert_id is not None:
        await db.execute(
            _update(Alert)
              .where(Alert.id == f.alert_id, Alert.status != "resolved")
              .values(
                  status      = "resolved",
                  resolved_at = now,
                  notes       = f"Dismissed at vendor-audit finding: {body.note or '(no reason given)'}",
                  updated_at  = now,
              )
        )
        f.alert_id = None
    await db.commit()
    return await _finding_to_out(db, f.id)


async def _finding_to_out(db: AsyncSession, finding_id: uuid.UUID) -> FindingOut:
    """Re-fetch and serialize a finding joined with its advisory."""
    from sqlalchemy import text as sa_text
    row = (await db.execute(sa_text("""
        SELECT f.id, f.config_id, f.device_id, f.advisory_id,
               f.status, f.severity, f.evidence, f.recommendation,
               f.evaluated_at, f.acknowledged_at, f.dismissed_at,
               a.cve_id, a.title, a.cvss_score, a.cvss_severity,
               a.references_urls, a.workaround
          FROM vendor_config_findings f
          JOIN vendor_advisories a ON a.id = f.advisory_id
         WHERE f.id = :fid
         LIMIT 1
    """), {"fid": str(finding_id)})).mappings().first()
    if row is None:
        raise HTTPException(404, "Finding not found")
    return FindingOut(
        id=row["id"], config_id=row["config_id"], device_id=row["device_id"],
        advisory_id=row["advisory_id"], cve_id=row["cve_id"], title=row["title"],
        cvss_score=float(row["cvss_score"]) if row["cvss_score"] is not None else None,
        cvss_severity=row["cvss_severity"], status=row["status"], severity=row["severity"],
        evidence=dict(row["evidence"] or {}),
        recommendation=row["recommendation"],
        references_urls=list(row["references_urls"] or []),
        workaround=row["workaround"],
        evaluated_at=row["evaluated_at"],
        acknowledged_at=row["acknowledged_at"],
        dismissed_at=row["dismissed_at"],
    )


# ── Curation: edit advisory preconditions + fact catalog ───────────────

class PreconditionsPatch(BaseModel):
    preconditions:   Dict[str, Any]
    curation_status: Optional[str] = None     # 'curated' | 'drafted' | 'uncurated'
    curated_by:      Optional[str] = None


class FactCatalogEntry(BaseModel):
    name:        str
    description: str


class PreviewRequest(BaseModel):
    """Body for ``POST /firewall/advisories/{id}/preview``.

    Either field is optional — omitted falls back to the advisory's stored value.
    Lets the curation editor preview a draft without saving.
    """
    preconditions:     Optional[Dict[str, Any]] = None
    affected_versions: Optional[List[str]]      = None


class PreviewDeviceVerdict(BaseModel):
    device_id:        uuid.UUID
    display_name:     str
    hostname:         str
    software_version: Optional[str]
    config_fetched_at: Optional[Any]
    status:           str        # 'applies' | 'not_applicable' | 'uncertain' | 'no_config'
    severity:         str
    reasons:          List[str]
    facts_evaluated:  List[Dict[str, Any]]


class PreviewResponse(BaseModel):
    advisory_id:   uuid.UUID
    cve_id:        str
    used_preconditions:     Dict[str, Any]
    used_affected_versions: List[str]
    counts:        Dict[str, int]   # {applies: 1, not_applicable: 0, ...}
    devices:       List[PreviewDeviceVerdict]


@router.get("/advisories/facts", response_model=List[FactCatalogEntry])
async def list_facts(
    _:  str = Depends(require_api_key),
):
    """Return the fact registry — names + descriptions of every fact the
    parser extracts. The curation UI displays this as an autocomplete /
    cheatsheet so the analyst knows which fact names are valid in
    preconditions."""
    from app.services.vendor_audit.pa_parser import fact_catalog
    return [FactCatalogEntry(**f) for f in fact_catalog()]


_VALID_CURATION_STATES = {"curated", "drafted", "uncurated"}


def _validate_preconditions(node: Any, depth: int = 0) -> None:
    """Lightweight DSL validator. Raises HTTPException(400) on bad shape."""
    if depth > 8:
        raise HTTPException(400, "preconditions tree too deep (max 8 levels)")
    if not isinstance(node, dict):
        raise HTTPException(400, f"expected object, got {type(node).__name__}")
    if not node:
        return  # empty = match anything (version-only rule)
    keys = set(node.keys())
    if "all_of" in keys or "any_of" in keys:
        op = "all_of" if "all_of" in keys else "any_of"
        items = node[op]
        if not isinstance(items, list):
            raise HTTPException(400, f"{op} must be a list")
        for child in items:
            _validate_preconditions(child, depth + 1)
        return
    if "not" in keys:
        _validate_preconditions(node["not"], depth + 1)
        return
    # Leaf: must have 'fact' + one operator
    if "fact" not in keys:
        raise HTTPException(400, f"leaf missing 'fact' key: {node!r}")
    ops = {"equals", "not_equals", "in", "not_in", "gt", "gte", "lt", "lte", "present"}
    if not (ops & keys):
        raise HTTPException(400, f"leaf for fact={node.get('fact')!r} has no recognised operator (expected one of {sorted(ops)})")


@router.patch("/advisories/{advisory_id}", response_model=AdvisoryOut)
async def patch_advisory(
    advisory_id: uuid.UUID,
    body: PreconditionsPatch,
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """Edit an advisory's curation. Body's `preconditions` is the new DSL
    tree (validated server-side). `curation_status` defaults to `curated`
    when caller doesn't specify and the new preconditions are non-empty —
    that's the typical 'analyst saved a useful precondition' path. Empty
    preconditions reset to `uncurated`."""
    from datetime import datetime, timezone

    _validate_preconditions(body.preconditions)

    a = (await db.execute(
        select(VendorAdvisory).where(VendorAdvisory.id == advisory_id)
    )).scalar_one_or_none()
    if not a:
        raise HTTPException(404, "Advisory not found")

    new_status = body.curation_status
    if new_status is None:
        new_status = "curated" if body.preconditions else "uncurated"
    if new_status not in _VALID_CURATION_STATES:
        raise HTTPException(400, f"curation_status must be one of {sorted(_VALID_CURATION_STATES)}")

    # Diff summary for the history log (followup-4): describe what this PATCH
    # changed from the prior state in human-readable form.
    prior_preconditions = dict(a.preconditions or {})
    prior_status        = a.curation_status
    summary_parts: List[str] = []
    if prior_status != new_status:
        summary_parts.append(f"status {prior_status} → {new_status}")
    if prior_preconditions != body.preconditions:
        if not prior_preconditions and body.preconditions:
            summary_parts.append("added preconditions")
        elif prior_preconditions and not body.preconditions:
            summary_parts.append("cleared preconditions")
        else:
            summary_parts.append("edited preconditions")
    summary = ", ".join(summary_parts) or "no-op patch"

    actor = body.curated_by or "human:ui"
    now = datetime.now(timezone.utc)
    new_log_entry = {
        "at":      now.isoformat(),
        "by":      actor,
        "action":  "patch",
        "summary": summary,
    }
    # Append to existing log (start fresh if column was NULL on a pre-migration row)
    history: List[Dict[str, Any]] = list(a.curation_log or [])
    history.append(new_log_entry)
    # Cap at 50 entries to keep the JSONB row from ballooning over years.
    if len(history) > 50:
        history = history[-50:]

    a.preconditions   = body.preconditions
    a.curation_status = new_status
    a.curated_at      = now if new_status != "uncurated" else None
    a.curated_by      = actor
    a.curation_log    = history

    await db.commit()
    await db.refresh(a)
    return AdvisoryOut(
        id=a.id, vendor=a.vendor, cve_id=a.cve_id,
        vendor_advisory_id=a.vendor_advisory_id, title=a.title,
        cvss_score=float(a.cvss_score) if a.cvss_score is not None else None,
        cvss_severity=a.cvss_severity,
        published_at=a.published_at, updated_at=a.updated_at,
        affected_products=list(a.affected_products or []),
        affected_versions=list(a.affected_versions or []),
        fixed_versions=list(a.fixed_versions or []) if a.fixed_versions else None,
        has_preconditions=bool(a.preconditions),
        curation_status=a.curation_status,
        curated_at=a.curated_at, curated_by=a.curated_by,
        references_urls=list(a.references_urls or []),
        workaround=a.workaround,
    )


@router.get("/advisories/{advisory_id}/raw")
async def get_advisory_raw(
    advisory_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """Full advisory record incl. preconditions DSL (for the curation modal)
    and raw_advisory CSAF doc (for audit / debugging)."""
    a = (await db.execute(
        select(VendorAdvisory).where(VendorAdvisory.id == advisory_id)
    )).scalar_one_or_none()
    if not a:
        raise HTTPException(404, "Advisory not found")
    return {
        "id": str(a.id), "cve_id": a.cve_id, "title": a.title,
        "description": a.description,
        "cvss_score": float(a.cvss_score) if a.cvss_score is not None else None,
        "cvss_severity": a.cvss_severity,
        "vendor_advisory_id": a.vendor_advisory_id,
        "published_at": a.published_at, "updated_at": a.updated_at,
        "affected_products":  list(a.affected_products or []),
        "affected_versions":  list(a.affected_versions or []),
        "fixed_versions":     list(a.fixed_versions or []) if a.fixed_versions else [],
        "preconditions":      dict(a.preconditions or {}),
        "workaround":         a.workaround,
        "references_urls":    list(a.references_urls or []),
        "curation_status":    a.curation_status,
        "curated_at":         a.curated_at,
        "curated_by":         a.curated_by,
        "curation_log":       list(a.curation_log or []),
        "raw_advisory":       a.raw_advisory,
    }


@router.post("/advisories/{advisory_id}/preview", response_model=PreviewResponse)
async def preview_advisory(
    advisory_id: uuid.UUID,
    body: PreviewRequest,
    db: AsyncSession = Depends(get_db),
    _:  str = Depends(require_api_key),
):
    """Preview verdicts for a draft advisory rule against every registered
    device's latest config snapshot, **without persisting anything**.

    Workflow this enables (curation editor):
      1. Analyst types preconditions in the JSON editor.
      2. Clicks 'Preview against your firewalls'.
      3. UI POSTs `{preconditions}` here, gets back per-device APPLIES /
         NOT_APPLICABLE / UNCERTAIN with the matching reasons.
      4. Tweaks rule, previews again, only saves once happy.

    `affected_versions` is optional in the body — omitted falls back to the
    advisory's stored ranges. Pass it explicitly when previewing
    a rewrite of the version-range too.

    No findings, no alerts, no DB mutations beyond a read.
    """
    a = (await db.execute(
        select(VendorAdvisory).where(VendorAdvisory.id == advisory_id)
    )).scalar_one_or_none()
    if not a:
        raise HTTPException(404, "Advisory not found")

    # If caller supplied preconditions, validate the DSL shape (same gate as PATCH).
    if body.preconditions is not None:
        _validate_preconditions(body.preconditions)
        used_preconditions = body.preconditions
    else:
        used_preconditions = dict(a.preconditions or {})

    used_affected = (
        list(body.affected_versions)
        if body.affected_versions is not None
        else list(a.affected_versions or [])
    )

    advisory_dict = {
        "cve_id":            a.cve_id,
        "cvss_severity":     a.cvss_severity,
        "affected_versions": used_affected,
        "preconditions":     used_preconditions,
    }

    # Walk every enabled device — only ones that have a stored config snapshot
    # produce a verdict. Devices with last_sync_status != 'ok' return 'no_config'.
    devices = (await db.execute(
        select(VendorDevice).where(VendorDevice.vendor == a.vendor)
    )).scalars().all()

    counts: Dict[str, int] = {
        "applies": 0, "not_applicable": 0, "uncertain": 0, "no_config": 0,
    }
    out_devices: List[PreviewDeviceVerdict] = []

    for d in devices:
        cfg = (await db.execute(
            select(VendorConfig)
            .where(VendorConfig.device_id == d.id)
            .order_by(desc(VendorConfig.fetched_at))
            .limit(1)
        )).scalar_one_or_none()

        if cfg is None:
            counts["no_config"] += 1
            out_devices.append(PreviewDeviceVerdict(
                device_id=d.id, display_name=d.display_name, hostname=d.hostname,
                software_version=None, config_fetched_at=None,
                status="no_config", severity=(a.cvss_severity or "info"),
                reasons=["No config snapshot for this device — run /sync first."],
                facts_evaluated=[],
            ))
            continue

        verdict: Verdict = evaluate_rule(
            facts=cfg.facts or {},
            software_version=cfg.software_version,
            advisory=advisory_dict,
        )
        counts[verdict.status] = counts.get(verdict.status, 0) + 1

        out_devices.append(PreviewDeviceVerdict(
            device_id=d.id, display_name=d.display_name, hostname=d.hostname,
            software_version=cfg.software_version,
            config_fetched_at=cfg.fetched_at,
            status=verdict.status, severity=verdict.severity,
            reasons=list(verdict.reasons),
            facts_evaluated=list(verdict.evidence.get("facts_evaluated") or []),
        ))

    return PreviewResponse(
        advisory_id=a.id, cve_id=a.cve_id,
        used_preconditions=used_preconditions,
        used_affected_versions=used_affected,
        counts=counts, devices=out_devices,
    )
