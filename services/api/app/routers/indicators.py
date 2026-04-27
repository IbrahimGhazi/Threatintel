"""
Indicator lookup and management endpoints.

All write operations require API key authentication.
Lookup endpoints are also authenticated to prevent intel extraction.

All lookup endpoints go through a Redis cache (positive + negative) to keep
Postgres off the hot path for chatty correlation workloads. The cache is
optional — if Redis is unavailable, requests fall through to Postgres.
"""
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app import cache
from app.database import get_db
from app.middleware.auth import require_api_key
from app.models.indicator import Indicator
from app.services import indicator_service

router = APIRouter(prefix="/indicators", tags=["Indicators"])


# ── Schemas ───────────────────────────────────────────────────

class SourceOut(BaseModel):
    source_name: str
    source_category: str
    confidence: int
    first_seen: Any
    last_seen: Any

    class Config:
        from_attributes = True


class IndicatorOut(BaseModel):
    id: uuid.UUID
    type: str
    value: str
    severity: str
    confidence: int
    reputation_score: int
    first_seen: Any
    last_seen: Any
    active: bool
    false_positive: bool
    tags: List[str]
    enrichment: Dict[str, Any]
    sources: List[SourceOut] = []
    expires_at: Optional[Any] = None

    class Config:
        from_attributes = True


class IndicatorListOut(BaseModel):
    total: int
    offset: int
    limit: int
    items: List[IndicatorOut]


class IndicatorCreateIn(BaseModel):
    type: str = Field(..., description="Indicator type: ip, domain, url, md5, sha256, ...")
    value: str = Field(..., min_length=1, max_length=2048)
    source_name: str = Field(default="manual")
    confidence: int = Field(default=75, ge=0, le=100)
    tags: List[str] = Field(default_factory=list)


class BulkLookupIn(BaseModel):
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)


class BulkLookupOut(BaseModel):
    ips: Dict[str, Optional[dict]] = Field(default_factory=dict)
    domains: Dict[str, Optional[dict]] = Field(default_factory=dict)
    urls: Dict[str, Optional[dict]] = Field(default_factory=dict)
    hashes: Dict[str, Optional[dict]] = Field(default_factory=dict)
    cache_hits: int = 0
    cache_negative: int = 0
    db_reads: int = 0


# ── Cache-aware helper ─────────────────────────────────────────

async def _cached_lookup(itype: str, value: str, db: AsyncSession) -> Optional[dict]:
    """
    Cache-aside lookup.
    Returns:
        dict  -> cache HIT or Postgres HIT (populated + cached)
        None  -> negative cache HIT or DB MISS (tombstone written on miss)
    """
    status_, cached_payload = await cache.get_cached(itype, value)
    if status_ == "hit":
        return cached_payload
    if status_ == "negative":
        return None

    indicator = await indicator_service.get_indicator_by_value(db, itype, value)
    if indicator is None:
        await cache.set_miss(itype, value)
        return None

    payload = cache._serialize_indicator(indicator)
    await cache.set_hit(itype, value, payload)
    return payload


# ── Endpoints ─────────────────────────────────────────────────

@router.get("", response_model=IndicatorListOut)
async def list_indicators(
    q: Optional[str] = Query(None, description="Search query"),
    type: Optional[str] = Query(None, description="Filter by indicator type"),
    severity: Optional[str] = Query(None),
    min_confidence: int = Query(0, ge=0, le=100),
    tags: Optional[str] = Query(None, description="Comma-separated tag filter"),
    active_only: bool = Query(True),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    tag_list = [t.strip() for t in tags.split(",")] if tags else None
    items, total = await indicator_service.search_indicators(
        db,
        q=q,
        itype=type,
        severity=severity,
        min_confidence=min_confidence,
        tags=tag_list,
        active_only=active_only,
        offset=offset,
        limit=limit,
    )
    return IndicatorListOut(total=total, offset=offset, limit=limit, items=items)


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    return await indicator_service.get_indicator_stats(db)


@router.get("/cache/stats")
async def get_cache_stats(_: str = Depends(require_api_key)):
    """Expose Redis cache hit/miss counters for monitoring."""
    return cache.cache_stats()


@router.post("/cache/flush")
async def flush_cache(
    itype: Optional[str] = Query(None, description="Indicator type; omit to flush all"),
    _: str = Depends(require_api_key),
):
    """Manual cache flush — useful after bulk indicator imports."""
    if itype:
        deleted = await cache.invalidate_prefix(itype)
        return {"status": "ok", "scope": itype, "deleted": deleted}
    totals = {}
    for t in ("ip", "domain", "url", "sha256", "md5", "sha1"):
        totals[t] = await cache.invalidate_prefix(t)
    return {"status": "ok", "scope": "all", "deleted": totals}


# ── Cached lookup endpoints ────────────────────────────────────

@router.get("/lookup/ip/{ip}")
async def lookup_ip(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Look up an IP address. Cache-aware (positive + negative)."""
    payload = await _cached_lookup("ip", ip, db)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"IP {ip!r} not found in database")
    return payload


@router.get("/lookup/domain/{domain}")
async def lookup_domain(
    domain: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    payload = await _cached_lookup("domain", domain, db)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"Domain {domain!r} not found")
    return payload


@router.get("/lookup/hash/{sha256}")
async def lookup_hash(
    sha256: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    payload = await _cached_lookup("sha256", sha256, db)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"Hash {sha256!r} not found")
    return payload


@router.get("/lookup/url")
async def lookup_url(
    url: str = Query(..., description="URL to look up"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    payload = await _cached_lookup("url", url, db)
    if payload is None:
        raise HTTPException(status_code=404, detail="URL not found")
    return payload


@router.post("/lookup/bulk", response_model=BulkLookupOut)
async def lookup_bulk(
    body: BulkLookupIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """
    Batched lookup across multiple indicator types.
    This is the RECOMMENDED endpoint for correlation / enrichment workers —
    one HTTP call instead of N, fully cached.
    """
    out = BulkLookupOut()

    async def _do_group(values: List[str], itype: str, dest: dict) -> None:
        for v in values:
            if not v:
                dest[v] = None
                continue
            status_, cached_payload = await cache.get_cached(itype, v)
            if status_ == "hit":
                dest[v] = cached_payload
                out.cache_hits += 1
                continue
            if status_ == "negative":
                dest[v] = None
                out.cache_negative += 1
                continue
            # Miss — hit Postgres
            indicator = await indicator_service.get_indicator_by_value(db, itype, v)
            out.db_reads += 1
            if indicator is None:
                await cache.set_miss(itype, v)
                dest[v] = None
            else:
                payload = cache._serialize_indicator(indicator)
                await cache.set_hit(itype, v, payload)
                dest[v] = payload

    await _do_group(body.ips, "ip", out.ips)
    await _do_group(body.domains, "domain", out.domains)
    await _do_group(body.urls, "url", out.urls)
    await _do_group(body.hashes, "sha256", out.hashes)
    return out


# ── Single-indicator fetch / writes ───────────────────────────

@router.get("/{indicator_id}", response_model=IndicatorOut)
async def get_indicator(
    indicator_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    from sqlalchemy import select
    from app.models.indicator import Indicator as IndicatorModel
    stmt = select(IndicatorModel).where(IndicatorModel.id == indicator_id)
    row = (await db.execute(stmt)).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return row


@router.post("", response_model=IndicatorOut, status_code=status.HTTP_201_CREATED)
async def create_indicator(
    body: IndicatorCreateIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Manually submit an indicator.  Invalidates the matching cache key."""
    indicator, created = await indicator_service.upsert_indicator(
        db,
        itype=body.type,
        value=body.value,
        source_name=body.source_name,
        source_category="user_submitted",
        confidence=body.confidence,
        tags=body.tags,
    )
    if indicator is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid indicator value for type {body.type!r}",
        )
    # Invalidate both original and normalized forms
    await cache.invalidate_many([
        (body.type, body.value),
        (body.type, indicator.normalized_value),
    ])
    return indicator


@router.post("/{indicator_id}/false-positive", status_code=status.HTTP_200_OK)
async def mark_false_positive(
    indicator_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Mark an indicator as a false positive (deactivates it)."""
    from sqlalchemy import select
    from app.models.indicator import Indicator as IndicatorModel
    row = (await db.execute(
        select(IndicatorModel).where(IndicatorModel.id == indicator_id)
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Indicator not found")

    success = await indicator_service.mark_false_positive(db, indicator_id)
    if not success:
        raise HTTPException(status_code=404, detail="Indicator not found")

    # Invalidate cache so clients see deactivated state immediately
    itype = row.type.value if hasattr(row.type, "value") else str(row.type)
    await cache.invalidate_many([
        (itype, row.value),
        (itype, row.normalized_value),
    ])
    return {"status": "marked as false positive", "id": str(indicator_id)}


@router.delete("/{indicator_id}", status_code=status.HTTP_200_OK)
async def delete_indicator(
    indicator_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Permanently delete an indicator."""
    from sqlalchemy import delete, select
    from app.models.indicator import Indicator as IndicatorModel

    row = (await db.execute(
        select(IndicatorModel).where(IndicatorModel.id == indicator_id)
    )).scalar_one_or_none()

    result = await db.execute(
        delete(IndicatorModel).where(IndicatorModel.id == indicator_id)
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Indicator not found")

    if row is not None:
        itype = row.type.value if hasattr(row.type, "value") else str(row.type)
        await cache.invalidate_many([
            (itype, row.value),
            (itype, row.normalized_value),
        ])
    return {"status": "deleted", "id": str(indicator_id)}
