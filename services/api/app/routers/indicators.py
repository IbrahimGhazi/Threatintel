"""
Indicator lookup and management endpoints.

All write operations require API key authentication.
Lookup endpoints are also authenticated to prevent intel extraction.
"""
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

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


@router.get("/lookup/ip/{ip}")
async def lookup_ip(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Look up an IP address against the intelligence database."""
    indicator = await indicator_service.get_indicator_by_value(db, "ip", ip)
    if not indicator:
        raise HTTPException(status_code=404, detail=f"IP {ip!r} not found in database")
    return indicator


@router.get("/lookup/domain/{domain}")
async def lookup_domain(
    domain: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    indicator = await indicator_service.get_indicator_by_value(db, "domain", domain)
    if not indicator:
        raise HTTPException(status_code=404, detail=f"Domain {domain!r} not found")
    return indicator


@router.get("/lookup/hash/{sha256}")
async def lookup_hash(
    sha256: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    indicator = await indicator_service.get_indicator_by_value(db, "sha256", sha256)
    if not indicator:
        raise HTTPException(status_code=404, detail=f"Hash {sha256!r} not found")
    return indicator


@router.get("/lookup/url")
async def lookup_url(
    url: str = Query(..., description="URL to look up"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    indicator = await indicator_service.get_indicator_by_value(db, "url", url)
    if not indicator:
        raise HTTPException(status_code=404, detail="URL not found")
    return indicator


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
    """Manually submit an indicator to the database."""
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
    return indicator


@router.post("/{indicator_id}/false-positive", status_code=status.HTTP_200_OK)
async def mark_false_positive(
    indicator_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Mark an indicator as a false positive (deactivates it)."""
    success = await indicator_service.mark_false_positive(db, indicator_id)
    if not success:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {"status": "marked as false positive", "id": str(indicator_id)}


@router.delete("/{indicator_id}", status_code=status.HTTP_200_OK)
async def delete_indicator(
    indicator_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Permanently delete an indicator."""
    from sqlalchemy import delete
    from app.models.indicator import Indicator
    result = await db.execute(
        delete(Indicator).where(Indicator.id == indicator_id)
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {"status": "deleted", "id": str(indicator_id)}
