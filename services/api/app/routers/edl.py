"""
EDL (External Dynamic List) endpoints.

EDL feeds are served as plain text, one indicator per line,
suitable for direct consumption by firewalls and proxies.
These endpoints are intentionally unauthenticated so security devices
can pull them without credential management.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import and_, select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key
from app.models.edl import EDLConfig
from app.models.indicator import Indicator

router = APIRouter(prefix="/edl", tags=["EDL"])

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


async def _build_edl_list(db: AsyncSession, config: EDLConfig) -> List[str]:
    """Query indicators matching an EDL configuration and return their values."""
    conditions = [
        Indicator.type == config.indicator_type,
        Indicator.active == True,
        Indicator.false_positive == False,
        Indicator.confidence >= config.min_confidence,
    ]

    # Severity filter: include all severities >= min_severity
    min_sev_idx = SEVERITY_ORDER.get(config.min_severity, 1)
    included_severities = [s for s, i in SEVERITY_ORDER.items() if i >= min_sev_idx]
    conditions.append(Indicator.severity.in_(included_severities))

    # Age filter
    if config.max_age_days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=config.max_age_days)
        conditions.append(Indicator.last_seen >= cutoff)

    # Tag filter
    if config.tags_filter:
        conditions.append(Indicator.tags.overlap(config.tags_filter))

    stmt = (
        select(Indicator.normalized_value)
        .where(and_(*conditions))
        .order_by(Indicator.normalized_value)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return list(rows)


# ── Public EDL feed endpoints (no auth) ──────────────────────

@router.get("/feed/{slug}", response_class=Response)
async def get_edl_feed(
    slug: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Serve an EDL feed as plain text (one indicator per line).
    Security devices poll this endpoint directly.
    """
    config = (
        await db.execute(
            select(EDLConfig).where(EDLConfig.slug == slug, EDLConfig.enabled == True)
        )
    ).scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail=f"EDL feed '{slug}' not found or disabled")

    indicators = await _build_edl_list(db, config)

    # Update cached count
    await db.execute(
        update(EDLConfig)
        .where(EDLConfig.id == config.id)
        .values(cached_count=len(indicators), last_built_at=func.now())
    )

    content = "\n".join(indicators)
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "X-EDL-Count": str(len(indicators)),
            "X-EDL-Name": config.name,
            "Cache-Control": "public, max-age=300",
        },
    )


# ── EDL management endpoints (requires auth) ─────────────────

class EDLConfigOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    description: Optional[str]
    indicator_type: str
    min_confidence: int
    min_severity: str
    tags_filter: Optional[List[str]]
    max_age_days: Optional[int]
    format: str
    enabled: bool
    cached_count: int
    last_built_at: Optional[Any]
    created_at: Any

    class Config:
        from_attributes = True


class EDLConfigCreateIn(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None
    indicator_type: str
    min_confidence: int = 50
    min_severity: str = "medium"
    tags_filter: Optional[List[str]] = None
    max_age_days: Optional[int] = 30
    format: str = "plain"


@router.get("", response_model=List[EDLConfigOut])
async def list_edl_configs(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    rows = (await db.execute(select(EDLConfig).order_by(EDLConfig.name))).scalars().all()
    return list(rows)


@router.post("", response_model=EDLConfigOut, status_code=201)
async def create_edl_config(
    body: EDLConfigCreateIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    config = EDLConfig(**body.model_dump())
    db.add(config)
    await db.flush()
    return config


@router.get("/{edl_id}/preview")
async def preview_edl(
    edl_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Preview the first 100 indicators that would appear in this EDL feed."""
    config = (
        await db.execute(select(EDLConfig).where(EDLConfig.id == edl_id))
    ).scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail="EDL config not found")

    indicators = await _build_edl_list(db, config)
    return {
        "edl_id": str(edl_id),
        "name": config.name,
        "total": len(indicators),
        "preview": indicators[:100],
    }


@router.delete("/{edl_id}", status_code=204)
async def delete_edl_config(
    edl_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    config = (
        await db.execute(select(EDLConfig).where(EDLConfig.id == edl_id))
    ).scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail="EDL config not found")
    await db.delete(config)
