"""
Feed management endpoints – view and control threat intelligence feed configuration.
"""
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key
from app.models.feed import Feed

router = APIRouter(prefix="/feeds", tags=["Feeds"])


class FeedOut(BaseModel):
    id: uuid.UUID
    name: str
    display_name: str
    description: Optional[str]
    feed_type: str
    enabled: bool
    url: Optional[str]
    poll_interval: int
    last_run_at: Optional[Any]
    last_success_at: Optional[Any]
    last_error: Optional[str]
    last_error_at: Optional[Any]
    total_ingested: int
    config: Dict[str, Any]
    created_at: Any

    class Config:
        from_attributes = True


class FeedUpdateIn(BaseModel):
    enabled: Optional[bool] = None
    poll_interval: Optional[int] = None


@router.get("", response_model=List[FeedOut])
async def list_feeds(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    rows = (await db.execute(select(Feed).order_by(Feed.display_name))).scalars().all()
    return list(rows)


@router.get("/{feed_id}", response_model=FeedOut)
async def get_feed(
    feed_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    row = (await db.execute(select(Feed).where(Feed.id == feed_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Feed not found")
    return row


@router.patch("/{feed_id}", response_model=FeedOut)
async def update_feed(
    feed_id: uuid.UUID,
    body: FeedUpdateIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    values = {k: v for k, v in body.model_dump().items() if v is not None}
    if not values:
        raise HTTPException(status_code=422, detail="No fields to update")

    values["updated_at"] = func.now()
    stmt = (
        update(Feed)
        .where(Feed.id == feed_id)
        .values(**values)
        .returning(Feed)
    )
    result = await db.execute(stmt)
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Feed not found")
    return row[0]


@router.get("/{feed_id}/stats")
async def feed_stats(
    feed_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Return aggregate stats for a single feed."""
    feed = (await db.execute(select(Feed).where(Feed.id == feed_id))).scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    from app.models.indicator import IndicatorSource
    count = (await db.execute(
        select(func.count())
        .select_from(IndicatorSource)
        .where(IndicatorSource.source_name == feed.name)
    )).scalar_one()

    return {
        "feed_id": str(feed_id),
        "name": feed.name,
        "total_ingested": feed.total_ingested,
        "active_indicators": count,
        "last_run_at": feed.last_run_at,
        "last_success_at": feed.last_success_at,
        "status": "healthy" if feed.last_success_at else "never_run",
    }
