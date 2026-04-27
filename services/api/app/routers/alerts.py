"""
Alert management endpoints.
"""
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key
from app.services import alert_service

router = APIRouter(prefix="/alerts", tags=["Alerts"])


class AlertOut(BaseModel):
    id: uuid.UUID
    title: str
    description: Optional[str]
    severity: str
    status: str
    indicator_value: Optional[str]
    indicator_type: Optional[str]
    rule_name: Optional[str]
    source_service: str
    context: Dict[str, Any]
    created_at: Any
    updated_at: Any
    acknowledged_at: Optional[Any]
    acknowledged_by: Optional[str]
    resolved_at: Optional[Any]
    notes: Optional[str]

    class Config:
        from_attributes = True


class AlertListOut(BaseModel):
    total: int
    offset: int
    limit: int
    items: List[AlertOut]


class AcknowledgeIn(BaseModel):
    acknowledged_by: str = "analyst"


class ResolveIn(BaseModel):
    notes: Optional[str] = None


@router.get("", response_model=AlertListOut)
async def list_alerts(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source_service: Optional[str] = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    items, total = await alert_service.list_alerts(
        db,
        status=status,
        severity=severity,
        source_service=source_service,
        offset=offset,
        limit=limit,
    )
    return AlertListOut(total=total, offset=offset, limit=limit, items=items)


@router.get("/stats")
async def alert_stats(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    return await alert_service.get_alert_stats(db)


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    from sqlalchemy import select
    from app.models.alert import Alert
    row = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge_alert(
    alert_id: uuid.UUID,
    body: AcknowledgeIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    row = await alert_service.acknowledge_alert(db, alert_id, body.acknowledged_by)
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found or already acknowledged")
    return row


@router.post("/{alert_id}/resolve", response_model=AlertOut)
async def resolve_alert(
    alert_id: uuid.UUID,
    body: ResolveIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    row = await alert_service.resolve_alert(db, alert_id, body.notes)
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row


@router.get("/{alert_id}/context")
async def get_alert_context(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Get detailed incident context for alert visualization."""
    from app.services import alert_service
    
    context = await alert_service.get_alert_context(db, alert_id)
    if not context:
        raise HTTPException(status_code=404, detail="Alert not found")
    return context
