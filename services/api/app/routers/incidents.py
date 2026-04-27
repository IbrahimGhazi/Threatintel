"""
Incident management endpoints – list, detail, and resolve grouped incidents.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.middleware.auth import require_api_key
from app.models.incident import Incident
from app.models.alert import Alert

router = APIRouter(prefix="/incidents", tags=["Incidents"])


# ── Response schemas ─────────────────────────────────────────────────────────

class AlertBrief(BaseModel):
    id: uuid.UUID
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    rule_name: Optional[str] = None
    indicator_value: Optional[str] = None
    source_service: str = "correlation"
    context: Dict[str, Any] = {}
    created_at: Any

    class Config:
        from_attributes = True


class IncidentOut(BaseModel):
    id: uuid.UUID
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    source_ip: Optional[str] = None
    attack_type: Optional[str] = None
    mitre_tactics: List[str] = []
    total_events: int = 0
    first_seen: Any
    last_seen: Any
    created_at: Any
    updated_at: Any

    class Config:
        from_attributes = True


class IncidentDetailOut(IncidentOut):
    alerts: List[AlertBrief] = []


class IncidentListOut(BaseModel):
    total: int
    offset: int
    limit: int
    items: List[IncidentOut]


class ResolveIn(BaseModel):
    notes: Optional[str] = None


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", response_model=IncidentListOut)
async def list_incidents(
    status: Optional[str] = Query(None, description="Filter by status: open, investigating, resolved, closed"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    attack_type: Optional[str] = Query(None, description="Filter by attack type"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """List incidents with optional filters."""
    base = select(Incident)
    count_q = select(func.count()).select_from(Incident)

    conditions = []
    if status:
        conditions.append(Incident.status == status)
    if severity:
        conditions.append(Incident.severity == severity)
    if attack_type:
        conditions.append(Incident.attack_type == attack_type)

    if conditions:
        base = base.where(and_(*conditions))
        count_q = count_q.where(and_(*conditions))

    total = (await db.execute(count_q)).scalar_one()
    rows = (
        await db.execute(
            base.order_by(desc(Incident.last_seen)).offset(offset).limit(limit)
        )
    ).scalars().all()

    return IncidentListOut(total=total, offset=offset, limit=limit, items=rows)


@router.get("/{incident_id}", response_model=IncidentDetailOut)
async def get_incident(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Get a single incident with its grouped alerts."""
    stmt = (
        select(Incident)
        .options(selectinload(Incident.alerts))
        .where(Incident.id == incident_id)
    )
    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Build the response manually so we can include alerts
    alert_list = sorted(incident.alerts, key=lambda a: a.created_at, reverse=True)
    return IncidentDetailOut(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        source_ip=incident.source_ip,
        attack_type=incident.attack_type,
        mitre_tactics=incident.mitre_tactics or [],
        total_events=incident.total_events,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        alerts=[
            AlertBrief(
                id=a.id,
                title=a.title,
                description=a.description,
                severity=a.severity,
                status=a.status,
                rule_name=a.rule_name,
                indicator_value=a.indicator_value,
                source_service=a.source_service,
                context=a.context or {},
                created_at=a.created_at,
            )
            for a in alert_list
        ],
    )


@router.post("/{incident_id}/resolve", response_model=IncidentOut)
async def resolve_incident(
    incident_id: uuid.UUID,
    body: ResolveIn = ResolveIn(),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Resolve an incident and all its associated alerts."""
    now = datetime.now(timezone.utc)

    # Update the incident status
    stmt = (
        update(Incident)
        .where(Incident.id == incident_id)
        .values(status="resolved", updated_at=now)
        .returning(Incident)
    )
    result = await db.execute(stmt)
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Resolve all associated open/acknowledged alerts
    alert_values = {
        "status": "resolved",
        "resolved_at": now,
        "updated_at": now,
    }
    if body.notes:
        alert_values["notes"] = body.notes

    await db.execute(
        update(Alert)
        .where(
            Alert.incident_id == incident_id,
            Alert.status.in_(["open", "acknowledged"]),
        )
        .values(**alert_values)
    )

    return row[0]
