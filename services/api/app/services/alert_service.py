"""
Alert management service – creation, querying, and lifecycle management.
"""
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.indicator import Indicator

logger = logging.getLogger(__name__)


async def create_alert(
    db: AsyncSession,
    title: str,
    severity: str,
    description: Optional[str] = None,
    indicator_id: Optional[uuid.UUID] = None,
    indicator_value: Optional[str] = None,
    indicator_type: Optional[str] = None,
    rule_name: Optional[str] = None,
    source_service: str = "correlation",
    context: Optional[Dict[str, Any]] = None,
) -> Alert:
    """Create a new alert and persist it."""
    alert = Alert(
        title=title,
        description=description,
        severity=severity,
        indicator_id=indicator_id,
        indicator_value=indicator_value,
        indicator_type=indicator_type,
        rule_name=rule_name,
        source_service=source_service,
        context=context or {},
    )
    db.add(alert)
    await db.flush()
    logger.info("Alert created: id=%s title=%r severity=%s", alert.id, title, severity)
    return alert


async def list_alerts(
    db: AsyncSession,
    *,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source_service: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
) -> Tuple[List[Alert], int]:
    base = select(Alert)
    count = select(func.count()).select_from(Alert)

    conditions = []
    if status:
        conditions.append(Alert.status == status)
    if severity:
        conditions.append(Alert.severity == severity)
    if source_service:
        conditions.append(Alert.source_service == source_service)

    if conditions:
        base = base.where(and_(*conditions))
        count = count.where(and_(*conditions))

    total = (await db.execute(count)).scalar_one()
    rows = (
        await db.execute(base.order_by(desc(Alert.created_at)).offset(offset).limit(limit))
    ).scalars().all()

    return list(rows), total


async def acknowledge_alert(
    db: AsyncSession,
    alert_id: uuid.UUID,
    acknowledged_by: str,
) -> Optional[Alert]:
    now = datetime.now(timezone.utc)
    stmt = (
        update(Alert)
        .where(Alert.id == alert_id, Alert.status == "open")
        .values(
            status="acknowledged",
            acknowledged_at=now,
            acknowledged_by=acknowledged_by,
            updated_at=now,
        )
        .returning(Alert)
    )
    result = await db.execute(stmt)
    row = result.fetchone()
    return row[0] if row else None


async def resolve_alert(
    db: AsyncSession,
    alert_id: uuid.UUID,
    notes: Optional[str] = None,
) -> Optional[Alert]:
    now = datetime.now(timezone.utc)
    values = {"status": "resolved", "resolved_at": now, "updated_at": now}
    if notes:
        values["notes"] = notes
    stmt = (
        update(Alert)
        .where(Alert.id == alert_id)
        .values(**values)
        .returning(Alert)
    )
    result = await db.execute(stmt)
    row = result.fetchone()
    return row[0] if row else None


async def get_alert_stats(db: AsyncSession) -> Dict[str, Any]:
    by_status = (await db.execute(
        select(Alert.status, func.count().label("cnt")).group_by(Alert.status)
    )).all()

    by_severity = (await db.execute(
        select(Alert.severity, func.count().label("cnt"))
        .where(Alert.status == "open")
        .group_by(Alert.severity)
    )).all()

    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    recent = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.created_at >= cutoff)
    )).scalar_one()

    return {
        "by_status": {r.status: r.cnt for r in by_status},
        "by_severity": {r.severity: r.cnt for r in by_severity},
        "recent_24h": recent,
    }


async def get_alert_context(
    db: AsyncSession, 
    alert_id: uuid.UUID
) -> Optional[Dict[str, Any]]:
    """Get alert with full incident context and related log entries."""
    from app.models.log_entry import LogEntry
    
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    
    if not alert:
        return None
    
    context = dict(alert.context)
    
    # Fetch related logs if log IDs present
    log_ids = context.get("related_logs", [])
    if log_ids:
        log_stmt = select(LogEntry).where(LogEntry.id.in_(log_ids))
        log_result = await db.execute(log_stmt)
        related_logs = log_result.scalars().all()
        context["related_logs"] = [
            {
                "id": str(log.id),
                "source_type": log.source_type,
                "source_ip": log.source_ip,
                "raw_log": log.raw_log,
                "processed_at": log.processed_at.isoformat() if log.processed_at else None,
                "is_malicious": log.is_malicious,
            }
            for log in related_logs
        ]
    
    return {
        "alert": {
            "id": str(alert.id),
            "title": alert.title,
            "severity": alert.severity,
            "status": alert.status,
            "rule_name": getattr(alert, "rule_name", None),
            "created_at": alert.created_at.isoformat(),
        },
        "context": context
    }
