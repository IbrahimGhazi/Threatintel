"""
Whitelist management endpoints.

Allows analysts to whitelist IPs, CIDRs, hostnames, rule names,
or indicator values to suppress future alerts.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, desc, select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key
from app.models.whitelist import WhitelistEntry

router = APIRouter(prefix="/whitelist", tags=["Whitelist"])


# ── Pydantic Models ──────────────────────────────────────────

class WhitelistCreateIn(BaseModel):
    entry_type: str = Field(..., description="ip | cidr | hostname | rule_name | indicator_value")
    value: str = Field(..., min_length=1, max_length=512)
    scope_rule: Optional[str] = Field(None, description="Restrict to specific rule name (null = all rules)")
    reason: Optional[str] = Field(None, max_length=1024)
    created_by: str = Field("analyst", max_length=128)
    expires_at: Optional[datetime] = None
    source_alert_id: Optional[uuid.UUID] = None


class WhitelistOut(BaseModel):
    id: uuid.UUID
    entry_type: str
    value: str
    scope_rule: Optional[str]
    reason: Optional[str]
    created_by: str
    expires_at: Optional[Any]
    enabled: bool
    source_alert_id: Optional[uuid.UUID]
    created_at: Any
    updated_at: Any

    class Config:
        from_attributes = True


class WhitelistListOut(BaseModel):
    total: int
    items: List[WhitelistOut]


# ── Endpoints ────────────────────────────────────────────────

@router.get("", response_model=WhitelistListOut)
async def list_whitelist(
    entry_type: Optional[str] = Query(None),
    enabled_only: bool = Query(True),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """List whitelist entries with optional filters."""
    conditions = []
    if entry_type:
        conditions.append(WhitelistEntry.entry_type == entry_type)
    if enabled_only:
        conditions.append(WhitelistEntry.enabled == True)

    base = select(WhitelistEntry)
    count_q = select(func.count()).select_from(WhitelistEntry)

    if conditions:
        base = base.where(and_(*conditions))
        count_q = count_q.where(and_(*conditions))

    total = (await db.execute(count_q)).scalar_one()
    rows = (
        await db.execute(
            base.order_by(desc(WhitelistEntry.created_at)).offset(offset).limit(limit)
        )
    ).scalars().all()

    return WhitelistListOut(total=total, items=list(rows))


@router.get("/active", response_model=List[WhitelistOut])
async def get_active_whitelist(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Get all active, non-expired whitelist entries (used by correlation service)."""
    now = datetime.now(timezone.utc)
    stmt = (
        select(WhitelistEntry)
        .where(WhitelistEntry.enabled == True)
        .where(
            (WhitelistEntry.expires_at == None) | (WhitelistEntry.expires_at > now)
        )
    )
    rows = (await db.execute(stmt)).scalars().all()
    return list(rows)


@router.post("", response_model=WhitelistOut, status_code=201)
async def create_whitelist_entry(
    body: WhitelistCreateIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Create a new whitelist entry."""
    valid_types = {"ip", "cidr", "hostname", "rule_name", "indicator_value"}
    if body.entry_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"entry_type must be one of: {', '.join(sorted(valid_types))}")

    # Check for duplicates
    existing = (await db.execute(
        select(WhitelistEntry).where(
            WhitelistEntry.entry_type == body.entry_type,
            WhitelistEntry.value == body.value,
            WhitelistEntry.scope_rule == body.scope_rule,
        )
    )).scalar_one_or_none()

    if existing:
        if not existing.enabled:
            # Re-enable existing disabled entry
            existing.enabled = True
            existing.reason = body.reason or existing.reason
            existing.expires_at = body.expires_at
            await db.flush()
            return existing
        raise HTTPException(status_code=409, detail="Whitelist entry already exists")

    entry = WhitelistEntry(
        entry_type=body.entry_type,
        value=body.value.strip(),
        scope_rule=body.scope_rule,
        reason=body.reason,
        created_by=body.created_by,
        expires_at=body.expires_at,
        source_alert_id=body.source_alert_id,
    )
    db.add(entry)
    await db.flush()
    return entry


@router.delete("/{entry_id}")
async def delete_whitelist_entry(
    entry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Disable a whitelist entry (soft delete)."""
    stmt = (
        update(WhitelistEntry)
        .where(WhitelistEntry.id == entry_id)
        .values(enabled=False, updated_at=datetime.now(timezone.utc))
    )
    result = await db.execute(stmt)
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Whitelist entry not found")
    return {"status": "disabled", "id": str(entry_id)}


@router.post("/from-alert/{alert_id}", response_model=WhitelistOut, status_code=201)
async def whitelist_from_alert(
    alert_id: uuid.UUID,
    body: WhitelistCreateIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Create a whitelist entry from an alert context and resolve the alert."""
    from app.models.alert import Alert

    # Verify alert exists
    alert = (await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    body.source_alert_id = alert_id

    valid_types = {"ip", "cidr", "hostname", "rule_name", "indicator_value"}
    if body.entry_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"entry_type must be one of: {', '.join(sorted(valid_types))}")

    # Create or re-enable
    existing = (await db.execute(
        select(WhitelistEntry).where(
            WhitelistEntry.entry_type == body.entry_type,
            WhitelistEntry.value == body.value,
            WhitelistEntry.scope_rule == body.scope_rule,
        )
    )).scalar_one_or_none()

    if existing:
        existing.enabled = True
        existing.reason = body.reason or existing.reason
        existing.source_alert_id = alert_id
        existing.expires_at = body.expires_at
        await db.flush()
        entry = existing
    else:
        entry = WhitelistEntry(
            entry_type=body.entry_type,
            value=body.value.strip(),
            scope_rule=body.scope_rule,
            reason=body.reason,
            created_by=body.created_by,
            expires_at=body.expires_at,
            source_alert_id=alert_id,
        )
        db.add(entry)
        await db.flush()

    # Resolve the alert as false positive
    now = datetime.now(timezone.utc)
    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id)
        .values(
            status="false_positive",
            resolved_at=now,
            updated_at=now,
            notes=f"Whitelisted: {body.entry_type}={body.value}" + (f" reason={body.reason}" if body.reason else ""),
        )
    )

    return entry
