"""
Response recommendation endpoints.

When the correlation engine detects a threat it inserts one or more
response_recommendations rows.  Analysts can then:
  - Approve  → marks the recommendation as approved with optional config edit
  - Edit     → saves an edited version of the configuration
  - Ignore   → dismisses the recommendation

All actions are recorded with the analyst's name for audit purposes.
"""
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key

router = APIRouter(prefix="/recommendations", tags=["Recommendations"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class ApproveIn(BaseModel):
    analyst: str = "analyst"
    edited_config: Optional[str] = None   # If provided, replaces config_example


class EditIn(BaseModel):
    edited_config: str
    analyst: str = "analyst"


class IgnoreIn(BaseModel):
    analyst: str = "analyst"


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_rec(db: AsyncSession, rec_id: uuid.UUID) -> Dict[str, Any]:
    row = (await db.execute(
        text("SELECT * FROM response_recommendations WHERE id = :id"),
        {"id": str(rec_id)},
    )).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return dict(row._mapping)


def _row_to_dict(row) -> Dict[str, Any]:
    d = dict(row._mapping)
    # Ensure UUIDs are strings for JSON serialisation
    for k in ("id", "alert_id"):
        if k in d and d[k] is not None:
            d[k] = str(d[k])
    return d


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_recommendations(
    alert_id: Optional[str] = Query(None, description="Filter by alert UUID"),
    status: Optional[str] = Query(None, description="pending | approved | edited | ignored"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """List recommendations, optionally filtered by alert or status."""
    where: List[str] = ["1=1"]
    params: Dict[str, Any] = {"limit": limit, "offset": offset}

    if alert_id:
        where.append("alert_id = :alert_id")
        params["alert_id"] = alert_id
    if status:
        where.append("status = :status")
        params["status"] = status

    where_clause = " AND ".join(where)
    count_params = {k: v for k, v in params.items() if k not in ("limit", "offset")}

    rows = (await db.execute(
        text(f"""
            SELECT * FROM response_recommendations
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        params,
    )).fetchall()

    total = (await db.execute(
        text(f"SELECT COUNT(*) FROM response_recommendations WHERE {where_clause}"),
        count_params,
    )).scalar() or 0

    return {
        "total": int(total),
        "offset": offset,
        "limit": limit,
        "items": [_row_to_dict(r) for r in rows],
    }


@router.post("/{rec_id}/approve")
async def approve_recommendation(
    rec_id: uuid.UUID,
    body: ApproveIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """
    Analyst approves the recommendation.

    If ``edited_config`` is supplied the analyst-modified version is used as
    the applied configuration; otherwise the system-generated ``config_example``
    is adopted verbatim.
    """
    result = await db.execute(
        text("""
            UPDATE response_recommendations
            SET status       = 'approved',
                approved_by  = :analyst,
                approved_at  = NOW(),
                edited_config = COALESCE(:edited_config, edited_config),
                applied_config = COALESCE(:edited_config, config_example),
                updated_at   = NOW()
            WHERE id = :id AND status IN ('pending', 'edited')
            RETURNING *
        """),
        {"id": str(rec_id), "analyst": body.analyst, "edited_config": body.edited_config},
    )
    row = result.fetchone()
    await db.commit()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Recommendation not found or already actioned",
        )
    return _row_to_dict(row)


@router.patch("/{rec_id}/edit")
async def edit_recommendation(
    rec_id: uuid.UUID,
    body: EditIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """
    Analyst edits the config before approving.

    Sets status → 'edited' so the analyst can review the diff and then
    call /approve to finalise.
    """
    result = await db.execute(
        text("""
            UPDATE response_recommendations
            SET status        = 'edited',
                edited_config = :edited_config,
                approved_by   = :analyst,
                approved_at   = NOW(),
                applied_config = :edited_config,
                updated_at    = NOW()
            WHERE id = :id
            RETURNING *
        """),
        {"id": str(rec_id), "edited_config": body.edited_config, "analyst": body.analyst},
    )
    row = result.fetchone()
    await db.commit()

    if not row:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return _row_to_dict(row)


@router.post("/{rec_id}/ignore")
async def ignore_recommendation(
    rec_id: uuid.UUID,
    body: IgnoreIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """Analyst dismisses the recommendation as not applicable."""
    result = await db.execute(
        text("""
            UPDATE response_recommendations
            SET status      = 'ignored',
                approved_by = :analyst,
                updated_at  = NOW()
            WHERE id = :id AND status IN ('pending', 'edited')
            RETURNING *
        """),
        {"id": str(rec_id), "analyst": body.analyst},
    )
    row = result.fetchone()
    await db.commit()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Recommendation not found or already actioned",
        )
    return _row_to_dict(row)
