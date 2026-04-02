"""
Adaptive Tuning API

GET  /tuning/suggestions                 — list rule-tuning suggestions
POST /tuning/suggestions/{id}/accept     — analyst accepts a suggestion
POST /tuning/suggestions/{id}/reject     — analyst rejects a suggestion
GET  /tuning/changes                     — audit log of applied changes
POST /tuning/changes/{id}/revert         — revert an applied change
GET  /tuning/baselines                   — view per-entity behavioral baselines
"""

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key

router = APIRouter(prefix="/tuning", tags=["Adaptive Tuning"])


# ── Serialisers ───────────────────────────────────────────────────────────────

def _iso(v) -> Optional[str]:
    return v.isoformat() if v else None


def _jsonb(v) -> Optional[Dict[str, Any]]:
    if v is None:
        return None
    if isinstance(v, dict):
        return v
    # asyncpg may return a string for JSONB columns
    if isinstance(v, str):
        try:
            return json.loads(v)
        except Exception:
            return {}
    return {}


def _suggestion_out(row) -> dict:
    return {
        "id":              str(row.id),
        "suggestion_type": row.suggestion_type,
        "category":        row.category,
        "entity_type":     row.entity_type,
        "entity_value":    row.entity_value,
        "rule_name":       row.rule_name,
        "current_value":   _jsonb(row.current_value),
        "suggested_value": _jsonb(row.suggested_value),
        "rationale":       row.rationale,
        "confidence":      row.confidence,
        "trigger_count":   row.trigger_count,
        "status":          row.status,
        "auto_apply_at":   _iso(row.auto_apply_at),
        "applied_at":      _iso(row.applied_at),
        "rejected_at":     _iso(row.rejected_at),
        "created_at":      row.created_at.isoformat(),
        "updated_at":      row.updated_at.isoformat(),
    }


def _change_out(row) -> dict:
    return {
        "id":             str(row.id),
        "suggestion_id":  str(row.suggestion_id) if row.suggestion_id else None,
        "change_type":    row.change_type,
        "rule_name":      row.rule_name,
        "entity_type":    row.entity_type,
        "entity_value":   row.entity_value,
        "previous_value": _jsonb(row.previous_value),
        "new_value":      _jsonb(row.new_value),
        "applied_by":     row.applied_by,
        "reason":         row.reason,
        "reverted_at":    _iso(row.reverted_at),
        "reverted_by":    row.reverted_by,
        "created_at":     row.created_at.isoformat(),
    }


# ── Suggestions ───────────────────────────────────────────────────────────────

@router.get("/suggestions")
async def list_suggestions(
    status:   Optional[str] = Query(None, description="pending | accepted | rejected | auto_applied"),
    category: Optional[str] = Query(None),
    limit:    int            = Query(50, ge=1, le=200),
    offset:   int            = Query(0,  ge=0),
    db:       AsyncSession   = Depends(get_db),
    _:        str            = Depends(require_api_key),
):
    """Return tuning suggestions, ordered by pending-first then confidence descending."""
    conditions = ["1=1"]
    params: dict = {"limit": limit, "offset": offset}

    if status:
        conditions.append("status = :status")
        params["status"] = status
    if category:
        conditions.append("category = :category")
        params["category"] = category

    where = " AND ".join(conditions)

    rows = (await db.execute(text(f"""
        SELECT * FROM tuning_suggestions
        WHERE {where}
        ORDER BY
          CASE status WHEN 'pending' THEN 0 ELSE 1 END,
          confidence  DESC,
          created_at  DESC
        LIMIT :limit OFFSET :offset
    """), params)).fetchall()

    total = (await db.execute(text(f"""
        SELECT COUNT(*) FROM tuning_suggestions WHERE {where}
    """), {k: v for k, v in params.items() if k not in ("limit", "offset")})).scalar_one()

    return {"items": [_suggestion_out(r) for r in rows], "total": total}


@router.post("/suggestions/{suggestion_id}/accept")
async def accept_suggestion(
    suggestion_id: str,
    db: AsyncSession = Depends(get_db),
    _:  str          = Depends(require_api_key),
):
    """Analyst manually accepts a suggestion and logs the change."""
    row = (await db.execute(text("""
        SELECT * FROM tuning_suggestions
        WHERE id = :id AND status = 'pending'
    """), {"id": suggestion_id})).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Suggestion not found or already processed")

    await db.execute(text("""
        UPDATE tuning_suggestions
        SET status = 'accepted', applied_at = NOW()
        WHERE id = :id
    """), {"id": suggestion_id})

    # Audit log
    await db.execute(text("""
        INSERT INTO adaptive_rule_changes
          (suggestion_id, change_type, rule_name,
           entity_type, entity_value,
           previous_value, new_value,
           applied_by, reason)
        VALUES
          (:suggestion_id, :change_type, :rule_name,
           :entity_type, :entity_value,
           CAST(:previous_value AS jsonb), CAST(:new_value AS jsonb),
           'analyst', :reason)
    """), {
        "suggestion_id": suggestion_id,
        "change_type":   row.suggestion_type,
        "rule_name":     row.rule_name,
        "entity_type":   row.entity_type,
        "entity_value":  row.entity_value,
        "previous_value": json.dumps(_jsonb(row.current_value) or {}),
        "new_value":      json.dumps(_jsonb(row.suggested_value) or {}),
        "reason":         "Manually accepted by analyst",
    })

    await db.commit()

    updated = (await db.execute(text(
        "SELECT * FROM tuning_suggestions WHERE id = :id"
    ), {"id": suggestion_id})).fetchone()
    return _suggestion_out(updated)


@router.post("/suggestions/{suggestion_id}/reject")
async def reject_suggestion(
    suggestion_id: str,
    db: AsyncSession = Depends(get_db),
    _:  str          = Depends(require_api_key),
):
    """Analyst rejects a suggestion; clears the auto-apply schedule."""
    row = (await db.execute(text("""
        SELECT id FROM tuning_suggestions
        WHERE id = :id AND status = 'pending'
    """), {"id": suggestion_id})).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Suggestion not found or already processed")

    await db.execute(text("""
        UPDATE tuning_suggestions
        SET status        = 'rejected',
            rejected_at   = NOW(),
            auto_apply_at = NULL
        WHERE id = :id
    """), {"id": suggestion_id})
    await db.commit()

    updated = (await db.execute(text(
        "SELECT * FROM tuning_suggestions WHERE id = :id"
    ), {"id": suggestion_id})).fetchone()
    return _suggestion_out(updated)


# ── Applied changes (audit log) ───────────────────────────────────────────────

@router.get("/changes")
async def list_changes(
    limit:  int           = Query(50, ge=1, le=200),
    offset: int           = Query(0,  ge=0),
    db:     AsyncSession  = Depends(get_db),
    _:      str           = Depends(require_api_key),
):
    """Audit log of every applied rule change, newest first."""
    rows = (await db.execute(text("""
        SELECT * FROM adaptive_rule_changes
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
    """), {"limit": limit, "offset": offset})).fetchall()

    total = (await db.execute(
        text("SELECT COUNT(*) FROM adaptive_rule_changes")
    )).scalar_one()

    return {"items": [_change_out(r) for r in rows], "total": total}


@router.post("/changes/{change_id}/revert")
async def revert_change(
    change_id: str,
    db: AsyncSession = Depends(get_db),
    _:  str          = Depends(require_api_key),
):
    """Revert an applied change and reset the originating suggestion to pending."""
    row = (await db.execute(text("""
        SELECT * FROM adaptive_rule_changes
        WHERE id = :id AND reverted_at IS NULL
    """), {"id": change_id})).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Change not found or already reverted")

    await db.execute(text("""
        UPDATE adaptive_rule_changes
        SET reverted_at = NOW(), reverted_by = 'analyst'
        WHERE id = :id
    """), {"id": change_id})

    # Reset the source suggestion so it can be re-evaluated
    if row.suggestion_id:
        await db.execute(text("""
            UPDATE tuning_suggestions
            SET status        = 'pending',
                applied_at    = NULL,
                auto_apply_at = NULL
            WHERE id = :id
        """), {"id": str(row.suggestion_id)})

    await db.commit()

    updated = (await db.execute(text(
        "SELECT * FROM adaptive_rule_changes WHERE id = :id"
    ), {"id": change_id})).fetchone()
    return _change_out(updated)


# ── Baselines ─────────────────────────────────────────────────────────────────

@router.get("/baselines")
async def list_baselines(
    entity_value: Optional[str] = Query(None, description="Filter by host IP or username"),
    category:     Optional[str] = Query(None, description="dns | port_scan | auth | connection | lateral_movement | c2"),
    limit:        int            = Query(100, ge=1, le=500),
    offset:       int            = Query(0,   ge=0),
    db:           AsyncSession   = Depends(get_db),
    _:            str            = Depends(require_api_key),
):
    """Return learned behavioral baselines, ordered by sample count descending."""
    conditions = ["1=1"]
    params: dict = {"limit": limit, "offset": offset}

    if entity_value:
        conditions.append("entity_value = :entity_value")
        params["entity_value"] = entity_value
    if category:
        conditions.append("category = :category")
        params["category"] = category

    where = " AND ".join(conditions)

    rows = (await db.execute(text(f"""
        SELECT * FROM behavioral_baselines
        WHERE {where}
        ORDER BY sample_count DESC, last_updated DESC
        LIMIT :limit OFFSET :offset
    """), params)).fetchall()

    total = (await db.execute(text(f"""
        SELECT COUNT(*) FROM behavioral_baselines WHERE {where}
    """), {k: v for k, v in params.items() if k not in ("limit", "offset")})).scalar_one()

    items = [{
        "entity_type":   r.entity_type,
        "entity_value":  r.entity_value,
        "metric":        r.metric,
        "category":      r.category,
        "mean":          r.mean,
        "std_dev":       r.std_dev,
        "sample_count":  r.sample_count,
        "min_observed":  r.min_observed,
        "max_observed":  r.max_observed,
        "p95":           r.p95,
        "last_updated":  r.last_updated.isoformat(),
    } for r in rows]

    return {"items": items, "total": total}


# ── Summary stats ─────────────────────────────────────────────────────────────

@router.get("/stats")
async def tuning_stats(
    db: AsyncSession = Depends(get_db),
    _:  str          = Depends(require_api_key),
):
    """Quick-glance counters for the tuning dashboard header."""
    counts = (await db.execute(text("""
        SELECT status, COUNT(*) AS cnt
        FROM tuning_suggestions
        GROUP BY status
    """))).fetchall()

    status_map = {r.status: r.cnt for r in counts}

    baselines_total = (await db.execute(
        text("SELECT COUNT(*) FROM behavioral_baselines")
    )).scalar_one()

    changes_total = (await db.execute(
        text("SELECT COUNT(*) FROM adaptive_rule_changes")
    )).scalar_one()

    return {
        "pending":        status_map.get("pending",      0),
        "accepted":       status_map.get("accepted",     0),
        "rejected":       status_map.get("rejected",     0),
        "auto_applied":   status_map.get("auto_applied", 0),
        "baselines_total": baselines_total,
        "changes_total":   changes_total,
    }
