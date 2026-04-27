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

from fastapi import APIRouter, Body, Depends, HTTPException, Query
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
        WHERE id = :id AND status IN ('pending', 'observed')
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

    # Write the suggested threshold into rule_overrides so the correlation
    # service picks it up on its next 60-second poll.
    suggested = _jsonb(row.suggested_value) or {}
    if suggested.get("threshold") is not None:
        await db.execute(text("""
            INSERT INTO rule_overrides
              (rule_name, entity_type, entity_value, threshold, applied_by, suggestion_id)
            VALUES
              (:rule_name, :entity_type, :entity_value, :threshold, 'analyst', :sid)
            ON CONFLICT (rule_name, entity_type, entity_value) DO UPDATE SET
              threshold   = EXCLUDED.threshold,
              applied_by  = 'analyst',
              applied_at  = NOW(),
              suggestion_id = EXCLUDED.suggestion_id
        """), {
            "rule_name":    row.rule_name,
            "entity_type":  row.entity_type or "global",
            "entity_value": row.entity_value or "*",
            "threshold":    float(suggested["threshold"]),
            "sid":          suggestion_id,
        })

    # Auto-resolve related open alerts for the tuned rule
    entity_val = row.entity_value or "*"
    resolve_note = (
        f"Auto-resolved: threshold tuned for rule '{row.rule_name}' "
        f"(accepted by analyst)"
    )
    await db.execute(text("""
        UPDATE alerts
        SET status      = 'resolved',
            resolved_at = NOW(),
            notes       = :note
        WHERE rule_name = :rule_name
          AND status    = 'open'
          AND (
              context->>'source_ip' = :entity_value
              OR :entity_value = '*'
          )
    """), {
        "rule_name":    row.rule_name,
        "entity_value": entity_val,
        "note":         resolve_note,
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
        WHERE id = :id AND status IN ('pending', 'observed')
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
    method:       Optional[str] = Query(None, description="statistical | ema"),
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
    if method:
        conditions.append("method = :method")
        params["method"] = method

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
        "entity_type":      r.entity_type,
        "entity_value":     r.entity_value,
        "metric":           r.metric,
        "category":         r.category,
        "method":           getattr(r, 'method', 'statistical'),
        "mean":             r.mean,
        "std_dev":          r.std_dev,
        "sample_count":     r.sample_count,
        "min_observed":     r.min_observed,
        "max_observed":     r.max_observed,
        "p95":              r.p95,
        "confidence_score": getattr(r, 'confidence_score', 0),
        "last_updated":     r.last_updated.isoformat(),
    } for r in rows]

    return {"items": items, "total": total}


# ── Learning Mode ────────────────────────────────────────────────────────────

@router.get("/learning/status")
async def get_learning_status(
    db: AsyncSession = Depends(get_db),
    _:  str          = Depends(require_api_key),
):
    """Return overall learning progress, mode, and per-method breakdown."""
    # Get learning config
    config_row = (await db.execute(text(
        "SELECT learning_mode, enforcement_mode, started_at "
        "FROM baseline_learning_config LIMIT 1"
    ))).fetchone()

    learning_mode    = config_row.learning_mode    if config_row else "on"
    enforcement_mode = config_row.enforcement_mode if config_row else "transparent"
    started_at       = config_row.started_at.isoformat() if config_row and config_row.started_at else None

    # Aggregate confidence per method
    method_stats = (await db.execute(text("""
        SELECT method,
               COUNT(*) AS baselines,
               COALESCE(AVG(confidence_score), 0) AS avg_confidence,
               COALESCE(SUM(sample_count), 0) AS total_samples
        FROM behavioral_baselines
        GROUP BY method
    """))).fetchall()

    methods = {}
    for row in method_stats:
        methods[row.method] = {
            "confidence":    round(float(row.avg_confidence) * 100, 1),
            "baselines":     row.baselines,
            "total_samples": int(row.total_samples),
        }

    # Category breakdown
    cat_stats = (await db.execute(text("""
        SELECT category,
               COUNT(*) AS baselines,
               COALESCE(AVG(confidence_score), 0) AS avg_confidence,
               COALESCE(SUM(sample_count), 0) AS total_samples
        FROM behavioral_baselines
        GROUP BY category
        ORDER BY total_samples DESC
    """))).fetchall()

    categories = {}
    for row in cat_stats:
        categories[row.category] = {
            "baselines":      row.baselines,
            "avg_confidence": round(float(row.avg_confidence) * 100, 1),
            "samples":        int(row.total_samples),
        }

    # Temporal coverage from baseline_time_patterns
    temporal_coverage = 0.0
    temporal_entries  = 0
    temporal_samples  = 0
    try:
        tp_row = (await db.execute(text("""
            SELECT COUNT(DISTINCT hour_of_week) AS covered,
                   COUNT(*) AS total_entries,
                   COALESCE(SUM(sample_count), 0) AS total_samples
            FROM baseline_time_patterns
            WHERE sample_count >= 5
        """))).fetchone()
        if tp_row and tp_row.covered:
            temporal_coverage = round(float(tp_row.covered) / 168 * 100, 1)
            temporal_entries  = tp_row.total_entries
            temporal_samples  = int(tp_row.total_samples)
    except Exception:
        pass

    # Peer group: count distinct /24 subnets with multiple hosts
    peer_subnets  = 0
    peer_hosts    = 0
    try:
        pg_row = (await db.execute(text("""
            SELECT COUNT(DISTINCT subnet) AS subnets,
                   SUM(host_count)         AS total_hosts
            FROM (
                SELECT SUBSTRING(entity_value FROM '^([0-9]+\\.[0-9]+\\.[0-9]+)') AS subnet,
                       COUNT(DISTINCT entity_value) AS host_count
                FROM behavioral_baselines
                WHERE entity_type = 'host'
                  AND entity_value ~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'
                GROUP BY SUBSTRING(entity_value FROM '^([0-9]+\\.[0-9]+\\.[0-9]+)')
                HAVING COUNT(DISTINCT entity_value) >= 2
            ) sub
        """))).fetchone()
        if pg_row and pg_row.subnets:
            peer_subnets = pg_row.subnets
            peer_hosts   = int(pg_row.total_hosts)
    except Exception:
        pass
    # Peer group confidence: need >= 3 subnets with multi-host coverage
    peer_confidence = min(round(peer_subnets / 3 * 100, 1), 100.0) if peer_subnets else 0.0

    # Ensure temporal and peer_group methods always present
    if "temporal" not in methods:
        methods["temporal"] = {"confidence": 0, "baselines": 0, "total_samples": 0}
    # Temporal confidence IS the coverage percentage (how much of the week is covered)
    methods["temporal"]["confidence"] = temporal_coverage
    methods["temporal"]["coverage"]   = temporal_coverage
    methods["temporal"]["baselines"]  = temporal_entries
    methods["temporal"]["total_samples"] = temporal_samples

    if "peer_group" not in methods:
        methods["peer_group"] = {"confidence": 0, "baselines": 0, "total_samples": 0}
    methods["peer_group"]["confidence"] = peer_confidence
    methods["peer_group"]["subnets"]    = peer_subnets
    methods["peer_group"]["hosts"]      = peer_hosts

    # Overall entities and metrics
    entity_count = (await db.execute(text(
        "SELECT COUNT(DISTINCT entity_value) FROM behavioral_baselines"
    ))).scalar_one()

    metric_count = (await db.execute(text(
        "SELECT COUNT(DISTINCT metric) FROM behavioral_baselines"
    ))).scalar_one()

    # Overall confidence (weighted)
    stat_conf = methods.get("statistical", {}).get("confidence", 0)
    temp_conf = methods.get("temporal", {}).get("confidence", 0)
    ema_conf  = methods.get("ema", {}).get("confidence", 0)
    peer_conf = methods.get("peer_group", {}).get("confidence", 0)

    overall = (stat_conf * 0.40 + temp_conf * 0.25 + ema_conf * 0.20 + peer_conf * 0.15)

    # Maturity
    if overall >= 90:
        maturity = "operational"
    elif overall >= 70:
        maturity = "nearly_ready"
    elif overall >= 45:
        maturity = "maturing"
    elif overall >= 20:
        maturity = "building"
    else:
        maturity = "initializing"

    return {
        "overall_confidence": round(overall, 1),
        "total_entities":     entity_count,
        "total_metrics":      metric_count,
        "learning_mode":      learning_mode,
        "enforcement_mode":   enforcement_mode,
        "started_at":         started_at,
        "methods":            methods,
        "categories":         categories,
        "maturity":           maturity,
    }


@router.patch("/learning/mode")
async def set_learning_mode(
    body: dict,
    db:   AsyncSession = Depends(get_db),
    _:    str          = Depends(require_api_key),
):
    """Update learning mode and/or enforcement mode.

    Body: { "learning_mode": "on"|"off", "enforcement_mode": "transparent"|"blocking" }
    """
    allowed_learning = {"on", "off"}
    allowed_enforcement = {"transparent", "blocking"}

    updates = []
    params = {}
    if "learning_mode" in body:
        if body["learning_mode"] not in allowed_learning:
            raise HTTPException(400, "learning_mode must be 'on' or 'off'")
        updates.append("learning_mode = :lm")
        params["lm"] = body["learning_mode"]
    if "enforcement_mode" in body:
        if body["enforcement_mode"] not in allowed_enforcement:
            raise HTTPException(400, "enforcement_mode must be 'transparent' or 'blocking'")
        updates.append("enforcement_mode = :em")
        params["em"] = body["enforcement_mode"]

    if not updates:
        raise HTTPException(400, "No valid fields provided")

    updates.append("updated_at = NOW()")
    set_clause = ", ".join(updates)

    # Upsert: update if exists, insert if not
    existing = (await db.execute(text(
        "SELECT id FROM baseline_learning_config LIMIT 1"
    ))).fetchone()

    if existing:
        await db.execute(text(
            f"UPDATE baseline_learning_config SET {set_clause} WHERE id = :id"
        ), {**params, "id": str(existing.id)})
    else:
        await db.execute(text("""
            INSERT INTO baseline_learning_config (learning_mode, enforcement_mode)
            VALUES (:lm, :em)
        """), {
            "lm": body.get("learning_mode", "on"),
            "em": body.get("enforcement_mode", "transparent"),
        })

    # If switching to learning=on, reset started_at
    if body.get("learning_mode") == "on":
        await db.execute(text(
            "UPDATE baseline_learning_config SET started_at = NOW()"
        ))

    await db.commit()

    return await get_learning_status(db=db, _=_)


@router.post("/learning/reset")
async def reset_baselines(
    db: AsyncSession = Depends(get_db),
    _:  str          = Depends(require_api_key),
):
    """Reset all behavioral baselines and restart learning from scratch."""
    await db.execute(text("TRUNCATE behavioral_baselines CASCADE"))
    await db.execute(text("TRUNCATE baseline_time_patterns CASCADE"))
    await db.execute(text(
        "UPDATE baseline_learning_config SET learning_mode = 'on', "
        "enforcement_mode = 'transparent', started_at = NOW(), updated_at = NOW()"
    ))
    await db.commit()
    return {"status": "ok", "message": "All baselines reset. Learning restarted."}


# ── Runtime config ───────────────────────────────────────────────────────────

_ALLOWED_SETTINGS = {
    "auto_apply_delay_hours": ("int",   1,    168),
    "auto_apply_confidence":  ("float", 0.50, 0.99),
}


def _config_row(row) -> dict:
    return {
        "value":       row.value,
        "description": row.description,
        "updated_at":  _iso(row.updated_at),
    }


@router.get("/config")
async def get_tuning_config(
    db: AsyncSession = Depends(get_db),
    _:  str          = Depends(require_api_key),
):
    """Return current auto-apply configuration."""
    rows = (await db.execute(text(
        "SELECT key, value, description, updated_at FROM platform_settings ORDER BY key"
    ))).fetchall()
    return {r.key: _config_row(r) for r in rows}


@router.patch("/config")
async def update_tuning_config(
    body: Dict[str, Any] = Body(...),
    db:   AsyncSession   = Depends(get_db),
    _:    str            = Depends(require_api_key),
):
    """Update auto-apply settings. Immediately reschedules pending suggestions."""
    for key, raw_value in body.items():
        if key not in _ALLOWED_SETTINGS:
            raise HTTPException(status_code=400, detail=f"Unknown setting: {key}")

        kind, lo, hi = _ALLOWED_SETTINGS[key]
        try:
            typed = int(raw_value) if kind == "int" else float(raw_value)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail=f"{key} must be a {kind}")

        if not (lo <= typed <= hi):
            raise HTTPException(
                status_code=400,
                detail=f"{key} must be between {lo} and {hi}",
            )

        await db.execute(
            text("UPDATE platform_settings SET value = :v WHERE key = :k"),
            {"k": key, "v": str(typed)},
        )

    # If the review window changed, reschedule all pending suggestions that
    # already have auto_apply_at set so the new delay takes effect immediately.
    if "auto_apply_delay_hours" in body:
        hours = int(body["auto_apply_delay_hours"])
        await db.execute(text("""
            UPDATE tuning_suggestions
            SET auto_apply_at = NOW() + (:hours * INTERVAL '1 hour')
            WHERE status = 'pending'
              AND auto_apply_at IS NOT NULL
        """), {"hours": hours})

    await db.commit()

    rows = (await db.execute(text(
        "SELECT key, value, description, updated_at FROM platform_settings ORDER BY key"
    ))).fetchall()
    return {r.key: _config_row(r) for r in rows}


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

    # Get learning mode
    config_row = (await db.execute(text(
        "SELECT learning_mode, enforcement_mode FROM baseline_learning_config LIMIT 1"
    ))).fetchone()

    return {
        "pending":          status_map.get("pending",      0),
        "accepted":         status_map.get("accepted",     0),
        "rejected":         status_map.get("rejected",     0),
        "auto_applied":     status_map.get("auto_applied", 0),
        "observed":         status_map.get("observed",     0),
        "baselines_total":  baselines_total,
        "changes_total":    changes_total,
        "learning_mode":    config_row.learning_mode if config_row else "on",
        "enforcement_mode": config_row.enforcement_mode if config_row else "transparent",
    }
