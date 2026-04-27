"""
Dashboard statistics endpoint – aggregates data from all services for the frontend.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key
from app.models.alert import Alert
from app.models.feed import Feed
from app.models.indicator import Indicator
from app.models.sandbox import SandboxResult
from app.services import indicator_service, alert_service

router = APIRouter(prefix="/stats", tags=["Statistics"])


@router.get("/dashboard")
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """
    Aggregate statistics for the main dashboard.
    Returns indicator counts, alert summaries, feed status, and time-series data.
    """
    ioc_stats = await indicator_service.get_indicator_stats(db)
    alert_stats = await alert_service.get_alert_stats(db)

    # Feed health
    feeds = (await db.execute(select(Feed))).scalars().all()
    feed_summary = []
    for f in feeds:
        feed_summary.append({
            "name": f.display_name,
            "enabled": f.enabled,
            "status": "healthy" if f.last_success_at else "degraded" if f.last_error else "pending",
            "last_run": f.last_run_at,
            "total_ingested": f.total_ingested,
        })

    # Sandbox summary
    sandbox_counts = (await db.execute(
        select(SandboxResult.status, func.count().label("cnt")).group_by(SandboxResult.status)
    )).all()

    # Top tags
    tag_query = text("""
        SELECT unnest(tags) AS tag, COUNT(*) AS cnt
        FROM indicators
        WHERE active = TRUE
        GROUP BY tag
        ORDER BY cnt DESC
        LIMIT 10
    """)
    top_tags = (await db.execute(tag_query)).all()

    # Ingestion timeline: indicators created per day for last 14 days
    timeline_query = text("""
        SELECT
            DATE_TRUNC('day', created_at) AS day,
            COUNT(*) AS count
        FROM indicators
        WHERE created_at >= NOW() - INTERVAL '14 days'
        GROUP BY day
        ORDER BY day ASC
    """)
    timeline = (await db.execute(timeline_query)).all()

    return {
        "indicators": ioc_stats,
        "alerts": alert_stats,
        "feeds": feed_summary,
        "sandbox": {r.status: r.cnt for r in sandbox_counts},
        "top_tags": [{"tag": r.tag, "count": r.cnt} for r in top_tags],
        "ingestion_timeline": [
            {"date": r.day.isoformat(), "count": r.count} for r in timeline
        ],
    }


@router.get("/alerts-timeline")
async def alerts_timeline(
    days:     int = Query(14, ge=1, le=90, description="Number of days to look back"),
    interval: str = Query("hour", description="Bucket size: hour | day"),
    db:       AsyncSession = Depends(get_db),
    _:        str          = Depends(require_api_key),
):
    """Alert counts bucketed by hour or day — used for the alerts-over-time chart."""
    trunc = "hour" if interval == "hour" else "day"
    rows = (await db.execute(text(f"""
        SELECT
            DATE_TRUNC('{trunc}', created_at)      AS bucket,
            severity,
            COUNT(*)                                AS count
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '{days} days'
        GROUP BY bucket, severity
        ORDER BY bucket ASC
    """))).fetchall()

    # Also return rule_name breakdown so the user can see which rules fired
    by_rule = (await db.execute(text(f"""
        SELECT
            DATE_TRUNC('{trunc}', created_at) AS bucket,
            rule_name,
            COUNT(*)                           AS count
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '{days} days'
        GROUP BY bucket, rule_name
        ORDER BY bucket ASC, count DESC
    """))).fetchall()

    return {
        "by_severity": [
            {"bucket": r.bucket.isoformat(), "severity": r.severity, "count": r.count}
            for r in rows
        ],
        "by_rule": [
            {"bucket": r.bucket.isoformat(), "rule_name": r.rule_name, "count": r.count}
            for r in by_rule
        ],
    }
