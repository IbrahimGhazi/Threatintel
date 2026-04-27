"""
Platform settings endpoints.

Exposes runtime-configurable settings stored in the ``platform_settings``
table.  Currently covers:

  - Log retention policy (log_retention_days: 1 | 7 | 30 | 90)
  - Tuning auto-apply parameters (proxied here for a unified settings page)
  - Weekly baseline toggle
"""
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key

router = APIRouter(prefix="/system", tags=["System"])

ALLOWED_RETENTION_DAYS = frozenset({1, 7, 30, 90})


# ── Schemas ───────────────────────────────────────────────────────────────────

class RetentionIn(BaseModel):
    log_retention_days: int = Field(..., description="1 | 7 | 30 | 90")


class SettingPatchIn(BaseModel):
    key: str
    value: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/settings")
async def get_all_settings(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """Return all platform_settings as a flat dict."""
    rows = (await db.execute(
        text("SELECT key, value, description, updated_at FROM platform_settings ORDER BY key")
    )).fetchall()
    return {row.key: row.value for row in rows}


@router.patch("/settings/retention")
async def update_log_retention(
    body: RetentionIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """
    Update the log retention period.

    Logs older than the configured number of days are purged by the
    background cleanup task that runs every 24 hours.
    """
    if body.log_retention_days not in ALLOWED_RETENTION_DAYS:
        raise HTTPException(
            status_code=422,
            detail=f"log_retention_days must be one of {sorted(ALLOWED_RETENTION_DAYS)}",
        )

    await db.execute(
        text("""
            INSERT INTO platform_settings (key, value, description)
            VALUES ('log_retention_days', :value, 'Number of days to retain log entries (1, 7, 30, 90)')
            ON CONFLICT (key) DO UPDATE
                SET value = EXCLUDED.value, updated_at = NOW()
        """),
        {"value": str(body.log_retention_days)},
    )
    await db.commit()

    return {
        "log_retention_days": body.log_retention_days,
        "status": "updated",
        "message": f"Logs older than {body.log_retention_days} day(s) will be purged on next cleanup cycle.",
    }


@router.patch("/settings")
async def update_setting(
    body: SettingPatchIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """Generic setting upsert (for tuning config etc.)."""
    await db.execute(
        text("""
            INSERT INTO platform_settings (key, value)
            VALUES (:key, :value)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        """),
        {"key": body.key, "value": body.value},
    )
    await db.commit()
    return {"key": body.key, "value": body.value, "status": "updated"}
