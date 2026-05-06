"""
Periodic device-poll scheduler.

Wakes every TICK_SECONDS, fetches due devices, and auto-triggers a single
analysis run when any of them yielded a fresh config (changed sha256).
Coalescing means at most one run per tick, even if 10 devices changed.

Singleton-safe: the attack-paths Deployment uses Recreate strategy with
replicas=1, so we don't need a Lease. If you scale out, add one.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import List

import sqlalchemy as sa

from app.db import AsyncSessionLocal
from app.devices.poll import poll_device
from app.engine.orchestrator import RunOrchestrator

log = logging.getLogger(__name__)

TICK_SECONDS = 60
# Per-device fetch timeout — the vendor clients also have their own timeouts,
# this is a belt-and-braces guard against a single hung TCP connect.
FETCH_TIMEOUT = 90


async def run_scheduler_forever() -> None:
    log.info("device scheduler started — tick=%ds", TICK_SECONDS)
    while True:
        try:
            await _tick()
        except asyncio.CancelledError:
            log.info("device scheduler cancelled")
            return
        except Exception:                                       # noqa: BLE001
            log.exception("scheduler tick crashed (continuing)")
        await asyncio.sleep(TICK_SECONDS)


async def _tick() -> None:
    due = await _list_due_devices()
    if not due:
        return
    log.info("scheduler tick: %d device(s) due", len(due))

    changed_uploads: List[uuid.UUID] = []
    for device_id in due:
        try:
            res = await asyncio.wait_for(
                poll_device(device_id, reason="scheduled"),
                timeout=FETCH_TIMEOUT,
            )
            if res.get("changed") and res.get("upload_id"):
                changed_uploads.append(uuid.UUID(res["upload_id"]))
                log.info("device %s: new config sha=%s",
                         device_id, res["sha256"][:12])
            else:
                log.debug("device %s: no change (%s)", device_id, res)
        except asyncio.TimeoutError:
            log.warning("device %s poll timed out", device_id)
        except Exception:                                       # noqa: BLE001
            log.exception("device %s poll raised", device_id)

    if changed_uploads:
        await _trigger_run(changed_uploads, reason=f"scheduler:{len(changed_uploads)}-changed")


async def _list_due_devices() -> List[uuid.UUID]:
    """Return UUIDs of enabled devices whose interval has elapsed (or never polled)."""
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(sa.text("""
            SELECT id FROM topology_devices
            WHERE enabled = TRUE
              AND (
                  last_polled_at IS NULL
               OR  last_polled_at + (poll_interval_seconds || ' seconds')::interval <= NOW()
              )
            ORDER BY COALESCE(last_polled_at, '1970-01-01'::timestamptz)
        """))).fetchall()
        return [r.id for r in rows]


async def _trigger_run(upload_ids: List[uuid.UUID], *, reason: str) -> None:
    orchestrator = RunOrchestrator()
    run_id = await orchestrator.create_run(
        upload_ids=upload_ids, triggered_by=reason,
    )
    # Auto-link uploads to devices' last_run_id so the UI can show "current
    # run" per device.
    async with AsyncSessionLocal() as db:
        await db.execute(sa.text("""
            UPDATE topology_devices d SET last_run_id = :rid
            WHERE d.last_upload_id = ANY(:uids)
        """), {"rid": str(run_id), "uids": [str(u) for u in upload_ids]})
        await db.commit()
    # Fire-and-forget execution; orchestrator persists status to Postgres.
    asyncio.create_task(orchestrator.execute(run_id))
    log.info("scheduler triggered run %s (%s)", run_id, reason)
