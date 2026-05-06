"""
Periodic device-poll scheduler.

Wakes every TICK_SECONDS, fetches due devices, and auto-triggers a single
analysis run when any of them yielded a fresh config (changed sha256).
Coalescing means at most one run per tick, even if 10 devices changed.

Also sweeps for "orphan" scheduler uploads — config uploads created via
the register or fetch-now path whose follow-up run-trigger somehow didn't
fire (process crash, transient DB error, or simply because we hadn't yet
shipped the per-action trigger). Orphans get picked up on the next tick
so the user never sees a permanently-stuck upload.

Singleton-safe: the attack-paths Deployment uses Recreate strategy with
replicas=1, so we don't need a Lease. If you scale out, add one.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import List, Optional

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
    changed_uploads: List[uuid.UUID] = []

    if due:
        log.info("scheduler tick: %d device(s) due", len(due))
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
            except Exception:                                   # noqa: BLE001
                log.exception("device %s poll raised", device_id)

    # Always sweep orphans so register-poll / fetch-now uploads that missed
    # their inline trigger eventually get analysed.
    orphans = await _list_orphan_uploads()
    all_uploads = list({*changed_uploads, *orphans})
    if all_uploads:
        reason_parts = []
        if changed_uploads:
            reason_parts.append(f"{len(changed_uploads)}-changed")
        if orphans:
            reason_parts.append(f"{len(orphans)}-orphan")
        await trigger_analysis_run(
            all_uploads, reason=f"scheduler:{','.join(reason_parts)}",
        )


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


async def _list_orphan_uploads() -> List[uuid.UUID]:
    """
    Scheduler-sourced uploads with no run linked. Recovers from any path
    that wrote an upload but failed to call `trigger_analysis_run` inline
    (register-poll, fetch-now, crashed mid-tick, etc.).

    Manual uploads (`source='manual'`) are excluded — those wait for the
    user's explicit "Run analysis" click.
    """
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(sa.text("""
            SELECT id FROM topology_config_uploads
            WHERE source = 'scheduler' AND run_id IS NULL
            ORDER BY uploaded_at
            LIMIT 50
        """))).fetchall()
        return [r.id for r in rows]


async def trigger_analysis_run(upload_ids: List[uuid.UUID], *,
                               reason: str) -> Optional[uuid.UUID]:
    """
    Create + execute a run for these uploads. Returns the run_id, or None
    if `upload_ids` is empty. Public so `devices.create_device` and
    `devices.fetch_now` can call it inline without waiting for the next
    scheduler tick.
    """
    if not upload_ids:
        return None
    orchestrator = RunOrchestrator()
    run_id = await orchestrator.create_run(
        upload_ids=upload_ids, triggered_by=reason,
    )
    # Auto-link uploads to their devices' last_run_id so the UI can show
    # "current run" per device.
    async with AsyncSessionLocal() as db:
        await db.execute(sa.text("""
            UPDATE topology_devices d SET last_run_id = :rid
            WHERE d.last_upload_id = ANY(:uids)
        """), {"rid": str(run_id), "uids": [str(u) for u in upload_ids]})
        await db.commit()
    asyncio.create_task(orchestrator.execute(run_id))
    log.info("triggered run %s (%s) for %d upload(s)",
             run_id, reason, len(upload_ids))
    return run_id
