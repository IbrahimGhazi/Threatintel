"""
Sandbox worker service.

Listens on NATS subject: ti.sandbox.submit
Message payload: {"result_id": "<uuid>", "sha256": "<hex>", "file_name": "<str>"}

Flow:
  1. Reads file from /sandbox-files/<sha256>
  2. Submits to configured engine (cape | virustotal | mock | local)
  3. Polls until complete (up to POLL_TIMEOUT_SECONDS)
  4. Updates sandbox_results row in PostgreSQL
  5. Re-ingests extracted IOCs into ti.indicators.ingest
"""
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import nats
import orjson
import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from engines.base import BaseSandboxEngine
from engines.cape import CapeEngine
from engines.mock import MockEngine
from engines.virustotal import VirusTotalEngine
from engines.local import LocalSandboxEngine
from engines.local.progress import ProgressEmitter

# ── Config ────────────────────────────────────────────────────────────────────
DATABASE_URL    = os.environ["DATABASE_URL"]
NATS_URL        = os.environ["NATS_URL"]
SANDBOX_ENGINE  = os.environ.get("SANDBOX_ENGINE", "mock").lower()
SANDBOX_URL     = os.environ.get("SANDBOX_URL", "http://localhost:8000")
VT_API_KEY      = os.environ.get("VIRUSTOTAL_API_KEY", "")  # env fallback; DB override resolved in main()
API_URL         = os.environ.get("API_URL", "http://api:8000")
API_KEY         = os.environ.get("API_KEY", "")
FILES_DIR       = os.environ.get("SANDBOX_FILES_DIR", "/sandbox-files")
POLL_INTERVAL         = int(os.environ.get("SANDBOX_POLL_INTERVAL", "15"))
POLL_TIMEOUT          = int(os.environ.get("SANDBOX_POLL_TIMEOUT", "600"))  # 10 min
PROGRESS_REDIS_URL    = os.environ.get("SANDBOX_PROGRESS_REDIS_URL") or os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(format="%(message)s", stream=sys.stderr, level=logging.INFO)
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
log = structlog.get_logger("sandbox")

# ── DB ────────────────────────────────────────────────────────────────────────
engine = create_async_engine(DATABASE_URL, pool_size=5, max_overflow=5)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

# ── Stage list (mirrors engines/local/progress.py) ────────────────────────────
# Used to build initial "queued" progress payloads for all engine types.
_STAGE_DEFS = [
    ("file_received",     "File Received"),
    ("queued",            "Queue Waiting"),
    ("static_analysis",   "Static Analysis"),
    ("sandbox_prep",      "Sandbox Preparation"),
    ("behavioral_exec",   "Behavioral Execution"),
    ("time_manipulation", "Time-Manipulation Tests"),
    ("ioc_extraction",    "IOC Extraction"),
    ("report_generation", "Report Generation"),
]

_PENDING_STAGES = [
    {"id": sid, "label": label, "status": "pending",
     "started_at": None, "duration_ms": None}
    for sid, label in _STAGE_DEFS
]


def _make_engine() -> BaseSandboxEngine:
    if SANDBOX_ENGINE == "cape":
        log.info("sandbox_engine", engine="cape", url=SANDBOX_URL)
        return CapeEngine(SANDBOX_URL)
    if SANDBOX_ENGINE == "virustotal":
        if not VT_API_KEY:
            raise ValueError("VIRUSTOTAL_API_KEY must be set when SANDBOX_ENGINE=virustotal")
        log.info("sandbox_engine", engine="virustotal")
        return VirusTotalEngine(VT_API_KEY)
    if SANDBOX_ENGINE == "local":
        log.info("sandbox_engine", engine="local")
        return LocalSandboxEngine()
    log.info("sandbox_engine", engine="mock")
    return MockEngine(api_url=API_URL, api_key=API_KEY)


async def _update_status(result_id: str, status: str, **kwargs):
    sets = ["status = :status", "started_at = COALESCE(started_at, NOW())"]
    params = {"status": status, "result_id": result_id}
    for k, v in kwargs.items():
        sets.append(f"{k} = :{k}")
        params[k] = v
    sql = f"UPDATE sandbox_results SET {', '.join(sets)} WHERE id = CAST(:result_id AS uuid)"
    async with SessionLocal() as db:
        await db.execute(text(sql), params)
        await db.commit()


async def _mark_completed(result_id: str, report):
    async with SessionLocal() as db:
        await db.execute(
            text("""
                UPDATE sandbox_results SET
                    status          = 'completed',
                    verdict         = :verdict,
                    malware_score   = :score,
                    malware_family  = :family,
                    sandbox_task_id = :task_id,
                    extracted_iocs  = CAST(:iocs AS jsonb),
                    report          = CAST(:report AS jsonb),
                    completed_at    = NOW()
                WHERE id = CAST(:result_id AS uuid)
            """),
            {
                "verdict":    report.verdict,
                "score":      report.malware_score,
                "family":     report.malware_family,
                "task_id":    report.task_id,
                "iocs":       orjson.dumps(report.extracted_iocs).decode(),
                "report":     orjson.dumps(report.report).decode(),
                "result_id":  result_id,
            },
        )
        await db.commit()


async def _push_progress(sha256: str, overall_status: str, error: str = "") -> None:
    """
    Write overall_status to Redis, preserving any stage data that the
    ProgressEmitter (local engine) has already written.
    Falls back to empty pending stages if no existing data is found.
    """
    now = datetime.now(timezone.utc).isoformat()
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(PROGRESS_REDIS_URL, decode_responses=True)

        # Read whatever the ProgressEmitter wrote so we don't overwrite stage data.
        existing_raw = await r.get(f"sandbox:progress:{sha256}")
        stages: list        = _PENDING_STAGES
        current_stage       = None
        completed_stages    = []

        if existing_raw:
            try:
                ex = json.loads(existing_raw)
                if ex.get("stages"):
                    stages           = ex["stages"]
                    current_stage    = ex.get("current_stage")
                    completed_stages = ex.get("completed_stages", [])
            except Exception:
                pass

        payload = json.dumps({
            "sha256":            sha256,
            "overall_status":    overall_status,
            "current_stage":     current_stage,
            "completed_stages":  completed_stages,
            "stages":            stages,
            "started_at":        now,
            "updated_at":        now,
            "error":             error,
        })
        await r.setex(f"sandbox:progress:{sha256}", 3600, payload)
        await r.aclose()
    except Exception as exc:
        log.warning("progress_redis_write_failed", sha256=sha256[:16], error=str(exc))


async def _mark_error(result_id: str, error: str):
    async with SessionLocal() as db:
        await db.execute(
            text("""
                UPDATE sandbox_results SET
                    status = 'failed', error = :error, completed_at = NOW()
                WHERE id = CAST(:result_id AS uuid)
            """),
            {"error": error[:1000], "result_id": result_id},
        )
        await db.commit()


async def _reingest_iocs(nc, iocs: dict, source_file: str):
    """Publish extracted IOCs back into the ingestion pipeline."""
    TYPE_MAP = [
        ("ips",     "ip"),
        ("domains", "domain"),
        ("urls",    "url"),
        ("hashes",  "sha256"),
    ]
    published = 0
    for key, ioc_type in TYPE_MAP:
        for value in iocs.get(key, []):
            if not value:
                continue
            payload = {
                "type":       ioc_type,
                "value":      value,
                "source":     "sandbox",
                "confidence": 90,
                "tags":       ["sandbox", "extracted-ioc", f"source:{source_file}"],
            }
            try:
                await nc.publish("ti.indicators.ingest", orjson.dumps(payload))
                published += 1
            except Exception as e:
                log.warning("ioc_publish_failed", value=value, error=str(e))
    if published:
        log.info("iocs_reingested", count=published)


async def _process(nc, sandbox_engine: BaseSandboxEngine, result_id: str, sha256: str, file_name: str):
    log = structlog.get_logger("sandbox").bind(result_id=result_id, sha256=sha256[:16])
    file_path = os.path.join(FILES_DIR, sha256)
    loop = asyncio.get_event_loop()

    # For non-local engines (mock, cape, virustotal) there is no ProgressEmitter
    # running inside the engine, so _process() drives the stage updates itself.
    # The local engine creates its own ProgressEmitter in submit() and handles all
    # stage transitions internally — we do NOT create a second one here.
    use_own_progress = SANDBOX_ENGINE != "local"
    progress: Optional[ProgressEmitter] = (
        ProgressEmitter(sha256) if use_own_progress else None
    )

    if not os.path.exists(file_path):
        err = f"File not found at {file_path}"
        log.error("file_missing", path=file_path)
        await _mark_error(result_id, err)
        if progress:
            await loop.run_in_executor(None, progress.mark_failed, err)
        else:
            await _push_progress(sha256, "failed", error=err)
        return

    await _update_status(result_id, "running")

    # ── Submission ──────────────────────────────────────────────────────────
    try:
        if progress:
            await loop.run_in_executor(None, progress.mark_done, "file_received")
            await loop.run_in_executor(None, progress.mark_running, "queued")

        task_id = await sandbox_engine.submit(file_path, file_name, sha256)
        log.info("submitted", task_id=task_id)

        if progress:
            await loop.run_in_executor(None, progress.mark_done, "queued")
            await loop.run_in_executor(None, progress.mark_running, "static_analysis")

        await _update_status(result_id, "running", sandbox_task_id=task_id)

    except Exception as e:
        log.error("submit_failed", error=str(e))
        err = f"Submit failed: {e}"
        await _mark_error(result_id, err)
        if progress:
            await loop.run_in_executor(None, progress.mark_failed, err)
        else:
            await _push_progress(sha256, "failed", error=err)
        return

    # ── Poll loop ───────────────────────────────────────────────────────────
    deadline   = asyncio.get_event_loop().time() + POLL_TIMEOUT
    poll_count = 0

    while True:
        if asyncio.get_event_loop().time() > deadline:
            err = "Timed out waiting for sandbox result"
            await _mark_error(result_id, err)
            if progress:
                await loop.run_in_executor(None, progress.mark_failed, err)
            else:
                await _push_progress(sha256, "failed", error=err)
            log.warning("poll_timeout")
            return

        await asyncio.sleep(POLL_INTERVAL)
        poll_count += 1

        # Advance stage indicators for non-local engines so the UI shows progress
        # rather than staying on "static_analysis" for the entire poll window.
        if progress:
            if poll_count == 1:
                # First poll: static analysis done, move to behavioral simulation.
                await loop.run_in_executor(None, progress.mark_done, "static_analysis")
                await loop.run_in_executor(None, progress.mark_running, "sandbox_prep")
            elif poll_count == 2:
                await loop.run_in_executor(None, progress.mark_done, "sandbox_prep")
                await loop.run_in_executor(None, progress.mark_running, "behavioral_exec")
            elif poll_count == 3:
                await loop.run_in_executor(None, progress.mark_done, "behavioral_exec")
                await loop.run_in_executor(None, progress.mark_skipped, "time_manipulation")
                await loop.run_in_executor(None, progress.mark_running, "ioc_extraction")
            elif poll_count >= 4:
                await loop.run_in_executor(None, progress.mark_done, "ioc_extraction")
                await loop.run_in_executor(None, progress.mark_running, "report_generation")

        try:
            report = await sandbox_engine.poll(task_id)
        except RuntimeError as e:
            log.error("poll_error", error=str(e))
            err = str(e)
            await _mark_error(result_id, err)
            if progress:
                await loop.run_in_executor(None, progress.mark_failed, err)
            else:
                await _push_progress(sha256, "failed", error=err)
            return
        except Exception as e:
            log.warning("poll_exception", error=str(e))
            continue  # transient error, keep polling

        if report is None:
            log.debug("still_pending", task_id=task_id)
            continue

        # ── Completed ───────────────────────────────────────────────────────
        await _mark_completed(result_id, report)

        if progress:
            # Non-local engine: mark all remaining stages complete and signal done.
            await loop.run_in_executor(None, progress.mark_complete)
        else:
            # Local engine: ProgressEmitter already wrote the terminal state;
            # _push_progress will preserve those stages.
            await _push_progress(sha256, "completed")

        log.info("completed",
                 verdict=report.verdict,
                 score=report.malware_score,
                 family=report.malware_family)

        # Re-ingest extracted IOCs
        total_iocs = sum(len(v) for v in report.extracted_iocs.values())
        if total_iocs > 0:
            await _reingest_iocs(nc, report.extracted_iocs, file_name or sha256)

        return


async def _resolve_vt_key_from_db() -> str:
    """
    BYO API key resolution: DB-first, env-fallback.

    Reads ``platform_settings.api_key.virustotal`` and decrypts if encrypted.
    Returns "" on any failure so we transparently fall back to the env-var
    that was already captured in module-global ``VT_API_KEY`` at import time.
    """
    if not DATABASE_URL:
        return ""
    try:
        import asyncpg
        from _crypto import decrypt as _decrypt
        dsn = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
        conn = await asyncpg.connect(dsn, timeout=10)
        try:
            row = await conn.fetchrow(
                """SELECT value, value_encrypted FROM platform_settings
                    WHERE key = 'api_key.virustotal'"""
            )
        finally:
            await conn.close()
        if not row or not row["value"]:
            return ""
        return _decrypt(row["value"]) if row["value_encrypted"] else row["value"]
    except Exception as exc:
        log.warning("vt_key_db_lookup_failed", error=str(exc))
        return ""


async def main():
    global VT_API_KEY
    log.info("sandbox_worker_starting", engine=SANDBOX_ENGINE)

    # BYO override: DB value wins, env keeps working as fallback.
    db_vt = await _resolve_vt_key_from_db()
    if db_vt:
        VT_API_KEY = db_vt
        log.info("vt_key_source", source="db")
    elif VT_API_KEY:
        log.info("vt_key_source", source="env")
    else:
        log.info("vt_key_source", source="none")

    sandbox_engine = _make_engine()

    nc = await nats.connect(NATS_URL)
    log.info("nats_connected", url=NATS_URL)

    active: set = set()

    async def handler(msg):
        try:
            data = orjson.loads(msg.data)
            result_id = data["result_id"]
            sha256    = data["sha256"]
            file_name = data.get("file_name", "")
        except Exception as e:
            log.error("bad_message", error=str(e), raw=msg.data[:200])
            return

        if result_id in active:
            log.debug("already_processing", result_id=result_id)
            return

        active.add(result_id)
        try:
            await _process(nc, sandbox_engine, result_id, sha256, file_name)
        finally:
            active.discard(result_id)

    sub = await nc.subscribe("ti.sandbox.submit", cb=handler)
    log.info("subscribed", subject="ti.sandbox.submit")

    try:
        while True:
            await asyncio.sleep(1)
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await sub.unsubscribe()
        await nc.drain()
        log.info("sandbox_worker_stopped")


if __name__ == "__main__":
    asyncio.run(main())
