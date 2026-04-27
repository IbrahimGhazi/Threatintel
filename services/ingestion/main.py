"""
Ingestion service entry point.

Runs all configured feed workers on a schedule using APScheduler.
Workers publish normalized indicators to NATS subject: ti.indicators.ingest

The API service subscribes to that subject and persists indicators.
"""
import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from typing import List

import asyncpg
import nats
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "service": "ingestion", "message": "%(message)s"}',
    stream=sys.stdout,
)
logger = logging.getLogger("ingestion")

# ── Environment configuration ─────────────────────────────────

NATS_URL         = os.getenv("NATS_URL", "nats://localhost:4222")
DATABASE_URL     = os.getenv("DATABASE_URL", "")
FEED_INTERVAL    = int(os.getenv("FEED_POLL_INTERVAL", "3600"))

# Feed enables (UI-overridable in a future milestone; env-driven for now).
URLHAUS_ENABLED  = os.getenv("URLHAUS_ENABLED", "true").lower() == "true"
THREATFOX_ENABLED = os.getenv("THREATFOX_ENABLED", "true").lower() == "true"
BAZAAR_ENABLED   = os.getenv("MALWAREBAZAAR_ENABLED", "true").lower() == "true"
OPENPHISH_ENABLED = os.getenv("OPENPHISH_ENABLED", "true").lower() == "true"

# API keys are resolved at startup via _resolve_keys() — DB-first, env-fallback.
# See services/api/app/routers/api_keys.py for the management endpoints.
ABUSEIPDB_KEY    = ""
OTX_KEY          = ""
THREATFOX_KEY    = ""
MALWAREBAZAAR_KEY = ""


# ── BYO API key resolution (DB → env → "") ────────────────────

# Mapping: provider_id → env var fallback
_KEY_PROVIDERS = {
    "abuseipdb":     "ABUSEIPDB_API_KEY",
    "otx":           "OTX_API_KEY",
    "threatfox":     "THREATFOX_API_KEY",
    "malwarebazaar": "MALWAREBAZAAR_API_KEY",
}


async def _resolve_keys() -> dict:
    """
    Returns ``{provider_id: plaintext_key}`` for each known provider.

    Resolution order per provider:
      1. ``platform_settings.value`` decrypted if ``value_encrypted=TRUE``
      2. env var (legacy ``.env`` behaviour)
      3. empty string  →  worker for that provider is skipped
    """
    from _crypto import decrypt as _decrypt

    out = {pid: "" for pid in _KEY_PROVIDERS}

    # Try DB first; if anything goes wrong, fall through to env-only.
    if DATABASE_URL:
        dsn = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
        try:
            conn = await asyncpg.connect(dsn, timeout=10)
            try:
                rows = await conn.fetch(
                    """SELECT key, value, value_encrypted
                         FROM platform_settings
                        WHERE key LIKE 'api_key.%'"""
                )
                for r in rows:
                    pid = r["key"].split("api_key.", 1)[1]
                    if pid not in _KEY_PROVIDERS:
                        continue
                    raw = r["value"] or ""
                    if not raw:
                        continue
                    try:
                        out[pid] = _decrypt(raw) if r["value_encrypted"] else raw
                    except Exception as exc:
                        logger.warning("Cannot decrypt api_key.%s: %s", pid, exc)
            finally:
                await conn.close()
        except Exception as exc:
            logger.warning("Could not load api keys from DB: %s — using env fallback", exc)

    # Env fallback for any still-empty providers
    for pid, env_var in _KEY_PROVIDERS.items():
        if not out[pid]:
            out[pid] = os.getenv(env_var, "").strip()

    # Log status without leaking values
    summary = {pid: ("set" if v else "empty") for pid, v in out.items()}
    logger.info("API key resolution complete: %s", summary)
    return out


# ── Global NATS client ────────────────────────────────────────

nc: nats.aio.client.Client = None


async def connect_nats():
    global nc
    nc = await nats.connect(
        NATS_URL,
        name="ti-ingestion",
        reconnect_time_wait=5,
        max_reconnect_attempts=-1,  # retry forever
    )
    logger.info("Connected to NATS at %s", NATS_URL)
    return nc


def build_workers(nc) -> List:
    """Instantiate all enabled feed workers."""
    from workers.urlhaus import URLHausWorker
    from workers.threatfox import ThreatFoxWorker
    from workers.malwarebazaar import MalwareBazaarWorker
    from workers.openphish import OpenPhishWorker
    from workers.abuseipdb import AbuseIPDBWorker
    from workers.otx import OTXWorker

    workers = []

    if URLHAUS_ENABLED:
        workers.append(URLHausWorker(nc))
    if THREATFOX_ENABLED:
        workers.append(ThreatFoxWorker(nc, THREATFOX_KEY))
    if BAZAAR_ENABLED:
        workers.append(MalwareBazaarWorker(nc, MALWAREBAZAAR_KEY))
    if OPENPHISH_ENABLED:
        workers.append(OpenPhishWorker(nc))
    if ABUSEIPDB_KEY:
        workers.append(AbuseIPDBWorker(nc, ABUSEIPDB_KEY))
    if OTX_KEY:
        workers.append(OTXWorker(nc, OTX_KEY))

    logger.info("Initialized %d feed workers: %s", len(workers), [w.name for w in workers])
    return workers


async def _update_feed_status(worker_name: str, count: int, error: str = None):
    """Write last_run_at / total_ingested back to the feeds table."""
    if not DATABASE_URL:
        return
    # asyncpg uses postgresql:// not postgresql+asyncpg://
    dsn = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    try:
        conn = await asyncpg.connect(dsn)
        now = datetime.now(timezone.utc)
        if error:
            await conn.execute(
                """UPDATE feeds SET last_run_at=$1, last_error=$2, last_error_at=$1, updated_at=$1
                   WHERE name=$3""",
                now, error[:500], worker_name,
            )
        else:
            await conn.execute(
                """UPDATE feeds SET last_run_at=$1, last_success_at=$1, last_error=NULL,
                       total_ingested=total_ingested+$2, updated_at=$1
                   WHERE name=$3""",
                now, count, worker_name,
            )
        await conn.close()
    except Exception as exc:
        logger.warning("Could not update feed status for %s: %s", worker_name, exc)


async def run_worker(worker) -> None:
    """Run a single worker cycle, catching all exceptions."""
    try:
        count = await worker.run()
        logger.info("Worker %s completed: %d indicators published", worker.name, count)
        await _update_feed_status(worker.name, count)
    except Exception as exc:
        logger.error("Worker %s failed: %s", worker.name, exc, exc_info=True)
        await _update_feed_status(worker.name, 0, error=str(exc))


async def main():
    global nc, ABUSEIPDB_KEY, OTX_KEY, THREATFOX_KEY, MALWAREBAZAAR_KEY

    # Resolve BYO API keys: DB-first, env-fallback. Done before NATS connect
    # so a slow DB doesn't gate NATS, but failures here are non-fatal — empty
    # keys just mean the matching workers are skipped in build_workers().
    keys = await _resolve_keys()
    ABUSEIPDB_KEY    = keys.get("abuseipdb", "")
    OTX_KEY          = keys.get("otx", "")
    THREATFOX_KEY    = keys.get("threatfox", "")
    MALWAREBAZAAR_KEY = keys.get("malwarebazaar", "")

    # Connect to NATS (with retry)
    while True:
        try:
            await connect_nats()
            break
        except Exception as exc:
            logger.warning("NATS connection failed, retrying in 5s: %s", exc)
            await asyncio.sleep(5)

    workers = build_workers(nc)

    if not workers:
        logger.warning("No workers configured. Set feed env vars and restart.")

    scheduler = AsyncIOScheduler()

    # Schedule each worker with a staggered start to avoid thundering herd
    for i, worker in enumerate(workers):
        # Initial run staggered by 10s per worker
        delay_seconds = i * 10

        scheduler.add_job(
            run_worker,
            "interval",
            args=[worker],
            seconds=FEED_INTERVAL,
            id=f"worker_{worker.name}",
            next_run_time=__import__("datetime").datetime.now() +
                          __import__("datetime").timedelta(seconds=delay_seconds),
        )

    scheduler.start()
    logger.info("Scheduler started. Feed interval: %ds", FEED_INTERVAL)

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down ingestion service")
        scheduler.shutdown(wait=False)
        if nc:
            await nc.drain()


if __name__ == "__main__":
    asyncio.run(main())
