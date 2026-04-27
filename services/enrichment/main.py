"""
Enrichment service entry point.

Subscribes to NATS for new indicator events and enriches them
asynchronously using pluggable enrichment modules.
"""
import asyncio
import logging
import os
import sys

import nats
import orjson
import redis.asyncio as aioredis

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "service": "enrichment", "message": "%(message)s"}',
    stream=sys.stdout,
)
logger = logging.getLogger("enrichment")

NATS_URL     = os.getenv("NATS_URL", "nats://localhost:4222")
REDIS_URL    = os.getenv("REDIS_URL", "redis://localhost:6379/2")
DATABASE_URL = os.getenv("DATABASE_URL", "")
WORKERS      = int(os.getenv("ENRICHMENT_WORKERS", "4"))

# ── Database helpers ──────────────────────────────────────────

async def update_enrichment(db_url: str, indicator_id: str, enrichment: dict) -> None:
    """Update the enrichment JSONB field for an indicator."""
    import asyncpg
    conn = await asyncpg.connect(db_url.replace("+asyncpg", ""))
    try:
        await conn.execute(
            """
            UPDATE indicators
            SET enrichment = enrichment || $1::jsonb,
                updated_at = NOW()
            WHERE id = $2
            """,
            orjson.dumps(enrichment).decode(),
            indicator_id,
        )
    finally:
        await conn.close()


# ── Enrichment pipeline ───────────────────────────────────────

async def build_enrichers(redis_client):
    """Instantiate all available enrichment modules."""
    from modules.geoip import GeoIPEnricher
    from modules.rdns import ReverseDNSEnricher
    from modules.asn import ASNEnricher
    from modules.whois_lookup import WHOISEnricher

    enrichers = [
        GeoIPEnricher(redis_client),
        ASNEnricher(redis_client),
        ReverseDNSEnricher(redis_client),
        WHOISEnricher(redis_client),
    ]
    logger.info("Loaded %d enrichment modules", len(enrichers))
    return enrichers


async def enrich_indicator(enrichers, data: dict) -> dict:
    """Run all applicable enrichment modules and merge results."""
    itype  = data.get("type", "")
    value  = data.get("value", "")

    merged = {}
    for enricher in enrichers:
        if not enricher.supports(itype):
            continue
        result = await enricher.enrich(itype, value)
        if result:
            merged[enricher.name] = result

    return merged


# ── Semaphore-limited message handler ────────────────────────

async def process_message(msg, enrichers, db_url: str, sem: asyncio.Semaphore):
    async with sem:
        try:
            data = orjson.loads(msg.data)
        except Exception:
            return

        indicator_id = data.get("id")
        itype        = data.get("type", "")
        value        = data.get("value", "")

        if not indicator_id or not itype or not value:
            return

        enrichment = await enrich_indicator(enrichers, data)
        if enrichment and db_url:
            try:
                await update_enrichment(db_url, indicator_id, enrichment)
                logger.debug("Enriched %s %s: modules=%s", itype, value[:50], list(enrichment.keys()))
            except Exception as exc:
                logger.error("DB update failed for %s: %s", indicator_id, exc)


async def main():
    # Redis connection
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=False)

    # NATS connection
    nc = None
    while True:
        try:
            nc = await nats.connect(
                NATS_URL,
                name="ti-enrichment",
                reconnect_time_wait=5,
                max_reconnect_attempts=-1,
            )
            logger.info("Connected to NATS")
            break
        except Exception as exc:
            logger.warning("NATS connection failed, retrying: %s", exc)
            await asyncio.sleep(5)

    enrichers = await build_enrichers(redis_client)
    sem = asyncio.Semaphore(WORKERS)

    # Subscribe to new indicator events published by the API service
    async def handler(msg):
        asyncio.create_task(process_message(msg, enrichers, DATABASE_URL, sem))

    await nc.subscribe("ti.indicators.new", cb=handler)
    logger.info("Subscribed to ti.indicators.new (workers=%d)", WORKERS)

    try:
        while True:
            await asyncio.sleep(60)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down enrichment service")
        await nc.drain()
        await redis_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
