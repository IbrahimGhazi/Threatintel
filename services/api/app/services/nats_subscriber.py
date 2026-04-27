"""
NATS subscriber that consumes indicator events published by the ingestion workers
and persists them to PostgreSQL.

Run this as a background task from the API startup (or as its own process).
"""
import asyncio
import logging
from typing import Optional

import nats
import orjson

from app.database import get_db_context
from app.services.indicator_service import upsert_indicator

logger = logging.getLogger(__name__)


async def handle_indicator_message(msg) -> None:
    """Process a single indicator message from NATS."""
    try:
        data = orjson.loads(msg.data)
    except Exception as exc:
        logger.error("Failed to decode NATS message: %s", exc)
        return

    itype  = data.get("type", "")
    value  = data.get("value", "")
    source = data.get("source_name", "unknown")

    if not itype or not value:
        logger.warning("Received incomplete indicator message: %s", data)
        return

    try:
        async with get_db_context() as db:
            indicator, created = await upsert_indicator(
                db,
                itype=itype,
                value=value,
                source_name=source,
                source_category=data.get("source_category", "open_source"),
                confidence=int(data.get("confidence", 50)),
                tags=data.get("tags", []),
                raw_data=data.get("raw_data", {}),
            )
            if created:
                logger.debug("New indicator: type=%s value=%s source=%s", itype, value[:60], source)
    except Exception as exc:
        logger.error(
            "Failed to persist indicator type=%s value=%s: %s",
            itype, value[:60], exc, exc_info=True,
        )


async def start_indicator_subscriber(nc: nats.aio.client.Client) -> Optional[nats.aio.client.Subscription]:
    """Subscribe to the indicator ingest subject on NATS JetStream."""
    try:
        sub = await nc.subscribe("ti.indicators.ingest", cb=handle_indicator_message)
        logger.info("Subscribed to ti.indicators.ingest")
        return sub
    except Exception as exc:
        logger.error("Failed to subscribe to NATS: %s", exc)
        return None
