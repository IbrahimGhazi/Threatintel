"""
Base class for all feed ingestion workers.

Each worker:
  1. Fetches raw data from the feed source
  2. Parses and normalizes indicators
  3. Publishes normalized indicators to NATS

Workers must override `fetch_and_parse()` to return a list of indicator dicts.
"""
import asyncio
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx
import nats
import orjson

from normalizer import normalize

logger = logging.getLogger(__name__)

# Shared indicator schema published to NATS
# Subject: ti.indicators.ingest
INDICATOR_SCHEMA = {
    "type":            str,   # ip, domain, url, md5, sha256, ...
    "value":           str,   # raw value from feed
    "source_name":     str,   # feed identifier
    "source_category": str,   # open_source, commercial, internal
    "confidence":      int,   # 0-100
    "tags":            list,  # list of strings
    "raw_data":        dict,  # original feed record
}


class BaseWorker(ABC):
    """Abstract base class for all threat feed workers."""

    name: str = "unnamed"
    display_name: str = "Unnamed Feed"
    source_category: str = "open_source"
    default_confidence: int = 60
    request_timeout: int = 30

    def __init__(self, nats_client: nats.aio.client.Client):
        self.nc = nats_client
        self._http: Optional[httpx.AsyncClient] = None

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                timeout=self.request_timeout,
                follow_redirects=True,
                headers={
                    "User-Agent": "TI-Platform/1.0 (+https://github.com/ti-platform)",
                },
            )
        return self._http

    @abstractmethod
    async def fetch_and_parse(self) -> List[Dict[str, Any]]:
        """
        Fetch data from the feed source and return a list of indicator dicts.
        Each dict must contain at minimum: type, value.
        """
        ...

    async def run(self) -> int:
        """
        Execute one ingestion cycle.
        Returns the number of indicators successfully published.
        """
        start = time.monotonic()
        logger.info("[%s] Starting ingestion cycle", self.name)

        try:
            raw_indicators = await self.fetch_and_parse()
        except httpx.TimeoutException:
            logger.error("[%s] Request timed out", self.name)
            return 0
        except httpx.HTTPStatusError as exc:
            logger.error("[%s] HTTP error %d: %s", self.name, exc.response.status_code, exc)
            return 0
        except Exception as exc:
            logger.error("[%s] Unexpected error during fetch: %s", self.name, exc, exc_info=True)
            return 0

        published = 0
        skipped = 0

        for raw in raw_indicators:
            itype = raw.get("type", "")
            value = raw.get("value", "")

            normalized = normalize(itype, value)
            if not normalized:
                skipped += 1
                continue

            indicator = {
                "type":            itype,
                "value":           value,
                "normalized_value": normalized,
                "source_name":     raw.get("source_name", self.name),
                "source_category": raw.get("source_category", self.source_category),
                "confidence":      raw.get("confidence", self.default_confidence),
                "tags":            raw.get("tags", []),
                "raw_data":        raw.get("raw_data", {}),
            }

            try:
                await self.nc.publish(
                    "ti.indicators.ingest",
                    orjson.dumps(indicator),
                )
                published += 1
            except Exception as exc:
                logger.error("[%s] NATS publish failed: %s", self.name, exc)

        elapsed = time.monotonic() - start
        logger.info(
            "[%s] Cycle complete: published=%d skipped=%d elapsed=%.1fs",
            self.name, published, skipped, elapsed,
        )
        return published

    async def close(self):
        if self._http and not self._http.is_closed:
            await self._http.aclose()
