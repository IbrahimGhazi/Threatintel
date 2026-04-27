"""
AlienVault OTX worker – Open Threat Exchange.
Requires a free API key from https://otx.alienvault.com
Fetches subscribed pulse indicators from the last 24h.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from workers.base import BaseWorker

logger = logging.getLogger(__name__)

API_BASE = "https://otx.alienvault.com/api/v1"

# Map OTX indicator types to platform types
OTX_TYPE_MAP = {
    "IPv4":       "ip",
    "IPv6":       "ip",
    "domain":     "domain",
    "hostname":   "domain",
    "URL":        "url",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
    "email":      "email",
}


class OTXWorker(BaseWorker):
    name = "otx"
    display_name = "AlienVault OTX"
    default_confidence = 65

    def __init__(self, nats_client, api_key: str):
        super().__init__(nats_client)
        self.api_key = api_key

    async def fetch_and_parse(self) -> List[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("[otx] No API key configured, skipping")
            return []

        headers = {"X-OTX-API-KEY": self.api_key}
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")

        # Fetch subscribed pulses modified in last 24h
        url = f"{API_BASE}/pulses/subscribed"
        params = {"modified_since": since, "limit": 100}

        indicators = []
        page_url = url

        while page_url:
            resp = await self.http.get(page_url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()

            for pulse in data.get("results", []):
                pulse_tags = [t.lower() for t in pulse.get("tags", [])]
                malware_families = []
                for mf in pulse.get("malware_families", []):
                    name = mf.get("display_name", "") if isinstance(mf, dict) else str(mf)
                    if name:
                        malware_families.append(name.lower().replace(" ", "_"))

                for ioc in pulse.get("indicators", []):
                    raw_type = ioc.get("type", "")
                    platform_type = OTX_TYPE_MAP.get(raw_type)
                    if not platform_type:
                        continue

                    value = ioc.get("indicator", "").strip()
                    if not value:
                        continue

                    tags = ["otx"] + pulse_tags + malware_families
                    tags = [t for t in set(tags) if t]

                    indicators.append({
                        "type": platform_type,
                        "value": value,
                        "confidence": self.default_confidence,
                        "tags": tags,
                        "raw_data": {
                            "source": "otx",
                            "pulse_id": pulse.get("id"),
                            "pulse_name": pulse.get("name", ""),
                            "pulse_author": pulse.get("author_name", ""),
                            "otx_type": raw_type,
                        },
                    })

            # Pagination
            next_url = data.get("next")
            page_url = next_url if next_url else None
            params = {}  # params embedded in next URL

        logger.info("[otx] Parsed %d indicators from OTX pulses", len(indicators))
        return indicators
