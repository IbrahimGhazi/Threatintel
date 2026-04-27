"""
OpenPhish worker – phishing URL feed.
Public feed, no API key required.
"""
import logging
from typing import Any, Dict, List

from workers.base import BaseWorker

logger = logging.getLogger(__name__)

FEED_URL = "https://openphish.com/feed.txt"


class OpenPhishWorker(BaseWorker):
    name = "openphish"
    display_name = "OpenPhish"
    default_confidence = 80

    async def fetch_and_parse(self) -> List[Dict[str, Any]]:
        resp = await self.http.get(FEED_URL)
        resp.raise_for_status()

        indicators = []
        for line in resp.text.splitlines():
            url = line.strip()
            if not url or url.startswith("#"):
                continue

            indicators.append({
                "type": "url",
                "value": url,
                "confidence": self.default_confidence,
                "tags": ["openphish", "phishing"],
                "raw_data": {"source": "openphish"},
            })

        logger.info("[openphish] Parsed %d phishing URLs", len(indicators))
        return indicators
