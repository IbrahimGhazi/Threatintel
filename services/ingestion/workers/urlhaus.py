"""
URLHaus feed worker – abuse.ch malicious URL database.
Public CSV feed, no API key required.
Documentation: https://urlhaus.abuse.ch/api/
"""
import csv
import io
import logging
from typing import Any, Dict, List

from workers.base import BaseWorker

logger = logging.getLogger(__name__)

FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Map URLHaus tags to platform tags
TAG_MAP = {
    "malware_download": ["malware", "downloader"],
    "botnet_cc": ["botnet", "c2"],
    "exe": ["executable"],
    "doc": ["document"],
    "js": ["javascript"],
    "zip": ["archive"],
}


class URLHausWorker(BaseWorker):
    name = "urlhaus"
    display_name = "URLHaus"
    default_confidence = 75  # Well-curated feed

    async def fetch_and_parse(self) -> List[Dict[str, Any]]:
        resp = await self.http.get(FEED_URL)
        resp.raise_for_status()

        indicators = []
        content = resp.text

        # URLHaus CSV starts with comment lines prefixed with #
        lines = [line for line in content.splitlines() if not line.startswith("#")]
        reader = csv.DictReader(
            io.StringIO("\n".join(lines)),
            fieldnames=["id", "dateadded", "url", "url_status", "last_online",
                        "threat", "tags", "urlhaus_link", "reporter"],
        )

        for row in reader:
            url = row.get("url", "").strip()
            if not url:
                continue

            status = row.get("url_status", "").strip().lower()
            # Skip already offline URLs (still worth storing but deprioritize)
            if status == "offline":
                confidence = 50
            else:
                confidence = 80

            # Build tags from URLHaus threat field and tags column
            tags = ["urlhaus"]
            threat = row.get("threat", "").strip().lower()
            if threat:
                tags.append(threat.replace(" ", "_"))

            raw_tags = row.get("tags", "").strip()
            if raw_tags:
                for t in raw_tags.split(","):
                    t = t.strip().lower()
                    if t:
                        tags.extend(TAG_MAP.get(t, [t]))

            indicators.append({
                "type": "url",
                "value": url,
                "confidence": confidence,
                "tags": list(set(tags)),
                "raw_data": {
                    "source": "urlhaus",
                    "threat": threat,
                    "status": status,
                    "urlhaus_id": row.get("id", ""),
                    "reporter": row.get("reporter", ""),
                },
            })

        logger.info("[urlhaus] Parsed %d URLs", len(indicators))
        return indicators
