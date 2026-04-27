"""
AbuseIPDB worker – blacklisted IP database.
Requires a free API key from https://www.abuseipdb.com/api
"""
import logging
import os
from typing import Any, Dict, List

from workers.base import BaseWorker

logger = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/blacklist"


class AbuseIPDBWorker(BaseWorker):
    name = "abuseipdb"
    display_name = "AbuseIPDB"
    default_confidence = 70

    def __init__(self, nats_client, api_key: str):
        super().__init__(nats_client)
        self.api_key = api_key

    async def fetch_and_parse(self) -> List[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("[abuseipdb] No API key configured, skipping")
            return []

        params = {
            "confidenceMinimum": "75",
            "limit": "10000",
        }
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        resp = await self.http.get(API_URL, params=params, headers=headers)
        resp.raise_for_status()

        data = resp.json()
        entries = data.get("data", [])

        indicators = []
        for entry in entries:
            ip = entry.get("ipAddress", "").strip()
            if not ip:
                continue

            # Map AbuseIPDB confidence (0-100) to our scale
            abuse_score = int(entry.get("abuseConfidenceScore", 50))

            tags = ["abuseipdb"]
            country = entry.get("countryCode", "")
            if country:
                tags.append(f"country:{country.lower()}")

            isp = entry.get("isp", "")

            indicators.append({
                "type": "ip",
                "value": ip,
                "confidence": abuse_score,
                "tags": list(set(tags)),
                "raw_data": {
                    "source": "abuseipdb",
                    "abuse_score": abuse_score,
                    "country_code": country,
                    "isp": isp,
                    "total_reports": entry.get("totalReports", 0),
                    "num_distinct_users": entry.get("numDistinctUsers", 0),
                    "last_reported": entry.get("lastReportedAt", ""),
                },
            })

        logger.info("[abuseipdb] Parsed %d IPs", len(indicators))
        return indicators
