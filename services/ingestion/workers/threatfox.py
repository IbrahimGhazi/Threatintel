"""
ThreatFox worker – abuse.ch multi-type IOC database.
Public API, no key required for basic access.
Documentation: https://threatfox.abuse.ch/api/
"""
import logging
from typing import Any, Dict, List

from workers.base import BaseWorker

logger = logging.getLogger(__name__)

API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Map ThreatFox IOC types to platform types
IOC_TYPE_MAP = {
    "ip:port":    "ip",
    "domain":     "domain",
    "url":        "url",
    "md5_hash":   "md5",
    "sha256_hash": "sha256",
}


class ThreatFoxWorker(BaseWorker):
    name = "threatfox"
    display_name = "ThreatFox"
    default_confidence = 70

    def __init__(self, nats_client, api_key: str = ""):
        super().__init__(nats_client)
        self.api_key = api_key

    async def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {"Auth-Key": self.api_key} if self.api_key else {}
        # Query recent IOCs (last 24h)
        payload = {"query": "get_iocs", "days": 1}
        resp = await self.http.post(API_URL, json=payload, headers=headers)
        resp.raise_for_status()

        data = resp.json()
        if data.get("query_status") != "ok":
            logger.error("[threatfox] API error: %s", data.get("query_status"))
            return []

        indicators = []
        for ioc in data.get("data", []) or []:
            raw_type = ioc.get("ioc_type", "")
            platform_type = IOC_TYPE_MAP.get(raw_type)
            if not platform_type:
                continue

            value = ioc.get("ioc", "").strip()
            if not value:
                continue

            # For ip:port, extract just the IP
            if raw_type == "ip:port" and ":" in value:
                value = value.split(":")[0]

            # Confidence from ThreatFox confidence level (1-100)
            tf_confidence = int(ioc.get("confidence_level", 50))

            tags = ["threatfox"]
            malware_family = ioc.get("malware", "")
            if malware_family:
                tags.append(malware_family.lower().replace(" ", "_"))

            threat_type = ioc.get("threat_type", "")
            if threat_type:
                tags.append(threat_type.lower())

            indicators.append({
                "type": platform_type,
                "value": value,
                "confidence": tf_confidence,
                "tags": list(set(tags)),
                "raw_data": {
                    "source": "threatfox",
                    "ioc_id": ioc.get("id"),
                    "malware": malware_family,
                    "threat_type": threat_type,
                    "reporter": ioc.get("reporter", ""),
                    "first_seen": ioc.get("first_seen", ""),
                },
            })

        logger.info("[threatfox] Parsed %d IOCs", len(indicators))
        return indicators
