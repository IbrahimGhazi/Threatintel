"""
WHOIS enrichment for IP addresses and domains.
"""
import asyncio
from typing import Any, Dict

from modules.base import BaseEnricher


class WHOISEnricher(BaseEnricher):
    name = "whois"
    supported_types = ["ip", "domain"]
    cache_ttl = 86400 * 3  # 3 days

    async def _enrich(self, indicator_type: str, value: str) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        try:
            import whois
            data = await loop.run_in_executor(None, lambda: whois.whois(value))
            if not data:
                return {}

            result = {}
            if data.get("registrar"):
                result["registrar"] = str(data["registrar"])
            if data.get("creation_date"):
                cd = data["creation_date"]
                if isinstance(cd, list):
                    cd = cd[0]
                result["creation_date"] = cd.isoformat() if hasattr(cd, "isoformat") else str(cd)
            if data.get("expiration_date"):
                ed = data["expiration_date"]
                if isinstance(ed, list):
                    ed = ed[0]
                result["expiration_date"] = ed.isoformat() if hasattr(ed, "isoformat") else str(ed)
            if data.get("name_servers"):
                ns = data["name_servers"]
                result["name_servers"] = list(ns) if isinstance(ns, (list, set)) else [str(ns)]
            if data.get("org"):
                result["org"] = str(data["org"])
            if data.get("country"):
                result["country"] = str(data["country"])

            return result
        except Exception:
            return {}
