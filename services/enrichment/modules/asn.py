"""
ASN enrichment using MaxMind GeoLite2-ASN database.

Requires GeoLite2-ASN.mmdb at $GEOIP_ASN_DB_PATH.
"""
import os
from typing import Any, Dict

from modules.base import BaseEnricher


class ASNEnricher(BaseEnricher):
    name = "asn"
    supported_types = ["ip"]
    cache_ttl = 86400  # 24 hours

    def __init__(self, redis_client=None):
        super().__init__(redis_client)
        self._reader = None
        self._db_path = os.getenv("GEOIP_ASN_DB_PATH", "/geoip/GeoLite2-ASN.mmdb")

    def _get_reader(self):
        if self._reader is None:
            import geoip2.database
            self._reader = geoip2.database.Reader(self._db_path)
        return self._reader

    async def _enrich(self, indicator_type: str, value: str) -> Dict[str, Any]:
        try:
            reader = self._get_reader()
            response = reader.asn(value)
            return {
                "asn": f"AS{response.autonomous_system_number}",
                "asn_number": response.autonomous_system_number,
                "asn_org": response.autonomous_system_organization,
            }
        except Exception:
            return {}
