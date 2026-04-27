"""
GeoIP enrichment using MaxMind GeoLite2.

Requires GeoLite2-City.mmdb placed at $GEOIP_DB_PATH (default: /geoip/GeoLite2-City.mmdb).
Free database available at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"""
import logging
import os
from typing import Any, Dict

from modules.base import BaseEnricher

logger = logging.getLogger(__name__)


class GeoIPEnricher(BaseEnricher):
    name = "geoip"
    supported_types = ["ip"]
    cache_ttl = 604800  # 7 days (GeoIP data is fairly stable)

    def __init__(self, redis_client=None):
        super().__init__(redis_client)
        self._reader = None
        self._db_path = os.getenv("GEOIP_DB_PATH", "/geoip/GeoLite2-City.mmdb")

    def _get_reader(self):
        if self._reader is None:
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(self._db_path)
                logger.info("GeoIP database loaded from %s", self._db_path)
            except Exception as exc:
                logger.error("Failed to load GeoIP database: %s", exc)
                raise
        return self._reader

    async def _enrich(self, indicator_type: str, value: str) -> Dict[str, Any]:
        reader = self._get_reader()

        try:
            response = reader.city(value)
        except Exception:
            # IP not found in database (private, reserved, etc.)
            return {}

        result = {}

        if response.country.iso_code:
            result["country_code"] = response.country.iso_code
            result["country_name"] = response.country.name

        if response.city.name:
            result["city"] = response.city.name

        if response.subdivisions.most_specific.name:
            result["region"] = response.subdivisions.most_specific.name

        if response.location.latitude:
            result["latitude"] = response.location.latitude
            result["longitude"] = response.location.longitude

        if response.postal.code:
            result["postal_code"] = response.postal.code

        result["is_vpn"] = False  # Requires paid database
        result["is_hosting"] = False  # Requires paid database

        return result
