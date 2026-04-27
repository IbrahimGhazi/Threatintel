"""
Abstract base class for all enrichment modules.

Each module must implement `enrich(indicator_type, value) -> dict`.
Modules should be stateless; state goes in Redis cache.
Failures must be caught and returned as empty dicts — never propagate.
"""
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseEnricher(ABC):
    """Abstract enrichment module."""

    name: str = "base"
    # Supported indicator types (None = all types)
    supported_types: Optional[list] = None
    # Cache TTL in seconds
    cache_ttl: int = 86400  # 24 hours

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.logger = logging.getLogger(f"enrichment.{self.name}")

    def supports(self, indicator_type: str) -> bool:
        if self.supported_types is None:
            return True
        return indicator_type in self.supported_types

    @abstractmethod
    async def _enrich(self, indicator_type: str, value: str) -> Dict[str, Any]:
        """Perform the actual enrichment. May raise exceptions."""
        ...

    async def enrich(self, indicator_type: str, value: str) -> Dict[str, Any]:
        """
        Public enrichment method with cache and error handling.
        Never raises exceptions – returns empty dict on failure.
        """
        if not self.supports(indicator_type):
            return {}

        cache_key = f"enrichment:{self.name}:{indicator_type}:{value}"

        # Check cache
        if self.redis:
            try:
                cached = await self.redis.get(cache_key)
                if cached:
                    import orjson
                    return orjson.loads(cached)
            except Exception as exc:
                self.logger.warning("Cache read failed: %s", exc)

        # Run enrichment
        try:
            result = await self._enrich(indicator_type, value)
        except Exception as exc:
            self.logger.warning("Enrichment failed for %s %s: %s", indicator_type, value[:60], exc)
            return {}

        # Store in cache
        if self.redis and result:
            try:
                import orjson
                await self.redis.setex(cache_key, self.cache_ttl, orjson.dumps(result))
            except Exception as exc:
                self.logger.warning("Cache write failed: %s", exc)

        return result
