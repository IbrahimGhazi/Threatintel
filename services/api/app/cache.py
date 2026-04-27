"""
Lightweight Redis cache helpers for indicator lookups (and friends).

Pattern: cache-aside with negative caching.
  - HIT      → cache the indicator payload for TTL_HIT (default 600s).
  - MISS 404 → cache a TOMBSTONE sentinel for TTL_MISS (default 120s) so
               the same 404 does NOT re-hit Postgres repeatedly.

The cache is optional: if Redis is down, calls silently fall through to
Postgres and the service remains fully functional. Stats are exposed via
`cache_stats()` for the dashboard / /metrics endpoint.
"""
from __future__ import annotations

import logging
from typing import Any, Optional, Tuple

import orjson
import redis.asyncio as aioredis

from app.config import get_settings

log = logging.getLogger("api.cache")

# ── Configuration ─────────────────────────────────────────────────────────────

NAMESPACE = "ind:lookup:v1"
TOMBSTONE = b"__MISS__"
TTL_HIT = 600      # 10 minutes
TTL_MISS = 120     # 2 minutes

# ── Module state ──────────────────────────────────────────────────────────────

_client: Optional[aioredis.Redis] = None
_stats: dict = {
    "hits": 0,
    "negative_hits": 0,
    "misses": 0,
    "errors": 0,
    "sets_hit": 0,
    "sets_miss": 0,
    "invalidations": 0,
}


# ── Connection management ─────────────────────────────────────────────────────

async def get_redis() -> Optional[aioredis.Redis]:
    """Return a shared Redis client, or None if unavailable."""
    global _client
    if _client is not None:
        return _client
    settings = get_settings()
    try:
        _client = aioredis.from_url(
            settings.redis_url,
            decode_responses=False,          # we encode values ourselves
            socket_timeout=0.75,
            socket_connect_timeout=1.0,
            health_check_interval=30,
            max_connections=24,
        )
        await _client.ping()
        log.info("indicator cache: connected to Redis")
    except Exception as exc:
        log.warning("indicator cache: Redis unavailable (%s) — running cache-less", exc)
        _client = None
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        try:
            await _client.close()
        except Exception:
            pass
        _client = None


# ── Keying ────────────────────────────────────────────────────────────────────

def _key(itype: str, value: str) -> str:
    # Lowercase value for case-insensitive lookup.  Truncate insanely long keys.
    v = (value or "").strip().lower()
    if len(v) > 512:
        v = v[:512]
    return f"{NAMESPACE}:{itype.lower()}:{v}"


# ── Public API ────────────────────────────────────────────────────────────────

async def get_cached(itype: str, value: str) -> Tuple[str, Optional[dict]]:
    """
    Return (status, payload) where status in {'hit', 'negative', 'miss'}.
    Never raises.
    """
    r = await get_redis()
    if r is None:
        _stats["errors"] += 1
        return "miss", None
    try:
        raw = await r.get(_key(itype, value))
    except Exception as exc:
        log.debug("cache.get error: %s", exc)
        _stats["errors"] += 1
        return "miss", None
    if raw is None:
        _stats["misses"] += 1
        return "miss", None
    if raw == TOMBSTONE:
        _stats["negative_hits"] += 1
        return "negative", None
    try:
        payload = orjson.loads(raw)
    except Exception:
        _stats["errors"] += 1
        return "miss", None
    _stats["hits"] += 1
    return "hit", payload


async def set_hit(itype: str, value: str, payload: Any) -> None:
    r = await get_redis()
    if r is None:
        return
    try:
        if not isinstance(payload, (dict, list, str, int, float, bool)) and payload is not None:
            payload = _serialize_indicator(payload)
        await r.setex(_key(itype, value), TTL_HIT, orjson.dumps(payload))
        _stats["sets_hit"] += 1
    except Exception as exc:
        log.debug("cache.set_hit error: %s", exc)
        _stats["errors"] += 1


async def set_miss(itype: str, value: str) -> None:
    r = await get_redis()
    if r is None:
        return
    try:
        await r.setex(_key(itype, value), TTL_MISS, TOMBSTONE)
        _stats["sets_miss"] += 1
    except Exception as exc:
        log.debug("cache.set_miss error: %s", exc)
        _stats["errors"] += 1


async def invalidate(itype: str, value: str) -> None:
    r = await get_redis()
    if r is None:
        return
    try:
        await r.delete(_key(itype, value))
        _stats["invalidations"] += 1
    except Exception as exc:
        log.debug("cache.invalidate error: %s", exc)
        _stats["errors"] += 1


async def invalidate_many(pairs) -> None:
    """Delete multiple (type, value) pairs at once."""
    r = await get_redis()
    if r is None or not pairs:
        return
    try:
        keys = [_key(t, v) for t, v in pairs]
        await r.delete(*keys)
        _stats["invalidations"] += len(keys)
    except Exception as exc:
        log.debug("cache.invalidate_many error: %s", exc)
        _stats["errors"] += 1


async def invalidate_prefix(itype: str) -> int:
    """Invalidate all keys for a given indicator type (SCAN-based)."""
    r = await get_redis()
    if r is None:
        return 0
    try:
        pattern = f"{NAMESPACE}:{itype.lower()}:*"
        deleted = 0
        async for key in r.scan_iter(match=pattern, count=500):
            await r.delete(key)
            deleted += 1
        _stats["invalidations"] += deleted
        return deleted
    except Exception as exc:
        log.debug("cache.invalidate_prefix error: %s", exc)
        _stats["errors"] += 1
        return 0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize_indicator(ind: Any) -> dict:
    """Turn a SQLAlchemy Indicator ORM row into a JSON-safe dict."""
    def _enum_or_str(x):
        return x.value if hasattr(x, "value") else (str(x) if x is not None else None)

    return {
        "id": str(getattr(ind, "id", "")),
        "type": _enum_or_str(getattr(ind, "type", None)),
        "value": getattr(ind, "value", None),
        "normalized_value": getattr(ind, "normalized_value", None),
        "severity": _enum_or_str(getattr(ind, "severity", None)),
        "confidence": getattr(ind, "confidence", None),
        "reputation_score": getattr(ind, "reputation_score", None),
        "first_seen": _iso(getattr(ind, "first_seen", None)),
        "last_seen": _iso(getattr(ind, "last_seen", None)),
        "active": getattr(ind, "active", None),
        "false_positive": getattr(ind, "false_positive", None),
        "tags": list(getattr(ind, "tags", []) or []),
        "enrichment": dict(getattr(ind, "enrichment", {}) or {}),
        "expires_at": _iso(getattr(ind, "expires_at", None)),
    }


def _iso(x):
    try:
        return x.isoformat() if x is not None else None
    except Exception:
        return None


def cache_stats() -> dict:
    total_reads = _stats["hits"] + _stats["negative_hits"] + _stats["misses"]
    hit_ratio = (
        (_stats["hits"] + _stats["negative_hits"]) / total_reads
        if total_reads > 0 else 0.0
    )
    return {
        **_stats,
        "total_reads": total_reads,
        "hit_ratio": round(hit_ratio, 4),
        "namespace": NAMESPACE,
        "ttl_hit_seconds": TTL_HIT,
        "ttl_miss_seconds": TTL_MISS,
    }
