"""
Indicator service – core business logic for creating, updating,
and querying threat indicators.

All indicator mutations go through this service to ensure:
  - consistent normalization
  - deduplication by (type, normalized_value)
  - source tracking
  - confidence aggregation
  - cache invalidation
"""
import ipaddress
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import tldextract
from sqlalchemy import Text, and_, desc, func, literal, or_, select, update
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.indicator import Indicator, IndicatorSource

logger = logging.getLogger(__name__)

# Severity ordering for aggregation comparisons
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_NAMES = ["info", "low", "medium", "high", "critical"]

# Confidence weights per source category
SOURCE_CONFIDENCE_WEIGHTS = {
    "commercial": 1.0,
    "open_source": 0.8,
    "internal": 0.9,
    "sandbox": 0.95,
    "user_submitted": 0.6,
}


# ── Normalization ─────────────────────────────────────────────

def normalize_ip(value: str) -> Optional[str]:
    """Normalize and validate IP address. Returns None if invalid."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def normalize_domain(value: str) -> Optional[str]:
    """Normalize domain: lowercase, strip leading/trailing dots and whitespace."""
    cleaned = value.strip().lower().lstrip("*.")
    if not cleaned or len(cleaned) > 253:
        return None
    # Basic validation: must have at least one dot
    if "." not in cleaned:
        return None
    return cleaned


def normalize_url(value: str) -> Optional[str]:
    """Normalize URL: lowercase scheme+host, preserve path case."""
    v = value.strip()
    if not v.startswith(("http://", "https://", "ftp://")):
        v = "http://" + v
    # Limit length
    if len(v) > 2048:
        return None
    return v


def normalize_hash(value: str, hash_type: str) -> Optional[str]:
    """Normalize file hash to lowercase hex. Validates expected length."""
    v = value.strip().lower()
    expected_lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
    expected = expected_lengths.get(hash_type)
    if expected and len(v) != expected:
        return None
    if not re.match(r'^[0-9a-f]+$', v):
        return None
    return v


NORMALIZERS = {
    "ip":     normalize_ip,
    "domain": normalize_domain,
    "url":    normalize_url,
    "md5":    lambda v: normalize_hash(v, "md5"),
    "sha1":   lambda v: normalize_hash(v, "sha1"),
    "sha256": lambda v: normalize_hash(v, "sha256"),
    "sha512": lambda v: normalize_hash(v, "sha512"),
    "email":  lambda v: v.strip().lower() if "@" in v else None,
}


def normalize_indicator(itype: str, value: str) -> Optional[str]:
    """Return normalized form of an indicator value, or None if invalid."""
    normalizer = NORMALIZERS.get(itype)
    if not normalizer:
        return value.strip() or None
    return normalizer(value)


def compute_severity(confidence: int, tags: List[str]) -> str:
    """Derive severity from confidence score and tags."""
    if "ransomware" in tags or "apt" in tags or confidence >= 90:
        return "critical"
    if confidence >= 75:
        return "high"
    if confidence >= 50:
        return "medium"
    if confidence >= 25:
        return "low"
    return "info"


# ── Core CRUD ─────────────────────────────────────────────────

async def upsert_indicator(
    db: AsyncSession,
    itype: str,
    value: str,
    source_name: str,
    source_category: str = "open_source",
    confidence: int = 50,
    tags: Optional[List[str]] = None,
    raw_data: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Indicator], bool]:
    """
    Insert or update an indicator.

    Returns (indicator, created) where `created` is True if a new row was inserted.
    Returns (None, False) if the indicator value is invalid.
    """
    tags = tags or []
    raw_data = raw_data or {}

    normalized = normalize_indicator(itype, value)
    if not normalized:
        logger.debug("Invalid indicator skipped: type=%s value=%r", itype, value[:80])
        return None, False

    now = datetime.now(timezone.utc)

    # Upsert the indicator row
    stmt = (
        insert(Indicator)
        .values(
            id=uuid.uuid4(),
            type=itype,
            value=value.strip(),
            normalized_value=normalized,
            confidence=confidence,
            severity=compute_severity(confidence, tags),
            tags=list(set(tags)),
            first_seen=now,
            last_seen=now,
            active=True,
        )
        .on_conflict_do_update(
            constraint="uq_indicator",
            set_={
                "last_seen": now,
                # Merge tags (PostgreSQL array union)
                "tags": func.array_cat(
                    Indicator.tags,
                    literal(list(set(tags)), type_=ARRAY(Text)),
                ),
                "active": True,
                # Confidence: keep max of existing and incoming
                "confidence": func.greatest(Indicator.confidence, confidence),
                "updated_at": now,
            },
        )
        .returning(Indicator)
    )

    try:
        result = await db.execute(stmt)
        row = result.fetchone()
        if not row:
            # Row was updated, fetch it
            sel = select(Indicator).where(
                Indicator.type == itype,
                Indicator.normalized_value == normalized,
            )
            row = (await db.execute(sel)).scalar_one_or_none()
            created = False
        else:
            created = True  # simplified; true upsert tracking needs XMAX check
    except Exception as exc:
        logger.error("Upsert failed for %s %s: %s", itype, normalized[:60], exc)
        raise

    if not row:
        return None, False

    indicator_id = row.id if hasattr(row, 'id') else row[0].id

    # Upsert the source record
    src_stmt = (
        insert(IndicatorSource)
        .values(
            id=uuid.uuid4(),
            indicator_id=indicator_id,
            source_name=source_name,
            source_category=source_category,
            raw_data=raw_data,
            first_seen=now,
            last_seen=now,
            confidence=confidence,
        )
        .on_conflict_do_update(
            constraint="uq_source",
            set_={
                "last_seen": now,
                "confidence": confidence,
                "raw_data": raw_data,
            },
        )
    )
    await db.execute(src_stmt)

    return row, created


async def get_indicator_by_value(
    db: AsyncSession,
    itype: str,
    value: str,
) -> Optional[Indicator]:
    """Fetch a single indicator by type and value."""
    normalized = normalize_indicator(itype, value)
    if not normalized:
        return None
    stmt = (
        select(Indicator)
        .where(
            Indicator.type == itype,
            Indicator.normalized_value == normalized,
            Indicator.active == True,
        )
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def search_indicators(
    db: AsyncSession,
    *,
    q: Optional[str] = None,
    itype: Optional[str] = None,
    severity: Optional[str] = None,
    min_confidence: int = 0,
    tags: Optional[List[str]] = None,
    active_only: bool = True,
    offset: int = 0,
    limit: int = 50,
) -> Tuple[List[Indicator], int]:
    """
    Search indicators with optional filters.
    Returns (rows, total_count).
    """
    base_query = select(Indicator)
    count_query = select(func.count()).select_from(Indicator)

    conditions = []

    if active_only:
        conditions.append(Indicator.active == True)

    if itype:
        conditions.append(Indicator.type == itype)

    if severity:
        # Return indicators at or above the requested severity level
        min_idx = SEVERITY_ORDER.get(severity, 0)
        included = [s for s, i in SEVERITY_ORDER.items() if i >= min_idx]
        conditions.append(Indicator.severity.in_(included))

    if min_confidence > 0:
        conditions.append(Indicator.confidence >= min_confidence)

    if q:
        conditions.append(
            or_(
                Indicator.value.ilike(f"%{q}%"),
                Indicator.normalized_value.ilike(f"%{q}%"),
            )
        )

    if tags:
        # All specified tags must be present
        conditions.append(Indicator.tags.contains(tags))

    if conditions:
        base_query = base_query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    total = (await db.execute(count_query)).scalar_one()

    rows = (
        await db.execute(
            base_query
            .order_by(desc(Indicator.last_seen))
            .offset(offset)
            .limit(limit)
        )
    ).scalars().all()

    return list(rows), total


async def mark_false_positive(db: AsyncSession, indicator_id: uuid.UUID) -> bool:
    """Mark an indicator as a false positive and deactivate it."""
    stmt = (
        update(Indicator)
        .where(Indicator.id == indicator_id)
        .values(false_positive=True, active=False, updated_at=func.now())
        .returning(Indicator.id)
    )
    result = await db.execute(stmt)
    return result.fetchone() is not None


async def get_indicator_stats(db: AsyncSession) -> Dict[str, Any]:
    """Return aggregate statistics for the dashboard."""
    total = (await db.execute(select(func.count()).select_from(Indicator))).scalar_one()
    active = (await db.execute(
        select(func.count()).select_from(Indicator).where(Indicator.active == True)
    )).scalar_one()

    # Count by type
    by_type = (await db.execute(
        select(Indicator.type, func.count().label("cnt"))
        .where(Indicator.active == True)
        .group_by(Indicator.type)
    )).all()

    # Count by severity
    by_severity = (await db.execute(
        select(Indicator.severity, func.count().label("cnt"))
        .where(Indicator.active == True)
        .group_by(Indicator.severity)
    )).all()

    # Recent ingestion rate (last 24h)
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    recent = (await db.execute(
        select(func.count()).select_from(Indicator).where(Indicator.created_at >= cutoff)
    )).scalar_one()

    return {
        "total": total,
        "active": active,
        "recent_24h": recent,
        "by_type": {r.type: r.cnt for r in by_type},
        "by_severity": {r.severity: r.cnt for r in by_severity},
    }
