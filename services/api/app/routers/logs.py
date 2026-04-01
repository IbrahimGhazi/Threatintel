"""
Log ingestion, enrichment, and querying.

POST /api/logs          — ingest one log (HTTP devices, logserver)
POST /api/logs/batch    — ingest up to 1000 logs
GET  /api/logs          — list logs (filterable)
GET  /api/logs/stats    — today's metrics
GET  /api/logs/stream   — SSE live stream of incoming logs
"""
import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

import orjson

from app.config import get_settings
from app.database import get_db
from app.middleware.auth import require_api_key
from app.models.indicator import Indicator
from app.models.alert import Alert
from app.models.log_entry import LogEntry
from app.models.whitelist import WhitelistEntry

router = APIRouter(prefix="/logs", tags=["Logs"])

# ── IOC extraction regexes ────────────────────────────────────────────────────

_RE_IP     = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,4}'
    r'(?:com|net|org|io|ru|cn|de|uk|info|biz|xyz|top|club|site|online|'
    r'icu|tk|ml|ga|cf|gq|pw|cc|tv|co|us|ca|au|jp|br|in|fr|it|es|nl|se)\b',
    re.IGNORECASE,
)
_RE_URL    = re.compile(r'https?://[^\s\x00-\x1f"\'<>\\]{4,200}', re.IGNORECASE)
_RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
_RE_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')

_LOCAL_IPS = ("127.", "10.", "172.16.", "172.17.", "192.168.", "0.", "255.")

# User-configured device IPs (firewalls, gateways) to exclude from IOC extraction.
# Set via KNOWN_DEVICE_IPS env var (comma-separated).
import os as _os
_DEVICE_IPS: set = set(
    ip.strip() for ip in _os.getenv("KNOWN_DEVICE_IPS", "").split(",") if ip.strip()
)

# Well-known infrastructure IPs excluded from TI matching to prevent false positives
_ALLOWLISTED_IPS = {
    "8.8.8.8", "8.8.4.4",                # Google DNS
    "1.1.1.1", "1.0.0.1",                # Cloudflare DNS
    "9.9.9.9", "149.112.112.112",        # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "8.26.56.26", "8.20.247.20",          # Comodo Secure DNS
    "64.6.64.6", "64.6.65.6",            # Verisign DNS
    "4.2.2.1", "4.2.2.2",                # Level3 / CenturyLink DNS
    "185.228.168.9", "185.228.169.9",    # CleanBrowsing DNS
    "94.140.14.14", "94.140.15.15",      # AdGuard DNS
}


def _extract_iocs(text: str) -> Dict[str, List[str]]:
    ips     = [ip for ip in dict.fromkeys(_RE_IP.findall(text))
               if not any(ip.startswith(p) for p in _LOCAL_IPS)
               and ip not in _ALLOWLISTED_IPS
               and ip not in _DEVICE_IPS]
    urls    = list(dict.fromkeys(_RE_URL.findall(text)))
    hashes  = list(dict.fromkeys(_RE_SHA256.findall(text)))
    # Don't double-count URLs as domains
    no_url  = _RE_URL.sub(" ", text)
    domains = [d for d in dict.fromkeys(_RE_DOMAIN.findall(no_url))
               if d.count(".") >= 1]
    return {
        "ips":     ips[:30],
        "domains": domains[:30],
        "urls":    urls[:20],
        "hashes":  hashes[:10],
    }


async def _match_iocs(
    iocs: Dict[str, List[str]],
    db: AsyncSession,
) -> List[Dict]:
    """Query the indicators table for any extracted IOC values."""
    matches = []
    type_map = [
        ("ip",     iocs.get("ips", [])),
        ("domain", iocs.get("domains", [])),
        ("url",    iocs.get("urls", [])),
        ("sha256", iocs.get("hashes", [])),
        ("md5",    iocs.get("hashes", [])),
    ]
    for ioc_type, values in type_map:
        for val in values[:10]:  # cap per type to avoid huge queries
            row = (await db.execute(
                select(Indicator)
                .where(Indicator.active == True)
                .where(Indicator.type == ioc_type)
                .where(Indicator.normalized_value == val.lower().strip())
                .limit(1)
            )).scalar_one_or_none()
            if row:
                matches.append({
                    "indicator_id":  str(row.id),
                    "type":          ioc_type,
                    "value":         val,
                    "severity":      row.severity,
                    "confidence":    row.confidence,
                    "tags":          row.tags,
                })
    return matches


async def _is_whitelisted(value: str, ioc_type: str, db: AsyncSession) -> bool:
    """Check if a value is whitelisted via the whitelist_entries table."""
    import ipaddress as _ipaddress
    from datetime import timezone as _tz

    now = datetime.now(_tz.utc)
    # Query active, non-expired whitelist entries
    rows = (await db.execute(
        select(WhitelistEntry)
        .where(WhitelistEntry.enabled == True)
        .where(
            (WhitelistEntry.expires_at == None) | (WhitelistEntry.expires_at > now)
        )
    )).scalars().all()

    for entry in rows:
        scope = entry.scope_rule
        # If scoped to a specific rule, only match ti_match
        if scope and scope != "ti_match":
            continue

        if entry.entry_type == "indicator_value":
            if entry.value.lower() == value.lower():
                return True
        elif entry.entry_type == "ip" and ioc_type == "ip":
            if entry.value == value:
                return True
        elif entry.entry_type == "cidr" and ioc_type == "ip":
            try:
                network = _ipaddress.ip_network(entry.value, strict=False)
                if _ipaddress.ip_address(value) in network:
                    return True
            except ValueError:
                pass
        elif entry.entry_type == "hostname" and ioc_type == "domain":
            if entry.value.lower() == value.lower():
                return True
        elif entry.entry_type == "rule_name" and entry.value == "ti_match":
            return True
    return False


async def _create_match_alert(
    entry: LogEntry,
    matches: List[Dict],
    db: AsyncSession,
):
    """Create an alert for the first/highest-severity matched IOC.

    Checks the whitelist before creating — skips alert if the IOC is whitelisted.
    """
    if not matches:
        return
    # Pick highest severity
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    best = min(matches, key=lambda m: SEV_ORDER.get(m["severity"], 99))

    # Check whitelist before creating alert
    if await _is_whitelisted(best["value"], best["type"], db):
        return

    alert = Alert(
        title       = f"TI Match from {entry.source_name or entry.source_type}: {best['value']}",
        description = (
            f"Log from {entry.source_name or entry.source_type} matched known malicious "
            f"{best['type'].upper()} indicator '{best['value']}' "
            f"(severity={best['severity']}, confidence={best['confidence']}).\n\n"
            f"Raw log: {(entry.raw_log or '')[:500]}"
        ),
        severity       = best["severity"],
        status         = "open",
        indicator_id   = uuid.UUID(best["indicator_id"]),
        indicator_value= best["value"],
        indicator_type = best["type"],
        rule_name      = "ti_match",
        source_service = "log_analysis",
        log_entry_id   = entry.id,
        context     = {
            "source_type":  entry.source_type,
            "source_name":  entry.source_name,
            "log_id":       str(entry.id),
            "all_matches":  matches,
        },
    )
    db.add(alert)


# ── Pydantic models ───────────────────────────────────────────────────────────

class LogIngestIn(BaseModel):
    source_type: str  = Field(..., description="firewall | proxy | edr | email | web_gw | syslog")
    source_name: Optional[str] = None
    source_ip:   Optional[str] = None
    raw_log:     Optional[str] = Field(None, max_length=65536)
    parsed:      Optional[Dict[str, Any]] = None
    log_timestamp: Optional[datetime] = None


class LogIngestBatchIn(BaseModel):
    entries: List[LogIngestIn] = Field(..., max_length=1000)


class LogOut(BaseModel):
    id:            uuid.UUID
    source_type:   str
    source_name:   Optional[str]
    source_ip:     Optional[str]
    raw_log:       Optional[str]
    parsed:        Dict[str, Any]
    extracted_iocs:Dict[str, Any]
    matched_iocs:  List[Any]
    indicator_ids: List[Any]
    is_malicious:  bool
    log_timestamp: Optional[Any]
    processed_at:  Any

    class Config:
        from_attributes = True


# ── Ingest ────────────────────────────────────────────────────────────────────

@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def ingest_log(
    request: Request,
    body: LogIngestIn,
    db:   AsyncSession = Depends(get_db),
    _:    str          = Depends(require_api_key),
):
    return await _process_log(body, db, request)


@router.post("/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_log_batch(
    request: Request,
    body: LogIngestBatchIn,
    db:   AsyncSession = Depends(get_db),
    _:    str          = Depends(require_api_key),
):
    results = []
    for item in body.entries:
        results.append(await _process_log(item, db, request))
    return {"accepted": len(results), "matched": sum(1 for r in results if r.get("is_malicious"))}


async def _process_log(body: LogIngestIn, db: AsyncSession, request: Request = None) -> Dict:
    """Core ingest path: extract IOCs → match TI → persist → alert → forward to correlation.

    Designed for resilience: alert creation and downstream publishing failures
    are logged but never prevent the log entry from being persisted.
    """
    import logging
    _log = logging.getLogger("ti.logs")

    text_content = body.raw_log or json.dumps(body.parsed or {})

    # IOC extraction — wrapped defensively
    try:
        extracted = _extract_iocs(text_content)
    except Exception as exc:
        _log.warning("IOC extraction failed, proceeding without IOCs: %s", exc)
        extracted = {"ips": [], "domains": [], "urls": [], "hashes": []}

    # TI matching — wrapped defensively
    try:
        matches = await _match_iocs(extracted, db)
    except Exception as exc:
        _log.warning("TI matching failed, proceeding without matches: %s", exc)
        matches = []

    # Persist the log entry — this is the critical operation that must succeed
    entry = LogEntry(
        source_type    = body.source_type,
        source_name    = body.source_name,
        source_ip      = body.source_ip,
        raw_log        = body.raw_log,
        parsed         = body.parsed or {},
        extracted_iocs = extracted,
        matched_iocs   = matches,
        indicator_ids  = [uuid.UUID(m["indicator_id"]) for m in matches],
        is_malicious   = len(matches) > 0,
        log_timestamp  = body.log_timestamp,
    )
    db.add(entry)
    await db.flush()

    # Create alert if matched — failure must NOT break log ingestion
    if matches:
        try:
            await _create_match_alert(entry, matches, db)
        except Exception as exc:
            _log.error("Alert creation failed for log %s (continuing): %s", entry.id, exc)
            # Rollback only the failed alert, keep the log entry
            # The session may be in a bad state after a DB error, so we
            # expunge the entry and re-add it in a clean state
            try:
                await db.rollback()
                db.add(entry)
                await db.flush()
            except Exception:
                _log.error("Failed to recover session after alert error for log %s", entry.id)

    # Push to Redis for the SSE stream — non-critical
    try:
        settings = get_settings()
        import redis.asyncio as aioredis  # type: ignore
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.lpush("logs:stream", json.dumps({
            "id":           str(entry.id),
            "source_type":  entry.source_type,
            "source_name":  entry.source_name,
            "source_ip":    entry.source_ip,
            "is_malicious": entry.is_malicious,
            "matches":      len(matches),
            "at":           datetime.now(timezone.utc).isoformat(),
        }))
        await r.ltrim("logs:stream", 0, 499)   # keep last 500
        await r.aclose()
    except Exception:
        pass

    # Publish to NATS for the correlation engine — non-critical
    if request:
        nats_client = getattr(request.app.state, "nats_client", None)
        if nats_client:
            try:
                await nats_client.publish(
                    "ti.logs.ingest",
                    orjson.dumps({
                        "log_id":      str(entry.id),
                        "raw_log":     body.raw_log or "",
                        "parsed":      body.parsed or {},
                        "source_type": body.source_type,
                        "timestamp":   entry.log_timestamp.timestamp() if entry.log_timestamp else None,
                    }),
                )
            except Exception as exc:
                _log.debug("NATS publish failed for log %s: %s", entry.id, exc)

    return {"id": str(entry.id), "is_malicious": entry.is_malicious, "matches": len(matches)}


# ── Query ─────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[LogOut])
async def list_logs(
    source_type:   Optional[str] = Query(None),
    malicious_only:bool          = Query(False),
    source_ip:     Optional[str] = Query(None),
    offset:        int           = Query(0, ge=0),
    limit:         int           = Query(50, ge=1, le=500),
    db:            AsyncSession  = Depends(get_db),
    _:             str           = Depends(require_api_key),
):
    stmt = select(LogEntry).order_by(desc(LogEntry.processed_at)).offset(offset).limit(limit)
    if source_type:
        stmt = stmt.where(LogEntry.source_type == source_type)
    if malicious_only:
        stmt = stmt.where(LogEntry.is_malicious == True)
    if source_ip:
        stmt = stmt.where(LogEntry.source_ip == source_ip)
    rows = (await db.execute(stmt)).scalars().all()
    return list(rows)


@router.get("/stats")
async def log_stats(
    db: AsyncSession = Depends(get_db),
    _:  str          = Depends(require_api_key),
):
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    total_today = (await db.execute(
        select(func.count()).select_from(LogEntry)
        .where(LogEntry.processed_at >= today_start)
    )).scalar_one()

    matched_today = (await db.execute(
        select(func.count()).select_from(LogEntry)
        .where(LogEntry.processed_at >= today_start)
        .where(LogEntry.is_malicious == True)
    )).scalar_one()

    # Distinct source devices today
    device_rows = (await db.execute(
        select(LogEntry.source_name, LogEntry.source_ip, LogEntry.source_type)
        .where(LogEntry.processed_at >= today_start)
        .distinct()
        .limit(50)
    )).all()
    devices = [r.source_name or r.source_ip or r.source_type for r in device_rows]

    total_all = (await db.execute(
        select(func.count()).select_from(LogEntry)
    )).scalar_one()

    return {
        "total_today":   total_today,
        "matched_today": matched_today,
        "match_rate":    round((matched_today / max(total_today, 1)) * 100, 1),
        "total_all":     total_all,
        "devices":       list(set(devices))[:20],
        "device_count":  len(set(devices)),
    }


@router.get("/stream")
async def log_stream(
    _: str = Depends(require_api_key),
):
    """SSE endpoint — pushes new log events in real time via Redis list."""
    settings = get_settings()

    async def event_stream():
        try:
            import redis.asyncio as aioredis  # type: ignore
            r      = aioredis.from_url(settings.redis_url, decode_responses=True)
            cursor = 0  # index into logs:stream list
            for _ in range(3600):   # max 1h
                length = await r.llen("logs:stream")
                if length > cursor:
                    items = await r.lrange("logs:stream", cursor, length - 1)
                    for item in reversed(items):    # oldest first
                        yield f"data: {item}\n\n"
                    cursor = length
                await asyncio.sleep(1)
            await r.aclose()
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
