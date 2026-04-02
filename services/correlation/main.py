"""
Correlation service entry point.

Subscribes to NATS subject: ti.logs.ingest
Message payload: {"log_id": "<uuid>", "raw_log": "<str>",
                  "parsed": {<dict>}, "source_type": "<str>",
                  "timestamp": <float|optional>}

For every log event the service:
  1. Parses and normalises the log into a structured ParsedLog.
  2. Stores the event in sliding-window keyed stores (by src_ip, dst_ip, user).
  3. Runs TI lookups on all extracted IOCs.
  4. Runs all behavioural correlation rules against the accumulated state.
  5. Persists alerts to the database with rich context JSON.
  6. Updates the log_entries row with matched indicator IDs.
"""
import asyncio
import logging
import os
import sys
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

import asyncpg
import httpx
import nats
import orjson

from parser import LogParser, ParsedLog, is_allowlisted_ip
from rules import evaluate
import rules
from rule_engine import load_rules_from_dir, evaluate_yaml_rules
from baseline import BaselineEngine
from suggestion_engine import SuggestionEngine

NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
DATABASE_URL = os.getenv("DATABASE_URL", "").replace("+asyncpg", "")
# SQLAlchemy needs the +asyncpg dialect prefix
_SA_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
API_URL = os.getenv("API_URL", "http://api:8000")
API_KEY = os.getenv("API_KEY", "")
MIN_CONFIDENCE = int(os.getenv("ALERT_MIN_CONFIDENCE", "60"))

# Configurable store parameters
STORE_MAX_EVENTS = int(os.getenv("CORRELATION_STORE_MAX_EVENTS", "1000"))
STORE_MAX_AGE = int(os.getenv("CORRELATION_STORE_MAX_AGE", "3600"))
PRUNE_INTERVAL = int(os.getenv("CORRELATION_PRUNE_INTERVAL", "60"))
ALERT_COOLDOWN = int(os.getenv("CORRELATION_ALERT_COOLDOWN", "1800"))
WHITELIST_REFRESH_INTERVAL = int(os.getenv("WHITELIST_REFRESH_INTERVAL", "60"))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "service": "correlation", "message": "%(message)s"}',
    stream=sys.stdout,
)
logger = logging.getLogger("correlation")
parser = LogParser()

# Global adaptive-engine instances — initialised in main() once the DB is ready.
baseline_engine: Optional[BaselineEngine] = None
suggestion_engine_inst: Optional[SuggestionEngine] = None


def _rule_to_category(rule_name: str) -> str:
    """Map a rule/attack-type name to a broad category for the tuning UI."""
    name = rule_name.lower()
    if "dns" in name:
        return "dns"
    if "scan" in name or "port" in name:
        return "port_scan"
    if "brute" in name or "auth" in name or "login" in name or "credential" in name:
        return "auth"
    if "lateral" in name or "smb" in name or "rdp" in name:
        return "lateral_movement"
    if "c2" in name or "beacon" in name or "exfil" in name or "tunnel" in name:
        return "c2"
    return "connection"


async def _baseline_flush_loop() -> None:
    """Background task: flush in-memory baselines to DB every FLUSH_INTERVAL seconds."""
    while True:
        await asyncio.sleep(60)
        if baseline_engine:
            try:
                await baseline_engine.maybe_flush()
            except Exception as exc:
                logger.warning("Baseline flush error: %s", exc)


class EventStore:
    def __init__(self) -> None:
        self.by_src: Dict[str, Deque[ParsedLog]] = defaultdict(lambda: deque(maxlen=STORE_MAX_EVENTS))
        self.by_dst: Dict[str, Deque[ParsedLog]] = defaultdict(lambda: deque(maxlen=STORE_MAX_EVENTS))
        self.by_user: Dict[str, Deque[ParsedLog]] = defaultdict(lambda: deque(maxlen=STORE_MAX_EVENTS))
        self._alert_times: Dict[str, float] = {}
        self._last_prune = time.monotonic()

    def add(self, log: ParsedLog) -> None:
        if log.src_ip:
            self.by_src[log.src_ip].append(log)
        if log.dst_ip:
            self.by_dst[log.dst_ip].append(log)
        if log.username:
            self.by_user[log.username].append(log)

    def prune(self) -> None:
        cutoff = time.time() - STORE_MAX_AGE
        for mapping in (self.by_src, self.by_dst, self.by_user):
            for key in list(mapping.keys()):
                queue = mapping[key]
                while queue and queue[0].timestamp < cutoff:
                    queue.popleft()
                if not queue:
                    del mapping[key]
        cooldown_cutoff = time.time() - ALERT_COOLDOWN
        self._alert_times = {key: value for key, value in self._alert_times.items() if value > cooldown_cutoff}

    def prune_if_due(self) -> None:
        now = time.monotonic()
        if now - self._last_prune >= PRUNE_INTERVAL:
            self.prune()
            self._last_prune = now

    def should_alert(self, attack_type: str, dedup_key: str) -> bool:
        key = f"{attack_type}:{dedup_key}"
        last = self._alert_times.get(key, 0.0)
        if time.time() - last < ALERT_COOLDOWN:
            return False
        self._alert_times[key] = time.time()
        return True


store = EventStore()

# Load YAML-based detection rules at startup
yaml_rules = load_rules_from_dir()
logger.info("Loaded %d YAML detection rules", len(yaml_rules))


class WhitelistCache:
    """Caches whitelist entries, refreshed periodically from the API."""

    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = []
        self._last_refresh: float = 0
        self._lock = asyncio.Lock()

    async def refresh(self, api: httpx.AsyncClient) -> None:
        """Fetch active whitelist entries from the API."""
        async with self._lock:
            now = time.monotonic()
            if now - self._last_refresh < WHITELIST_REFRESH_INTERVAL:
                return
            try:
                resp = await api.get(
                    f"{API_URL}/whitelist/active",
                    headers={"X-API-Key": API_KEY},
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    self._entries = resp.json()
                    self._last_refresh = now
                    logger.debug("Whitelist refreshed: %d entries", len(self._entries))
            except Exception as exc:
                logger.debug("Whitelist refresh failed: %s", exc)

    def is_whitelisted(
        self,
        *,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        hostname: Optional[str] = None,
        rule_name: Optional[str] = None,
        indicator_value: Optional[str] = None,
    ) -> bool:
        """Check if any parameter matches a whitelist entry."""
        import ipaddress
        for entry in self._entries:
            etype = entry.get("entry_type", "")
            value = entry.get("value", "")
            scope = entry.get("scope_rule")

            # If entry is scoped to a specific rule, only match that rule
            if scope and rule_name and scope != rule_name:
                continue

            if etype == "ip":
                if value == src_ip or value == dst_ip:
                    return True
            elif etype == "cidr":
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    if src_ip:
                        try:
                            if ipaddress.ip_address(src_ip) in network:
                                return True
                        except ValueError:
                            pass
                    if dst_ip:
                        try:
                            if ipaddress.ip_address(dst_ip) in network:
                                return True
                        except ValueError:
                            pass
                except ValueError:
                    pass
            elif etype == "hostname":
                if hostname and (value.lower() == hostname.lower()):
                    return True
            elif etype == "rule_name":
                if rule_name and value == rule_name:
                    return True
            elif etype == "indicator_value":
                if indicator_value and value.lower() == indicator_value.lower():
                    return True
        return False


whitelist_cache = WhitelistCache()


async def db_update_log(pool: asyncpg.Pool, log_id: str, indicator_ids: List[str], is_malicious: bool) -> None:
    await pool.execute(
        """
        UPDATE log_entries
        SET indicator_ids = $1::uuid[],
            is_malicious  = $2
        WHERE id = $3::uuid
        """,
        indicator_ids,
        is_malicious,
        log_id,
    )


async def db_create_alert(
    pool: asyncpg.Pool,
    title: str,
    description: str,
    severity: str,
    rule_name: str,
    indicator_id: Optional[str],
    indicator_value: str,
    indicator_type: Optional[str],
    context: Dict[str, Any],
) -> None:
    # Valid indicator_type ENUM values in PostgreSQL
    VALID_INDICATOR_TYPES = {
        "ip", "cidr", "domain", "url", "md5", "sha1", "sha256", "sha512",
        "email", "filename", "mutex", "registry_key", "user_agent",
    }
    # Set to None if not a valid enum value to avoid DB insertion failure
    if indicator_type and indicator_type not in VALID_INDICATOR_TYPES:
        logger.warning("Invalid indicator_type '%s', setting to NULL", indicator_type)
        indicator_type = None

    await pool.execute(
        """
        INSERT INTO alerts
            (id, title, description, severity, status,
             indicator_id, indicator_value, indicator_type,
             source_service, rule_name, context)
        VALUES
            (gen_random_uuid(), $1, $2,
             CAST($3 AS severity_level), 'open',
             $4::uuid, $5, CAST($6 AS indicator_type),
             'correlation', $7, CAST($8 AS jsonb))
        """,
        title,
        description,
        severity,
        indicator_id,
        indicator_value,
        indicator_type,
        rule_name,
        orjson.dumps(context).decode(),
    )


async def ti_lookup(api: httpx.AsyncClient, itype: str, value: str) -> Optional[Dict[str, Any]]:
    try:
        if itype == "ip":
            path = f"/indicators/lookup/ip/{value}"
        elif itype == "domain":
            path = f"/indicators/lookup/domain/{value}"
        elif itype in ("sha256", "sha1", "md5"):
            path = f"/indicators/lookup/hash/{value}"
        elif itype == "url":
            import urllib.parse
            path = f"/indicators/lookup/url?url={urllib.parse.quote(value, safe='')}"
        else:
            return None
        response = await api.get(f"{API_URL}{path}", headers={"X-API-Key": API_KEY}, timeout=3.0)
        if response.status_code == 200:
            return response.json()
    except Exception as exc:
        logger.debug("TI lookup failed %s %s: %s", itype, value[:60], exc)
    return None


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _bump_severity(base: str) -> str:
    idx = SEVERITY_ORDER.index(base) if base in SEVERITY_ORDER else 2
    return SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]


def _build_context(
    *,
    attack_type: str,
    severity: str,
    description: str,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    affected_host: Optional[str] = None,
    affected_hosts: Optional[List[str]] = None,
    related_log_ids: Optional[List[str]] = None,
    recommended_action: str = "",
    event_count: Optional[int] = None,
    time_window: Optional[Dict[str, Any]] = None,
    event_chain: Optional[List[Dict[str, Any]]] = None,
    mitre_attack: Optional[List[Dict[str, str]]] = None,
    stages: Optional[List[str]] = None,
    stage_progression: Optional[List[Dict[str, Any]]] = None,
    log: Optional[ParsedLog] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    context = {
        "alert_id": str(uuid.uuid4()),
        "attack_type": attack_type,
        "severity": severity,
        "description": description,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "affected_host": affected_host,
        "affected_hosts": affected_hosts or ([affected_host] if affected_host else []),
        "related_logs": related_log_ids or [],
        "event_count": event_count if event_count is not None else len(related_log_ids or []),
        "time_window": time_window or {},
        "event_chain": event_chain or [],
        "mitre_attack": mitre_attack or [],
        "stages": stages or [],
        "stage_progression": stage_progression or [],
        "recommended_action": recommended_action,
    }
    if log:
        context.setdefault("log_source_type", log.source_type)
        context.setdefault("protocol", log.protocol)
        context.setdefault("destination_port", log.dst_port)
        context.setdefault("program", log.program)
    if extra:
        context.update(extra)
    return context


async def handle_log(msg, pool: asyncpg.Pool, api: httpx.AsyncClient) -> None:
    try:
        data = orjson.loads(msg.data)
    except Exception:
        return

    log_id = data.get("log_id")
    raw_log = data.get("raw_log", "")
    parsed_dict = data.get("parsed", {})
    source_type = data.get("source_type", "unknown")
    ts = data.get("timestamp")

    if not log_id:
        return

    try:
        log = parser.parse(
            log_id=log_id,
            raw_log=raw_log,
            parsed=parsed_dict,
            source_type=source_type,
            timestamp=float(ts) if ts else None,
        )
    except Exception as exc:
        logger.error("Parser failed for log %s: %s", log_id, exc)
        return

    store.add(log)
    store.prune_if_due()

    # Record window-rate metrics for baseline learning.
    # We record the CURRENT WINDOW SIZE on each event so that baselines
    # reflect real activity levels rather than a flat 1.0 per-event flag.
    if baseline_engine and log.src_ip:
        src_events = list(store.by_src.get(log.src_ip, []))
        n = float(len(src_events))

        baseline_engine.record("host", log.src_ip, "connection_count_per_hour", n)
        baseline_engine.record_subnet(log.src_ip, "connection_count_per_hour", n)

        unique_dsts = float(len({e.dst_ip for e in src_events if e.dst_ip}))
        baseline_engine.record("host", log.src_ip, "unique_destinations", unique_dsts)

        unique_ports = float(len({e.dst_port for e in src_events if e.dst_port}))
        baseline_engine.record("host", log.src_ip, "unique_ports_per_window", unique_ports)

        failed = float(sum(
            1 for e in src_events
            if (e.status or "").lower() in ("failed", "error", "invalid", "refused")
        ))
        if failed:
            baseline_engine.record("host", log.src_ip, "failed_auth_per_hour", failed)

        rdp = float(sum(
            1 for e in src_events
            if (e.protocol or "").lower() == "rdp" or e.dst_port == 3389
        ))
        if rdp:
            baseline_engine.record("host", log.src_ip, "rdp_connections", rdp)

        smb = float(sum(
            1 for e in src_events
            if (e.protocol or "").lower() == "smb" or e.dst_port in (445, 139)
        ))
        if smb:
            baseline_engine.record("host", log.src_ip, "smb_connections", smb)

    if baseline_engine and log.username:
        user_events = list(store.by_user.get(log.username, []))
        failed_user = float(sum(
            1 for e in user_events
            if (e.status or "").lower() in ("failed", "error", "invalid", "refused")
        ))
        if failed_user:
            baseline_engine.record("user", log.username, "failed_auth_per_hour", failed_user)

    # Refresh whitelist cache periodically
    await whitelist_cache.refresh(api)

    by_src = {ip: list(queue) for ip, queue in store.by_src.items()}
    by_dst = {ip: list(queue) for ip, queue in store.by_dst.items()}
    by_user = {user: list(queue) for user, queue in store.by_user.items()}

    matched_indicator_ids: List[str] = []
    is_malicious = False
    # Collect IPs that are confirmed malicious by TI lookup.
    # Passed to evaluate() so check_malicious_ip_connection only fires on real matches.
    ti_matched_ips: set = set()

    for itype, value in log.iocs:
        # Skip TI lookups for known-good infrastructure IPs
        if itype == "ip" and is_allowlisted_ip(value):
            logger.debug("Skipping TI lookup for allowlisted IP: %s", value)
            continue
        indicator = await ti_lookup(api, itype, value)
        if not indicator:
            continue
        confidence = indicator.get("confidence", 0)
        severity = indicator.get("severity", "info")
        indicator_id = indicator.get("id")
        if indicator_id:
            matched_indicator_ids.append(indicator_id)
        if itype == "ip" and confidence >= MIN_CONFIDENCE and severity in ("medium", "high", "critical"):
            ti_matched_ips.add(value)
        if confidence >= MIN_CONFIDENCE and severity in ("medium", "high", "critical"):
            is_malicious = True
            alert_severity = _bump_severity(severity) if confidence >= 85 else severity
            dedup_key = f"{itype}:{value}"
            # Check whitelist before alerting
            if whitelist_cache.is_whitelisted(
                src_ip=log.src_ip, dst_ip=log.dst_ip, hostname=log.hostname,
                rule_name="ti_match", indicator_value=value,
            ):
                logger.debug("Whitelisted TI match: %s %s", itype, value[:60])
                continue
            if pool and store.should_alert("ti_match", dedup_key):
                description = (
                    f"Log source: {source_type}\n"
                    f"Indicator: {itype}={value}\n"
                    f"Confidence: {confidence}% Severity: {severity}"
                )
                event = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "stage": "Threat Intelligence Match",
                    "action": log.action,
                    "source_ip": log.src_ip,
                    "destination_ip": log.dst_ip,
                    "destination_port": log.dst_port,
                    "hostname": log.hostname,
                    "program": log.program,
                    "status": log.status,
                    "log_id": log_id,
                    "summary": f"Indicator match for {itype} {value}",
                }
                context = _build_context(
                    attack_type="ti_match",
                    severity=alert_severity,
                    description=description,
                    source_ip=log.src_ip,
                    destination_ip=log.dst_ip,
                    affected_host=log.hostname or log.src_ip,
                    affected_hosts=[candidate for candidate in [log.hostname, log.src_ip, log.dst_ip] if candidate],
                    related_log_ids=[log_id],
                    recommended_action="Investigate the host communicating with the malicious indicator and block the indicator at perimeter controls.",
                    event_count=1,
                    time_window={"start": event["timestamp"], "end": event["timestamp"], "duration_seconds": 0},
                    event_chain=[event],
                    mitre_attack=[],
                    stages=["Threat Intelligence Match"],
                    stage_progression=[{"stage": "Threat Intelligence Match", "count": 1, "first_seen": event["timestamp"], "last_seen": event["timestamp"], "status": "completed"}],
                    log=log,
                    extra={"indicator_type": itype, "indicator_value": value, "indicator": indicator},
                )
                try:
                    await db_create_alert(
                        pool,
                        title=f"TI Match: {itype.upper()} {value[:60]}",
                        description=description,
                        severity=alert_severity,
                        rule_name="ti_match",
                        indicator_id=indicator_id,
                        indicator_value=value,
                        indicator_type=itype,
                        context=context,
                    )
                except Exception as exc:
                    logger.error("Failed to persist TI alert: %s", exc)

    incidents = evaluate(by_src, by_dst, by_user, log, ti_matched_ips=ti_matched_ips)
    # Also evaluate YAML-defined Sigma-style rules
    yaml_incidents = evaluate_yaml_rules(yaml_rules, by_src, by_dst, by_user, log)
    incidents.extend(yaml_incidents)
    for incident in incidents:
        dedup_key = incident.source_ip or incident.affected_host or incident.destination_ip or "global"
        # Check whitelist before alerting
        if whitelist_cache.is_whitelisted(
            src_ip=incident.source_ip,
            dst_ip=incident.destination_ip,
            hostname=incident.affected_host,
            rule_name=incident.attack_type,
        ):
            logger.debug("Whitelisted behavioral alert: %s from %s", incident.attack_type, incident.source_ip)
            continue

        # Record every trigger toward tuning suggestions (before cooldown check
        # so the count accumulates even when the alert is deduped).
        if suggestion_engine_inst:
            entity_type  = "host" if incident.source_ip else "global"
            entity_value = incident.source_ip or incident.affected_host or "global"
            asyncio.create_task(suggestion_engine_inst.record_alert(
                rule_name=incident.attack_type,
                severity=incident.severity,
                entity_type=entity_type,
                entity_value=entity_value,
                category=_rule_to_category(incident.attack_type),
                baseline_info=(
                    baseline_engine.get_baseline(entity_type, entity_value, "connection_count_per_hour")
                    if baseline_engine else None
                ),
            ))

        if not store.should_alert(incident.attack_type, dedup_key):
            continue
        is_malicious = True
        context = incident.to_context()
        context["alert_id"] = str(uuid.uuid4())
        context["timestamp"] = datetime.now(timezone.utc).isoformat()
        context.setdefault("log_source_type", log.source_type)
        if pool:
            try:
                await db_create_alert(
                    pool,
                    title=incident.title,
                    description=incident.description,
                    severity=incident.severity,
                    rule_name=incident.attack_type,
                    indicator_id=None,
                    indicator_value=incident.source_ip or "",
                    indicator_type="ip",
                    context=context,
                )
            except Exception as exc:
                logger.error("Failed to persist behavioural alert %s: %s", incident.attack_type, exc)

    if pool:
        try:
            await db_update_log(pool, log_id, matched_indicator_ids, is_malicious)
        except Exception as exc:
            logger.error("Failed to update log entry %s: %s", log_id, exc)


async def main() -> None:
    global baseline_engine, suggestion_engine_inst

    pool: Optional[asyncpg.Pool] = None
    if DATABASE_URL:
        while True:
            try:
                pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
                logger.info("Connected to PostgreSQL")
                break
            except Exception as exc:
                logger.warning("DB connection failed, retrying in 5s: %s", exc)
                await asyncio.sleep(5)

    # ── Adaptive baseline & suggestion engines ────────────────────────────────
    if _SA_DATABASE_URL:
        try:
            from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
            sa_engine = create_async_engine(
                _SA_DATABASE_URL,
                pool_size=2,
                max_overflow=3,
                pool_pre_ping=True,
            )
            session_factory = async_sessionmaker(sa_engine, expire_on_commit=False)
            baseline_engine      = BaselineEngine(db_session_factory=session_factory)
            suggestion_engine_inst = SuggestionEngine(db_session_factory=session_factory)
            await baseline_engine.load_from_db()
            logger.info("Adaptive baseline engine initialised")
        except Exception as exc:
            logger.warning("Adaptive engines failed to initialise: %s", exc)

    api = httpx.AsyncClient(timeout=5.0, limits=httpx.Limits(max_connections=20, max_keepalive_connections=10))

    nc = None
    while True:
        try:
            nc = await nats.connect(NATS_URL, name="ti-correlation", reconnect_time_wait=5, max_reconnect_attempts=-1)
            logger.info("Connected to NATS")
            break
        except Exception as exc:
            logger.warning("NATS connection failed, retrying in 5s: %s", exc)
            await asyncio.sleep(5)

    async def handler(msg) -> None:
        async def _safe_handle():
            try:
                await handle_log(msg, pool, api)
            except Exception as exc:
                logger.error("Unhandled error in log handler: %s", exc, exc_info=True)
        asyncio.create_task(_safe_handle())

    await nc.subscribe("ti.logs.ingest", cb=handler)
    logger.info("Correlation service ready subject=ti.logs.ingest min_confidence=%d store_window=%ds yaml_rules=%d",
                MIN_CONFIDENCE, STORE_MAX_AGE, len(yaml_rules))
    logger.info("Active rule windows — brute_force=%ds port_scan=%ds c2=%ds lateral=%ds blocked=%ds",
                rules.BRUTE_FORCE_WINDOW, rules.PORT_SCAN_WINDOW, rules.C2_WINDOW,
                rules.LATERAL_WINDOW, rules.BLOCKED_CONN_WINDOW)

    # Start adaptive engine background tasks
    asyncio.create_task(_baseline_flush_loop())
    if suggestion_engine_inst:
        asyncio.create_task(suggestion_engine_inst.run_auto_apply_loop())
        logger.info("Adaptive tuning background tasks started")

    try:
        while True:
            await asyncio.sleep(60)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down correlation service")
    finally:
        await nc.drain()
        if pool:
            await pool.close()
        await api.aclose()


if __name__ == "__main__":
    asyncio.run(main())