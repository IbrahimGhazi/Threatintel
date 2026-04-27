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
import hashlib
import logging
import math
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
from rules import evaluate, ReputationConfig
import rules
from rule_engine import load_rules_from_dir, evaluate_yaml_rules
from baseline import BaselineEngine
from suggestion_engine import SuggestionEngine
from incident_grouper import assign_alert_to_incident
from reputation import ReputationScorer, DomainFirstSeenTracker, extract_domain_from_log

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
# Baseline-aware suppression: suppress alerts when the activity metric is within
# this many standard deviations of the learned baseline (z-score).
BASELINE_SUPPRESS_Z = float(os.getenv("BASELINE_SUPPRESS_Z_THRESHOLD", "2.5"))
# Minimum baseline samples before suppression kicks in (prevents false quiet)
BASELINE_MIN_SAMPLES = int(os.getenv("BASELINE_MIN_SAMPLES", "100"))

# ── Per-host override storage (populated by _apply_rule_overrides) ───────
# Maps source_ip → { module_attr_name: threshold_value }
_host_overrides: Dict[str, Dict[str, int]] = {}
_host_window_overrides: Dict[str, Dict[str, int]] = {}
# Snapshot of the *default* thresholds from rules.py so we can restore them
_default_thresholds: Dict[str, int] = {}
_default_windows: Dict[str, int] = {}

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

# Reputation scorer and first-seen tracker. Initialised in main(). Milestone 2
# activates them via `_reputation_config` below, which is refreshed from
# platform_settings every 60s.
reputation_scorer: Optional[ReputationScorer] = None
domain_tracker:    Optional[DomainFirstSeenTracker] = None
_reputation_config: ReputationConfig = ReputationConfig()  # starts in 'off' mode


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


def _compute_fingerprint(
    rule_name: str,
    entity: str,
    rec_type: str,
    device_type: str,
    detection_type: str = "",
) -> str:
    """
    Generate a deterministic SHA-256 fingerprint for a recommendation.

    Combines rule_name | entity | rec_type | device_type | detection_type
    into a unique hash.  The same combination always produces the same
    fingerprint, enabling upsert-based deduplication.
    """
    raw = f"{rule_name}|{entity}|{rec_type}|{device_type}|{detection_type}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _recommendation_confidence(evidence_count: int, false_positive_rate: float = 0.0) -> float:
    """
    Compute recommendation confidence based on accumulated evidence.

    Grows asymptotically from ~10 % toward 95 %:
        confidence = 0.10 + 0.85 × (1 − e^(−evidence_count / 8))

    A non-zero false_positive_rate dampens confidence:
        confidence *= (1 − fp_rate)
    """
    base = 0.10 + 0.85 * (1.0 - math.exp(-evidence_count / 8.0))
    if false_positive_rate > 0:
        base *= (1.0 - min(false_positive_rate, 0.9))
    return min(0.95, round(base, 4))


_THRESHOLD_MAP = {
    "brute_force":                 "BRUTE_FORCE_THRESHOLD",
    "port_scan":                   "PORT_SCAN_PORTS_MIN",
    "host_discovery":              "HOST_DISCOVERY_TARGETS_MIN",
    "service_scan":                "SERVICE_SCAN_HOSTS_MIN",
    "repeated_connection_attempts": "REPEATED_CONN_ATTEMPTS_MIN",
    "blocked_connections":         "BLOCKED_CONN_THRESHOLD",
    "c2_beaconing":                "C2_CONN_MIN",
    "lateral_movement":            "LATERAL_HOSTS_MIN",
}
_WINDOW_MAP = {
    "brute_force":                 "BRUTE_FORCE_WINDOW",
    "port_scan":                   "PORT_SCAN_WINDOW",
    "host_discovery":              "HOST_DISCOVERY_WINDOW",
    "service_scan":                "SERVICE_SCAN_WINDOW",
    "repeated_connection_attempts": "REPEATED_CONN_ATTEMPTS_WINDOW",
    "blocked_connections":         "BLOCKED_CONN_WINDOW",
    "c2_beaconing":                "C2_WINDOW",
    "lateral_movement":            "LATERAL_WINDOW",
}


async def _apply_rule_overrides(pool: Optional[asyncpg.Pool]) -> None:
    """Read rule_overrides from DB and patch in-memory rule thresholds.

    GLOBAL overrides (entity_type='global') raise the module-level constant
    for everyone.  PER-HOST overrides (entity_type='host') are stored in
    _host_overrides and only applied at evaluation time for matching
    source IPs, so a chatty internal host doesn't blind the engine to
    attacks from other sources.
    """
    global _host_overrides, _host_window_overrides
    global _default_thresholds, _default_windows
    if not pool:
        return

    import rules as _rules

    # Snapshot original defaults on first call
    if not _default_thresholds:
        for attr in _THRESHOLD_MAP.values():
            _default_thresholds[attr] = getattr(_rules, attr)
        for attr in _WINDOW_MAP.values():
            _default_windows[attr] = getattr(_rules, attr)

    try:
        rows = await pool.fetch("""
            SELECT rule_name, entity_type, entity_value, threshold, window_secs
            FROM rule_overrides
        """)

        global_thr: Dict[str, int] = {}
        global_win: Dict[str, int] = {}
        host_thr: Dict[str, Dict[str, int]] = {}   # ip → {attr: val}
        host_win: Dict[str, Dict[str, int]] = {}

        for row in rows:
            name      = row["rule_name"]
            etype     = row["entity_type"]
            evalue    = row["entity_value"] or ""
            threshold = row["threshold"]
            window    = row["window_secs"]

            if etype == "host" and evalue:
                # ── Per-host override — store separately ──────────────
                if threshold is not None and name in _THRESHOLD_MAP:
                    attr = _THRESHOLD_MAP[name]
                    host_thr.setdefault(evalue, {})
                    host_thr[evalue][attr] = max(host_thr[evalue].get(attr, 0), int(threshold))
                if window is not None and name in _WINDOW_MAP:
                    attr = _WINDOW_MAP[name]
                    host_win.setdefault(evalue, {})
                    host_win[evalue][attr] = max(host_win[evalue].get(attr, 0), int(window))
            else:
                # ── Global override — applied to module constants ─────
                if threshold is not None and name in _THRESHOLD_MAP:
                    attr = _THRESHOLD_MAP[name]
                    global_thr[attr] = max(global_thr.get(attr, 0), int(threshold))
                if window is not None and name in _WINDOW_MAP:
                    attr = _WINDOW_MAP[name]
                    global_win[attr] = max(global_win.get(attr, 0), int(window))

        # Apply global overrides (or restore defaults if none)
        for attr, default in _default_thresholds.items():
            effective = global_thr.get(attr, default)
            if effective < default:
                effective = default
            setattr(_rules, attr, effective)
        for attr, default in _default_windows.items():
            effective = global_win.get(attr, default)
            setattr(_rules, attr, effective)

        _host_overrides = host_thr
        _host_window_overrides = host_win

        if host_thr:
            logger.info("Per-host overrides loaded for %d source IPs", len(host_thr))
        if global_thr:
            logger.info("Global overrides: %s", {k: v for k, v in global_thr.items()})

    except Exception as exc:
        logger.warning("Failed to apply rule overrides: %s", exc)


def _apply_host_context(src_ip: Optional[str]) -> Dict[str, int]:
    """Temporarily raise thresholds for a specific host if per-host overrides exist.

    Returns a dict of {attr: original_value} so the caller can restore them.
    """
    if not src_ip:
        return {}
    import rules as _rules
    overrides = _host_overrides.get(src_ip, {})
    window_ov = _host_window_overrides.get(src_ip, {})
    saved: Dict[str, int] = {}
    for attr, thr in overrides.items():
        current = getattr(_rules, attr)
        saved[attr] = current
        if thr > current:
            setattr(_rules, attr, thr)
    for attr, win in window_ov.items():
        if attr not in saved:
            saved[attr] = getattr(_rules, attr)
        setattr(_rules, attr, win)
    return saved


def _restore_thresholds(saved: Dict[str, int]) -> None:
    """Restore thresholds after per-host evaluation."""
    if not saved:
        return
    import rules as _rules
    for attr, val in saved.items():
        setattr(_rules, attr, val)


async def _rule_overrides_refresh_loop(pool: Optional[asyncpg.Pool]) -> None:
    """Reload rule overrides every 60 s so accepted suggestions take effect without restart."""
    while True:
        await asyncio.sleep(60)
        await _apply_rule_overrides(pool)


async def _baseline_flush_loop() -> None:
    """Background task: flush in-memory baselines to DB every FLUSH_INTERVAL seconds."""
    while True:
        await asyncio.sleep(60)
        if baseline_engine:
            try:
                await baseline_engine.maybe_flush()
            except Exception as exc:
                logger.warning("Baseline flush error: %s", exc)


async def _learning_config_refresh_loop() -> None:
    """Refresh learning mode config from DB every 30 seconds."""
    while True:
        await asyncio.sleep(30)
        if baseline_engine:
            try:
                await baseline_engine.load_learning_config()
            except Exception as exc:
                logger.debug("Learning config refresh error: %s", exc)


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


def _generate_recommendations(
    rule_name: str,
    severity: str,
    indicator_value: Optional[str] = None,
    indicator_type: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Return a list of response recommendation dicts for a given alert.
    Templates are chosen based on the rule/attack type.

    Each recommendation includes a 'fingerprint' field computed from
    (rule_name, entity, rec_type, device_type, detection_type) so the
    caller can upsert instead of blindly inserting duplicates.
    """
    recs: List[Dict[str, Any]] = []
    ip = source_ip or indicator_value or "<IP>"
    entity = ip  # primary entity for fingerprinting
    name = rule_name.lower()
    detection_type = "ti_match" if ("ti_match" in name or indicator_type) else "behavioral"

    if "ti_match" in name or indicator_type == "ip":
        ioc = indicator_value or ip
        recs += [
            {
                "rec_type": "block_ip",
                "title": f"Block malicious IP {ioc} on perimeter firewall",
                "description": (
                    f"The IP address {ioc} matched a threat intelligence indicator. "
                    "Block all inbound and outbound traffic to/from this IP at the network perimeter."
                ),
                "device_type": "paloalto_fw",
                "config_example": (
                    f"# Palo Alto – create address object and block rule\n"
                    f"set address malicious-{ioc.replace('.', '-')} ip-netmask {ioc}/32\n"
                    f"set security policy pre-rulebase security rules BLOCK-MALICIOUS-{ioc.replace('.', '-')} "
                    f"from any to any source malicious-{ioc.replace('.', '-')} destination any "
                    f"application any service any action deny"
                ),
            },
            {
                "rec_type": "block_ip",
                "title": f"Block {ioc} via Windows Firewall",
                "description": f"Add a Windows Firewall rule to block all traffic to/from {ioc}.",
                "device_type": "windows_fw",
                "config_example": (
                    f'netsh advfirewall firewall add rule name="Block-TI-{ioc}" '
                    f'dir=in action=block remoteip={ioc}\n'
                    f'netsh advfirewall firewall add rule name="Block-TI-{ioc}-out" '
                    f'dir=out action=block remoteip={ioc}'
                ),
            },
        ]
        if indicator_type in ("domain", "url"):
            recs.append({
                "rec_type": "block_domain",
                "title": f"Sinkhole or block domain {indicator_value}",
                "description": (
                    f"The domain {indicator_value} is flagged as malicious. "
                    "Configure DNS sinkholing or create a block policy."
                ),
                "device_type": "paloalto_fw",
                "config_example": (
                    f"# Palo Alto – Custom URL category + Security policy\n"
                    f"set custom-url-category BLOCKED-DOMAINS list {indicator_value}\n"
                    f"set security policy pre-rulebase security rules BLOCK-DOMAIN-{indicator_value[:30]} "
                    f"from any to any source any destination any application ssl,web-browsing "
                    f"service any url-category BLOCKED-DOMAINS action deny"
                ),
            })

    if "brute" in name or "spray" in name or "auth" in name:
        recs += [
            {
                "rec_type": "rate_limit",
                "title": f"Rate-limit or block {ip} – brute force source",
                "description": (
                    f"{ip} is generating excessive authentication failures. "
                    "Apply a rate-limit or temporary block at the firewall."
                ),
                "device_type": "paloalto_fw",
                "config_example": (
                    f"# Palo Alto – Zone protection profile rate-limit\n"
                    f"set zone-protection-profile BRUTE-FORCE-PROTECT flood tcp-syn red enable yes\n"
                    f"set zone-protection-profile BRUTE-FORCE-PROTECT flood tcp-syn red maximal-rate 1000\n"
                    f"# Block specific source IP\n"
                    f"set address brute-force-src ip-netmask {ip}/32\n"
                    f"set security policy pre-rulebase security rules BLOCK-BRUTE-FORCE "
                    f"source brute-force-src action deny log-end yes"
                ),
            },
            {
                "rec_type": "update_rule",
                "title": "Enable account lockout policy on affected systems",
                "description": (
                    "Configure Active Directory or the target service to lock accounts "
                    "after a configurable number of failed attempts."
                ),
                "device_type": "edr",
                "config_example": (
                    "# Windows – Group Policy\n"
                    "Computer Configuration > Windows Settings > Security Settings\n"
                    "  > Account Policies > Account Lockout Policy\n"
                    "    Account lockout threshold: 5 invalid logon attempts\n"
                    "    Account lockout duration:  30 minutes\n"
                    "    Reset account lockout counter after: 30 minutes"
                ),
            },
        ]

    if "port_scan" in name or "scan" in name or "host_discovery" in name:
        recs.append({
            "rec_type": "rate_limit",
            "title": f"Rate-limit reconnaissance traffic from {ip}",
            "description": (
                f"{ip} is conducting port or host discovery scanning. "
                "Apply a connection rate-limit and alert on further activity."
            ),
            "device_type": "paloalto_fw",
            "config_example": (
                f"# Palo Alto – Scan protection\n"
                f"set zone-protection-profile SCAN-PROTECT scan tcp-port-scan enable yes\n"
                f"set zone-protection-profile SCAN-PROTECT scan udp-port-scan enable yes\n"
                f"set zone-protection-profile SCAN-PROTECT scan host-sweep enable yes\n"
                f"# Or block the source directly\n"
                f"set address scanner-src ip-netmask {ip}/32\n"
                f"set security policy pre-rulebase security rules BLOCK-SCANNER "
                f"source scanner-src action deny"
            ),
        })

    if "lateral" in name or "rdp" in name or "smb" in name:
        recs += [
            {
                "rec_type": "isolate_host",
                "title": f"Isolate host {ip} from the network",
                "description": (
                    f"{ip} shows signs of lateral movement. Isolate the host to prevent "
                    "further spread while performing forensic investigation."
                ),
                "device_type": "edr",
                "config_example": (
                    f"# CrowdStrike Falcon – Network containment\n"
                    f"crowdstrike-falcon contain-host --hostname {ip}\n\n"
                    f"# Microsoft Defender for Endpoint\n"
                    f"Invoke-MgDeviceIsolate -DeviceId <device-id>\n\n"
                    f"# Palo Alto – Dynamic address group quarantine\n"
                    f"set address quarantined-host ip-netmask {ip}/32\n"
                    f"set security policy pre-rulebase security rules QUARANTINE-HOST "
                    f"source quarantined-host destination any action deny"
                ),
            },
            {
                "rec_type": "update_rule",
                "title": "Block lateral movement ports between segments",
                "description": (
                    "Create micro-segmentation rules to block SMB (445), RDP (3389), "
                    "and WMI (135) between workstations."
                ),
                "device_type": "paloalto_fw",
                "config_example": (
                    "# Block workstation-to-workstation lateral movement ports\n"
                    "set security policy pre-rulebase security rules BLOCK-LATERAL-MOVE\n"
                    "  from trust to trust\n"
                    "  source workstations-zone\n"
                    "  destination workstations-zone\n"
                    "  application ms-rdp,smb,msrpc\n"
                    "  action deny log-end yes"
                ),
            },
        ]

    if "c2" in name or "beacon" in name or "exfil" in name or "tunnel" in name:
        recs += [
            {
                "rec_type": "block_ip",
                "title": f"Block C2 communication to {indicator_value or ip}",
                "description": (
                    f"Suspected C2 beaconing detected. Block outbound connections to {indicator_value or ip} "
                    "and enable SSL decryption to inspect encrypted C2 channels."
                ),
                "device_type": "paloalto_fw",
                "config_example": (
                    f"# Block outbound C2 traffic\n"
                    f"set address c2-server ip-netmask {indicator_value or ip}/32\n"
                    f"set security policy pre-rulebase security rules BLOCK-C2\n"
                    f"  from trust to untrust source any destination c2-server\n"
                    f"  application any service any action deny log-end yes\n\n"
                    f"# Enable SSL decryption policy for remaining traffic\n"
                    f"set decryption policy DECRYPT-OUTBOUND from trust to untrust\n"
                    f"  action decrypt type ssl-forward-proxy"
                ),
            },
            {
                "rec_type": "isolate_host",
                "title": f"Isolate beaconing host {ip} immediately",
                "description": (
                    f"{ip} is communicating with a suspected C2 server at regular intervals. "
                    "Isolate and perform memory forensics."
                ),
                "device_type": "edr",
                "config_example": (
                    f"# CrowdStrike – Contain host and pull memory dump\n"
                    f"crowdstrike-falcon contain-host --hostname {ip}\n"
                    f"crowdstrike-falcon get-process-memory --pid <c2-process-pid> --output /forensics/{ip}_mem.dmp"
                ),
            },
        ]

    if "malicious_ip" in name:
        recs.append({
            "rec_type": "block_ip",
            "title": f"Block known-malicious IP {indicator_value or ip}",
            "description": (
                f"Connection to/from known-malicious IP {indicator_value or ip} detected. "
                "Create an immediate block rule."
            ),
            "device_type": "paloalto_fw",
            "config_example": (
                f"set address known-bad-{(indicator_value or ip).replace('.', '-')} "
                f"ip-netmask {indicator_value or ip}/32\n"
                f"set security policy pre-rulebase security rules BLOCK-KNOWN-BAD "
                f"source any destination known-bad-{(indicator_value or ip).replace('.', '-')} "
                f"action deny"
            ),
        })

    # If no specific recommendation was generated, add a generic one
    if not recs:
        recs.append({
            "rec_type": "update_rule",
            "title": f"Investigate and respond to {rule_name.replace('_', ' ')}",
            "description": (
                f"A '{rule_name}' alert (severity: {severity}) was detected. "
                "Review the alert context, verify the activity, and apply appropriate controls."
            ),
            "device_type": "generic",
            "config_example": (
                "1. Review the alert context and correlated events\n"
                "2. Verify the activity with the asset owner\n"
                "3. If confirmed malicious, isolate affected hosts and block source IPs\n"
                "4. Collect logs and memory artifacts for forensic analysis\n"
                "5. Update threat intelligence and detection rules"
            ),
        })

    # ── Attach fingerprint to every recommendation ────────────────────────────
    for rec in recs:
        rec["fingerprint"] = _compute_fingerprint(
            rule_name=rule_name,
            entity=entity,
            rec_type=rec["rec_type"],
            device_type=rec["device_type"],
            detection_type=detection_type,
        )

    return recs


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
) -> Optional[str]:
    # Valid indicator_type ENUM values in PostgreSQL
    VALID_INDICATOR_TYPES = {
        "ip", "cidr", "domain", "url", "md5", "sha1", "sha256", "sha512",
        "email", "filename", "mutex", "registry_key", "user_agent",
    }
    # Set to None if not a valid enum value to avoid DB insertion failure
    if indicator_type and indicator_type not in VALID_INDICATOR_TYPES:
        logger.warning("Invalid indicator_type '%s', setting to NULL", indicator_type)
        indicator_type = None

    alert_id = await pool.fetchval(
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
        RETURNING id
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

    # Generate and persist response recommendations with fingerprint dedup.
    # If a recommendation with the same fingerprint already exists, update
    # it (increment evidence, recalculate confidence, refresh last_seen)
    # instead of creating a duplicate entry.
    if alert_id:
        source_ip = context.get("source_ip") if isinstance(context, dict) else None
        recs = _generate_recommendations(
            rule_name=rule_name,
            severity=severity,
            indicator_value=indicator_value,
            indicator_type=indicator_type,
            source_ip=source_ip,
        )
        for rec in recs:
            fingerprint = rec.get("fingerprint")
            try:
                if fingerprint:
                    # Check for existing recommendation with same fingerprint
                    existing = await pool.fetchrow(
                        """
                        SELECT id, evidence_count, status
                        FROM response_recommendations
                        WHERE fingerprint = $1
                        """,
                        fingerprint,
                    )
                    if existing:
                        # Do not update if analyst has already applied/rejected
                        if existing["status"] in ("approved", "applied", "rejected", "ignored"):
                            logger.debug(
                                "Skipping update for actioned recommendation %s (status=%s)",
                                existing["id"], existing["status"],
                            )
                            continue

                        new_evidence = existing["evidence_count"] + 1
                        new_confidence = _recommendation_confidence(new_evidence)
                        # Transition from 'pending' to 'observed' after 3+ evidence
                        new_status = existing["status"]
                        if new_evidence >= 3 and new_status == "pending":
                            new_status = "observed"

                        await pool.execute(
                            """
                            UPDATE response_recommendations
                            SET evidence_count = $1,
                                confidence     = $2,
                                last_seen      = NOW(),
                                status         = $3,
                                explanation    = $4,
                                description    = $5,
                                updated_at     = NOW()
                            WHERE id = $6
                            """,
                            new_evidence,
                            new_confidence,
                            new_status,
                            (
                                f"Seen {new_evidence} times. "
                                f"Confidence {new_confidence:.0%} based on accumulated evidence."
                            ),
                            rec["description"],
                            str(existing["id"]),
                        )
                        logger.debug(
                            "Updated recommendation %s: evidence=%d confidence=%.0f%%",
                            existing["id"], new_evidence, new_confidence * 100,
                        )
                        continue

                # Insert new recommendation with fingerprint
                await pool.execute(
                    """
                    INSERT INTO response_recommendations
                        (alert_id, rec_type, title, description, device_type,
                         config_example, fingerprint, evidence_count, confidence,
                         first_seen, last_seen, explanation)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, NOW(), NOW(), $9)
                    """,
                    str(alert_id),
                    rec["rec_type"],
                    rec["title"],
                    rec["description"],
                    rec["device_type"],
                    rec.get("config_example"),
                    fingerprint,
                    _recommendation_confidence(1),
                    f"First detection. Confidence {_recommendation_confidence(1):.0%}.",
                )
            except Exception as exc:
                logger.warning("Failed to upsert recommendation for alert %s: %s", alert_id, exc)

    # ── Incident grouping ────────────────────────────────────────────────────
    if alert_id:
        source_ip = context.get("source_ip") if isinstance(context, dict) else None
        try:
            await assign_alert_to_incident(
                pool,
                alert_id=str(alert_id),
                rule_name=rule_name,
                severity=severity,
                source_ip=source_ip,
                context=context,
            )
        except Exception as exc:
            logger.warning("Incident grouper failed for alert %s: %s", alert_id, exc)

    return str(alert_id) if alert_id else None


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

    # ── Reputation data population (Milestone 1: data-only, non-enforcing) ──
    # Record learned-destination sets so the scorer can recognise
    # "this destination is normal for this host" once enforcement starts.
    if baseline_engine and log.src_ip and log.dst_ip:
        baseline_engine.record_observation("host", log.src_ip, "destinations", log.dst_ip)
        # Also feed the /24 peer-group set
        try:
            import ipaddress as _ipa
            a = _ipa.ip_address(log.src_ip)
            if isinstance(a, _ipa.IPv4Address):
                subnet = str(_ipa.ip_network(f"{log.src_ip}/24", strict=False).network_address)
                baseline_engine.record_observation("subnet", subnet, "destinations", log.dst_ip)
        except ValueError:
            pass

    # Track first-seen domains for the reputation scorer
    if domain_tracker:
        for itype, value in (log.iocs or []):
            if itype == "domain" and value:
                domain_tracker.observe(value)
        # Also pull a domain from the raw log if no IOC-extracted one
        _fallback_domain = extract_domain_from_log(log)
        if _fallback_domain:
            domain_tracker.observe(_fallback_domain)

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

    # Apply per-host threshold overrides only for the source IP being evaluated,
    # then restore defaults so other sources are evaluated with normal thresholds.
    _saved_ctx = _apply_host_context(log.src_ip)
    incidents, shadow_records = evaluate(
        by_src, by_dst, by_user, log,
        ti_matched_ips=ti_matched_ips,
        scorer=reputation_scorer,
        reputation_config=_reputation_config,
    )
    # Also evaluate YAML-defined Sigma-style rules. When the reputation scorer
    # is active (shadow or enforce), we suppress the count-based dns_tunneling
    # YAML rule to avoid double-firing alongside the reputation detector.
    if _reputation_config.mode in ("shadow", "enforce"):
        effective_yaml_rules = [r for r in yaml_rules if getattr(r, "name", None) != "dns_tunneling"]
    else:
        effective_yaml_rules = yaml_rules
    yaml_incidents = evaluate_yaml_rules(effective_yaml_rules, by_src, by_dst, by_user, log)
    incidents.extend(yaml_incidents)
    _restore_thresholds(_saved_ctx)

    # Track which reputation rule_names produced a real alert this cycle so we
    # can link shadow events to them via real_alert_id. Populated further down
    # after db_create_alert succeeds.
    _real_alert_ids_by_rule: Dict[str, str] = {}

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

        # ── Baseline-aware suppression ─────────────────────────────────────
        _BASELINE_PROTECTED_RULES = {"ti_match", "c2_beaconing", "malicious_ip_connection"}
        if (
            baseline_engine
            and incident.attack_type not in _BASELINE_PROTECTED_RULES
            and incident.source_ip
        ):
            _metric = "connection_count_per_hour"
            bl = baseline_engine.get_baseline("host", incident.source_ip, _metric)
            if bl and bl.get("sample_count", 0) >= BASELINE_MIN_SAMPLES:
                src_events = store.by_src.get(incident.source_ip)
                current_val = float(len(src_events)) if src_events else 0.0
                mean = bl.get("mean", 0)
                std  = bl.get("std_dev", 1)
                if std > 0:
                    z = (current_val - mean) / std
                else:
                    z = 0.0
                # Only suppress if activity is AT or ABOVE baseline level
                # but still within normal variance.  A negative z-score means
                # activity is BELOW the baseline, which means the host is new
                # or less active than usual — NOT a reason to suppress.
                if z >= 0 and z < BASELINE_SUPPRESS_Z:
                    logger.debug(
                        "Baseline suppressed %s from %s: value=%.0f mean=%.0f std=%.0f z=%.2f (threshold=%.1f)",
                        incident.attack_type, incident.source_ip, current_val, mean, std, z, BASELINE_SUPPRESS_Z,
                    )
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
        # NOTE: We intentionally do NOT set is_malicious = True here.
        # The is_malicious flag on log_entries means "matched a known
        # threat-intelligence indicator".  Behavioral detections create
        # alerts independently but should not mark the log as TI-matched,
        # otherwise the logs page misleadingly shows "IOC Match" for
        # normal traffic that merely triggered a heuristic rule.
        context = incident.to_context()
        context["alert_id"] = str(uuid.uuid4())
        context["timestamp"] = datetime.now(timezone.utc).isoformat()
        context.setdefault("log_source_type", log.source_type)
        if pool:
            try:
                new_alert_id = await db_create_alert(
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
                if new_alert_id:
                    # Last alert wins for linking (events within a single log
                    # evaluation are effectively simultaneous).
                    _real_alert_ids_by_rule[incident.attack_type] = str(new_alert_id)
            except Exception as exc:
                logger.error("Failed to persist behavioural alert %s: %s", incident.attack_type, exc)

    # ── Persist reputation shadow events ──────────────────────────────────────
    if pool and shadow_records:
        for rec in shadow_records:
            try:
                await pool.execute(
                    """
                    INSERT INTO reputation_shadow_events
                        (rule_name, src_ip, dst_ip, real_alert_id,
                         would_fire, risk_score, risk_threshold,
                         volume, dos_floor, detection_mode, context)
                    VALUES
                        ($1, $2, $3, $4::uuid, $5, $6, $7, $8, $9, $10, CAST($11 AS jsonb))
                    """,
                    rec.get("rule_name"),
                    rec.get("src_ip"),
                    rec.get("dst_ip"),
                    _real_alert_ids_by_rule.get(rec.get("rule_name", "")),
                    bool(rec.get("would_fire", False)),
                    float(rec.get("risk_score", 0.0)),
                    float(rec.get("risk_threshold", 0.0)),
                    int(rec.get("volume", 0)),
                    int(rec.get("dos_floor", 0)),
                    rec.get("detection_mode", "reputation"),
                    orjson.dumps(rec.get("context") or {}).decode(),
                )
            except Exception as exc:
                logger.debug("Shadow event persist error (%s): %s", rec.get("rule_name"), exc)

    if pool:
        try:
            await db_update_log(pool, log_id, matched_indicator_ids, is_malicious)
        except Exception as exc:
            logger.error("Failed to update log entry %s: %s", log_id, exc)


async def _domain_flush_loop() -> None:
    """Background task: periodically flush buffered domain observations to
    domain_first_seen and refresh the scorer's recent-domain set."""
    while True:
        await asyncio.sleep(DomainFirstSeenTracker.FLUSH_INTERVAL)
        if domain_tracker:
            try:
                n = await domain_tracker.flush()
                if n:
                    logger.debug("Flushed %d domain observations", n)
            except Exception as exc:
                logger.warning("Domain flush error: %s", exc)
        if reputation_scorer and domain_tracker:
            try:
                recent = await domain_tracker.load_recent(max_age_hours=24)
                reputation_scorer.update_recent_domains(recent)
            except Exception as exc:
                logger.debug("Recent-domain refresh error: %s", exc)


# ── Mapping from platform_settings keys → ReputationConfig rule keys ────────
# (DB key uses `repeated_conn_*` / `blocked_conn_*` / `dns_tunnel_*`; the
# rule-internal key matches the check_ function name for consistency with
# rules.py defaults.)
_THRESHOLD_KEY_MAP = {
    "port_scan_risk_threshold":      "port_scan",
    "host_discovery_risk_threshold": "host_discovery",
    "service_scan_risk_threshold":   "service_scan",
    "repeated_conn_risk_threshold":  "repeated_connection_attempts",
    "blocked_conn_risk_threshold":   "repeated_blocked_connections",
    "dns_tunnel_risk_threshold":     "dns_tunneling",
}
_FLOOR_KEY_MAP = {
    "port_scan_dos_floor":      "port_scan",
    "host_discovery_dos_floor": "host_discovery",
    "service_scan_dos_floor":   "service_scan",
    "repeated_conn_dos_floor":  "repeated_connection_attempts",
    "blocked_conn_dos_floor":   "repeated_blocked_connections",
    "dns_tunnel_dos_floor":     "dns_tunneling",
}


async def _load_reputation_config(pool: Optional[asyncpg.Pool]) -> None:
    """Load reputation mode + thresholds + floors + weights from
    platform_settings and rebuild the global `_reputation_config`.
    Also pushes weight settings into the scorer."""
    global _reputation_config
    if not pool:
        return
    try:
        rows = await pool.fetch(
            """
            SELECT key, value FROM platform_settings
            WHERE key = 'reputation_detection_mode'
               OR key LIKE '%_risk_threshold'
               OR key LIKE '%_dos_floor'
               OR key LIKE '%_weight'
            """
        )
        settings = {r["key"]: r["value"] for r in rows}

        mode = (settings.get("reputation_detection_mode") or "off").strip().lower()
        if mode not in ("off", "shadow", "enforce"):
            mode = "off"

        thresholds: Dict[str, float] = {}
        for db_key, rule_key in _THRESHOLD_KEY_MAP.items():
            if db_key in settings:
                try:
                    thresholds[rule_key] = float(settings[db_key])
                except (TypeError, ValueError):
                    logger.debug("Bad threshold for %s: %r", db_key, settings[db_key])

        floors: Dict[str, int] = {}
        for db_key, rule_key in _FLOOR_KEY_MAP.items():
            if db_key in settings:
                try:
                    floors[rule_key] = int(float(settings[db_key]))
                except (TypeError, ValueError):
                    logger.debug("Bad floor for %s: %r", db_key, settings[db_key])

        _reputation_config = ReputationConfig(
            mode=mode, thresholds=thresholds, floors=floors,
        )
        logger.debug(
            "Reputation config refreshed: mode=%s thresholds=%d floors=%d",
            mode, len(thresholds), len(floors),
        )

        # Push weight-style settings into the scorer as before.
        if reputation_scorer:
            weight_settings = {k: v for k, v in settings.items() if k.endswith("_weight")}
            if weight_settings:
                reputation_scorer.apply_settings(weight_settings)
    except Exception as exc:
        logger.debug("Reputation config load error: %s", exc)


async def _reputation_settings_refresh_loop(pool: Optional[asyncpg.Pool]) -> None:
    """Hot-reload reputation mode/thresholds/floors/weights every 60s."""
    while True:
        await asyncio.sleep(60)
        if not (reputation_scorer and pool):
            continue
        await _load_reputation_config(pool)


async def _load_entity_embeddings(pool: Optional[asyncpg.Pool]) -> None:
    """M3: pull learned host + destination embeddings from entity_embedding and
    push them into the scorer. Safe no-op if the table is empty (learner hasn't
    run yet) or missing (schema not applied yet)."""
    if not (pool and reputation_scorer):
        return
    try:
        rows = await pool.fetch(
            """
            SELECT entity_type, entity_value, vector
            FROM entity_embedding
            """
        )
    except Exception as exc:
        logger.debug("entity_embedding fetch skipped: %s", exc)
        return

    host_vecs: Dict[str, List[float]] = {}
    dst_vecs:  Dict[str, List[float]] = {}
    for r in rows:
        et = r["entity_type"]
        ev = r["entity_value"]
        vec = list(r["vector"]) if r["vector"] is not None else None
        if not vec:
            continue
        if et == "host":
            host_vecs[ev] = vec
        elif et == "destination":
            dst_vecs[ev] = vec

    if host_vecs or dst_vecs:
        reputation_scorer.update_embeddings(host_vecs, dst_vecs)
    else:
        logger.debug("entity_embedding empty — learned_similarity factor inactive")


async def _entity_embedding_refresh_loop(pool: Optional[asyncpg.Pool]) -> None:
    """Hot-reload behavioural embeddings every 10 minutes. The learner writes
    new rows nightly; 10-min polling picks that up without a redeploy and
    means any manual retrain is live within 10 minutes."""
    while True:
        await asyncio.sleep(600)
        await _load_entity_embeddings(pool)


async def main() -> None:
    global baseline_engine, suggestion_engine_inst
    global reputation_scorer, domain_tracker

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
                pool_size=5,
                max_overflow=10,
                pool_pre_ping=True,
                pool_timeout=60,
            )
            session_factory = async_sessionmaker(sa_engine, expire_on_commit=False)
            baseline_engine        = BaselineEngine(db_session_factory=session_factory)
            suggestion_engine_inst = SuggestionEngine(db_session_factory=session_factory)
            await baseline_engine.load_from_db()
            await baseline_engine.load_time_from_db()
            await baseline_engine.load_learning_config()
            await suggestion_engine_inst.load_triggers_from_db()
            await _apply_rule_overrides(pool)
            logger.info(
                "Adaptive baseline engine initialised (learning=%s, enforcement=%s)",
                baseline_engine.learning_mode, baseline_engine.enforcement_mode,
            )
        except Exception as exc:
            logger.warning("Adaptive engines failed to initialise: %s", exc)

    # ── Reputation scorer (Milestone 1: data-only, no suppression) ──────────
    try:
        reputation_scorer = ReputationScorer(
            baseline_engine=baseline_engine,
            whitelist_cache=whitelist_cache,
        )
        domain_tracker = DomainFirstSeenTracker(pool=pool)
        if pool:
            recent = await domain_tracker.load_recent(max_age_hours=24)
            reputation_scorer.update_recent_domains(recent)
            logger.info(
                "ReputationScorer ready (tranco=%d, recent_domains=%d)",
                len(reputation_scorer.tranco), len(recent),
            )
    except Exception as exc:
        logger.warning("ReputationScorer failed to initialise: %s", exc)

    # Initial reputation config load (mode/thresholds/floors/weights) before
    # accepting the first NATS message.
    await _load_reputation_config(pool)
    logger.info(
        "Reputation detection mode=%s (thresholds=%d floors=%d)",
        _reputation_config.mode,
        len(_reputation_config.thresholds),
        len(_reputation_config.floors),
    )

    # M3: initial embedding load (safe no-op if learner hasn't run yet)
    await _load_entity_embeddings(pool)

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

    # Queue group "correlation-workers" ensures NATS distributes each message
    # to exactly ONE subscriber in the group — safe to run multiple replicas.
    await nc.subscribe("ti.logs.ingest", queue="correlation-workers", cb=handler)
    logger.info("Correlation service ready subject=ti.logs.ingest queue=correlation-workers min_confidence=%d store_window=%ds yaml_rules=%d",
                MIN_CONFIDENCE, STORE_MAX_AGE, len(yaml_rules))
    logger.info("Active rule windows — brute_force=%ds port_scan=%ds c2=%ds lateral=%ds blocked=%ds",
                rules.BRUTE_FORCE_WINDOW, rules.PORT_SCAN_WINDOW, rules.C2_WINDOW,
                rules.LATERAL_WINDOW, rules.BLOCKED_CONN_WINDOW)

    # Start background tasks
    asyncio.create_task(_rule_overrides_refresh_loop(pool))

    # Start adaptive engine background tasks
    asyncio.create_task(_baseline_flush_loop())
    asyncio.create_task(_learning_config_refresh_loop())
    if suggestion_engine_inst:
        asyncio.create_task(suggestion_engine_inst.run_auto_apply_loop())
        logger.info("Adaptive tuning background tasks started")

    # Start reputation background tasks
    if domain_tracker:
        asyncio.create_task(_domain_flush_loop())
    if reputation_scorer:
        asyncio.create_task(_reputation_settings_refresh_loop(pool))
        asyncio.create_task(_entity_embedding_refresh_loop(pool))

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