"""
Behavioral correlation rules for the SIEM engine.

Rules return rich incidents with event chain, MITRE mappings, affected hosts,
time windows, and stage progression so the frontend can render a full incident.

Milestone 2 (reputation-aware): the recon / DNS-tunneling detectors now
consult a ReputationScorer to weight each event by destination reputation.
Legacy count-based detectors are preserved and used as the fallback when
`detection_mode == 'off'` or no scorer is wired in.
"""
import math
import re
import statistics
import time
from typing import Any, Dict, List, Optional, Tuple

import os

from incidents import build_incident
from models import Incident
from parser import ParsedLog, is_private_ip, is_public_ip

# Configurable time windows (seconds) - override with env vars
def get_window(base_name: str, default: int) -> int:
    """Get rule window from env var or use default."""
    env_var = f"CORRELATION_{base_name.upper()}_WINDOW"
    return int(os.getenv(env_var, str(default)))

BRUTE_FORCE_THRESHOLD = 15
BRUTE_FORCE_WINDOW = get_window("brute_force", 300)  # 5min default

SPRAY_ACCOUNTS_MIN = 10
SPRAY_WINDOW = get_window("password_spray", 600)  # 10min

PORT_SCAN_PORTS_MIN = 25
PORT_SCAN_WINDOW = get_window("port_scan", 300)

LATERAL_HOSTS_MIN = 5
LATERAL_WINDOW = get_window("lateral_movement", 900)  # 15min
LATERAL_PORTS = {22, 135, 139, 445, 3389, 5985, 5986, 1433, 3306, 5432}

BLOCKED_CONN_THRESHOLD = 30
BLOCKED_CONN_WINDOW = get_window("blocked_connections", 300)

C2_CONN_MIN = 10
C2_WINDOW = get_window("c2_beaconing", 1800)  # 30min
C2_MAX_JITTER = 0.25

# Ports that naturally produce periodic traffic and should NOT trigger C2 alerts.
C2_EXCLUDED_PORTS = {53, 123, 80, 443, 8080, 8443}

# Well-known service IP ranges (prefixes) that should not be flagged as C2.
C2_SAFE_DST_PREFIXES = (
    "142.250.", "142.251.", "172.217.", "216.58.",  # Google
    "40.126.", "40.99.", "13.107.", "52.96.",       # Microsoft
    "20.190.", "204.79.", "150.171.",               # Microsoft
    "104.16.", "104.17.", "104.18.", "104.19.",     # Cloudflare
    "104.20.", "104.21.", "104.22.", "104.23.",     # Cloudflare
    "104.24.", "104.25.", "104.26.", "104.27.",     # Cloudflare
    "188.114.",                                     # Cloudflare
    "157.240.",                                     # Facebook/Meta
    "17.253.",                                      # Apple
    "23.206.", "23.207.",                           # Akamai
    "151.101.",                                     # Fastly / Reddit
    "185.125.190.",                                 # Canonical/Ubuntu
    "34.120.", "34.107.",                           # Google Cloud
    "65.0.", "65.1.",                               # AWS
    "43.205.", "143.204.",                          # AWS CloudFront
    "95.101.",                                      # Akamai
)

MALICIOUS_IP_CONN_MIN = 3
MALICIOUS_IP_WINDOW = get_window("malicious_ip", 1800)

# Host discovery / ping sweep — baseline shows ~900 conn/hr so 50 targets
# in 5 min is genuinely suspicious, not routine LAN traffic
HOST_DISCOVERY_TARGETS_MIN = 50
HOST_DISCOVERY_WINDOW = get_window("host_discovery", 300)  # 5min

# Service scan (Nmap-style: few ports across many hosts)
SERVICE_SCAN_HOSTS_MIN = 25
SERVICE_SCAN_WINDOW = get_window("service_scan", 300)
SERVICE_SCAN_PORTS = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                      993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 8080, 8443}

# Repeated connection attempts from same source
REPEATED_CONN_ATTEMPTS_MIN = 40
REPEATED_CONN_ATTEMPTS_WINDOW = get_window("repeated_conn_attempts", 300)

# DNS tunneling — replaced YAML rule at Milestone 2. The count-only threshold
# (50 DNS queries per 5 min) was the primary false-positive source. The new
# detector weights each query by reputation; a volumetric DoS floor (300)
# still fires on true flooding.
DNS_TUNNELING_COUNT_MIN = 50
DNS_TUNNELING_WINDOW = get_window("dns_tunneling", 300)

# Multi-stage windows (supports 30s, 1m, 5m via env vars)
MULTI_STAGE_RECON_WINDOW = get_window("multi_stage_recon", 300)
MULTI_STAGE_EXPLOIT_WINDOW = get_window("multi_stage_exploit", 1800)

AUTH_FAILURE_RE = re.compile(
    r"\b(?:fail(?:ed|ure)?|invalid\s+(?:user|password|credentials?)|incorrect\s+password|authentication\s+(?:error|failed)|logon\s+failure|access\s+denied|bad\s+password|rejected|wrong\s+password)\b",
    re.I,
)
AUTH_SUCCESS_RE = re.compile(
    r"\b(?:accepted|authenticated|logged\s+(?:in|on)|session\s+opened|login\s+successful)\b",
    re.I,
)
EXPLOIT_RE = re.compile(
    r"\b(?:sql\s+injection|command\s+injection|deserialization|exploit|payload|shellcode|directory\s+traversal|remote\s+code\s+execution|rce|xxe|ssti)\b",
    re.I,
)
PRIV_ESC_RE = re.compile(
    r"\b(?:sudo|runas|SeDebugPrivilege|SeImpersonatePrivilege|privilege\s+escal|uac\s+bypass|token\s+impersonat|net\s+localgroup\s+administrators|Add-LocalGroupMember)\b",
    re.I,
)


# ── Reputation-aware settings container ─────────────────────────────────────
class ReputationConfig:
    """Holds per-rule thresholds + DoS floors + detection mode.

    Populated by main.py from platform_settings on startup and refreshed
    every 60s. Mode: 'off' | 'shadow' | 'enforce'.
    """
    __slots__ = ("mode", "thresholds", "floors")

    def __init__(
        self,
        mode: str = "off",
        thresholds: Optional[Dict[str, float]] = None,
        floors: Optional[Dict[str, int]] = None,
    ) -> None:
        self.mode = (mode or "off").lower()
        self.thresholds: Dict[str, float] = dict(thresholds or {})
        self.floors: Dict[str, int] = dict(floors or {})

    def risk_threshold(self, rule: str, default: float) -> float:
        return float(self.thresholds.get(rule, default))

    def dos_floor(self, rule: str, default: int) -> int:
        return int(self.floors.get(rule, default))


# Default thresholds — match platform_settings defaults set by 12_reputation.sql
_DEFAULT_RISK_THRESHOLDS = {
    "port_scan":                    10.0,
    "host_discovery":                6.0,
    "service_scan":                  8.0,
    "repeated_connection_attempts":  6.0,
    "repeated_blocked_connections":  6.0,
    "dns_tunneling":                15.0,
}
_DEFAULT_DOS_FLOORS = {
    "port_scan":                    500,
    "host_discovery":               300,
    "service_scan":                 200,
    "repeated_connection_attempts": 500,
    "repeated_blocked_connections": 500,
    "dns_tunneling":                300,
}


def _recent(events: List[ParsedLog], window: float) -> List[ParsedLog]:
    cutoff = time.time() - window
    return [event for event in events if event.timestamp >= cutoff]


def _is_auth_failure(log: ParsedLog) -> bool:
    if log.status == "failed":
        return True
    if log.action in {"deny", "denied", "block", "blocked", "reject", "rejected"}:
        return True
    return bool(AUTH_FAILURE_RE.search(log.raw))


def _is_auth_success(log: ParsedLog) -> bool:
    if log.status == "success":
        return True
    return bool(AUTH_SUCCESS_RE.search(log.raw))


def _is_blocked(log: ParsedLog) -> bool:
    return log.action in {"deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected"}


def _dedupe_logs(logs: List[ParsedLog]) -> List[ParsedLog]:
    seen = {}
    for log in logs:
        seen[log.log_id] = log
    return sorted(seen.values(), key=lambda item: item.timestamp)


def _mitre(*entries: tuple) -> List[Dict[str, str]]:
    return [{"tactic": t, "technique_id": tid, "technique": tec} for t, tid, tec in entries]


# ── Reputation-aware scoring helpers ────────────────────────────────────────

def _score_event_destination(scorer, log: ParsedLog) -> float:
    """Return the scorer's weight for the destination of this event.

    Absorbs scorer errors so a scoring exception on one event never breaks
    the detection loop.
    """
    if scorer is None:
        return 1.0
    try:
        # Extract domain if present in IOCs (for DNS-style events)
        dst_domain = None
        for itype, value in (log.iocs or []):
            if itype == "domain" and value:
                dst_domain = value
                break
        br = scorer.score_destination(
            src_ip=log.src_ip,
            dst_ip=log.dst_ip,
            dst_domain=dst_domain,
            dst_port=log.dst_port,
        )
        return float(br.weight)
    except Exception:
        return 1.0


def _score_dns_event(scorer, log: ParsedLog) -> Tuple[float, Optional[str]]:
    """Score a DNS query event. Returns (weight, query_name)."""
    if scorer is None:
        return 1.0, None
    # Import lazily to avoid circular deps
    try:
        from reputation import extract_domain_from_log
        query = extract_domain_from_log(log)
    except Exception:
        query = None
    if not query:
        return 1.0, None
    try:
        br = scorer.score_dns_query(src_ip=log.src_ip, query_name=query, qtype=None)
        return float(br.weight), query
    except Exception:
        return 1.0, query


def _shadow_record(
    *,
    rule_name: str,
    src_ip: Optional[str],
    dst_ip: Optional[str],
    would_fire: bool,
    risk_score: float,
    risk_threshold: float,
    volume: int,
    dos_floor: int,
    detection_mode: str,
    context_extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a reputation_shadow_events row dict. Main.py persists these."""
    return {
        "rule_name": rule_name,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "would_fire": bool(would_fire),
        "risk_score": round(float(risk_score), 3),
        "risk_threshold": round(float(risk_threshold), 3),
        "volume": int(volume),
        "dos_floor": int(dos_floor),
        "detection_mode": detection_mode,
        "context": context_extra or {},
    }


# ── Legacy check functions (unchanged, used as fallback in off mode) ────────

def check_brute_force(by_src: Dict[str, List[ParsedLog]], current: ParsedLog) -> Optional[Incident]:
    src = current.src_ip
    if not src:
        return None
    window = _recent(by_src.get(src, []), BRUTE_FORCE_WINDOW)
    failures = [event for event in window if _is_auth_failure(event)]
    if len(failures) < BRUTE_FORCE_THRESHOLD:
        return None
    targets = sorted({event.dst_ip or event.hostname for event in failures if event.dst_ip or event.hostname})
    accounts = sorted({event.username for event in failures if event.username})
    return build_incident(
        attack_type="brute_force",
        severity="high",
        title=f"Brute Force Login: {len(failures)} failures from {src}",
        description=f"Source IP {src} generated repeated authentication failures against {len(targets) or 1} target(s).",
        recommended_action="Block the source IP, enforce account lockout, and review targeted accounts for compromise.",
        logs=_dedupe_logs(failures),
        stage_map={"Credential Access": failures},
        mitre_attack=_mitre(("Credential Access", "T1110", "Brute Force")),
        metadata={"accounts": accounts, "target_hosts": targets},
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=targets[0] if targets else current.hostname,
    )


def check_password_spray(by_src: Dict[str, List[ParsedLog]], current: ParsedLog) -> Optional[Incident]:
    src = current.src_ip
    if not src:
        return None
    window = _recent(by_src.get(src, []), SPRAY_WINDOW)
    failures = [event for event in window if _is_auth_failure(event) and event.username]
    accounts = sorted({event.username for event in failures})
    if len(accounts) < SPRAY_ACCOUNTS_MIN:
        return None
    return build_incident(
        attack_type="password_spray",
        severity="high",
        title=f"Password Spray: {src} targeting {len(accounts)} accounts",
        description=f"Source IP {src} attempted authentication across many accounts in a short period.",
        recommended_action="Block the source IP, reset targeted accounts, and enable MFA for impacted users.",
        logs=_dedupe_logs(failures),
        stage_map={"Credential Access": failures},
        mitre_attack=_mitre(("Credential Access", "T1110.003", "Password Spraying")),
        metadata={"distinct_accounts": accounts},
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    )


def check_port_scan(by_src: Dict[str, List[ParsedLog]], current: ParsedLog) -> Optional[Incident]:
    src = current.src_ip
    if not src:
        return None
    window = _recent(by_src.get(src, []), PORT_SCAN_WINDOW)
    with_ports = [event for event in window if event.dst_port]
    distinct_ports = {event.dst_port for event in with_ports}
    if len(distinct_ports) < PORT_SCAN_PORTS_MIN:
        return None
    return build_incident(
        attack_type="port_scan",
        severity="medium",
        title=f"Port Scan: {src} probed {len(distinct_ports)} ports",
        description=f"Source IP {src} probed many distinct destination ports in a compressed time window.",
        recommended_action="Block or rate-limit the source IP and review exposed services for unnecessary exposure.",
        logs=_dedupe_logs(with_ports),
        stage_map={"Reconnaissance": with_ports},
        mitre_attack=_mitre(("Reconnaissance", "T1046", "Network Service Scanning")),
        metadata={"distinct_ports": sorted(distinct_ports)},
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    )


def check_repeated_blocked_connections(by_src: Dict[str, List[ParsedLog]], current: ParsedLog) -> Optional[Incident]:
    src = current.src_ip
    if not src:
        return None
    window = _recent(by_src.get(src, []), BLOCKED_CONN_WINDOW)
    blocked = [event for event in window if _is_blocked(event)]
    if len(blocked) < BLOCKED_CONN_THRESHOLD:
        return None
    targets = sorted({event.dst_ip for event in blocked if event.dst_ip})
    return build_incident(
        attack_type="repeated_blocked_connections",
        severity="medium",
        title=f"Repeated Blocked Connections: {src}",
        description=f"Source IP {src} triggered repeated blocked or denied connections consistent with probing or failed access attempts.",
        recommended_action="Inspect firewall decisions, block the source if malicious, and validate targeted services are intended to be reachable.",
        logs=_dedupe_logs(blocked),
        stage_map={"Reconnaissance": blocked},
        mitre_attack=_mitre(("Reconnaissance", "T1046", "Network Service Scanning")),
        metadata={"target_hosts": targets},
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    )


def check_lateral_movement(by_src: Dict[str, List[ParsedLog]], current: ParsedLog) -> Optional[Incident]:
    src = current.src_ip
    if not src or not is_private_ip(src):
        return None
    window = _recent(by_src.get(src, []), LATERAL_WINDOW)
    lateral = [
        event
        for event in window
        if event.dst_ip and is_private_ip(event.dst_ip) and event.dst_ip != src and (event.dst_port in LATERAL_PORTS or _is_auth_success(event))
    ]
    destinations = sorted({event.dst_ip for event in lateral})
    if len(destinations) < LATERAL_HOSTS_MIN:
        return None
    return build_incident(
        attack_type="lateral_movement",
        severity="high",
        title=f"Lateral Movement: {src} to {len(destinations)} hosts",
        description=f"Internal host {src} accessed multiple internal systems over management or authentication channels.",
        recommended_action="Isolate the source host, investigate all destination hosts, and rotate credentials involved in the activity.",
        logs=_dedupe_logs(lateral),
        stage_map={"Lateral Movement": lateral},
        mitre_attack=_mitre(("Lateral Movement", "T1021", "Remote Services")),
        metadata={"target_hosts": destinations, "ports": sorted({event.dst_port for event in lateral if event.dst_port})},
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=src,
    )


def check_malicious_ip_connection(
    by_dst: Dict[str, List[ParsedLog]],
    current: ParsedLog,
    ti_matched_ips: Optional[set] = None,
) -> Optional[Incident]:
    """Fire only when the destination IP is confirmed by a real TI lookup."""
    dst = current.dst_ip
    if not dst or not is_public_ip(dst):
        return None
    if not ti_matched_ips or dst not in ti_matched_ips:
        return None
    window = _recent(by_dst.get(dst, []), MALICIOUS_IP_WINDOW)
    related = [event for event in window if event.src_ip == current.src_ip or current.src_ip is None]
    if len(related) < MALICIOUS_IP_CONN_MIN:
        return None
    return build_incident(
        attack_type="malicious_ip_connection",
        severity="critical",
        title=f"Malicious IP Connection: {current.src_ip or 'host'} to {dst}",
        description=f"Repeated connections were observed to a destination referenced as malicious or threat-related in telemetry.",
        recommended_action="Block the destination IP, isolate the source host, and investigate any payload delivery or beaconing activity.",
        logs=_dedupe_logs(related),
        stage_map={"Command and Control": related},
        mitre_attack=_mitre(("Command and Control", "T1071", "Application Layer Protocol")),
        metadata={"malicious_destination": dst},
        source_ip=current.src_ip,
        destination_ip=dst,
        affected_host=current.hostname or current.src_ip,
    )


def check_c2_beaconing(by_dst: Dict[str, List[ParsedLog]], current: ParsedLog) -> Optional[Incident]:
    dst = current.dst_ip
    if not dst or not is_public_ip(dst):
        return None

    dst_port = current.dst_port
    if dst_port and int(dst_port) in C2_EXCLUDED_PORTS:
        return None
    if any(dst.startswith(prefix) for prefix in C2_SAFE_DST_PREFIXES):
        return None

    src = current.src_ip
    connections = _recent(by_dst.get(dst, []), C2_WINDOW)
    scoped = [event for event in connections if event.src_ip == src] if src else connections
    if len(scoped) < C2_CONN_MIN:
        return None
    timestamps = sorted(event.timestamp for event in scoped)
    intervals = [timestamps[index + 1] - timestamps[index] for index in range(len(timestamps) - 1)]
    if len(intervals) < 2:
        return None
    mean_interval = sum(intervals) / len(intervals)
    if mean_interval <= 0:
        return None
    try:
        jitter = statistics.stdev(intervals) / mean_interval
    except statistics.StatisticsError:
        jitter = 1.0
    if jitter > C2_MAX_JITTER:
        return None
    return build_incident(
        attack_type="c2_beaconing",
        severity="critical",
        title=f"C2 Beaconing: {src or 'host'} to {dst}",
        description=f"Regular interval outbound communication suggests beaconing to external destination {dst}.",
        recommended_action="Block the destination, isolate the host, and investigate for malware or remote control implants.",
        logs=_dedupe_logs(scoped),
        stage_map={"Command and Control": scoped},
        mitre_attack=_mitre(("Command and Control", "T1071", "Application Layer Protocol")),
        metadata={"mean_interval_sec": round(mean_interval, 1), "jitter_pct": round(jitter * 100, 1)},
        source_ip=src,
        destination_ip=dst,
        affected_host=current.hostname or src,
    )


def check_host_discovery(by_src: Dict[str, List[ParsedLog]], current: ParsedLog) -> Optional[Incident]:
    """Detect ping sweeps / host discovery: one source hitting many distinct destinations."""
    src = current.src_ip
    if not src:
        return None
    window = _recent(by_src.get(src, []), HOST_DISCOVERY_WINDOW)
    candidates = [
        event for event in window
        if event.dst_ip and event.dst_ip != src
        and (
            (event.protocol and event.protocol.lower() == "icmp")
            or _is_blocked(event)
            or event.action in {"allow", "allowed", "accept", "accepted", "pass", "passed", "permit", "permitted"}
        )
    ]
    distinct_targets = {event.dst_ip for event in candidates}
    if len(distinct_targets) < HOST_DISCOVERY_TARGETS_MIN:
        return None
    return build_incident(
        attack_type="host_discovery",
        severity="medium",
        title=f"Host Discovery / Ping Sweep: {src} probed {len(distinct_targets)} hosts",
        description=f"Source IP {src} contacted {len(distinct_targets)} distinct destination IPs in a short window, consistent with network host discovery or ping sweep reconnaissance.",
        recommended_action="Investigate the source host for unauthorized scanning tools. Block the source IP if external. Review network segmentation.",
        logs=_dedupe_logs(candidates),
        stage_map={"Reconnaissance": candidates},
        mitre_attack=_mitre(
            ("Reconnaissance", "T1046", "Network Service Scanning"),
            ("Discovery", "T1018", "Remote System Discovery"),
        ),
        metadata={"distinct_targets": sorted(distinct_targets), "target_count": len(distinct_targets)},
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    )


def check_service_scan(by_src: Dict[str, List[ParsedLog]], current: ParsedLog) -> Optional[Incident]:
    """Detect Nmap-style service scanning: connections to well-known service ports across multiple hosts."""
    src = current.src_ip
    if not src:
        return None
    window = _recent(by_src.get(src, []), SERVICE_SCAN_WINDOW)
    service_hits = [
        event for event in window
        if event.dst_ip and event.dst_port and event.dst_port in SERVICE_SCAN_PORTS
        and event.dst_ip != src
    ]
    distinct_hosts = {event.dst_ip for event in service_hits}
    distinct_ports = {event.dst_port for event in service_hits}
    if len(distinct_hosts) < SERVICE_SCAN_HOSTS_MIN:
        return None
    return build_incident(
        attack_type="service_scan",
        severity="high",
        title=f"Service Scan: {src} scanning {len(distinct_ports)} services across {len(distinct_hosts)} hosts",
        description=f"Source IP {src} probed well-known service ports ({', '.join(str(p) for p in sorted(distinct_ports)[:10])}) across {len(distinct_hosts)} distinct hosts, consistent with Nmap service scanning.",
        recommended_action="Block the source IP immediately. Audit exposed services. Check for follow-up exploitation attempts from this source.",
        logs=_dedupe_logs(service_hits),
        stage_map={"Reconnaissance": service_hits},
        mitre_attack=_mitre(
            ("Reconnaissance", "T1046", "Network Service Scanning"),
            ("Discovery", "T1046", "Network Service Discovery"),
        ),
        metadata={
            "distinct_hosts": sorted(distinct_hosts),
            "scanned_ports": sorted(distinct_ports),
            "host_count": len(distinct_hosts),
        },
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    )


def check_repeated_connection_attempts(by_src: Dict[str, List[ParsedLog]], current: ParsedLog) -> Optional[Incident]:
    """Detect repeated connection attempts from the same source (reset, refused, timeout)."""
    src = current.src_ip
    if not src:
        return None
    window = _recent(by_src.get(src, []), REPEATED_CONN_ATTEMPTS_WINDOW)
    failed_conns = [
        event for event in window
        if event.status in {"failed", "refused", "reset", "timeout", "error"}
        or event.action in {"deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected"}
        or (event.raw and re.search(r'\b(?:reset|refused|timeout|RST|FIN|connection\s+refused)\b', event.raw, re.I))
    ]
    if len(failed_conns) < REPEATED_CONN_ATTEMPTS_MIN:
        return None
    targets = sorted({event.dst_ip for event in failed_conns if event.dst_ip})
    ports = sorted({event.dst_port for event in failed_conns if event.dst_port})
    return build_incident(
        attack_type="repeated_connection_attempts",
        severity="medium",
        title=f"Repeated Failed Connections: {src} ({len(failed_conns)} attempts)",
        description=f"Source IP {src} generated {len(failed_conns)} failed, refused, or reset connection attempts targeting {len(targets)} host(s), consistent with scanning or unauthorized access attempts.",
        recommended_action="Investigate the source. If external, consider blocking. Review targeted services for exposure.",
        logs=_dedupe_logs(failed_conns),
        stage_map={"Reconnaissance": failed_conns},
        mitre_attack=_mitre(("Reconnaissance", "T1046", "Network Service Scanning")),
        metadata={"target_hosts": targets, "target_ports": ports},
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    )


def check_multi_stage_attack(by_src: Dict[str, List[ParsedLog]], by_user: Dict[str, List[ParsedLog]], current: ParsedLog) -> Optional[Incident]:
    src = current.src_ip
    if not src:
        return None
    window = _recent(by_src.get(src, []), 3600)
    recon = [event for event in window if event.dst_port and (_is_blocked(event) or len({e.dst_port for e in window if e.dst_port}) >= 10)]
    exploit = [event for event in window if EXPLOIT_RE.search(event.raw)]
    success = [event for event in window if _is_auth_success(event)]
    user_events = _recent(by_user.get(current.username, []), 3600) if current.username else []
    privilege = [event for event in (window + user_events) if PRIV_ESC_RE.search(event.raw)]
    if not recon or not exploit or not success or not privilege:
        return None
    combined = _dedupe_logs(recon + exploit + success + privilege)
    stages = {
        "Reconnaissance": recon,
        "Exploit Attempt": exploit,
        "Login Success": success,
        "Privilege Escalation": privilege,
    }
    return build_incident(
        attack_type="multi_stage_attack",
        severity="critical",
        title=f"Multi-Stage Attack Sequence from {src}",
        description="Correlated telemetry shows reconnaissance followed by exploit activity, successful authentication, and privilege escalation.",
        recommended_action="Escalate to incident response immediately, isolate involved hosts, reset accounts, and preserve forensic evidence.",
        logs=combined,
        stage_map=stages,
        mitre_attack=_mitre(
            ("Reconnaissance", "T1046", "Network Service Scanning"),
            ("Initial Access", "T1190", "Exploit Public-Facing Application"),
            ("Credential Access", "T1078", "Valid Accounts"),
            ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
        ),
        metadata={"stage_count": 4},
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname or src,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Reputation-aware detectors (Milestone 2)
# ═══════════════════════════════════════════════════════════════════════════
#
# Each detector returns a 2-tuple (Optional[Incident], Optional[shadow_record]).
# The shadow record is ALWAYS written when mode == 'shadow' and the volume
# threshold has been crossed, regardless of whether the incident was produced.
# This lets operators measure the suppression delta before flipping to enforce.


def _reputation_port_scan(
    by_src: Dict[str, List[ParsedLog]],
    current: ParsedLog,
    scorer,
    config: ReputationConfig,
) -> Tuple[Optional[Incident], Optional[Dict[str, Any]]]:
    src = current.src_ip
    if not src:
        return None, None
    window = _recent(by_src.get(src, []), PORT_SCAN_WINDOW)
    with_ports = [e for e in window if e.dst_port]
    distinct_ports = {e.dst_port for e in with_ports}
    volume = len(distinct_ports)
    # Skip entirely below the legacy count threshold — nothing interesting yet
    if volume < PORT_SCAN_PORTS_MIN:
        return None, None

    dos_floor = config.dos_floor("port_scan", _DEFAULT_DOS_FLOORS["port_scan"])
    risk_thr = config.risk_threshold("port_scan", _DEFAULT_RISK_THRESHOLDS["port_scan"])

    # Aggregate per-destination reputation across all events in window
    # Weighted risk = sum over distinct destinations of their reputation weight.
    # Unique destinations matter more than raw event count for scanning.
    dst_weights: Dict[str, float] = {}
    for e in with_ports:
        if not e.dst_ip:
            continue
        if e.dst_ip in dst_weights:
            continue
        dst_weights[e.dst_ip] = _score_event_destination(scorer, e)
    risk_score = sum(dst_weights.values())

    volumetric_fire = volume >= dos_floor
    reputation_fire = risk_score >= risk_thr
    new_would_fire = volumetric_fire or reputation_fire

    # Build the incident payload (used when new logic fires or legacy fires)
    incident = build_incident(
        attack_type="port_scan",
        severity="high" if volumetric_fire else "medium",
        title=f"Port Scan: {src} probed {volume} ports (risk={risk_score:.1f})",
        description=(
            f"Source IP {src} probed {volume} distinct destination ports in a "
            f"compressed time window. Reputation-weighted risk score: {risk_score:.1f} "
            f"(threshold {risk_thr:.1f}; DoS floor {dos_floor})."
        ),
        recommended_action="Block or rate-limit the source IP and review exposed services.",
        logs=_dedupe_logs(with_ports),
        stage_map={"Reconnaissance": with_ports},
        mitre_attack=_mitre(("Reconnaissance", "T1046", "Network Service Scanning")),
        metadata={
            "distinct_ports": sorted(distinct_ports),
            "risk_score": round(risk_score, 2),
            "risk_threshold": risk_thr,
            "dos_floor": dos_floor,
            "volumetric": volumetric_fire,
        },
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    ) if new_would_fire else None

    shadow = _shadow_record(
        rule_name="port_scan",
        src_ip=src,
        dst_ip=current.dst_ip,
        would_fire=new_would_fire,
        risk_score=risk_score,
        risk_threshold=risk_thr,
        volume=volume,
        dos_floor=dos_floor,
        detection_mode=config.mode,
        context_extra={
            "volumetric_fire": volumetric_fire,
            "reputation_fire": reputation_fire,
            "distinct_destinations": len(dst_weights),
        },
    )
    return incident, shadow


def _reputation_host_discovery(
    by_src: Dict[str, List[ParsedLog]],
    current: ParsedLog,
    scorer,
    config: ReputationConfig,
) -> Tuple[Optional[Incident], Optional[Dict[str, Any]]]:
    src = current.src_ip
    if not src:
        return None, None
    window = _recent(by_src.get(src, []), HOST_DISCOVERY_WINDOW)
    candidates = [
        e for e in window
        if e.dst_ip and e.dst_ip != src
        and (
            (e.protocol and e.protocol.lower() == "icmp")
            or _is_blocked(e)
            or e.action in {"allow", "allowed", "accept", "accepted", "pass", "passed", "permit", "permitted"}
        )
    ]
    distinct_targets = {e.dst_ip for e in candidates}
    volume = len(distinct_targets)
    if volume < HOST_DISCOVERY_TARGETS_MIN:
        return None, None

    dos_floor = config.dos_floor("host_discovery", _DEFAULT_DOS_FLOORS["host_discovery"])
    risk_thr = config.risk_threshold("host_discovery", _DEFAULT_RISK_THRESHOLDS["host_discovery"])

    dst_weights: Dict[str, float] = {}
    for e in candidates:
        if e.dst_ip in dst_weights:
            continue
        dst_weights[e.dst_ip] = _score_event_destination(scorer, e)
    risk_score = sum(dst_weights.values())

    volumetric_fire = volume >= dos_floor
    reputation_fire = risk_score >= risk_thr
    new_would_fire = volumetric_fire or reputation_fire

    incident = build_incident(
        attack_type="host_discovery",
        severity="high" if volumetric_fire else "medium",
        title=f"Host Discovery: {src} probed {volume} hosts (risk={risk_score:.1f})",
        description=(
            f"Source IP {src} contacted {volume} distinct destination IPs in a short "
            f"window. Reputation-weighted risk score: {risk_score:.1f} (threshold "
            f"{risk_thr:.1f}; DoS floor {dos_floor})."
        ),
        recommended_action="Investigate the source host for unauthorized scanning tools. Block if external.",
        logs=_dedupe_logs(candidates),
        stage_map={"Reconnaissance": candidates},
        mitre_attack=_mitre(
            ("Reconnaissance", "T1046", "Network Service Scanning"),
            ("Discovery", "T1018", "Remote System Discovery"),
        ),
        metadata={
            "distinct_targets": sorted(distinct_targets),
            "target_count": volume,
            "risk_score": round(risk_score, 2),
            "risk_threshold": risk_thr,
            "dos_floor": dos_floor,
            "volumetric": volumetric_fire,
        },
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    ) if new_would_fire else None

    shadow = _shadow_record(
        rule_name="host_discovery",
        src_ip=src,
        dst_ip=current.dst_ip,
        would_fire=new_would_fire,
        risk_score=risk_score,
        risk_threshold=risk_thr,
        volume=volume,
        dos_floor=dos_floor,
        detection_mode=config.mode,
        context_extra={
            "volumetric_fire": volumetric_fire,
            "reputation_fire": reputation_fire,
            "distinct_destinations": len(dst_weights),
        },
    )
    return incident, shadow


def _reputation_service_scan(
    by_src: Dict[str, List[ParsedLog]],
    current: ParsedLog,
    scorer,
    config: ReputationConfig,
) -> Tuple[Optional[Incident], Optional[Dict[str, Any]]]:
    src = current.src_ip
    if not src:
        return None, None
    window = _recent(by_src.get(src, []), SERVICE_SCAN_WINDOW)
    service_hits = [
        e for e in window
        if e.dst_ip and e.dst_port and e.dst_port in SERVICE_SCAN_PORTS
        and e.dst_ip != src
    ]
    distinct_hosts = {e.dst_ip for e in service_hits}
    distinct_ports = {e.dst_port for e in service_hits}
    volume = len(distinct_hosts)
    if volume < SERVICE_SCAN_HOSTS_MIN:
        return None, None

    dos_floor = config.dos_floor("service_scan", _DEFAULT_DOS_FLOORS["service_scan"])
    risk_thr = config.risk_threshold("service_scan", _DEFAULT_RISK_THRESHOLDS["service_scan"])

    dst_weights: Dict[str, float] = {}
    for e in service_hits:
        if e.dst_ip in dst_weights:
            continue
        dst_weights[e.dst_ip] = _score_event_destination(scorer, e)
    risk_score = sum(dst_weights.values())

    volumetric_fire = volume >= dos_floor
    reputation_fire = risk_score >= risk_thr
    new_would_fire = volumetric_fire or reputation_fire

    incident = build_incident(
        attack_type="service_scan",
        severity="high",
        title=f"Service Scan: {src} scanning {len(distinct_ports)} services across {volume} hosts (risk={risk_score:.1f})",
        description=(
            f"Source IP {src} probed well-known service ports "
            f"({', '.join(str(p) for p in sorted(distinct_ports)[:10])}) across {volume} hosts. "
            f"Reputation-weighted risk score: {risk_score:.1f} (threshold {risk_thr:.1f}; "
            f"DoS floor {dos_floor})."
        ),
        recommended_action="Block the source IP immediately. Audit exposed services.",
        logs=_dedupe_logs(service_hits),
        stage_map={"Reconnaissance": service_hits},
        mitre_attack=_mitre(
            ("Reconnaissance", "T1046", "Network Service Scanning"),
            ("Discovery", "T1046", "Network Service Discovery"),
        ),
        metadata={
            "distinct_hosts": sorted(distinct_hosts),
            "scanned_ports": sorted(distinct_ports),
            "host_count": volume,
            "risk_score": round(risk_score, 2),
            "risk_threshold": risk_thr,
            "dos_floor": dos_floor,
            "volumetric": volumetric_fire,
        },
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    ) if new_would_fire else None

    shadow = _shadow_record(
        rule_name="service_scan",
        src_ip=src,
        dst_ip=current.dst_ip,
        would_fire=new_would_fire,
        risk_score=risk_score,
        risk_threshold=risk_thr,
        volume=volume,
        dos_floor=dos_floor,
        detection_mode=config.mode,
        context_extra={
            "volumetric_fire": volumetric_fire,
            "reputation_fire": reputation_fire,
            "distinct_destinations": len(dst_weights),
            "scanned_ports": sorted(distinct_ports),
        },
    )
    return incident, shadow


def _reputation_repeated_conn(
    by_src: Dict[str, List[ParsedLog]],
    current: ParsedLog,
    scorer,
    config: ReputationConfig,
) -> Tuple[Optional[Incident], Optional[Dict[str, Any]]]:
    src = current.src_ip
    if not src:
        return None, None
    window = _recent(by_src.get(src, []), REPEATED_CONN_ATTEMPTS_WINDOW)
    failed_conns = [
        e for e in window
        if e.status in {"failed", "refused", "reset", "timeout", "error"}
        or e.action in {"deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected"}
        or (e.raw and re.search(r'\b(?:reset|refused|timeout|RST|FIN|connection\s+refused)\b', e.raw, re.I))
    ]
    volume = len(failed_conns)
    if volume < REPEATED_CONN_ATTEMPTS_MIN:
        return None, None

    dos_floor = config.dos_floor("repeated_connection_attempts", _DEFAULT_DOS_FLOORS["repeated_connection_attempts"])
    risk_thr = config.risk_threshold("repeated_connection_attempts", _DEFAULT_RISK_THRESHOLDS["repeated_connection_attempts"])

    # Use distinct destinations for reputation scoring — scanning chatter against
    # one known-good dest shouldn't stack to a higher score than chatter
    # against multiple unknown ones.
    dst_weights: Dict[str, float] = {}
    for e in failed_conns:
        if not e.dst_ip or e.dst_ip in dst_weights:
            continue
        dst_weights[e.dst_ip] = _score_event_destination(scorer, e)
    risk_score = sum(dst_weights.values())

    volumetric_fire = volume >= dos_floor
    reputation_fire = risk_score >= risk_thr
    new_would_fire = volumetric_fire or reputation_fire

    targets = sorted({e.dst_ip for e in failed_conns if e.dst_ip})
    ports = sorted({e.dst_port for e in failed_conns if e.dst_port})

    incident = build_incident(
        attack_type="repeated_connection_attempts",
        severity="medium",
        title=f"Repeated Failed Connections: {src} ({volume} attempts, risk={risk_score:.1f})",
        description=(
            f"Source IP {src} generated {volume} failed/refused/reset connection attempts "
            f"targeting {len(targets)} host(s). Reputation-weighted risk score: "
            f"{risk_score:.1f} (threshold {risk_thr:.1f}; DoS floor {dos_floor})."
        ),
        recommended_action="Investigate the source. If external, consider blocking.",
        logs=_dedupe_logs(failed_conns),
        stage_map={"Reconnaissance": failed_conns},
        mitre_attack=_mitre(("Reconnaissance", "T1046", "Network Service Scanning")),
        metadata={
            "target_hosts": targets,
            "target_ports": ports,
            "risk_score": round(risk_score, 2),
            "risk_threshold": risk_thr,
            "dos_floor": dos_floor,
            "volumetric": volumetric_fire,
        },
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    ) if new_would_fire else None

    shadow = _shadow_record(
        rule_name="repeated_connection_attempts",
        src_ip=src,
        dst_ip=current.dst_ip,
        would_fire=new_would_fire,
        risk_score=risk_score,
        risk_threshold=risk_thr,
        volume=volume,
        dos_floor=dos_floor,
        detection_mode=config.mode,
        context_extra={
            "volumetric_fire": volumetric_fire,
            "reputation_fire": reputation_fire,
            "distinct_destinations": len(dst_weights),
        },
    )
    return incident, shadow


def _reputation_blocked_conn(
    by_src: Dict[str, List[ParsedLog]],
    current: ParsedLog,
    scorer,
    config: ReputationConfig,
) -> Tuple[Optional[Incident], Optional[Dict[str, Any]]]:
    src = current.src_ip
    if not src:
        return None, None
    window = _recent(by_src.get(src, []), BLOCKED_CONN_WINDOW)
    blocked = [e for e in window if _is_blocked(e)]
    volume = len(blocked)
    if volume < BLOCKED_CONN_THRESHOLD:
        return None, None

    dos_floor = config.dos_floor("repeated_blocked_connections", _DEFAULT_DOS_FLOORS["repeated_blocked_connections"])
    risk_thr = config.risk_threshold("repeated_blocked_connections", _DEFAULT_RISK_THRESHOLDS["repeated_blocked_connections"])

    dst_weights: Dict[str, float] = {}
    for e in blocked:
        if not e.dst_ip or e.dst_ip in dst_weights:
            continue
        dst_weights[e.dst_ip] = _score_event_destination(scorer, e)
    risk_score = sum(dst_weights.values())

    volumetric_fire = volume >= dos_floor
    reputation_fire = risk_score >= risk_thr
    new_would_fire = volumetric_fire or reputation_fire

    targets = sorted({e.dst_ip for e in blocked if e.dst_ip})

    incident = build_incident(
        attack_type="repeated_blocked_connections",
        severity="medium",
        title=f"Repeated Blocked Connections: {src} (risk={risk_score:.1f})",
        description=(
            f"Source IP {src} triggered {volume} blocked/denied connections. "
            f"Reputation-weighted risk score: {risk_score:.1f} (threshold "
            f"{risk_thr:.1f}; DoS floor {dos_floor})."
        ),
        recommended_action="Inspect firewall decisions and block the source if malicious.",
        logs=_dedupe_logs(blocked),
        stage_map={"Reconnaissance": blocked},
        mitre_attack=_mitre(("Reconnaissance", "T1046", "Network Service Scanning")),
        metadata={
            "target_hosts": targets,
            "risk_score": round(risk_score, 2),
            "risk_threshold": risk_thr,
            "dos_floor": dos_floor,
            "volumetric": volumetric_fire,
        },
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    ) if new_would_fire else None

    shadow = _shadow_record(
        rule_name="repeated_blocked_connections",
        src_ip=src,
        dst_ip=current.dst_ip,
        would_fire=new_would_fire,
        risk_score=risk_score,
        risk_threshold=risk_thr,
        volume=volume,
        dos_floor=dos_floor,
        detection_mode=config.mode,
        context_extra={
            "volumetric_fire": volumetric_fire,
            "reputation_fire": reputation_fire,
            "distinct_destinations": len(dst_weights),
        },
    )
    return incident, shadow


def _reputation_dns_tunneling(
    by_src: Dict[str, List[ParsedLog]],
    current: ParsedLog,
    scorer,
    config: ReputationConfig,
) -> Tuple[Optional[Incident], Optional[Dict[str, Any]]]:
    """Reputation-aware DNS tunneling detector.

    Replaces the count-only YAML rule which fired at >=50 UDP/53 queries —
    the largest source of false positives prior to Milestone 2.
    """
    src = current.src_ip
    if not src:
        return None, None

    window = _recent(by_src.get(src, []), DNS_TUNNELING_WINDOW)
    # DNS queries: dst_port=53 (udp/tcp), or dns protocol marker
    dns_events = [
        e for e in window
        if (e.dst_port == 53) or (e.protocol and e.protocol.lower() in ("dns", "udp") and e.dst_port == 53)
    ]
    volume = len(dns_events)
    if volume < DNS_TUNNELING_COUNT_MIN:
        return None, None

    dos_floor = config.dos_floor("dns_tunneling", _DEFAULT_DOS_FLOORS["dns_tunneling"])
    risk_thr = config.risk_threshold("dns_tunneling", _DEFAULT_RISK_THRESHOLDS["dns_tunneling"])

    # Score each distinct query name once; sum the weights.
    query_weights: Dict[str, float] = {}
    distinct_queries: set = set()
    for e in dns_events:
        w, q = _score_dns_event(scorer, e)
        if q is None:
            continue
        distinct_queries.add(q)
        if q in query_weights:
            continue
        query_weights[q] = w
    risk_score = sum(query_weights.values())

    volumetric_fire = volume >= dos_floor
    reputation_fire = risk_score >= risk_thr
    new_would_fire = volumetric_fire or reputation_fire

    incident = build_incident(
        attack_type="dns_tunneling",
        severity="high",
        title=f"DNS Tunneling Suspected: {src} ({volume} queries, risk={risk_score:.1f})",
        description=(
            f"Source IP {src} generated {volume} DNS queries within {DNS_TUNNELING_WINDOW}s "
            f"across {len(distinct_queries)} distinct names. Reputation-weighted risk "
            f"score: {risk_score:.1f} (threshold {risk_thr:.1f}; DoS floor {dos_floor} "
            f"queries). High-entropy / long-label / uncommon-TLD / newly-seen domains "
            f"contribute most to the score."
        ),
        recommended_action="Analyze DNS query payloads for encoded data. Block the source if tunneling is confirmed.",
        logs=_dedupe_logs(dns_events),
        stage_map={"Command and Control": dns_events},
        mitre_attack=_mitre(
            ("Command and Control", "T1071.004", "DNS"),
            ("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol"),
        ),
        metadata={
            "query_count": volume,
            "distinct_queries": len(distinct_queries),
            "risk_score": round(risk_score, 2),
            "risk_threshold": risk_thr,
            "dos_floor": dos_floor,
            "volumetric": volumetric_fire,
        },
        source_ip=src,
        destination_ip=current.dst_ip,
        affected_host=current.hostname,
    ) if new_would_fire else None

    shadow = _shadow_record(
        rule_name="dns_tunneling",
        src_ip=src,
        dst_ip=current.dst_ip,
        would_fire=new_would_fire,
        risk_score=risk_score,
        risk_threshold=risk_thr,
        volume=volume,
        dos_floor=dos_floor,
        detection_mode=config.mode,
        context_extra={
            "volumetric_fire": volumetric_fire,
            "reputation_fire": reputation_fire,
            "distinct_queries": len(distinct_queries),
        },
    )
    return incident, shadow


# ═══════════════════════════════════════════════════════════════════════════
# Evaluate — orchestrator
# ═══════════════════════════════════════════════════════════════════════════

_REPUTATION_RULE_NAMES = {
    "port_scan", "host_discovery", "service_scan",
    "repeated_connection_attempts", "repeated_blocked_connections",
    "dns_tunneling",
}


def evaluate(
    by_src: Dict[str, List[ParsedLog]],
    by_dst: Dict[str, List[ParsedLog]],
    by_user: Dict[str, List[ParsedLog]],
    current: ParsedLog,
    ti_matched_ips: Optional[set] = None,
    scorer=None,
    reputation_config: Optional[ReputationConfig] = None,
) -> Tuple[List[Incident], List[Dict[str, Any]]]:
    """Evaluate all rules; return (incidents, shadow_records).

    Shadow records are produced only for the reputation-aware rules when
    `reputation_config.mode` is 'shadow' or 'enforce'. In 'off' (default)
    or when scorer is None, behavior is byte-identical to the legacy path
    and an empty shadow list is returned.
    """
    config = reputation_config or ReputationConfig()
    use_reputation = scorer is not None and config.mode in ("shadow", "enforce")

    incidents: List[Incident] = []
    shadows: List[Dict[str, Any]] = []

    # Always run: auth + TI + C2 + multi-stage + lateral (not reputation-aware)
    for inc in (
        check_brute_force(by_src, current),
        check_password_spray(by_src, current),
        check_lateral_movement(by_src, current),
        check_malicious_ip_connection(by_dst, current, ti_matched_ips=ti_matched_ips),
        check_c2_beaconing(by_dst, current),
        check_multi_stage_attack(by_src, by_user, current),
    ):
        if inc:
            incidents.append(inc)

    # Reputation-aware rules
    if use_reputation:
        for runner in (
            _reputation_port_scan,
            _reputation_host_discovery,
            _reputation_service_scan,
            _reputation_repeated_conn,
            _reputation_blocked_conn,
            _reputation_dns_tunneling,
        ):
            try:
                new_inc, shadow = runner(by_src, current, scorer, config)
            except Exception:
                # Never let scoring break detection — fall through to legacy path
                new_inc, shadow = None, None
            if shadow:
                shadows.append(shadow)
            if config.mode == "enforce" and new_inc:
                incidents.append(new_inc)
        # In shadow mode: legacy count-based alerts still drive the real pipeline
        if config.mode == "shadow":
            for legacy in (
                check_port_scan(by_src, current),
                check_host_discovery(by_src, current),
                check_service_scan(by_src, current),
                check_repeated_connection_attempts(by_src, current),
                check_repeated_blocked_connections(by_src, current),
            ):
                if legacy:
                    incidents.append(legacy)
            # dns_tunneling is driven by the YAML rule in shadow mode; our
            # reputation detector above only writes a shadow event.
    else:
        # Legacy path — exactly preserves pre-M2 behavior
        for legacy in (
            check_port_scan(by_src, current),
            check_host_discovery(by_src, current),
            check_service_scan(by_src, current),
            check_repeated_connection_attempts(by_src, current),
            check_repeated_blocked_connections(by_src, current),
        ):
            if legacy:
                incidents.append(legacy)

    return incidents, shadows
