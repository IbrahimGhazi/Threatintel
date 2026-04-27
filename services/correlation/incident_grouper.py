"""
Incident Grouper – groups related alerts into security incidents.

After each alert is created, this module checks whether the alert belongs
to an existing open incident (same source_ip within a time window) or
whether a new incident should be created.

Rule-to-incident-type mapping:
  - port_scan + host_discovery + service_scan + repeated_connection_attempts -> Network Reconnaissance
  - brute_force + password_spray                                            -> Credential Attack
  - lateral_movement + suspicious_rdp_burst                                 -> Lateral Movement
  - c2_beaconing + malicious_ip_connection                                  -> Command & Control
  - dns_tunneling + outbound_data_burst                                     -> Data Exfiltration
"""

import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import asyncpg
import orjson

logger = logging.getLogger("correlation.incident_grouper")

# Default time window for grouping alerts into the same incident (seconds)
INCIDENT_WINDOW_SECS = int(__import__("os").getenv("INCIDENT_WINDOW_SECS", "1800"))  # 30 min

# Severity ordering for promotion (highest alert severity wins)
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_NAMES = {v: k for k, v in SEVERITY_ORDER.items()}

# ── Rule-to-incident-type mapping ────────────────────────────────────────────

INCIDENT_TYPE_MAP: Dict[str, str] = {
    "port_scan":                     "Network Reconnaissance",
    "host_discovery":                "Network Reconnaissance",
    "service_scan":                  "Network Reconnaissance",
    "repeated_connection_attempts":  "Network Reconnaissance",
    "brute_force":                   "Credential Attack",
    "password_spray":                "Credential Attack",
    "lateral_movement":              "Lateral Movement",
    "suspicious_rdp_burst":          "Lateral Movement",
    "c2_beaconing":                  "Command & Control",
    "malicious_ip_connection":       "Command & Control",
    "dns_tunneling":                 "Data Exfiltration",
    "outbound_data_burst":           "Data Exfiltration",
}

# MITRE tactic defaults by incident type
INCIDENT_MITRE_DEFAULTS: Dict[str, List[str]] = {
    "Network Reconnaissance": ["TA0043 - Reconnaissance", "TA0007 - Discovery"],
    "Credential Attack":      ["TA0006 - Credential Access", "TA0001 - Initial Access"],
    "Lateral Movement":       ["TA0008 - Lateral Movement"],
    "Command & Control":      ["TA0011 - Command and Control"],
    "Data Exfiltration":      ["TA0010 - Exfiltration"],
}


def _get_incident_type(rule_name: str) -> str:
    """Map a rule_name to a high-level incident type."""
    return INCIDENT_TYPE_MAP.get(rule_name, "Security Incident")


def _max_severity(sev_a: str, sev_b: str) -> str:
    """Return the higher of two severity levels."""
    a = SEVERITY_ORDER.get(sev_a, 2)
    b = SEVERITY_ORDER.get(sev_b, 2)
    return SEVERITY_NAMES.get(max(a, b), "medium")


def _merge_mitre_tactics(existing: List[str], new_tactics: List[str]) -> List[str]:
    """Merge MITRE tactic lists, deduplicating."""
    seen = set(existing)
    merged = list(existing)
    for t in new_tactics:
        if t not in seen:
            merged.append(t)
            seen.add(t)
    return merged


def _extract_mitre_from_context(context: Dict[str, Any]) -> List[str]:
    """Pull MITRE tactic strings from an alert's context JSON."""
    tactics: List[str] = []
    mitre_list = context.get("mitre_attack", [])
    if isinstance(mitre_list, list):
        for entry in mitre_list:
            if isinstance(entry, dict):
                tactic = entry.get("tactic", "")
                technique_id = entry.get("technique_id", "")
                if tactic:
                    label = f"{technique_id} - {tactic}" if technique_id else tactic
                    tactics.append(label)
    return tactics


async def assign_alert_to_incident(
    pool: asyncpg.Pool,
    alert_id: str,
    rule_name: str,
    severity: str,
    source_ip: Optional[str],
    context: Dict[str, Any],
) -> Optional[str]:
    """
    Assign an alert to an existing or new incident.

    Groups alerts by source_ip within INCIDENT_WINDOW_SECS.  If an open
    incident already exists for the same source_ip and incident type within
    the window, the alert is added to it.  Otherwise a new incident is created.

    Returns the incident UUID string, or None on failure.
    """
    if not pool:
        return None

    incident_type = _get_incident_type(rule_name)
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=INCIDENT_WINDOW_SECS)

    # Extract MITRE tactics from the alert context, falling back to defaults
    alert_tactics = _extract_mitre_from_context(context)
    if not alert_tactics:
        alert_tactics = INCIDENT_MITRE_DEFAULTS.get(incident_type, [])

    try:
        # Look for an existing open incident for this source_ip + type within the window
        existing = None
        if source_ip:
            existing = await pool.fetchrow(
                """
                SELECT id, severity, mitre_tactics, total_events, first_seen
                FROM incidents
                WHERE source_ip = $1
                  AND attack_type = $2
                  AND status IN ('open', 'investigating')
                  AND last_seen >= $3
                ORDER BY last_seen DESC
                LIMIT 1
                """,
                source_ip,
                incident_type,
                window_start,
            )

        if existing:
            # Merge into existing incident
            incident_id = str(existing["id"])
            new_severity = _max_severity(existing["severity"], severity)
            old_tactics = list(existing["mitre_tactics"]) if existing["mitre_tactics"] else []
            merged_tactics = _merge_mitre_tactics(old_tactics, alert_tactics)
            new_total = existing["total_events"] + 1

            await pool.execute(
                """
                UPDATE incidents
                SET severity     = CAST($1 AS severity_level),
                    mitre_tactics = $2,
                    total_events = $3,
                    last_seen    = NOW(),
                    updated_at   = NOW()
                WHERE id = $4::uuid
                """,
                new_severity,
                merged_tactics,
                new_total,
                incident_id,
            )

            # Link the alert to this incident
            await pool.execute(
                "UPDATE alerts SET incident_id = $1::uuid WHERE id = $2::uuid",
                incident_id,
                alert_id,
            )

            logger.info(
                "Alert %s merged into incident %s (type=%s, events=%d)",
                alert_id, incident_id, incident_type, new_total,
            )
            return incident_id

        else:
            # Create a new incident
            title = f"{incident_type}: {source_ip or 'Unknown Source'}"
            description = (
                f"Automated incident grouping for {incident_type.lower()} activity"
                f"{' from ' + source_ip if source_ip else ''}. "
                f"Initial trigger: {rule_name.replace('_', ' ')}."
            )

            incident_id = await pool.fetchval(
                """
                INSERT INTO incidents
                    (id, title, description, severity, status,
                     source_ip, attack_type, mitre_tactics,
                     total_events, first_seen, last_seen)
                VALUES
                    (gen_random_uuid(), $1, $2,
                     CAST($3 AS severity_level), 'open',
                     $4, $5, $6,
                     1, NOW(), NOW())
                RETURNING id
                """,
                title,
                description,
                severity,
                source_ip,
                incident_type,
                alert_tactics,
            )

            if incident_id:
                incident_id_str = str(incident_id)
                # Link the alert
                await pool.execute(
                    "UPDATE alerts SET incident_id = $1::uuid WHERE id = $2::uuid",
                    incident_id_str,
                    alert_id,
                )
                logger.info(
                    "New incident %s created (type=%s, source=%s, trigger=%s)",
                    incident_id_str, incident_type, source_ip, rule_name,
                )
                return incident_id_str

    except Exception as exc:
        logger.error("Incident grouper failed for alert %s: %s", alert_id, exc)

    return None
