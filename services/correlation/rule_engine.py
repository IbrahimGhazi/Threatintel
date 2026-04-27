"""
Sigma-style YAML rule engine for behavioral detection.

Rules are loaded from YAML files in the rules_defs/ directory.  Each rule
defines conditions that are evaluated against a sliding window of events
grouped by a configurable key (source IP, destination IP, or username).

YAML rule schema:
  name:          Unique rule identifier (e.g., "port_scan")
  title:         Human-readable title template (supports {src_ip}, {count}, etc.)
  description:   Description template
  enabled:       true/false (default true)
  severity:      info | low | medium | high | critical
  window:        Time window in seconds (or env var reference)
  threshold:     Minimum number of matching events to trigger
  group_by:      Field to group events by: src_ip | dst_ip | username
  detection:
    condition:   Condition type: "count_distinct" | "count" | "match_all" | "match_any"
    field:       Field to count distinct values of (for count_distinct)
    filters:     List of filters that events must match
      - field:   Event field name
        op:      Operator: eq | neq | in | not_in | regex | exists | gt | lt
        value:   Value to compare against
  mitre_attack:
    - tactic:    MITRE ATT&CK tactic
      technique_id: Technique ID (e.g., T1046)
      technique: Technique name
  recommended_action: Action to take when the rule fires

Example:
  name: dns_tunneling
  title: "DNS Tunneling: {src_ip} — {count} queries"
  description: "Source IP {src_ip} generated {count} DNS queries in {window}s."
  severity: high
  window: 300
  threshold: 50
  group_by: src_ip
  detection:
    condition: count
    filters:
      - field: dst_port
        op: eq
        value: 53
      - field: protocol
        op: eq
        value: udp
  mitre_attack:
    - tactic: "Command and Control"
      technique_id: T1071.004
      technique: "DNS"
  recommended_action: "Investigate DNS query patterns for data exfiltration."
"""
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

from incidents import build_incident
from models import Incident
from parser import ParsedLog

logger = logging.getLogger("correlation.rule_engine")

RULES_DIR = Path(__file__).parent / "rule_defs"


@dataclass
class RuleFilter:
    field: str
    op: str  # eq, neq, in, not_in, regex, exists, gt, lt
    value: Any = None
    _regex: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        if self.op == "regex" and isinstance(self.value, str):
            self._regex = re.compile(self.value, re.IGNORECASE)

    def matches(self, log: ParsedLog) -> bool:
        actual = _get_field(log, self.field)
        if self.op == "exists":
            return actual is not None
        if actual is None:
            return False
        if self.op == "eq":
            return str(actual).lower() == str(self.value).lower()
        if self.op == "neq":
            return str(actual).lower() != str(self.value).lower()
        if self.op == "in":
            vals = self.value if isinstance(self.value, list) else [self.value]
            return str(actual).lower() in {str(v).lower() for v in vals}
        if self.op == "not_in":
            vals = self.value if isinstance(self.value, list) else [self.value]
            return str(actual).lower() not in {str(v).lower() for v in vals}
        if self.op == "regex":
            return bool(self._regex and self._regex.search(str(actual)))
        if self.op == "gt":
            try:
                return float(actual) > float(self.value)
            except (ValueError, TypeError):
                return False
        if self.op == "lt":
            try:
                return float(actual) < float(self.value)
            except (ValueError, TypeError):
                return False
        return False


@dataclass
class DetectionRule:
    name: str
    title: str
    description: str
    severity: str
    window: int
    threshold: int
    group_by: str  # src_ip, dst_ip, username
    condition: str  # count, count_distinct, match_all, match_any
    distinct_field: Optional[str]  # for count_distinct
    filters: List[RuleFilter]
    mitre_attack: List[Dict[str, str]]
    recommended_action: str
    enabled: bool = True

    def _format(self, template: str, **kwargs) -> str:
        try:
            return template.format(**kwargs)
        except (KeyError, IndexError):
            return template

    def evaluate(
        self,
        events: List[ParsedLog],
        current: ParsedLog,
    ) -> Optional[Incident]:
        """Evaluate this rule against a window of events. Returns an Incident or None."""
        cutoff = time.time() - self.window
        recent = [e for e in events if e.timestamp >= cutoff]

        # Apply filters
        matching = recent
        for f in self.filters:
            matching = [e for e in matching if f.matches(e)]

        if self.condition == "count":
            count = len(matching)
            if count < self.threshold:
                return None
        elif self.condition == "count_distinct":
            if not self.distinct_field:
                return None
            distinct_values = {_get_field(e, self.distinct_field) for e in matching}
            distinct_values.discard(None)
            count = len(distinct_values)
            if count < self.threshold:
                return None
        elif self.condition == "match_all":
            if len(matching) < self.threshold:
                return None
            count = len(matching)
        elif self.condition == "match_any":
            if not matching:
                return None
            count = len(matching)
        else:
            return None

        # Build format kwargs
        group_val = _get_field(current, self.group_by) or "unknown"
        fmt = {
            "src_ip": current.src_ip or "unknown",
            "dst_ip": current.dst_ip or "unknown",
            "username": current.username or "unknown",
            "count": count,
            "window": self.window,
            "group": group_val,
        }
        if self.distinct_field and self.condition == "count_distinct":
            fmt["distinct_count"] = count
            fmt["distinct_field"] = self.distinct_field

        title = self._format(self.title, **fmt)
        description = self._format(self.description, **fmt)

        return build_incident(
            attack_type=self.name,
            severity=self.severity,
            title=title,
            description=description,
            recommended_action=self.recommended_action,
            logs=matching,
            stage_map={self.name.replace("_", " ").title(): matching},
            mitre_attack=self.mitre_attack,
            metadata={"rule_name": self.name, "event_count": count, "window_seconds": self.window},
            source_ip=current.src_ip,
            destination_ip=current.dst_ip,
            affected_host=current.hostname,
        )


def _get_field(log: ParsedLog, field_name: str) -> Optional[Any]:
    """Get a field value from a ParsedLog by name."""
    if hasattr(log, field_name):
        return getattr(log, field_name)
    return None


def _resolve_window(window_val: Any) -> int:
    """Resolve window value — can be an int or an env var name."""
    if isinstance(window_val, int):
        return window_val
    if isinstance(window_val, str):
        # Check if it's an env var reference like "$CORRELATION_DNS_TUNNEL_WINDOW"
        if window_val.startswith("$"):
            env_name = window_val[1:]
            return int(os.getenv(env_name, "300"))
        try:
            return int(window_val)
        except ValueError:
            return 300
    return 300


def load_rule(data: Dict[str, Any]) -> Optional[DetectionRule]:
    """Parse a YAML rule dict into a DetectionRule object."""
    try:
        detection = data.get("detection", {})
        filters_raw = detection.get("filters", [])
        filters = []
        for f in filters_raw:
            filters.append(RuleFilter(
                field=f["field"],
                op=f.get("op", "eq"),
                value=f.get("value"),
            ))

        mitre = data.get("mitre_attack", [])
        if isinstance(mitre, list):
            mitre = [m if isinstance(m, dict) else {} for m in mitre]
        else:
            mitre = []

        return DetectionRule(
            name=data["name"],
            title=data.get("title", data["name"]),
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            window=_resolve_window(data.get("window", 300)),
            threshold=int(data.get("threshold", 1)),
            group_by=data.get("group_by", "src_ip"),
            condition=detection.get("condition", "count"),
            distinct_field=detection.get("field"),
            filters=filters,
            mitre_attack=mitre,
            recommended_action=data.get("recommended_action", "Investigate the activity."),
            enabled=data.get("enabled", True),
        )
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("Failed to load rule: %s — %s", data.get("name", "?"), exc)
        return None


def load_rules_from_dir(rules_dir: Path = RULES_DIR) -> List[DetectionRule]:
    """Load all YAML rule definitions from a directory."""
    rules = []
    if not rules_dir.is_dir():
        logger.info("No rule_defs directory found at %s, skipping YAML rules", rules_dir)
        return rules
    for path in sorted(rules_dir.glob("*.yml")):
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
            if data:
                rule = load_rule(data)
                if rule and rule.enabled:
                    rules.append(rule)
                    logger.info("Loaded YAML rule: %s (window=%ds, threshold=%d)", rule.name, rule.window, rule.threshold)
        except Exception as exc:
            logger.warning("Failed to load rule file %s: %s", path, exc)
    return rules


def evaluate_yaml_rules(
    rules: List[DetectionRule],
    by_src: Dict[str, List[ParsedLog]],
    by_dst: Dict[str, List[ParsedLog]],
    by_user: Dict[str, List[ParsedLog]],
    current: ParsedLog,
) -> List[Incident]:
    """Evaluate all loaded YAML rules against current event state."""
    results = []
    for rule in rules:
        if rule.group_by == "src_ip":
            key = current.src_ip
            store = by_src
        elif rule.group_by == "dst_ip":
            key = current.dst_ip
            store = by_dst
        elif rule.group_by == "username":
            key = current.username
            store = by_user
        else:
            continue

        if not key:
            continue

        events = store.get(key, [])
        if not events:
            continue

        incident = rule.evaluate(events, current)
        if incident:
            results.append(incident)

    return results
