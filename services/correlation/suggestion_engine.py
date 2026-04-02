"""
Suggestion Engine for Adaptive Rule Tuning

Monitors repeated alert patterns and generates tuning suggestions when
normal-looking activity keeps triggering behavioral detection rules.

Confidence model
----------------
* Starts at 20 % on the 5th trigger.
* Grows asymptotically toward 90 % using:
      confidence = 0.20 + 0.70 × (1 − e^(−triggers / 30))
* When confidence ≥ AUTO_APPLY_CONFIDENCE (default 85 %) a timestamp is
  set (auto_apply_at = NOW() + AUTO_APPLY_DELAY_HOURS).  If the analyst
  does not reject the suggestion within that window, the system auto-applies it.

Safeguards (cannot be overridden)
----------------------------------
1. Rules whose names contain ANY of PROTECTED_RULE_PATTERNS are never touched.
2. Alerts with severity == 'critical' are never suppressed.
3. All applied changes (auto or manual) are written to ``adaptive_rule_changes``.
4. Every auto-applied change can be reverted via the API.
"""

import asyncio
import json
import logging
import math
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

logger = logging.getLogger("ti.suggestion")

# ── Configuration ─────────────────────────────────────────────────────────────

# Rule name substrings that are NEVER subject to auto-adjustment.
PROTECTED_RULE_PATTERNS = frozenset({
    "ti_match",
    "threat_intel",
    "malicious_ip",
    "c2_beaconing",
    "known_bad",
    "ioc_match",
    "signature",
})

# Alert severities exempt from any suppression.
PROTECTED_SEVERITIES = frozenset({"critical"})

# Minimum number of triggers before generating a suggestion.
MIN_TRIGGERS = int(os.getenv("SUGGESTION_MIN_TRIGGERS", "5"))

# Confidence threshold [0-1] at which auto-apply is scheduled.
AUTO_APPLY_CONFIDENCE = float(os.getenv("BASELINE_AUTO_APPLY_CONFIDENCE", "0.85"))

# Hours to wait after scheduling before actually applying.
AUTO_APPLY_DELAY_HOURS = int(os.getenv("BASELINE_AUTO_APPLY_DELAY_HOURS", "24"))


# ── Guards ────────────────────────────────────────────────────────────────────

def _is_protected_rule(rule_name: str) -> bool:
    name = rule_name.lower()
    return any(p in name for p in PROTECTED_RULE_PATTERNS)


def _confidence(trigger_count: int) -> float:
    """Sigmoid-like growth: starts at 20 %, approaches 90 % asymptotically."""
    return min(0.90, 0.20 + 0.70 * (1.0 - math.exp(-trigger_count / 30.0)))


# ── Engine ────────────────────────────────────────────────────────────────────

class SuggestionEngine:
    """Creates and maintains tuning suggestions in the database.

    Usage in the correlation service
    ---------------------------------
    After an alert is raised (or would be raised) for a behavioral rule:

        await engine.record_alert(
            rule_name      = "dns_query_spike",
            severity       = "medium",
            entity_type    = "host",
            entity_value   = "192.168.1.50",
            category       = "dns",
            current_threshold = {"threshold": 20, "window_secs": 60},
            baseline_info  = baseline_engine.get_baseline("host", "192.168.1.50", "dns_qpm"),
        )
    """

    def __init__(self, db_session_factory=None):
        self._db_factory = db_session_factory
        # In-memory trigger counter: (rule_name, entity_value) → count
        self._triggers: Dict[Tuple[str, str], int] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    async def record_alert(
        self,
        rule_name:         str,
        severity:          str,
        entity_type:       str,
        entity_value:      str,
        category:          str,
        current_threshold: Optional[dict] = None,
        baseline_info:     Optional[dict] = None,
    ) -> None:
        """Record a triggered alert; create/update a suggestion if warranted."""
        if _is_protected_rule(rule_name) or severity in PROTECTED_SEVERITIES:
            return

        key = (rule_name, (entity_value or "global").lower())
        self._triggers[key] = self._triggers.get(key, 0) + 1
        count = self._triggers[key]

        if count >= MIN_TRIGGERS:
            await self._upsert(
                rule_name=rule_name,
                entity_type=entity_type,
                entity_value=entity_value,
                category=category,
                trigger_count=count,
                current_threshold=current_threshold or {},
                baseline_info=baseline_info or {},
            )

    async def run_auto_apply_loop(self) -> None:
        """Background task: check for auto-apply candidates every 5 minutes."""
        while True:
            try:
                await self._process_auto_apply()
            except Exception as exc:
                logger.error("Auto-apply loop error: %s", exc)
            await asyncio.sleep(300)

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _upsert(
        self,
        rule_name:        str,
        entity_type:      str,
        entity_value:     str,
        category:         str,
        trigger_count:    int,
        current_threshold: dict,
        baseline_info:    dict,
    ) -> None:
        if not self._db_factory:
            return

        confidence = _confidence(trigger_count)

        # Build human-readable rationale
        baseline_clause = ""
        if baseline_info.get("mean") is not None:
            m   = baseline_info["mean"]
            std = baseline_info.get("std_dev", 0.0)
            n   = baseline_info.get("sample_count", 0)
            baseline_clause = (
                f" The {n}-sample baseline shows a mean of {m:.1f} ± {std:.1f}."
            )

        rationale = (
            f"Rule '{rule_name}' has fired {trigger_count} time(s) for "
            f"{entity_type} '{entity_value}' without confirmed malicious "
            f"activity.{baseline_clause}  The current threshold appears too "
            f"sensitive for this entity."
        )

        # Build suggested value
        suggested: dict = dict(current_threshold)
        if baseline_info.get("mean") is not None and baseline_info.get("std_dev") is not None:
            new_thresh = baseline_info["mean"] + 3.0 * baseline_info["std_dev"]
            suggested["threshold"] = round(new_thresh, 0)
            suggested["basis"]     = "mean_plus_3sigma"

        # Schedule auto-apply only when confidence reaches the threshold
        auto_apply_at: Optional[str] = None
        if confidence >= AUTO_APPLY_CONFIDENCE:
            auto_apply_at = (
                datetime.now(timezone.utc) + timedelta(hours=AUTO_APPLY_DELAY_HOURS)
            ).isoformat()

        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                existing = (await db.execute(sa_text("""
                    SELECT id, trigger_count FROM tuning_suggestions
                    WHERE rule_name    = :rule_name
                      AND entity_value = :entity_value
                      AND status       = 'pending'
                    LIMIT 1
                """), {"rule_name": rule_name, "entity_value": entity_value})).fetchone()

                if existing:
                    # Reconcile in-memory counter with persisted value so that
                    # service restarts never cause the count to regress.
                    db_count = int(existing.trigger_count or 0)
                    if db_count > trigger_count:
                        trigger_count = db_count + 1
                        key = (rule_name, (entity_value or "global").lower())
                        self._triggers[key] = trigger_count
                        confidence    = _confidence(trigger_count)
                        auto_apply_at = None
                        if confidence >= AUTO_APPLY_CONFIDENCE:
                            auto_apply_at = (
                                datetime.now(timezone.utc)
                                + timedelta(hours=AUTO_APPLY_DELAY_HOURS)
                            ).isoformat()

                    await db.execute(sa_text("""
                        UPDATE tuning_suggestions SET
                          confidence      = :confidence,
                          trigger_count   = :trigger_count,
                          rationale       = :rationale,
                          suggested_value = CAST(:suggested_value AS jsonb),
                          auto_apply_at   = :auto_apply_at,
                          updated_at      = NOW()
                        WHERE id = :id
                    """), {
                        "confidence":      confidence,
                        "trigger_count":   trigger_count,
                        "rationale":       rationale,
                        "suggested_value": json.dumps(suggested),
                        "auto_apply_at":   auto_apply_at,
                        "id":              str(existing.id),
                    })
                else:
                    await db.execute(sa_text("""
                        INSERT INTO tuning_suggestions
                          (suggestion_type, category, entity_type, entity_value,
                           rule_name, current_value, suggested_value,
                           rationale, confidence, trigger_count, auto_apply_at)
                        VALUES
                          (:suggestion_type, :category, :entity_type, :entity_value,
                           :rule_name, CAST(:current_value AS jsonb), CAST(:suggested_value AS jsonb),
                           :rationale, :confidence, :trigger_count, :auto_apply_at)
                    """), {
                        "suggestion_type": "increase_threshold",
                        "category":        category,
                        "entity_type":     entity_type,
                        "entity_value":    entity_value,
                        "rule_name":       rule_name,
                        "current_value":   json.dumps(current_threshold),
                        "suggested_value": json.dumps(suggested),
                        "rationale":       rationale,
                        "confidence":      confidence,
                        "trigger_count":   trigger_count,
                        "auto_apply_at":   auto_apply_at,
                    })
                await db.commit()

            logger.info(
                "Suggestion upserted: rule=%s entity=%s confidence=%.0f%% triggers=%d",
                rule_name, entity_value, confidence * 100, trigger_count,
            )
        except Exception as exc:
            logger.warning("Failed to upsert suggestion: %s", exc)

    async def _process_auto_apply(self) -> None:
        """Find due auto-apply suggestions and write audit-log entries."""
        if not self._db_factory:
            return
        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                due = (await db.execute(sa_text("""
                    SELECT id, rule_name, entity_type, entity_value,
                           suggestion_type, category,
                           current_value, suggested_value,
                           confidence, trigger_count
                    FROM tuning_suggestions
                    WHERE status        = 'pending'
                      AND auto_apply_at IS NOT NULL
                      AND auto_apply_at <= NOW()
                      AND confidence   >= :threshold
                    LIMIT 20
                """), {"threshold": AUTO_APPLY_CONFIDENCE})).fetchall()

                for row in due:
                    if _is_protected_rule(row.rule_name):
                        logger.warning(
                            "Skipping auto-apply for protected rule: %s", row.rule_name
                        )
                        continue

                    # Mark suggestion as applied
                    await db.execute(sa_text("""
                        UPDATE tuning_suggestions
                        SET status = 'auto_applied', applied_at = NOW()
                        WHERE id = :id
                    """), {"id": str(row.id)})

                    # Write audit log
                    await db.execute(sa_text("""
                        INSERT INTO adaptive_rule_changes
                          (suggestion_id, change_type, rule_name,
                           entity_type, entity_value,
                           previous_value, new_value,
                           applied_by, reason)
                        VALUES
                          (:suggestion_id, :change_type, :rule_name,
                           :entity_type, :entity_value,
                           CAST(:previous_value AS jsonb), CAST(:new_value AS jsonb),
                           'system_auto', :reason)
                    """), {
                        "suggestion_id": str(row.id),
                        "change_type":   row.suggestion_type,
                        "rule_name":     row.rule_name,
                        "entity_type":   row.entity_type,
                        "entity_value":  row.entity_value,
                        "previous_value": json.dumps(
                            dict(row.current_value) if row.current_value else {}
                        ),
                        "new_value": json.dumps(
                            dict(row.suggested_value) if row.suggested_value else {}
                        ),
                        "reason": (
                            f"Auto-applied after {AUTO_APPLY_DELAY_HOURS}h with no response. "
                            f"confidence={row.confidence:.0%}, triggers={row.trigger_count}"
                        ),
                    })

                await db.commit()

                if due:
                    logger.info("Auto-applied %d tuning suggestion(s).", len(due))

        except Exception as exc:
            logger.warning("Auto-apply processing failed: %s", exc)
