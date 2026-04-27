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
import hashlib
import json
import logging
import math
import os
import time
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


def _compute_tuning_fingerprint(
    rule_name: str,
    entity_value: str,
    suggestion_type: str,
    category: str,
) -> str:
    """SHA-256 fingerprint for deduplicating tuning suggestions."""
    raw = f"{rule_name}|{entity_value}|{suggestion_type}|{category}"
    return hashlib.sha256(raw.encode()).hexdigest()


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

    # How long to cache DB settings before re-reading (seconds)
    _SETTINGS_TTL = 60.0

    # How many days of silence before generating a threshold-restore suggestion.
    _RESTORE_SILENCE_DAYS = 7

    def __init__(self, db_session_factory=None):
        self._db_factory = db_session_factory
        # In-memory trigger counter: (rule_name, entity_value) → count
        self._triggers: Dict[Tuple[str, str], int] = {}
        # Last fire timestamp per (rule_name, entity_value) — for restore tracking
        self._last_fire: Dict[Tuple[str, str], float] = {}
        # Cached runtime settings (overrides env-var defaults when DB is available)
        self._delay_hours:      int   = AUTO_APPLY_DELAY_HOURS
        self._conf_threshold:   float = AUTO_APPLY_CONFIDENCE
        self._settings_read_at: float = 0.0

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
        self._last_fire[key] = time.monotonic()
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

    async def load_triggers_from_db(self) -> None:
        """Seed in-memory trigger counters from pending suggestions in the DB.

        Called once at startup so that restarts never reset the trigger count
        to zero — the counter picks up from where it left off.
        """
        if not self._db_factory:
            return
        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                rows = (await db.execute(sa_text("""
                    SELECT rule_name, entity_value, trigger_count
                    FROM tuning_suggestions
                    WHERE status = 'pending'
                """))).fetchall()
            for row in rows:
                key = (row.rule_name, (row.entity_value or "global").lower())
                existing = self._triggers.get(key, 0)
                if row.trigger_count > existing:
                    self._triggers[key] = int(row.trigger_count)
            logger.info("Seeded %d trigger counters from DB", len(rows))
        except Exception as exc:
            logger.warning("Failed to seed trigger counters: %s", exc)

    async def _refresh_settings(self) -> None:
        """Read auto-apply settings from platform_settings (cached for _SETTINGS_TTL s)."""
        if not self._db_factory:
            return
        if time.monotonic() - self._settings_read_at < self._SETTINGS_TTL:
            return
        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                rows = (await db.execute(sa_text(
                    "SELECT key, value FROM platform_settings "
                    "WHERE key IN ('auto_apply_delay_hours', 'auto_apply_confidence')"
                ))).fetchall()
            for row in rows:
                if row.key == "auto_apply_delay_hours":
                    self._delay_hours = max(1, int(row.value))
                elif row.key == "auto_apply_confidence":
                    self._conf_threshold = float(row.value)
            self._settings_read_at = time.monotonic()
        except Exception as exc:
            logger.debug("Could not refresh tuning settings from DB: %s", exc)

    # ── Bidirectional threshold tracking ──────────────────────────────────────

    def mark_fired(self, rule_name: str, entity_value: str) -> None:
        """Record that a rule just fired for the given entity (for restore tracking)."""
        key = (rule_name, (entity_value or "global").lower())
        self._last_fire[key] = time.monotonic()

    async def run_auto_apply_loop(self) -> None:
        """Background task: check for auto-apply and threshold-restore candidates every 5 minutes."""
        while True:
            try:
                await self._process_auto_apply()
                await self._process_threshold_restores()
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

        await self._refresh_settings()
        confidence = _confidence(trigger_count)

        # Compute fingerprint for deduplication
        fingerprint = _compute_tuning_fingerprint(
            rule_name=rule_name,
            entity_value=(entity_value or "global").lower(),
            suggestion_type="increase_threshold",
            category=category,
        )

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

        # Schedule auto-apply only when confidence reaches the threshold.
        # Store as a real datetime object — asyncpg cannot accept ISO strings.
        auto_apply_at: Optional[datetime] = None
        if confidence >= self._conf_threshold:
            auto_apply_at = datetime.now(timezone.utc) + timedelta(hours=self._delay_hours)

        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                # Use fingerprint for deduplication; fall back to
                # rule_name + entity_value for rows without fingerprint.
                existing = (await db.execute(sa_text("""
                    SELECT id, trigger_count, status FROM tuning_suggestions
                    WHERE (fingerprint = :fingerprint
                           OR (fingerprint IS NULL
                               AND rule_name    = :rule_name
                               AND entity_value = :entity_value))
                      AND status IN ('pending', 'observed')
                    LIMIT 1
                """), {
                    "fingerprint": fingerprint,
                    "rule_name": rule_name,
                    "entity_value": entity_value,
                })).fetchone()

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
                        if confidence >= self._conf_threshold:
                            auto_apply_at = (
                                datetime.now(timezone.utc)
                                + timedelta(hours=self._delay_hours)
                            )

                    # Transition pending → observed after 10+ triggers
                    new_status = existing.status
                    if trigger_count >= 10 and new_status == "pending":
                        new_status = "observed"

                    await db.execute(sa_text("""
                        UPDATE tuning_suggestions SET
                          confidence      = :confidence,
                          trigger_count   = :trigger_count,
                          rationale       = :rationale,
                          suggested_value = CAST(:suggested_value AS jsonb),
                          auto_apply_at   = :auto_apply_at,
                          fingerprint     = :fingerprint,
                          status          = :status,
                          updated_at      = NOW()
                        WHERE id = :id
                    """), {
                        "confidence":      confidence,
                        "trigger_count":   trigger_count,
                        "rationale":       rationale,
                        "suggested_value": json.dumps(suggested),
                        "auto_apply_at":   auto_apply_at,
                        "fingerprint":     fingerprint,
                        "status":          new_status,
                        "id":              str(existing.id),
                    })
                else:
                    await db.execute(sa_text("""
                        INSERT INTO tuning_suggestions
                          (suggestion_type, category, entity_type, entity_value,
                           rule_name, current_value, suggested_value,
                           rationale, confidence, trigger_count, auto_apply_at,
                           fingerprint)
                        VALUES
                          (:suggestion_type, :category, :entity_type, :entity_value,
                           :rule_name, CAST(:current_value AS jsonb), CAST(:suggested_value AS jsonb),
                           :rationale, :confidence, :trigger_count, :auto_apply_at,
                           :fingerprint)
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
                        "fingerprint":     fingerprint,
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
        await self._refresh_settings()
        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                # confidence was already validated when auto_apply_at was scheduled;
                # do not re-check it here so rounding near the threshold never blocks apply.
                due = (await db.execute(sa_text("""
                    SELECT id, rule_name, entity_type, entity_value,
                           suggestion_type, category,
                           current_value, suggested_value,
                           confidence, trigger_count
                    FROM tuning_suggestions
                    WHERE status        = 'pending'
                      AND auto_apply_at IS NOT NULL
                      AND auto_apply_at <= NOW()
                    LIMIT 20
                """))).fetchall()

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
                            f"Auto-applied after {self._delay_hours}h with no response. "
                            f"confidence={row.confidence:.0%}, triggers={row.trigger_count}"
                        ),
                    })

                # Auto-resolve related open alerts for tuned rules
                resolved_total = 0
                for row in due:
                    if _is_protected_rule(row.rule_name):
                        continue
                    note = (
                        f"Auto-resolved: threshold tuned for rule '{row.rule_name}' "
                        f"(entity={row.entity_value}, confidence={row.confidence:.0%})"
                    )
                    res = await db.execute(sa_text("""
                        UPDATE alerts
                        SET status      = 'resolved',
                            resolved_at = NOW(),
                            notes       = :note
                        WHERE rule_name = :rule_name
                          AND status    = 'open'
                          AND (
                              context->>'source_ip' = :entity_value
                              OR :entity_value = '*'
                          )
                    """), {
                        "rule_name":    row.rule_name,
                        "entity_value": row.entity_value or "*",
                        "note":         note,
                    })
                    resolved_total += res.rowcount

                await db.commit()

                if due:
                    logger.info(
                        "Auto-applied %d tuning suggestion(s), auto-resolved %d alert(s).",
                        len(due), resolved_total,
                    )

        except Exception as exc:
            logger.warning("Auto-apply processing failed: %s", exc)

    async def _process_threshold_restores(self) -> None:
        """
        Bidirectional threshold adjustment: suggest *lowering* thresholds back
        toward their original values when an entity has been quiet for
        _RESTORE_SILENCE_DAYS days after a threshold was raised.

        Detection logic (DB-based so it survives restarts):
          - Find auto_applied suggestions with type='increase_threshold' that were
            applied > _RESTORE_SILENCE_DAYS ago.
          - For each, check that no new alerts have been created for the same
            rule_name + entity_value in the silence window.
          - If silent, create a 'decrease_threshold' suggestion.
        """
        if not self._db_factory:
            return
        try:
            from sqlalchemy import text as sa_text
            silence_cutoff = datetime.now(timezone.utc) - timedelta(days=self._RESTORE_SILENCE_DAYS)

            async with self._db_factory() as db:
                # Find previously increased rules that have been quiet
                candidates = (await db.execute(sa_text("""
                    SELECT arc.rule_name, arc.entity_type, arc.entity_value,
                           arc.previous_value, arc.new_value, arc.created_at,
                           ts.category
                    FROM adaptive_rule_changes arc
                    LEFT JOIN tuning_suggestions ts ON ts.id = arc.suggestion_id
                    WHERE arc.change_type = 'increase_threshold'
                      AND arc.created_at <= :cutoff
                      AND arc.reverted_at IS NULL
                      -- No pending restore suggestion already exists
                      AND NOT EXISTS (
                          SELECT 1 FROM tuning_suggestions
                          WHERE rule_name    = arc.rule_name
                            AND entity_value = arc.entity_value
                            AND suggestion_type = 'decrease_threshold'
                            AND status IN ('pending', 'auto_applied')
                      )
                    ORDER BY arc.created_at ASC
                    LIMIT 10
                """), {"cutoff": silence_cutoff})).fetchall()

                restored = 0
                for row in candidates:
                    rule_name    = row.rule_name
                    entity_value = row.entity_value or "global"

                    # Check that this rule+entity hasn't fired since the cutoff
                    recent_alert = (await db.execute(sa_text("""
                        SELECT 1 FROM alerts
                        WHERE rule_name = :rule_name
                          AND (
                              indicator_value = :entity_value
                              OR context->>'source_ip' = :entity_value
                          )
                          AND created_at > :cutoff
                        LIMIT 1
                    """), {
                        "rule_name":    rule_name,
                        "entity_value": entity_value,
                        "cutoff":       silence_cutoff,
                    })).fetchone()

                    if recent_alert:
                        continue  # Still active — don't restore yet

                    # Also skip if the rule has fired recently in-memory
                    mem_key = (rule_name, entity_value.lower())
                    last_fire = self._last_fire.get(mem_key)
                    if last_fire and (time.monotonic() - last_fire) < (self._RESTORE_SILENCE_DAYS * 86400):
                        continue

                    prev_val = dict(row.previous_value) if row.previous_value else {}
                    new_val  = dict(row.new_value)  if row.new_value  else {}
                    category = row.category or "connection"

                    rationale = (
                        f"Rule '{rule_name}' has not fired for {self._RESTORE_SILENCE_DAYS} days "
                        f"after its threshold was raised for {row.entity_type} '{entity_value}'. "
                        f"Consider restoring the original threshold to maintain detection sensitivity. "
                        f"Previous value: {prev_val}. Raised to: {new_val}."
                    )

                    restore_fp = _compute_tuning_fingerprint(
                        rule_name=rule_name,
                        entity_value=entity_value.lower(),
                        suggestion_type="decrease_threshold",
                        category=category,
                    )
                    await db.execute(sa_text("""
                        INSERT INTO tuning_suggestions
                          (suggestion_type, category, entity_type, entity_value,
                           rule_name, current_value, suggested_value,
                           rationale, confidence, trigger_count, fingerprint)
                        VALUES
                          ('decrease_threshold', :category, :entity_type, :entity_value,
                           :rule_name, CAST(:current_value AS jsonb), CAST(:suggested_value AS jsonb),
                           :rationale, 0.70, 0, :fingerprint)
                        ON CONFLICT DO NOTHING
                    """), {
                        "category":      category,
                        "entity_type":   row.entity_type,
                        "entity_value":  entity_value,
                        "rule_name":     rule_name,
                        "current_value": json.dumps(new_val),
                        "suggested_value": json.dumps(prev_val),
                        "rationale":     rationale,
                        "fingerprint":   restore_fp,
                    })
                    restored += 1

                await db.commit()
                if restored:
                    logger.info("Generated %d threshold-restore suggestion(s).", restored)

        except Exception as exc:
            logger.warning("Threshold-restore check failed: %s", exc)
