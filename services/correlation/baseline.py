"""
Adaptive Behavioral Baseline Engine

Learns normal activity patterns per host / subnet / user and provides
anomaly detection based on statistical deviation from the learned baseline.

Algorithm
---------
* Welford's online algorithm for incremental mean and variance — no need
  to store all historical values.
* Reservoir sampling (up to 200 values per metric) for a p95 estimate.
* Separate baselines per entity AND a global aggregate (entity_value='*')
  so that both host-level and org-wide anomalies can be detected.

Persistence
-----------
In-memory store for low-latency access.  Periodically flushed to
PostgreSQL via ``flush_to_db()``.  On startup call ``load_from_db()``
to restore prior state.

Integration point in the correlation service
---------------------------------------------
1. After parsing a log, call ``record()`` with the relevant metric value.
2. ``record()`` returns ``(is_anomalous, z_score)`` — use this to decide
   whether to escalate the alert severity or create a tuning suggestion.
"""

import asyncio
import logging
import math
import os
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("ti.baseline")

# ── Configuration ─────────────────────────────────────────────────────────────

# Minimum observations before anomaly detection activates for an entity.
MIN_SAMPLES = int(os.getenv("BASELINE_MIN_SAMPLES", "20"))

# Z-score threshold: observations beyond this many standard deviations are anomalous.
Z_SCORE_THRESHOLD = float(os.getenv("BASELINE_Z_SCORE_THRESHOLD", "3.0"))

# How often (seconds) to flush baselines to PostgreSQL.
FLUSH_INTERVAL = int(os.getenv("BASELINE_FLUSH_INTERVAL", "300"))

# Metric → category mapping, used when persisting to the database.
METRIC_CATEGORY: Dict[str, str] = {
    # DNS
    "dns_qpm":                 "dns",
    "unique_domains_per_hour": "dns",
    # Port scanning
    "unique_ports_per_window": "port_scan",
    "connection_rate":         "port_scan",
    # Authentication
    "failed_auth_per_hour":    "auth",
    "auth_rate":               "auth",
    # General connections
    "connection_count_per_hour": "connection",
    "unique_destinations":       "connection",
    # Lateral movement
    "smb_connections":         "lateral_movement",
    "rdp_connections":         "lateral_movement",
    "unique_internal_dst":     "lateral_movement",
    # C2 / beaconing
    "beacon_interval_std":     "c2",
    "outbound_connection_rate": "c2",
}


# ── Statistics helper ─────────────────────────────────────────────────────────

@dataclass
class MetricStats:
    """Running statistics for a single (entity, metric) pair.

    Uses Welford's online algorithm so we never need to store all values.
    A small reservoir of up to 200 observations gives a p95 estimate.
    """

    mean:         float = 0.0
    _m2:          float = 0.0       # accumulator for Welford variance
    sample_count: int   = 0
    min_observed: float = field(default_factory=lambda: float("inf"))
    max_observed: float = field(default_factory=lambda: float("-inf"))
    _reservoir:   List[float] = field(default_factory=list)
    _RESERVOIR_MAX: int = 200

    # ── Derived properties ────────────────────────────────────────────────────

    @property
    def variance(self) -> float:
        if self.sample_count < 2:
            return 0.0
        return self._m2 / (self.sample_count - 1)

    @property
    def std_dev(self) -> float:
        return math.sqrt(max(0.0, self.variance))

    @property
    def p95(self) -> Optional[float]:
        if not self._reservoir:
            return None
        s = sorted(self._reservoir)
        idx = min(int(len(s) * 0.95), len(s) - 1)
        return s[idx]

    # ── Mutation ──────────────────────────────────────────────────────────────

    def update(self, value: float) -> None:
        """Add a new observation using Welford's online algorithm."""
        self.sample_count += 1
        delta  = value - self.mean
        self.mean += delta / self.sample_count
        delta2 = value - self.mean
        self._m2 += delta * delta2

        if value < self.min_observed:
            self.min_observed = value
        if value > self.max_observed:
            self.max_observed = value

        # Reservoir sampling (Algorithm R)
        if len(self._reservoir) < self._RESERVOIR_MAX:
            self._reservoir.append(value)
        else:
            j = random.randint(0, self.sample_count - 1)
            if j < self._RESERVOIR_MAX:
                self._reservoir[j] = value

    # ── Anomaly detection ─────────────────────────────────────────────────────

    def z_score(self, value: float) -> float:
        """Return the z-score of ``value`` relative to this baseline."""
        if self.std_dev < 1e-6 or self.sample_count < MIN_SAMPLES:
            return 0.0
        return (value - self.mean) / self.std_dev

    def is_anomalous(self, value: float) -> Tuple[bool, float]:
        """Return ``(is_anomaly, z_score)`` before updating the baseline."""
        if self.sample_count < MIN_SAMPLES:
            return False, 0.0
        z = self.z_score(value)
        return abs(z) > Z_SCORE_THRESHOLD, z

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "mean":          round(self.mean, 4),
            "std_dev":       round(self.std_dev, 4),
            "sample_count":  self.sample_count,
            "min_observed":  round(self.min_observed, 4)
                             if self.min_observed != float("inf") else None,
            "max_observed":  round(self.max_observed, 4)
                             if self.max_observed != float("-inf") else None,
            "p95":           round(self.p95, 4) if self.p95 is not None else None,
        }

    @classmethod
    def from_db_row(cls, row) -> "MetricStats":
        """Restore a MetricStats from a database row (approximate)."""
        s = cls()
        s.mean         = float(row.mean or 0)
        s.sample_count = int(row.sample_count or 0)
        # Re-derive _m2 from stored std_dev
        std = float(row.std_dev or 0)
        s._m2 = (std ** 2) * max(s.sample_count - 1, 0)
        s.min_observed = float(row.min_observed) if row.min_observed is not None else float("inf")
        s.max_observed = float(row.max_observed) if row.max_observed is not None else float("-inf")
        if row.p95 is not None:
            s._reservoir = [float(row.p95)]
        return s


# ── Baseline engine ───────────────────────────────────────────────────────────

class BaselineEngine:
    """Manages behavioral baselines for all tracked entities.

    Key: ``(entity_type, entity_value, metric)`` → ``MetricStats``.

    Entity types:
        * ``"host"``   — an individual source IP address
        * ``"subnet"`` — /24 aggregation (derived automatically)
        * ``"user"``   — a username
        * ``"global"`` — org-wide aggregate (entity_value = ``"*"``)
    """

    def __init__(self, db_session_factory=None):
        # In-memory stats store; key = (entity_type, entity_value, metric)
        self._stats: Dict[Tuple[str, str, str], MetricStats] = {}
        self._db_factory = db_session_factory
        self._last_flush: float = time.monotonic()

    # ── Recording ─────────────────────────────────────────────────────────────

    def record(
        self,
        entity_type:  str,
        entity_value: str,
        metric:       str,
        value:        float,
    ) -> Tuple[bool, float]:
        """Record ``value`` and test for anomaly *before* updating the baseline.

        Returns
        -------
        (is_anomalous, z_score)
        """
        key = (entity_type, entity_value.lower(), metric)
        if key not in self._stats:
            self._stats[key] = MetricStats()

        stats = self._stats[key]
        is_anom, z = stats.is_anomalous(value)
        stats.update(value)

        # Always update the global aggregate too
        global_key = ("global", "*", metric)
        if global_key not in self._stats:
            self._stats[global_key] = MetricStats()
        self._stats[global_key].update(value)

        return is_anom, z

    def record_subnet(self, host_ip: str, metric: str, value: float) -> Tuple[bool, float]:
        """Record a /24 subnet aggregate (derived from host IP)."""
        parts = host_ip.split(".")
        if len(parts) != 4:
            return False, 0.0
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return self.record("subnet", subnet, metric, value)

    # ── Metric extraction from a ParsedLog ───────────────────────────────────

    def extract_and_record(self, parsed_log) -> List[Tuple[str, str, str, bool, float]]:
        """Extract metrics from a ParsedLog, record them, and return anomaly info.

        Returns a list of ``(entity_type, entity_value, metric, is_anomaly, z_score)``.
        """
        results = []
        src_ip   = getattr(parsed_log, "src_ip",   None)
        dst_port = getattr(parsed_log, "dst_port", None)
        protocol = getattr(parsed_log, "protocol", "").lower() if getattr(parsed_log, "protocol", None) else ""
        status   = (getattr(parsed_log, "status",  "") or "").lower()
        username = getattr(parsed_log, "username", None)

        def _rec(et, ev, metric, val):
            is_a, z = self.record(et, ev, metric, val)
            results.append((et, ev, metric, is_a, z))
            return is_a, z

        if src_ip:
            _rec("host", src_ip, "connection_count_per_hour", 1.0)
            self.record_subnet(src_ip, "connection_count_per_hour", 1.0)

            is_failed = status in ("failed", "error", "invalid", "refused")
            if is_failed and username:
                _rec("host", src_ip, "failed_auth_per_hour", 1.0)

            if protocol == "rdp" or dst_port == 3389:
                _rec("host", src_ip, "rdp_connections", 1.0)

            if protocol == "smb" or dst_port in (445, 139):
                _rec("host", src_ip, "smb_connections", 1.0)

        if username:
            is_failed = status in ("failed", "error", "invalid", "refused")
            if is_failed:
                _rec("user", username, "failed_auth_per_hour", 1.0)

        return results

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_baseline(
        self,
        entity_type:  str,
        entity_value: str,
        metric:       str,
    ) -> Optional[dict]:
        """Return stats dict for the given entity+metric, or None if unseen."""
        key = (entity_type, entity_value.lower(), metric)
        s = self._stats.get(key)
        return s.to_dict() if s else None

    def all_baselines(self) -> List[dict]:
        """Return all tracked baselines as a flat list suitable for the API."""
        rows = []
        for (et, ev, metric), stats in self._stats.items():
            d = stats.to_dict()
            d["entity_type"]  = et
            d["entity_value"] = ev
            d["metric"]       = metric
            d["category"]     = METRIC_CATEGORY.get(metric, "unknown")
            rows.append(d)
        return rows

    # ── Persistence ───────────────────────────────────────────────────────────

    async def maybe_flush(self) -> None:
        """Flush baselines to DB if the flush interval has elapsed."""
        if time.monotonic() - self._last_flush >= FLUSH_INTERVAL:
            await self.flush_to_db()
            self._last_flush = time.monotonic()

    async def flush_to_db(self) -> None:
        """Persist all in-memory baselines to PostgreSQL (upsert)."""
        if not self._db_factory:
            return
        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                for (entity_type, entity_value, metric), stats in self._stats.items():
                    category = METRIC_CATEGORY.get(metric, "unknown")
                    d = stats.to_dict()
                    await db.execute(sa_text("""
                        INSERT INTO behavioral_baselines
                          (entity_type, entity_value, metric, category,
                           mean, std_dev, sample_count, min_observed, max_observed, p95,
                           last_updated)
                        VALUES
                          (:entity_type, :entity_value, :metric, :category,
                           :mean, :std_dev, :sample_count, :min_observed, :max_observed, :p95,
                           NOW())
                        ON CONFLICT (entity_type, entity_value, metric) DO UPDATE SET
                          mean         = EXCLUDED.mean,
                          std_dev      = EXCLUDED.std_dev,
                          sample_count = EXCLUDED.sample_count,
                          min_observed = EXCLUDED.min_observed,
                          max_observed = EXCLUDED.max_observed,
                          p95          = EXCLUDED.p95,
                          last_updated = NOW()
                    """), {
                        "entity_type":  entity_type,
                        "entity_value": entity_value,
                        "metric":       metric,
                        "category":     category,
                        **d,
                    })
                await db.commit()
            logger.debug("Flushed %d baseline entries to database", len(self._stats))
        except Exception as exc:
            logger.warning("Baseline flush failed: %s", exc)

    async def load_from_db(self) -> None:
        """Restore baselines persisted by a previous run."""
        if not self._db_factory:
            return
        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                rows = (await db.execute(sa_text(
                    "SELECT entity_type, entity_value, metric, "
                    "mean, std_dev, sample_count, min_observed, max_observed, p95 "
                    "FROM behavioral_baselines"
                ))).fetchall()
            for row in rows:
                key = (row.entity_type, row.entity_value.lower(), row.metric)
                self._stats[key] = MetricStats.from_db_row(row)
            logger.info("Loaded %d baseline entries from database", len(rows))
        except Exception as exc:
            logger.warning("Failed to load baselines from database: %s", exc)
