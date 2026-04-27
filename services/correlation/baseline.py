"""
Adaptive Multi-Method Behavioral Baseline Engine

Implements SIEM-grade baselining with multiple detection methods:

Methods
-------
1. **Statistical** (Welford's online algorithm)
   - Incremental mean/variance, reservoir sampling for p95
   - Best for: connection rates, auth failures, port scan intensity

2. **Temporal** (hour-of-week seasonal profiles)
   - 168 buckets (Mon 00:00 … Sun 23:00), each a micro-baseline
   - Best for: business-hours detection, after-hours anomalies

3. **EMA** (Exponential Moving Average)
   - Smoothed rate tracking with adaptive deviation bands
   - Best for: trend detection, burst detection, gradual drift

4. **Peer Group** (subnet /24 comparison)
   - Compares host to its /24 peers' aggregate statistics
   - Best for: insider threat, lateral movement outliers

Learning Modes (F5 WAF-style)
-----------------------------
* **Learning ON**  — all methods actively record observations
* **Learning OFF** — baselines frozen, no new data recorded
* **Transparent**  — anomalies logged at info level, no high-severity alerts
* **Blocking**     — full alert generation based on learned baselines

Confidence tracks how much learning is done per method (0-100%).
"""

import asyncio
import logging
import math
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("ti.baseline")

# ── Configuration ─────────────────────────────────────────────────────────────

MIN_SAMPLES = int(os.getenv("BASELINE_MIN_SAMPLES", "20"))
Z_SCORE_THRESHOLD = float(os.getenv("BASELINE_Z_SCORE_THRESHOLD", "3.0"))
FLUSH_INTERVAL = int(os.getenv("BASELINE_FLUSH_INTERVAL", "300"))

# Targets for confidence calculation
STATISTICAL_TARGET_SAMPLES = 500      # samples for 100% confidence
TEMPORAL_TARGET_COVERAGE   = 0.60     # 60% of 168 hours covered
EMA_TARGET_OBSERVATIONS    = 200      # observations for 100% EMA confidence
PEER_TARGET_COUNT          = 3        # minimum peers for meaningful comparison

METRIC_CATEGORY: Dict[str, str] = {
    "dns_qpm":                   "dns",
    "unique_domains_per_hour":   "dns",
    "unique_ports_per_window":   "port_scan",
    "connection_rate":           "port_scan",
    "failed_auth_per_hour":      "auth",
    "auth_rate":                 "auth",
    "connection_count_per_hour": "connection",
    "unique_destinations":       "connection",
    "smb_connections":           "lateral_movement",
    "rdp_connections":           "lateral_movement",
    "unique_internal_dst":       "lateral_movement",
    "beacon_interval_std":       "c2",
    "outbound_connection_rate":  "c2",
}


# ── Method 1: Statistical (Welford) ─────────────────────────────────────────

@dataclass
class MetricStats:
    """Running statistics using Welford's online algorithm with reservoir sampling."""

    mean:         float = 0.0
    _m2:          float = 0.0
    sample_count: int   = 0
    min_observed: float = field(default_factory=lambda: float("inf"))
    max_observed: float = field(default_factory=lambda: float("-inf"))
    _reservoir:   List[float] = field(default_factory=list)
    _RESERVOIR_MAX: int = 200

    @property
    def variance(self) -> float:
        return self._m2 / (self.sample_count - 1) if self.sample_count >= 2 else 0.0

    @property
    def std_dev(self) -> float:
        return math.sqrt(max(0.0, self.variance))

    @property
    def p95(self) -> Optional[float]:
        if not self._reservoir:
            return None
        s = sorted(self._reservoir)
        return s[min(int(len(s) * 0.95), len(s) - 1)]

    def update(self, value: float) -> None:
        self.sample_count += 1
        delta  = value - self.mean
        self.mean += delta / self.sample_count
        delta2 = value - self.mean
        self._m2 += delta * delta2
        if value < self.min_observed:
            self.min_observed = value
        if value > self.max_observed:
            self.max_observed = value
        if len(self._reservoir) < self._RESERVOIR_MAX:
            self._reservoir.append(value)
        else:
            j = random.randint(0, self.sample_count - 1)
            if j < self._RESERVOIR_MAX:
                self._reservoir[j] = value

    def z_score(self, value: float) -> float:
        if self.std_dev < 1e-6 or self.sample_count < MIN_SAMPLES:
            return 0.0
        return (value - self.mean) / self.std_dev

    def is_anomalous(self, value: float) -> Tuple[bool, float]:
        if self.sample_count < MIN_SAMPLES:
            return False, 0.0
        z = self.z_score(value)
        return abs(z) > Z_SCORE_THRESHOLD, z

    def confidence(self) -> float:
        """How confident we are in this statistical baseline (0.0 – 1.0)."""
        if self.sample_count <= 0:
            return 0.0
        raw = self.sample_count / STATISTICAL_TARGET_SAMPLES
        # Use sqrt curve so early samples contribute more to perceived progress
        return min(1.0, math.sqrt(raw))

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
        s = cls()
        s.mean         = float(row.mean or 0)
        s.sample_count = int(row.sample_count or 0)
        std = float(row.std_dev or 0)
        s._m2 = (std ** 2) * max(s.sample_count - 1, 0)
        s.min_observed = float(row.min_observed) if row.min_observed is not None else float("inf")
        s.max_observed = float(row.max_observed) if row.max_observed is not None else float("-inf")
        if row.p95 is not None:
            s._reservoir = [float(row.p95)]
        return s


# ── Method 2: Temporal (hour-of-week seasonal) ──────────────────────────────

class TemporalProfile:
    """168 hour-of-week micro-baselines for seasonal pattern detection."""

    def __init__(self):
        # hour_of_week (0-167) -> MetricStats
        self.buckets: Dict[int, MetricStats] = {}

    def record(self, value: float, dt: Optional[datetime] = None) -> None:
        if dt is None:
            dt = datetime.now(timezone.utc)
        how = dt.weekday() * 24 + dt.hour
        if how not in self.buckets:
            self.buckets[how] = MetricStats()
        self.buckets[how].update(value)

    def is_anomalous(self, value: float, dt: Optional[datetime] = None) -> Tuple[bool, float, str]:
        if dt is None:
            dt = datetime.now(timezone.utc)
        how = dt.weekday() * 24 + dt.hour
        stats = self.buckets.get(how)
        if stats is None or stats.sample_count < MIN_SAMPLES:
            return False, 0.0, ""
        is_anom, z = stats.is_anomalous(value)
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        label = f"{day_names[dt.weekday()]} {dt.hour:02d}:00"
        return is_anom, z, label

    def coverage(self) -> float:
        """Fraction of 168 hours with at least MIN_SAMPLES data."""
        covered = sum(1 for s in self.buckets.values() if s.sample_count >= MIN_SAMPLES)
        return covered / 168.0

    def confidence(self) -> float:
        """Temporal learning confidence (0-1)."""
        return min(1.0, self.coverage() / TEMPORAL_TARGET_COVERAGE)

    def coverage_map(self) -> List[int]:
        """168-element list: sample_count per hour-of-week bucket."""
        return [self.buckets.get(h, MetricStats()).sample_count for h in range(168)]


# ── Method 3: Exponential Moving Average ─────────────────────────────────────

@dataclass
class EMATracker:
    """Exponential Moving Average with adaptive deviation bands.

    Uses two EMAs:
      * `ema_value` — smoothed average of the metric
      * `ema_dev`   — smoothed average of absolute deviation (for bands)

    Anomaly when ``|value - ema_value| > Z_SCORE_THRESHOLD * ema_dev``.
    """
    ema_value:     float = 0.0
    ema_dev:       float = 0.0
    count:         int   = 0
    _alpha:        float = 0.1    # smoothing factor (2 / (span+1)), span=19

    def update(self, value: float) -> None:
        self.count += 1
        if self.count == 1:
            self.ema_value = value
            self.ema_dev   = 0.0
            return
        self.ema_value = self._alpha * value + (1 - self._alpha) * self.ema_value
        deviation = abs(value - self.ema_value)
        self.ema_dev = self._alpha * deviation + (1 - self._alpha) * self.ema_dev

    def is_anomalous(self, value: float) -> Tuple[bool, float]:
        if self.count < MIN_SAMPLES or self.ema_dev < 1e-6:
            return False, 0.0
        z = (value - self.ema_value) / self.ema_dev
        return abs(z) > Z_SCORE_THRESHOLD, z

    def confidence(self) -> float:
        raw = self.count / EMA_TARGET_OBSERVATIONS
        return min(1.0, math.sqrt(raw))

    def to_dict(self) -> dict:
        return {
            "ema_value": round(self.ema_value, 4),
            "ema_dev":   round(self.ema_dev, 4),
            "count":     self.count,
        }


# ── Method 4: Peer Group Comparison ──────────────────────────────────────────

class PeerGroupEngine:
    """Compares entity metrics against /24 subnet peers.

    Maintains aggregate stats per subnet and flags hosts whose
    metrics deviate significantly from their peers.
    """

    def __init__(self):
        # (subnet_str, metric) -> MetricStats  (aggregate of all hosts in subnet)
        self._subnet_stats: Dict[Tuple[str, str], MetricStats] = {}
        # (subnet_str, metric) -> set of host IPs
        self._subnet_hosts: Dict[Tuple[str, str], set] = {}

    def _to_subnet(self, ip: str) -> Optional[str]:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    def record(self, host_ip: str, metric: str, value: float) -> None:
        subnet = self._to_subnet(host_ip)
        if not subnet:
            return
        key = (subnet, metric)
        if key not in self._subnet_stats:
            self._subnet_stats[key] = MetricStats()
            self._subnet_hosts[key] = set()
        self._subnet_stats[key].update(value)
        self._subnet_hosts[key].add(host_ip)

    def is_peer_anomalous(self, host_ip: str, metric: str, value: float) -> Tuple[bool, float]:
        """Check if value is anomalous relative to subnet peers."""
        subnet = self._to_subnet(host_ip)
        if not subnet:
            return False, 0.0
        key = (subnet, metric)
        stats = self._subnet_stats.get(key)
        if not stats or stats.sample_count < MIN_SAMPLES:
            return False, 0.0
        peers = self._subnet_hosts.get(key, set())
        if len(peers) < PEER_TARGET_COUNT:
            return False, 0.0
        return stats.is_anomalous(value)

    def peer_count(self, host_ip: str, metric: str) -> int:
        subnet = self._to_subnet(host_ip)
        if not subnet:
            return 0
        key = (subnet, metric)
        return len(self._subnet_hosts.get(key, set()))

    def confidence(self, host_ip: str, metric: str) -> float:
        subnet = self._to_subnet(host_ip)
        if not subnet:
            return 0.0
        key = (subnet, metric)
        stats = self._subnet_stats.get(key)
        peers = len(self._subnet_hosts.get(key, set()))
        if not stats:
            return 0.0
        sample_conf = min(1.0, stats.sample_count / STATISTICAL_TARGET_SAMPLES)
        peer_conf   = min(1.0, peers / PEER_TARGET_COUNT)
        return sample_conf * peer_conf


# ── Main Engine ──────────────────────────────────────────────────────────────

class BaselineEngine:
    """Multi-method behavioral baseline engine with learning mode support.

    Entity types: host, subnet, user, global.
    Methods: statistical, temporal, ema, peer_group.

    Learning modes (F5 WAF-style):
      * learning_mode = "on"  — active learning, baselines being built
      * learning_mode = "off" — frozen, no new observations recorded
      * enforcement_mode = "transparent" — log anomalies at info level only
      * enforcement_mode = "blocking"    — full alert generation
    """

    def __init__(self, db_session_factory=None):
        # Method 1: Statistical (Welford)
        self._stats: Dict[Tuple[str, str, str], MetricStats] = {}
        # Method 2: Temporal (hour-of-week)
        self._temporal: Dict[Tuple[str, str, str], TemporalProfile] = {}
        # Method 3: EMA
        self._ema: Dict[Tuple[str, str, str], EMATracker] = {}
        # Method 4: Peer Group
        self._peer = PeerGroupEngine()

        # Method 5: Observed-value sets (for reputation scoring).
        # Bounded per-key LRU of string values seen for (entity, metric).
        # Used by ReputationScorer to recognise "this destination is normal for
        # this host" and suppress associated risk. In-memory only for now;
        # warm-up time on pod restart is a few minutes for active hosts.
        from collections import OrderedDict as _OD
        self._observed_sets: Dict[Tuple[str, str, str], "_OD[str, float]"] = {}
        self._observed_set_max: int = 500  # entries per (entity, metric) key

        self._db_factory = db_session_factory
        self._last_flush: float = time.monotonic()

        # Learning mode — loaded from DB at startup
        self.learning_mode:    str   = "on"       # "on" | "off"
        self.enforcement_mode: str   = "transparent"  # "transparent" | "blocking"
        self.started_at:       float = time.time()

    # ── Observed-value sets (for reputation scoring) ─────────────────────────

    def record_observation(
        self,
        entity_type:  str,
        entity_value: str,
        metric:       str,
        value:        str,
    ) -> None:
        """Add a string observation (e.g. a destination IP or domain) to the
        bounded observed-set for (entity, metric). Oldest entries evict at cap.
        Frozen when learning_mode=='off'."""
        if self.learning_mode == "off" or not value or not entity_value:
            return
        key = (entity_type, entity_value.lower(), metric)
        from collections import OrderedDict as _OD
        od = self._observed_sets.get(key)
        if od is None:
            od = _OD()
            self._observed_sets[key] = od
        od[value] = time.monotonic()
        od.move_to_end(value)
        while len(od) > self._observed_set_max:
            od.popitem(last=False)

    def get_observed_set(
        self,
        entity_type:  str,
        entity_value: str,
        metric:       str,
    ) -> set:
        """Return the current bounded observed set as a plain set of strings.
        Empty set if nothing has been recorded for this key."""
        if not entity_value:
            return set()
        key = (entity_type, entity_value.lower(), metric)
        od = self._observed_sets.get(key)
        if od is None:
            return set()
        return set(od.keys())

    # ── Recording ─────────────────────────────────────────────────────────────

    def record(
        self,
        entity_type:  str,
        entity_value: str,
        metric:       str,
        value:        float,
    ) -> Tuple[bool, float]:
        """Record observation across all applicable methods.

        Returns (is_anomalous, z_score) from the statistical method.
        """
        if self.learning_mode == "off":
            # Frozen — still check for anomalies but don't update
            return self._check_anomaly(entity_type, entity_value, metric, value)

        key = (entity_type, entity_value.lower(), metric)

        # --- Method 1: Statistical ---
        if key not in self._stats:
            self._stats[key] = MetricStats()
        stats = self._stats[key]
        is_anom, z = stats.is_anomalous(value)
        stats.update(value)

        # Global aggregate
        global_key = ("global", "*", metric)
        if global_key not in self._stats:
            self._stats[global_key] = MetricStats()
        self._stats[global_key].update(value)

        # --- Method 2: Temporal ---
        if key not in self._temporal:
            self._temporal[key] = TemporalProfile()
        self._temporal[key].record(value)

        # --- Method 3: EMA ---
        if key not in self._ema:
            self._ema[key] = EMATracker()
        self._ema[key].update(value)

        # --- Method 4: Peer Group ---
        if entity_type == "host":
            self._peer.record(entity_value, metric, value)

        return is_anom, z

    def record_subnet(self, host_ip: str, metric: str, value: float) -> Tuple[bool, float]:
        parts = host_ip.split(".")
        if len(parts) != 4:
            return False, 0.0
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return self.record("subnet", subnet, metric, value)

    def _check_anomaly(
        self, entity_type: str, entity_value: str, metric: str, value: float
    ) -> Tuple[bool, float]:
        """Check anomaly without updating (for learning_mode=off)."""
        key = (entity_type, entity_value.lower(), metric)
        stats = self._stats.get(key)
        if stats:
            return stats.is_anomalous(value)
        return False, 0.0

    # ── Multi-method anomaly scoring ──────────────────────────────────────────

    def get_anomaly_score(
        self, entity_type: str, entity_value: str, metric: str, value: float
    ) -> dict:
        """Aggregate anomaly score across all methods.

        Returns {is_anomalous, score, methods: {statistical, temporal, ema, peer_group}}.
        """
        key = (entity_type, entity_value.lower(), metric)
        results = {}

        # Statistical
        stats = self._stats.get(key)
        if stats and stats.sample_count >= MIN_SAMPLES:
            is_a, z = stats.is_anomalous(value)
            results["statistical"] = {"anomalous": is_a, "z_score": round(z, 2)}

        # Temporal
        tp = self._temporal.get(key)
        if tp:
            is_a, z, label = tp.is_anomalous(value)
            if label:
                results["temporal"] = {"anomalous": is_a, "z_score": round(z, 2), "window": label}

        # EMA
        ema = self._ema.get(key)
        if ema and ema.count >= MIN_SAMPLES:
            is_a, z = ema.is_anomalous(value)
            results["ema"] = {"anomalous": is_a, "z_score": round(z, 2)}

        # Peer Group
        if entity_type == "host":
            is_a, z = self._peer.is_peer_anomalous(entity_value, metric, value)
            if z != 0:
                results["peer_group"] = {"anomalous": is_a, "z_score": round(z, 2)}

        # Aggregate: anomalous if ANY method flags it
        any_anomalous = any(m.get("anomalous") for m in results.values())
        max_z = max((abs(m.get("z_score", 0)) for m in results.values()), default=0)

        return {
            "is_anomalous": any_anomalous,
            "score":        round(max_z, 2),
            "methods":      results,
        }

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_baseline(
        self, entity_type: str, entity_value: str, metric: str,
    ) -> Optional[dict]:
        key = (entity_type, entity_value.lower(), metric)
        s = self._stats.get(key)
        return s.to_dict() if s else None

    def all_baselines(self) -> List[dict]:
        rows = []
        for (et, ev, metric), stats in self._stats.items():
            d = stats.to_dict()
            d["entity_type"]  = et
            d["entity_value"] = ev
            d["metric"]       = metric
            d["category"]     = METRIC_CATEGORY.get(metric, "unknown")
            rows.append(d)
        return rows

    # ── Learning Status ───────────────────────────────────────────────────────

    def get_learning_status(self) -> dict:
        """Return overall learning progress and per-method breakdown."""
        # Count unique (entity, metric) keys across all methods
        stat_keys = set(self._stats.keys())
        temp_keys = set(self._temporal.keys())
        ema_keys  = set(self._ema.keys())
        all_keys  = stat_keys | temp_keys | ema_keys

        if not all_keys:
            return {
                "overall_confidence": 0.0,
                "total_entities":     0,
                "total_metrics":      0,
                "learning_mode":      self.learning_mode,
                "enforcement_mode":   self.enforcement_mode,
                "methods": {
                    "statistical": {"confidence": 0, "baselines": 0, "total_samples": 0},
                    "temporal":    {"confidence": 0, "baselines": 0, "coverage": 0},
                    "ema":         {"confidence": 0, "baselines": 0, "total_observations": 0},
                    "peer_group":  {"confidence": 0, "subnets": 0, "total_peers": 0},
                },
                "categories": {},
                "maturity":  "initializing",
            }

        # Statistical confidence
        stat_confs  = [s.confidence() for s in self._stats.values()]
        stat_avg    = sum(stat_confs) / len(stat_confs) if stat_confs else 0
        stat_samples = sum(s.sample_count for s in self._stats.values())

        # Temporal confidence
        temp_confs   = [t.confidence() for t in self._temporal.values()]
        temp_avg     = sum(temp_confs) / len(temp_confs) if temp_confs else 0
        temp_coverage = sum(t.coverage() for t in self._temporal.values()) / len(self._temporal) if self._temporal else 0

        # EMA confidence
        ema_confs   = [e.confidence() for e in self._ema.values()]
        ema_avg     = sum(ema_confs) / len(ema_confs) if ema_confs else 0
        ema_obs     = sum(e.count for e in self._ema.values())

        # Peer Group confidence
        peer_subnets = len(self._peer._subnet_stats)
        peer_hosts   = sum(len(h) for h in self._peer._subnet_hosts.values())
        peer_confs   = []
        for (et, ev, metric) in stat_keys:
            if et == "host":
                pc = self._peer.confidence(ev, metric)
                if pc > 0:
                    peer_confs.append(pc)
        peer_avg = sum(peer_confs) / len(peer_confs) if peer_confs else 0

        # Overall = weighted average (statistical is primary)
        weights = {"statistical": 0.40, "temporal": 0.25, "ema": 0.20, "peer_group": 0.15}
        overall = (
            weights["statistical"] * stat_avg +
            weights["temporal"]    * temp_avg +
            weights["ema"]         * ema_avg +
            weights["peer_group"]  * peer_avg
        )

        # Entities and categories
        entities = set()
        categories: Dict[str, dict] = {}
        for (et, ev, metric) in all_keys:
            entities.add((et, ev))
            cat = METRIC_CATEGORY.get(metric, "unknown")
            if cat not in categories:
                categories[cat] = {"baselines": 0, "avg_confidence": 0, "samples": 0}
            categories[cat]["baselines"] += 1
            s = self._stats.get((et, ev, metric))
            if s:
                categories[cat]["samples"] += s.sample_count
                categories[cat]["avg_confidence"] += s.confidence()

        for cat in categories.values():
            if cat["baselines"] > 0:
                cat["avg_confidence"] = round(cat["avg_confidence"] / cat["baselines"] * 100, 1)

        # Maturity label
        if overall >= 0.90:
            maturity = "operational"
        elif overall >= 0.70:
            maturity = "nearly_ready"
        elif overall >= 0.45:
            maturity = "maturing"
        elif overall >= 0.20:
            maturity = "building"
        else:
            maturity = "initializing"

        # Unique metrics tracked
        metrics_set = set(m for (_, _, m) in all_keys)

        return {
            "overall_confidence":  round(overall * 100, 1),
            "total_entities":      len(entities),
            "total_metrics":       len(metrics_set),
            "learning_mode":       self.learning_mode,
            "enforcement_mode":    self.enforcement_mode,
            "started_at":          self.started_at,
            "methods": {
                "statistical": {
                    "confidence":     round(stat_avg * 100, 1),
                    "baselines":      len(self._stats),
                    "total_samples":  stat_samples,
                },
                "temporal": {
                    "confidence":       round(temp_avg * 100, 1),
                    "baselines":        len(self._temporal),
                    "coverage":         round(temp_coverage * 100, 1),
                },
                "ema": {
                    "confidence":           round(ema_avg * 100, 1),
                    "baselines":            len(self._ema),
                    "total_observations":   ema_obs,
                },
                "peer_group": {
                    "confidence":   round(peer_avg * 100, 1),
                    "subnets":      peer_subnets,
                    "total_peers":  peer_hosts,
                },
            },
            "categories": categories,
            "maturity":   maturity,
        }

    def get_temporal_heatmap(self) -> dict:
        """Return hour-of-week coverage heatmap across all entities.

        Returns {metric: [168 ints]} aggregated sample counts.
        """
        result: Dict[str, List[int]] = {}
        for (_, _, metric), tp in self._temporal.items():
            if metric not in result:
                result[metric] = [0] * 168
            for h in range(168):
                bucket = tp.buckets.get(h)
                if bucket:
                    result[metric][h] += bucket.sample_count
        return result

    # ── Persistence ───────────────────────────────────────────────────────────

    async def maybe_flush(self) -> None:
        if time.monotonic() - self._last_flush >= FLUSH_INTERVAL:
            await self.flush_to_db()
            await self.flush_time_to_db()
            self._last_flush = time.monotonic()

    async def flush_to_db(self) -> None:
        if not self._db_factory:
            return
        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                for (entity_type, entity_value, metric), stats in self._stats.items():
                    category = METRIC_CATEGORY.get(metric, "unknown")
                    d = stats.to_dict()
                    conf = stats.confidence()
                    await db.execute(sa_text("""
                        INSERT INTO behavioral_baselines
                          (entity_type, entity_value, metric, category, method,
                           mean, std_dev, sample_count, min_observed, max_observed, p95,
                           confidence_score, last_updated)
                        VALUES
                          (:entity_type, :entity_value, :metric, :category, 'statistical',
                           :mean, :std_dev, :sample_count, :min_observed, :max_observed, :p95,
                           :confidence_score, NOW())
                        ON CONFLICT (entity_type, entity_value, metric, method) DO UPDATE SET
                          mean             = EXCLUDED.mean,
                          std_dev          = EXCLUDED.std_dev,
                          sample_count     = EXCLUDED.sample_count,
                          min_observed     = EXCLUDED.min_observed,
                          max_observed     = EXCLUDED.max_observed,
                          p95              = EXCLUDED.p95,
                          confidence_score = EXCLUDED.confidence_score,
                          last_updated     = NOW()
                    """), {
                        "entity_type":      entity_type,
                        "entity_value":     entity_value,
                        "metric":           metric,
                        "category":         category,
                        "confidence_score": round(conf, 4),
                        **d,
                    })

                # Flush EMA stats as a separate method
                for (entity_type, entity_value, metric), ema in self._ema.items():
                    category = METRIC_CATEGORY.get(metric, "unknown")
                    await db.execute(sa_text("""
                        INSERT INTO behavioral_baselines
                          (entity_type, entity_value, metric, category, method,
                           mean, std_dev, sample_count,
                           confidence_score, last_updated)
                        VALUES
                          (:entity_type, :entity_value, :metric, :category, 'ema',
                           :mean, :std_dev, :sample_count,
                           :confidence_score, NOW())
                        ON CONFLICT (entity_type, entity_value, metric, method) DO UPDATE SET
                          mean             = EXCLUDED.mean,
                          std_dev          = EXCLUDED.std_dev,
                          sample_count     = EXCLUDED.sample_count,
                          confidence_score = EXCLUDED.confidence_score,
                          last_updated     = NOW()
                    """), {
                        "entity_type":      entity_type,
                        "entity_value":     entity_value,
                        "metric":           metric,
                        "category":         category,
                        "mean":             round(ema.ema_value, 4),
                        "std_dev":          round(ema.ema_dev, 4),
                        "sample_count":     ema.count,
                        "confidence_score": round(ema.confidence(), 4),
                    })

                await db.commit()
            logger.debug("Flushed %d statistical + %d EMA baselines", len(self._stats), len(self._ema))
        except Exception as exc:
            logger.warning("Baseline flush failed: %s", exc)

    async def load_from_db(self) -> None:
        if not self._db_factory:
            return
        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                rows = (await db.execute(sa_text(
                    "SELECT entity_type, entity_value, metric, method, "
                    "mean, std_dev, sample_count, min_observed, max_observed, p95 "
                    "FROM behavioral_baselines"
                ))).fetchall()
            stat_count = ema_count = 0
            for row in rows:
                method = getattr(row, 'method', 'statistical')
                if method == 'ema':
                    key = (row.entity_type, row.entity_value.lower(), row.metric)
                    ema = EMATracker()
                    ema.ema_value = float(row.mean or 0)
                    ema.ema_dev   = float(row.std_dev or 0)
                    ema.count     = int(row.sample_count or 0)
                    self._ema[key] = ema
                    ema_count += 1
                else:
                    key = (row.entity_type, row.entity_value.lower(), row.metric)
                    self._stats[key] = MetricStats.from_db_row(row)
                    stat_count += 1
            logger.info("Loaded %d statistical + %d EMA baselines from database", stat_count, ema_count)
        except Exception as exc:
            logger.warning("Failed to load baselines from database: %s", exc)

    async def flush_time_to_db(self) -> None:
        if not self._db_factory or not self._temporal:
            return
        try:
            from sqlalchemy import text as sa_text
            count = 0
            async with self._db_factory() as db:
                for (entity_type, entity_value, metric), tp in self._temporal.items():
                    for how, stats in tp.buckets.items():
                        d = stats.to_dict()
                        await db.execute(sa_text("""
                            INSERT INTO baseline_time_patterns
                              (entity_type, entity_value, metric, hour_of_week,
                               mean, std_dev, sample_count, last_updated)
                            VALUES
                              (:entity_type, :entity_value, :metric, :hour_of_week,
                               :mean, :std_dev, :sample_count, NOW())
                            ON CONFLICT (entity_type, entity_value, metric, hour_of_week) DO UPDATE SET
                              mean         = EXCLUDED.mean,
                              std_dev      = EXCLUDED.std_dev,
                              sample_count = EXCLUDED.sample_count,
                              last_updated = NOW()
                        """), {
                            "entity_type":  entity_type,
                            "entity_value": entity_value,
                            "metric":       metric,
                            "hour_of_week": how,
                            "mean":         d["mean"],
                            "std_dev":      d["std_dev"],
                            "sample_count": d["sample_count"],
                        })
                        count += 1
                await db.commit()
            logger.debug("Flushed %d time-pattern entries", count)
        except Exception as exc:
            logger.warning("Time-pattern flush failed: %s", exc)

    async def load_time_from_db(self) -> None:
        if not self._db_factory:
            return
        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                rows = (await db.execute(sa_text(
                    "SELECT entity_type, entity_value, metric, hour_of_week, "
                    "mean, std_dev, sample_count FROM baseline_time_patterns"
                ))).fetchall()
            for row in rows:
                key = (row.entity_type, row.entity_value.lower(), row.metric)
                if key not in self._temporal:
                    self._temporal[key] = TemporalProfile()
                stats = MetricStats()
                stats.mean         = float(row.mean or 0)
                stats.sample_count = int(row.sample_count or 0)
                std = float(row.std_dev or 0)
                stats._m2 = (std ** 2) * max(stats.sample_count - 1, 0)
                self._temporal[key].buckets[row.hour_of_week] = stats
            logger.info("Loaded %d time-pattern entries from database", len(rows))
        except Exception as exc:
            logger.warning("Failed to load time-patterns: %s", exc)

    async def load_learning_config(self) -> None:
        """Load learning/enforcement mode from DB."""
        if not self._db_factory:
            return
        try:
            from sqlalchemy import text as sa_text
            async with self._db_factory() as db:
                row = (await db.execute(sa_text(
                    "SELECT learning_mode, enforcement_mode, started_at "
                    "FROM baseline_learning_config LIMIT 1"
                ))).fetchone()
            if row:
                self.learning_mode    = row.learning_mode
                self.enforcement_mode = row.enforcement_mode
                self.started_at       = row.started_at.timestamp() if row.started_at else time.time()
                logger.info(
                    "Learning config: mode=%s enforcement=%s",
                    self.learning_mode, self.enforcement_mode,
                )
        except Exception as exc:
            logger.warning("Failed to load learning config: %s", exc)
