"""
Scoring formula — produces a 0..100 score and severity label per finding.

  score = 100 * sum(weight_i * factor_i)

with factors normalized to [0,1]. Weights are read from platform_settings
at run-start so tunings take effect on the next run, not mid-flight.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.engine.types import FanOutCandidate, PathCandidate


@dataclass
class Weights:
    exposure: float = 0.30
    proximity: float = 0.25
    branching: float = 0.20
    criticality: float = 0.25

    @classmethod
    def from_platform_settings(cls, settings_map: Dict[str, str]) -> "Weights":
        def f(key: str, default: float) -> float:
            try:
                return float(settings_map.get(key, default))
            except (TypeError, ValueError):
                return default
        return cls(
            exposure=f("attack_path_weight_exposure", 0.30),
            proximity=f("attack_path_weight_proximity", 0.25),
            branching=f("attack_path_weight_branching", 0.20),
            criticality=f("attack_path_weight_criticality", 0.25),
        )

    def as_json(self) -> Dict[str, float]:
        return {
            "exposure": self.exposure, "proximity": self.proximity,
            "branching": self.branching, "criticality": self.criticality,
        }


_CRITICALITY_FACTOR: Dict[str, float] = {
    "crown_jewel": 1.0,
    "high":        0.7,
    "medium":      0.4,
    "low":         0.2,
}
_DEFAULT_CRIT = 0.3   # 'unset' so absence doesn't zero everything out


def severity_from_score(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


# ── Path scoring ──────────────────────────────────────────────────────────────

def score_path(p: PathCandidate, *, weights: Weights,
               criticality: Optional[str],
               max_branching_observed: int = 1) -> Dict[str, Any]:
    # Exposure: paths are always rooted at Internet here, so exposure=1.0.
    # Untrusted-zone start would be 0.6; reachability_from_internet returns
    # only Internet-rooted paths so we keep this simple in the MVP.
    exposure = 1.0

    proximity = 1.0 / max(1, p.hops)

    # Branching factor: max member_count seen in any Pool node along the path.
    max_branch = 1
    for n in p.nodes:
        labels = n.get("labels") or []
        if "Pool" in labels:
            mc = (n.get("props") or {}).get("member_count")
            if isinstance(mc, int):
                max_branch = max(max_branch, mc)
    branching = min(1.0, math.log2(max_branch + 1) / math.log2(20))

    crit = _CRITICALITY_FACTOR.get(criticality or "", _DEFAULT_CRIT)

    score = 100.0 * (
        weights.exposure    * exposure +
        weights.proximity   * proximity +
        weights.branching   * branching +
        weights.criticality * crit
    )
    score = max(0.0, min(100.0, score))

    return {
        "score": round(score, 2),
        "severity": severity_from_score(score),
        "breakdown": {
            "exposure": exposure,
            "proximity": proximity,
            "branching": branching,
            "criticality": crit,
        },
    }


# ── Fan-out scoring ───────────────────────────────────────────────────────────

def score_fanout(c: FanOutCandidate, *, weights: Weights,
                 internet_reachable: bool) -> Dict[str, Any]:
    exposure = 1.0 if internet_reachable else 0.4

    branching = min(1.0, math.log2(c.outdeg + 1) / math.log2(20))

    # Asymmetry: fewer ingress paths → more concentrated risk.
    # ingress_paths in {0,1,2,3} → factor in [1.0, 0.8, 0.6, 0.4]
    asym_factor = max(0.4, 1.0 - 0.2 * c.ingress_paths)
    proximity = asym_factor

    # Fan-out criticality is taken as the average criticality of downstream
    # hosts in a follow-up step; for now use 'medium' as a neutral default.
    crit = _DEFAULT_CRIT

    score = 100.0 * (
        weights.exposure    * exposure +
        weights.proximity   * proximity +
        weights.branching   * branching +
        weights.criticality * crit
    )
    score = max(0.0, min(100.0, score))
    return {
        "score": round(score, 2),
        "severity": severity_from_score(score),
        "breakdown": {
            "exposure": exposure,
            "proximity": proximity,
            "branching": branching,
            "criticality": crit,
        },
    }
