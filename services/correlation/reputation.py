"""
Reputation-aware risk scorer for behavioral detection rules.

Replaces "count >= threshold" detection with a weighted risk sum where
each event's contribution depends on the reputation of its destination.

Known-good / learned / popular destinations contribute ~0 to the risk sum,
so recon against internal prod servers or DNS queries to popular domains
stop generating alerts. Unknown / TI-matched / newly-seen / high-entropy
destinations contribute heavily, so real scans and DNS tunneling still fire.

A volumetric DoS floor is applied on top so that true volumetric events
(e.g. >500 unique ports/5m, >300 DNS qps) still alert regardless of
reputation — this is what the rules.py callers layer on.

This module is pure-Python and side-effect free beyond a bounded LRU cache
and optional async batched upsert into domain_first_seen.
"""
from __future__ import annotations

import ipaddress
import logging
import math
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import tldextract

logger = logging.getLogger("correlation.reputation")

# ── Tranco list ───────────────────────────────────────────────────────────────
TRANCO_PATH = Path(os.getenv("TRANCO_LIST_PATH", "/app/data/tranco_top100k.txt"))

# ── Weights (defaults; override via platform_settings in Milestone 2) ────────
DEFAULT_WEIGHTS = {
    "base":              1.0,   # unknown destination starts here
    "whitelist":        -1.0,   # -> 0.0 if whitelisted
    "baseline_match":   -1.0,   # -> 0.0 if in per-host learned set
    "peer_baseline":    -0.8,   # -> 0.2 if in /24 peer-group baseline
    "tranco":           -0.8,   # -> 0.2 for Tranco Top 100k parent domains
    "rfc1918":          -0.5,   # -> 0.5 for RFC1918 internal destinations
    "ti_match":         +2.0,   # bumped by TI indicator match
    "nrd":              +1.5,   # newly-registered domain (<30 days)
    "high_entropy":     +0.8,   # DNS label entropy > 3.8
    "long_label":       +0.5,   # DNS label > 40 chars
    "uncommon_tld":     +0.5,   # .xyz / .top / .cc / .ru / .tk / .ml / .ga / .pw / .click
    "unusual_rrtype":   +0.5,   # TXT / NULL in high volume
    "first_seen_recent": +0.5,  # first_seen < 24h ago globally
    "unusual_port":     +0.3,   # destination contacted only on non-standard ports
    # M3: behavioural-embedding cosine similarity between this host and the
    # destination's "normal caller centroid". Interpolated piecewise between
    # a "near" and "far" cosine threshold.
    "learned_similarity":  +1.0,  # bump when host is unusual-for-this-destination
    "learned_familiarity": -0.8,  # discount when host is typical-for-this-destination
}

# Default interpolation thresholds for the learned_similarity factor.
# cosine <= FAR_COS   -> apply full learned_similarity (risk bump)
# cosine >= NEAR_COS  -> apply full learned_familiarity (risk discount)
# between             -> linearly interpolate to 0 at midpoint.
_DEFAULT_LEARNED_FAR_COS  = 0.30
_DEFAULT_LEARNED_NEAR_COS = 0.85

# TLD risk list — these are consistently over-represented in malicious
# infrastructure per industry reports. Users can extend this list via
# platform_settings in Milestone 2.
UNCOMMON_TLDS: Set[str] = {
    "xyz", "top", "cc", "ru", "tk", "ml", "ga", "pw", "click", "loan",
    "country", "stream", "download", "gdn", "racing", "win", "bid",
    "party", "review", "trade", "date", "faith", "science", "accountant",
    "men", "cricket", "work",
}

# These RR-types are legitimate but uncommon enough that high volume is suspicious
UNUSUAL_RRTYPES: Set[str] = {"TXT", "NULL", "SRV", "ANY"}

# Extract parent-domain using a pre-loaded suffix list for speed
_tldex = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


# ── Utility helpers ──────────────────────────────────────────────────────────

def _is_rfc1918(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def _parent_domain(domain: str) -> Optional[str]:
    """Return the registrable parent (e.g. 'x.foo.google.com' -> 'google.com')."""
    if not domain:
        return None
    ext = _tldex(domain.lower())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


def _tld(domain: str) -> Optional[str]:
    if not domain:
        return None
    ext = _tldex(domain.lower())
    return (ext.suffix or "").lower() or None


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _longest_label(domain: str) -> int:
    if not domain:
        return 0
    return max((len(lbl) for lbl in domain.split(".") if lbl), default=0)


_DOMAIN_RE = re.compile(
    r"\b((?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24})\b"
)


def extract_domain_from_log(log) -> Optional[str]:
    """Best-effort: pull a DNS query name out of a ParsedLog."""
    # Prefer IOC-extracted domains
    for itype, value in (log.iocs or []):
        if itype == "domain" and value:
            return value.lower()
    # Fallback: first plausible domain in raw text
    if log.raw:
        m = _DOMAIN_RE.search(log.raw)
        if m:
            return m.group(1).lower()
    return None


# ── LRU cache (async-safe within single-threaded asyncio) ───────────────────

class _TTLCache:
    """Tiny TTL+LRU cache — no external deps, asyncio-safe."""

    def __init__(self, maxsize: int = 50000, ttl: int = 3600):
        self.maxsize = maxsize
        self.ttl = ttl
        self._data: "OrderedDict[Any, Tuple[float, Any]]" = OrderedDict()

    def get(self, key: Any) -> Optional[Any]:
        hit = self._data.get(key)
        if hit is None:
            return None
        ts, val = hit
        if time.monotonic() - ts > self.ttl:
            self._data.pop(key, None)
            return None
        # LRU bump
        self._data.move_to_end(key)
        return val

    def put(self, key: Any, value: Any) -> None:
        if key in self._data:
            self._data.move_to_end(key)
        self._data[key] = (time.monotonic(), value)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


# ── ReputationScorer ─────────────────────────────────────────────────────────

@dataclass
class ScoreBreakdown:
    """Transparent breakdown of how a single-event risk score was computed.

    Useful for logging suppression decisions and for the eventual UI drilldown.
    """
    weight: float = 0.0
    factors: Dict[str, float] = field(default_factory=dict)

    def add(self, name: str, value: float) -> None:
        self.factors[name] = value
        self.weight += value


class ReputationScorer:
    """Per-destination and per-DNS-query risk weighting.

    Scores are in [0.0, 5.0]:
      0.0 = known-good (whitelisted / baseline / Tranco top)
      1.0 = unknown (no information either way)
      3.0+ = TI-matched or multiple negative signals
    """

    def __init__(
        self,
        baseline_engine=None,
        whitelist_cache=None,
        tranco_path: Path = TRANCO_PATH,
        weights: Optional[Dict[str, float]] = None,
    ) -> None:
        self.baseline_engine = baseline_engine
        self.whitelist_cache = whitelist_cache
        self.weights = dict(DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)

        # Tranco Top 100k loaded as frozenset of parent domains
        self.tranco: frozenset = self._load_tranco(tranco_path)

        # Short-TTL cache keyed by (src_ip, dst_ip|domain)
        self._cache = _TTLCache(maxsize=50000, ttl=600)

        # TI-matched IP set: populated externally per log-event by main.py
        # (main.py already builds `ti_matched_ips` from real TI lookups).
        self._ti_ips: Set[str] = set()

        # Set of domains known to have first_seen within the last 24h.
        # Updated periodically from domain_first_seen table.
        self._recent_domains: Set[str] = set()

        # M3: learned behavioural embeddings.
        # host_embeddings[src_ip]       -> list[float]  (L2-normalized, 32-dim)
        # dst_embeddings[dst_ip]        -> list[float]  (destination's normal-caller centroid)
        # Both are refreshed periodically from entity_embedding by main.py.
        self._host_embeddings: Dict[str, List[float]] = {}
        self._dst_embeddings:  Dict[str, List[float]] = {}
        self._learned_far_cos:  float = _DEFAULT_LEARNED_FAR_COS
        self._learned_near_cos: float = _DEFAULT_LEARNED_NEAR_COS

        logger.info(
            "ReputationScorer loaded: tranco=%d domains, weights=%s",
            len(self.tranco), {k: round(v, 2) for k, v in self.weights.items()},
        )

    # ── Data loaders ─────────────────────────────────────────────────────────

    @staticmethod
    def _load_tranco(path: Path) -> frozenset:
        if not path.is_file():
            logger.warning("Tranco list not found at %s — popular-domain suppression disabled", path)
            return frozenset()
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                entries = {line.strip().lower() for line in fh if line.strip()}
            # Normalise to parent domain to handle both "google.com" and "www.google.com"
            parents = set()
            for entry in entries:
                parent = _parent_domain(entry) or entry
                parents.add(parent)
            return frozenset(parents)
        except Exception as exc:
            logger.warning("Failed to load Tranco list from %s: %s", path, exc)
            return frozenset()

    def set_ti_ips(self, ti_ips: Iterable[str]) -> None:
        """Called by main.py per-event with the set of destination IPs that
        matched a TI indicator in the current batch. Stored as a shallow ref."""
        self._ti_ips = set(ti_ips or ())

    def update_recent_domains(self, recent: Iterable[str]) -> None:
        """Update the set of first-seen-<24h domains. Call periodically."""
        self._recent_domains = {d.lower() for d in recent}

    def update_embeddings(
        self,
        host_vectors:  Dict[str, List[float]],
        dst_vectors:   Dict[str, List[float]],
        far_cos:  Optional[float] = None,
        near_cos: Optional[float] = None,
    ) -> None:
        """Replace the learned-embedding caches.

        Called by main.py's periodic refresh loop after the learner job
        has written new rows to entity_embedding. Input vectors must already
        be L2-normalized (the learner does this).
        """
        self._host_embeddings = dict(host_vectors)
        self._dst_embeddings  = dict(dst_vectors)
        if far_cos  is not None: self._learned_far_cos  = float(far_cos)
        if near_cos is not None: self._learned_near_cos = float(near_cos)
        # Invalidate per-destination scoring cache — weights effectively changed
        # for any (src, dst) pair now covered by the new embeddings.
        self._cache = _TTLCache(maxsize=self._cache.maxsize, ttl=self._cache.ttl)
        logger.info(
            "ReputationScorer embeddings refreshed: hosts=%d destinations=%d far=%.2f near=%.2f",
            len(self._host_embeddings), len(self._dst_embeddings),
            self._learned_far_cos, self._learned_near_cos,
        )

    # ── Learned-similarity scoring ───────────────────────────────────────────

    @staticmethod
    def _cosine(u: List[float], v: List[float]) -> float:
        """Cosine similarity between two already-L2-normalized vectors.

        Both learner-produced vectors are already unit-normalized, so this
        is just a dot product. Guards against dimension mismatch (different
        model version loaded on either side) by returning 0.0.
        """
        if len(u) != len(v) or not u:
            return 0.0
        return sum(a * b for a, b in zip(u, v))

    def _learned_similarity_factor(self, src_ip: Optional[str], dst_ip: Optional[str]) -> Optional[Tuple[str, float]]:
        """Return (factor_name, weight_contribution) or None.

        Maps cosine similarity to a risk contribution:
          cos <= far_cos   -> full "learned_similarity" weight (unusual pair, risk bump)
          cos >= near_cos  -> full "learned_familiarity" weight (typical pair, discount)
          between          -> linear interpolation through 0 at midpoint
        """
        if not src_ip or not dst_ip:
            return None
        hv = self._host_embeddings.get(src_ip)
        dv = self._dst_embeddings.get(dst_ip)
        if hv is None or dv is None:
            return None
        cos = self._cosine(hv, dv)
        far  = self._learned_far_cos
        near = self._learned_near_cos
        if near <= far:  # mis-configured — avoid divide-by-zero
            return None
        if cos <= far:
            return ("learned_similarity", self.weights.get("learned_similarity", 0.0))
        if cos >= near:
            return ("learned_familiarity", self.weights.get("learned_familiarity", 0.0))
        # Linear interpolation: cos=far -> +sim_weight, cos=near -> +fam_weight
        sim_w = self.weights.get("learned_similarity",  0.0)
        fam_w = self.weights.get("learned_familiarity", 0.0)
        t = (cos - far) / (near - far)      # 0 at far, 1 at near
        contribution = sim_w * (1 - t) + fam_w * t
        name = "learned_similarity" if contribution >= 0 else "learned_familiarity"
        return (name, contribution)

    # ── Scoring ──────────────────────────────────────────────────────────────

    def score_destination(
        self,
        src_ip: Optional[str],
        dst_ip: Optional[str] = None,
        dst_domain: Optional[str] = None,
        dst_port: Optional[int] = None,
    ) -> ScoreBreakdown:
        """Score a (src -> dst) pair. Returns a breakdown summing to the final weight."""
        cache_key = (src_ip, dst_ip or "", dst_domain or "")
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        br = ScoreBreakdown()
        br.add("base", self.weights["base"])

        # RFC1918 / loopback → known-infra, lower weight but still non-zero
        if dst_ip and _is_rfc1918(dst_ip):
            br.add("rfc1918", self.weights["rfc1918"])

        # Whitelist check (covers ip, cidr, hostname, indicator_value)
        if self.whitelist_cache is not None:
            try:
                if self.whitelist_cache.is_whitelisted(
                    dst_ip=dst_ip, hostname=dst_domain,
                    indicator_value=dst_ip or dst_domain,
                ):
                    br.add("whitelist", self.weights["whitelist"])
            except Exception as exc:
                logger.debug("Whitelist check raised: %s", exc)

        # Per-host baseline — is this destination already in the learned set?
        if self.baseline_engine is not None and src_ip:
            try:
                observed = self.baseline_engine.get_observed_set("host", src_ip, "destinations")
                if dst_ip and dst_ip in observed:
                    br.add("baseline_match", self.weights["baseline_match"])
                elif dst_domain and dst_domain.lower() in observed:
                    br.add("baseline_match", self.weights["baseline_match"])
            except AttributeError:
                pass  # baseline_engine doesn't have get_observed_set yet

        # Peer-group baseline (/24)
        if self.baseline_engine is not None and src_ip:
            try:
                peer = self.baseline_engine.get_observed_set("subnet", self._subnet_of(src_ip), "destinations")
                if dst_ip and dst_ip in peer:
                    br.add("peer_baseline", self.weights["peer_baseline"])
                elif dst_domain and dst_domain.lower() in peer:
                    br.add("peer_baseline", self.weights["peer_baseline"])
            except AttributeError:
                pass

        # Tranco popular-domain suppression
        if dst_domain:
            parent = _parent_domain(dst_domain)
            if parent and parent in self.tranco:
                br.add("tranco", self.weights["tranco"])

        # TI-indicator match
        if dst_ip and dst_ip in self._ti_ips:
            br.add("ti_match", self.weights["ti_match"])

        # Newly-registered / first-seen
        if dst_domain:
            parent = _parent_domain(dst_domain) or dst_domain.lower()
            if parent in self._recent_domains:
                br.add("first_seen_recent", self.weights["first_seen_recent"])

        # Uncommon TLD
        if dst_domain:
            tld = _tld(dst_domain)
            if tld and tld in UNCOMMON_TLDS:
                br.add("uncommon_tld", self.weights["uncommon_tld"])

        # M3: learned behavioural-embedding similarity.
        # Only applied for IP destinations (domain-based queries go through
        # score_dns_query which calls us first; duplicate lookup on domain
        # embeddings isn't meaningful — we key the caller-centroid on the
        # resolved dst_ip).
        learned = self._learned_similarity_factor(src_ip, dst_ip)
        if learned is not None:
            br.add(learned[0], learned[1])

        # Clamp to [0, 5]
        br.weight = max(0.0, min(5.0, br.weight))
        self._cache.put(cache_key, br)
        return br

    def score_dns_query(
        self,
        src_ip: Optional[str],
        query_name: str,
        qtype: Optional[str] = None,
    ) -> ScoreBreakdown:
        """Score a single DNS query. DNS-specific signals (entropy, label length,
        rare record type) are layered on top of the destination score."""
        if not query_name:
            return ScoreBreakdown(weight=self.weights["base"])

        query_name = query_name.lower().rstrip(".")
        parent = _parent_domain(query_name)

        # Start from the destination-style score (Tranco / first-seen / TLD)
        br = self.score_destination(src_ip=src_ip, dst_domain=query_name)

        # DNS-specific bumps applied on top of a fresh copy so cache stays pure
        br2 = ScoreBreakdown()
        br2.factors.update(br.factors)
        br2.weight = br.weight

        # Strong popular-domain floor: if parent is in Tranco, floor to near-0
        # regardless of entropy / length (legitimate CDN subdomains are often
        # high-entropy).
        if parent and parent in self.tranco:
            self._cache.put((src_ip, "", query_name), br2)
            return br2

        # Label-level entropy (strip parent; check just the sub-part)
        sub = query_name
        if parent and query_name.endswith(parent) and query_name != parent:
            sub = query_name[: -len(parent) - 1]
        if sub:
            longest = _longest_label(sub)
            if longest > 40:
                br2.add("long_label", self.weights["long_label"])

            entropy = _shannon_entropy(sub.replace(".", ""))
            if entropy > 3.8:
                br2.add("high_entropy", self.weights["high_entropy"])

        # Unusual RR-type
        if qtype and qtype.upper() in UNUSUAL_RRTYPES:
            br2.add("unusual_rrtype", self.weights["unusual_rrtype"])

        br2.weight = max(0.0, min(5.0, br2.weight))
        self._cache.put((src_ip, "", query_name), br2)
        return br2

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _subnet_of(ip: str) -> str:
        """Return the /24 (v4) or /64 (v6) key for peer-group lookups."""
        try:
            a = ipaddress.ip_address(ip)
            if isinstance(a, ipaddress.IPv4Address):
                return str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
            return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address)
        except ValueError:
            return ip

    # ── Weight hot-reload ────────────────────────────────────────────────────

    def apply_settings(self, settings: Dict[str, str]) -> None:
        """Replace weight defaults from a platform_settings dict. Called by the
        60-second refresh loop in main.py."""
        mapping = {
            "tranco_match_weight":        "tranco",
            "baseline_match_weight":      "baseline_match",
            "ti_match_weight":            "ti_match",
            "nrd_weight":                 "nrd",
            "unusual_tld_weight":         "uncommon_tld",
            "high_entropy_weight":        "high_entropy",
            "long_label_weight":          "long_label",
            "learned_similarity_weight":  "learned_similarity",
            "learned_familiarity_weight": "learned_familiarity",
        }
        for setting_key, weight_key in mapping.items():
            if setting_key in settings:
                try:
                    self.weights[weight_key] = float(settings[setting_key])
                except (TypeError, ValueError):
                    continue
        # Also pick up the cosine thresholds for the learned factor, if present
        if "learned_similarity_far_cos" in settings:
            try:
                self._learned_far_cos = float(settings["learned_similarity_far_cos"])
            except (TypeError, ValueError):
                pass
        if "learned_similarity_near_cos" in settings:
            try:
                self._learned_near_cos = float(settings["learned_similarity_near_cos"])
            except (TypeError, ValueError):
                pass
        # Invalidate cache since weights changed
        self._cache = _TTLCache(maxsize=self._cache.maxsize, ttl=self._cache.ttl)


# ── First-seen domain tracker (async batched) ────────────────────────────────

class DomainFirstSeenTracker:
    """Buffers domain observations and flushes to domain_first_seen every
    FLUSH_INTERVAL seconds. Keeps hot-path DB IO off the event loop."""

    FLUSH_INTERVAL = 30
    MAX_BUFFER = 10000

    def __init__(self, pool) -> None:
        self.pool = pool
        self._buffer: Dict[str, int] = {}   # domain -> observation count in this flush window

    def observe(self, domain: str) -> None:
        if not domain:
            return
        d = domain.lower().rstrip(".")
        # Store the parent; we don't need one row per subdomain
        parent = _parent_domain(d) or d
        if not parent:
            return
        self._buffer[parent] = self._buffer.get(parent, 0) + 1
        if len(self._buffer) > self.MAX_BUFFER:
            # Cap the buffer — drop rarest entries under load
            kept = sorted(self._buffer.items(), key=lambda kv: -kv[1])[: self.MAX_BUFFER // 2]
            self._buffer = dict(kept)

    async def flush(self) -> int:
        """Upsert buffered observations. Returns rows written."""
        if not self._buffer or self.pool is None:
            return 0
        items = list(self._buffer.items())
        self._buffer.clear()
        try:
            async with self.pool.acquire() as conn:
                await conn.executemany(
                    """
                    INSERT INTO domain_first_seen (domain, sample_count)
                    VALUES ($1, $2)
                    ON CONFLICT (domain) DO UPDATE SET
                      sample_count = domain_first_seen.sample_count + EXCLUDED.sample_count,
                      last_seen_at = NOW()
                    """,
                    items,
                )
            return len(items)
        except Exception as exc:
            logger.warning("domain_first_seen flush failed: %s", exc)
            return 0

    async def load_recent(self, max_age_hours: int = 24) -> List[str]:
        """Return parent-domains whose first_seen_at was within max_age_hours."""
        if self.pool is None:
            return []
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT domain
                    FROM domain_first_seen
                    WHERE first_seen_at > NOW() - INTERVAL '1 hour' * $1
                    """,
                    max_age_hours,
                )
            return [r["domain"] for r in rows]
        except Exception as exc:
            logger.warning("load_recent domains failed: %s", exc)
            return []
