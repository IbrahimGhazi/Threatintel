"""Async DNS enrichment for URL intelligence.

For a given hostname, produces a small bag of evidence features the
scoring layer can blend into the risk score:

    nxdomain         : bool   — the host does not resolve
    a_count          : int    — number of A records (fast-flux proxy)
    aaaa_count       : int    — number of AAAA records
    resolve_ms       : float  — wall-clock lookup cost
    first_ip         : str    — first resolved IPv4 (or empty)
    asn              : int    — autonomous-system number of first_ip (0 if unknown)
    country          : str    — ISO-2 country code (empty if unknown)
    is_private       : bool   — RFC1918 / loopback / link-local A record
    is_sinkhole      : bool   — matches a curated sinkhole IP list

From these, ``DnsFeatures.suspicion`` yields a 0..1 score that:

  * adds weight for many A records (fast-flux / bulletproof CDN)
  * adds weight for private / sinkhole resolutions
  * adds mild weight for rarely-seen ASNs (when pyasn is active)
  * NXDOMAIN is surfaced as a separate signal (not a risk multiplier):
    non-resolving URLs are usually stale, not malicious, so we flag
    rather than penalise.

Optional dependencies
---------------------
* ``dnspython``  : required — without it the module returns a no-op stub
* ``pyasn``      : optional — offline IP→ASN lookup, needs a periodic
                   ``pyasn_util_download.py`` DB refresh
                   (path via ``TI_DNS_PYASN_DB``)
* ``geoip2``     : optional — MaxMind GeoLite2-Country.mmdb for country
                   (path via ``TI_DNS_GEOIP_DB``)

Environment
-----------
    TI_DNS_TIMEOUT      seconds per lookup (default 2.0)
    TI_DNS_CACHE_TTL    seconds to cache a lookup (default 300)
    TI_DNS_CACHE_SIZE   LRU size (default 8192)
    TI_DNS_RESOLVERS    comma list (default "1.1.1.1,1.0.0.1")
    TI_DNS_PYASN_DB     filesystem path to ipasn_*.dat
    TI_DNS_GEOIP_DB     filesystem path to GeoLite2-Country.mmdb
"""
from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

log = logging.getLogger("ti.url_intel.dns")

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
    _HAS_DNS = True
except ImportError:  # pragma: no cover
    _HAS_DNS = False

try:
    import pyasn
    _HAS_PYASN = True
except ImportError:  # pragma: no cover
    _HAS_PYASN = False

try:
    import geoip2.database
    _HAS_GEOIP = True
except ImportError:  # pragma: no cover
    _HAS_GEOIP = False


# ─── Configuration ────────────────────────────────────────────────────────────

DNS_TIMEOUT     = float(os.environ.get("TI_DNS_TIMEOUT",    "2.0"))
CACHE_TTL       = int(  os.environ.get("TI_DNS_CACHE_TTL",  "300"))
CACHE_SIZE      = int(  os.environ.get("TI_DNS_CACHE_SIZE", "8192"))
DNS_RESOLVERS   = [s.strip() for s in
                    os.environ.get("TI_DNS_RESOLVERS",
                                    "1.1.1.1,1.0.0.1").split(",")
                    if s.strip()]
PYASN_DB        = os.environ.get("TI_DNS_PYASN_DB", "")
GEOIP_DB        = os.environ.get("TI_DNS_GEOIP_DB", "")

# A tiny curated list of public sinkhole IPs used by major takedowns.
# Not exhaustive; callers can extend via TI_DNS_SINKHOLE_IPS (comma list).
_SINKHOLE_IPS: frozenset = frozenset({
    "0.0.0.0",
    "127.0.0.1",
    "198.51.100.0",   # TEST-NET-2
    "203.0.113.0",    # TEST-NET-3
    "52.58.78.16",    # Microsoft DCU sinkhole
    "104.244.14.252", # Shadowserver sinkhole
} | set(s.strip() for s in
         os.environ.get("TI_DNS_SINKHOLE_IPS", "").split(",")
         if s.strip()))


# ─── Data shape ──────────────────────────────────────────────────────────────

@dataclass
class DnsFeatures:
    nxdomain:    bool   = False
    a_count:     int    = 0
    aaaa_count:  int    = 0
    resolve_ms:  float  = 0.0
    first_ip:    str    = ""
    asn:         int    = 0
    country:     str    = ""
    is_private:  bool   = False
    is_sinkhole: bool   = False
    error:       str    = ""  # human message when resolution failed non-NXDOMAIN

    @property
    def resolved(self) -> bool:
        return self.a_count > 0 or self.aaaa_count > 0

    @property
    def suspicion(self) -> float:
        """0..1 DNS-derived suspicion for blending into risk_score.

        NOT a probability — a soft-weighted sum capped via tanh-style
        saturation. Callers are expected to combine with other signals
        via their own blend (see the service).
        """
        raw = 0.0
        if self.is_sinkhole:
            raw += 1.0
        if self.is_private:
            raw += 0.9  # public-facing URL pointing at RFC1918 is always weird
        # Fast-flux heuristic: many records w/o a major CDN ASN (we don't
        # distinguish CDN ASNs in v1; the weight is deliberately small).
        if self.a_count >= 8:
            raw += 0.35
        elif self.a_count >= 5:
            raw += 0.20
        if self.aaaa_count >= 10:
            raw += 0.15
        # Soft saturation
        import math
        return float(1.0 - math.exp(-raw))

    def as_dict(self) -> Dict[str, object]:
        return dataclasses.asdict(self)


# ─── Enricher ────────────────────────────────────────────────────────────────

class DnsEnricher:
    """Cached async resolver + ASN/country enrichment."""

    def __init__(self) -> None:
        self._cache: Dict[str, Tuple[float, DnsFeatures]] = {}
        self._resolver: Optional["dns.asyncresolver.Resolver"] = None
        self._asndb:    Optional["pyasn.pyasn"] = None
        self._geodb:    Optional["geoip2.database.Reader"] = None

        if _HAS_DNS:
            r = dns.asyncresolver.Resolver(configure=True)
            if DNS_RESOLVERS:
                r.nameservers = DNS_RESOLVERS
            r.timeout  = DNS_TIMEOUT
            r.lifetime = DNS_TIMEOUT + 0.5
            self._resolver = r
        else:
            log.warning("dnspython not installed — DNS enrichment disabled")

        if _HAS_PYASN and PYASN_DB and os.path.isfile(PYASN_DB):
            try:
                self._asndb = pyasn.pyasn(PYASN_DB)
                log.info("pyasn loaded from %s", PYASN_DB)
            except Exception as exc:
                log.warning("pyasn init failed: %s", exc)
        if _HAS_GEOIP and GEOIP_DB and os.path.isfile(GEOIP_DB):
            try:
                self._geodb = geoip2.database.Reader(GEOIP_DB)
                log.info("geoip2 loaded from %s", GEOIP_DB)
            except Exception as exc:
                log.warning("geoip2 init failed: %s", exc)

    async def close(self) -> None:
        if self._geodb is not None:
            try:
                self._geodb.close()
            except Exception:
                pass

    # ── Public API ────────────────────────────────────────────────────────
    async def enrich(self, host: str) -> DnsFeatures:
        if not host or self._resolver is None:
            return DnsFeatures()

        # Short-circuit IP literals — no DNS needed
        if _is_ip_literal(host):
            ip = host.strip("[]")
            feats = DnsFeatures(first_ip=ip, a_count=1)
            self._annotate_ip(feats, ip)
            return feats

        now = time.monotonic()
        cached = self._cache.get(host)
        if cached and (now - cached[0]) < CACHE_TTL:
            return cached[1]

        # Manual LRU-lite: evict oldest when oversized
        if len(self._cache) > CACHE_SIZE:
            oldest = min(self._cache.items(), key=lambda kv: kv[1][0])[0]
            self._cache.pop(oldest, None)

        feats = await self._resolve(host)
        self._cache[host] = (now, feats)
        return feats

    # ── Internals ─────────────────────────────────────────────────────────
    async def _resolve(self, host: str) -> DnsFeatures:
        assert self._resolver is not None
        t0 = time.perf_counter()
        a, aaaa = await asyncio.gather(
            self._query(host, "A"),
            self._query(host, "AAAA"),
            return_exceptions=True,
        )

        a_records:    list = []
        aaaa_records: list = []
        nxdomain = False
        error = ""

        def _apply(result, sink: list) -> None:
            nonlocal nxdomain, error
            if isinstance(result, Exception):
                if isinstance(result, dns.resolver.NXDOMAIN):
                    nxdomain = True
                elif isinstance(result, dns.resolver.NoAnswer):
                    pass  # just no records of that type — fine
                else:
                    error = error or type(result).__name__
                return
            sink.extend(str(r) for r in result)

        _apply(a,    a_records)
        _apply(aaaa, aaaa_records)

        # If BOTH queries returned NXDOMAIN, we believe it. If only one did,
        # the host at least has one record type → not NXDOMAIN.
        if a_records or aaaa_records:
            nxdomain = False

        feats = DnsFeatures(
            nxdomain   = nxdomain,
            a_count    = len(a_records),
            aaaa_count = len(aaaa_records),
            resolve_ms = round((time.perf_counter() - t0) * 1000.0, 2),
            first_ip   = a_records[0] if a_records else "",
            error      = error,
        )
        if feats.first_ip:
            self._annotate_ip(feats, feats.first_ip)
        return feats

    async def _query(self, host: str, rtype: str):
        assert self._resolver is not None
        return await self._resolver.resolve(host, rtype)

    def _annotate_ip(self, feats: DnsFeatures, ip: str) -> None:
        # Private / sinkhole / ASN / country
        try:
            addr = ipaddress.ip_address(ip)
            feats.is_private = bool(
                addr.is_private or addr.is_loopback or addr.is_link_local
            )
        except ValueError:
            return
        feats.is_sinkhole = ip in _SINKHOLE_IPS
        if self._asndb is not None:
            try:
                asn, _ = self._asndb.lookup(ip)
                if asn:
                    feats.asn = int(asn)
            except Exception:
                pass
        if self._geodb is not None:
            try:
                rec = self._geodb.country(ip)
                if rec and rec.country and rec.country.iso_code:
                    feats.country = rec.country.iso_code
            except Exception:
                pass


# ─── Helper ──────────────────────────────────────────────────────────────────

def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False
