"""External threat-feed integration for URL intelligence.

Sources
-------
* URLhaus (abuse.ch)           — bulk text feed, tens of thousands of
                                  active malware URLs. Refreshed every
                                  ``TI_FEEDS_REFRESH_SECS`` (default 300s).
* OpenPhish community          — bulk text feed of active phishing URLs.
* Spamhaus DBL                 — live DNS-based per-domain lookup
                                  (``<etld1>.dbl.spamhaus.org``).
* Google Safe Browsing v4      — live per-URL API lookup *if*
                                  ``GSB_API_KEY`` is set.

Reliability contract
--------------------
Every lookup is **fail-open**: any network, parse, or DNS error is logged
at DEBUG and treated as "unknown" (not a hit). The service's hot path
never blocks on a feed for more than ``TI_FEEDS_HTTP_TIMEOUT`` (default
8 s) for bulk refresh or 2 s for DBL/GSB.

Environment knobs
-----------------
    TI_FEEDS_REFRESH_SECS    bulk-feed refresh period (default 300)
    TI_FEEDS_HTTP_TIMEOUT    seconds (default 8)
    TI_FEEDS_DBL_ENABLED     "1" / "0" (default "1")
    TI_FEEDS_DBL_RESOLVERS   comma list (default "1.1.1.1,8.8.8.8")
    TI_FEEDS_URLHAUS_URL     override feed URL
    TI_FEEDS_OPENPHISH_URL   override feed URL
    TI_FEEDS_DISABLE_URLHAUS   "1" to skip
    TI_FEEDS_DISABLE_OPENPHISH "1" to skip
    GSB_API_KEY              optional — enables Google Safe Browsing v4

Usage
-----
    reg = ThreatFeedRegistry()
    await reg.start()             # launches refresh loop
    verdict = await reg.lookup(url, host, etld1)
    # verdict.any_definitive, verdict.score, verdict.as_dict()
    await reg.stop()
"""
from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import logging
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urlparse

log = logging.getLogger("ti.url_intel.feeds")

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
    _HAS_DNS = True
except ImportError:  # pragma: no cover
    _HAS_DNS = False

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:  # pragma: no cover
    _HAS_AIOHTTP = False


# ─── Configuration ────────────────────────────────────────────────────────────

FEED_REFRESH_SECS = int(os.environ.get("TI_FEEDS_REFRESH_SECS", "300"))
HTTP_TIMEOUT      = float(os.environ.get("TI_FEEDS_HTTP_TIMEOUT", "8"))

URLHAUS_URL   = os.environ.get(
    "TI_FEEDS_URLHAUS_URL", "https://urlhaus.abuse.ch/downloads/text/")
OPENPHISH_URL = os.environ.get(
    "TI_FEEDS_OPENPHISH_URL", "https://openphish.com/feed.txt")

DISABLE_URLHAUS   = os.environ.get("TI_FEEDS_DISABLE_URLHAUS", "0") == "1"
DISABLE_OPENPHISH = os.environ.get("TI_FEEDS_DISABLE_OPENPHISH", "0") == "1"

DBL_ENABLED = os.environ.get("TI_FEEDS_DBL_ENABLED", "1") == "1"
DBL_ZONE    = "dbl.spamhaus.org"
DBL_RESOLVERS = [s.strip() for s in
                 os.environ.get("TI_FEEDS_DBL_RESOLVERS",
                                 "1.1.1.1,8.8.8.8").split(",")
                 if s.strip()]

GSB_API_KEY = os.environ.get("GSB_API_KEY", "")
GSB_URL     = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Spamhaus DBL response-code → human label (per their published docs).
# Any 127.0.1.x answer means "listed"; the specific x disambiguates.
_DBL_CODES: Dict[str, str] = {
    "127.0.1.2":   "spam",
    "127.0.1.4":   "phish",
    "127.0.1.5":   "malware",
    "127.0.1.6":   "botnet_c2",
    "127.0.1.102": "abused_legit_spam",
    "127.0.1.103": "abused_legit_redir",
    "127.0.1.104": "abused_legit_phish",
    "127.0.1.105": "abused_legit_malware",
    "127.0.1.106": "abused_legit_botnet",
    "127.0.1.255": "test_entry",
}

# Spamhaus error responses (client is querying from a public/abusive
# resolver). Treat as "unknown", not as a hit.
_DBL_ERROR_PREFIXES = ("127.255.255.", "127.0.0.")


# ─── Verdict shape ───────────────────────────────────────────────────────────

@dataclass
class FeedVerdict:
    urlhaus_hit:    bool = False
    openphish_hit:  bool = False
    dbl_hit:        bool = False
    dbl_reason:     str  = ""
    gsb_hit:        bool = False
    gsb_threat:     str  = ""

    @property
    def any_definitive(self) -> bool:
        """True iff any authoritative feed flagged this URL / host / domain."""
        return bool(self.urlhaus_hit or self.openphish_hit
                    or self.dbl_hit or self.gsb_hit)

    @property
    def score(self) -> float:
        """Aggregate malicious confidence in [0, 1].

        Zero hits → 0.0 (neutral; NOT evidence of benign).
        One hit    → 0.90   (single authoritative source agrees)
        Two hits   → 0.96
        Three      → 0.984
        Four       → 0.9936
        """
        hits = int(self.urlhaus_hit) + int(self.openphish_hit) \
             + int(self.dbl_hit)    + int(self.gsb_hit)
        if hits == 0:
            return 0.0
        return float(1.0 - 0.1 * (0.4 ** (hits - 1)))

    def as_dict(self) -> Dict[str, object]:
        return dataclasses.asdict(self)


# ─── Registry ────────────────────────────────────────────────────────────────

class ThreatFeedRegistry:
    """In-memory bulk-feed sets + live DBL/GSB queries with TTL cache."""

    def __init__(self) -> None:
        self._urlhaus_urls:    Set[str] = set()
        self._urlhaus_hosts:   Set[str] = set()
        self._openphish_urls:  Set[str] = set()
        self._openphish_hosts: Set[str] = set()
        self._last_refresh: float = 0.0
        self._refresh_task: Optional[asyncio.Task] = None
        self._session:      Optional["aiohttp.ClientSession"] = None
        self._dbl_cache: Dict[str, Tuple[float, Tuple[bool, str]]] = {}
        self._gsb_cache: Dict[str, Tuple[float, Tuple[bool, str]]] = {}
        self._dbl_resolver: Optional["dns.asyncresolver.Resolver"] = None
        if _HAS_DNS and DBL_ENABLED:
            r = dns.asyncresolver.Resolver(configure=False)
            r.nameservers = DBL_RESOLVERS
            r.timeout  = 2.0
            r.lifetime = 2.5
            self._dbl_resolver = r

    # ── Lifecycle ─────────────────────────────────────────────────────────
    async def start(self) -> None:
        if not _HAS_AIOHTTP:
            log.warning("aiohttp not installed — URLhaus/OpenPhish/GSB disabled")
            return
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
            headers={"User-Agent": "ti-platform-url-intel/1.0"},
        )
        self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def stop(self) -> None:
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
            self._refresh_task = None
        if self._session:
            await self._session.close()
            self._session = None

    @property
    def stats(self) -> Dict[str, object]:
        return {
            "urlhaus_urls":    len(self._urlhaus_urls),
            "urlhaus_hosts":   len(self._urlhaus_hosts),
            "openphish_urls":  len(self._openphish_urls),
            "openphish_hosts": len(self._openphish_hosts),
            "last_refresh_ago": (
                None if self._last_refresh == 0.0
                else round(time.monotonic() - self._last_refresh, 1)
            ),
            "dbl_enabled": self._dbl_resolver is not None,
            "gsb_enabled": bool(GSB_API_KEY),
        }

    # ── Refresh loop ──────────────────────────────────────────────────────
    async def _refresh_loop(self) -> None:
        try:
            await self._refresh_once()
        except Exception as exc:
            log.warning("initial feed refresh failed: %s", exc)
        while True:
            try:
                await asyncio.sleep(FEED_REFRESH_SECS)
                await self._refresh_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("feed refresh failed: %s", exc)

    async def _refresh_once(self) -> None:
        if self._session is None:
            return
        jobs = []
        if not DISABLE_URLHAUS:
            jobs.append(("urlhaus",   self._fetch_text(URLHAUS_URL)))
        if not DISABLE_OPENPHISH:
            jobs.append(("openphish", self._fetch_text(OPENPHISH_URL)))
        if not jobs:
            return
        results = await asyncio.gather(*[j[1] for j in jobs],
                                        return_exceptions=True)
        for (name, _), res in zip(jobs, results):
            if isinstance(res, Exception):
                log.warning("feed %s refresh failed: %s", name, res)
                continue
            urls, hosts = _parse_feed(res)
            if name == "urlhaus":
                self._urlhaus_urls, self._urlhaus_hosts = urls, hosts
            elif name == "openphish":
                self._openphish_urls, self._openphish_hosts = urls, hosts
            log.info("feed %s loaded: %d urls, %d hosts",
                     name, len(urls), len(hosts))
        self._last_refresh = time.monotonic()

    async def _fetch_text(self, url: str) -> str:
        assert self._session is not None
        async with self._session.get(url) as r:
            r.raise_for_status()
            return await r.text()

    # ── Lookup ────────────────────────────────────────────────────────────
    async def lookup(self, url: str, host: str, etld1: str) -> FeedVerdict:
        """Consult all configured feeds for *url* / *host* / *etld1*."""
        v = FeedVerdict()
        url_norm = _canon_for_match(url)
        host = (host or "").lower()
        etld1 = (etld1 or "").lower()

        # Bulk-feed set membership — O(1) per check
        v.urlhaus_hit = (
            (url_norm in self._urlhaus_urls)
            or (host  and host  in self._urlhaus_hosts)
            or (etld1 and etld1 in self._urlhaus_hosts)
        )
        v.openphish_hit = (
            (url_norm in self._openphish_urls)
            or (host  and host  in self._openphish_hosts)
            or (etld1 and etld1 in self._openphish_hosts)
        )

        # DBL — skip for IP literals (DBL keys on domain names)
        if self._dbl_resolver and etld1 and not _looks_like_ip(etld1):
            v.dbl_hit, v.dbl_reason = await self._dbl_check(etld1)

        # GSB — per-URL API
        if GSB_API_KEY and self._session is not None and url:
            v.gsb_hit, v.gsb_threat = await self._gsb_check(url)

        return v

    async def _dbl_check(self, etld1: str) -> Tuple[bool, str]:
        now = time.monotonic()
        cached = self._dbl_cache.get(etld1)
        if cached and (now - cached[0]) < 3600:
            return cached[1]
        assert self._dbl_resolver is not None
        try:
            qname = f"{etld1}.{DBL_ZONE}"
            ans = await self._dbl_resolver.resolve(qname, "A")
            ips = {str(r) for r in ans}
            # Ignore Spamhaus rate-limit / error responses
            real_hits = [ip for ip in ips
                          if not any(ip.startswith(p) for p in _DBL_ERROR_PREFIXES)
                          or ip in _DBL_CODES]
            hit = any(ip.startswith("127.0.1.") for ip in real_hits)
            reason = ""
            if hit:
                for ip in real_hits:
                    reason = _DBL_CODES.get(ip, reason or "listed")
                    if reason and reason != "listed":
                        break
            self._dbl_cache[etld1] = (now, (hit, reason))
            return hit, reason
        except dns.resolver.NXDOMAIN:
            self._dbl_cache[etld1] = (now, (False, ""))
            return False, ""
        except (dns.exception.DNSException, asyncio.TimeoutError) as exc:
            log.debug("DBL lookup error for %s: %s", etld1, exc)
            return False, ""
        except Exception as exc:  # defensive
            log.debug("DBL unexpected error for %s: %s", etld1, exc)
            return False, ""

    async def _gsb_check(self, url: str) -> Tuple[bool, str]:
        now = time.monotonic()
        cached = self._gsb_cache.get(url)
        if cached and (now - cached[0]) < 3600:
            return cached[1]
        body = {
            "client": {"clientId": "ti-platform", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes":     ["ANY_PLATFORM"],
                "threatEntryTypes":  ["URL"],
                "threatEntries":     [{"url": url}],
            },
        }
        assert self._session is not None
        try:
            async with self._session.post(
                f"{GSB_URL}?key={GSB_API_KEY}", json=body,
                timeout=aiohttp.ClientTimeout(total=2.5),
            ) as r:
                if r.status != 200:
                    return False, ""
                data = await r.json()
                matches = data.get("matches") or []
                if matches:
                    threat = str(matches[0].get("threatType", "listed"))
                    self._gsb_cache[url] = (now, (True, threat))
                    return True, threat
                self._gsb_cache[url] = (now, (False, ""))
                return False, ""
        except Exception as exc:
            log.debug("GSB lookup error: %s", exc)
            return False, ""


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _parse_feed(text: str) -> Tuple[Set[str], Set[str]]:
    """Return (normalised-urls, hostnames) parsed from a line-based feed."""
    urls:  Set[str] = set()
    hosts: Set[str] = set()
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        urls.add(_canon_for_match(s))
        try:
            u = s if "://" in s else "http://" + s
            h = (urlparse(u).hostname or "").lower()
            if h:
                hosts.add(h)
        except Exception:
            # Feed lines are best-effort; skip unparseable entries
            pass
    return urls, hosts


def _canon_for_match(url: str) -> str:
    """Minimal canonicalisation for feed-set membership.

    * lowercase scheme + host
    * strip trailing '/'
    * drop fragment

    Kept deliberately weaker than a full URL normaliser: we want the
    canonical form to be reproducible between what URLhaus publishes and
    what the service sees. Over-normalising risks false-negatives.
    """
    if not url:
        return ""
    s = url.strip()
    # fragment
    if "#" in s:
        s = s.split("#", 1)[0]
    # lowercase scheme+authority
    if "://" in s:
        scheme, rest = s.split("://", 1)
        slash = rest.find("/")
        if slash < 0:
            s = scheme.lower() + "://" + rest.lower()
        else:
            s = scheme.lower() + "://" + rest[:slash].lower() + rest[slash:]
    else:
        s = s.lower()
    if s.endswith("/") and s.count("/") > 2:
        s = s[:-1]
    return s


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False
