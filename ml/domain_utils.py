"""eTLD+1 (registrable-domain) extraction via the Public Suffix List.

Why this module exists
----------------------
The URL-intel service originally used ``urlparse(url).hostname.lower()`` as
the "domain" for reputation lookups. That treats ``a.evil.co.uk`` and
``b.evil.co.uk`` as *different* domains, because ``.co.uk`` is not a real
TLD — it's a public-suffix-defined one. The registrable-domain view
(``evil.co.uk``) is how every mainstream TI product slices the address
space and how a subdomain-spray campaign actually maps to a shared owner.

Public API
----------
    extract_hostname(url) -> str   # lowercase host, empty on failure
    extract_etld1(url)    -> str   # eTLD+1 (registrable domain)
    is_ip_literal(host)   -> bool  # helper used by callers

Depends on ``tldextract`` when available; falls back to a naive
``last-two-labels`` approximation otherwise, so the service still boots
on a minimal image without the dep.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from urllib.parse import urlparse

try:
    import tldextract
    # Default cache dir — tldextract auto-refreshes the PSL every 30 days.
    # `include_psl_private_domains=True` widens the list to registrar-known
    # private suffixes (blogspot.com, github.io, etc.) which is what a TI
    # system wants: we should treat `victim.github.io` as its own entity,
    # not lump all of github.io under one reputation row.
    _EXT = tldextract.TLDExtract(include_psl_private_domains=True)
    _HAS_TLDEXTRACT = True
except ImportError:  # pragma: no cover — degraded mode
    _EXT = None
    _HAS_TLDEXTRACT = False


def is_ip_literal(host: str) -> bool:
    """True if *host* is an IPv4/IPv6 literal (with or without brackets)."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


@lru_cache(maxsize=65536)
def extract_hostname(url: str) -> str:
    """Lowercase hostname for *url*, empty string on failure.

    Tolerates scheme-less input (``example.com/foo``) by prepending
    ``http://`` before parsing.
    """
    if not url:
        return ""
    u = url if "://" in url else "http://" + url
    try:
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""


@lru_cache(maxsize=65536)
def extract_etld1(url: str) -> str:
    """Registrable (eTLD+1) domain for *url*.

    Examples
    --------
    >>> extract_etld1("https://a.b.example.co.uk/path")
    'example.co.uk'
    >>> extract_etld1("http://192.168.1.1/x")
    '192.168.1.1'
    >>> extract_etld1("evil.com")
    'evil.com'
    >>> extract_etld1("victim.github.io")
    'victim.github.io'

    Falls back to the last two labels when ``tldextract`` is not installed.
    Returns ``""`` on unparseable input.
    """
    host = extract_hostname(url)
    if not host:
        return ""
    if is_ip_literal(host):
        return host
    if not _HAS_TLDEXTRACT:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    result = _EXT(host)
    # `registered_domain` == "evil.co.uk"; empty for IPs / unknown TLDs
    return (result.registered_domain or host).lower()
