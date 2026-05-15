"""Tests for pa_scrape_ingest — focused on the listing-page regex and
the last-run tracking that backs /firewall/advisories/health.

These are pure-function / module-state tests; no live HTTP, no DB.
"""
from __future__ import annotations

import re
import sys
import types
from pathlib import Path


# pa_scrape_ingest imports httpx at module load and csaf_ingest lazily, but the
# regex constants are at module top-level and don't need any service stack to
# exercise.  Stub heavy deps if missing so this runs on a clean dev box.
if "sqlalchemy" not in sys.modules:
    _sa = types.ModuleType("sqlalchemy")
    _sa.text = lambda s: s   # type: ignore[attr-defined]
    sys.modules["sqlalchemy"] = _sa

# Add the api/ root to sys.path so `import app.services...` works when the test
# is invoked directly (matches the test_license_* convention in this repo).
_API_ROOT = Path(__file__).resolve().parents[1]
if str(_API_ROOT) not in sys.path:
    sys.path.insert(0, str(_API_ROOT))


def test_listing_cve_regex_matches_pa_anchor_format():
    """The PA listing page renders each advisory row with an anchor of the form
    ``<a href="/CVE-YYYY-NNNN">…`` — _LISTING_CVE_RE must capture the path.

    Verified against live PA HTML on 2026-05-15.
    """
    from app.services.vendor_audit.pa_scrape_ingest import _LISTING_CVE_RE

    sample = '<tr><td><a href="/CVE-2026-0265" class="ng-binding">CVE-2026-0265</a></td></tr>'
    matches = _LISTING_CVE_RE.findall(sample)
    assert matches == ["/CVE-2026-0265"]


def test_listing_cve_regex_collects_multiple_ids():
    """A fragment with several CVE anchors yields one match per unique link."""
    from app.services.vendor_audit.pa_scrape_ingest import _LISTING_CVE_RE

    sample = (
        '<a href="/CVE-2020-10188">x</a>'
        '<a href="/CVE-2025-4231">y</a>'
        '<a href="/CVE-2026-0265">z</a>'
    )
    matches = _LISTING_CVE_RE.findall(sample)
    assert matches == ["/CVE-2020-10188", "/CVE-2025-4231", "/CVE-2026-0265"]


def test_listing_pansa_regex_matches_pansa_anchor_format():
    """PAN-SA-* bulletins use the same anchor convention as CVE rows."""
    from app.services.vendor_audit.pa_scrape_ingest import _LISTING_PANSA_RE

    sample = '<a href="/PAN-SA-2026-0010">PAN-SA-2026-0010</a>'
    matches = _LISTING_PANSA_RE.findall(sample)
    assert matches == ["/PAN-SA-2026-0010"]


def test_get_last_run_returns_none_before_any_ingest(monkeypatch):
    """Health endpoint must surface ``last_run=None`` before the first ingest
    so the UI can render a 'never run in this pod' state instead of a 500."""
    from app.services.vendor_audit import pa_scrape_ingest

    monkeypatch.setattr(pa_scrape_ingest, "_last_run", None)
    assert pa_scrape_ingest.get_last_run() is None


def test_get_last_run_returns_stats_dict_after_run(monkeypatch):
    """get_last_run reflects whatever ingest() last stored (used by
    /advisories/health to surface failures without log-tailing)."""
    from app.services.vendor_audit import pa_scrape_ingest

    sentinel = {"ok": True, "fetched": 7, "rows": 3, "inserted": 1,
                "source": "pa_scrape"}
    monkeypatch.setattr(pa_scrape_ingest, "_last_run", sentinel)
    assert pa_scrape_ingest.get_last_run() == sentinel
