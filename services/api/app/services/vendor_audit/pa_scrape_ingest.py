"""Direct ingestion from Palo Alto's security advisory pages.

This is the PRIMARY real-feed source as of 2026-05-05.  Replaces the
NVD ingester because:
  - PA's own pages publish at the moment of disclosure (no NVD lag)
  - PA encodes hotfix-precise version ranges (NVD's CPE format strips them)
  - PA has a "Required Configuration for Exposure" section we can read
    to drive auto-curation

Discovery flow
--------------
1. ``GET https://security.paloaltonetworks.com/rss.xml`` → list of recent
   ``<item>``s, each with title + link + pubDate.
2. For each link in the lookback window, ``GET <link>`` → HTML.
3. Parse the well-formed sections (H3 headings) for: title, description,
   severity, CVSS, required-config-text, solution, workarounds, the
   per-major-train affected/unaffected version table.
4. Convert to our ``vendor_advisories`` row shape.
5. Upsert via ``csaf_ingest._upsert_rows`` (curation preservation holds).

Configuration
-------------
``PA_SCRAPE_LOOKBACK_DAYS``  default 365  — RSS items older than this
                                              are skipped.
``PA_SCRAPE_BASE_URL``       default ``https://security.paloaltonetworks.com``
``PA_SCRAPE_FETCH_TIMEOUT``  default 20s
``PA_SCRAPE_DISABLED``       set ``true`` to skip the scrape entirely
                              (offline test mode).
"""
from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("ti.api")

PA_BASE_URL          = os.environ.get("PA_SCRAPE_BASE_URL", "https://security.paloaltonetworks.com").rstrip("/")
# Default lookback widened from 365 → 2200 days (2026-05-05).  PA's listing
# page returns the 300 most-recent advisories spanning ~6 years (oldest
# observed: CVE-2020-10188).  Firewall ops cycles are multi-year — a
# customer on PAN-OS 10.1 still benefits from knowing about 10.1-era CVEs.
# 2200 covers PA's entire listing without unbounding our query (PA's cap
# of 300 on the listing is the actual upper bound).
PA_LOOKBACK_DAYS     = int(os.environ.get("PA_SCRAPE_LOOKBACK_DAYS", "2200"))
PA_FETCH_TIMEOUT     = float(os.environ.get("PA_SCRAPE_FETCH_TIMEOUT", "20"))
PA_SCRAPE_DISABLED   = os.environ.get("PA_SCRAPE_DISABLED", "").lower() in ("1", "true", "yes")
PA_RSS_URL           = f"{PA_BASE_URL}/rss.xml"
# 2026-05-05 (followup-2-direct-v2): replace RSS (25 items) as primary
# discovery with the listing page filtered+sorted by date. PA caps the
# limit at 300; ?limit=500 returns 500 error.  300 covers ~6 years of
# advisories which is well past our 365-day lookback.
PA_LISTING_URL       = f"{PA_BASE_URL}/?sort=-date&limit=300"
PA_USER_AGENT        = os.environ.get("PA_SCRAPE_UA", "ti-platform/vendor-audit (+contact: tiplatform)")

# Conservative request pacing — PA's site is fast but we don't want to
# look like an attacker spraying requests.  At 0.5s between page fetches
# a 50-CVE ingest takes ~25 seconds, well under any reasonable rate limit.
PA_INTER_REQUEST_DELAY = float(os.environ.get("PA_SCRAPE_REQ_DELAY", "0.5"))


# ── Discovery (RSS) ───────────────────────────────────────────────────

_RSS_ITEM_RE   = re.compile(r"<item>(.*?)</item>", re.DOTALL)
_RSS_TITLE_RE  = re.compile(r"<title>(.*?)</title>", re.DOTALL)
_RSS_LINK_RE   = re.compile(r"<link>(.*?)</link>", re.DOTALL)
_RSS_PUB_RE    = re.compile(r"<pubDate>(.*?)</pubDate>", re.DOTALL)
_RSS_GUID_RE   = re.compile(r"<guid[^>]*>(.*?)</guid>", re.DOTALL)

# Listing-page CVE link pattern. Each row in the table has a `<a href="/CVE-…">`
# anchor for the advisory id. We only need the unique IDs — the per-page scrape
# pulls the actual data.
_LISTING_CVE_RE   = re.compile(r'href="(/CVE-\d{4}-\d+)"')
_LISTING_PANSA_RE = re.compile(r'href="(/PAN-SA-\d{4}-\d+)"')


async def _fetch_listing_advisory_ids(client: httpx.AsyncClient) -> List[Dict[str, str]]:
    """Discover advisory IDs from PA's listing page.

    Returns one dict per advisory: ``{advisory_id, link, title, pub_date_iso}``.
    Title and pub_date_iso are left empty here — the per-page scrape pulls
    them from the advisory's own HTML (Twitter card meta).

    Replaces the older RSS-based discovery (which only exposed ~25 items).
    """
    r = await client.get(PA_LISTING_URL, headers={"User-Agent": PA_USER_AGENT})
    r.raise_for_status()
    text = r.text

    cve_paths   = sorted(set(_LISTING_CVE_RE.findall(text)))
    pansa_paths = sorted(set(_LISTING_PANSA_RE.findall(text)))

    items: List[Dict[str, str]] = []
    for path in cve_paths + pansa_paths:
        adv_id = path.lstrip("/")
        items.append({
            "advisory_id":  adv_id,
            "link":         f"{PA_BASE_URL}{path}",
            "title":        adv_id,   # placeholder; overwritten by per-page scrape
            "pub_date_iso": "",       # ditto
        })
    return items


async def _fetch_rss_items(client: httpx.AsyncClient) -> List[Dict[str, str]]:
    """Legacy RSS-based discovery — kept for tests / fallback when the
    listing page changes shape.  Default ingest path uses
    ``_fetch_listing_advisory_ids`` instead."""
    r = await client.get(PA_RSS_URL, headers={"User-Agent": PA_USER_AGENT})
    r.raise_for_status()
    items: List[Dict[str, str]] = []
    for chunk in _RSS_ITEM_RE.findall(r.text):
        title_m = _RSS_TITLE_RE.search(chunk)
        link_m  = _RSS_LINK_RE.search(chunk)
        pub_m   = _RSS_PUB_RE.search(chunk)
        if not link_m:
            continue
        link = link_m.group(1).strip()
        adv_id = link.rstrip("/").rsplit("/", 1)[-1]
        title = title_m.group(1).strip() if title_m else adv_id
        pub_iso = ""
        if pub_m:
            pub_iso = _parse_pub_date(pub_m.group(1).strip())
        items.append({
            "advisory_id": adv_id, "link": link,
            "title": title, "pub_date_iso": pub_iso,
        })
    return items


def _parse_pub_date(s: str) -> str:
    """Convert RSS pubDate (RFC822 or ISO-ish) to ISO8601 in UTC."""
    s = (s or "").strip()
    # PA uses ISO-with-Z: "2026-04-08T18:05:00.000Z"
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d.astimezone(timezone.utc).isoformat()
    except Exception:
        pass
    # Fallback: RFC822 (rarely seen but be safe)
    try:
        from email.utils import parsedate_to_datetime
        d = parsedate_to_datetime(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc).isoformat()
    except Exception:
        return ""


# ── Per-page scraper ──────────────────────────────────────────────────

# Match a section's full content between an H3 of the given text and the next H2/H3.
def _section_re(heading_text: str) -> re.Pattern:
    return re.compile(
        r"<h3[^>]*>\s*" + re.escape(heading_text) + r"\s*</h3>(.*?)(?:<h[23][^>]*>|</main>|</article>|<footer)",
        re.DOTALL | re.IGNORECASE,
    )


_DESC_RE     = _section_re("Description")
_REQCFG_RE   = _section_re("Required Configuration for Exposure")
_SOLUTION_RE = _section_re("Solution")
_WORK_RE     = _section_re("Workarounds and Mitigations")
_EXPLOIT_RE  = _section_re("Exploitation Status")

_TITLE_RE    = re.compile(r"<h2[^>]*>(.*?)</h2>", re.DOTALL)
# PA puts severity in a Twitter card meta tag (consistent across all advisories).
# Avoids the noisier H3 "Severity: " markup that varies by template.
_SEV_RE      = re.compile(
    r'<meta[^>]+name="twitter:data1"[^>]+content="([A-Z]+)"', re.IGNORECASE,
)
# Published date also lives in a Twitter card meta tag (yyyy-mm-dd).
_PUB_META_RE = re.compile(
    r'<meta[^>]+name="twitter:data2"[^>]+content="(\d{4}-\d{2}-\d{2})"',
)
# PA's pages don't display a numeric CVSS score in the HTML — only the
# severity bucket (CRITICAL/HIGH/...). Leave cvss_score=None when scraping;
# the analyst still gets the severity bucket which is what drives alerting.
_CVSS_RE     = re.compile(r"CVSS\s*Base\s*Score[^<]*</?[a-z][^>]*>\s*([\d.]+)", re.IGNORECASE)
_CVSS_FALLBACK_RE = re.compile(r'class="cvss"[^>]*>\s*([0-9]\.[0-9])\s*<', re.IGNORECASE)
_TABLE_RE    = re.compile(r"<table[^>]*>(.*?)</table>", re.DOTALL)
_TR_RE       = re.compile(r"<tr[^>]*>(.*?)</tr>", re.DOTALL)
_TD_RE       = re.compile(r"<t[dh][^>]*>(.*?)</t[dh]>", re.DOTALL)


def _strip_html(s: str) -> str:
    """Remove tags, decode common entities, collapse whitespace."""
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = (s.replace("&nbsp;", " ")
           .replace("&lt;", "<").replace("&gt;", ">")
           .replace("&amp;", "&").replace("&quot;", '"')
           .replace("&#39;", "'").replace("&rsquo;", "'").replace("&lsquo;", "'")
           .replace("&ldquo;", '"').replace("&rdquo;", '"')
           .replace("&mdash;", "—").replace("&ndash;", "–"))
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _section_text(html: str, pat: re.Pattern) -> Optional[str]:
    m = pat.search(html)
    if not m:
        return None
    return _strip_html(m.group(1))


def parse_advisory_html(html: str, advisory_id: str) -> Dict[str, Any]:
    """Parse one PA advisory page.  Returns a dict of extracted fields.

    Resilient: missing sections become ``None`` rather than raising.
    """
    out: Dict[str, Any] = {
        "advisory_id":           advisory_id,
        "title":                 None,
        "severity":              None,
        "cvss_score":            None,
        "published_date":        None,   # YYYY-MM-DD from Twitter card meta
        "description":           None,
        "required_config":       None,
        "solution":              None,
        "workarounds":           None,
        "exploitation_status":   None,
        "products":              [],   # [{name, affected_ranges, unaffected_ranges}]
        "raw_html_size":         len(html),
    }

    # Title from the page's H2
    m = _TITLE_RE.search(html)
    if m:
        out["title"] = _strip_html(m.group(1))

    # Severity from Twitter card meta (CRITICAL/HIGH/MEDIUM/LOW/INFO/INFORMATIONAL)
    sev = _SEV_RE.search(html)
    if sev:
        s = sev.group(1).strip().lower()
        # PA uses "INFORMATIONAL" for PAN-SA-* style bulletins; map to our "info"
        if s == "informational":
            s = "info"
        out["severity"] = s

    # Published date from Twitter card meta — usually present and consistent
    pub_m = _PUB_META_RE.search(html)
    if pub_m:
        out["published_date"] = pub_m.group(1)

    # CVSS — try labeled then fallback to bare class="cvss" containing the score
    cvss = _CVSS_RE.search(html) or _CVSS_FALLBACK_RE.search(html)
    if cvss:
        try:
            out["cvss_score"] = float(cvss.group(1))
        except Exception:
            pass

    out["description"]         = _section_text(html, _DESC_RE)
    out["required_config"]     = _section_text(html, _REQCFG_RE)
    out["solution"]            = _section_text(html, _SOLUTION_RE)
    out["workarounds"]         = _section_text(html, _WORK_RE)
    out["exploitation_status"] = _section_text(html, _EXPLOIT_RE)

    # Version table — first <table> with a "Versions"/"Version" header
    for tbl in _TABLE_RE.findall(html):
        rows = _TR_RE.findall(tbl)
        if not rows:
            continue
        header_cells = [_strip_html(c) for c in _TD_RE.findall(rows[0])]
        if not header_cells:
            continue
        # The version table has 3 header cells: Versions / Affected / Unaffected
        if len(header_cells) >= 3 and (
            "version" in header_cells[0].lower() and
            "affected" in header_cells[1].lower() and
            ("unaffected" in header_cells[2].lower() or "fixed" in header_cells[2].lower())
        ):
            for r in rows[1:]:
                cells = [_strip_html(c) for c in _TD_RE.findall(r)]
                if len(cells) < 3:
                    continue
                product = cells[0]
                aff_raw = cells[1]
                unaff_raw = cells[2]
                if not product or product.lower() == "version":
                    continue
                out["products"].append({
                    "name":              product,
                    "affected_raw":      aff_raw,
                    "unaffected_raw":    unaff_raw,
                    "affected_ranges":   _pa_cell_to_ranges(product, aff_raw, kind="affected"),
                    "unaffected_ranges": _pa_cell_to_ranges(product, unaff_raw, kind="unaffected"),
                })
            break  # Only the first matching table — stop after we got it

    return out


# ── PA version cell → DSL ranges ──────────────────────────────────────

# A single version token, possibly with a "-h<N>" hotfix or "-c<N>" RC suffix.
_TOKEN_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?(?:-[chr]\d+)*")
# Just the major.minor prefix from a major-train header like "PAN-OS 11.1"
_TRAIN_RE = re.compile(r"\b(\d+)\.(\d+)\b")
# Filter to PAN-OS rows only (not Cloud NGFW / Prisma Access / GlobalProtect App).
# Rows that contain "PAN-OS" + a major-train number are what we want.
_PANOS_HEAD_RE = re.compile(r"\bPAN-OS\b\s*(\d+)\.(\d+)", re.IGNORECASE)


def _pa_cell_to_ranges(product_name: str, cell_text: str, *, kind: str) -> List[str]:
    """Convert one cell of PA's version table into our DSL range strings.

    PA notation per row, by example::

        product = "PAN-OS 11.1"
        affected = "< 11.1.0-h3, < 11.1.1-h1, < 11.1.2-h3"
            → [">=11.1.0,<11.1.0-h3",
               ">=11.1.1,<11.1.1-h1",
               ">=11.1.2,<11.1.2-h3"]

        affected = "None"  → []
        affected = "All"   → [">=<train>.0"]   (everything in the train)

    The lower bound for each entry is the train+patch prefix of the
    upper-bound version (e.g. "<11.1.0-h3" → ">=11.1.0").
    """
    if not cell_text:
        return []
    text = cell_text.strip()
    low = text.lower()
    if low in ("none", "n/a", ""):
        return []

    # Identify the train prefix from the product name (e.g. "PAN-OS 11.1" → "11.1").
    train_m = _PANOS_HEAD_RE.search(product_name)
    if not train_m:
        # Non-PAN-OS row (Cloud NGFW, Prisma Access, GlobalProtect App, etc.).
        # We only audit PAN-OS, so skip.
        return []
    train_prefix = f"{train_m.group(1)}.{train_m.group(2)}"

    # "All" means every version in this PAN-OS train is affected/unaffected.
    # Critically, the bound MUST be limited to the row's train — without an
    # upper bound, an "PAN-OS 10.1 All" row would sweep up 11.x and 12.x as
    # APPLIES (causing many false positives observed 2026-05-05 against IIPL).
    # Cap at the next-minor `.0` of the same major to keep the range inside
    # the row's scope (e.g. PAN-OS 10.1 All → >=10.1.0,<10.2.0).
    if low.startswith("all"):
        try:
            train_major, train_minor = train_prefix.split(".", 1)
            next_minor_train = f"{train_major}.{int(train_minor) + 1}.0"
            return [f">={train_prefix}.0,<{next_minor_train}"]
        except Exception:
            return [f">={train_prefix}.0"]

    # Tokenize the cell.  Comma OR run-of-whitespace separated; each token
    # may have a leading "<" / "<=" / ">" / ">=" / "==" operator.
    # We strip the operators and just collect the version literals.
    out: List[str] = []
    # Split on commas first, then whitespace within each piece.
    pieces: List[str] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        # Some cells use whitespace as separator: "< 11.2.0-h1 < 11.2.1-h1 ..."
        # so split each part on the next "<"/">"/"==" boundary too.
        sub = re.split(r"(?=<|>|==)", part)
        for s in sub:
            s = s.strip()
            if s:
                pieces.append(s)

    for p in pieces:
        # Each piece looks like "< 11.1.0-h3" or ">= 11.1.0-h3"
        op_m = re.match(r"^\s*([<>]=?|==)\s*(.+)$", p)
        if not op_m:
            # Sometimes a bare version: treat as "< this" (PA's column convention)
            ver_m = _TOKEN_VERSION_RE.search(p)
            if not ver_m:
                continue
            op = "<" if kind == "affected" else ">="
            ver = ver_m.group(0)
        else:
            op = op_m.group(1)
            ver_m = _TOKEN_VERSION_RE.search(op_m.group(2))
            if not ver_m:
                continue
            ver = ver_m.group(0)

        # We only emit affected ranges in our DSL; unaffected gets converted
        # to a "fixed_versions" hint for the caller.
        if kind != "affected":
            continue

        if op in ("<",):
            # ">=<train>.0,<<ver>" — vulnerable below the fix
            # Prefix the train-patch lower bound where possible (avoid implying
            # 11.2.x is affected by an 11.1 row).
            # Use the patch component of the upper bound as the lower bound's
            # patch component when ver starts with the train prefix; otherwise
            # fall back to <train>.0.
            patch_m = re.match(r"(\d+\.\d+\.\d+)", ver)
            lower_bound = (patch_m.group(1) if patch_m and ver.startswith(train_prefix + ".") else f"{train_prefix}.0")
            # Avoid degenerate empty ranges.
            if lower_bound != ver:
                out.append(f">={lower_bound},<{ver}")
        elif op in ("<=",):
            patch_m = re.match(r"(\d+\.\d+\.\d+)", ver)
            lower_bound = (patch_m.group(1) if patch_m and ver.startswith(train_prefix + ".") else f"{train_prefix}.0")
            out.append(f">={lower_bound},<={ver}")
        elif op == "==":
            out.append(f"=={ver}")
        elif op in (">=",):
            # Rare in 'affected' cells but tolerated.
            out.append(f">={ver}")
        elif op == ">":
            out.append(f">{ver}")

    return out


# ── Top-level ingest ───────────────────────────────────────────────────

def to_row(scraped: Dict[str, Any], pub_iso: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Convert a parsed advisory page into a ``vendor_advisories`` row.

    Returns None for advisories that don't audit-target PAN-OS firewalls
    (e.g. GlobalProtect-app-only or Prisma-only advisories).
    """
    advisory_id = scraped.get("advisory_id")
    if not advisory_id:
        return None
    # Only insert proper CVE entries here — informational PAN-SA-* bulletins
    # don't have a CVE id and don't carry version data we can match on.
    if not advisory_id.startswith("CVE-"):
        return None

    # Filter: at least one product row must be PAN-OS-on-firewall.
    panos_products = [
        p for p in (scraped.get("products") or [])
        if "pan-os" in (p.get("name") or "").lower()
    ]
    if not panos_products:
        return None

    affected: List[str] = []
    fixed: List[str] = []
    products: List[str] = []

    for p in panos_products:
        if p["name"] not in products:
            products.append(p["name"])
        for r in (p.get("affected_ranges") or []):
            if r and r not in affected:
                affected.append(r)
        # Pull "fixed in" hints out of the unaffected_raw text — best-effort.
        # Each "≥X.Y.Z-hN" token in the unaffected column is a candidate fix.
        for m in re.finditer(r">=\s*(\d+\.\d+\.\d+(?:-[ch]\d+)*)", p.get("unaffected_raw") or ""):
            v = m.group(1)
            if v not in fixed:
                fixed.append(v)

    # Skip advisories whose only "affected" entry is empty (None/All-only rows).
    if not affected:
        return None

    severity = (scraped.get("severity") or "").lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = "info"

    # Prefer the scraped Twitter-card published date (the original PA disclosure
    # date) over the RSS pubDate (which can be a re-publish/edit date).
    pub_dt = (
        _parse_iso((scraped.get("published_date") or "") + "T00:00:00+00:00")
        or _parse_iso(pub_iso)
        or datetime.now(timezone.utc)
    )

    refs = [f"{PA_BASE_URL}/{advisory_id}"]

    return {
        "vendor":             "palo_alto",
        "cve_id":             advisory_id,
        "vendor_advisory_id": None,    # PA pages don't expose PSIRT id consistently in HTML
        "title":              scraped.get("title") or advisory_id,
        "description":        scraped.get("description"),
        "cvss_score":         scraped.get("cvss_score"),
        "cvss_severity":      severity,
        "published_at":       pub_dt,
        "updated_at":         pub_dt,
        "affected_products":  products,
        "affected_versions":  affected,
        "fixed_versions":     fixed,
        "preconditions":      {},   # human/LLM-curated separately
        "workaround":         scraped.get("workarounds"),
        "references_urls":    refs,
        "raw_advisory":       {"source": "pa_scrape",
                               "required_config_text": scraped.get("required_config"),
                               "solution_text":        scraped.get("solution"),
                               "exploitation_status":  scraped.get("exploitation_status")},
        "curation_status":    "uncurated",
    }


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


import asyncio


# Module-level cache of the most recent ingest result.  Lets operators query
# /firewall/advisories/health to see what the last run did without having to
# tail pod logs.  Reset on every ingest() call.  None until first run.
_last_run: Optional[Dict[str, Any]] = None


def get_last_run() -> Optional[Dict[str, Any]]:
    """Return the stats dict from the most recent ingest() call (success or
    failure), or None if ingest has never run in this process.

    Used by the /firewall/advisories/health endpoint so operators can see
    fetched/inserted counts and any error without tailing logs."""
    return _last_run


async def ingest(*, days: int = PA_LOOKBACK_DAYS) -> Dict[str, Any]:
    """Discover advisories via PA's listing page, scrape each in-window page,
    parse, upsert.

    Discovery:
      ``GET /?sort=-date&limit=300`` — gives up to 300 advisory IDs spanning
      ~6 years of disclosures (PA caps the limit at 300; ?limit=500 errors).
      We then filter to the last ``days`` (default 365) by the per-page
      Twitter-card published date.

    Returns a stats dict suitable for the daily-cycle response.
    """
    global _last_run

    if PA_SCRAPE_DISABLED:
        stats = {"ok": True, "skipped": "PA_SCRAPE_DISABLED set", "fetched": 0,
                 "elapsed_ms": 0, "source": "pa_scrape",
                 "finished_at": datetime.now(timezone.utc).isoformat()}
        _last_run = stats
        logger.info("pa_scrape: ingest skipped (PA_SCRAPE_DISABLED set)")
        return stats

    t0 = time.monotonic()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    headers = {"User-Agent": PA_USER_AGENT}
    rows: List[Dict[str, Any]] = []
    skipped_old      = 0
    skipped_pan_sa   = 0
    parse_failed     = 0
    fetched_pages    = 0
    # Categorise per-page failures so operators see *why* the listing
    # yielded fewer rows than expected (HTTP errors vs. non-PAN-OS rows
    # filtered out by to_row vs. unhandled parse exceptions).
    failure_reasons  = {"http_error": 0, "filtered_non_panos": 0, "exception": 0}
    listing_total    = 0

    try:
        async with httpx.AsyncClient(timeout=PA_FETCH_TIMEOUT, follow_redirects=True,
                                     headers=headers) as cli:
            items = await _fetch_listing_advisory_ids(cli)
            listing_total = len(items)
            logger.info("pa_scrape: %d advisories on listing page", listing_total)

            # Skip PAN-SA-* informational bulletins (no CVE id, no version match
            # data we can use). They're mostly Chromium-monthly-roll-up notices.
            cve_items = [it for it in items if it["advisory_id"].startswith("CVE-")]
            skipped_pan_sa = len(items) - len(cve_items)

            for item in cve_items:
                try:
                    r = await cli.get(item["link"])
                    if r.status_code != 200:
                        parse_failed += 1
                        failure_reasons["http_error"] += 1
                        logger.debug("pa_scrape: %s returned HTTP %s",
                                     item["link"], r.status_code)
                        continue
                    fetched_pages += 1
                    scraped = parse_advisory_html(r.text, item["advisory_id"])

                    # Cutoff filter — uses the per-page Twitter card published
                    # date (more accurate than any external feed claim).
                    pub_date = scraped.get("published_date")
                    if pub_date:
                        pub_dt = _parse_iso(pub_date + "T00:00:00+00:00")
                        if pub_dt and pub_dt < cutoff:
                            skipped_old += 1
                            continue

                    row = to_row(scraped, pub_iso=None)
                    if row is None:
                        parse_failed += 1
                        failure_reasons["filtered_non_panos"] += 1
                        continue
                    rows.append(row)
                except Exception as exc:
                    parse_failed += 1
                    failure_reasons["exception"] += 1
                    logger.debug("pa_scrape: %s failed: %s", item["link"], exc)

                await asyncio.sleep(PA_INTER_REQUEST_DELAY)
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        # Convert the silent failure to a structured, surfaced error so the
        # /firewall/advisories/health endpoint exposes it and operators can
        # see *why* the catalog stopped updating.
        logger.warning("pa_scrape: ingest failed at top level: %s", exc)
        stats = {
            "ok":              False,
            "source":          "pa_scrape",
            "error":           str(exc),
            "error_type":      type(exc).__name__,
            "fetched":         fetched_pages,
            "listing_total":   listing_total,
            "elapsed_ms":      elapsed_ms,
            "finished_at":     datetime.now(timezone.utc).isoformat(),
        }
        _last_run = stats
        return stats

    from app.services.vendor_audit.csaf_ingest import _upsert_rows
    upsert_stats = await _upsert_rows(rows)

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    stats = {
        "ok":              True,
        "source":          "pa_scrape",
        "listing_total":   listing_total,
        "fetched":         fetched_pages,
        "rows":            len(rows),
        "skipped_old":     skipped_old,
        "skipped_pan_sa":  skipped_pan_sa,
        "parse_failed":    parse_failed,
        "failure_reasons": failure_reasons,
        "elapsed_ms":      elapsed_ms,
        "finished_at":     datetime.now(timezone.utc).isoformat(),
        **upsert_stats,
    }
    _last_run = stats
    logger.info(
        "pa_scrape: ingest complete, fetched=%d rows=%d insert=%d refresh_uncurated=%d "
        "preserved_curated=%d skipped_old=%d skipped_pan_sa=%d parse_failed=%d in %dms",
        fetched_pages, len(rows),
        stats.get("inserted", 0), stats.get("refreshed_uncurated", 0),
        stats.get("preserved_curated", 0),
        skipped_old, skipped_pan_sa, parse_failed, elapsed_ms,
    )
    return stats
