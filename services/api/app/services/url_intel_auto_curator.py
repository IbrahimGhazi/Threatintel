"""
URL-intel auto-curator (aggressive policy).

The user no longer wants to hand-curate ground-truth labels on URLs. This
background task replaces the manual feedback workflow:

  * Every iteration, find ``url_reputation`` rows whose ground_truth is
    NULL but whose combined_verdict is computable (i.e. they have an ML
    risk_score AND a recent content analysis with a content_risk_score).
  * Compute the combined verdict (same formula as
    ``app/routers/url_intel.py`` — must stay in sync) and write it into
    ``ground_truth``, with ``labeled_by='auto-curator-v1'`` and
    ``labeled_at=NOW()``.
  * Process 5 000 rows per UPDATE (mirrors the retention loop's batched
    DELETE) so a big backfill never blocks the event loop.
  * Loop forever; sleep ``URL_INTEL_AUTO_CURATOR_INTERVAL_SECONDS``
    between sweeps (default 600 = 10 min).

Mistakes are corrected via DELETE /url-intel/feedback/{row_id} which
clears the label and lets the next sweep re-label.
"""
from __future__ import annotations

import asyncio
import logging
import os

log = logging.getLogger("ti.api")

# Combined-verdict formula (keep in sync with app/routers/url_intel.py).
_W_ML = float(os.getenv("URL_INTEL_W_ML", "0.5"))
_W_CONTENT = float(os.getenv("URL_INTEL_W_CONTENT", "0.5"))
_ALERT_COMBINED_THR = float(os.getenv("ALERT_COMBINED_THR", "0.55"))
_COMBINED_SUSP_THR = float(os.getenv("COMBINED_SUSP_THR", "0.35"))

# Tunables
_BATCH_SIZE = int(os.getenv("URL_INTEL_AUTO_CURATOR_BATCH_SIZE", "5000"))
_INTERVAL_SECONDS = int(os.getenv("URL_INTEL_AUTO_CURATOR_INTERVAL_SECONDS", "600"))
_STARTUP_GRACE_SECONDS = 30
_MAX_ITERATIONS_PER_SWEEP = 200  # safety cap (1M rows per sweep)


async def _run_auto_curator_once() -> int:
    """Run a single auto-curation sweep.

    Looks for unlabeled rows whose combined_verdict is computable and
    writes the verdict into ``ground_truth``. Returns the total number
    of rows labeled in this sweep.

    Mirrors the batched-UPDATE pattern in ``_run_retention_once`` —
    short transactions, ``WHERE id IN (SELECT ... LIMIT batch)`` so each
    UPDATE finishes in well under a second on the trial cluster.
    """
    from app.database import AsyncSessionLocal
    from sqlalchemy import text

    # The CTE picks unlabeled rows that have a usable combined verdict.
    # We compute combined_verdict inline (same formula as the
    # url_intel router) and write it directly to ground_truth.
    sql = text(f"""
        WITH victims AS (
            SELECT r.id,
                   CASE
                     WHEN {_W_ML} * (r.risk_score::float / 100.0)
                        + {_W_CONTENT} * LEAST(ca.content_risk_score::float / 10.0, 1.0)
                       >= {_ALERT_COMBINED_THR} THEN 'malicious'
                     WHEN {_W_ML} * (r.risk_score::float / 100.0)
                        + {_W_CONTENT} * LEAST(ca.content_risk_score::float / 10.0, 1.0)
                       >= {_COMBINED_SUSP_THR} THEN 'suspicious'
                     ELSE 'benign'
                   END AS verdict
              FROM url_reputation r
              JOIN LATERAL (
                SELECT content_risk_score
                  FROM url_content_analysis
                 WHERE url_reputation_id = r.id
                 ORDER BY analyzed_at DESC
                 LIMIT 1
              ) ca ON true
             WHERE r.ground_truth IS NULL
               AND r.content_analyzed_at IS NOT NULL
             LIMIT :batch
        )
        UPDATE url_reputation r
           SET ground_truth = v.verdict,
               labeled_by   = 'auto-curator-v1',
               labeled_at   = NOW()
          FROM victims v
         WHERE r.id = v.id
    """)

    total = 0
    for _ in range(_MAX_ITERATIONS_PER_SWEEP):
        async with AsyncSessionLocal() as db:
            result = await db.execute(sql, {"batch": _BATCH_SIZE})
            await db.commit()
            n = result.rowcount or 0
            total += n
            if n < _BATCH_SIZE:
                break
        # Yield to other coroutines between batches so a big backfill
        # doesn't starve the request loop.
        await asyncio.sleep(0)

    if total:
        log.info("auto-curator: labeled %d rows", total)
    return total


async def _auto_curator_loop() -> None:
    """Background task: continuously auto-label unlabeled url_reputation rows.

    * 30s startup grace so the DB pool and any in-flight migrations have
      settled before we touch the table.
    * Sleep ``URL_INTEL_AUTO_CURATOR_INTERVAL_SECONDS`` between sweeps.
    * Cancel cleanly on ``asyncio.CancelledError``.
    """
    try:
        await asyncio.sleep(_STARTUP_GRACE_SECONDS)
    except asyncio.CancelledError:
        return

    log.info(
        "auto-curator: interval=%ds, batch=%d",
        _INTERVAL_SECONDS, _BATCH_SIZE,
    )

    while True:
        try:
            await _run_auto_curator_once()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("auto-curator sweep failed: %s", exc)

        try:
            await asyncio.sleep(_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            break
