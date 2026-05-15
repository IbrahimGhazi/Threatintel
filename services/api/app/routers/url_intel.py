"""
URL-intel dashboard API — v2 (combined-verdict architecture).

Source-of-truth is now the combined verdict
    combined = w_ml * (risk_score/100) + w_content * min(content_risk_score/10, 1.0)
which is what the WCA gate uses to drive indicator upsert / deactivate.

Endpoints:
  GET  /url-intel/model-info           — classifier + gate config
  GET  /url-intel/stats                — pipeline / drift / combined / indicator / gate / feed rollup
  GET  /url-intel/histogram            — ML confidence buckets × verdict (legacy)
  GET  /url-intel/combined-histogram   — combined-score buckets × verdict
  GET  /url-intel/heatmap              — 2-D ml_risk × content_risk density
  GET  /url-intel/accuracy             — confusion matrix (basis=ml|content|combined)
  GET  /url-intel/indicator-tags       — tag distribution across active indicators
  GET  /url-intel/indicator-lifecycle  — last-N upsert/deactivate events
  GET  /url-intel/recent               — paginated recent predictions (+combined/indicator cols)
  POST /url-intel/feedback             — DEPRECATED (returns 410). Labels
                                          are now applied automatically by
                                          the auto-curator background task
                                          (app/services/url_intel_auto_curator.py).
  DELETE /url-intel/feedback/{id}      — clear a label (so the auto-curator
                                          re-labels on its next sweep)
  GET  /url-intel/content/{row_id}     — web content analysis bundle
  POST /url-intel/content/analyze      — queue a url for re-analysis
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Literal
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key

router = APIRouter(prefix="/url-intel", tags=["URL Intel"])


# ── Gate / combined-verdict config (keep in sync with WCA) ───────────────
W_ML = float(os.getenv("URL_INTEL_W_ML", "0.5"))
W_CONTENT = float(os.getenv("URL_INTEL_W_CONTENT", "0.5"))
ALERT_COMBINED_THR = float(os.getenv("ALERT_COMBINED_THR", "0.55"))
COMBINED_SUSP_THR = float(os.getenv("COMBINED_SUSP_THR", "0.35"))
FEED_TAGS = ("urlhaus", "openphish", "spamhaus_dbl", "gsb")
URL_INTEL_SVC = os.getenv("URL_INTEL_URL", "http://ti-url-intel:8080")

VALID_LABELS = {"benign", "suspicious", "malicious"}

# CTE that joins each url_reputation row with its latest content_risk_score
# (which lives on url_content_analysis, not url_reputation itself).
_UR_WITH_CRS = """
    url_reputation r
    LEFT JOIN LATERAL (
      SELECT content_risk_score
      FROM url_content_analysis
      WHERE url_reputation_id = r.id
      ORDER BY analyzed_at DESC
      LIMIT 1
    ) ca ON true
"""

# Reusable SQL fragment that projects combined_score and combined_verdict
# assuming you're selecting FROM url_reputation r + lateral ca (ca.content_risk_score).
_COMBINED_SQL = f"""
  CASE
    WHEN ca.content_risk_score IS NULL OR r.content_analyzed_at IS NULL
      THEN NULL
    ELSE {W_ML} * (r.risk_score::float / 100.0)
       + {W_CONTENT} * LEAST(ca.content_risk_score::float / 10.0, 1.0)
  END AS combined_score,
  CASE
    WHEN ca.content_risk_score IS NULL OR r.content_analyzed_at IS NULL
      THEN NULL
    WHEN {W_ML} * (r.risk_score::float / 100.0)
       + {W_CONTENT} * LEAST(ca.content_risk_score::float / 10.0, 1.0)
      >= {ALERT_COMBINED_THR} THEN 'malicious'
    WHEN {W_ML} * (r.risk_score::float / 100.0)
       + {W_CONTENT} * LEAST(ca.content_risk_score::float / 10.0, 1.0)
      >= {COMBINED_SUSP_THR} THEN 'suspicious'
    ELSE 'benign'
  END AS combined_verdict
"""


# ── Pydantic models ──────────────────────────────────────────────────────

class FeedbackIn(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    ground_truth: str = Field(..., description="benign | suspicious | malicious")
    labeled_by: Optional[str] = Field(default="operator", max_length=128)


class RecentRow(BaseModel):
    id: int
    url: str
    domain: Optional[str]
    prediction: str
    confidence: float
    risk_score: int
    ml_probability: float
    hit_count: int
    first_seen: datetime
    last_seen: datetime
    ground_truth: Optional[str] = None
    labeled_at: Optional[datetime] = None
    labeled_by: Optional[str] = None
    content_verdict: Optional[str] = None
    content_risk_score: Optional[int] = None
    content_analyzed_at: Optional[datetime] = None
    original_prediction: Optional[str] = None
    override_reason: Optional[str] = None
    # v2 additions
    combined_score: Optional[float] = None
    combined_verdict: Optional[str] = None
    indicator_active: Optional[bool] = None
    indicator_tags: Optional[List[str]] = None


class RecentOut(BaseModel):
    total: int
    offset: int
    limit: int
    items: List[RecentRow]


# ── Model info (proxied to url-intel service) ────────────────────────────

@router.get("/model-info")
async def model_info(_: str = Depends(require_api_key)):
    """Classifier model info + combined-gate configuration."""
    info: Dict[str, Any] = {
        "classifier": {"name": "unknown", "version": "unknown"},
        "gate": {
            "w_ml": W_ML,
            "w_content": W_CONTENT,
            "threshold_malicious": ALERT_COMBINED_THR,
            "threshold_suspicious": COMBINED_SUSP_THR,
            "feed_tags": list(FEED_TAGS),
        },
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{URL_INTEL_SVC}/model_info")
            if r.status_code == 200:
                info["classifier"] = r.json()
    except Exception as e:
        info["classifier"]["error"] = str(e)
    return info


# ── Stats (the big rollup) ───────────────────────────────────────────────

@router.get("/stats")
async def stats(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """v2 rollup: ML verdicts, content verdicts, combined verdicts,
    pipeline counts, gate diagnostics, indicator-state, feed-hit breakdown."""

    # ML verdicts + recent volume + labeled accuracy
    row = (await db.execute(text("""
        SELECT
          COUNT(*)::bigint                                                    AS total,
          COALESCE(SUM((prediction='benign')::int),     0)::bigint            AS benign,
          COALESCE(SUM((prediction='suspicious')::int), 0)::bigint            AS suspicious,
          COALESCE(SUM((prediction='malicious')::int),  0)::bigint            AS malicious,
          COALESCE(SUM((prediction='error')::int),      0)::bigint            AS errors,
          ROUND(AVG(confidence)::numeric, 4)                                  AS avg_confidence,
          ROUND(AVG(risk_score)::numeric, 2)                                  AS avg_risk_score,
          COALESCE(SUM(hit_count), 0)::bigint                                 AS total_hits,
          COUNT(*) FILTER (WHERE last_seen > now() - interval '1 hour')::bigint  AS last_hour,
          COUNT(*) FILTER (WHERE last_seen > now() - interval '24 hours')::bigint AS last_24h,
          COUNT(*) FILTER (WHERE ground_truth IS NOT NULL)::bigint            AS labeled,
          COALESCE(SUM((ground_truth = prediction)::int), 0)::bigint          AS labeled_correct
        FROM url_reputation
    """))).mappings().first() or {}

    # Content rollup + overrides
    c_row = (await db.execute(text("""
        SELECT
          COUNT(*) FILTER (WHERE content_verdict IS NOT NULL)::bigint AS analyzed,
          COUNT(*) FILTER (WHERE content_verdict = 'benign')::bigint     AS c_benign,
          COUNT(*) FILTER (WHERE content_verdict = 'suspicious')::bigint AS c_susp,
          COUNT(*) FILTER (WHERE content_verdict = 'malicious')::bigint  AS c_mal,
          COUNT(*) FILTER (WHERE content_verdict = 'error')::bigint      AS c_err,
          COUNT(*) FILTER (WHERE override_reason IS NOT NULL)::bigint    AS overrides,
          COUNT(*) FILTER (WHERE override_reason LIKE 'content_analysis_benign%')::bigint AS overrides_to_benign,
          COUNT(*) FILTER (WHERE override_reason = 'content_analysis_malicious')::bigint   AS overrides_to_mal
        FROM url_reputation
    """))).mappings().first() or {}

    # Combined-verdict counts (only rows with a combined score)
    combined_row = (await db.execute(text(f"""
        WITH s AS (
          SELECT {_COMBINED_SQL}
          FROM {_UR_WITH_CRS}
        )
        SELECT
          COUNT(*) FILTER (WHERE combined_verdict IS NOT NULL)::bigint AS analyzed,
          COUNT(*) FILTER (WHERE combined_verdict = 'benign')::bigint      AS c_benign,
          COUNT(*) FILTER (WHERE combined_verdict = 'suspicious')::bigint  AS c_susp,
          COUNT(*) FILTER (WHERE combined_verdict = 'malicious')::bigint   AS c_mal,
          COUNT(*) FILTER (WHERE combined_score >= {ALERT_COMBINED_THR})::bigint AS ge_threshold
        FROM s
    """))).mappings().first() or {}

    # Gate diagnostics: ML ↔ content cross-tab
    gate_row = (await db.execute(text("""
        SELECT
          COUNT(*) FILTER (WHERE prediction IN ('malicious','suspicious')
                             AND content_verdict = 'benign')::bigint AS ml_bad_content_ok,
          COUNT(*) FILTER (WHERE prediction = 'benign'
                             AND content_verdict IN ('malicious','suspicious'))::bigint AS ml_ok_content_bad,
          COUNT(*) FILTER (WHERE prediction IN ('malicious','suspicious')
                             AND content_verdict IN ('malicious','suspicious'))::bigint AS both_bad,
          COUNT(*) FILTER (WHERE prediction = 'benign'
                             AND content_verdict = 'benign')::bigint AS both_ok,
          COUNT(*) FILTER (WHERE content_verdict IS NULL
                             AND prediction IN ('malicious','suspicious'))::bigint AS ml_bad_content_pending
        FROM url_reputation
    """))).mappings().first() or {}

    # Indicator rollup (active/inactive) + recent drift
    ind_row = (await db.execute(text(f"""
        SELECT
          COUNT(*)::bigint AS total,
          COUNT(*) FILTER (WHERE active = true)::bigint  AS active,
          COUNT(*) FILTER (WHERE active = false)::bigint AS inactive,
          COUNT(*) FILTER (WHERE active = true
            AND tags && ARRAY['authoritative_feed']::text[])::bigint AS active_feed_confirmed,
          COUNT(*) FILTER (WHERE active = true
            AND tags && ARRAY['combined_gate']::text[])::bigint AS active_combined_gate,
          COUNT(*) FILTER (WHERE active = true
            AND tags && ARRAY{list(FEED_TAGS)}::text[])::bigint AS active_any_feed,
          COUNT(*) FILTER (WHERE active = false
            AND last_seen > now() - interval '24 hours')::bigint AS deactivated_24h,
          COUNT(*) FILTER (WHERE active = true
            AND last_seen > now() - interval '24 hours')::bigint AS upserted_24h
        FROM indicators
        WHERE type = 'url'
    """))).mappings().first() or {}

    # Feed-hit breakdown
    feed_row = (await db.execute(text(f"""
        SELECT
          COUNT(*) FILTER (WHERE 'urlhaus' = ANY(tags))::bigint       AS urlhaus,
          COUNT(*) FILTER (WHERE 'openphish' = ANY(tags))::bigint     AS openphish,
          COUNT(*) FILTER (WHERE 'spamhaus_dbl' = ANY(tags))::bigint  AS spamhaus_dbl,
          COUNT(*) FILTER (WHERE 'gsb' = ANY(tags))::bigint           AS gsb,
          COUNT(*) FILTER (WHERE 'combined_gate' = ANY(tags)
            AND NOT (tags && ARRAY{list(FEED_TAGS)}::text[]))::bigint AS combined_only,
          COUNT(*) FILTER (WHERE 'authoritative_feed' = ANY(tags))::bigint AS authoritative_feed
        FROM indicators
        WHERE type = 'url' AND active = true
    """))).mappings().first() or {}

    # Top domains, now with indicator state alongside ML + content verdict
    top = (await db.execute(text(f"""
        WITH agg AS (
          SELECT r.domain,
                 SUM(r.hit_count)::bigint AS hits,
                 ROUND(AVG(r.confidence)::numeric, 3) AS avg_conf,
                 MODE() WITHIN GROUP (ORDER BY r.prediction) AS ml_verdict,
                 MODE() WITHIN GROUP (ORDER BY r.content_verdict) AS content_verdict,
                 BOOL_OR(
                   r.content_analyzed_at IS NOT NULL
                   AND ca.content_risk_score IS NOT NULL
                   AND ({W_ML} * (r.risk_score::float / 100.0)
                        + {W_CONTENT} * LEAST(ca.content_risk_score::float / 10.0, 1.0))
                       >= {ALERT_COMBINED_THR}
                 ) AS combined_bad
          FROM {_UR_WITH_CRS}
          WHERE r.domain IS NOT NULL
          GROUP BY r.domain
          ORDER BY SUM(r.hit_count) DESC NULLS LAST
          LIMIT 10
        )
        SELECT
          agg.domain,
          agg.ml_verdict AS prediction,
          agg.content_verdict,
          agg.combined_bad,
          agg.hits,
          agg.avg_conf,
          EXISTS (
            SELECT 1 FROM indicators i
             WHERE i.type = 'url'
               AND i.active = true
               AND (i.normalized_value = agg.domain
                    OR i.normalized_value ILIKE agg.domain || '/%')
          ) AS indicator_active
        FROM agg
    """))).mappings().all()

    return {
        "total": row.get("total", 0),
        "counts": {
            "benign":     row.get("benign", 0),
            "suspicious": row.get("suspicious", 0),
            "malicious":  row.get("malicious", 0),
            "errors":     row.get("errors", 0),
        },
        "avg_confidence": float(row.get("avg_confidence") or 0.0),
        "avg_risk_score": float(row.get("avg_risk_score") or 0.0),
        "total_hits":     row.get("total_hits", 0),
        "recent_volume": {
            "last_hour": row.get("last_hour", 0),
            "last_24h":  row.get("last_24h", 0),
        },
        "labeled":         row.get("labeled", 0),
        "labeled_correct": row.get("labeled_correct", 0),
        "top_domains": [dict(r) for r in top],
        "content": {
            "analyzed":           int(c_row.get("analyzed") or 0),
            "counts": {
                "benign":     int(c_row.get("c_benign") or 0),
                "suspicious": int(c_row.get("c_susp")   or 0),
                "malicious":  int(c_row.get("c_mal")    or 0),
                "errors":     int(c_row.get("c_err")    or 0),
            },
            "overrides_total":        int(c_row.get("overrides") or 0),
            "overrides_to_benign":    int(c_row.get("overrides_to_benign") or 0),
            "overrides_to_malicious": int(c_row.get("overrides_to_mal") or 0),
        },
        "combined": {
            "analyzed":     int(combined_row.get("analyzed") or 0),
            "counts": {
                "benign":     int(combined_row.get("c_benign") or 0),
                "suspicious": int(combined_row.get("c_susp")   or 0),
                "malicious":  int(combined_row.get("c_mal")    or 0),
            },
            "ge_threshold": int(combined_row.get("ge_threshold") or 0),
        },
        "pipeline": {
            "url_classified":     row.get("total", 0),
            "content_analyzed":   int(c_row.get("analyzed") or 0),
            "combined_gated":     int(combined_row.get("analyzed") or 0),
            "combined_ge_thr":    int(combined_row.get("ge_threshold") or 0),
            "active_indicators":  int(ind_row.get("active") or 0),
            "feed_confirmed":     int(ind_row.get("active_feed_confirmed") or 0),
        },
        "drift": {
            "overrides_to_benign":    int(c_row.get("overrides_to_benign") or 0),
            "overrides_to_malicious": int(c_row.get("overrides_to_mal") or 0),
            "deactivated_24h":        int(ind_row.get("deactivated_24h") or 0),
            "upserted_24h":           int(ind_row.get("upserted_24h") or 0),
        },
        "gate_diagnostics": {
            "ml_bad_content_ok":      int(gate_row.get("ml_bad_content_ok") or 0),
            "ml_ok_content_bad":      int(gate_row.get("ml_ok_content_bad") or 0),
            "both_bad":               int(gate_row.get("both_bad") or 0),
            "both_ok":                int(gate_row.get("both_ok") or 0),
            "ml_bad_content_pending": int(gate_row.get("ml_bad_content_pending") or 0),
        },
        "indicators": {
            "total":                 int(ind_row.get("total") or 0),
            "active":                int(ind_row.get("active") or 0),
            "inactive":              int(ind_row.get("inactive") or 0),
            "active_feed_confirmed": int(ind_row.get("active_feed_confirmed") or 0),
            "active_combined_gate":  int(ind_row.get("active_combined_gate") or 0),
        },
        "feed_hits": {
            "urlhaus":            int(feed_row.get("urlhaus") or 0),
            "openphish":          int(feed_row.get("openphish") or 0),
            "spamhaus_dbl":       int(feed_row.get("spamhaus_dbl") or 0),
            "gsb":                int(feed_row.get("gsb") or 0),
            "combined_only":      int(feed_row.get("combined_only") or 0),
            "authoritative_feed": int(feed_row.get("authoritative_feed") or 0),
        },
        "threshold_config": {
            "w_ml": W_ML,
            "w_content": W_CONTENT,
            "threshold_malicious": ALERT_COMBINED_THR,
            "threshold_suspicious": COMBINED_SUSP_THR,
        },
    }


# ── Confidence histogram (legacy, ML only) ───────────────────────────────

@router.get("/histogram")
async def histogram(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """ML confidence histogram (10 buckets × verdict)."""
    result = await db.execute(text("""
        SELECT prediction,
               floor(confidence * 10)::int AS bucket,
               COUNT(*)::bigint AS n
        FROM url_reputation
        WHERE prediction IN ('benign','suspicious','malicious')
        GROUP BY prediction, bucket
        ORDER BY prediction, bucket
    """))
    rows = result.mappings().all()
    buckets = [
        {"bucket": i, "range": f"{i/10:.1f}-{(i+1)/10:.1f}",
         "benign": 0, "suspicious": 0, "malicious": 0}
        for i in range(10)
    ]
    for r in rows:
        b = min(int(r["bucket"]), 9)
        buckets[b][r["prediction"]] = int(r["n"])
    return {"buckets": buckets}


# ── Combined-score histogram ─────────────────────────────────────────────

@router.get("/combined-histogram")
async def combined_histogram(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """10-bucket combined-score histogram (0..1), split by combined verdict."""
    rows = (await db.execute(text(f"""
        WITH s AS (
          SELECT {_COMBINED_SQL}
          FROM {_UR_WITH_CRS}
        )
        SELECT LEAST(floor(combined_score * 10)::int, 9) AS bucket,
               combined_verdict, COUNT(*)::bigint AS n
        FROM s
        WHERE combined_score IS NOT NULL
        GROUP BY bucket, combined_verdict
    """))).mappings().all()

    buckets = [
        {"bucket": i, "range": f"{i/10:.1f}-{(i+1)/10:.1f}",
         "benign": 0, "suspicious": 0, "malicious": 0}
        for i in range(10)
    ]
    for r in rows:
        b = min(int(r["bucket"]), 9)
        v = r["combined_verdict"]
        if v in ("benign", "suspicious", "malicious"):
            buckets[b][v] = int(r["n"])
    return {
        "buckets": buckets,
        "threshold_malicious":  ALERT_COMBINED_THR,
        "threshold_suspicious": COMBINED_SUSP_THR,
    }


# ── 2-D ML×content heatmap ───────────────────────────────────────────────

@router.get("/heatmap")
async def heatmap(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """ml_risk_bucket (0..9) × content_risk_bucket (0..9) density."""
    rows = (await db.execute(text(f"""
        SELECT LEAST(floor(r.risk_score / 10.0)::int, 9) AS ml_b,
               LEAST(floor(LEAST(ca.content_risk_score, 10.0))::int, 9) AS ct_b,
               COUNT(*)::bigint AS n
        FROM {_UR_WITH_CRS}
        WHERE ca.content_risk_score IS NOT NULL
          AND r.content_analyzed_at IS NOT NULL
        GROUP BY ml_b, ct_b
    """))).mappings().all()

    grid = [[0 for _ in range(10)] for _ in range(10)]
    for r in rows:
        grid[int(r["ml_b"])][int(r["ct_b"])] = int(r["n"])
    return {
        "ml_buckets":       [f"{i*10}-{(i+1)*10}" for i in range(10)],
        "content_buckets":  [f"{i}-{i+1}" for i in range(10)],
        "grid":             grid,
        "threshold_malicious":  ALERT_COMBINED_THR,
        "w_ml":      W_ML,
        "w_content": W_CONTENT,
    }


# ── Accuracy (ML / Content / Combined basis) ─────────────────────────────

@router.get("/accuracy")
async def accuracy(
    basis: Literal["ml", "content", "combined"] = Query("ml"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """
    Precision/recall/F1 per class + confusion matrix, evaluated against
    ground_truth. `basis` chooses which verdict column is treated as "pred":
      * ml       — prediction (url-intel GBDT)
      * content  — content_verdict (web-content-analyzer)
      * combined — computed combined verdict
    """
    if basis == "ml":
        pred_expr = "r.prediction"
    elif basis == "content":
        pred_expr = "r.content_verdict"
    else:
        pred_expr = f"""
          CASE
            WHEN ca.content_risk_score IS NULL OR r.content_analyzed_at IS NULL
              THEN NULL
            WHEN {W_ML} * (r.risk_score::float / 100.0)
               + {W_CONTENT} * LEAST(ca.content_risk_score::float / 10.0, 1.0)
              >= {ALERT_COMBINED_THR} THEN 'malicious'
            WHEN {W_ML} * (r.risk_score::float / 100.0)
               + {W_CONTENT} * LEAST(ca.content_risk_score::float / 10.0, 1.0)
              >= {COMBINED_SUSP_THR} THEN 'suspicious'
            ELSE 'benign'
          END
        """

    rows = (await db.execute(text(f"""
        SELECT r.ground_truth AS truth, ({pred_expr}) AS pred, COUNT(*)::bigint AS n
        FROM {_UR_WITH_CRS}
        WHERE r.ground_truth IS NOT NULL
          AND ({pred_expr}) IS NOT NULL
        GROUP BY truth, pred
    """))).mappings().all()

    labels = ["benign", "suspicious", "malicious"]
    cm: Dict[str, Dict[str, int]] = {t: {p: 0 for p in labels} for t in labels}
    total = 0
    for r in rows:
        t, p, n = r["truth"], r["pred"], int(r["n"])
        if t in cm and p in cm[t]:
            cm[t][p] += n
            total += n

    correct = sum(cm[l][l] for l in labels)
    overall_acc = (correct / total) if total else 0.0

    per_class = {}
    for l in labels:
        tp = cm[l][l]
        fp = sum(cm[t][l] for t in labels if t != l)
        fn = sum(cm[l][p] for p in labels if p != l)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall    = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        per_class[l] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4),
            "recall":    round(recall, 4),
            "f1":        round(f1, 4),
            "support":   tp + fn,
        }

    return {
        "basis": basis,
        "labeled_total": total,
        "overall_accuracy": round(overall_acc, 4),
        "confusion_matrix": cm,
        "per_class": per_class,
        "labels": labels,
    }


# ── Indicator tag distribution ───────────────────────────────────────────

@router.get("/indicator-tags")
async def indicator_tags(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Tag frequency across currently-active url indicators."""
    rows = (await db.execute(text("""
        SELECT tag, COUNT(*)::bigint AS n FROM (
          SELECT UNNEST(tags) AS tag FROM indicators
          WHERE type = 'url' AND active = true
        ) t
        GROUP BY tag
        ORDER BY n DESC
    """))).mappings().all()
    return {"tags": [{"tag": r["tag"], "count": int(r["n"])} for r in rows]}


# ── Indicator lifecycle events ───────────────────────────────────────────

@router.get("/indicator-lifecycle")
async def indicator_lifecycle(
    minutes: int = Query(60, ge=1, le=1440),
    limit: int = Query(30, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Recent url-indicator rows ordered by last_seen — shows both upserts
    (active=true) and deactivations (active=false) within the window."""
    rows = (await db.execute(text("""
        SELECT id, value, normalized_value, severity, confidence, tags,
               active, first_seen, last_seen
        FROM indicators
        WHERE type = 'url'
          AND last_seen > now() - make_interval(mins => :mins)
        ORDER BY last_seen DESC
        LIMIT :lim
    """), {"mins": minutes, "lim": limit})).mappings().all()

    events = []
    for r in rows:
        events.append({
            "id":     r["id"],
            "value":  r["value"],
            "event":  "upsert" if r["active"] else "deactivate",
            "active": bool(r["active"]),
            "severity": r["severity"],
            "confidence": float(r["confidence"] or 0),
            "tags":   list(r["tags"] or []),
            "last_seen": r["last_seen"],
            "first_seen": r["first_seen"],
        })
    return {"window_minutes": minutes, "events": events}


# ── Recent predictions (enriched with combined + indicator state) ────────

@router.get("/recent", response_model=RecentOut)
async def recent(
    prediction: Optional[str] = Query(None),
    labeled: Optional[bool] = Query(None),
    only_mispredictions: bool = Query(False),
    combined_only: bool = Query(
        False,
        description="Only rows where combined_verdict='malicious'"),
    q: Optional[str] = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    conds = ["1=1"]
    params: Dict[str, Any] = {}
    if prediction:
        conds.append("prediction = :p")
        params["p"] = prediction
    if labeled is True:
        conds.append("ground_truth IS NOT NULL")
    if labeled is False:
        conds.append("ground_truth IS NULL")
    if only_mispredictions:
        conds.append("ground_truth IS NOT NULL AND ground_truth <> prediction")
    if combined_only:
        conds.append(
            f"{W_ML} * (risk_score::float / 100.0) "
            f"+ {W_CONTENT} * LEAST(COALESCE(content_risk_score,0)::float / 10.0, 1.0) "
            f">= {ALERT_COMBINED_THR} "
            f"AND content_analyzed_at IS NOT NULL"
        )
    if q:
        conds.append("(url ILIKE :q OR domain ILIKE :q)")
        params["q"] = f"%{q}%"

    where = " AND ".join(conds)

    total = int((await db.execute(
        text(f"SELECT COUNT(*) FROM url_reputation WHERE {where}"), params
    )).scalar() or 0)

    rows = (await db.execute(
        text(f"""
            WITH rep AS (
              SELECT r.*,
                     (SELECT content_risk_score FROM url_content_analysis
                       WHERE url_reputation_id = r.id
                       ORDER BY analyzed_at DESC LIMIT 1) AS ca_risk
              FROM url_reputation r
              WHERE {where}
            )
            SELECT rep.id, rep.url, rep.domain, rep.prediction, rep.confidence, rep.risk_score,
                   rep.ml_probability, rep.hit_count, rep.first_seen, rep.last_seen,
                   rep.ground_truth, rep.labeled_at, rep.labeled_by,
                   rep.content_verdict, rep.content_analyzed_at,
                   rep.original_prediction, rep.override_reason,
                   rep.ca_risk AS content_risk_score,
                   CASE
                     WHEN rep.ca_risk IS NULL OR rep.content_analyzed_at IS NULL
                       THEN NULL
                     ELSE {W_ML} * (rep.risk_score::float / 100.0)
                        + {W_CONTENT} * LEAST(rep.ca_risk::float / 10.0, 1.0)
                   END AS combined_score,
                   CASE
                     WHEN rep.ca_risk IS NULL OR rep.content_analyzed_at IS NULL
                       THEN NULL
                     WHEN {W_ML} * (rep.risk_score::float / 100.0)
                        + {W_CONTENT} * LEAST(rep.ca_risk::float / 10.0, 1.0)
                       >= {ALERT_COMBINED_THR} THEN 'malicious'
                     WHEN {W_ML} * (rep.risk_score::float / 100.0)
                        + {W_CONTENT} * LEAST(rep.ca_risk::float / 10.0, 1.0)
                       >= {COMBINED_SUSP_THR} THEN 'suspicious'
                     ELSE 'benign'
                   END AS combined_verdict,
                   i.active AS indicator_active,
                   COALESCE(i.tags, ARRAY[]::text[]) AS indicator_tags
            FROM rep
            LEFT JOIN LATERAL (
              SELECT active, tags FROM indicators
              WHERE type = 'url'
                AND (normalized_value = rep.url OR normalized_value = rep.domain)
              ORDER BY last_seen DESC
              LIMIT 1
            ) i ON true
            ORDER BY rep.last_seen DESC
            LIMIT :lim OFFSET :off
        """),
        {**params, "lim": limit, "off": offset},
    )).mappings().all()

    return RecentOut(
        total=total,
        offset=offset,
        limit=limit,
        items=[RecentRow(**dict(r)) for r in rows],
    )


# ── Feedback (ground truth) ──────────────────────────────────────────────

@router.post("/feedback")
async def submit_feedback(
    body: FeedbackIn,
    _: str = Depends(require_api_key),
):
    # 2026-05-15 — deprecated. Aggressive auto-curation now labels every
    # unlabeled url_reputation row from its combined verdict (see
    # app/services/url_intel_auto_curator.py). Mistakes are corrected by
    # clearing the label and letting the next sweep re-label.
    raise HTTPException(
        status_code=410,
        detail=(
            "Manual feedback is deprecated. Labels are now applied "
            "automatically by the auto-curator. Use "
            "DELETE /url-intel/feedback/{row_id} to clear a wrong label."
        ),
    )


@router.delete("/feedback/{row_id}", status_code=status.HTTP_200_OK)
async def clear_feedback(
    row_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    res = await db.execute(
        text("""
            UPDATE url_reputation
               SET ground_truth = NULL, labeled_at = NULL, labeled_by = NULL
             WHERE id = :id
         RETURNING id
        """),
        {"id": row_id},
    )
    if res.first() is None:
        await db.rollback()
        raise HTTPException(404, "row not found")
    await db.commit()
    return {"status": "ok"}


# ── Content analysis bundle ──────────────────────────────────────────────

@router.get("/content/{row_id}")
async def content_analysis(
    row_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    rep = (await db.execute(text("""
        SELECT id, url, domain, prediction, confidence, risk_score,
               ml_probability, hit_count, first_seen, last_seen,
               ground_truth, labeled_at, labeled_by,
               content_verdict, content_analyzed_at, original_prediction,
               override_reason
        FROM url_reputation WHERE id = :id
    """), {"id": row_id})).mappings().first()
    if not rep:
        raise HTTPException(404, "url_reputation row not found")

    ca = (await db.execute(text("""
        SELECT id, analyzed_at, final_url, status_code, load_time_ms,
               html_sha256, html_size, title, redirect_count,
               external_origin_count, script_count, inline_script_count,
               signals, network_summary, content_risk_score, content_verdict,
               analyzer_version, error, indicators
        FROM url_content_analysis
        WHERE url_reputation_id = :id
        ORDER BY analyzed_at DESC LIMIT 1
    """), {"id": row_id})).mappings().first()

    history = (await db.execute(text("""
        SELECT id, analyzed_at, content_verdict, content_risk_score
        FROM url_content_analysis
        WHERE url_reputation_id = :id
        ORDER BY analyzed_at DESC LIMIT 10
    """), {"id": row_id})).mappings().all()

    return {
        "reputation": dict(rep),
        "latest":     dict(ca) if ca else None,
        "history":    [dict(h) for h in history],
    }


class AnalyzeRequestIn(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


@router.post("/content/analyze", status_code=status.HTTP_202_ACCEPTED)
async def request_content_analysis(
    body: AnalyzeRequestIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    res = await db.execute(text("""
        UPDATE url_reputation
           SET content_analyzed_at = NULL
         WHERE url = :url
         RETURNING id, url, prediction
    """), {"url": body.url})
    row = res.mappings().first()
    await db.commit()
    if not row:
        raise HTTPException(404, f"URL {body.url!r} not found in url_reputation")
    return {"status": "queued", **dict(row)}
