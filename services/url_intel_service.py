"""
URL Intelligence microservice.

FastAPI app exposing URL classification backed by the trained XGBoost model
from ``ml/model/url_classifier.json``.

Endpoints
---------
    GET  /health                 – liveness probe
    POST /analyze_url            – single-URL classification
    POST /analyze_urls           – batch classification (≤ 256 URLs)
    GET  /model_info             – model metadata + feature list + calibrator
    GET  /stats                  – feed / DNS / cache subsystem stats

Behaviour
---------
    * A URL reputation cache (Postgres table ``url_reputation``) is consulted
      before running the model.  Cache hits update ``last_seen`` and return
      the cached verdict.  Cache misses run the model and persist the row.
    * When the DB is unreachable the service continues in cache-bypass mode
      and logs a warning — the classification path is always available.
    * Risk score is the blended formula:

            risk_score = 100 * min(1, max(0,
                         0.45 * ml_probability_calibrated
                       + 0.15 * (1 - domain_reputation)
                       + 0.15 * url_feature_score
                       + 0.15 * dns_suspicion
                       + 0.10 * external_feed_score))

      *Override*: if any authoritative external feed (URLhaus / OpenPhish /
      Spamhaus DBL / Google Safe Browsing) returns a positive hit, the
      risk is floored at 95 regardless of the ML score.

      Components
      ----------
      * ``ml_probability``  – XGBoost output passed through an isotonic
                              calibrator loaded from ``url_classifier.calib.json``
                              (identity-map when the file is absent).
      * ``domain_reputation`` – reputation-cache history keyed on
                              **eTLD+1** (registrable domain) rather than
                              raw hostname. Computed as
                              ``1 − mean(ml_probability over etld1)``.
      * ``url_feature_score`` – model-free heuristic from
                              ``ml.feature_extractor.feature_score``.
      * ``dns_suspicion``   – asynchronous DNS lookup: NXDOMAIN flag,
                              A/AAAA record counts, sinkhole/private-IP
                              resolution. See ``ml.dns_enrichment``.
      * ``external_feed``   – URLhaus + OpenPhish (bulk-downloaded
                              every 5 min), Spamhaus DBL (live DNS),
                              optional Google Safe Browsing (live API).

Environment variables
---------------------
    URL_INTEL_MODEL_PATH    (default: ml/model/url_classifier.json)
    URL_INTEL_META_PATH     (default: ml/model/url_classifier.meta.json)
    URL_INTEL_CALIB_PATH    (default: ml/model/url_classifier.calib.json)
    URL_INTEL_DB_URL        postgresql+asyncpg://user:pass@host:5432/db   (optional)
    URL_INTEL_CACHE_TTL     seconds, default 86400 (24h). 0 = never expire.
    URL_INTEL_TOUCH_MIN_AGE minimum age (seconds) before a cache hit writes
                            a last_seen update. Prevents write amplification.
                            Default 3600.
    URL_INTEL_THRESHOLD     override the classification threshold
    URL_INTEL_DISABLE_FEEDS "1" to disable external threat-feed lookups
    URL_INTEL_DISABLE_DNS   "1" to disable DNS enrichment
    (see ml.external_feeds and ml.dns_enrichment for their own env vars)
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, validator

# Lazy imports for heavy deps so `--help` works even without them.
try:
    from xgboost import XGBClassifier
except ImportError:  # pragma: no cover
    XGBClassifier = None  # type: ignore

try:
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    _HAS_SQLA = True
except ImportError:  # pragma: no cover
    _HAS_SQLA = False

# Allow running either as ``python services/url_intel_service.py``
# (where "ml" is a sibling package) or as ``uvicorn services.url_intel_service:app``.
import sys
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml.feature_extractor import FEATURE_NAMES, extract_features, feature_score  # noqa: E402
from ml.dataset_loader   import _canonical as _canonicalise_url                 # noqa: E402
from ml.domain_utils     import extract_etld1, extract_hostname                 # noqa: E402
from ml.calibration      import IsotonicCalibrator                              # noqa: E402
from ml.external_feeds   import ThreatFeedRegistry, FeedVerdict                 # noqa: E402
from ml.dns_enrichment   import DnsEnricher, DnsFeatures                        # noqa: E402

log = logging.getLogger("ti.url_intel")

# ─── Configuration ────────────────────────────────────────────────────────────

MODEL_PATH      = Path(os.environ.get("URL_INTEL_MODEL_PATH", "ml/model/url_classifier.json"))
META_PATH       = Path(os.environ.get("URL_INTEL_META_PATH",  "ml/model/url_classifier.meta.json"))
CALIB_PATH      = Path(os.environ.get("URL_INTEL_CALIB_PATH", "ml/model/url_classifier.calib.json"))
DB_URL          = os.environ.get("URL_INTEL_DB_URL", "")
CACHE_TTL       = int(os.environ.get("URL_INTEL_CACHE_TTL",  "86400"))
TOUCH_MIN_AGE   = int(os.environ.get("URL_INTEL_TOUCH_MIN_AGE", "3600"))
THRESHOLD_OVR   = os.environ.get("URL_INTEL_THRESHOLD")
BATCH_LIMIT     = 256
DISABLE_FEEDS   = os.environ.get("URL_INTEL_DISABLE_FEEDS", "0") == "1"
DISABLE_DNS     = os.environ.get("URL_INTEL_DISABLE_DNS",   "0") == "1"

# Risk-score blend weights — surface as constants so they're tunable in one place.
W_ML    = 0.45
W_REP   = 0.15
W_UFS   = 0.15
W_DNS   = 0.15
W_FEED  = 0.10
FEED_FLOOR = 0.95   # any authoritative feed hit floors the final score here

# ─── Pydantic schemas ─────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    source: Optional[str] = Field(None, description="Origin log source (firewall, dns, proxy, edr, email)")
    bypass_cache: bool = False

    @validator("url")
    def _strip(cls, v: str) -> str:
        return v.strip()


class BatchAnalyzeRequest(BaseModel):
    urls:   List[str] = Field(..., min_items=1, max_items=BATCH_LIMIT)
    source: Optional[str] = None
    bypass_cache: bool = False


class AnalyzeResponse(BaseModel):
    url:                   str
    domain:                str   # hostname (backwards-compat field)
    etld1:                 str   # registrable (eTLD+1) domain
    prediction:            str
    confidence:            float
    risk_score:            int
    ml_probability:        float                    # calibrated
    ml_probability_raw:    float                    # pre-calibration
    domain_reputation:     float
    url_feature_score:     float
    dns_suspicion:         float = 0.0
    feed_score:            float = 0.0
    feed_hits:             Dict[str, Any] = Field(default_factory=dict)
    dns:                   Dict[str, Any] = Field(default_factory=dict)
    cached:                bool = False
    latency_ms:            float = 0.0
    model_version:         Optional[str] = None
    calibrated:            bool = False


# ─── Classifier wrapper ───────────────────────────────────────────────────────

class URLClassifier:
    """Thin wrapper around the XGBoost model + isotonic calibrator."""

    def __init__(self, model_path: Path, meta_path: Path,
                 calib_path: Optional[Path] = None):
        if XGBClassifier is None:
            raise RuntimeError("xgboost is not installed")
        if not model_path.is_file():
            raise FileNotFoundError(
                f"Model not found at {model_path}. "
                "Run `python -m ml.train_model` first."
            )

        self.model = XGBClassifier()
        self.model.load_model(str(model_path))
        # Cache the underlying booster so request handlers can take the fast
        # inplace_predict path (~3-10x lower per-call overhead than the
        # sklearn predict_proba wrapper).
        self._booster = self.model.get_booster()
        # Warm the booster so the first request is not penalised.
        self._booster.inplace_predict(np.zeros((1, len(FEATURE_NAMES)), dtype=np.float32))

        meta: Dict[str, Any] = {}
        if meta_path.is_file():
            import json
            meta = json.loads(meta_path.read_text())

        self.meta           = meta
        self.feature_names  = meta.get("feature_names", FEATURE_NAMES)
        self.threshold      = (
            float(THRESHOLD_OVR)
            if THRESHOLD_OVR is not None
            else float(meta.get("threshold", 0.5))
        )
        self.version        = meta.get("trained_at", "unknown")

        # Optional probability calibrator. When not fitted / not present the
        # calibrator acts as the identity function.
        self.calibrator = IsotonicCalibrator.load(calib_path) if calib_path else IsotonicCalibrator()
        if self.calibrator.fitted:
            log.info("Loaded isotonic calibrator from %s (meta=%s)",
                     calib_path, self.calibrator.meta)
        else:
            log.warning("No fitted calibrator found at %s — raw XGBoost "
                        "probabilities will be used. Run "
                        "`python -m ml.calibrate_model` to fit one.", calib_path)

    def predict_one(self, url: str) -> Dict[str, float]:
        vec = extract_features(url).reshape(1, -1).astype(np.float32)
        # Fast path: Booster.inplace_predict returns P(class=1) directly for
        # binary:logistic objective.
        raw = float(self._booster.inplace_predict(vec)[0])
        calibrated = self.calibrator.apply(raw)
        # Decision threshold applies to the *calibrated* probability so that
        # the threshold number means what it says. If no calibrator, this is
        # identical to the old behaviour.
        label = int(calibrated >= self.threshold)
        fscore = feature_score(url)
        return {
            "ml_probability_raw": raw,
            "ml_probability":     calibrated,
            "label":              label,
            "url_feature_score":  fscore,
        }


# ─── Reputation cache (PostgreSQL) ────────────────────────────────────────────

class ReputationCache:
    """Async SQLAlchemy accessor for the ``url_reputation`` table."""

    def __init__(self, db_url: str):
        if not _HAS_SQLA:
            raise RuntimeError("sqlalchemy[asyncpg] is not installed")
        self.engine   = create_async_engine(db_url, pool_pre_ping=True, pool_size=5, max_overflow=10)
        self._Session = sessionmaker(self.engine, expire_on_commit=False, class_=AsyncSession)

    async def close(self) -> None:
        await self.engine.dispose()

    async def lookup(self, url: str) -> Optional[Dict[str, Any]]:
        q = sa.text("""
            SELECT url, domain, etld1, prediction, confidence, risk_score,
                   first_seen, last_seen, source,
                   ml_probability, ml_probability_raw,
                   url_feature_score, domain_reputation,
                   feed_verdict, dns_features
            FROM url_reputation
            WHERE url = :url
            LIMIT 1
        """)
        async with self._Session() as s:
            row = (await s.execute(q, {"url": url})).mappings().first()
            return dict(row) if row else None

    async def touch(self, url: str, last_seen) -> None:
        """Cheap ``last_seen`` bump — avoids rewriting the full row on every hit."""
        q = sa.text("""
            UPDATE url_reputation
               SET last_seen = :last_seen
             WHERE url = :url
        """)
        async with self._Session() as s:
            await s.execute(q, {"url": url, "last_seen": last_seen})
            await s.commit()

    async def upsert(self, entry: Dict[str, Any]) -> None:
        q = sa.text("""
            INSERT INTO url_reputation
                (url, domain, etld1, prediction, confidence, risk_score,
                 first_seen, last_seen, source,
                 ml_probability, ml_probability_raw,
                 url_feature_score, domain_reputation,
                 feed_verdict, dns_features)
            VALUES
                (:url, :domain, :etld1, :prediction, :confidence, :risk_score,
                 :first_seen, :last_seen, :source,
                 :ml_probability, :ml_probability_raw,
                 :url_feature_score, :domain_reputation,
                 CAST(:feed_verdict AS jsonb), CAST(:dns_features AS jsonb))
            ON CONFLICT (url) DO UPDATE SET
                domain             = EXCLUDED.domain,
                etld1              = EXCLUDED.etld1,
                prediction         = EXCLUDED.prediction,
                confidence         = EXCLUDED.confidence,
                risk_score         = EXCLUDED.risk_score,
                last_seen          = EXCLUDED.last_seen,
                source             = COALESCE(EXCLUDED.source, url_reputation.source),
                ml_probability     = EXCLUDED.ml_probability,
                ml_probability_raw = EXCLUDED.ml_probability_raw,
                url_feature_score  = EXCLUDED.url_feature_score,
                domain_reputation  = EXCLUDED.domain_reputation,
                feed_verdict       = EXCLUDED.feed_verdict,
                dns_features       = EXCLUDED.dns_features
        """)
        async with self._Session() as s:
            await s.execute(q, entry)
            await s.commit()

    async def domain_reputation(self, etld1: str) -> float:
        """0..1 reputation score for the registrable (eTLD+1) domain.

        1.0 = known benign / unseen, 0.0 = consistently malicious history.
        Keyed on ``etld1`` so subdomain sprays under one owner aggregate
        correctly (``a.evil.co.uk`` and ``b.evil.co.uk`` share reputation).
        """
        if not etld1:
            return 1.0
        q = sa.text("""
            SELECT AVG(ml_probability) AS mean_p, COUNT(*) AS n
            FROM url_reputation
            WHERE etld1 = :etld1
        """)
        async with self._Session() as s:
            row = (await s.execute(q, {"etld1": etld1})).mappings().first()
        if not row or not row["n"]:
            return 1.0
        mean_p = float(row["mean_p"] or 0.0)
        return float(max(0.0, min(1.0, 1.0 - mean_p)))


# ─── FastAPI application ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Classifier + calibrator
    app.state.classifier = URLClassifier(MODEL_PATH, META_PATH, CALIB_PATH)
    log.info("Loaded model from %s (threshold=%.4f, calibrated=%s)",
             MODEL_PATH, app.state.classifier.threshold,
             app.state.classifier.calibrator.fitted)

    # Reputation cache (best-effort)
    app.state.cache = None
    if DB_URL:
        try:
            app.state.cache = ReputationCache(DB_URL)
            log.info("Connected reputation cache")
        except Exception as exc:
            log.warning("Reputation cache unavailable, running in bypass mode: %s", exc)

    # External threat feeds (best-effort; refreshes in background)
    app.state.feeds = None
    if not DISABLE_FEEDS:
        try:
            reg = ThreatFeedRegistry()
            await reg.start()
            app.state.feeds = reg
            log.info("Threat-feed registry started")
        except Exception as exc:
            log.warning("Threat-feed registry unavailable: %s", exc)

    # DNS enricher (in-process, cached)
    app.state.dns = None
    if not DISABLE_DNS:
        try:
            app.state.dns = DnsEnricher()
            log.info("DNS enricher initialised")
        except Exception as exc:
            log.warning("DNS enricher unavailable: %s", exc)

    yield

    if app.state.feeds is not None:
        await app.state.feeds.stop()
    if app.state.dns is not None:
        await app.state.dns.close()
    if app.state.cache is not None:
        await app.state.cache.close()


app = FastAPI(
    title="TI Platform URL Intelligence",
    description="ML-backed malicious URL classification service",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Route helpers ─────────────────────────────────────────────────────────────

async def _classify(
    request: Request,
    url: str,
    source: Optional[str],
    bypass_cache: bool,
) -> AnalyzeResponse:
    t0 = time.perf_counter()
    classifier: URLClassifier             = request.app.state.classifier
    cache:      Optional[ReputationCache] = request.app.state.cache
    feeds:      Optional[ThreatFeedRegistry] = getattr(request.app.state, "feeds", None)
    dns_en:     Optional[DnsEnricher]        = getattr(request.app.state, "dns",   None)

    # Canonicalise to match the form the model was trained on (bare host+path,
    # no scheme, no www.). Without this, training-vs-inference URL-shape skew
    # makes popular bare domains (google.com) look malicious to the char-n-gram
    # features. Hostname + eTLD+1 are extracted from the ORIGINAL url so that
    # scheme-bearing inputs resolve correctly; the canonical form is used for
    # cache key, feature extraction, and persistence.
    domain  = extract_hostname(url)
    etld1   = extract_etld1(url)
    url     = _canonicalise_url(url) or url
    now     = datetime.now(timezone.utc)

    # 1. Cache lookup — cheap, always try first
    if cache and not bypass_cache:
        try:
            cached = await cache.lookup(url)
        except Exception as exc:
            log.warning("Cache lookup failed for %s: %s", url, exc)
            cached = None

        if cached and _is_fresh(cached.get("last_seen"), CACHE_TTL):
            # Touch last_seen only when the row is meaningfully old —
            # avoids write amplification on hot URLs.
            if _age_seconds(cached.get("last_seen")) >= TOUCH_MIN_AGE:
                try:
                    await cache.touch(cached["url"], now)
                except Exception:
                    pass
            return _response_from_cache(cached, classifier,
                                        fallback_domain=domain,
                                        fallback_etld1=etld1,
                                        latency_ms=(time.perf_counter() - t0) * 1000.0)

    # 2. Run model + enrichment concurrently. The model itself is a tight
    #    CPU loop (~1 ms), so `to_thread` frees the event loop for the I/O
    #    work (DNS + feeds) to overlap.
    model_task = asyncio.to_thread(classifier.predict_one, url)
    feed_task  = feeds.lookup(url, domain, etld1) if feeds else _zero_feed_verdict()
    dns_task   = dns_en.enrich(domain)            if dns_en else _zero_dns_features()
    rep_task   = cache.domain_reputation(etld1)   if cache   else _one()

    pred, fv, dns_feat, dom_rep = await asyncio.gather(
        model_task, feed_task, dns_task, rep_task,
        return_exceptions=False,
    )

    ml_p_raw  = float(pred["ml_probability_raw"])
    ml_p      = float(pred["ml_probability"])
    url_fs    = float(pred["url_feature_score"])
    label     = int(pred["label"])
    feed_sc   = float(fv.score)
    dns_susp  = float(dns_feat.suspicion)
    dom_rep   = float(dom_rep)

    # 3. Blended risk score
    risk = (
        W_ML   * ml_p
      + W_REP  * (1.0 - dom_rep)
      + W_UFS  * url_fs
      + W_DNS  * dns_susp
      + W_FEED * feed_sc
    )
    risk = max(0.0, min(1.0, risk))

    # Authoritative-feed override: any definitive hit floors the risk.
    if fv.any_definitive:
        risk = max(risk, FEED_FLOOR)
        label = 1

    risk_int = int(round(risk * 100))

    prediction_label = "malicious" if label == 1 else "benign"
    # Confidence is calibrated P(class | url) — when an external feed forced
    # the label we report the higher of (ml_p, feed_sc).
    if label == 1:
        confidence = max(ml_p, feed_sc) if fv.any_definitive else ml_p
    else:
        confidence = 1.0 - ml_p

    response = AnalyzeResponse(
        url                = url,
        domain             = domain,
        etld1              = etld1,
        prediction         = prediction_label,
        confidence         = round(float(confidence), 4),
        risk_score         = risk_int,
        ml_probability     = round(ml_p, 4),
        ml_probability_raw = round(ml_p_raw, 4),
        domain_reputation  = round(dom_rep, 4),
        url_feature_score  = round(url_fs, 4),
        dns_suspicion      = round(dns_susp, 4),
        feed_score         = round(feed_sc, 4),
        feed_hits          = fv.as_dict(),
        dns                = dns_feat.as_dict(),
        cached             = False,
        latency_ms         = round((time.perf_counter() - t0) * 1000.0, 3),
        model_version      = classifier.version,
        calibrated         = classifier.calibrator.fitted,
    )

    # 4. Persist (best-effort)
    if cache:
        import json as _json
        entry = {
            "url":                url,
            "domain":             domain,
            "etld1":              etld1,
            "prediction":         prediction_label,
            "confidence":         float(confidence),
            "risk_score":         risk_int,
            "first_seen":         now,
            "last_seen":          now,
            "source":             source,
            "ml_probability":     ml_p,
            "ml_probability_raw": ml_p_raw,
            "url_feature_score":  url_fs,
            "domain_reputation":  dom_rep,
            "feed_verdict":       _json.dumps(fv.as_dict()),
            "dns_features":       _json.dumps(dns_feat.as_dict()),
        }
        try:
            await cache.upsert(entry)
        except Exception as exc:
            log.warning("Cache upsert failed for %s: %s", url, exc)

    return response


# ── Cache-hit response builder ───────────────────────────────────────────────

def _response_from_cache(cached: Dict[str, Any],
                         classifier: "URLClassifier",
                         fallback_domain: str,
                         fallback_etld1:  str,
                         latency_ms: float) -> AnalyzeResponse:
    ml_p      = float(cached.get("ml_probability")     or 0.0)
    ml_p_raw  = float(cached.get("ml_probability_raw") or ml_p)
    url_fs    = float(cached.get("url_feature_score")  or 0.0)
    dom_rep   = float(cached.get("domain_reputation")  or (1.0 - ml_p))
    fv_dict   = cached.get("feed_verdict") or {}
    dns_dict  = cached.get("dns_features") or {}
    return AnalyzeResponse(
        url                = cached["url"],
        domain             = cached.get("domain") or fallback_domain,
        etld1              = cached.get("etld1")  or fallback_etld1,
        prediction         = cached["prediction"],
        confidence         = float(cached["confidence"]),
        risk_score         = int(cached["risk_score"]),
        ml_probability     = ml_p,
        ml_probability_raw = ml_p_raw,
        domain_reputation  = dom_rep,
        url_feature_score  = url_fs,
        dns_suspicion      = 0.0,  # not recomputed on hit
        feed_score         = 0.0,
        feed_hits          = dict(fv_dict)  if isinstance(fv_dict,  dict) else {},
        dns                = dict(dns_dict) if isinstance(dns_dict, dict) else {},
        cached             = True,
        latency_ms         = round(latency_ms, 3),
        model_version      = classifier.version,
        calibrated         = classifier.calibrator.fitted,
    )


# ── Small async shim helpers so `asyncio.gather` always has awaitables ───────

async def _zero_feed_verdict() -> "FeedVerdict":
    return FeedVerdict()

async def _zero_dns_features() -> "DnsFeatures":
    return DnsFeatures()

async def _one() -> float:
    return 1.0


def _age_seconds(last_seen: Any) -> float:
    if not last_seen:
        return float("inf")
    if isinstance(last_seen, datetime):
        ts = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds()
    return float("inf")


def _is_fresh(last_seen: Any, ttl: int) -> bool:
    if ttl <= 0:
        return True
    if not last_seen:
        return False
    if isinstance(last_seen, datetime):
        ts = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
    else:
        return False
    return (datetime.now(timezone.utc) - ts) < timedelta(seconds=ttl)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok", "model_loaded": True}


@app.get("/model_info")
async def model_info(request: Request) -> Dict[str, Any]:
    clf: URLClassifier = request.app.state.classifier
    return {
        "version":    clf.version,
        "threshold":  clf.threshold,
        "features":   clf.feature_names,
        "metrics":    clf.meta.get("metrics"),
        "calibrator": {
            "fitted": clf.calibrator.fitted,
            "meta":   clf.calibrator.meta,
        },
        "blend_weights": {
            "ml": W_ML, "domain_reputation": W_REP,
            "url_feature_score": W_UFS,
            "dns_suspicion": W_DNS, "external_feed": W_FEED,
            "authoritative_feed_floor": FEED_FLOOR,
        },
    }


@app.get("/stats")
async def stats(request: Request) -> Dict[str, Any]:
    feeds: Optional[ThreatFeedRegistry] = getattr(request.app.state, "feeds", None)
    return {
        "feeds": feeds.stats if feeds else {"enabled": False},
        "dns":   {"enabled": getattr(request.app.state, "dns", None) is not None},
        "cache": {"enabled": getattr(request.app.state, "cache", None) is not None},
    }


@app.post("/analyze_url", response_model=AnalyzeResponse)
async def analyze_url(body: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    if not body.url:
        raise HTTPException(status_code=400, detail="url is required")
    return await _classify(request, body.url, body.source, body.bypass_cache)


@app.post("/analyze_urls", response_model=List[AnalyzeResponse])
async def analyze_urls(body: BatchAnalyzeRequest, request: Request) -> List[AnalyzeResponse]:
    if len(body.urls) > BATCH_LIMIT:
        raise HTTPException(status_code=413, detail=f"max {BATCH_LIMIT} urls per request")
    # fan-out keeps the DB round-trips concurrent without overwhelming the pool
    results = await asyncio.gather(
        *[_classify(request, u, body.source, body.bypass_cache) for u in body.urls],
        return_exceptions=True,
    )
    out: List[AnalyzeResponse] = []
    for u, r in zip(body.urls, results):
        if isinstance(r, Exception):
            log.exception("analyze_urls: %s failed: %s", u, r)
            out.append(AnalyzeResponse(
                url=u,
                domain=extract_hostname(u),
                etld1=extract_etld1(u),
                prediction="error",
                confidence=0.0, risk_score=0,
                ml_probability=0.0, ml_probability_raw=0.0,
                domain_reputation=1.0, url_feature_score=0.0,
                dns_suspicion=0.0, feed_score=0.0,
                feed_hits={}, dns={},
                cached=False, latency_ms=0.0,
                model_version=None, calibrated=False,
            ))
        else:
            out.append(r)
    return out


# ── Entrypoint for `python services/url_intel_service.py` ─────────────────────

if __name__ == "__main__":  # pragma: no cover
    import uvicorn
    uvicorn.run(
        "services.url_intel_service:app",
        host=os.environ.get("URL_INTEL_HOST", "0.0.0.0"),
        port=int(os.environ.get("URL_INTEL_PORT", "8088")),
        workers=int(os.environ.get("URL_INTEL_WORKERS", "1")),
        log_level="info",
    )
