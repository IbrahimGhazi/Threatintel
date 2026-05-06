"""
TI Platform — FastAPI application entry point.

Pipeline:
  log ingestion → parsing → normalization → baseline learning
  → detection engine → suggestion engine → alert pipeline → dashboard
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

import nats as nats_client_lib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import engine, Base

# ── Routers ───────────────────────────────────────────────────────────────────
from app.routers import logs, tuning

# These routers live in the main repo; imported here for completeness.
# If they don't exist yet in this branch, remove the import and re-add when merged.
try:
    from app.routers import indicators
    _has_indicators = True
except ImportError:
    _has_indicators = False

try:
    from app.routers import alerts
    _has_alerts = True
except ImportError:
    _has_alerts = False

try:
    from app.routers import sandbox
    _has_sandbox = True
except ImportError:
    _has_sandbox = False

try:
    from app.routers import feeds
    _has_feeds = True
except ImportError:
    _has_feeds = False

try:
    from app.routers import edl
    _has_edl = True
except ImportError:
    _has_edl = False

try:
    from app.routers import whitelist
    _has_whitelist = True
except ImportError:
    _has_whitelist = False

try:
    from app.routers import stats
    _has_stats = True
except ImportError:
    _has_stats = False

try:
    from app.routers import network
    _has_network = True
except ImportError:
    _has_network = False

try:
    from app.routers import recommendations
    _has_recommendations = True
except ImportError:
    _has_recommendations = False

try:
    from app.routers import settings as settings_router
    _has_settings = True
except ImportError:
    _has_settings = False

try:
    from app.routers import incidents
    _has_incidents = True
except ImportError:
    _has_incidents = False

try:
    from app.routers import metrics
    _has_metrics = True
except ImportError:
    _has_metrics = False

try:
    from app.routers import url_intel
    _has_url_intel = True
except ImportError:
    _has_url_intel = False

try:
    from app.routers import api_keys
    _has_api_keys = True
except ImportError:
    _has_api_keys = False

try:
    from app.routers import attack_paths
    _has_attack_paths = True
except ImportError:
    _has_attack_paths = False


log = logging.getLogger("ti.api")


# ── Log retention cleanup ──────────────────────────────────────────────────────

async def _retention_cleanup_loop() -> None:
    """
    Background task: purge log_entries older than the configured retention period.
    Runs once on startup, then every 24 hours.
    """
    from app.database import AsyncSessionLocal

    while True:
        try:
            from sqlalchemy import text
            async with AsyncSessionLocal() as db:
                # Read retention setting (default 30 days)
                row = (await db.execute(
                    text("SELECT value FROM platform_settings WHERE key = 'log_retention_days'")
                )).fetchone()
                retention_days = int(row.value) if row else 30

                result = await db.execute(
                    text("""
                        DELETE FROM log_entries
                        WHERE processed_at < NOW() - INTERVAL '1 day' * :days
                    """),
                    {"days": retention_days},
                )
                await db.commit()
                purged = result.rowcount
                if purged:
                    log.info("Retention cleanup: purged %d log entries older than %d days", purged, retention_days)
        except Exception as exc:
            log.warning("Retention cleanup failed: %s", exc)

        await asyncio.sleep(86400)  # sleep 24 hours




async def _url_reputation_ground_truth_migration() -> None:
    """Idempotently add ground_truth columns to url_reputation (one-off boot task)."""
    from app.database import AsyncSessionLocal
    from sqlalchemy import text
    SQL = """
    ALTER TABLE url_reputation
        ADD COLUMN IF NOT EXISTS ground_truth text,
        ADD COLUMN IF NOT EXISTS labeled_at   timestamptz,
        ADD COLUMN IF NOT EXISTS labeled_by   text;
    DO $$ BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'url_reputation_ground_truth_check'
        ) THEN
            ALTER TABLE url_reputation
              ADD CONSTRAINT url_reputation_ground_truth_check
              CHECK (ground_truth IS NULL OR ground_truth = ANY (ARRAY['benign','suspicious','malicious']));
        END IF;
    END $$;
    CREATE INDEX IF NOT EXISTS idx_url_reputation_ground_truth
        ON url_reputation (ground_truth) WHERE ground_truth IS NOT NULL;
    """
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text(SQL))
            await db.commit()
        log.info("url_reputation ground_truth columns OK")
    except Exception as exc:
        log.warning("ground_truth migration failed (continuing): %s", exc)



async def _url_content_analysis_migration() -> None:
    """Idempotently create url_content_analysis + extend url_reputation with
    content-analysis adjudication columns."""
    from app.database import AsyncSessionLocal
    from sqlalchemy import text
    SQL = """
    ALTER TABLE url_reputation
        ADD COLUMN IF NOT EXISTS content_verdict      text,
        ADD COLUMN IF NOT EXISTS content_analyzed_at  timestamptz,
        ADD COLUMN IF NOT EXISTS original_prediction  text,
        ADD COLUMN IF NOT EXISTS override_reason      text;

    CREATE TABLE IF NOT EXISTS url_content_analysis (
        id                    bigserial PRIMARY KEY,
        url_reputation_id     bigint NOT NULL
                               REFERENCES url_reputation(id) ON DELETE CASCADE,
        url                   text NOT NULL,
        analyzed_at           timestamptz NOT NULL DEFAULT now(),
        final_url             text,
        status_code           int,
        load_time_ms          int,
        html_sha256           text,
        html_size             int,
        title                 text,
        redirect_count        int,
        external_origin_count int,
        script_count          int,
        inline_script_count   int,
        signals               jsonb NOT NULL DEFAULT '{}'::jsonb,
        network_summary       jsonb,
        content_risk_score    int NOT NULL DEFAULT 0,
        content_verdict       text NOT NULL,
        analyzer_version      text NOT NULL DEFAULT 'wca-v1',
        error                 text
    );

    DO $$ BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname='url_content_analysis_verdict_check'
        ) THEN
            ALTER TABLE url_content_analysis
              ADD CONSTRAINT url_content_analysis_verdict_check
              CHECK (content_verdict = ANY (ARRAY['benign','suspicious','malicious','error']));
        END IF;
    END $$;

    CREATE INDEX IF NOT EXISTS idx_ucontent_url_rep
        ON url_content_analysis(url_reputation_id);
    CREATE INDEX IF NOT EXISTS idx_ucontent_verdict
        ON url_content_analysis(content_verdict);
    CREATE INDEX IF NOT EXISTS idx_ucontent_analyzed_at
        ON url_content_analysis(analyzed_at DESC);
    CREATE INDEX IF NOT EXISTS idx_url_rep_content_verdict
        ON url_reputation(content_verdict) WHERE content_verdict IS NOT NULL;
    """
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text(SQL))
            await db.commit()
        log.info("url_content_analysis schema OK")
    except Exception as exc:
        log.warning("url_content_analysis migration failed (continuing): %s", exc)

# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    # One-off schema migrations (idempotent)
    try:
        await _url_reputation_ground_truth_migration()
        await _url_content_analysis_migration()
    except Exception as exc:
        log.warning("startup migration error: %s", exc)

    # Connect to NATS
    nats_conn = None
    try:
        nats_conn = await nats_client_lib.connect(
            settings.nats_url,
            reconnect_time_wait=2,
            max_reconnect_attempts=-1,
        )
        app.state.nats_client = nats_conn
        log.info("Connected to NATS at %s", settings.nats_url)
    except Exception as exc:
        log.warning("NATS connection failed (continuing without): %s", exc)
        app.state.nats_client = None

    # Start NATS subscriber (picks up indicator ingestion messages)
    subscriber_task = None
    try:
        from app.services.nats_subscriber import start_indicator_subscriber
        subscriber_task = asyncio.create_task(
            start_indicator_subscriber(app.state.nats_client)
        )
    except ImportError:
        pass

    # Start log retention cleanup loop
    retention_task = asyncio.create_task(_retention_cleanup_loop())

    yield

    # Cleanup
    retention_task.cancel()
    try:
        await retention_task
    except asyncio.CancelledError:
        pass

    if subscriber_task:
        subscriber_task.cancel()
        try:
            await subscriber_task
        except asyncio.CancelledError:
            pass
    if nats_conn:
        await nats_conn.close()


# ── Application factory ────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="TI Platform API",
        description="Vendor-Agnostic Threat Intelligence & SIEM Platform",
        version="1.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins.split(",") if settings.cors_origins else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Always-present routers ────────────────────────────────────────────────
    app.include_router(logs.router)
    app.include_router(tuning.router)

    # ── Optional routers (present in main branch) ─────────────────────────────
    if _has_indicators:      app.include_router(indicators.router)
    if _has_alerts:          app.include_router(alerts.router)
    if _has_sandbox:         app.include_router(sandbox.router)
    if _has_feeds:           app.include_router(feeds.router)
    if _has_edl:             app.include_router(edl.router)
    if _has_whitelist:       app.include_router(whitelist.router)
    if _has_stats:           app.include_router(stats.router)
    if _has_network:         app.include_router(network.router)
    if _has_recommendations: app.include_router(recommendations.router)
    if _has_settings:        app.include_router(settings_router.router)
    if _has_api_keys:        app.include_router(api_keys.router)
    if _has_incidents:       app.include_router(incidents.router)
    if _has_metrics:         app.include_router(metrics.router)
    if _has_url_intel:       app.include_router(url_intel.router)
    if _has_attack_paths:    app.include_router(attack_paths.router)

    # ── Health check ──────────────────────────────────────────────────────────
    @app.get("/health", include_in_schema=False)
    async def health():
        return {"status": "ok", "version": "1.1.0"}

    return app


app = create_app()
