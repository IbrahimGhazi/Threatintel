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

log = logging.getLogger("ti.api")

# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

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
    try:
        from app.services.nats_subscriber import start_subscriber
        subscriber_task = asyncio.create_task(
            start_subscriber(app.state.nats_client)
        )
    except ImportError:
        subscriber_task = None

    yield

    # Cleanup
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
        version="1.0.0",
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
    app.include_router(logs.router,   prefix="/api")
    app.include_router(tuning.router, prefix="/api")

    # ── Optional routers (present in main branch) ─────────────────────────────
    if _has_indicators: app.include_router(indicators.router, prefix="/api")
    if _has_alerts:     app.include_router(alerts.router,     prefix="/api")
    if _has_sandbox:    app.include_router(sandbox.router,    prefix="/api")
    if _has_feeds:      app.include_router(feeds.router,      prefix="/api")
    if _has_edl:        app.include_router(edl.router,        prefix="/api")
    if _has_whitelist:  app.include_router(whitelist.router,  prefix="/api")
    if _has_stats:      app.include_router(stats.router,      prefix="/api")

    # ── Health check ──────────────────────────────────────────────────────────
    @app.get("/health", include_in_schema=False)
    async def health():
        return {"status": "ok"}

    return app


app = create_app()
