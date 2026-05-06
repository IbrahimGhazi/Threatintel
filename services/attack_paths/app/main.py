"""
attack-paths service — FastAPI entry point.

Owns: parsing device configs, building the Neo4j graph, running the
analysis engines, and writing findings to Postgres. The api service
proxies user-facing endpoints to here for run triggers + graph reads.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import get_settings
from app.db import close_neo4j, get_neo4j
from app.routes import runs as runs_route
from app.routes import graph as graph_route

log = logging.getLogger("ti.attack_paths")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)

    # Eagerly construct the Neo4j driver so misconfiguration fails fast.
    driver = get_neo4j()
    try:
        async with driver.session(database=settings.neo4j_database) as s:
            await s.run("RETURN 1")
        log.info("Connected to Neo4j at %s", settings.neo4j_uri)
    except Exception as exc:
        log.warning("Neo4j connectivity check failed: %s", exc)

    yield

    await close_neo4j()


def create_app() -> FastAPI:
    app = FastAPI(
        title="TI Platform — attack-paths",
        description="Config-driven Attack Path & Fan-Out Analysis Engine",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.include_router(runs_route.router)
    app.include_router(graph_route.router)

    @app.get("/health", include_in_schema=False)
    async def health():
        return {"status": "ok", "service": "attack-paths"}

    return app


app = create_app()
