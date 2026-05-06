"""
Database + Neo4j connection management for the attack-paths service.
"""
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from neo4j import AsyncDriver, AsyncGraphDatabase
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# ── Postgres ──────────────────────────────────────────────────────────────────

engine = create_async_engine(
    settings.database_url,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_timeout=settings.db_pool_timeout,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    pass


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Neo4j ─────────────────────────────────────────────────────────────────────

_neo4j_driver: AsyncDriver | None = None


def get_neo4j() -> AsyncDriver:
    """Process-wide Neo4j driver. Lazily constructed; close in lifespan shutdown."""
    global _neo4j_driver
    if _neo4j_driver is None:
        _neo4j_driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            max_connection_lifetime=3600,
        )
    return _neo4j_driver


async def close_neo4j() -> None:
    global _neo4j_driver
    if _neo4j_driver is not None:
        await _neo4j_driver.close()
        _neo4j_driver = None


async def neo4j_session(write: bool = False):
    """Convenience: open an async session in the configured database."""
    driver = get_neo4j()
    return driver.session(
        database=settings.neo4j_database,
        default_access_mode="WRITE" if write else "READ",
    )
