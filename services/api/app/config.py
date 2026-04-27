"""
Central configuration module – all settings loaded from environment variables.
Settings are validated at startup; missing required values raise a clear error.
"""
from functools import lru_cache
from typing import List, Optional

from pydantic import field_validator, AnyUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────
    app_name: str = "TI Platform"
    app_version: str = "1.0.0"
    environment: str = "production"
    log_level: str = "INFO"
    secret_key: str
    api_key: str

    # ── Database ─────────────────────────────────────────────
    database_url: str
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_timeout: int = 30

    # ── Redis ────────────────────────────────────────────────
    redis_url: str
    redis_ttl_default: int = 3600         # 1 hour
    redis_ttl_edl: int = 300              # 5 minutes
    redis_ttl_enrichment: int = 86400     # 24 hours

    # ── NATS ─────────────────────────────────────────────────
    nats_url: str

    # ── CORS ─────────────────────────────────────────────────
    cors_origins: str = "http://localhost:3000"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v: str) -> str:
        return v  # kept as string; parsed in main.py

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    # ── Pagination ───────────────────────────────────────────
    default_page_size: int = 50
    max_page_size: int = 1000

    # ── Enrichment ───────────────────────────────────────────
    alert_min_confidence: int = 60

    # ── Feature flags ────────────────────────────────────────
    sandbox_enabled: bool = False
    sandbox_url: Optional[str] = None

    @property
    def is_development(self) -> bool:
        return self.environment == "development"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
