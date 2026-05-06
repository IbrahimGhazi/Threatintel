"""
attack-paths service configuration.
"""
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────
    log_level: str = "INFO"
    api_key: str

    # ── Database ─────────────────────────────────────────────
    database_url: str
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_timeout: int = 30

    # ── Neo4j ────────────────────────────────────────────────
    neo4j_uri: str
    # Format: "user/password" — matches the official image's NEO4J_AUTH env.
    neo4j_auth: str
    neo4j_database: str = "neo4j"

    # ── Storage ──────────────────────────────────────────────
    attack_paths_config_dir: str = "/var/lib/ti/configs"

    # ── Run budget ───────────────────────────────────────────
    attack_paths_run_timeout: int = 600  # seconds; 0 = unlimited

    @property
    def neo4j_user(self) -> str:
        return self.neo4j_auth.split("/", 1)[0]

    @property
    def neo4j_password(self) -> str:
        parts = self.neo4j_auth.split("/", 1)
        return parts[1] if len(parts) > 1 else ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
