"""Application configuration.

Secrets are read from the environment only. Defaults exist so that a developer can
clone and run, but :meth:`Settings.assert_production_ready` refuses to boot with any
default secret once the environment is not ``development``.
"""

from __future__ import annotations

import base64
import functools
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Sentinels: these exact values are shipped in .env.example and must never reach production.
INSECURE_SECRET_KEY = "dev-insecure-secret-key-change-me"
INSECURE_MASTER_KEY = "Y3liZXJ0cmFjZS1kZXZlbG9wbWVudC1rZWstMzJieXQ="


class Environment(StrEnum):
    development = "development"
    test = "test"
    production = "production"


def _split_csv(value: object) -> object:
    """Allow comma-separated strings for list-valued settings."""
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


# NoDecode stops pydantic-settings from attempting to JSON-parse the raw environment
# value, so operators can write a plain comma-separated list instead of a JSON array.
CsvList = Annotated[list[str], NoDecode, BeforeValidator(_split_csv)]


class ConfigurationError(RuntimeError):
    """Raised when the process is not safe to start with the supplied configuration."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CYBERTRACE_",
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ---
    env: Environment = Environment.development
    debug: bool = True
    app_name: str = "CYBERTRACE"
    api_prefix: str = "/api/v1"

    # --- Database ---
    database_url: str = (
        "postgresql+psycopg://cybertrace:cybertrace_dev_password@localhost:5433/cybertrace"
    )
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_echo: bool = False

    # --- Cryptography ---
    secret_key: str = INSECURE_SECRET_KEY
    master_key: str = INSECURE_MASTER_KEY
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 1_209_600
    password_min_length: int = 12

    # --- Sessions / cookies ---
    refresh_cookie_name: str = "cybertrace_refresh"
    csrf_cookie_name: str = "cybertrace_csrf"
    cookie_secure: bool = False
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    cookie_domain: str | None = None

    # --- Account protection ---
    max_failed_logins: int = 5
    lockout_seconds: int = 900
    login_rate_limit_per_minute: int = 10

    # --- Storage ---
    storage_root: Path = Path("./var/storage")
    max_upload_bytes: int = 2 * 1024 * 1024 * 1024
    hash_chunk_bytes: int = 1024 * 1024
    download_url_ttl_seconds: int = 120

    # --- Web ---
    cors_origins: CsvList = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )

    # --- Worker ---
    worker_enabled: bool = True
    worker_concurrency: int = 2
    worker_poll_interval_seconds: float = 1.0
    job_max_attempts: int = 3
    job_lease_seconds: int = 600

    # --- Analysis tuning ---
    max_analyzable_bytes: int = 64 * 1024 * 1024
    correlation_min_score: float = 0.15
    anomaly_zscore_threshold: float = 2.5

    # --- Optional LLM layer ---
    llm_enabled: bool = False
    llm_api_key: str | None = None
    llm_model: str = "gpt-4o-mini"

    @field_validator("storage_root")
    @classmethod
    def _resolve_storage_root(cls, value: Path) -> Path:
        return value.expanduser()

    @property
    def is_production(self) -> bool:
        return self.env is Environment.production

    @functools.cached_property
    def master_key_bytes(self) -> bytes:
        """The 32-byte KEK used to wrap per-object evidence data keys."""
        try:
            raw = base64.b64decode(self.master_key, validate=True)
        except Exception as exc:
            raise ConfigurationError(
                "CYBERTRACE_MASTER_KEY must be base64-encoded 32 bytes"
            ) from exc
        if len(raw) != 32:
            raise ConfigurationError(
                f"CYBERTRACE_MASTER_KEY must decode to exactly 32 bytes, got {len(raw)}"
            )
        return raw

    def assert_production_ready(self) -> None:
        """Fail fast rather than run a forensic platform with known-public secrets."""
        if not self.is_production:
            return
        problems: list[str] = []
        if self.secret_key == INSECURE_SECRET_KEY:
            problems.append("CYBERTRACE_SECRET_KEY is still the shipped development default")
        if self.master_key == INSECURE_MASTER_KEY:
            problems.append("CYBERTRACE_MASTER_KEY is still the shipped development default")
        if len(self.secret_key) < 32:
            problems.append("CYBERTRACE_SECRET_KEY must be at least 32 characters")
        if not self.cookie_secure:
            problems.append("CYBERTRACE_COOKIE_SECURE must be true in production")
        if self.debug:
            problems.append("CYBERTRACE_DEBUG must be false in production")
        if any(origin.startswith("http://") for origin in self.cors_origins):
            problems.append("CORS origins must use https in production")
        if problems:
            raise ConfigurationError(
                "Refusing to start in production:\n  - " + "\n  - ".join(problems)
            )


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
