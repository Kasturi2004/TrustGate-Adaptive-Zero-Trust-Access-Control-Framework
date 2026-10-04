"""Typed environment configuration.

Phase 1 requires only the settings needed to boot the API. Later-phase
secrets are optional until the phase that reads them, so local setup does
not invent placeholder credentials.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = REPO_ROOT / ".env"

AppEnv = Literal["local", "test", "staging", "production"]


class Settings(BaseSettings):
    """Process configuration loaded from the environment and the root .env file."""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: AppEnv
    cors_allowed_origin: str

    # Supabase Auth settings. They are separate from DATABASE_URL and unused here.
    supabase_url: str | None = None
    supabase_anon_key: str | None = None
    supabase_jwt_secret: str | None = None
    supabase_service_role_key: str | None = None
    # Async SQLAlchemy connection. Optional so GET /health can boot without a database.
    database_url: str | None = None
    # Owner-role URL for Alembic. Optional until it differs from DATABASE_URL.
    # This is not a Supabase Auth credential.
    migration_database_url: str | None = None
    device_hash_secret: str | None = None
    # Dedicated HMAC key for opaque login account rate-limit identifiers.
    rate_limit_key_secret: str | None = None
    security_event_key_secret: str | None = None
    # Dedicated key for encrypting TOTP secrets at rest; never reuse an HMAC key.
    totp_secret_encryption_key: SecretStr | None = None
    trusted_proxy_hops: int = Field(default=0, ge=0)
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    trusted_proxies: str | None = None
    geoip_db_path: str | None = None
    treat_localhost_as_secure: bool | None = None
    block_indicator_limit: int | None = None

    @field_validator(
        "supabase_url",
        "supabase_anon_key",
        "supabase_jwt_secret",
        "supabase_service_role_key",
        "database_url",
        "migration_database_url",
        "device_hash_secret",
        "rate_limit_key_secret",
        "security_event_key_secret",
        "totp_secret_encryption_key",
        "smtp_host",
        "smtp_user",
        "smtp_password",
        "smtp_from",
        "trusted_proxies",
        "geoip_db_path",
        mode="before",
    )
    @classmethod
    def blank_string_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and value.strip() == "":
            return None
        return value

    @field_validator("cors_allowed_origin")
    @classmethod
    def origin_must_be_explicit(cls, value: str) -> str:
        origin = value.strip()
        if origin == "" or "*" in origin or "," in origin:
            raise ValueError(
                "CORS_ALLOWED_ORIGIN must be one explicit origin and must never be a wildcard"
            )
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise ValueError("CORS_ALLOWED_ORIGIN must be an http(s) origin")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("CORS_ALLOWED_ORIGIN must be an origin without userinfo or a query")
        if parsed.path not in {"", "/"}:
            raise ValueError("CORS_ALLOWED_ORIGIN must not include a path")
        return origin.rstrip("/")


@lru_cache
def get_settings() -> Settings:
    """Return cached settings. Missing required variables fail at first use."""
    # Required fields are supplied by the environment, not by this call.
    return Settings()  # type: ignore[call-arg]
