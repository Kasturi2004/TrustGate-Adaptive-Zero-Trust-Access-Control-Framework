"""Async SQLAlchemy engine and session factory.

This module reads DATABASE_URL only. Supabase Auth settings are not used here.
The engine connects on first use, so application startup and GET /health do not
require a database. The URL and its password are never logged.
"""

import ssl

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings

_POSTGRES_SCHEMES = {"postgres", "postgresql", "postgresql+asyncpg"}
_ENCRYPT_ONLY = {"require", "prefer", "allow"}
_VERIFY = {"verify-ca", "verify-full"}


class DatabaseConfigurationError(RuntimeError):
    """DATABASE_URL is missing or not a PostgreSQL URL."""


def require_database_url(settings: Settings) -> str:
    """Return the configured database URL, or raise without echoing its value."""
    url = settings.database_url
    if url is None or url.strip() == "":
        raise DatabaseConfigurationError("DATABASE_URL is not configured")
    return url.strip()


def prepare_database_url(raw_url: str) -> tuple[str, dict[str, object]]:
    """Turn a libpq URL into an asyncpg URL and connect arguments.

    Supabase transaction-pooler connections need statement_cache_size=0.
    That setting is also safe for a direct connection. sslmode is translated
    because asyncpg does not accept it as a keyword argument.
    """
    stripped = raw_url.strip()
    scheme, separator, remainder = stripped.partition("://")
    if separator == "" or remainder == "":
        raise DatabaseConfigurationError("DATABASE_URL must be a PostgreSQL connection URL")
    if scheme.lower() not in _POSTGRES_SCHEMES:
        raise DatabaseConfigurationError("DATABASE_URL must use the PostgreSQL scheme")
    if scheme.lower() in {"postgres", "postgresql"}:
        stripped = f"postgresql+asyncpg://{remainder}"

    try:
        parsed = make_url(stripped)
    except Exception:
        raise DatabaseConfigurationError("DATABASE_URL is not a valid PostgreSQL URL") from None

    query = dict(parsed.query)
    sslmode = query.pop("sslmode", None)
    query.pop("channel_binding", None)
    parsed = parsed.set(query=query)

    connect_args: dict[str, object] = {"statement_cache_size": 0}
    host = parsed.host or ""
    supabase_host = host.endswith(".supabase.co") or host.endswith(".pooler.supabase.com")
    ssl_context = _ssl_context(
        sslmode if isinstance(sslmode, str) else None, supabase_host=supabase_host
    )
    if ssl_context is not None:
        connect_args["ssl"] = ssl_context

    return parsed.render_as_string(hide_password=False), connect_args


def _ssl_context(sslmode: str | None, *, supabase_host: bool) -> ssl.SSLContext | None:
    """Map libpq sslmode onto asyncpg.

    libpq ``require`` encrypts without verifying the certificate. asyncpg's
    ``ssl=True`` verifies, which rejects Supabase's chain on some machines.
    ``verify-ca`` and ``verify-full`` keep certificate verification.
    """
    mode = sslmode.lower() if sslmode is not None else None
    if mode == "disable":
        return None
    if mode in _VERIFY:
        context = ssl.create_default_context()
        if mode == "verify-ca":
            context.check_hostname = False
        return context
    if mode in _ENCRYPT_ONLY or supabase_host:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return None


def create_db_engine(settings: Settings) -> AsyncEngine:
    """Create a lazy async engine. This does not open a connection."""
    url, connect_args = prepare_database_url(require_database_url(settings))
    return create_async_engine(
        url,
        echo=False,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """SQLAlchemy 2.0 async session factory bound to an existing engine."""
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)


async def select_one(session_factory: async_sessionmaker[AsyncSession]) -> int:
    """Run SELECT 1. The caller owns engine disposal."""
    async with session_factory() as session:
        result = await session.execute(text("SELECT 1"))
        if result.scalar_one() != 1:
            raise RuntimeError("Database connectivity check returned an unexpected result")
    return 1
