"""End-to-end login rate-limit checks against the disposable PostgreSQL database."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from app.api import deps
from app.api.routes import auth
from app.core.clock import FixedClock
from app.core.config import Settings
from app.core.limiter import limiter
from app.core.rate_limit import account_rate_limit_key, ip_rate_limit_key
from app.db.models.rate_limit_state import RateLimitState
from app.db.repositories.rate_limit_state import RateLimitStateRepository
from app.db.session import create_async_engine_for_url, create_session_factory
from app.main import create_app
from app.services import security_events
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.integration.database import ScratchDatabase

_NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
_ORIGIN = "http://localhost:5173"
_PASSWORD = "integration-password-must-not-be-stored"
_KEY_SECRET = "integration-rate-limit-key-secret"
_SECURITY_EVENT_TEST_SECRET = "integration-security-event-key-secret"


class _UpstreamClient:
    def __init__(self, calls: list[dict[str, Any]]) -> None:
        self.calls = calls

    async def __aenter__(self) -> _UpstreamClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def post(self, *_: Any, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        request = httpx.Request("POST", "https://project.example.test/auth/v1/token")
        return httpx.Response(
            200,
            content=(
                b'{"access_token":"integration-token",'
                b'"user":{"id":"10000000-0000-4000-8000-000000000001"}}'
            ),
            request=request,
        )


def _configured_client(
    monkeypatch: pytest.MonkeyPatch,
    database: ScratchDatabase,
    *,
    peer_ip: str,
    raise_server_exceptions: bool = True,
) -> tuple[TestClient, Any, list[dict[str, Any]], async_sessionmaker[AsyncSession]]:
    engine = create_async_engine_for_url(database.url, null_pool=True)
    session_factory = create_session_factory(engine)
    upstream_calls: list[dict[str, Any]] = []
    settings = Settings(
        app_env="test",
        cors_allowed_origin=_ORIGIN,
        supabase_url="https://project.example.test",
        supabase_anon_key="test-anon-key",
        rate_limit_key_secret=_KEY_SECRET,
        security_event_key_secret=_SECURITY_EVENT_TEST_SECRET,
    )
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(security_events, "get_settings", lambda: settings)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_: _UpstreamClient(upstream_calls))
    application = create_app(settings)

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    application.dependency_overrides[deps.get_db_session] = override_session
    application.dependency_overrides[deps.get_clock] = lambda: FixedClock(_NOW)
    client = TestClient(
        application,
        client=(peer_ip, 50000),
        raise_server_exceptions=raise_server_exceptions,
    )
    return client, engine, upstream_calls, session_factory


def _post_login(client: TestClient, email: str) -> Any:
    limiter.reset()
    return client.post("/auth/login", json={"email": email, "password": _PASSWORD})


def _read_counters(
    session_factory: async_sessionmaker[AsyncSession], keys: set[str]
) -> dict[str, int]:
    async def read() -> dict[str, int]:
        async with session_factory() as session:
            states = await session.scalars(
                select(RateLimitState).where(RateLimitState.key.in_(keys))
            )
            return {state.key: state.counter for state in states.all()}

    return asyncio.run(read())


def _delete_keys(database: ScratchDatabase, keys: set[str]) -> None:
    async def delete() -> None:
        engine = create_async_engine_for_url(database.url, null_pool=True)
        try:
            async with engine.begin() as connection:
                for key in keys:
                    await connection.execute(
                        text("DELETE FROM public.rate_limit_state WHERE key = :key"),
                        {"key": key},
                    )
        finally:
            await engine.dispose()

    asyncio.run(delete())


def test_login_postgres_allows_five_and_blocks_sixth(
    monkeypatch: pytest.MonkeyPatch,
    migrated_test_database: ScratchDatabase,
) -> None:
    email = f"login-{uuid4()}@integration.test"
    peer_ip = "192.0.2.101"
    keys = {
        ip_rate_limit_key(peer_ip),
        account_rate_limit_key(
            email,
            settings=Settings(
                app_env="test",
                cors_allowed_origin=_ORIGIN,
                rate_limit_key_secret=_KEY_SECRET,
            ),
        ),
    }
    client, engine, upstream_calls, session_factory = _configured_client(
        monkeypatch,
        migrated_test_database,
        peer_ip=peer_ip,
    )
    try:
        for _ in range(5):
            response = _post_login(client, email)
            assert response.status_code == 200

        blocked = _post_login(client, email)
        assert blocked.status_code == 429
        assert blocked.json()["error"]["code"] == "RATE_LIMITED"
        assert len(upstream_calls) == 5
        assert _read_counters(session_factory, keys) == dict.fromkeys(keys, 5)
    finally:
        client.close()
        _delete_keys(migrated_test_database, keys)
        asyncio.run(engine.dispose())


def test_login_postgres_ip_and_account_keys_are_independent_scopes(
    monkeypatch: pytest.MonkeyPatch,
    migrated_test_database: ScratchDatabase,
) -> None:
    peer_ip = "192.0.2.102"
    emails = [f"shared-ip-{uuid4()}@integration.test" for _ in range(6)]
    ip_key = ip_rate_limit_key(peer_ip)
    account_keys = {
        account_rate_limit_key(
            email,
            settings=Settings(
                app_env="test",
                cors_allowed_origin=_ORIGIN,
                rate_limit_key_secret=_KEY_SECRET,
            ),
        )
        for email in emails
    }
    client, engine, upstream_calls, session_factory = _configured_client(
        monkeypatch,
        migrated_test_database,
        peer_ip=peer_ip,
    )
    try:
        for email in emails[:5]:
            assert _post_login(client, email).status_code == 200
        blocked = _post_login(client, emails[5])
        assert blocked.status_code == 429
        assert len(upstream_calls) == 5
        counters = _read_counters(session_factory, account_keys | {ip_key})
        assert counters[ip_key] == 5
        assert {key: counters[key] for key in account_keys} == dict.fromkeys(account_keys, 1)
    finally:
        client.close()
        _delete_keys(migrated_test_database, account_keys | {ip_key})
        asyncio.run(engine.dispose())


def test_login_postgres_account_limit_is_shared_across_client_ips(
    monkeypatch: pytest.MonkeyPatch,
    migrated_test_database: ScratchDatabase,
) -> None:
    email = f"shared-account-{uuid4()}@integration.test"
    peer_ips = [f"198.51.100.{index}" for index in range(1, 7)]
    keys = {ip_rate_limit_key(peer_ip) for peer_ip in peer_ips}
    keys.add(
        account_rate_limit_key(
            email,
            settings=Settings(
                app_env="test",
                cors_allowed_origin=_ORIGIN,
                rate_limit_key_secret=_KEY_SECRET,
            ),
        )
    )
    clients: list[TestClient] = []
    engines = []
    calls_per_client: list[list[dict[str, Any]]] = []
    session_factory: async_sessionmaker[AsyncSession] | None = None
    try:
        for peer_ip in peer_ips:
            client, engine, upstream_calls, session_factory = _configured_client(
                monkeypatch,
                migrated_test_database,
                peer_ip=peer_ip,
            )
            clients.append(client)
            engines.append(engine)
            calls_per_client.append(upstream_calls)
            response = _post_login(client, email)
            if peer_ip == peer_ips[-1]:
                assert response.status_code == 429
            else:
                assert response.status_code == 200

        account_key = account_rate_limit_key(
            email,
            settings=Settings(
                app_env="test",
                cors_allowed_origin=_ORIGIN,
                rate_limit_key_secret=_KEY_SECRET,
            ),
        )
        assert sum(map(len, calls_per_client)) == 5
        assert session_factory is not None
        assert _read_counters(session_factory, keys)[account_key] == 5
    finally:
        for client in clients:
            client.close()
        _delete_keys(migrated_test_database, keys)
        for engine in engines:
            asyncio.run(engine.dispose())


def test_login_postgres_partial_admission_commits_and_database_failure_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
    migrated_test_database: ScratchDatabase,
) -> None:
    email = f"partial-{uuid4()}@integration.test"
    peer_ip = "192.0.2.103"
    account_key = account_rate_limit_key(
        email,
        settings=Settings(
            app_env="test",
            cors_allowed_origin=_ORIGIN,
            rate_limit_key_secret=_KEY_SECRET,
        ),
    )
    ip_key = ip_rate_limit_key(peer_ip)
    keys = {account_key, ip_key}
    client, engine, upstream_calls, session_factory = _configured_client(
        monkeypatch,
        migrated_test_database,
        peer_ip=peer_ip,
    )

    async def seed_capped_account() -> None:
        async with session_factory() as session, session.begin():
            await RateLimitStateRepository(session).add_or_update(
                RateLimitState(
                    key=account_key,
                    counter=5,
                    window_reset_at=_NOW + timedelta(minutes=5),
                    updated_at=_NOW,
                )
            )

    try:
        asyncio.run(seed_capped_account())
        denied = _post_login(client, email)
        assert denied.status_code == 429
        assert len(upstream_calls) == 0
        counters = _read_counters(session_factory, keys)
        assert counters[account_key] == 5
        assert counters[ip_key] == 1

        original_consume = RateLimitStateRepository.consume_attempt
        call_count = 0

        async def fail_on_second_key(
            repository: RateLimitStateRepository,
            key: str,
            now: datetime,
            attempt_limit: int,
            window_duration: Any,
        ) -> bool:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise RuntimeError("scratch database operation failure")
            return await original_consume(
                repository,
                key,
                now,
                attempt_limit,
                window_duration,
            )

        monkeypatch.setattr(RateLimitStateRepository, "consume_attempt", fail_on_second_key)
        rollback_email = f"rollback-{uuid4()}@integration.test"
        rollback_account_key = account_rate_limit_key(
            rollback_email,
            settings=Settings(
                app_env="test",
                cors_allowed_origin=_ORIGIN,
                rate_limit_key_secret=_KEY_SECRET,
            ),
        )
        rollback_ip_key = ip_rate_limit_key("192.0.2.104")
        rollback_keys = {rollback_account_key, rollback_ip_key}
        rollback_client, rollback_engine, _, rollback_factory = _configured_client(
            monkeypatch,
            migrated_test_database,
            peer_ip="192.0.2.104",
            raise_server_exceptions=False,
        )
        try:
            failed = rollback_client.post(
                "/auth/login",
                json={"email": rollback_email, "password": _PASSWORD},
            )
            assert failed.status_code == 500
            assert "scratch database operation failure" not in failed.text
            assert _read_counters(rollback_factory, rollback_keys) == {}
        finally:
            rollback_client.close()
            _delete_keys(migrated_test_database, rollback_keys)
            asyncio.run(rollback_engine.dispose())
    finally:
        client.close()
        _delete_keys(migrated_test_database, keys)
        asyncio.run(engine.dispose())
