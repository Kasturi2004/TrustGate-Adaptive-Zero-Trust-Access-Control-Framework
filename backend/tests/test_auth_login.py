"""Tests for the Supabase Auth login proxy."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from app.api import deps
from app.api.routes import auth
from app.core.config import Settings
from app.core.limiter import limiter
from app.core.rate_limit import account_rate_limit_key, ip_rate_limit_key
from app.db.repositories.rate_limit_state import RateLimitStateRepository
from app.main import create_app
from app.services import security_events
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

_ORIGIN = "http://localhost:5173"
_PASSWORD = "test-password-never-log"
_ACCESS_TOKEN = "test-access-token-never-log"
_REFRESH_TOKEN = "test-refresh-token-never-log"
_OTP = "test-otp-never-store"
_NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


class _Transaction:
    def __init__(self, counters: dict[str, int]) -> None:
        self._counters = counters
        self._initial_counters: dict[str, int] = {}
        self.committed = False
        self.rolled_back = False

    async def __aenter__(self) -> _Transaction:
        self._initial_counters = self._counters.copy()
        return self

    async def __aexit__(self, *args: object) -> None:
        self.rolled_back = args[0] is not None
        self.committed = not self.rolled_back
        if self.rolled_back:
            self._counters.clear()
            self._counters.update(self._initial_counters)


class _CountingClock:
    def __init__(self) -> None:
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return _NOW


class _RateLimitRuntime:
    def __init__(self) -> None:
        self.session = AsyncMock(spec=AsyncSession)
        self.clock = _CountingClock()
        self.calls: list[tuple[str, datetime, int, timedelta]] = []
        self.counters: dict[str, int] = {}
        self.fail_on_call: int | None = None
        self.transaction = _Transaction(self.counters)
        self.session.begin.return_value = self.transaction

    async def consume(
        self,
        key: str,
        now: datetime,
        attempt_limit: int,
        window_duration: timedelta,
    ) -> bool:
        self.calls.append((key, now, attempt_limit, window_duration))
        if self.fail_on_call == len(self.calls):
            raise RuntimeError("private database failure")
        counter = self.counters.get(key, 0)
        if counter >= attempt_limit:
            return False
        self.counters[key] = counter + 1
        return True


@pytest.fixture(autouse=True)
def _reset_limiter_state() -> Iterator[None]:
    limiter.reset()
    yield
    limiter.reset()


class _MockClient:
    def __init__(
        self, response: httpx.Response | None = None, error: Exception | None = None
    ) -> None:
        self.response = response
        self.error = error
        self.post = AsyncMock(side_effect=self._post)

    async def _post(self, *_: Any, **__: Any) -> httpx.Response:
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response

    async def __aenter__(self) -> _MockClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None


def _client(
    monkeypatch: pytest.MonkeyPatch,
    mock_client: _MockClient,
    *,
    runtime: _RateLimitRuntime | None = None,
    peer_ip: str = "192.0.2.10",
    raise_server_exceptions: bool = True,
) -> TestClient:
    resolved_runtime = runtime or _RateLimitRuntime()
    settings = Settings(
        app_env="test",
        cors_allowed_origin=_ORIGIN,
        supabase_url="https://project.example.test",
        supabase_anon_key="test-anon-key",
        supabase_service_role_key="must-not-be-used",
        rate_limit_key_secret="rate-limit-test-secret",
        security_event_key_secret="security-event-test-secret",
    )
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(security_events, "get_settings", lambda: settings)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_: mock_client)

    async def consume_attempt(
        repository: RateLimitStateRepository,
        key: str,
        now: datetime,
        attempt_limit: int,
        window_duration: timedelta,
    ) -> bool:
        del repository
        return await resolved_runtime.consume(key, now, attempt_limit, window_duration)

    monkeypatch.setattr(RateLimitStateRepository, "consume_attempt", consume_attempt)
    application = create_app(settings)

    async def override_session() -> AsyncIterator[AsyncSession]:
        yield resolved_runtime.session

    application.dependency_overrides[deps.get_db_session] = override_session
    application.dependency_overrides[deps.get_clock] = lambda: resolved_runtime.clock
    return TestClient(
        application,
        client=(peer_ip, 50000),
        raise_server_exceptions=raise_server_exceptions,
    )


def _upstream_response(
    status_code: int, body: bytes, content_type: str = "application/json"
) -> httpx.Response:
    request = httpx.Request("POST", "https://project.example.test/auth/v1/token")
    return httpx.Response(
        status_code,
        content=body,
        headers={"content-type": content_type},
        request=request,
    )


def test_valid_credentials_are_proxied_and_token_response_is_relayed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = (
        b'{"access_token":"test-access-token-never-log",'
        b'"refresh_token":"test-refresh-token-never-log","token_type":"bearer"}'
    )
    mock_client = _MockClient(_upstream_response(200, body))
    client = _client(monkeypatch, mock_client)

    response = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
    )

    assert response.status_code == 200
    assert response.content == body
    mock_client.post.assert_awaited_once()
    call = mock_client.post.await_args
    assert call is not None
    args, kwargs = call
    assert args[0] == "https://project.example.test/auth/v1/token?grant_type=password"
    assert kwargs["headers"] == {
        "apikey": "test-anon-key",
        "Content-Type": "application/json",
    }
    assert kwargs["json"] == {"email": "user@example.test", "password": _PASSWORD}


def test_successful_login_records_redacted_security_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = "e77184cf-0f33-44cf-9ec1-0789a66c2cab"
    body = (
        '{"access_token":"test-access-token-never-log",'
        '"refresh_token":"test-refresh-token-never-log",'
        f'"user":{{"id":"{user_id}"}}'
        "}"
    ).encode()
    runtime = _RateLimitRuntime()
    client = _client(monkeypatch, _MockClient(_upstream_response(200, body)), runtime=runtime)

    response = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
    )

    assert response.status_code == 200
    event = runtime.session.add.call_args.args[0]
    assert event.event_type == "LOGIN_SUCCESS"
    assert str(event.actor_id) == user_id
    assert set(event.details) == {"email_identifier"}
    assert event.details["email_identifier"] == security_events.email_identifier(
        "user@example.test"
    )
    assert "user@example.test" not in str(event.details)
    assert _PASSWORD not in str(event.details)
    assert _ACCESS_TOKEN not in str(event.details)
    assert _REFRESH_TOKEN not in str(event.details)
    runtime.session.commit.assert_not_awaited()


def test_successful_login_security_event_failure_returns_safe_500_and_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _RateLimitRuntime()
    mock_client = _MockClient(
        _upstream_response(
            200,
            (
                b'{"access_token":"test-access-token-never-log",'
                b'"refresh_token":"test-refresh-token-never-log",'
                b'"user":{"id":"e77184cf-0f33-44cf-9ec1-0789a66c2cab"}}'
            ),
        )
    )
    client = _client(
        monkeypatch,
        mock_client,
        runtime=runtime,
        raise_server_exceptions=False,
    )
    private_error = (
        f"private audit persistence failure {_PASSWORD} {_ACCESS_TOKEN} "
        f"{_REFRESH_TOKEN} user@example.test"
    )

    def fail_event_persistence(*_: Any, **__: Any) -> None:
        raise RuntimeError(private_error)

    monkeypatch.setattr(auth, "record_event", fail_event_persistence)

    response = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
        headers={"X-Request-ID": "login-event-storage-failure"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "INTERNAL_ERROR",
            "message": "An unexpected error occurred.",
            "request_id": "login-event-storage-failure",
        }
    }
    assert private_error not in response.text
    for sensitive_value in (_PASSWORD, _ACCESS_TOKEN, _REFRESH_TOKEN, "user@example.test"):
        assert sensitive_value not in response.text
    mock_client.post.assert_awaited_once()
    assert runtime.transaction.rolled_back is True
    assert runtime.transaction.committed is False


def test_failed_login_records_actorless_redacted_event_and_keeps_generic_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = "user@example.test"
    runtime = _RateLimitRuntime()
    upstream_message = f"{email} {_PASSWORD} {_ACCESS_TOKEN} {_REFRESH_TOKEN}"
    client = _client(
        monkeypatch,
        _MockClient(_upstream_response(400, upstream_message.encode())),
        runtime=runtime,
    )

    response = client.post(
        "/auth/login",
        json={"email": email, "password": _PASSWORD},
        headers={"X-Request-ID": "login-failure-event"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Invalid email or password."
    assert upstream_message not in response.text
    event = runtime.session.add.call_args.args[0]
    assert event.event_type == "LOGIN_FAILURE"
    assert event.actor_id is None
    assert set(event.details) == {"email_identifier"}
    assert event.details["email_identifier"] == security_events.email_identifier(email)
    assert email not in str(event.details)
    assert _PASSWORD not in str(event.details)
    assert _ACCESS_TOKEN not in str(event.details)
    assert _REFRESH_TOKEN not in str(event.details)


def test_slowapi_rejection_does_not_create_login_attempt_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _RateLimitRuntime()
    mock_client = _MockClient(_upstream_response(200, b"{}"))
    client = _client(monkeypatch, mock_client, runtime=runtime)

    for _attempt in range(5):
        response = client.post(
            "/auth/login",
            json={"email": "user@example.test", "password": _PASSWORD},
        )
        assert response.status_code == 200
    events_before_rejection = runtime.session.add.call_count

    limited = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
    )

    assert limited.status_code == 429
    assert runtime.session.add.call_count == events_before_rejection
    assert mock_client.post.await_count == 5


def test_login_is_limited_to_five_requests_and_health_is_not_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = _MockClient(_upstream_response(200, b'{"access_token":"ok"}'))
    client = _client(monkeypatch, mock_client)

    for attempt in range(5):
        response = client.post(
            "/auth/login",
            json={"email": "user@example.test", "password": _PASSWORD},
            headers={"X-Request-ID": f"allowed-{attempt}"},
        )
        assert response.status_code == 200

    limited = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
        headers={"X-Request-ID": "sixth-login-attempt"},
    )

    assert limited.status_code == 429
    assert limited.json() == {
        "error": {
            "code": "RATE_LIMITED",
            "message": "Too many requests. Please try again later.",
            "request_id": "sixth-login-attempt",
        }
    }
    assert "slowapi" not in limited.text.lower()
    assert "5 per 5" not in limited.text.lower()
    assert "192.0.2.10" not in limited.text
    assert mock_client.post.await_count == 5

    health = client.get("/health")
    assert health.status_code == 200


def test_forwarded_headers_do_not_change_the_login_limiter_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = _MockClient(_upstream_response(200, b'{"access_token":"ok"}'))
    client = _client(monkeypatch, mock_client)

    for attempt in range(5):
        response = client.post(
            "/auth/login",
            json={"email": "user@example.test", "password": _PASSWORD},
            headers={"X-Forwarded-For": f"198.51.100.{attempt + 1}"},
        )
        assert response.status_code == 200

    limited = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
        headers={"X-Forwarded-For": "203.0.113.99"},
    )

    assert limited.status_code == 429
    assert mock_client.post.await_count == 5


def test_postgres_limiter_consumes_both_keys_in_sorted_order_and_same_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _RateLimitRuntime()
    mock_client = _MockClient(_upstream_response(200, b'{"access_token":"ok"}'))
    client = _client(monkeypatch, mock_client, runtime=runtime)

    response = client.post(
        "/auth/login",
        json={"email": "User@example.test", "password": _PASSWORD},
    )

    settings = Settings(
        app_env="test",
        cors_allowed_origin=_ORIGIN,
        rate_limit_key_secret="rate-limit-test-secret",
    )
    expected_keys = sorted(
        [
            ip_rate_limit_key("192.0.2.10"),
            account_rate_limit_key("User@example.test", settings=settings),
        ]
    )
    assert response.status_code == 200
    assert [call[0] for call in runtime.calls] == expected_keys
    assert all(call[1] == _NOW for call in runtime.calls)
    assert all(call[2:] == (5, timedelta(minutes=5)) for call in runtime.calls)
    assert runtime.clock.calls == 1
    assert runtime.transaction.committed is True
    assert runtime.transaction.rolled_back is False
    assert mock_client.post.await_count == 1

    stored_keys = " ".join(runtime.counters)
    for sensitive_value in (_PASSWORD, _ACCESS_TOKEN, _REFRESH_TOKEN, _OTP, "User@example.test"):
        assert sensitive_value not in stored_keys


def test_blocked_ip_commits_admitted_account_key_and_never_calls_supabase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _RateLimitRuntime()
    ip_key = ip_rate_limit_key("192.0.2.10")
    runtime.counters[ip_key] = 5
    mock_client = _MockClient(_upstream_response(200, b"{}"))
    client = _client(monkeypatch, mock_client, runtime=runtime)

    response = client.post(
        "/auth/login",
        json={"email": "blocked-ip@example.test", "password": _PASSWORD},
        headers={"X-Request-ID": "persistent-ip-block"},
    )

    assert response.status_code == 429
    assert response.json() == {
        "error": {
            "code": "RATE_LIMITED",
            "message": "Too many requests. Please try again later.",
            "request_id": "persistent-ip-block",
        }
    }
    account_key = account_rate_limit_key(
        "blocked-ip@example.test",
        settings=Settings(
            app_env="test",
            cors_allowed_origin=_ORIGIN,
            rate_limit_key_secret="rate-limit-test-secret",
        ),
    )
    assert runtime.counters[account_key] == 1
    assert runtime.counters[ip_key] == 5
    assert runtime.transaction.committed is True
    mock_client.post.assert_not_awaited()


def test_blocked_account_commits_admitted_ip_key_and_never_calls_supabase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _RateLimitRuntime()
    account_key = account_rate_limit_key(
        "blocked-account@example.test",
        settings=Settings(
            app_env="test",
            cors_allowed_origin=_ORIGIN,
            rate_limit_key_secret="rate-limit-test-secret",
        ),
    )
    runtime.counters[account_key] = 5
    mock_client = _MockClient(_upstream_response(200, b"{}"))
    client = _client(monkeypatch, mock_client, runtime=runtime)

    response = client.post(
        "/auth/login",
        json={"email": "blocked-account@example.test", "password": _PASSWORD},
    )

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "RATE_LIMITED"
    ip_key = ip_rate_limit_key("192.0.2.10")
    assert runtime.counters[account_key] == 5
    assert runtime.counters[ip_key] == 1
    assert runtime.transaction.committed is True
    mock_client.post.assert_not_awaited()


def test_rate_limit_database_failure_rolls_back_and_does_not_call_supabase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _RateLimitRuntime()
    runtime.fail_on_call = 2
    mock_client = _MockClient(_upstream_response(200, b"{}"))
    client = _client(
        monkeypatch,
        mock_client,
        runtime=runtime,
        raise_server_exceptions=False,
    )

    response = client.post(
        "/auth/login",
        json={"email": "database-error@example.test", "password": _PASSWORD},
        headers={"X-Request-ID": "rate-limit-db-error"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "INTERNAL_ERROR",
            "message": "An unexpected error occurred.",
            "request_id": "rate-limit-db-error",
        }
    }
    assert "private database failure" not in response.text
    assert runtime.transaction.rolled_back is True
    assert runtime.transaction.committed is False
    assert runtime.counters == {}
    mock_client.post.assert_not_awaited()


def test_different_accounts_from_same_ip_share_persistent_ip_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _RateLimitRuntime()
    mock_client = _MockClient(_upstream_response(200, b"{}"))
    client = _client(monkeypatch, mock_client, runtime=runtime)

    for attempt in range(5):
        limiter.reset()
        response = client.post(
            "/auth/login",
            json={"email": f"user{attempt}@example.test", "password": _PASSWORD},
        )
        assert response.status_code == 200

    limiter.reset()
    blocked = client.post(
        "/auth/login",
        json={"email": "another-account@example.test", "password": _PASSWORD},
    )

    assert blocked.status_code == 429
    assert runtime.counters[ip_rate_limit_key("192.0.2.10")] == 5
    assert mock_client.post.await_count == 5


def test_same_account_from_different_ips_shares_persistent_account_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _RateLimitRuntime()
    mock_client = _MockClient(_upstream_response(200, b"{}"))

    for attempt in range(5):
        limiter.reset()
        client = _client(
            monkeypatch,
            mock_client,
            runtime=runtime,
            peer_ip=f"198.51.100.{attempt + 1}",
        )
        response = client.post(
            "/auth/login",
            json={"email": "shared-account@example.test", "password": _PASSWORD},
        )
        assert response.status_code == 200

    limiter.reset()
    client = _client(
        monkeypatch,
        mock_client,
        runtime=runtime,
        peer_ip="198.51.100.99",
    )
    blocked = client.post(
        "/auth/login",
        json={"email": "shared-account@example.test", "password": _PASSWORD},
    )

    account_key = account_rate_limit_key(
        "shared-account@example.test",
        settings=Settings(
            app_env="test",
            cors_allowed_origin=_ORIGIN,
            rate_limit_key_secret="rate-limit-test-secret",
        ),
    )
    assert blocked.status_code == 429
    assert runtime.counters[account_key] == 5
    assert mock_client.post.await_count == 5


@pytest.mark.parametrize("upstream_message", ["Invalid login credentials", "Email not found"])
def test_authentication_failures_have_the_same_generic_401(
    monkeypatch: pytest.MonkeyPatch,
    upstream_message: str,
) -> None:
    response_body = f'{{"message":"{upstream_message}"}}'.encode()
    client = _client(monkeypatch, _MockClient(_upstream_response(400, response_body)))

    response = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
        headers={"X-Request-ID": "login-failure"},
    )

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "UNAUTHENTICATED",
            "message": "Invalid email or password.",
            "request_id": "login-failure",
        }
    }
    assert upstream_message not in response.text


@pytest.mark.parametrize(
    "payload",
    [
        {"password": _PASSWORD},
        {"email": "user@example.test"},
        {"email": "", "password": _PASSWORD},
        {"email": "user@example.test", "password": ""},
        {"email": "user@example.test", "password": _PASSWORD, "role": "ADMIN"},
        {"email": "user@example.test", "password": _PASSWORD, "is_deleted": True},
        {"email": 123, "password": _PASSWORD},
    ],
)
def test_missing_or_malformed_fields_return_422(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
) -> None:
    mock_client = _MockClient(_upstream_response(200, b"{}"))
    client = _client(monkeypatch, mock_client)

    response = client.post("/auth/login", json=payload)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert response.json()["error"]["message"] == "Request validation failed."
    mock_client.post.assert_not_awaited()


def test_malformed_email_returns_422_without_calling_supabase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = _MockClient(_upstream_response(200, b"{}"))
    client = _client(monkeypatch, mock_client)

    response = client.post(
        "/auth/login",
        json={"email": "not-an-email", "password": _PASSWORD},
        headers={"X-Request-ID": "malformed-login-email"},
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Request validation failed.",
            "request_id": "malformed-login-email",
        }
    }
    mock_client.post.assert_not_awaited()


def test_upstream_network_failure_returns_safe_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(
        monkeypatch,
        _MockClient(error=httpx.ConnectError("upstream body with sensitive details")),
    )

    response = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
    )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "HTTP_502"
    assert response.json()["error"]["message"] == "An unexpected error occurred."
    assert "sensitive details" not in response.text
    assert _PASSWORD not in response.text


def test_upstream_server_error_body_is_not_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(
        monkeypatch,
        _MockClient(_upstream_response(503, b"upstream secret response body")),
    )

    response = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
    )

    assert response.status_code == 502
    assert "upstream secret response body" not in response.text


def test_login_error_uses_request_id_and_existing_error_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(monkeypatch, _MockClient(_upstream_response(401, b"{}")))

    response = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
        headers={"X-Request-ID": "known-login-request"},
    )

    assert response.headers["x-request-id"] == "known-login-request"
    assert response.json()["error"]["request_id"] == "known-login-request"


def test_post_cors_preflight_allows_only_configured_origin(client: TestClient) -> None:
    allowed = client.options(
        "/auth/login",
        headers={
            "Origin": _ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == _ORIGIN
    assert "POST" in allowed.headers["access-control-allow-methods"]

    disallowed = client.options(
        "/auth/login",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert "access-control-allow-origin" not in disallowed.headers


def test_password_and_token_values_are_not_logged(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = (
        b'{"access_token":"test-access-token-never-log",'
        b'"refresh_token":"test-refresh-token-never-log"}'
    )
    client = _client(monkeypatch, _MockClient(_upstream_response(200, body)))

    response = client.post(
        "/auth/login",
        json={"email": "user@example.test", "password": _PASSWORD},
    )

    assert response.status_code == 200
    assert _PASSWORD not in caplog.text
    assert _ACCESS_TOKEN not in caplog.text
    assert _REFRESH_TOKEN not in caplog.text
