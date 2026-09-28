"""Tests for the Supabase Auth login proxy."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from app.api.routes import auth
from app.core.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient

_ORIGIN = "http://localhost:5173"
_PASSWORD = "test-password-never-log"
_ACCESS_TOKEN = "test-access-token-never-log"
_REFRESH_TOKEN = "test-refresh-token-never-log"


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


def _client(monkeypatch: pytest.MonkeyPatch, mock_client: _MockClient) -> TestClient:
    settings = Settings(
        app_env="test",
        cors_allowed_origin=_ORIGIN,
        supabase_url="https://project.example.test",
        supabase_anon_key="test-anon-key",
        supabase_service_role_key="must-not-be-used",
    )
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_: mock_client)
    return TestClient(create_app(settings))


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
