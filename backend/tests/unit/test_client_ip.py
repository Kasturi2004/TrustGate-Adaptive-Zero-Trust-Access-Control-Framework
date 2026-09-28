"""Tests for direct peer client IP resolution."""

import pytest
from app.core.client_ip import ClientIPResolutionError, resolve_client_ip
from starlette.requests import Request


def _request(
    client: tuple[str, int] | None,
    *,
    forwarded_for: str | None = None,
) -> Request:
    headers = [] if forwarded_for is None else [(b"x-forwarded-for", forwarded_for.encode())]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "client": client,
        "server": ("testserver", 8000),
    }
    return Request(scope)


def test_resolver_returns_normalized_direct_client_host() -> None:
    request = _request(("2001:0DB8::1", 12345))

    assert resolve_client_ip(request) == "2001:db8::1"


def test_untrusted_forwarded_for_header_is_ignored() -> None:
    request = _request(("192.0.2.10", 12345), forwarded_for="198.51.100.50")

    assert resolve_client_ip(request) == "192.0.2.10"


def test_missing_direct_client_fails_safely_even_if_forwarded_header_exists() -> None:
    request = _request(None, forwarded_for="198.51.100.50")

    with pytest.raises(ClientIPResolutionError):
        resolve_client_ip(request)
