"""Tests for direct peer and explicitly trusted proxy IP resolution."""

import pytest
from app.core.client_ip import ClientIPResolutionError, resolve_client_ip
from app.core.config import Settings
from starlette.requests import Request


def _request(
    client: tuple[str, int] | None,
    *,
    forwarded_for: str | None = None,
    forwarded_values: list[str] | None = None,
) -> Request:
    headers = [] if forwarded_for is None else [(b"x-forwarded-for", forwarded_for.encode())]
    if forwarded_values is not None:
        headers = [(b"x-forwarded-for", value.encode()) for value in forwarded_values]
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


def _settings(*, hops: int | None = None, proxies: str | None = None) -> Settings:
    values: dict[str, object] = {
        "app_env": "test",
        "cors_allowed_origin": "http://localhost:5173",
        "trusted_proxies": proxies,
    }
    if hops is not None:
        values["trusted_proxy_hops"] = hops
    return Settings.model_validate(values)


def test_resolver_returns_normalized_direct_client_host() -> None:
    request = _request(("2001:0DB8::1", 12345))

    assert resolve_client_ip(request) == "2001:db8::1"


def test_untrusted_forwarded_for_header_is_ignored() -> None:
    request = _request(("192.0.2.10", 12345), forwarded_for="198.51.100.50")

    assert resolve_client_ip(request, settings=_settings(hops=1, proxies="10.0.0.0/8")) == (
        "192.0.2.10"
    )


def test_default_configuration_is_deny_by_default() -> None:
    settings = _settings()
    request = _request(("192.0.2.10", 12345), forwarded_for="198.51.100.50")

    assert settings.trusted_proxy_hops == 0
    assert settings.trusted_proxies is None
    assert resolve_client_ip(request, settings=settings) == "192.0.2.10"


def test_trusted_proxy_uses_forwarded_client_ip() -> None:
    request = _request(("10.0.0.12", 12345), forwarded_for="198.51.100.50")

    assert (
        resolve_client_ip(request, settings=_settings(hops=1, proxies="10.0.0.0/24"))
        == "198.51.100.50"
    )


def test_multiple_forwarded_entries_select_leftmost_client_ip() -> None:
    request = _request(
        ("10.0.0.12", 12345),
        forwarded_for="198.51.100.99, 203.0.113.42, 10.0.0.8",
    )

    assert (
        resolve_client_ip(request, settings=_settings(hops=2, proxies="10.0.0.0/24"))
        == "198.51.100.99"
    )


def test_trusted_proxy_missing_forwarded_header_falls_back_to_peer() -> None:
    request = _request(("10.0.0.12", 12345))

    assert (
        resolve_client_ip(request, settings=_settings(hops=1, proxies="10.0.0.0/24")) == "10.0.0.12"
    )


@pytest.mark.parametrize("forwarded_for", ["not-an-ip", "198.51.100.4, not-an-ip"])
def test_trusted_proxy_malformed_forwarded_ip_falls_back_safely(
    forwarded_for: str,
) -> None:
    request = _request(("10.0.0.12", 12345), forwarded_for=forwarded_for)

    assert (
        resolve_client_ip(request, settings=_settings(hops=1, proxies="10.0.0.0/24")) == "10.0.0.12"
    )


def test_trusted_proxy_normalizes_forwarded_ipv6() -> None:
    request = _request(("10.0.0.12", 12345), forwarded_for="2001:0DB8::1")

    assert (
        resolve_client_ip(request, settings=_settings(hops=1, proxies="10.0.0.0/24"))
        == "2001:db8::1"
    )


def test_too_few_forwarded_entries_falls_back_to_peer() -> None:
    request = _request(("10.0.0.12", 12345), forwarded_for="198.51.100.50")

    assert (
        resolve_client_ip(request, settings=_settings(hops=2, proxies="10.0.0.0/24")) == "10.0.0.12"
    )


def test_duplicate_forwarded_headers_fall_back_to_peer() -> None:
    request = _request(("10.0.0.12", 12345), forwarded_values=["198.51.100.50", "203.0.113.20"])

    assert (
        resolve_client_ip(request, settings=_settings(hops=1, proxies="10.0.0.0/24")) == "10.0.0.12"
    )


def test_missing_direct_client_fails_safely_even_if_forwarded_header_exists() -> None:
    request = _request(None, forwarded_for="198.51.100.50")

    with pytest.raises(ClientIPResolutionError):
        resolve_client_ip(request)
