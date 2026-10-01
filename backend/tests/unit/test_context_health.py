"""Tests for the Phase 6C prototype browser-observable device-health signal."""

import inspect
from pathlib import Path

import pytest
from app.core.config import AppEnv, Settings
from app.services.context import health
from app.services.context.health import (
    BrowserSupportRules,
    DeviceHealthResult,
    _normalize_os,
    evaluate_device_health,
    is_connection_secure,
    load_supported_browser_rules,
)
from starlette.requests import Request

_SUPPORTED_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _settings(
    *,
    app_env: AppEnv = "test",
    trusted_proxies: str | None = None,
    treat_localhost_as_secure: bool | None = None,
) -> Settings:
    return Settings(
        app_env=app_env,
        cors_allowed_origin="http://localhost:5173",
        trusted_proxies=trusted_proxies,
        treat_localhost_as_secure=treat_localhost_as_secure,
    )


def _request(
    *,
    scheme: str = "http",
    client: tuple[str, int] = ("192.0.2.10", 12345),
    forwarded_proto: str | None = None,
    forwarded_proto_values: list[str] | None = None,
) -> Request:
    headers = [] if forwarded_proto is None else [(b"x-forwarded-proto", forwarded_proto.encode())]
    if forwarded_proto_values is not None:
        headers = [(b"x-forwarded-proto", value.encode()) for value in forwarded_proto_values]
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": scheme,
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": headers,
            "client": client,
            "server": ("testserver", 8000),
        }
    )


def _rules(
    *,
    browsers: dict[str, str] | None = None,
    operating_systems: dict[str, str] | None = None,
    eol_browsers: frozenset[str] = frozenset(),
    eol_operating_systems: frozenset[str] = frozenset(),
) -> BrowserSupportRules:
    return BrowserSupportRules(
        browsers={key.casefold(): value for key, value in (browsers or {"Chrome": "120"}).items()},
        operating_systems={
            key.casefold(): value
            for key, value in (operating_systems or {"Windows 10": "10"}).items()
        },
        eol_browsers=frozenset(value.casefold() for value in eol_browsers),
        eol_operating_systems=frozenset(value.casefold() for value in eol_operating_systems),
    )


def test_secure_supported_browser_and_os_are_healthy() -> None:
    result = evaluate_device_health(
        connection_secure=True,
        user_agent=_SUPPORTED_UA,
        rules=_rules(),
    )

    assert result.category == "HEALTHY"
    assert result.browser_family == "Chrome"
    assert result.browser_version == "120"
    assert result.os_family == "Windows 10"
    assert result.os_version == "10"


def test_insecure_connection_is_unhealthy_even_with_supported_user_agent() -> None:
    result = evaluate_device_health(
        connection_secure=False,
        user_agent=_SUPPORTED_UA,
        rules=_rules(),
    )

    assert result == DeviceHealthResult("UNHEALTHY")


def test_secure_unsupported_browser_is_partial() -> None:
    ua = _SUPPORTED_UA.replace("Chrome/120.0.0.0", "OPR/100.0.0.0")

    result = evaluate_device_health(
        connection_secure=True,
        user_agent=ua,
        rules=_rules(),
    )

    assert result.category == "PARTIAL"


def test_secure_unidentifiable_browser_and_os_are_partial() -> None:
    result = evaluate_device_health(
        connection_secure=True,
        user_agent="TrustGate custom client 1.0",
        rules=_rules(),
    )

    assert result.category == "PARTIAL"


def test_missing_user_agent_is_partial_for_secure_connection() -> None:
    assert evaluate_device_health(connection_secure=True, user_agent=None).category == "PARTIAL"


def test_malformed_user_agent_is_unhealthy() -> None:
    result = evaluate_device_health(
        connection_secure=True,
        user_agent="Mozilla/5.0\nChrome/120.0 Windows NT 10.0",
        rules=_rules(),
    )

    assert result.category == "UNHEALTHY"


def test_inconsistent_os_markers_are_unhealthy() -> None:
    result = evaluate_device_health(
        connection_secure=True,
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Android 14) AppleWebKit/537.36 "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        rules=_rules(),
    )

    assert result.category == "UNHEALTHY"


def test_eol_browser_is_unhealthy() -> None:
    ua = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"
    result = evaluate_device_health(
        connection_secure=True,
        user_agent=ua,
        rules=_rules(eol_browsers=frozenset({"Internet Explorer"})),
    )

    assert result.category == "UNHEALTHY"


def test_ua_parser_ie_family_normalizes_to_policy_vocabulary() -> None:
    ua = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"
    result = evaluate_device_health(
        connection_secure=True,
        user_agent=ua,
        rules=_rules(eol_browsers=frozenset({"internet explorer"})),
    )

    assert result.browser_family == "Internet Explorer"
    assert result.category == "UNHEALTHY"


def test_eol_operating_system_is_unhealthy() -> None:
    ua = _SUPPORTED_UA.replace("Windows NT 10.0", "Windows NT 6.1")
    result = evaluate_device_health(
        connection_secure=True,
        user_agent=ua,
        rules=_rules(eol_operating_systems=frozenset({"Windows 7"})),
    )

    assert result.category == "UNHEALTHY"


@pytest.mark.parametrize(
    ("windows_nt_version", "expected_family"),
    [
        ("5.1", "Windows XP"),
        ("6.0", "Windows Vista"),
        ("6.1", "Windows 7"),
        ("6.2", "Windows 8"),
        ("6.3", "Windows 8.1"),
        ("10.0", "Windows 10"),
    ],
)
def test_windows_parser_version_normalizes_to_policy_family(
    windows_nt_version: str,
    expected_family: str,
) -> None:
    ua = _SUPPORTED_UA.replace("Windows NT 10.0", f"Windows NT {windows_nt_version}")
    result = evaluate_device_health(
        connection_secure=True,
        user_agent=ua,
        rules=_rules(eol_operating_systems=frozenset({expected_family})),
    )

    assert result.os_family == expected_family
    assert result.category == "UNHEALTHY"


def test_explicit_windows_11_version_maps_separately_from_windows_10() -> None:
    family, version = _normalize_os("Windows", "11", None)

    assert (family, version) == ("Windows 11", "11")


def test_unrecognized_windows_version_is_not_assumed_to_be_windows_10() -> None:
    family, version = _normalize_os("Windows", "NT", None)

    assert (family, version) == ("Windows", None)


def test_windows_nt_64_is_not_misclassified_as_supported_windows_10() -> None:
    ua = _SUPPORTED_UA.replace("Windows NT 10.0", "Windows NT 6.4")
    result = evaluate_device_health(
        connection_secure=True,
        user_agent=ua,
        rules=_rules(operating_systems={"Windows 10": "10"}),
    )

    assert result.os_family == "Windows 10"
    assert result.os_version == "6.4"
    assert result.category == "PARTIAL"


def test_browser_version_below_supported_boundary_is_partial() -> None:
    ua = _SUPPORTED_UA.replace("Chrome/120.0.0.0", "Chrome/119.0.0.0")

    assert (
        evaluate_device_health(
            connection_secure=True,
            user_agent=ua,
            rules=_rules(),
        ).category
        == "PARTIAL"
    )


def test_browser_version_at_supported_boundary_is_healthy() -> None:
    assert (
        evaluate_device_health(
            connection_secure=True,
            user_agent=_SUPPORTED_UA,
            rules=_rules(),
        ).category
        == "HEALTHY"
    )


def test_operating_system_version_below_supported_boundary_is_partial() -> None:
    ua = _SUPPORTED_UA.replace("Windows NT 10.0", "Windows NT 6.4")

    assert (
        evaluate_device_health(
            connection_secure=True,
            user_agent=ua,
            rules=_rules(operating_systems={"Windows 10": "10"}),
        ).category
        == "PARTIAL"
    )


def test_https_asgi_scheme_is_secure() -> None:
    assert is_connection_secure(_request(scheme="https"), settings=_settings()) is True


def test_untrusted_forwarded_proto_is_ignored() -> None:
    request = _request(forwarded_proto="https")

    assert is_connection_secure(request, settings=_settings(trusted_proxies="10.0.0.0/8")) is False


def test_trusted_proxy_forwarded_https_is_secure() -> None:
    request = _request(client=("10.0.0.12", 12345), forwarded_proto="https")

    assert is_connection_secure(request, settings=_settings(trusted_proxies="10.0.0.0/24")) is True


def test_trusted_proxy_forwarded_http_is_not_secure() -> None:
    request = _request(client=("10.0.0.12", 12345), forwarded_proto="http")

    assert is_connection_secure(request, settings=_settings(trusted_proxies="10.0.0.0/24")) is False


def test_ambiguous_forwarded_proto_is_not_trusted() -> None:
    request = _request(client=("10.0.0.12", 12345), forwarded_proto_values=["https", "http"])

    assert is_connection_secure(request, settings=_settings(trusted_proxies="10.0.0.0/24")) is False


def test_localhost_secure_override_is_dev_only() -> None:
    request = _request(client=("127.0.0.1", 12345))

    assert (
        is_connection_secure(
            request,
            settings=_settings(app_env="local", treat_localhost_as_secure=True),
        )
        is True
    )
    assert (
        is_connection_secure(
            request,
            settings=_settings(app_env="production", treat_localhost_as_secure=True),
        )
        is False
    )


def test_support_rules_are_loaded_from_expected_table_driven_yaml() -> None:
    rules = load_supported_browser_rules()

    assert (Path(__file__).resolve().parents[2] / "config" / "supported_browsers.yaml").is_file()
    assert rules.browsers["chrome"] == "120"
    assert "internet explorer" in rules.eol_browsers


def test_health_cannot_be_provided_as_client_health_value() -> None:
    assert set(inspect.signature(evaluate_device_health).parameters) == {
        "connection_secure",
        "user_agent",
        "rules",
    }


def test_result_and_logs_do_not_retain_raw_user_agent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw_user_agent = _SUPPORTED_UA

    result = evaluate_device_health(
        connection_secure=True,
        user_agent=raw_user_agent,
        rules=_rules(),
    )

    assert raw_user_agent not in repr(result)
    assert raw_user_agent not in caplog.text


def test_module_documents_prototype_health_signal_limitation() -> None:
    assert "antivirus" in (health.__doc__ or "").casefold()
    assert "hardware attestation" in (health.__doc__ or "").casefold()
