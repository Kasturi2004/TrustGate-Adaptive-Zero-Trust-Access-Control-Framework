"""Tests for the Phase 6D coarse IP region signal."""

import inspect
from ipaddress import IPv4Address, IPv6Address

import pytest
from app.services.context.location import (
    GeoRegion,
    LocationResult,
    evaluate_location_normality,
    normalize_region_label,
)


class StubGeoResolver:
    def __init__(self, result: GeoRegion | None = None, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[IPv4Address | IPv6Address] = []

    def resolve(self, address: IPv4Address | IPv6Address) -> GeoRegion | None:
        self.calls.append(address)
        if self.error is not None:
            raise self.error
        return self.result


def test_region_matching_history_is_expected() -> None:
    resolver = StubGeoResolver(GeoRegion("us", "ca"))

    result = evaluate_location_normality(
        server_resolved_ip="8.8.8.8",
        historical_resolved_regions=["US-CA"],
        geo_resolver=resolver,
    )

    assert result == LocationResult(category="EXPECTED", resolved_region="US-CA")
    assert resolver.calls == [IPv4Address("8.8.8.8")]


def test_successfully_resolved_unseen_region_is_new() -> None:
    resolver = StubGeoResolver(GeoRegion("gb", "eng"))

    result = evaluate_location_normality(
        server_resolved_ip="8.8.4.4",
        historical_resolved_regions=["US-CA"],
        geo_resolver=resolver,
    )

    assert result == LocationResult(category="NEW", resolved_region="GB-ENG")


def test_unresolvable_public_ip_is_unavailable() -> None:
    resolver = StubGeoResolver()

    result = evaluate_location_normality(
        server_resolved_ip="8.8.8.8",
        historical_resolved_regions=[],
        geo_resolver=resolver,
    )

    assert result == LocationResult(category="UNAVAILABLE", resolved_region=None)
    assert resolver.calls == [IPv4Address("8.8.8.8")]


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "192.168.1.1",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "2001:db8::1",
    ],
)
def test_non_public_ip_is_unavailable_and_never_sent_to_resolver(address: str) -> None:
    resolver = StubGeoResolver(GeoRegion("us", "ca"))

    result = evaluate_location_normality(
        server_resolved_ip=address,
        historical_resolved_regions=[],
        geo_resolver=resolver,
    )

    assert result.category == "UNAVAILABLE"
    assert result.resolved_region is None
    assert resolver.calls == []


def test_resolver_exception_never_propagates() -> None:
    resolver = StubGeoResolver(error=RuntimeError("private resolver detail"))

    result = evaluate_location_normality(
        server_resolved_ip="8.8.8.8",
        historical_resolved_regions=[],
        geo_resolver=resolver,
    )

    assert result == LocationResult(category="UNAVAILABLE", resolved_region=None)


@pytest.mark.parametrize("address", [None, "not-an-ip", "", "999.1.1.1"])
def test_missing_or_invalid_ip_is_unavailable_without_lookup(address: str | None) -> None:
    resolver = StubGeoResolver(GeoRegion("us", "ca"))

    result = evaluate_location_normality(
        server_resolved_ip=address,
        historical_resolved_regions=[],
        geo_resolver=resolver,
    )

    assert result == LocationResult(category="UNAVAILABLE", resolved_region=None)
    assert resolver.calls == []


def test_historical_region_comparison_is_case_and_whitespace_normalized() -> None:
    resolver = StubGeoResolver(GeoRegion(" us ", " ca "))

    result = evaluate_location_normality(
        server_resolved_ip="8.8.8.8",
        historical_resolved_regions=[" us-ca "],
        geo_resolver=resolver,
    )

    assert result.category == "EXPECTED"
    assert result.resolved_region == "US-CA"


@pytest.mark.parametrize(
    ("region", "expected"),
    [
        (GeoRegion("us", "ca"), "US-CA"),
        (GeoRegion("GB", "ENG"), "GB-ENG"),
        (GeoRegion("USA", "CA"), None),
        (GeoRegion("US", "California"), None),
        (None, None),
    ],
)
def test_resolver_region_is_normalized_or_rejected(
    region: GeoRegion | None,
    expected: str | None,
) -> None:
    assert normalize_region_label(region) == expected


def test_location_evaluator_accepts_no_client_region_parameter() -> None:
    assert set(inspect.signature(evaluate_location_normality).parameters) == {
        "server_resolved_ip",
        "historical_resolved_regions",
        "geo_resolver",
    }


def test_region_values_are_not_logged_or_returned_as_raw_resolver_data(
    caplog: pytest.LogCaptureFixture,
) -> None:
    resolver = StubGeoResolver(GeoRegion("us", "ca"))

    result = evaluate_location_normality(
        server_resolved_ip="8.8.8.8",
        historical_resolved_regions=[],
        geo_resolver=resolver,
    )

    assert result.resolved_region == "US-CA"
    assert "GeoRegion" not in repr(result)
    assert caplog.text == ""
