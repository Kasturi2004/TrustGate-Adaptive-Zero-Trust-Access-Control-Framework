"""Resolve an approximate IP region and compare it with historical regions.

Location is a coarse country/subdivision estimate, not a precise physical
location. Callers must provide the server-resolved client IP and historical
``access_requests.resolved_region`` values; this module does not accept
frontend location data or persist the result.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, Protocol

IPAddress = IPv4Address | IPv6Address
LocationCategory = Literal["EXPECTED", "NEW", "UNAVAILABLE"]
_COUNTRY_CODE = re.compile(r"^[A-Z]{2}$")
_SUBDIVISION_CODE = re.compile(r"^[A-Z0-9]{1,3}$")


@dataclass(frozen=True, slots=True)
class GeoRegion:
    """Coarse ISO region from an injected GeoIP resolver."""

    country_iso: str
    subdivision_iso: str


class GeoResolver(Protocol):
    """Local/injected resolver interface; no external request is performed here."""

    def resolve(self, address: IPAddress) -> GeoRegion | None:
        """Resolve a public address to its country and subdivision ISO codes."""


class UnavailableGeoResolver:
    """Safe resolver used until the deployment configures its server-side GeoIP source."""

    def resolve(self, address: IPAddress) -> GeoRegion | None:
        del address
        return None


_DEFAULT_GEO_RESOLVER = UnavailableGeoResolver()


def get_geo_resolver() -> GeoResolver:
    """Provide an overrideable server-side geolocation resolver dependency."""
    return _DEFAULT_GEO_RESOLVER


@dataclass(frozen=True, slots=True)
class LocationResult:
    """Normalized, coarse location signal without raw resolver data."""

    category: LocationCategory
    resolved_region: str | None


UNAVAILABLE_LOCATION = LocationResult(category="UNAVAILABLE", resolved_region=None)


def normalize_region_label(region: GeoRegion | None) -> str | None:
    """Return the stable ``COUNTRY-SUBDIVISION`` representation or None."""
    if region is None:
        return None

    country = region.country_iso.strip().upper()
    subdivision = region.subdivision_iso.strip().upper()
    if not _COUNTRY_CODE.fullmatch(country) or not _SUBDIVISION_CODE.fullmatch(subdivision):
        return None
    return f"{country}-{subdivision}"


def _normalize_historical_region(region: str) -> str | None:
    parts = region.strip().upper().split("-")
    if len(parts) != 2:
        return None
    country, subdivision = parts
    if not _COUNTRY_CODE.fullmatch(country) or not _SUBDIVISION_CODE.fullmatch(subdivision):
        return None
    return f"{country}-{subdivision}"


def _public_ip(value: str | IPAddress | None) -> IPAddress | None:
    if value is None:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not address.is_global or address.is_multicast or address.is_unspecified:
        return None
    return address


def evaluate_location_normality(
    *,
    server_resolved_ip: str | IPAddress | None,
    historical_resolved_regions: Iterable[str],
    geo_resolver: GeoResolver,
) -> LocationResult:
    """Classify an IP-derived region against a user's historical request regions.

    The history iterable must be sourced server-side from
    ``access_requests.resolved_region``. Invalid/private addresses never reach
    the resolver, and resolver exceptions are converted to UNAVAILABLE.
    """
    address = _public_ip(server_resolved_ip)
    if address is None:
        return UNAVAILABLE_LOCATION

    try:
        region = normalize_region_label(geo_resolver.resolve(address))
    except Exception:
        return UNAVAILABLE_LOCATION
    if region is None:
        return UNAVAILABLE_LOCATION

    observed_regions = {
        normalized
        for historical in historical_resolved_regions
        if (normalized := _normalize_historical_region(historical)) is not None
    }
    category: Literal["EXPECTED", "NEW"] = "EXPECTED" if region in observed_regions else "NEW"
    return LocationResult(category=category, resolved_region=region)
