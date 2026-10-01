"""Prototype-only browser-observable device-health signal evaluator.

This signal describes only the request's transport security and parsed
browser/OS family and version. It cannot detect antivirus, disk encryption,
patch status, EDR, MDM, device compromise, hardware attestation, or general
endpoint security posture.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Literal, TypedDict

import yaml  # type: ignore[import-untyped]
from starlette.requests import Request
from ua_parser import parse

from app.core.config import Settings, get_settings
from app.services.context.client_ip import is_trusted_proxy_peer

HealthCategory = Literal["HEALTHY", "PARTIAL", "UNHEALTHY"]
_DEFAULT_RULES_PATH = Path(__file__).resolve().parents[3] / "config" / "supported_browsers.yaml"
_MAX_USER_AGENT_LENGTH = 1024
_OS_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("windows", ("windows nt",)),
    ("android", ("android",)),
    ("ios", ("iphone", "ipad", "ipod")),
    ("macos", ("macintosh; intel mac os",)),
    ("linux", ("x11; linux", "linux x86", "linux aarch64")),
)
_VERSION_PART = re.compile(r"^[0-9]+$")
_WINDOWS_NT_VERSION = re.compile(r"\bWindows NT ([0-9]+(?:\.[0-9]+)?)\b", re.IGNORECASE)
_WINDOWS_NT_POLICY_FAMILIES = {
    "5.1": ("Windows XP", "XP"),
    "6.0": ("Windows Vista", "Vista"),
    "6.1": ("Windows 7", "7"),
    "6.2": ("Windows 8", "8"),
    "6.3": ("Windows 8.1", "8.1"),
    "6.4": ("Windows 10", "6.4"),
    "10.0": ("Windows 10", "10"),
    "11.0": ("Windows 11", "11"),
}


class SupportedBrowserConfigurationError(RuntimeError):
    """Raised when the server-owned browser support configuration is invalid."""


@dataclass(frozen=True, slots=True)
class BrowserSupportRules:
    """Immutable server-owned family/version allowlists and explicit EOL families."""

    browsers: Mapping[str, str]
    operating_systems: Mapping[str, str]
    eol_browsers: frozenset[str]
    eol_operating_systems: frozenset[str]


@dataclass(frozen=True, slots=True)
class DeviceHealthResult:
    """Normalized signal with non-sensitive UA family/version metadata only."""

    category: HealthCategory
    browser_family: str | None = None
    browser_version: str | None = None
    os_family: str | None = None
    os_version: str | None = None


class _HealthMetadata(TypedDict):
    browser_family: str | None
    browser_version: str | None
    os_family: str | None
    os_version: str | None


def _string_version(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    parts = value.split(".")
    if any(not _VERSION_PART.fullmatch(part) for part in parts):
        return None
    return ".".join(parts[:2])


def _parsed_version(major: str | None, minor: str | None) -> str | None:
    """Normalize ua-parser version components without retaining patch details."""
    if major is None:
        return None
    if major.casefold() in {"xp", "vista"}:
        return major.upper() if major.casefold() == "xp" else "Vista"
    normalized_major = _string_version(major)
    if normalized_major is None:
        return None
    if minor is None:
        return normalized_major
    normalized_minor = _string_version(minor)
    if normalized_minor is None:
        return None
    return f"{normalized_major}.{normalized_minor}"


def _normalize_browser_family(family: str | None) -> str | None:
    """Map ua-parser browser aliases to the vocabulary used by policy YAML."""
    if family is None:
        return None
    if family.casefold() in {"ie", "internet explorer"}:
        return "Internet Explorer"
    return family


def _normalize_os(
    family: str | None,
    major: str | None,
    minor: str | None,
    *,
    windows_nt_version: str | None = None,
) -> tuple[str | None, str | None]:
    """Normalize ua-parser's generic Windows family into explicit policy names."""
    if family is None:
        return None, None
    version = _parsed_version(major, minor)
    if family.casefold() != "windows":
        return family, version

    if windows_nt_version is not None:
        mapped = _WINDOWS_NT_POLICY_FAMILIES.get(windows_nt_version)
        if mapped is not None:
            return mapped
        return "Windows", windows_nt_version

    normalized_major = version.casefold() if version is not None else None
    windows_labels = {
        "xp": "Windows XP",
        "vista": "Windows Vista",
        "7": "Windows 7",
        "8": "Windows 8",
        "8.1": "Windows 8.1",
        "10": "Windows 10",
        "11": "Windows 11",
    }
    normalized_version = version
    policy_family = windows_labels.get(normalized_version.casefold() if normalized_version else "")
    if policy_family is None and normalized_major in {"xp", "vista"}:
        policy_family = windows_labels[normalized_major]
    return policy_family or "Windows", version


def _windows_nt_version(user_agent: str) -> str | None:
    match = _WINDOWS_NT_VERSION.search(user_agent)
    return match.group(1) if match is not None else None


def _version_tuple(value: str) -> tuple[int, ...] | None:
    parts = value.split(".")
    if not parts or any(not _VERSION_PART.fullmatch(part) for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _version_at_least(actual: str, minimum: str) -> bool:
    actual_parts = _version_tuple(actual)
    minimum_parts = _version_tuple(minimum)
    if actual_parts is None or minimum_parts is None:
        return False
    width = max(len(actual_parts), len(minimum_parts))
    padded_actual = actual_parts + (0,) * (width - len(actual_parts))
    padded_minimum = minimum_parts + (0,) * (width - len(minimum_parts))
    return padded_actual >= padded_minimum


def _string_mapping(value: object) -> Mapping[str, str]:
    if not isinstance(value, dict):
        raise SupportedBrowserConfigurationError("Supported browser configuration is invalid")
    normalized: dict[str, str] = {}
    for family, minimum in value.items():
        if not isinstance(family, str) or not isinstance(minimum, str):
            raise SupportedBrowserConfigurationError("Supported browser configuration is invalid")
        if _version_tuple(minimum) is None:
            raise SupportedBrowserConfigurationError("Supported browser configuration is invalid")
        normalized[family.casefold()] = minimum
    return MappingProxyType(normalized)


def _string_set(value: object) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SupportedBrowserConfigurationError("Supported browser configuration is invalid")
    return frozenset(item.casefold() for item in value)


@lru_cache(maxsize=1)
def load_supported_browser_rules() -> BrowserSupportRules:
    """Load validated, immutable server-owned rules from the expected YAML file."""
    try:
        raw: object = yaml.safe_load(_DEFAULT_RULES_PATH.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        raise SupportedBrowserConfigurationError(
            "Supported browser configuration is unavailable"
        ) from None

    if not isinstance(raw, dict):
        raise SupportedBrowserConfigurationError("Supported browser configuration is invalid")
    supported = raw.get("supported")
    unsupported = raw.get("unsupported")
    if not isinstance(supported, dict) or not isinstance(unsupported, dict):
        raise SupportedBrowserConfigurationError("Supported browser configuration is invalid")

    return BrowserSupportRules(
        browsers=_string_mapping(supported.get("browsers")),
        operating_systems=_string_mapping(supported.get("operating_systems")),
        eol_browsers=_string_set(unsupported.get("browsers")),
        eol_operating_systems=_string_set(unsupported.get("operating_systems")),
    )


def _malformed_user_agent(user_agent: str) -> bool:
    return (
        len(user_agent) > _MAX_USER_AGENT_LENGTH
        or not user_agent.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in user_agent)
    )


def _has_inconsistent_os_markers(user_agent: str) -> bool:
    normalized = user_agent.casefold()
    matches = sum(any(marker in normalized for marker in markers) for _, markers in _OS_MARKERS)
    return matches > 1


def evaluate_device_health(
    *,
    connection_secure: bool | None,
    user_agent: str | None,
    rules: BrowserSupportRules | None = None,
) -> DeviceHealthResult:
    """Evaluate only transport and browser/OS signals; do not infer endpoint posture."""
    if connection_secure is False:
        return DeviceHealthResult("UNHEALTHY")
    if user_agent is None:
        return DeviceHealthResult("PARTIAL")
    if _malformed_user_agent(user_agent) or _has_inconsistent_os_markers(user_agent):
        return DeviceHealthResult("UNHEALTHY")

    try:
        parsed = parse(user_agent)
    except (TypeError, ValueError, UnicodeError):
        return DeviceHealthResult("UNHEALTHY")
    parsed_browser = parsed.user_agent
    parsed_os = parsed.os
    browser_family = _normalize_browser_family(
        parsed_browser.family if parsed_browser is not None else None
    )
    browser_version = (
        _string_version(parsed_browser.major)
        if parsed_browser is not None and parsed_browser.major is not None
        else None
    )
    os_family, os_version = _normalize_os(
        parsed_os.family if parsed_os is not None else None,
        parsed_os.major if parsed_os is not None else None,
        parsed_os.minor if parsed_os is not None else None,
        windows_nt_version=_windows_nt_version(user_agent),
    )

    metadata: _HealthMetadata = {
        "browser_family": browser_family,
        "browser_version": browser_version,
        "os_family": os_family,
        "os_version": os_version,
    }
    policy = load_supported_browser_rules() if rules is None else rules
    browser_key = browser_family.casefold() if browser_family else None
    os_key = os_family.casefold() if os_family else None

    if browser_key in policy.eol_browsers or os_key in policy.eol_operating_systems:
        return DeviceHealthResult("UNHEALTHY", **metadata)
    if connection_secure is None or browser_key is None or os_key is None:
        return DeviceHealthResult("PARTIAL", **metadata)
    if browser_version is None or os_version is None:
        return DeviceHealthResult("PARTIAL", **metadata)

    browser_minimum = policy.browsers.get(browser_key)
    os_minimum = policy.operating_systems.get(os_key)
    if browser_minimum is None or os_minimum is None:
        return DeviceHealthResult("PARTIAL", **metadata)
    if not _version_at_least(browser_version, browser_minimum) or not _version_at_least(
        os_version, os_minimum
    ):
        return DeviceHealthResult("PARTIAL", **metadata)
    return DeviceHealthResult("HEALTHY", **metadata)


def is_connection_secure(request: Request, *, settings: Settings | None = None) -> bool:
    """Resolve HTTPS from ASGI scheme, a trusted proxy, or explicit local-dev setting.

    X-Forwarded-Proto is honored only from a configured trusted proxy. Local
    HTTP may be treated as secure only with TREAT_LOCALHOST_AS_SECURE=true in
    the local environment; production never honors that development override.
    """
    configuration = settings if settings is not None else get_settings()
    if request.url.scheme.casefold() == "https":
        return True

    client = request.client
    if (
        configuration.app_env == "local"
        and configuration.treat_localhost_as_secure is True
        and client is not None
    ):
        try:
            if ipaddress.ip_address(client.host).is_loopback:
                return True
        except ValueError:
            pass

    if not is_trusted_proxy_peer(request, settings=configuration):
        return False

    forwarded_protocols = request.headers.getlist("x-forwarded-proto")
    return len(forwarded_protocols) == 1 and forwarded_protocols[0].strip().casefold() == "https"
