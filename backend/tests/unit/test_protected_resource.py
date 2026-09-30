"""Tests for the immutable MVP protected-resource registry."""

from dataclasses import FrozenInstanceError
from typing import cast

import pytest
from app.services.protected_resource import (
    PROTECTED_RESOURCES,
    ProtectedResource,
    ProtectedResourceNotFoundError,
    get_protected_resource,
)


def test_registry_contains_only_ops_dashboard() -> None:
    assert tuple(PROTECTED_RESOURCES) == ("ops-dashboard",)


def test_ops_dashboard_has_server_owned_metadata() -> None:
    resource = get_protected_resource("ops-dashboard")

    assert resource.resource_id == "ops-dashboard"
    assert resource.name == "Operations Dashboard"
    assert resource.description == "The TrustGate operations dashboard protected resource."


def test_lookup_returns_the_registered_resource() -> None:
    assert get_protected_resource("ops-dashboard") is PROTECTED_RESOURCES["ops-dashboard"]


def test_unknown_resource_is_rejected_without_echoing_client_input() -> None:
    with pytest.raises(ProtectedResourceNotFoundError) as error:
        get_protected_resource("client-controlled-resource")

    assert str(error.value) == "Protected resource is not registered."
    assert "client-controlled-resource" not in str(error.value)


def test_registry_and_returned_resource_cannot_be_mutated() -> None:
    resource = get_protected_resource("ops-dashboard")

    with pytest.raises(TypeError):
        cast(dict[str, ProtectedResource], PROTECTED_RESOURCES)["new-resource"] = resource

    with pytest.raises(FrozenInstanceError):
        resource.name = "Changed by caller"  # type: ignore[misc]
