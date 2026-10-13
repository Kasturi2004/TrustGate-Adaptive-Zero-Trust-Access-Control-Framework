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


def test_registry_contains_ops_dashboard_and_acme_documents() -> None:
    assert tuple(PROTECTED_RESOURCES) == (
        "ops-dashboard",
        "employee-handbook",
        "company-policies",
        "quarterly-strategy-plan",
        "confidential-financial-report",
    )


def test_ops_dashboard_has_server_owned_metadata() -> None:
    resource = get_protected_resource("ops-dashboard")

    assert resource.resource_id == "ops-dashboard"
    assert resource.name == "Operations Dashboard"
    assert resource.description == "The TrustGate operations dashboard protected resource."
    assert resource.employee_access_allowed is True


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


def test_document_entitlements_are_server_owned_and_fail_closed() -> None:
    handbook = get_protected_resource("employee-handbook")
    policies = get_protected_resource("company-policies")
    strategy = get_protected_resource("quarterly-strategy-plan")
    financial = get_protected_resource("confidential-financial-report")

    assert handbook.employee_access_allowed is True
    assert handbook.content is not None and "FICTIONAL SAMPLE" in handbook.content
    assert policies.employee_access_allowed is True
    assert policies.content is not None and "FICTIONAL SAMPLE" in policies.content
    assert strategy.employee_access_allowed is False
    assert strategy.content is None
    assert financial.employee_access_allowed is False
    assert financial.content is None
