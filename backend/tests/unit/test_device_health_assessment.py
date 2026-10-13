"""Deterministic tests for verified endpoint posture evidence assessment."""

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from app.core.config import Settings
from app.services.device_health_assessment import (
    CHECK_WEIGHTS,
    DeviceHealthAssessment,
    EvidenceObservation,
    UnavailableEvidenceProvider,
    assess_device_health,
)

_NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)
_BINDING = "opaque-device-binding"


class FixedProvider:
    def __init__(self, observations: Sequence[EvidenceObservation]) -> None:
        self.observations = observations

    async def collect(
        self, *, device_binding: str | None, now: datetime
    ) -> Sequence[EvidenceObservation]:
        del device_binding, now
        return self.observations


class AcceptTestEvidence:
    def verify(self, observation: EvidenceObservation) -> bool:
        return observation.proof == b"valid-test-proof"


class RejectTestEvidence:
    def verify(self, observation: EvidenceObservation) -> bool:
        del observation
        return False


def _settings(**overrides: Any) -> Settings:
    values: dict[str, object] = {
        "app_env": "test",
        "cors_allowed_origin": "http://localhost:5173",
    }
    values.update(overrides)
    return Settings.model_validate(values)


def _observations(
    *,
    states: dict[str, str] | None = None,
    observed_at: datetime = _NOW,
    binding: str = _BINDING,
) -> tuple[EvidenceObservation, ...]:
    values = states or {}
    return tuple(
        EvidenceObservation(
            check=check,
            state=values.get(check, "PASS"),  # type: ignore[arg-type]
            source="test-provider",
            observed_at=observed_at,
            device_binding=binding,
            proof=b"valid-test-proof",
        )
        for check in CHECK_WEIGHTS
    )


def _assess(
    observations: Sequence[EvidenceObservation] | None = None,
    *,
    settings: Settings | None = None,
    verifier: Any = None,
    provider: Any = None,
    binding: str | None = _BINDING,
) -> DeviceHealthAssessment:
    return asyncio.run(
        assess_device_health(
            device_binding=binding,
            now=_NOW,
            settings=settings or _settings(),
            provider=(
                provider
                if provider is not None
                else UnavailableEvidenceProvider()
                if observations is None
                else FixedProvider(observations)
            ),
            verifier=verifier or AcceptTestEvidence(),
        )
    )


def test_all_valid_passing_evidence_is_healthy_with_full_score() -> None:
    result = _assess(_observations())

    assert result.classification == "HEALTHY"
    assert result.score == Decimal("100.00")
    assert result.complete is True
    assert {item.validation_status for item in result.evidence} == {"VALID"}
    assert {item.state for item in result.evidence} == {"PASS"}
    assert {item.binding_status for item in result.evidence} == {"MATCHED"}


def test_mandatory_failure_overrides_missing_evidence() -> None:
    observations = (
        EvidenceObservation(
            check="endpoint_protection",
            state="FAIL",
            source="test-provider",
            observed_at=_NOW,
            device_binding=_BINDING,
            proof=b"valid-test-proof",
        ),
    )

    result = _assess(observations)

    assert result.complete is False
    assert result.classification == "UNHEALTHY"
    assert "mandatory_check_failed" in result.reason_codes
    assert result.score == Decimal("0.00")


def test_mandatory_failure_zeroes_trust_risk_score_even_with_high_evidence_score() -> None:
    result = _assess(_observations(states={"os_patch_compliance": "FAIL"}))

    assert result.score == Decimal("75.00")
    assert result.classification == "UNHEALTHY"
    assert result.risk_score == Decimal("0.00")


@pytest.mark.parametrize(
    ("states", "expected_score", "expected_classification"),
    [
        ({"integrity_management_compliance": "FAIL"}, Decimal("85.00"), "HEALTHY"),
        (
            {
                "firewall_status": "FAIL",
                "integrity_management_compliance": "FAIL",
            },
            Decimal("70.00"),
            "PARTIAL",
        ),
    ],
)
def test_threshold_boundary_is_deterministic(
    states: dict[str, str], expected_score: Decimal, expected_classification: str
) -> None:
    result = _assess(_observations(states=states))

    assert result.score == expected_score
    assert result.classification == expected_classification


def test_missing_and_stale_evidence_earn_no_points() -> None:
    fresh = _observations(states={"os_patch_compliance": "PASS"})[0:1]
    stale = EvidenceObservation(
        check="endpoint_protection",
        state="PASS",
        source="test-provider",
        observed_at=_NOW - timedelta(days=2),
        device_binding=_BINDING,
        proof=b"valid-test-proof",
    )
    result = _assess(
        (*fresh, stale),
        settings=_settings(device_health_evidence_max_age_seconds=86400),
    )

    assert result.classification == "PARTIAL"
    assert result.score == Decimal("25.00")
    assert result.evidence[1].state == "UNKNOWN"
    assert result.evidence[1].validation_status == "STALE"
    assert result.evidence[1].reason_code == "evidence_stale"
    assert all(item.state == "UNKNOWN" for item in result.evidence[2:])


def test_invalid_authentication_and_wrong_device_are_unknown() -> None:
    observations = (
        _observations()[0],
        EvidenceObservation(
            check="endpoint_protection",
            state="PASS",
            source="test-provider",
            observed_at=_NOW,
            device_binding="different-device",
            proof=b"valid-test-proof",
        ),
    )

    rejected = _assess(observations, verifier=RejectTestEvidence())
    wrong_binding = _assess(observations[1:], verifier=AcceptTestEvidence())

    assert rejected.evidence[0].state == "UNKNOWN"
    assert rejected.evidence[0].validation_status == "INVALID"
    assert wrong_binding.evidence[1].state == "UNKNOWN"
    assert wrong_binding.evidence[1].validation_status == "WRONG_DEVICE"


def test_missing_binding_cannot_validate_evidence() -> None:
    result = _assess(_observations(), binding=None)

    assert result.classification == "PARTIAL"
    assert result.score is None
    assert all(item.state == "UNKNOWN" for item in result.evidence)
    assert all(item.reason_code == "device_binding_missing" for item in result.evidence)


def test_unavailable_provider_and_malformed_provider_fail_to_unknown() -> None:
    class RaisingProvider:
        async def collect(self, *, device_binding: str | None, now: datetime) -> object:
            del device_binding, now
            raise RuntimeError("must not escape assessment")

    class MalformedProvider:
        async def collect(self, *, device_binding: str | None, now: datetime) -> object:
            del device_binding, now
            return {"not": "evidence sequence"}

    unavailable = _assess()
    outage = _assess(provider=RaisingProvider())
    malformed = _assess(provider=MalformedProvider())

    for result in (unavailable, outage, malformed):
        assert result.classification == "PARTIAL"
        assert result.score is None
        assert all(item.state == "UNKNOWN" for item in result.evidence)
    assert all(item.reason_code == "provider_unavailable" for item in unavailable.evidence)
    assert all(item.reason_code == "provider_unavailable" for item in outage.evidence)
    assert all(item.reason_code == "malformed_provider_response" for item in malformed.evidence)
    assert all(item.validation_status == "MALFORMED" for item in malformed.evidence)


def test_malformed_records_are_not_trusted() -> None:
    result = _assess([object()])  # type: ignore[list-item]

    assert result.classification == "PARTIAL"
    assert result.score is None
    assert all(item.validation_status == "MALFORMED" for item in result.evidence)


@pytest.mark.parametrize(
    ("check", "state"),
    [([], "PASS"), ("os_patch_compliance", [])],
)
def test_malformed_runtime_fields_fail_closed_without_raising(check: object, state: object) -> None:
    malformed = EvidenceObservation(
        check=check,  # type: ignore[arg-type]
        state=state,  # type: ignore[arg-type]
        source="test-provider",
        observed_at=_NOW,
        device_binding=_BINDING,
        proof=b"valid-test-proof",
    )

    result = _assess((malformed,))

    assert result.classification == "PARTIAL"
    assert result.score is None
    assert all(item.state == "UNKNOWN" for item in result.evidence)
    if check == "os_patch_compliance":
        assert result.evidence[0].validation_status == "MALFORMED"
    else:
        assert all(item.validation_status == "MALFORMED" for item in result.evidence)


def test_score_is_deterministic_and_unknowns_are_not_renormalized() -> None:
    observations = _observations(states={"firewall_status": "FAIL"})
    first = _assess(observations)
    second = _assess(observations)

    assert first == second
    assert first.score == Decimal("85.00")


def test_configurable_weights_must_total_one_hundred() -> None:
    with pytest.raises(ValueError, match="weights must sum to 100"):
        _settings(device_health_os_patch_weight=Decimal("24"))


def test_default_provider_exposes_unverified_reason_without_fake_telemetry() -> None:
    result = _assess()

    assert result.score is None
    assert result.classification == "PARTIAL"
    assert {item.source for item in result.evidence} == {"no_configured_provider"}
    assert {item.reason_code for item in result.evidence} == {"provider_unavailable"}
    assert all(item.validation_status == "UNVERIFIED" for item in result.evidence)
    assert all(item.observed_at is None for item in result.evidence)


def test_unknown_evidence_with_malformed_timestamp_or_reason_is_sanitized() -> None:
    malformed = EvidenceObservation(
        check="disk_encryption",
        state="UNKNOWN",
        source="test-provider",
        observed_at="not-a-timestamp",  # type: ignore[arg-type]
        device_binding=_BINDING,
        reason_code="personal@example.invalid",
    )

    result = _assess((malformed,))
    disk = next(item for item in result.evidence if item.check == "disk_encryption")

    assert disk.state == "UNKNOWN"
    assert disk.validation_status == "INVALID"
    assert disk.reason_code == "observation_time_invalid"
    assert disk.observed_at is None


def test_unknown_evidence_with_valid_timestamp_is_checked_for_freshness_and_binding() -> None:
    stale_wrong_device = EvidenceObservation(
        check="disk_encryption",
        state="UNKNOWN",
        source="test-provider",
        observed_at=_NOW - timedelta(days=2),
        device_binding="another-device",
        reason_code="provider_unavailable",
    )

    result = _assess((stale_wrong_device,))
    disk = next(item for item in result.evidence if item.check == "disk_encryption")

    assert disk.state == "UNKNOWN"
    assert disk.validation_status == "WRONG_DEVICE"
    assert disk.reason_code == "device_binding_mismatch"
    assert disk.device_binding is None
