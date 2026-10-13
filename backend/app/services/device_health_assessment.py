"""Evidence-based endpoint posture assessment with fail-closed validation.

No operating-system, EDR, encryption, firewall, or device-management provider is
configured in this project. The default provider therefore supplies no
observations and the production assessment remains PARTIAL/UNKNOWN. Browser
user-agent and transport data are intentionally outside this service.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Literal, Protocol

from app.core.config import Settings

CheckName = Literal[
    "os_patch_compliance",
    "endpoint_protection",
    "disk_encryption",
    "firewall_status",
    "integrity_management_compliance",
]
EvidenceState = Literal["PASS", "FAIL", "UNKNOWN"]
ValidationStatus = Literal[
    "VALID",
    "UNVERIFIED",
    "INVALID",
    "STALE",
    "WRONG_DEVICE",
    "MALFORMED",
]
HealthClassification = Literal["HEALTHY", "PARTIAL", "UNHEALTHY"]

CHECK_WEIGHTS: Mapping[CheckName, str] = {
    "os_patch_compliance": "device_health_os_patch_weight",
    "endpoint_protection": "device_health_endpoint_protection_weight",
    "disk_encryption": "device_health_disk_encryption_weight",
    "firewall_status": "device_health_firewall_weight",
    "integrity_management_compliance": "device_health_integrity_management_weight",
}
MANDATORY_CHECKS: frozenset[CheckName] = frozenset({"os_patch_compliance", "endpoint_protection"})
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")
SAFE_REASON_CODES = frozenset(
    {
        "provider_unavailable",
        "evidence_missing",
        "malformed_provider_response",
        "duplicate_evidence",
        "malformed_evidence",
        "invalid_source",
        "source_reports_unknown",
        "device_binding_missing",
        "device_binding_mismatch",
        "observation_time_invalid",
        "observation_time_in_future",
        "evidence_stale",
        "evidence_authentication_failed",
        "mandatory_check_failed",
        "evidence_incomplete",
    }
)


@dataclass(frozen=True, slots=True)
class EvidenceObservation:
    """Provider observation; its proof is only passed to the server authenticator."""

    check: CheckName
    state: EvidenceState
    source: str
    observed_at: datetime | None
    device_binding: str | None
    proof: bytes | None = None
    reason_code: str | None = None


class DeviceHealthEvidenceProvider(Protocol):
    """A server-configured integration that returns raw posture observations."""

    async def collect(
        self, *, device_binding: str | None, now: datetime
    ) -> Sequence[EvidenceObservation]:
        """Collect evidence for one opaque server-derived device binding."""


class EvidenceVerifier(Protocol):
    """Verify source authenticity independently of client/provider state labels."""

    def verify(self, observation: EvidenceObservation) -> bool:
        """Validate the provider-specific signature or trusted-source proof."""


class UnavailableEvidenceProvider:
    """Production default until a real trusted posture integration is configured."""

    async def collect(
        self, *, device_binding: str | None, now: datetime
    ) -> Sequence[EvidenceObservation]:
        del now
        return tuple(
            EvidenceObservation(
                check=check,
                state="UNKNOWN",
                source="no_configured_provider",
                observed_at=None,
                device_binding=device_binding,
                reason_code="provider_unavailable",
            )
            for check in CHECK_WEIGHTS
        )


class RejectEvidenceVerifier:
    """Default verifier; observations cannot pass without a configured verifier."""

    def verify(self, observation: EvidenceObservation) -> bool:
        del observation
        return False


def get_device_health_evidence_provider() -> DeviceHealthEvidenceProvider:
    """Return the configured provider; no provider is currently configured."""
    return UnavailableEvidenceProvider()


def get_device_health_evidence_verifier() -> EvidenceVerifier:
    """Return the configured source verifier; no source verifier is configured."""
    return RejectEvidenceVerifier()


@dataclass(frozen=True, slots=True)
class AssessedEvidence:
    check: CheckName
    state: EvidenceState
    source: str
    observed_at: datetime | None
    validation_status: ValidationStatus
    device_binding: str | None
    binding_status: Literal["MATCHED", "MISSING", "MISMATCH", "NOT_OBSERVED"]
    reason_code: str | None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "check": self.check,
            "state": self.state,
            "source": self.source,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "validation_status": self.validation_status,
            "device_binding": self.device_binding,
            "binding_status": self.binding_status,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class DeviceHealthAssessment:
    classification: HealthClassification
    score: Decimal | None
    complete: bool
    evidence: tuple[AssessedEvidence, ...]
    reason_codes: tuple[str, ...]

    @property
    def risk_score(self) -> Decimal | None:
        """Score sent to the trust engine; mandatory failure always earns zero."""
        if "mandatory_check_failed" in self.reason_codes:
            return Decimal("0.00")
        return self.score

    def as_context(self) -> dict[str, object]:
        """Serialize safe assessment metadata for existing context JSON storage."""
        return {
            "version": "posture-v1",
            "classification": self.classification,
            "score": str(self.score) if self.score is not None else None,
            "complete": self.complete,
            "reason_codes": list(self.reason_codes),
            "evidence": [item.as_dict() for item in self.evidence],
        }


def _setting_decimal(settings: Settings, field: str) -> Decimal:
    return Decimal(str(getattr(settings, field)))


def _weight_map(settings: Settings) -> dict[CheckName, Decimal]:
    return {check: _setting_decimal(settings, setting) for check, setting in CHECK_WEIGHTS.items()}


def _unknown(
    check: CheckName,
    *,
    reason_code: str,
    source: str = "unavailable",
    validation_status: ValidationStatus = "UNVERIFIED",
    device_binding: str | None = None,
    binding_status: Literal["MATCHED", "MISSING", "MISMATCH", "NOT_OBSERVED"] = "NOT_OBSERVED",
    observed_at: datetime | None = None,
) -> AssessedEvidence:
    safe_source = source if _SAFE_IDENTIFIER.fullmatch(source) else "invalid"
    return AssessedEvidence(
        check=check,
        state="UNKNOWN",
        source=safe_source,
        observed_at=observed_at,
        validation_status=validation_status,
        device_binding=device_binding,
        binding_status=binding_status,
        reason_code=reason_code,
    )


def _assess_observation(
    observation: object,
    *,
    check: CheckName,
    expected_binding: str | None,
    now: datetime,
    max_age: timedelta,
    verifier: EvidenceVerifier,
) -> AssessedEvidence:
    if not isinstance(observation, EvidenceObservation):
        return _unknown(check, reason_code="malformed_evidence", validation_status="MALFORMED")
    if (
        not isinstance(observation.check, str)
        or observation.check != check
        or not isinstance(observation.state, str)
        or observation.state not in {"PASS", "FAIL", "UNKNOWN"}
    ):
        return _unknown(
            check,
            reason_code="malformed_evidence",
            source=observation.source if isinstance(observation.source, str) else "invalid",
            validation_status="MALFORMED",
        )
    source = observation.source
    if not isinstance(source, str) or not source.strip() or len(source) > 100:
        return _unknown(check, reason_code="invalid_source", validation_status="MALFORMED")
    if _SAFE_IDENTIFIER.fullmatch(source) is None:
        return _unknown(check, reason_code="invalid_source", validation_status="MALFORMED")
    if observation.state == "UNKNOWN":
        source_reason = observation.reason_code
        if not isinstance(source_reason, str) or source_reason not in SAFE_REASON_CODES:
            source_reason = "source_reports_unknown"
        observed_at = observation.observed_at
        if observed_at is not None and (
            not isinstance(observed_at, datetime)
            or observed_at.tzinfo is None
            or observed_at.utcoffset() is None
        ):
            return _unknown(
                check,
                reason_code="observation_time_invalid",
                source=source,
                validation_status="INVALID",
            )
        if observed_at is not None and expected_binding is None:
            return _unknown(
                check,
                reason_code="device_binding_missing",
                source=source,
                validation_status="UNVERIFIED",
                device_binding=observation.device_binding,
                binding_status="MISSING",
                observed_at=observed_at,
            )
        if observed_at is None:
            binding_status: Literal["MATCHED", "MISSING", "MISMATCH", "NOT_OBSERVED"] = (
                "NOT_OBSERVED"
            )
            recorded_binding = None
        elif not observation.device_binding:
            binding_status = "MISSING"
            recorded_binding = None
        elif observation.device_binding != expected_binding:
            binding_status = "MISMATCH"
            recorded_binding = None
        else:
            binding_status = "MATCHED"
            recorded_binding = observation.device_binding
        if observed_at is not None and binding_status == "MISMATCH":
            return _unknown(
                check,
                reason_code="device_binding_mismatch",
                source=source,
                validation_status="WRONG_DEVICE",
                binding_status="MISMATCH",
                observed_at=observed_at,
            )
        if observed_at is not None:
            age = now - observed_at.astimezone(UTC)
            if age < timedelta(0):
                return _unknown(
                    check,
                    reason_code="observation_time_in_future",
                    source=source,
                    validation_status="INVALID",
                    device_binding=recorded_binding,
                    binding_status=binding_status,
                    observed_at=observed_at,
                )
            if age > max_age:
                return _unknown(
                    check,
                    reason_code="evidence_stale",
                    source=source,
                    validation_status="STALE",
                    device_binding=recorded_binding,
                    binding_status=binding_status,
                    observed_at=observed_at,
                )
        return _unknown(
            check,
            reason_code=source_reason,
            source=source,
            device_binding=recorded_binding,
            binding_status=binding_status,
            observed_at=observation.observed_at,
        )
    if expected_binding is None or not observation.device_binding:
        return _unknown(
            check,
            reason_code="device_binding_missing",
            source=source,
            validation_status="UNVERIFIED",
            device_binding=observation.device_binding,
            binding_status="MISSING",
            observed_at=observation.observed_at,
        )
    if observation.device_binding != expected_binding:
        return _unknown(
            check,
            reason_code="device_binding_mismatch",
            source=source,
            validation_status="WRONG_DEVICE",
            device_binding=None,
            binding_status="MISMATCH",
            observed_at=observation.observed_at,
        )
    observed_at = observation.observed_at
    if (
        not isinstance(observed_at, datetime)
        or observed_at.tzinfo is None
        or observed_at.utcoffset() is None
    ):
        return _unknown(
            check,
            reason_code="observation_time_invalid",
            source=source,
            validation_status="INVALID",
            device_binding=observation.device_binding,
            binding_status="MATCHED",
        )
    age = now - observed_at.astimezone(UTC)
    if age < timedelta(0):
        return _unknown(
            check,
            reason_code="observation_time_in_future",
            source=source,
            validation_status="INVALID",
            device_binding=observation.device_binding,
            binding_status="MATCHED",
            observed_at=observed_at,
        )
    if age > max_age:
        return _unknown(
            check,
            reason_code="evidence_stale",
            source=source,
            validation_status="STALE",
            device_binding=observation.device_binding,
            binding_status="MATCHED",
            observed_at=observed_at,
        )
    try:
        authenticated = verifier.verify(observation)
    except Exception:
        authenticated = False
    if authenticated is not True:
        return _unknown(
            check,
            reason_code="evidence_authentication_failed",
            source=source,
            validation_status="INVALID",
            device_binding=observation.device_binding,
            binding_status="MATCHED",
            observed_at=observed_at,
        )
    return AssessedEvidence(
        check=check,
        state=observation.state,
        source=source,
        observed_at=observed_at,
        validation_status="VALID",
        device_binding=observation.device_binding,
        binding_status="MATCHED",
        reason_code=None,
    )


async def assess_device_health(
    *,
    device_binding: str | None,
    now: datetime,
    settings: Settings,
    provider: DeviceHealthEvidenceProvider | None = None,
    verifier: EvidenceVerifier | None = None,
) -> DeviceHealthAssessment:
    """Assess only authenticated, fresh, correctly bound server-side evidence.

    The score is the sum of configured points for validated PASS evidence.
    The configured weights sum to 100; FAIL and every non-valid state earn zero.
    UNKNOWN points are never renormalized away. With no passing observation the
    score is null, while insufficient coverage still classifies PARTIAL.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Assessment time must be timezone-aware")
    current = now.astimezone(UTC)
    configured_provider = provider or UnavailableEvidenceProvider()
    configured_verifier = verifier or RejectEvidenceVerifier()
    try:
        observations = await configured_provider.collect(device_binding=device_binding, now=current)
    except Exception:
        observations = ()
        provider_failed = True
        provider_malformed = False
    else:
        provider_failed = False
        provider_malformed = not isinstance(observations, Sequence) or isinstance(
            observations, (str, bytes)
        )
        if provider_malformed:
            observations = ()

    by_check: dict[CheckName, list[object]] = {check: [] for check in CHECK_WEIGHTS}
    malformed_checks: set[CheckName] = set()
    for observation in observations:
        if not isinstance(observation, EvidenceObservation):
            malformed_checks.update(CHECK_WEIGHTS)
            continue
        if not isinstance(observation.check, str) or observation.check not in by_check:
            malformed_checks.update(CHECK_WEIGHTS)
            continue
        by_check[observation.check].append(observation)

    max_age = timedelta(seconds=settings.device_health_evidence_max_age_seconds)
    assessed: list[AssessedEvidence] = []
    for check in CHECK_WEIGHTS:
        candidates = by_check[check]
        if provider_failed:
            item = _unknown(check, reason_code="provider_unavailable")
        elif provider_malformed:
            item = _unknown(
                check,
                reason_code="malformed_provider_response",
                validation_status="MALFORMED",
            )
        elif check in malformed_checks:
            item = _unknown(
                check, reason_code="malformed_provider_response", validation_status="MALFORMED"
            )
        elif len(candidates) > 1:
            item = _unknown(check, reason_code="duplicate_evidence", validation_status="MALFORMED")
        elif not candidates:
            item = _unknown(check, reason_code="evidence_missing")
        else:
            item = _assess_observation(
                candidates[0],
                check=check,
                expected_binding=device_binding,
                now=current,
                max_age=max_age,
                verifier=configured_verifier,
            )
        assessed.append(item)

    weights = _weight_map(settings)
    complete = all(item.validation_status == "VALID" for item in assessed)
    earned = sum(
        (
            weights[item.check]
            for item in assessed
            if item.validation_status == "VALID" and item.state == "PASS"
        ),
        start=Decimal("0"),
    )
    has_valid_evidence = any(item.validation_status == "VALID" for item in assessed)
    score = earned.quantize(Decimal("0.01")) if has_valid_evidence else None
    failed_mandatory = any(
        item.check in MANDATORY_CHECKS
        and item.validation_status == "VALID"
        and item.state == "FAIL"
        for item in assessed
    )
    healthy_threshold = Decimal(str(settings.device_health_healthy_threshold))
    unhealthy_threshold = Decimal(str(settings.device_health_unhealthy_threshold))
    if failed_mandatory:
        classification: HealthClassification = "UNHEALTHY"
    elif not complete:
        classification = "PARTIAL"
    elif score is not None and score >= healthy_threshold:
        classification = "HEALTHY"
    elif score is not None and score < unhealthy_threshold:
        classification = "UNHEALTHY"
    else:
        classification = "PARTIAL"

    reasons = tuple(
        dict.fromkeys(
            [item.reason_code for item in assessed if item.reason_code]
            + (["mandatory_check_failed"] if failed_mandatory else [])
            + (["evidence_incomplete"] if not complete and not failed_mandatory else [])
        )
    )
    return DeviceHealthAssessment(
        classification=classification,
        score=score,
        complete=complete,
        evidence=tuple(assessed),
        reason_codes=reasons,
    )
