"""Explicit, allow-listed response schemas for administrative endpoints."""

from datetime import datetime
from decimal import Decimal
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

AdminDeviceHealthCheck = Literal[
    "os_patch_compliance",
    "endpoint_protection",
    "disk_encryption",
    "firewall_status",
    "integrity_management_compliance",
]
AdminDeviceHealthState = Literal["PASS", "FAIL", "UNKNOWN"]
AdminDeviceHealthValidationStatus = Literal[
    "VALID", "UNVERIFIED", "INVALID", "STALE", "WRONG_DEVICE", "MALFORMED"
]


class AdminRiskIndicator(BaseModel):
    """One normalized behavioral indicator computed from persisted records."""

    model_config = ConfigDict(extra="forbid")

    count: int = Field(ge=0)
    normalized_value: float = Field(ge=0, le=1)
    flagged: bool


class AdminBehavioralRiskIndicators(BaseModel):
    """Allow-listed Phase 13 indicators for an administrative read."""

    model_config = ConfigDict(extra="forbid")

    repeated_failed_access_attempts: AdminRiskIndicator
    recent_blocks: AdminRiskIndicator


class AdminDashboardResponse(BaseModel):
    """Aggregate dashboard metrics without ORM or credential fields."""

    model_config = ConfigDict(extra="forbid")

    total_requests: int
    allow_count: int
    step_up_count: int
    block_count: int
    average_trust_score: float | None
    high_risk_count: int
    mfa_success_rate: float | None
    behavioral_indicators: AdminBehavioralRiskIndicators


class AdminSecurityEventItem(BaseModel):
    """Narrow event-list projection with a truncated device identifier."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    event_type: str
    created_at: datetime
    user_id: UUID | None
    decision: str | None
    risk_category: str | None
    trust_score: Decimal | None
    device: str | None


class AdminSecurityEventPage(BaseModel):
    """Paginated, explicitly allow-listed administrative event results."""

    model_config = ConfigDict(extra="forbid")

    items: list[AdminSecurityEventItem]
    total: int
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=50)


class AdminInvestigationEvent(BaseModel):
    """Safe event metadata for the root event or its related events."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    event_type: str
    actor_id: UUID | None
    target_user_id: UUID | None
    decision: str | None
    risk_category: str | None
    created_at: datetime


class AdminInvestigationDevice(BaseModel):
    """Device identifier presented only as a truncated hash."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    device_hash: str


class AdminInvestigationRequest(BaseModel):
    """Persisted request fields relevant to an administrator's investigation."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    user_id: UUID
    resource_id: str
    source_ip: str
    resolved_region: str | None
    initial_decision: str
    mfa_required: bool
    final_outcome: str | None
    requested_at: datetime
    resolved_at: datetime | None
    device: AdminInvestigationDevice | None


class AdminDeviceHealthEvidence(BaseModel):
    """Safe, allow-listed posture evidence fields for an admin investigation."""

    model_config = ConfigDict(extra="forbid")

    check: AdminDeviceHealthCheck
    state: AdminDeviceHealthState
    validation_status: AdminDeviceHealthValidationStatus
    observed_at: datetime | None
    reason_code: str | None


class AdminDeviceHealthAssessment(BaseModel):
    """Scoring summary and coverage; never includes proof or device binding."""

    model_config = ConfigDict(extra="forbid")

    version: Literal["posture-v1"]
    classification: Literal["HEALTHY", "PARTIAL", "UNHEALTHY"]
    score: Decimal | None = Field(default=None, ge=0, le=100)
    complete: bool
    verified_evidence_count: int = Field(ge=0, le=5)
    total_evidence_count: int = Field(ge=0, le=5)
    reason_codes: list[str]
    evidence: list[AdminDeviceHealthEvidence]


class AdminInvestigationContext(BaseModel):
    """Normalized persisted context signals, excluding raw context payloads."""

    model_config = ConfigDict(extra="forbid")

    captured_at: datetime
    device_familiarity_raw: str
    device_health_raw: str
    device_health_assessment_version: str | None = None
    device_health_assessment: AdminDeviceHealthAssessment | None = None
    location_raw: str
    time_raw: str


class AdminInvestigationFactor(BaseModel):
    """Persisted factor inputs and scores with a deterministic explanation."""

    model_config = ConfigDict(extra="forbid")

    factor_name: str
    raw_value: str
    normalized_score: Decimal
    weight: Decimal
    weighted_contribution: Decimal
    explanation: str


class AdminInvestigationTrustEvaluation(BaseModel):
    """Persisted evaluation summary and its allow-listed factor breakdown."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    trust_score: Decimal
    risk_classification: str
    status: str
    evaluated_at: datetime
    factors: list[AdminInvestigationFactor]


class AdminInvestigationPolicyVersion(BaseModel):
    """Policy version identity without raw configuration or thresholds."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    version_label: str
    created_at: datetime


class AdminInvestigationPolicyDecision(BaseModel):
    """Persisted policy decision, reason, and referenced policy version."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    decision: str
    decision_reason: str
    decided_at: datetime
    policy_version: AdminInvestigationPolicyVersion | None


class AdminInvestigationOtpChallenge(BaseModel):
    """OTP lifecycle metadata; never includes its hash or secret material."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    status: str
    attempt_count: int
    created_at: datetime
    expires_at: datetime
    verified_at: datetime | None


class AdminEventInvestigation(BaseModel):
    """Explicit investigation response graph assembled from persisted records."""

    model_config = ConfigDict(extra="forbid")

    event: AdminInvestigationEvent | None
    access_request: AdminInvestigationRequest | None
    context_signals: AdminInvestigationContext | None
    trust_evaluation: AdminInvestigationTrustEvaluation | None
    policy_decision: AdminInvestigationPolicyDecision | None
    otp_challenges: list[AdminInvestigationOtpChallenge]
    related_events: list[AdminInvestigationEvent]
    behavioral_indicators: AdminBehavioralRiskIndicators | None = None
