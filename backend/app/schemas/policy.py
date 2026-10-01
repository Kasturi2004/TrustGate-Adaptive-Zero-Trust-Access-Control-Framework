"""Typed inputs and outputs for policy decision evaluation."""

from __future__ import annotations

from decimal import Decimal

from pydantic import BaseModel, ConfigDict, model_validator

from app.schemas.access import AccessDecision


class PolicyThresholds(BaseModel):
    """Decision thresholds supplied by the active server-side policy."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    allow_threshold: Decimal
    stepup_threshold: Decimal

    @model_validator(mode="after")
    def validate_thresholds(self) -> PolicyThresholds:
        values = (self.allow_threshold, self.stepup_threshold)
        if any(
            not value.is_finite() or not Decimal("0") <= value <= Decimal("100") for value in values
        ):
            raise ValueError("Policy thresholds must be finite values between 0 and 100")
        if self.stepup_threshold >= self.allow_threshold:
            raise ValueError("The STEP_UP threshold must be below the ALLOW threshold")
        return self


class PolicyDecisionResult(BaseModel):
    """Explainable decision and the score/thresholds used to reach it."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    decision: AccessDecision
    decision_reason: str
    trust_score: Decimal
    allow_threshold: Decimal
    stepup_threshold: Decimal
