"""Typed inputs and outputs for deterministic trust scoring."""

from __future__ import annotations

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

FactorName = Literal[
    "device_familiarity",
    "device_health",
    "location_normality",
    "time_normality",
]

DeviceFamiliaritySignal = Literal["known_device", "unknown_device"]
DeviceHealthSignal = Literal["healthy", "partially_healthy", "unhealthy"]
LocationSignal = Literal["expected_region", "new_region", "unavailable"]
TimeSignal = Literal["within_normal_window", "outside_normal_window"]


class TrustSignals(BaseModel):
    """Normalized raw signal categories collected for one request."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    device_familiarity_raw: DeviceFamiliaritySignal
    device_health_raw: DeviceHealthSignal
    location_raw: LocationSignal
    time_raw: TimeSignal


class TrustWeights(BaseModel):
    """Active policy weights for each trust factor."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    device_familiarity: Decimal
    device_health: Decimal
    location_normality: Decimal
    time_normality: Decimal

    @model_validator(mode="after")
    def validate_weights(self) -> TrustWeights:
        values = tuple(self.model_dump().values())
        if any(
            not value.is_finite()
            or value <= Decimal("0")
            or value > Decimal("1")
            or value.as_tuple().exponent < -3
            for value in values
        ):
            raise ValueError(
                "Trust weights must be finite values in (0, 1] with at most 3 decimals"
            )
        if sum(values, start=Decimal("0")) != Decimal("1"):
            raise ValueError("Trust weights must sum to 1")
        return self


class TrustFactorResult(BaseModel):
    """Explainable normalized score and weighted contribution for one factor."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    factor_name: FactorName
    raw_value: str
    normalized_score: Decimal
    weight: Decimal
    weighted_contribution: Decimal
    explanation: str


class TrustEvaluationResult(BaseModel):
    """Pure trust score and its ordered factor breakdown."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    trust_score: Decimal
    factors: tuple[TrustFactorResult, ...]
