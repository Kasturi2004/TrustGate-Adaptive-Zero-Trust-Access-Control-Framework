"""Pure, deterministic trust score calculation from normalized context signals."""

from decimal import Decimal

from app.schemas.trust import (
    TrustEvaluationResult,
    TrustFactorResult,
    TrustSignals,
    TrustWeights,
)

_DEVICE_FAMILIARITY_SCORES = {
    "known_device": Decimal("100"),
    "unknown_device": Decimal("20"),
}
_DEVICE_HEALTH_SCORES = {
    "healthy": Decimal("100"),
    "partially_healthy": Decimal("60"),
    "unhealthy": Decimal("10"),
}
_LOCATION_SCORES = {
    "expected_region": Decimal("100"),
    "new_region": Decimal("40"),
    "unavailable": Decimal("70"),
}
_TIME_SCORES = {
    "within_normal_window": Decimal("100"),
    "outside_normal_window": Decimal("30"),
}


def evaluate(signals: TrustSignals, weights: TrustWeights) -> TrustEvaluationResult:
    """Return a deterministic weighted score and factor-level explanations.

    Signal categories come from the Phase 6 context collector. All weights are
    supplied by the caller from the active policy; this function performs no
    I/O, persistence, or policy decision-making.
    """
    inputs = (
        (
            "device_familiarity",
            signals.device_familiarity_raw,
            _DEVICE_FAMILIARITY_SCORES,
            weights.device_familiarity,
        ),
        ("device_health", signals.device_health_raw, _DEVICE_HEALTH_SCORES, weights.device_health),
        ("location_normality", signals.location_raw, _LOCATION_SCORES, weights.location_normality),
        ("time_normality", signals.time_raw, _TIME_SCORES, weights.time_normality),
    )

    factors: list[TrustFactorResult] = []
    for factor_name, raw_value, score_map, weight in inputs:
        normalized_score = score_map[raw_value]
        contribution = normalized_score * weight
        factors.append(
            TrustFactorResult(
                factor_name=factor_name,  # type: ignore[arg-type]
                raw_value=raw_value,
                normalized_score=normalized_score,
                weight=weight,
                weighted_contribution=contribution,
                explanation=(
                    f"{factor_name.replace('_', ' ').title()}: {raw_value} maps to "
                    f"{normalized_score} points; at weight {weight}, contributes {contribution}."
                ),
            )
        )

    trust_score = sum((factor.weighted_contribution for factor in factors), start=Decimal("0"))
    if not Decimal("0") <= trust_score <= Decimal("100"):
        raise ArithmeticError("Calculated trust score is outside the 0 to 100 range")

    return TrustEvaluationResult(trust_score=trust_score, factors=tuple(factors))
