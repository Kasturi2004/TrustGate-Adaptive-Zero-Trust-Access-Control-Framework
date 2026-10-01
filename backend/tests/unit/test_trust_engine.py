"""Unit tests for the pure Phase 7A trust evaluation engine."""

from decimal import Decimal
from itertools import product

import pytest
from app.schemas.trust import TrustSignals, TrustWeights
from app.services.trust_engine import evaluate
from pydantic import ValidationError

_DEFAULT_WEIGHTS = TrustWeights(
    device_familiarity=Decimal("0.350"),
    device_health=Decimal("0.300"),
    location_normality=Decimal("0.200"),
    time_normality=Decimal("0.150"),
)
_SIGNAL_VALUES = (
    ("known_device", "unknown_device"),
    ("healthy", "partially_healthy", "unhealthy"),
    ("expected_region", "new_region", "unavailable"),
    ("within_normal_window", "outside_normal_window"),
)


@pytest.mark.parametrize("values", list(product(*_SIGNAL_VALUES)))
def test_all_required_signal_combinations_produce_four_typed_factors(
    values: tuple[str, str, str, str],
) -> None:
    signals = TrustSignals(
        device_familiarity_raw=values[0],  # type: ignore[arg-type]
        device_health_raw=values[1],  # type: ignore[arg-type]
        location_raw=values[2],  # type: ignore[arg-type]
        time_raw=values[3],  # type: ignore[arg-type]
    )

    result = evaluate(signals, _DEFAULT_WEIGHTS)

    assert len(result.factors) == 4
    assert tuple(factor.factor_name for factor in result.factors) == (
        "device_familiarity",
        "device_health",
        "location_normality",
        "time_normality",
    )
    assert [factor.raw_value for factor in result.factors] == list(values)
    expected_scores = {
        "known_device": Decimal("100"),
        "unknown_device": Decimal("20"),
        "healthy": Decimal("100"),
        "partially_healthy": Decimal("60"),
        "unhealthy": Decimal("10"),
        "expected_region": Decimal("100"),
        "new_region": Decimal("40"),
        "unavailable": Decimal("70"),
        "within_normal_window": Decimal("100"),
        "outside_normal_window": Decimal("30"),
    }
    assert [factor.normalized_score for factor in result.factors] == [
        expected_scores[value] for value in values
    ]
    supplied_weights = (
        _DEFAULT_WEIGHTS.device_familiarity,
        _DEFAULT_WEIGHTS.device_health,
        _DEFAULT_WEIGHTS.location_normality,
        _DEFAULT_WEIGHTS.time_normality,
    )
    assert [factor.weight for factor in result.factors] == list(supplied_weights)
    assert [factor.weighted_contribution for factor in result.factors] == [
        factor.normalized_score * weight
        for factor, weight in zip(result.factors, supplied_weights, strict=True)
    ]
    assert all(factor.explanation for factor in result.factors)
    assert Decimal("0") <= result.trust_score <= Decimal("100")
    assert result.trust_score == sum(
        (factor.weighted_contribution for factor in result.factors), start=Decimal("0")
    )
    assert evaluate(signals, _DEFAULT_WEIGHTS) == result


def test_default_policy_weights_have_exact_decimal_factor_calculations() -> None:
    result = evaluate(
        TrustSignals(
            device_familiarity_raw="known_device",
            device_health_raw="partially_healthy",
            location_raw="new_region",
            time_raw="outside_normal_window",
        ),
        _DEFAULT_WEIGHTS,
    )

    assert [factor.normalized_score for factor in result.factors] == [
        Decimal("100"),
        Decimal("60"),
        Decimal("40"),
        Decimal("30"),
    ]
    assert [factor.weighted_contribution for factor in result.factors] == [
        Decimal("35.000"),
        Decimal("18.000"),
        Decimal("8.000"),
        Decimal("4.500"),
    ]
    assert result.trust_score == Decimal("65.500")


def test_evaluation_is_deterministic_and_explanations_are_stable() -> None:
    signals = TrustSignals(
        device_familiarity_raw="unknown_device",
        device_health_raw="unhealthy",
        location_raw="unavailable",
        time_raw="within_normal_window",
    )

    assert evaluate(signals, _DEFAULT_WEIGHTS) == evaluate(signals, _DEFAULT_WEIGHTS)


def test_active_policy_weight_changes_change_contributions_and_score() -> None:
    signals = TrustSignals(
        device_familiarity_raw="known_device",
        device_health_raw="unhealthy",
        location_raw="new_region",
        time_raw="outside_normal_window",
    )
    changed_weights = TrustWeights(
        device_familiarity=Decimal("0.200"),
        device_health=Decimal("0.450"),
        location_normality=Decimal("0.200"),
        time_normality=Decimal("0.150"),
    )

    baseline = evaluate(signals, _DEFAULT_WEIGHTS)
    changed = evaluate(signals, changed_weights)

    assert baseline.trust_score == Decimal("50.500")
    assert changed.trust_score == Decimal("37.000")
    assert changed.factors[0].weight == Decimal("0.200")
    assert changed.factors[1].weight == Decimal("0.450")


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (
            ("known_device", "healthy", "expected_region", "within_normal_window"),
            Decimal("100.000"),
        ),
        (("unknown_device", "unhealthy", "new_region", "outside_normal_window"), Decimal("22.500")),
    ],
)
def test_score_boundaries_are_exact(values: tuple[str, str, str, str], expected: Decimal) -> None:
    result = evaluate(
        TrustSignals(
            device_familiarity_raw=values[0],  # type: ignore[arg-type]
            device_health_raw=values[1],  # type: ignore[arg-type]
            location_raw=values[2],  # type: ignore[arg-type]
            time_raw=values[3],  # type: ignore[arg-type]
        ),
        _DEFAULT_WEIGHTS,
    )

    assert result.trust_score == expected
    assert Decimal("0") <= result.trust_score <= Decimal("100")


@pytest.mark.parametrize(
    "weights",
    [
        {
            "device_familiarity": Decimal("0.350"),
            "device_health": Decimal("0.300"),
            "location_normality": Decimal("0.200"),
            "time_normality": Decimal("0.100"),
        },
        {
            "device_familiarity": Decimal("0"),
            "device_health": Decimal("0.350"),
            "location_normality": Decimal("0.300"),
            "time_normality": Decimal("0.350"),
        },
        {
            "device_familiarity": Decimal("0.3500"),
            "device_health": Decimal("0.300"),
            "location_normality": Decimal("0.200"),
            "time_normality": Decimal("0.150"),
        },
    ],
)
def test_invalid_policy_weights_are_rejected(weights: dict[str, Decimal]) -> None:
    with pytest.raises(ValidationError):
        TrustWeights(**weights)


def test_float_policy_weights_are_rejected_to_preserve_decimal_arithmetic() -> None:
    with pytest.raises(ValidationError):
        TrustWeights(
            device_familiarity=0.35,  # type: ignore[arg-type]
            device_health=Decimal("0.300"),
            location_normality=Decimal("0.200"),
            time_normality=Decimal("0.150"),
        )


def test_normalized_signal_schema_rejects_unknown_categories() -> None:
    with pytest.raises(ValidationError):
        TrustSignals(
            device_familiarity_raw="recognized_device",  # type: ignore[arg-type]
            device_health_raw="healthy",
            location_raw="expected_region",
            time_raw="within_normal_window",
        )
