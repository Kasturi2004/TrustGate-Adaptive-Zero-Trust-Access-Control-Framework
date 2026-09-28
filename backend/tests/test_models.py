import os
import subprocess
import sys
from pathlib import Path

from app.db.models import Base
from sqlalchemy import DateTime, Numeric, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

EXPECTED_TABLES = {
    "profiles",
    "devices",
    "access_requests",
    "context_signals",
    "trust_evaluations",
    "trust_factors",
    "policy_versions",
    "policy_decisions",
    "otp_challenges",
    "rate_limit_state",
    "security_events",
}


def test_metadata_contains_only_the_eleven_phase_two_tables() -> None:
    assert {table.name for table in Base.metadata.tables.values()} == EXPECTED_TABLES
    assert all(table.schema == "public" for table in Base.metadata.tables.values())


def test_primary_key_definitions() -> None:
    for table in Base.metadata.tables.values():
        if table.name != "rate_limit_state":
            primary_key = next(iter(table.primary_key.columns))
            assert primary_key.name == "id"
            assert isinstance(primary_key.type, PG_UUID)

    profiles = Base.metadata.tables["public.profiles"]
    profile_id = profiles.c.id
    assert profile_id.primary_key
    assert isinstance(profile_id.type, PG_UUID)
    profile_fk = next(iter(profile_id.foreign_keys))
    assert profile_fk.target_fullname == "auth.users.id"

    rate_limit_key = Base.metadata.tables["public.rate_limit_state"].c.key
    assert rate_limit_key.primary_key
    assert isinstance(rate_limit_key.type, Text)


def test_audit_foreign_keys_and_delete_rules() -> None:
    tables = Base.metadata.tables
    devices = tables["public.devices"]
    access_requests = tables["public.access_requests"]
    security_events = tables["public.security_events"]
    assert next(iter(devices.c.user_id.foreign_keys)).ondelete == "CASCADE"
    assert next(iter(access_requests.c.device_id.foreign_keys)).ondelete == "RESTRICT"
    assert next(iter(security_events.c.actor_id.foreign_keys)).ondelete == "SET NULL"
    assert next(iter(security_events.c.access_request_id.foreign_keys)).ondelete == "SET NULL"

    context_signal = tables["public.context_signals"]
    evaluation = tables["public.trust_evaluations"]
    factor = tables["public.trust_factors"]
    decision = tables["public.policy_decisions"]
    challenge = tables["public.otp_challenges"]
    assert next(iter(context_signal.c.access_request_id.foreign_keys)).ondelete == "RESTRICT"
    assert next(iter(evaluation.c.policy_version_id.foreign_keys)).ondelete == "RESTRICT"
    assert next(iter(factor.c.trust_evaluation_id.foreign_keys)).ondelete == "RESTRICT"
    assert next(iter(decision.c.trust_evaluation_id.foreign_keys)).ondelete == "RESTRICT"
    assert next(iter(challenge.c.access_request_id.foreign_keys)).ondelete == "RESTRICT"


def test_unique_and_partial_unique_constraints() -> None:
    tables = Base.metadata.tables
    device_uniques = {
        frozenset(column.name for column in constraint.columns)
        for constraint in tables["public.devices"].constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    assert frozenset({"user_id", "device_hash"}) in device_uniques
    for table_name in ("context_signals", "trust_evaluations", "policy_decisions"):
        table = tables[f"public.{table_name}"]
        assert table.c.access_request_id.unique is True

    policy_index = next(
        index
        for index in tables["public.policy_versions"].indexes
        if index.name == "idx_policy_versions_one_active"
    )
    assert policy_index.unique
    assert str(policy_index.dialect_options["postgresql"]["where"]) == "is_active"

    otp_index = next(
        index
        for index in tables["public.otp_challenges"].indexes
        if index.name == "idx_otp_challenges_one_pending_per_request"
    )
    assert otp_index.unique
    assert str(otp_index.dialect_options["postgresql"]["where"]) == "status = 'PENDING'"


def test_check_constraints_cover_important_ranges_and_states() -> None:
    constraints = {
        table.name: {
            str(constraint.sqltext)
            for constraint in table.constraints
            if hasattr(constraint, "sqltext")
        }
        for table in Base.metadata.tables.values()
    }
    assert "trust_score BETWEEN 0 AND 100" in constraints["trust_evaluations"]
    assert "weight > 0 AND weight <= 1" in constraints["trust_factors"]
    assert "attempt_count <= max_attempts" in constraints["otp_challenges"]
    assert "counter >= 0" in constraints["rate_limit_state"]
    assert "role IN ('USER', 'ADMIN')" in constraints["profiles"]
    assert "initial_decision IN ('ALLOW', 'STEP_UP', 'BLOCK')" in constraints["access_requests"]
    assert "decision IN ('ALLOW', 'STEP_UP', 'BLOCK')" in constraints["policy_decisions"]
    assert "status IN ('PENDING', 'SUCCESS', 'EXPIRED', 'LOCKED')" in constraints["otp_challenges"]
    assert "decision IN ('ALLOW', 'STEP_UP', 'BLOCK')" in constraints["security_events"]


def test_schema_indexes_are_registered() -> None:
    expected_indexes = {
        "idx_devices_user_id",
        "idx_access_requests_user_id",
        "idx_access_requests_user_created",
        "idx_access_requests_decision",
        "idx_access_requests_device_id",
        "idx_trust_evaluations_score",
        "idx_trust_factors_evaluation_id",
        "idx_policy_decisions_decision",
        "idx_policy_versions_one_active",
        "idx_otp_challenges_user_id",
        "idx_otp_challenges_status",
        "idx_otp_challenges_access_request",
        "idx_otp_challenges_one_pending_per_request",
        "idx_rate_limit_state_window_reset_at",
        "idx_security_events_created_at",
        "idx_security_events_actor",
        "idx_security_events_event_type",
        "idx_security_events_request",
    }
    actual_indexes = {
        index.name for table in Base.metadata.tables.values() for index in table.indexes
    }
    assert actual_indexes == expected_indexes


def test_timestamp_and_score_columns_use_required_types() -> None:
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, DateTime):
                assert column.type.timezone is True

    tables = Base.metadata.tables
    numeric_columns = {
        "trust_evaluations": {"trust_score": (5, 2)},
        "trust_factors": {
            "normalized_score": (5, 2),
            "weight": (4, 3),
            "weighted_contribution": (6, 3),
        },
        "policy_versions": {"allow_threshold": (5, 2), "stepup_threshold": (5, 2)},
    }
    for table_name, columns in numeric_columns.items():
        for column_name, dimensions in columns.items():
            column_type = tables[f"public.{table_name}"].c[column_name].type
            assert isinstance(column_type, Numeric)
            assert (column_type.precision, column_type.scale) == dimensions


def test_model_metadata_import_does_not_create_a_database_engine() -> None:
    script = (
        "from unittest.mock import patch; "
        "import sqlalchemy.ext.asyncio as async_sqlalchemy; "
        "guard = patch.object(async_sqlalchemy, 'create_async_engine', "
        "side_effect=AssertionError); "
        "guard.start(); "
        "from app.db.models import target_metadata; "
        "assert len(target_metadata.tables) == 11"
    )
    environment = os.environ.copy()
    environment.pop("DATABASE_URL", None)
    environment.pop("MIGRATION_DATABASE_URL", None)
    subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
