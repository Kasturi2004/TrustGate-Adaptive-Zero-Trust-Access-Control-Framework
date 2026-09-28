"""Create the TrustGate Phase 2 application schema."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260928_01"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the eleven TrustGate-owned Phase 2 tables and constraints."""
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
    op.create_table(
        "profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column("role", sa.Text(), server_default=sa.text("'USER'"), nullable=False),
        sa.Column("timezone", sa.Text(), server_default=sa.text("'UTC'"), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("role IN ('USER', 'ADMIN')", name="ck_profiles_role_values"),
        sa.PrimaryKeyConstraint("id", name="pk_profiles"),
        schema="public",
    )
    # Supabase Auth owns auth.users; represent its relationship without creating that table.
    op.create_foreign_key(
        "fk_profiles_id_users",
        "profiles",
        "users",
        ["id"],
        ["id"],
        source_schema="public",
        referent_schema="auth",
        ondelete="RESTRICT",
    )

    op.create_table(
        "devices",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("device_hash", sa.Text(), nullable=False),
        sa.Column("recognized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_user_agent_family", sa.Text(), nullable=True),
        sa.Column("last_user_agent_version", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["public.profiles.id"],
            name="fk_devices_user_id_profiles",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_devices"),
        sa.UniqueConstraint("user_id", "device_hash", name="user_device_hash"),
        schema="public",
    )
    op.create_index("idx_devices_user_id", "devices", ["user_id"], schema="public")

    op.create_table(
        "access_requests",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "resource_id", sa.Text(), server_default=sa.text("'ops-dashboard'"), nullable=False
        ),
        sa.Column("source_ip", postgresql.INET(), nullable=False),
        sa.Column("resolved_region", sa.Text(), nullable=True),
        sa.Column("initial_decision", sa.Text(), nullable=False),
        sa.Column("mfa_required", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("final_outcome", sa.Text(), nullable=True),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "initial_decision IN ('ALLOW', 'STEP_UP', 'BLOCK')",
            name="ck_access_requests_initial_decision_values",
        ),
        sa.CheckConstraint(
            "final_outcome IN ('ALLOW', 'BLOCK')", name="ck_access_requests_final_outcome_values"
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["public.devices.id"],
            name="fk_access_requests_device_id_devices",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["public.profiles.id"],
            name="fk_access_requests_user_id_profiles",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_access_requests"),
        schema="public",
    )
    op.create_index("idx_access_requests_user_id", "access_requests", ["user_id"], schema="public")
    op.create_index(
        "idx_access_requests_user_created",
        "access_requests",
        ["user_id", sa.text("requested_at DESC")],
        schema="public",
    )
    op.create_index(
        "idx_access_requests_decision",
        "access_requests",
        ["initial_decision", sa.text("requested_at DESC")],
        schema="public",
    )
    op.create_index(
        "idx_access_requests_device_id",
        "access_requests",
        ["device_id", sa.text("requested_at DESC")],
        schema="public",
    )

    op.create_table(
        "context_signals",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("access_request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("device_familiarity_raw", sa.Text(), nullable=False),
        sa.Column("device_health_raw", sa.Text(), nullable=False),
        sa.Column("location_raw", sa.Text(), nullable=False),
        sa.Column("time_raw", sa.Text(), nullable=False),
        sa.Column(
            "raw_context", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column(
            "captured_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "device_familiarity_raw IN ('known_device', 'unknown_device')",
            name="ck_context_signals_device_familiarity_values",
        ),
        sa.CheckConstraint(
            "device_health_raw IN ('healthy', 'partially_healthy', 'unhealthy')",
            name="ck_context_signals_device_health_values",
        ),
        sa.CheckConstraint(
            "location_raw IN ('expected_region', 'new_region', 'unavailable')",
            name="ck_context_signals_location_values",
        ),
        sa.CheckConstraint(
            "time_raw IN ('within_normal_window', 'outside_normal_window')",
            name="ck_context_signals_time_values",
        ),
        sa.ForeignKeyConstraint(
            ["access_request_id"],
            ["public.access_requests.id"],
            name="fk_context_signals_access_request_id_access_requests",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_context_signals"),
        sa.UniqueConstraint("access_request_id", name="uq_context_signals_access_request_id"),
        schema="public",
    )

    op.create_table(
        "policy_versions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("version_label", sa.Text(), nullable=False),
        sa.Column("weights_json", postgresql.JSONB(), nullable=False),
        sa.Column(
            "allow_threshold", sa.Numeric(5, 2), server_default=sa.text("70.00"), nullable=False
        ),
        sa.Column(
            "stepup_threshold", sa.Numeric(5, 2), server_default=sa.text("40.00"), nullable=False
        ),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_policy_versions"),
        sa.UniqueConstraint("version_label", name="uq_policy_versions_version_label"),
        schema="public",
    )
    op.create_index(
        "idx_policy_versions_one_active",
        "policy_versions",
        ["is_active"],
        unique=True,
        schema="public",
        postgresql_where=sa.text("is_active"),
    )

    op.create_table(
        "trust_evaluations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("access_request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("trust_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("risk_classification", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'COMPLETE'"), nullable=False),
        sa.Column(
            "evaluated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "risk_classification IN ('LOW', 'MEDIUM', 'HIGH')",
            name="ck_trust_evaluations_risk_classification_values",
        ),
        sa.CheckConstraint(
            "status IN ('COMPLETE', 'DEGRADED_FAILSAFE')", name="ck_trust_evaluations_status_values"
        ),
        sa.CheckConstraint(
            "trust_score BETWEEN 0 AND 100", name="ck_trust_evaluations_trust_score_range"
        ),
        sa.ForeignKeyConstraint(
            ["access_request_id"],
            ["public.access_requests.id"],
            name="fk_trust_evaluations_access_request_id_access_requests",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_version_id"],
            ["public.policy_versions.id"],
            name="fk_trust_evaluations_policy_version_id_policy_versions",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_trust_evaluations"),
        sa.UniqueConstraint("access_request_id", name="uq_trust_evaluations_access_request_id"),
        schema="public",
    )
    op.create_index(
        "idx_trust_evaluations_score", "trust_evaluations", ["trust_score"], schema="public"
    )

    op.create_table(
        "trust_factors",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("trust_evaluation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("factor_name", sa.Text(), nullable=False),
        sa.Column("raw_value", sa.Text(), nullable=False),
        sa.Column("normalized_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("weight", sa.Numeric(4, 3), nullable=False),
        sa.Column("weighted_contribution", sa.Numeric(6, 3), nullable=False),
        sa.CheckConstraint(
            "factor_name IN ('device_familiarity', 'device_health', "
            "'location_normality', 'time_normality')",
            name="ck_trust_factors_factor_name_values",
        ),
        sa.CheckConstraint(
            "normalized_score BETWEEN 0 AND 100", name="ck_trust_factors_normalized_score_range"
        ),
        sa.CheckConstraint("weight > 0 AND weight <= 1", name="ck_trust_factors_weight_range"),
        sa.ForeignKeyConstraint(
            ["trust_evaluation_id"],
            ["public.trust_evaluations.id"],
            name="fk_trust_factors_trust_evaluation_id_trust_evaluations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_trust_factors"),
        sa.UniqueConstraint("trust_evaluation_id", "factor_name", name="evaluation_factor"),
        schema="public",
    )
    op.create_index(
        "idx_trust_factors_evaluation_id", "trust_factors", ["trust_evaluation_id"], schema="public"
    )

    op.create_table(
        "policy_decisions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("access_request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("trust_evaluation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("decision_reason", sa.Text(), nullable=False),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "decision IN ('ALLOW', 'STEP_UP', 'BLOCK')", name="ck_policy_decisions_decision_values"
        ),
        sa.ForeignKeyConstraint(
            ["access_request_id"],
            ["public.access_requests.id"],
            name="fk_policy_decisions_access_request_id_access_requests",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_version_id"],
            ["public.policy_versions.id"],
            name="fk_policy_decisions_policy_version_id_policy_versions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["trust_evaluation_id"],
            ["public.trust_evaluations.id"],
            name="fk_policy_decisions_trust_evaluation_id_trust_evaluations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_policy_decisions"),
        sa.UniqueConstraint("access_request_id", name="uq_policy_decisions_access_request_id"),
        schema="public",
    )
    op.create_index(
        "idx_policy_decisions_decision",
        "policy_decisions",
        ["decision", sa.text("decided_at DESC")],
        schema="public",
    )

    op.create_table(
        "otp_challenges",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("access_request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("otp_hash", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'PENDING'"), nullable=False),
        sa.Column("attempt_count", sa.SmallInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("max_attempts", sa.SmallInteger(), server_default=sa.text("3"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "attempt_count >= 0", name="ck_otp_challenges_attempt_count_nonnegative"
        ),
        sa.CheckConstraint(
            "attempt_count <= max_attempts", name="ck_otp_challenges_attempt_count_limit"
        ),
        sa.CheckConstraint(
            "status IN ('PENDING', 'SUCCESS', 'EXPIRED', 'LOCKED')",
            name="ck_otp_challenges_status_values",
        ),
        sa.ForeignKeyConstraint(
            ["access_request_id"],
            ["public.access_requests.id"],
            name="fk_otp_challenges_access_request_id_access_requests",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["public.profiles.id"],
            name="fk_otp_challenges_user_id_profiles",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_otp_challenges"),
        schema="public",
    )
    op.create_index(
        "idx_otp_challenges_one_pending_per_request",
        "otp_challenges",
        ["access_request_id"],
        unique=True,
        schema="public",
        postgresql_where=sa.text("status = 'PENDING'"),
    )
    op.create_index("idx_otp_challenges_user_id", "otp_challenges", ["user_id"], schema="public")
    op.create_index(
        "idx_otp_challenges_status",
        "otp_challenges",
        ["status"],
        schema="public",
        postgresql_where=sa.text("status = 'PENDING'"),
    )
    op.create_index(
        "idx_otp_challenges_access_request",
        "otp_challenges",
        ["access_request_id"],
        schema="public",
    )

    op.create_table(
        "rate_limit_state",
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("counter", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("window_reset_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("counter >= 0", name="ck_rate_limit_state_counter_nonnegative"),
        sa.PrimaryKeyConstraint("key", name="pk_rate_limit_state"),
        schema="public",
    )
    op.create_index(
        "idx_rate_limit_state_window_reset_at",
        "rate_limit_state",
        ["window_reset_at"],
        schema="public",
    )

    op.create_table(
        "security_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("access_request_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("trust_evaluation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("decision", sa.Text(), nullable=True),
        sa.Column("risk_category", sa.Text(), nullable=True),
        sa.Column(
            "details", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "decision IN ('ALLOW', 'STEP_UP', 'BLOCK')", name="ck_security_events_decision_values"
        ),
        sa.CheckConstraint(
            "risk_category IN ('LOW', 'MEDIUM', 'HIGH')",
            name="ck_security_events_risk_category_values",
        ),
        sa.ForeignKeyConstraint(
            ["access_request_id"],
            ["public.access_requests.id"],
            name="fk_security_events_access_request_id_access_requests",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["public.profiles.id"],
            name="fk_security_events_actor_id_profiles",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["target_user_id"],
            ["public.profiles.id"],
            name="fk_security_events_target_user_id_profiles",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["trust_evaluation_id"],
            ["public.trust_evaluations.id"],
            name="fk_security_events_trust_evaluation_id_trust_evaluations",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_security_events"),
        schema="public",
    )
    op.create_index(
        "idx_security_events_created_at",
        "security_events",
        [sa.text("created_at DESC")],
        schema="public",
    )
    op.create_index(
        "idx_security_events_actor",
        "security_events",
        ["actor_id", sa.text("created_at DESC")],
        schema="public",
    )
    op.create_index(
        "idx_security_events_event_type",
        "security_events",
        ["event_type", sa.text("created_at DESC")],
        schema="public",
    )
    op.create_index(
        "idx_security_events_request", "security_events", ["access_request_id"], schema="public"
    )


def downgrade() -> None:
    """Remove the TrustGate schema in reverse dependency order."""
    op.drop_table("security_events", schema="public")
    op.drop_index(
        "idx_rate_limit_state_window_reset_at", table_name="rate_limit_state", schema="public"
    )
    op.drop_table("rate_limit_state", schema="public")
    op.drop_index("idx_otp_challenges_access_request", table_name="otp_challenges", schema="public")
    op.drop_index("idx_otp_challenges_status", table_name="otp_challenges", schema="public")
    op.drop_index("idx_otp_challenges_user_id", table_name="otp_challenges", schema="public")
    op.drop_index(
        "idx_otp_challenges_one_pending_per_request", table_name="otp_challenges", schema="public"
    )
    op.drop_table("otp_challenges", schema="public")
    op.drop_index("idx_policy_decisions_decision", table_name="policy_decisions", schema="public")
    op.drop_table("policy_decisions", schema="public")
    op.drop_index("idx_trust_factors_evaluation_id", table_name="trust_factors", schema="public")
    op.drop_table("trust_factors", schema="public")
    op.drop_index("idx_trust_evaluations_score", table_name="trust_evaluations", schema="public")
    op.drop_table("trust_evaluations", schema="public")
    op.drop_index("idx_policy_versions_one_active", table_name="policy_versions", schema="public")
    op.drop_table("policy_versions", schema="public")
    op.drop_table("context_signals", schema="public")
    op.drop_index("idx_access_requests_device_id", table_name="access_requests", schema="public")
    op.drop_index("idx_access_requests_decision", table_name="access_requests", schema="public")
    op.drop_index("idx_access_requests_user_created", table_name="access_requests", schema="public")
    op.drop_index("idx_access_requests_user_id", table_name="access_requests", schema="public")
    op.drop_table("access_requests", schema="public")
    op.drop_index("idx_devices_user_id", table_name="devices", schema="public")
    op.drop_table("devices", schema="public")
    op.drop_constraint("fk_profiles_id_users", "profiles", schema="public", type_="foreignkey")
    op.drop_table("profiles", schema="public")
    op.execute("DROP EXTENSION IF EXISTS pgcrypto;")
