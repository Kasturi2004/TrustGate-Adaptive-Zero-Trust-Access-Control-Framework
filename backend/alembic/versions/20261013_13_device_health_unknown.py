"""Allow explicit unknown posture in persisted context signals.

Revision ID: 20261013_13
Revises: 20261013_12
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20261013_13"
down_revision: str | None = "20261013_12"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Extend the accepted context vocabulary without rewriting existing rows."""
    # The initial migration created this legacy name with the naming
    # convention applied twice. Mark it as final so Alembic does not rewrite it.
    op.drop_constraint(
        op.f("ck_context_signals_ck_context_signals_device_health_values"),
        "context_signals",
        schema="public",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_context_signals_device_health_values"),
        "context_signals",
        "device_health_raw IN ('healthy', 'partially_healthy', 'unhealthy', 'unknown')",
        schema="public",
    )


def downgrade() -> None:
    """Refuse downgrade while any explicit unknown rows need the new vocabulary."""
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM public.context_signals WHERE device_health_raw = 'unknown'
            ) THEN
                RAISE EXCEPTION
                    'Cannot downgrade device-health vocabulary while unknown rows exist';
            END IF;
        END
        $$
        """
    )
    op.drop_constraint(
        op.f("ck_context_signals_device_health_values"),
        "context_signals",
        schema="public",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_context_signals_ck_context_signals_device_health_values"),
        "context_signals",
        "device_health_raw IN ('healthy', 'partially_healthy', 'unhealthy')",
        schema="public",
    )
