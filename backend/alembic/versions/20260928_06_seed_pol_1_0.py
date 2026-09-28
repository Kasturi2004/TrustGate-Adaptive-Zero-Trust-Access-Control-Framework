"""Seed the initial TrustGate policy version."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260928_06"
down_revision: str | None = "20260928_05"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Insert the exact POL-1.0 seed, relying on existing uniqueness guards."""
    op.execute(
        """
        INSERT INTO public.policy_versions (
            version_label,
            weights_json,
            allow_threshold,
            stepup_threshold,
            is_active
        )
        VALUES (
            'POL-1.0',
            '{"device_familiarity"\\:0.35,"device_health"\\:0.30,"location_normality"\\:0.20,"time_normality"\\:0.15}'::jsonb,
            70.00,
            40.00,
            true
        )
        """
    )


def downgrade() -> None:
    """Remove only the policy seed introduced by this revision."""
    op.execute("DELETE FROM public.policy_versions WHERE version_label = 'POL-1.0'")
