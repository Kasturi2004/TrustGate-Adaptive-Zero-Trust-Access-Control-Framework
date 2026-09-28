"""Enable RLS on TrustGate tables with the three own-row read policies."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260928_03"
down_revision: str | None = "20260928_02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = (
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
)


def upgrade() -> None:
    """Enable row-level security and add only the three documented policies."""
    for table in _TABLES:
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")

    op.execute(
        "CREATE POLICY profiles_select_own ON public.profiles FOR SELECT USING (auth.uid() = id)"
    )
    op.execute(
        "CREATE POLICY devices_select_own ON public.devices FOR SELECT USING (auth.uid() = user_id)"
    )
    op.execute(
        "CREATE POLICY access_requests_select_own ON public.access_requests "
        "FOR SELECT USING (auth.uid() = user_id)"
    )


def downgrade() -> None:
    """Remove the policies and restore the previously disabled RLS state."""
    op.execute("DROP POLICY access_requests_select_own ON public.access_requests")
    op.execute("DROP POLICY devices_select_own ON public.devices")
    op.execute("DROP POLICY profiles_select_own ON public.profiles")

    for table in reversed(_TABLES):
        op.execute(f"ALTER TABLE public.{table} DISABLE ROW LEVEL SECURITY")
