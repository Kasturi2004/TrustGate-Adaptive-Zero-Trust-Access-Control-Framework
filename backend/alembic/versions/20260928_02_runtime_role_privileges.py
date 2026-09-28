"""Configure the TrustGate runtime role and least-privilege table grants."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260928_02"
down_revision: str | None = "20260928_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE_GRANTS: tuple[tuple[str, str], ...] = (
    ("profiles", "SELECT, UPDATE"),
    ("devices", "SELECT, INSERT, UPDATE"),
    ("access_requests", "SELECT, INSERT, UPDATE"),
    ("context_signals", "SELECT, INSERT"),
    ("trust_evaluations", "SELECT, INSERT"),
    ("trust_factors", "SELECT, INSERT"),
    ("policy_versions", "SELECT"),
    ("policy_decisions", "SELECT, INSERT"),
    ("otp_challenges", "SELECT, INSERT, UPDATE"),
    ("rate_limit_state", "SELECT, INSERT, UPDATE"),
    ("security_events", "SELECT, INSERT"),
)

_TRUSTGATE_TABLES = tuple(table for table, _privileges in _TABLE_GRANTS)


def upgrade() -> None:
    """Apply the reviewed runtime role and per-table DML baseline."""
    op.execute("ALTER ROLE trustgate_app BYPASSRLS")

    for table in _TRUSTGATE_TABLES:
        op.execute(f"REVOKE ALL PRIVILEGES ON TABLE public.{table} FROM anon, authenticated")
        op.execute(f"REVOKE ALL PRIVILEGES ON TABLE public.{table} FROM trustgate_app")

    for table, privileges in _TABLE_GRANTS:
        op.execute(f"GRANT {privileges} ON TABLE public.{table} TO trustgate_app")


def downgrade() -> None:
    """Restore the inspected pre-migration role and table privilege state."""
    for table in _TRUSTGATE_TABLES:
        op.execute(f"REVOKE ALL PRIVILEGES ON TABLE public.{table} FROM trustgate_app")

    op.execute("ALTER ROLE trustgate_app NOBYPASSRLS")

    for table in _TRUSTGATE_TABLES:
        op.execute(f"GRANT ALL PRIVILEGES ON TABLE public.{table} TO anon, authenticated")
