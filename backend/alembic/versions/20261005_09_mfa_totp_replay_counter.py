"""Track the last accepted TOTP time step per credential."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261005_09"
down_revision: str | None = "20261005_08"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add nullable replay state to encrypted MFA credentials."""
    op.add_column(
        "mfa_credentials",
        sa.Column("last_accepted_time_step", sa.BigInteger(), nullable=True),
        schema="public",
    )


def downgrade() -> None:
    """Remove TOTP replay state."""
    op.drop_column("mfa_credentials", "last_accepted_time_step", schema="public")
