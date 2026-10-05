"""Allow TOTP challenges that do not store an OTP hash."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261005_08"
down_revision: str | None = "20261004_07"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Make the unused OTP hash nullable for TOTP challenges."""
    op.alter_column(
        "otp_challenges",
        "otp_hash",
        existing_type=sa.Text(),
        nullable=True,
        schema="public",
    )


def downgrade() -> None:
    """Restore the required hash; this fails while null-hash TOTP rows exist."""
    op.alter_column(
        "otp_challenges",
        "otp_hash",
        existing_type=sa.Text(),
        nullable=False,
        schema="public",
    )
