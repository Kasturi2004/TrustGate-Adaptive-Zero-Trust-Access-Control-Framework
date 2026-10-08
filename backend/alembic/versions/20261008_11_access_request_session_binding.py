"""Bind access requests to their creating authentication session."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261008_11"
down_revision: str | None = "20261008_10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "access_requests",
        sa.Column("auth_session_id", sa.UUID(), nullable=True),
        schema="public",
    )


def downgrade() -> None:
    op.drop_column("access_requests", "auth_session_id", schema="public")
