"""Track one-time consumption of approved access requests."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261008_10"
down_revision: str | None = "20261005_09"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "access_requests",
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        schema="public",
    )


def downgrade() -> None:
    op.drop_column("access_requests", "consumed_at", schema="public")
