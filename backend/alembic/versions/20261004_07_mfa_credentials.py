"""Add encrypted TOTP credential persistence."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261004_07"
down_revision: str | None = "20260928_06"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the private per-profile MFA credential table."""
    op.create_table(
        "mfa_credentials",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
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
        sa.CheckConstraint(
            "NOT enabled OR verified_at IS NOT NULL",
            name="ck_mfa_credentials_enabled_requires_verified",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["public.profiles.id"],
            ondelete="CASCADE",
            name="fk_mfa_credentials_user_id_profiles",
        ),
        sa.PrimaryKeyConstraint("user_id", name="pk_mfa_credentials"),
        schema="public",
    )
    op.execute("ALTER TABLE public.mfa_credentials ENABLE ROW LEVEL SECURITY")
    op.execute("REVOKE ALL PRIVILEGES ON TABLE public.mfa_credentials FROM anon, authenticated")
    op.execute("REVOKE ALL PRIVILEGES ON TABLE public.mfa_credentials FROM trustgate_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON TABLE public.mfa_credentials TO trustgate_app")
    op.execute(
        """
        CREATE TRIGGER trg_mfa_credentials_updated_at
        BEFORE UPDATE ON public.mfa_credentials
        FOR EACH ROW
        EXECUTE FUNCTION public.set_updated_at()
        """
    )


def downgrade() -> None:
    """Remove the MFA credential table and its timestamp trigger."""
    op.execute("DROP TRIGGER trg_mfa_credentials_updated_at ON public.mfa_credentials")
    op.drop_table("mfa_credentials", schema="public")
