"""Require authenticator setup for newly created Auth users."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261013_12"
down_revision: str | None = "20261008_11"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Mark new Supabase identities for mandatory TOTP onboarding."""
    op.add_column(
        "profiles",
        sa.Column(
            "authenticator_required",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        schema="public",
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
            INSERT INTO public.profiles (id, email, role, authenticator_required)
            VALUES (NEW.id, NEW.email, 'USER', true);
            RETURN NEW;
        END;
        $function$
        """
    )


def downgrade() -> None:
    """Restore the original profile trigger and remove the onboarding marker."""
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
            INSERT INTO public.profiles (id, email, role)
            VALUES (NEW.id, NEW.email, 'USER');
            RETURN NEW;
        END;
        $function$
        """
    )
    op.drop_column("profiles", "authenticator_required", schema="public")
