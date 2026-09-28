"""Create the profile timestamp and Supabase Auth profile triggers."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260928_04"
down_revision: str | None = "20260928_03"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the profile timestamp trigger and Auth-to-profile signup trigger."""
    op.execute(
        """
        CREATE FUNCTION public.set_updated_at()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
            NEW.updated_at := pg_catalog.now();
            RETURN NEW;
        END;
        $function$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION public.set_updated_at() FROM PUBLIC")
    op.execute(
        """
        CREATE TRIGGER trg_profiles_updated_at
        BEFORE UPDATE ON public.profiles
        FOR EACH ROW
        EXECUTE FUNCTION public.set_updated_at()
        """
    )

    op.execute(
        """
        CREATE FUNCTION public.handle_new_auth_user()
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
    op.execute("REVOKE ALL ON FUNCTION public.handle_new_auth_user() FROM PUBLIC")
    op.execute(
        """
        CREATE TRIGGER on_auth_user_created
        AFTER INSERT ON auth.users
        FOR EACH ROW
        EXECUTE FUNCTION public.handle_new_auth_user()
        """
    )


def downgrade() -> None:
    """Remove only the triggers and functions created by this revision."""
    op.execute("DROP TRIGGER on_auth_user_created ON auth.users")
    op.execute("DROP TRIGGER trg_profiles_updated_at ON public.profiles")
    op.execute("DROP FUNCTION public.handle_new_auth_user()")
    op.execute("DROP FUNCTION public.set_updated_at()")
