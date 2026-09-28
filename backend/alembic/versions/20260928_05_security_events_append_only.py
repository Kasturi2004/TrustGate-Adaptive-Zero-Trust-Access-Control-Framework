"""Enforce append-only behavior for security events."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260928_05"
down_revision: str | None = "20260928_04"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Protect security events and enforce its reviewed runtime privileges."""
    op.execute("REVOKE ALL PRIVILEGES ON TABLE public.security_events FROM trustgate_app")
    op.execute("GRANT SELECT, INSERT ON TABLE public.security_events TO trustgate_app")
    op.execute(
        """
        CREATE FUNCTION public.reject_security_event_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
            IF TG_OP = 'UPDATE' THEN
                RAISE EXCEPTION
                    'security_events is append-only: % is not permitted', TG_OP;
                RETURN NEW;
            ELSIF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION
                    'security_events is append-only: % is not permitted', TG_OP;
                RETURN OLD;
            END IF;

            RETURN NEW;
        END;
        $function$
        """
    )
    op.execute("REVOKE EXECUTE ON FUNCTION public.reject_security_event_mutation() FROM PUBLIC")
    op.execute(
        """
        CREATE TRIGGER trg_security_events_append_only
        BEFORE UPDATE OR DELETE ON public.security_events
        FOR EACH ROW
        EXECUTE FUNCTION public.reject_security_event_mutation()
        """
    )


def downgrade() -> None:
    """Remove append-only protection and restore the prior runtime privileges."""
    op.execute("DROP TRIGGER trg_security_events_append_only ON public.security_events")
    op.execute("DROP FUNCTION public.reject_security_event_mutation()")
    op.execute("REVOKE ALL PRIVILEGES ON TABLE public.security_events FROM trustgate_app")
    op.execute("GRANT SELECT, INSERT ON TABLE public.security_events TO trustgate_app")
