from decimal import Decimal
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase

BACKEND_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_WEIGHTS = {
    "device_familiarity": 0.35,
    "device_health": 0.30,
    "location_normality": 0.20,
    "time_normality": 0.15,
}


def test_seed_migration_uses_exact_values_and_label_only_downgrade() -> None:
    migration = (BACKEND_ROOT / "alembic" / "versions" / "20260928_06_seed_pol_1_0.py").read_text(
        encoding="utf-8"
    )
    upgrade, downgrade = migration.split("def downgrade()", maxsplit=1)
    upgrade = upgrade.replace("\\\\:", ":")

    assert "INSERT INTO public.policy_versions" in upgrade
    assert "'POL-1.0'" in upgrade
    assert (
        '{"device_familiarity":0.35,"device_health":0.30,'
        '"location_normality":0.20,"time_normality":0.15}'
    ) in upgrade
    assert "70.00" in upgrade
    assert "40.00" in upgrade
    assert "true" in upgrade
    assert "ON CONFLICT" not in upgrade
    assert "UPDATE public.policy_versions" not in upgrade
    assert "DELETE FROM public.policy_versions WHERE version_label = 'POL-1.0'" in downgrade
    assert "DROP TABLE" not in downgrade


def test_applied_policy_seed_and_schema(migrated_test_database: ScratchDatabase) -> None:
    async def inspect_database(session: AsyncSession) -> dict[str, object]:
        rows = (
            (
                await session.execute(
                    text(
                        """
                    SELECT version_label, weights_json, allow_threshold,
                           stepup_threshold, is_active
                    FROM public.policy_versions
                    WHERE version_label = 'POL-1.0'
                    """
                    )
                )
            )
            .mappings()
            .all()
        )
        policy_count = await session.scalar(
            text("SELECT count(*) FROM public.policy_versions WHERE version_label = 'POL-1.0'")
        )
        active_count = await session.scalar(
            text(
                "SELECT count(*) FROM public.policy_versions "
                "WHERE version_label = 'POL-1.0' AND is_active"
            )
        )
        columns = (
            await session.execute(
                text(
                    """
                    SELECT column_name, data_type, numeric_precision, numeric_scale,
                           is_nullable, column_default
                    FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'policy_versions'
                    ORDER BY ordinal_position
                    """
                )
            )
        ).all()
        unique_version_label = await session.scalar(
            text(
                """
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.table_constraints
                    WHERE table_schema = 'public' AND table_name = 'policy_versions'
                      AND constraint_type = 'UNIQUE'
                      AND constraint_name = 'uq_policy_versions_version_label'
                )
                """
            )
        )
        active_index = await session.scalar(
            text(
                """
                SELECT indexdef FROM pg_indexes
                WHERE schemaname = 'public' AND tablename = 'policy_versions'
                  AND indexname = 'idx_policy_versions_one_active'
                """
            )
        )
        return {
            "rows": [dict(row) for row in rows],
            "policy_count": policy_count,
            "active_count": active_count,
            "columns": [tuple(column) for column in columns],
            "unique_version_label": unique_version_label,
            "active_index": active_index,
        }

    state = migrated_test_database.run_in_transaction(inspect_database)

    assert state["rows"] == [
        {
            "version_label": "POL-1.0",
            "weights_json": EXPECTED_WEIGHTS,
            "allow_threshold": Decimal("70.00"),
            "stepup_threshold": Decimal("40.00"),
            "is_active": True,
        }
    ]
    assert state["policy_count"] == 1
    assert state["active_count"] == 1
    assert state["columns"] == [
        ("id", "uuid", None, None, "NO", "gen_random_uuid()"),
        ("version_label", "text", None, None, "NO", None),
        ("weights_json", "jsonb", None, None, "NO", None),
        ("allow_threshold", "numeric", 5, 2, "NO", "70.00"),
        ("stepup_threshold", "numeric", 5, 2, "NO", "40.00"),
        ("is_active", "boolean", None, None, "NO", "false"),
        ("created_at", "timestamp with time zone", None, None, "NO", "now()"),
    ]
    assert state["unique_version_label"] is True
    assert (
        state["active_index"]
        == "CREATE UNIQUE INDEX idx_policy_versions_one_active ON public.policy_versions "
        "USING btree (is_active) WHERE is_active"
    )
