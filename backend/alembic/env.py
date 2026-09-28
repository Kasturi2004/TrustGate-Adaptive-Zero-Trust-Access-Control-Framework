"""Async Alembic environment.

The connection comes from application settings. No TrustGate metadata is
registered yet, so commands apply no application schema.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from app.core.config import get_settings
from app.db.models import target_metadata
from app.db.session import create_migration_engine, prepare_database_url, require_migration_url
from sqlalchemy.engine import Connection

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    """Render SQL without opening a connection."""
    url, _connect_args = prepare_database_url(require_migration_url(get_settings()))
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = create_migration_engine(get_settings())
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
