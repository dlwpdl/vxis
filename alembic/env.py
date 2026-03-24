"""Alembic environment configuration for VXIS (async SQLAlchemy).

This module is executed by Alembic whenever a migration command is run.
It supports both online (connected) and offline (SQL-script) modes, and
uses ``run_async`` for the online path so that migrations work with the
async ``aiosqlite`` / ``asyncpg`` drivers used by VXIS.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Import the ORM Base so Alembic can inspect the target metadata.
from vxis.models.db_models import Base

# Alembic Config object — provides access to values in alembic.ini.
config = context.config

# Set up Python logging from the config file section.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# MetaData object used for 'autogenerate' support.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Generates SQL scripts without connecting to the database.  Useful for
    reviewing migration SQL before applying it.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Configure and run migrations within a synchronous connection."""
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and run migrations inside a connection."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode using an async engine."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
