"""Async database engine factory and session management for VXIS.

Provides a thin layer over SQLAlchemy's async API with SQLite-optimised
PRAGMA configuration applied via an event listener.  The same interface
works transparently with any SQLAlchemy-compatible async URL (e.g. asyncpg
for PostgreSQL), though the SQLite PRAGMAs are only emitted for SQLite
connections.

Usage::

    engine = create_engine("sqlite+aiosqlite:///vxis.db")
    await init_db(engine)

    async with get_session(engine) as session:
        scan = ScanRecord(target="10.0.0.1", profile="quick", status="pending")
        session.add(scan)
        await session.commit()
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from vxis.models.db_models import Base


def create_engine(db_url: str) -> AsyncEngine:
    """Create and configure an async SQLAlchemy engine.

    For SQLite databases the following PRAGMAs are applied on every new
    connection to maximise concurrent throughput and durability:

    * ``journal_mode = WAL``  — write-ahead logging for concurrent reads.
    * ``synchronous = NORMAL`` — fsync only at WAL checkpoints (safe + fast).
    * ``cache_size = -65536``  — 64 MB page cache (negative = KiB).
    * ``busy_timeout = 5000``  — wait up to 5 s before raising SQLITE_BUSY.

    Args:
        db_url: SQLAlchemy async database URL, e.g.
                ``"sqlite+aiosqlite:///path/to/vxis.db"`` or
                ``"postgresql+asyncpg://user:pw@host/db"``.

    Returns:
        A configured :class:`~sqlalchemy.ext.asyncio.AsyncEngine` instance.
    """
    engine = create_async_engine(db_url, future=True)

    if db_url.startswith("sqlite"):
        # SQLite connection-level PRAGMAs must be set on the sync connection
        # that lives inside the async driver.  The 'connect' event fires once
        # per physical connection (before the connection is handed to the pool).
        @event.listens_for(engine.sync_engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn: object, _connection_record: object) -> None:
            cursor = dbapi_conn.cursor()  # type: ignore[union-attr]
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA cache_size=-65536")   # 64 MB
            cursor.execute("PRAGMA busy_timeout=5000")   # 5 seconds
            cursor.close()

    return engine


async def init_db(engine: AsyncEngine) -> None:
    """Create all ORM-defined tables if they do not already exist.

    This is idempotent — calling it on a database that already has all
    tables is a no-op.

    Args:
        engine: The async engine returned by :func:`create_engine`.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@asynccontextmanager
async def get_session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Async context manager that yields a transactional :class:`AsyncSession`.

    The session is automatically committed on normal exit and rolled back on
    exception.  The session is always closed when the context manager exits.

    Args:
        engine: The async engine returned by :func:`create_engine`.

    Yields:
        An :class:`~sqlalchemy.ext.asyncio.AsyncSession` bound to *engine*.

    Example::

        async with get_session(engine) as session:
            session.add(my_record)
            # commit happens automatically on __aexit__
    """
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
