"""Engine and session management.

CYBERTRACE uses synchronous SQLAlchemy deliberately. The workload is dominated by
CPU-bound forensic work (streaming SHA-256, AES-GCM, parsing) rather than by high-
concurrency socket fan-out, and FastAPI already runs ``def`` endpoints in a worker
threadpool. Staying synchronous removes greenlet/async-context hazards from the paths
where correctness matters most: hashing, encryption and hash-chain appends.
"""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

engine: Engine = create_engine(
    settings.database_url,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,
    pool_recycle=1800,
    echo=settings.db_echo,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    class_=Session,
)


@event.listens_for(engine, "connect")
def _configure_connection(dbapi_connection: object, _record: object) -> None:
    """Apply per-connection guarantees.

    A statement timeout stops a pathological analysis query from pinning a connection
    forever; UTC keeps every timestamp comparison unambiguous regardless of host locale.
    """
    with dbapi_connection.cursor() as cursor:  # type: ignore[attr-defined]
        cursor.execute("SET TIME ZONE 'UTC'")
        cursor.execute("SET statement_timeout = '60s'")
        cursor.execute("SET idle_in_transaction_session_timeout = '120s'")


def get_db() -> Generator[Session]:
    """FastAPI dependency yielding a request-scoped session.

    The session is rolled back on any exception so a failed request can never leave a
    partially applied change, which for chained custody records would break verification.
    """
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session for worker tasks, seeding and scripts."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
