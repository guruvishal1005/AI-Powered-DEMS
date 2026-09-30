"""Test fixtures.

Tests run against a real PostgreSQL database rather than SQLite, because the behaviour that
matters most here is PostgreSQL-specific: JSONB columns, partial unique indexes, advisory
locks, ``FOR UPDATE SKIP LOCKED`` and the append-only triggers. A SQLite substitute would
verify none of it.

Isolation is by transaction rollback, not by deletion. Each test runs inside an outer
transaction that is rolled back at teardown, which is both fast and the only approach
compatible with tables whose triggers refuse ``DELETE`` and ``TRUNCATE``.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest

# Must be set before app.core.config is imported anywhere.
os.environ.setdefault("CYBERTRACE_ENV", "test")
os.environ.setdefault(
    "CYBERTRACE_DATABASE_URL",
    "postgresql+psycopg://cybertrace:cybertrace_dev_password@localhost:5433/cybertrace_test",
)
os.environ.setdefault("CYBERTRACE_WORKER_ENABLED", "false")

from fastapi.testclient import TestClient
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.audit.writer import append_audit
from app.core.config import settings
from app.core.context import RequestContext
from app.db.session import get_db
from app.models.enums import AuditResult, RoleSlug
from app.models.user import Role, User
from app.security.bootstrap import sync_permissions
from app.security.crypto import hash_password

TEST_PASSWORD = "Investigate!2026"


def _admin_url() -> str:
    """Connection URL for the maintenance database, used to create the test database."""
    return settings.database_url.rsplit("/", 1)[0] + "/postgres"


def _test_database_name() -> str:
    return settings.database_url.rsplit("/", 1)[1]


@pytest.fixture(scope="session", autouse=True)
def _prepare_database() -> Iterator[None]:
    """Create the test database and build its schema from the migrations."""
    admin_engine = create_engine(_admin_url(), isolation_level="AUTOCOMMIT")
    name = _test_database_name()
    with admin_engine.connect() as conn:
        exists = conn.execute(
            text("select 1 from pg_database where datname = :name"), {"name": name}
        ).scalar()
        if not exists:
            conn.execute(text(f'create database "{name}"'))
    admin_engine.dispose()

    from alembic import command
    from alembic.config import Config

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", settings.database_url)
    # Rebuild from scratch so a schema change can never be masked by a stale test database.
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    yield


@pytest.fixture(scope="session")
def engine(_prepare_database):
    engine = create_engine(settings.database_url, pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def _reference_data(engine) -> None:
    """Permissions and roles, created once because they are immutable during a run."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        sync_permissions(session)
        session.commit()


@pytest.fixture
def connection(engine, _reference_data) -> Iterator[Connection]:
    conn = engine.connect()
    transaction = conn.begin()
    try:
        yield conn
    finally:
        transaction.rollback()
        conn.close()


@pytest.fixture
def db(connection: Connection) -> Iterator[Session]:
    """A session bound to the test transaction.

    ``join_transaction_mode="create_savepoint"`` lets application code call ``commit()``
    normally - it becomes a savepoint release inside the outer transaction, so services under
    test behave exactly as they do in production while the test still rolls everything back.
    """
    factory = sessionmaker(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    session = factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def _denials_share_the_test_transaction(db: Session, monkeypatch) -> None:
    """Write access-denied audit rows on the test session.

    Production records denials on a separate connection so they survive the request rollback.
    That second connection cannot take the audit-chain advisory lock while the test
    transaction still holds it, so denials would hang under pytest. Routing them onto the
    rolled-back test session preserves the record for assertions without leaking rows.
    """
    from fastapi import Request

    from app.models.enums import Permission

    def record(ctx: RequestContext, request: Request, missing: tuple[Permission, ...]) -> None:
        append_audit(
            db,
            ctx,
            action="access.denied",
            resource_type="endpoint",
            resource_id=request.url.path,
            resource_label=f"{request.method} {request.url.path}",
            result=AuditResult.denied,
            detail="missing permission(s): " + ", ".join(p.value for p in missing),
            http_method=request.method,
            http_path=str(request.url.path),
            status_code=403,
        )
        db.flush()

    monkeypatch.setattr("app.security.deps._record_denial", record)


@pytest.fixture
def client(db: Session) -> Iterator[TestClient]:
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    # Bypass lifespan: the worker and permission sync are handled by fixtures instead.
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client
    app.dependency_overrides.clear()


def make_user(
    db: Session,
    *,
    role: RoleSlug,
    email: str | None = None,
    full_name: str | None = None,
    password: str = TEST_PASSWORD,
) -> User:
    """Create an active user holding exactly one role."""
    from sqlalchemy import select

    role_row = db.execute(select(Role).where(Role.slug == role.value)).scalar_one()
    user = User(
        email=email or f"{role.value}-{uuid.uuid4().hex[:8]}@cybertrace.gov",
        full_name=full_name or role.value.replace("_", " ").title(),
        password_hash=hash_password(password),
        job_title=role.value.replace("_", " ").title(),
    )
    user.roles.append(role_row)
    db.add(user)
    db.flush()
    return user


def context_for(user: User) -> RequestContext:
    return RequestContext.for_user(
        user, permissions=user.permission_codes, ip_address="127.0.0.1", user_agent="pytest"
    )


@pytest.fixture
def storage_root(tmp_path, monkeypatch) -> Iterator[object]:
    """Point evidence storage at a temporary directory for the duration of one test.

    Evidence is encrypted at rest, so what lands here is ciphertext; the directory is still
    isolated per test because ingestion is content-addressed and a shared root would let one
    test's object satisfy another's deduplication check.
    """
    from app.storage.local import reset_storage

    root = tmp_path / "evidence-store"
    monkeypatch.setattr(settings, "storage_root", str(root))
    reset_storage()
    yield root
    reset_storage()


@pytest.fixture
def investigator(db: Session) -> User:
    return make_user(db, role=RoleSlug.investigator, email="investigator@cybertrace.gov")


@pytest.fixture
def analyst(db: Session) -> User:
    return make_user(db, role=RoleSlug.forensic_analyst, email="analyst@cybertrace.gov")


@pytest.fixture
def auditor(db: Session) -> User:
    return make_user(db, role=RoleSlug.auditor, email="auditor@cybertrace.gov")


@pytest.fixture
def administrator(db: Session) -> User:
    return make_user(db, role=RoleSlug.administrator, email="administrator@cybertrace.gov")


def login(client: TestClient, email: str, password: str = TEST_PASSWORD) -> str:
    """Sign in and return the access token, leaving cookies set on the client."""
    response = client.post(
        f"{settings.api_prefix}/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
