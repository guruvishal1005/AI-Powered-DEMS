"""Demo scenario generator.

This seeder does not insert fake analysis rows. It creates four users, three linked cases,
and a set of *real files* (valid ``.eml``, syslog, nginx, JPEG with EXIF GPS, PDF, netflow
CSV, zip), then drives the same ingestion, analysis, correlation and intelligence path the
API uses. Cross-case links therefore exist because the artifacts actually share indicators.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.logging import configure_logging, get_logger
from app.db.session import session_scope
from app.models.enums import RoleSlug
from app.models.user import Role, User
from app.security.bootstrap import sync_permissions
from app.security.crypto import hash_password
from app.seed import artifacts, intel, scenarios

logger = get_logger(__name__)

DEMO_PASSWORD = "Investigate!2026"

USERS: tuple[dict[str, str], ...] = (
    {
        "email": "admin@cybertrace.gov",
        "full_name": "Priya Nair",
        "role": RoleSlug.administrator.value,
        "job_title": "Platform Administrator",
        "badge_number": "ADM-001",
    },
    {
        "email": "r.mehta@cybertrace.gov",
        "full_name": "Rohan Mehta",
        "role": RoleSlug.investigator.value,
        "job_title": "Lead Investigator",
        "badge_number": "INV-0142",
    },
    {
        "email": "s.iyer@cybertrace.gov",
        "full_name": "Sana Iyer",
        "role": RoleSlug.forensic_analyst.value,
        "job_title": "Forensic Analyst",
        "badge_number": "FA-0088",
    },
    {
        "email": "audit@cybertrace.gov",
        "full_name": "Marcus Hale",
        "role": RoleSlug.auditor.value,
        "job_title": "Compliance Auditor",
        "badge_number": "AUD-0004",
    },
)


def seed(session: Session) -> dict[str, str]:
    configure_logging()
    sync_permissions(session)
    users = _ensure_users(session)
    investigator = users["r.mehta@cybertrace.gov"]
    analyst = users["s.iyer@cybertrace.gov"]
    ctx = RequestContext.for_user(
        investigator,
        permissions=investigator.permission_codes,
        ip_address="127.0.0.1",
        user_agent="cybertrace-seeder",
    )
    intel.seed_indicators(session)
    files = artifacts.generate_all()
    created = scenarios.ingest_scenarios(session, ctx, investigator, analyst, files)
    logger.info("seed_complete", cases=created)
    return created


def _ensure_users(session: Session) -> dict[str, User]:
    roles = {role.slug: role for role in session.execute(select(Role)).scalars()}
    users: dict[str, User] = {}
    for spec in USERS:
        existing = session.execute(
            select(User).where(User.email == spec["email"])
        ).scalar_one_or_none()
        if existing is not None:
            users[spec["email"]] = existing
            continue
        user = User(
            email=spec["email"],
            full_name=spec["full_name"],
            password_hash=hash_password(DEMO_PASSWORD),
            job_title=spec["job_title"],
            badge_number=spec["badge_number"],
            department="Cybercrime Division",
            must_change_password=False,
        )
        user.roles.append(roles[spec["role"]])
        if spec["role"] == RoleSlug.administrator.value:
            user.is_superuser = True
        session.add(user)
        session.flush()
        users[spec["email"]] = user
        logger.info("seed_user_created", email=user.email, role=spec["role"])
    return users


def main() -> None:
    configure_logging()
    with session_scope() as session:
        seed(session)
        # session_scope commits.


if __name__ == "__main__":
    main()
