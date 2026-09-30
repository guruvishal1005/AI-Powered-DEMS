"""Synchronise the permission catalogue and default roles into the database.

Runs at startup. The reconciliation rules are chosen so that a deployment never silently
discards an administrator's decisions:

* **Permissions** are fully reconciled with :data:`PERMISSION_CATALOG`. They are a vocabulary
  defined by the code, so a permission the code no longer knows about is removed.
* **Roles** are created if absent, but an existing role's permission set is left untouched.
  If an administrator has deliberately removed ``evidence:download`` from investigators, a
  redeploy must not hand it back.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.user import PermissionRecord, Role
from app.security.permissions import PERMISSION_CATALOG, ROLE_DEFINITIONS

logger = get_logger(__name__)


@dataclass(slots=True)
class BootstrapReport:
    permissions_created: int = 0
    permissions_updated: int = 0
    permissions_removed: int = 0
    roles_created: int = 0


def sync_permissions(session: Session) -> BootstrapReport:
    report = BootstrapReport()

    existing = {
        record.code: record for record in session.execute(select(PermissionRecord)).scalars().all()
    }
    catalog_codes = set()

    for spec in PERMISSION_CATALOG:
        code = spec.code.value
        catalog_codes.add(code)
        record = existing.get(code)
        if record is None:
            session.add(
                PermissionRecord(
                    code=code,
                    category=spec.category,
                    label=spec.label,
                    description=spec.description,
                    is_sensitive=spec.is_sensitive,
                )
            )
            report.permissions_created += 1
            continue

        if (
            record.category != spec.category
            or record.label != spec.label
            or record.description != spec.description
            or record.is_sensitive != spec.is_sensitive
        ):
            record.category = spec.category
            record.label = spec.label
            record.description = spec.description
            record.is_sensitive = spec.is_sensitive
            report.permissions_updated += 1

    for code, record in existing.items():
        if code not in catalog_codes:
            session.delete(record)
            report.permissions_removed += 1

    session.flush()

    permission_by_code = {
        record.code: record for record in session.execute(select(PermissionRecord)).scalars().all()
    }
    existing_roles = {role.slug: role for role in session.execute(select(Role)).scalars().all()}

    for role_spec in ROLE_DEFINITIONS:
        role = existing_roles.get(role_spec.slug.value)
        if role is None:
            role = Role(
                slug=role_spec.slug.value,
                name=role_spec.name,
                description=role_spec.description,
                is_system=True,
                rank=role_spec.rank,
            )
            role.permissions = [
                permission_by_code[permission.value]
                for permission in role_spec.permissions
                if permission.value in permission_by_code
            ]
            session.add(role)
            report.roles_created += 1
        else:
            # Descriptive metadata may be refreshed; the grant set belongs to the operator.
            role.name = role_spec.name
            role.description = role_spec.description
            role.is_system = True
            role.rank = role_spec.rank

    session.flush()
    logger.info(
        "permission_sync_complete",
        permissions_created=report.permissions_created,
        permissions_updated=report.permissions_updated,
        permissions_removed=report.permissions_removed,
        roles_created=report.roles_created,
    )
    return report
