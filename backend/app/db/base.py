"""Declarative base, shared column types and mixins."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, ClassVar

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Deterministic constraint names so Alembic autogenerate produces stable migrations
# and downgrades can actually find the objects they need to drop.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_N_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Every JSON column in CYBERTRACE is JSONB: it is indexable, deduplicates keys and
# rejects invalid documents at write time rather than at read time.
JsonDict = JSONB


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map: ClassVar[dict[Any, Any]] = {
        dict[str, Any]: JSONB,
        list[Any]: JSONB,
    }

    def __repr__(self) -> str:
        ident = getattr(self, "id", None)
        ref = getattr(self, "reference", None)
        label = f" {ref}" if ref else ""
        return f"<{type(self).__name__}{label} {ident}>"


class UUIDPrimaryKey:
    """UUID primary keys, generated client-side.

    Client-side generation matters here: services need the identifier *before* the row is
    flushed so that a custody event and its hash-chain payload can reference the evidence
    they describe within a single transaction.
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class CreatedAtMixin:
    """For append-only tables, which by definition are never updated."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
