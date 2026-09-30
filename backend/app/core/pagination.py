"""Offset pagination shared by every list endpoint."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import Query
from pydantic import BaseModel, Field
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

MAX_PAGE_SIZE = 200


@dataclass(frozen=True, slots=True)
class PageParams:
    page: int
    size: int

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.size


def page_params(
    page: int = Query(1, ge=1, description="1-based page number"),
    size: int = Query(25, ge=1, le=MAX_PAGE_SIZE, description="Items per page"),
) -> PageParams:
    return PageParams(page=page, size=size)


class PageMeta(BaseModel):
    page: int
    size: int
    total: int
    pages: int
    has_next: bool
    has_previous: bool


class Page[T](BaseModel):
    items: list[T]
    meta: PageMeta

    @classmethod
    def build(cls, items: list[T], total: int, params: PageParams) -> Page[T]:
        pages = max(1, -(-total // params.size))  # ceiling division
        return cls(
            items=items,
            meta=PageMeta(
                page=params.page,
                size=params.size,
                total=total,
                pages=pages,
                has_next=params.page < pages,
                has_previous=params.page > 1,
            ),
        )


class SortSpec(BaseModel):
    field: str = Field(description="Sortable column name")
    descending: bool = False


def paginate(
    session: Session,
    stmt: Select[tuple[Any, ...]],
    params: PageParams,
) -> tuple[list[Any], int]:
    """Execute ``stmt`` for one page and return ``(rows, total)``.

    The count is derived from the same statement with ordering stripped, so filters and
    authorization scoping can never drift between the page and its total.
    """
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = session.execute(count_stmt).scalar_one()
    rows = list(session.execute(stmt.limit(params.size).offset(params.offset)).scalars().unique())
    return rows, total
