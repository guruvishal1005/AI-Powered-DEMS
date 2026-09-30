"""Relationship graph projection."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.db.session import get_db
from app.models.enums import Permission
from app.schemas.graph import GraphProjectionOut
from app.security.deps import require
from app.services import graph_service

router = APIRouter(tags=["graph"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("/graph", response_model=GraphProjectionOut, summary="Relationship graph")
def get_graph(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    case_id: uuid.UUID | None = None,
    seed_entity_id: uuid.UUID | None = None,
    depth: Annotated[int, Query(ge=1, le=4)] = 2,
    min_score: Annotated[float, Query(ge=0.0, le=1.0)] = 0.15,
    include_evidence_nodes: bool = True,
    max_nodes: Annotated[int, Query(ge=20, le=500)] = 250,
) -> GraphProjectionOut:
    return GraphProjectionOut.model_validate(
        graph_service.project(
            db,
            ctx,
            case_id=case_id,
            seed_entity_id=seed_entity_id,
            depth=depth,
            min_score=min_score,
            include_evidence_nodes=include_evidence_nodes,
            max_nodes=max_nodes,
        )
    )
