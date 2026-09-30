"""Relationship-graph projection shapes.

The graph the interface draws is a projection of persisted entities and edges, not a live
inference. Centrality is computed server-side so the client can highlight pivots without
reimplementing the maths, and so two investigators looking at the same case see the same
ranking.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models.enums import EntityType
from app.schemas.common import EvidenceRef


class GraphNodeOut(BaseModel):
    id: str
    kind: Literal["entity", "evidence", "case"]
    label: str
    sublabel: str | None = None
    entity_type: EntityType | None = None
    evidence_id: uuid.UUID | None = None
    case_id: uuid.UUID | None = None
    occurrence_count: int = 0
    document_frequency: int = 0
    intel_severity: str | None = None
    degree_centrality: float = 0.0
    betweenness_centrality: float = 0.0
    pagerank: float = 0.0
    is_pivot: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)


class GraphEdgeOut(BaseModel):
    id: str
    source: str
    target: str
    kind: str
    label: str
    weight: float = 1.0
    score: float | None = None
    is_cross_case: bool = False
    basis: dict[str, Any] = Field(default_factory=dict)
    supporting_evidence: list[EvidenceRef] = Field(default_factory=list)


class GraphProjectionOut(BaseModel):
    case_id: uuid.UUID | None
    depth: int
    node_count: int
    edge_count: int
    pivot_node_ids: list[str]
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]
    layout_hint: Literal["cose", "concentric", "breadthfirst"] = "cose"
    computed_from: str
