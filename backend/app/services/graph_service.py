"""Relationship graph projection.

Nodes and edges are read from persisted analysis, then ranked with networkx so the interface
can highlight pivots without inventing its own topology. Depth is a BFS from the seed set
(every entity in the case, or a supplied entity) rather than "show everything", because a
corpus-wide graph is unreadable and would leak cases the caller cannot see.
"""

from __future__ import annotations

import uuid
from collections import defaultdict, deque
from typing import Any

import networkx as nx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.models.analysis import CorrelationEdge, Entity, EntityOccurrence, EntityRelationship
from app.models.evidence import Evidence
from app.security.scoping import accessible_case_ids, has_global_case_access, scope_case_ids
from app.services import case_service


def project(
    db: Session,
    ctx: RequestContext,
    *,
    case_id: uuid.UUID | None = None,
    seed_entity_id: uuid.UUID | None = None,
    depth: int = 2,
    min_score: float = 0.15,
    include_evidence_nodes: bool = True,
    entity_types: list[str] | None = None,
    max_nodes: int = 250,
) -> dict[str, Any]:
    if case_id is not None:
        case_service.require_case_access(db, ctx, case_id)
    depth = max(1, min(depth, 4))

    seed_ids = _seed_entities(db, ctx, case_id=case_id, seed_entity_id=seed_entity_id)
    if entity_types:
        typed = db.execute(
            select(Entity.id).where(Entity.id.in_(seed_ids)).where(Entity.type.in_(entity_types))
        ).scalars()
        seed_ids = set(typed)
    if not seed_ids:
        return _empty(case_id, depth)

    relationships = _load_relationships(db, seed_ids)
    reachable = _bfs(seed_ids, relationships, depth)
    if len(reachable) > max_nodes:
        # Prefer seeds, then high-degree neighbours, so truncation does not drop the
        # investigative centre of the graph.
        reachable = _cap(reachable, relationships, seed_ids, max_nodes)

    entities = {
        entity.id: entity
        for entity in db.execute(select(Entity).where(Entity.id.in_(reachable))).scalars()
    }

    graph = nx.Graph()
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    for entity_id, entity in entities.items():
        node_id = f"entity:{entity_id}"
        graph.add_node(node_id)
        nodes[node_id] = {
            "id": node_id,
            "kind": "entity",
            "label": entity.display_value,
            "sublabel": entity.type.value,
            "entity_type": entity.type,
            "occurrence_count": entity.occurrence_count,
            "document_frequency": entity.document_frequency,
            "intel_severity": entity.intel_severity.value if entity.intel_severity else None,
            "attributes": entity.attributes or {},
        }

    for rel in relationships:
        if rel.source_entity_id not in reachable or rel.target_entity_id not in reachable:
            continue
        source = f"entity:{rel.source_entity_id}"
        target = f"entity:{rel.target_entity_id}"
        graph.add_edge(source, target, weight=rel.weight)
        edges.append(
            {
                "id": f"rel:{rel.id}",
                "source": source,
                "target": target,
                "kind": rel.relation,
                "label": rel.relation.replace("_", " "),
                "weight": rel.weight,
                "score": None,
                "is_cross_case": False,
                "basis": {"observation_count": rel.observation_count},
                "supporting_evidence": [],
            }
        )

    evidence_nodes, correlation_edges = _correlation_layer(
        db,
        ctx,
        case_id=case_id,
        entity_ids=reachable,
        min_score=min_score,
        include_evidence_nodes=include_evidence_nodes,
    )
    for node_id, payload in evidence_nodes.items():
        graph.add_node(node_id)
        nodes[node_id] = payload
    for edge in correlation_edges:
        graph.add_edge(edge["source"], edge["target"], weight=edge.get("score") or 1.0)
        edges.append(edge)

    degree = nx.degree_centrality(graph) if graph.number_of_nodes() else {}
    betweenness = (
        nx.betweenness_centrality(graph, normalized=True) if graph.number_of_nodes() > 2 else {}
    )
    pagerank = nx.pagerank(graph) if graph.number_of_edges() else {}

    ranked = sorted(degree.items(), key=lambda item: item[1], reverse=True)
    pivot_ids = [node_id for node_id, _ in ranked[: min(8, len(ranked))]]

    for node_id, payload in nodes.items():
        payload["degree_centrality"] = round(degree.get(node_id, 0.0), 6)
        payload["betweenness_centrality"] = round(betweenness.get(node_id, 0.0), 6)
        payload["pagerank"] = round(pagerank.get(node_id, 0.0), 6)
        payload["is_pivot"] = node_id in pivot_ids

    return {
        "case_id": case_id,
        "depth": depth,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "pivot_node_ids": pivot_ids,
        "nodes": list(nodes.values()),
        "edges": edges,
        "layout_hint": "cose" if len(nodes) > 12 else "concentric",
        "computed_from": "entity_relationships+correlation_edges+networkx",
    }


def _empty(case_id: uuid.UUID | None, depth: int) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "depth": depth,
        "node_count": 0,
        "edge_count": 0,
        "pivot_node_ids": [],
        "nodes": [],
        "edges": [],
        "layout_hint": "cose",
        "computed_from": "entity_relationships+correlation_edges+networkx",
    }


def _seed_entities(
    db: Session,
    ctx: RequestContext,
    *,
    case_id: uuid.UUID | None,
    seed_entity_id: uuid.UUID | None,
) -> set[uuid.UUID]:
    if seed_entity_id is not None:
        return {seed_entity_id}
    stmt = select(EntityOccurrence.entity_id).distinct()
    stmt = scope_case_ids(stmt, ctx, EntityOccurrence.case_id)
    if case_id:
        stmt = stmt.where(EntityOccurrence.case_id == case_id)
    return set(db.execute(stmt).scalars().all())


def _load_relationships(db: Session, entity_ids: set[uuid.UUID]) -> list[EntityRelationship]:
    if not entity_ids:
        return []
    return list(
        db.execute(
            select(EntityRelationship).where(
                or_(
                    EntityRelationship.source_entity_id.in_(entity_ids),
                    EntityRelationship.target_entity_id.in_(entity_ids),
                )
            )
        )
        .scalars()
        .all()
    )


def _bfs(
    seeds: set[uuid.UUID],
    relationships: list[EntityRelationship],
    depth: int,
) -> set[uuid.UUID]:
    adjacency: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    for rel in relationships:
        adjacency[rel.source_entity_id].add(rel.target_entity_id)
        adjacency[rel.target_entity_id].add(rel.source_entity_id)

    seen: set[uuid.UUID] = set(seeds)
    queue: deque[tuple[uuid.UUID, int]] = deque((node, 0) for node in seeds)
    while queue:
        node, hops = queue.popleft()
        if hops >= depth:
            continue
        for neighbour in adjacency.get(node, ()):
            if neighbour in seen:
                continue
            seen.add(neighbour)
            queue.append((neighbour, hops + 1))
    return seen


def _cap(
    reachable: set[uuid.UUID],
    relationships: list[EntityRelationship],
    seeds: set[uuid.UUID],
    limit: int,
) -> set[uuid.UUID]:
    degree: dict[uuid.UUID, int] = defaultdict(int)
    for rel in relationships:
        degree[rel.source_entity_id] += 1
        degree[rel.target_entity_id] += 1
    ranked = sorted(reachable - seeds, key=lambda entity_id: degree[entity_id], reverse=True)
    kept = set(seeds)
    for entity_id in ranked:
        if len(kept) >= limit:
            break
        kept.add(entity_id)
    return kept


def _correlation_layer(
    db: Session,
    ctx: RequestContext,
    *,
    case_id: uuid.UUID | None,
    entity_ids: set[uuid.UUID],
    min_score: float,
    include_evidence_nodes: bool,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    stmt = select(CorrelationEdge).where(CorrelationEdge.score >= min_score)
    if case_id:
        stmt = stmt.where(
            or_(
                CorrelationEdge.source_case_id == case_id,
                CorrelationEdge.target_case_id == case_id,
            )
        )
    else:
        if not has_global_case_access(ctx):
            visible = accessible_case_ids(ctx)
            stmt = stmt.where(
                CorrelationEdge.source_case_id.in_(visible),
                CorrelationEdge.target_case_id.in_(visible),
            )

    edges = db.execute(stmt).scalars().all()
    if not edges:
        return {}, []

    evidence_ids = {edge.source_evidence_id for edge in edges} | {
        edge.target_evidence_id for edge in edges
    }
    evidence_rows = {
        row.id: row
        for row in db.execute(select(Evidence).where(Evidence.id.in_(evidence_ids))).scalars()
    }

    # Restrict evidence nodes to items that actually contain one of the reachable entities,
    # otherwise correlation would pull in unrelated artefacts at the same zoom.
    linked = set(
        db.execute(
            select(EntityOccurrence.evidence_id)
            .where(EntityOccurrence.entity_id.in_(entity_ids))
            .where(EntityOccurrence.evidence_id.in_(evidence_ids))
        )
        .scalars()
        .all()
    )

    nodes: dict[str, dict[str, Any]] = {}
    projected: list[dict[str, Any]] = []
    for edge in edges:
        if edge.source_evidence_id not in linked and edge.target_evidence_id not in linked:
            continue
        source_id = f"evidence:{edge.source_evidence_id}"
        target_id = f"evidence:{edge.target_evidence_id}"
        if include_evidence_nodes:
            for evidence_id, node_id in (
                (edge.source_evidence_id, source_id),
                (edge.target_evidence_id, target_id),
            ):
                item = evidence_rows.get(evidence_id)
                if item is None or node_id in nodes:
                    continue
                nodes[node_id] = {
                    "id": node_id,
                    "kind": "evidence",
                    "label": item.reference,
                    "sublabel": item.title,
                    "evidence_id": item.id,
                    "case_id": item.case_id,
                    "occurrence_count": 0,
                    "document_frequency": 0,
                    "intel_severity": None,
                    "attributes": {"sha256": item.sha256},
                }
        projected.append(
            {
                "id": f"corr:{edge.id}",
                "source": source_id,
                "target": target_id,
                "kind": edge.kind.value,
                "label": edge.kind.value.replace("_", " "),
                "weight": edge.score,
                "score": edge.score,
                "is_cross_case": edge.is_cross_case,
                "basis": edge.basis or {},
                "supporting_evidence": [],
            }
        )
    return nodes, projected
