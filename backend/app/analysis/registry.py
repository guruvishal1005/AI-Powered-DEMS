"""Analyzer registry.

Analyzers are looked up by name, and their version travels with every result they produce. That
combination is what keeps analysis interpretable over time: a finding recorded two years ago
states which analyzer produced it and at which version, so improving an analyzer adds new
results rather than silently reinterpreting old ones.

Execution order comes from each analyzer's declared ``priority``, not from the order modules happen
to be imported. Import order is alphabetical once a linter has sorted it, so relying on it would
mean a formatting change could silently reorder analysis.
"""

from __future__ import annotations

from app.analysis.base import Analyzer, ArtifactHandle
from app.core.errors import NotFound
from app.core.logging import get_logger

logger = get_logger(__name__)

_REGISTRY: dict[str, Analyzer] = {}
_ORDER: list[str] = []


def register(analyzer: Analyzer) -> Analyzer:
    if analyzer.name in _REGISTRY:
        raise RuntimeError(f"analyzer '{analyzer.name}' is already registered")
    _REGISTRY[analyzer.name] = analyzer
    _ORDER.append(analyzer.name)
    return analyzer


def get(name: str) -> Analyzer:
    load_analyzers()
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise NotFound("Analyzer", name) from exc


def all_analyzers() -> tuple[Analyzer, ...]:
    """Every registered analyzer, in execution order.

    Sorted by declared priority, with registration order breaking ties so the sequence is stable
    across runs rather than depending on dictionary iteration.
    """
    load_analyzers()
    return tuple(
        sorted(
            (_REGISTRY[name] for name in _ORDER),
            key=lambda analyzer: (getattr(analyzer, "priority", 100), _ORDER.index(analyzer.name)),
        )
    )


def applicable(artifact: ArtifactHandle) -> tuple[Analyzer, ...]:
    """The analyzers that will run for one artifact, in execution order."""
    return tuple(
        analyzer for analyzer in all_analyzers() if analyzer.applies_to(artifact)
    )


def load_analyzers() -> None:
    """Import analyzer modules so their registrations run."""
    if _REGISTRY:
        return
    from app.analysis.analyzers import (  # noqa: F401
        archives,
        documents,
        email,
        file_metadata,
        image,
        logs,
        text,
    )

    logger.debug("analyzers_loaded", count=len(_REGISTRY))


def describe() -> list[dict[str, str]]:
    """Analyzer inventory for the administration interface."""
    load_analyzers()
    return [
        {
            "name": analyzer.name,
            "version": analyzer.version,
            "description": analyzer.description,
        }
        for analyzer in all_analyzers()
    ]
