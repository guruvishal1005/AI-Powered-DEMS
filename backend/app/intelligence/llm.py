"""The language-model boundary.

CYBERTRACE will accept a language model for exactly one job: rewriting facts it has already
established into more readable prose. It will not accept one as a source of forensic findings. The
reason is simple and non-negotiable - a generative model can produce a fluent, confident statement
that is not true, and in this domain an untrue statement can end up in a report that a court relies
on.

That rule is enforced by structure rather than by instruction:

* A provider receives a :class:`NarrativeRequest` containing only facts already persisted by
  deterministic code, and returns a :class:`NarrativeResult` carrying **one string**. There is no
  field in the return type for an entity, an observation, a finding, a score or a severity, so a
  provider has nowhere to put a fabricated fact even if it generates one.
* Providers are never handed a database session. They cannot write anything.
* The output lands in :attr:`Insight.llm_narrative`, a column read by the interface as prose and by
  nothing else. Every fact the interface displays comes from ``observed``, ``basis`` and
  ``evidence_refs``, all written by deterministic code.
* :func:`validate_narrative` rejects prose that introduces identifiers, addresses, hashes or dates
  absent from the supplied facts. That catches the failure that matters most: a model inventing a
  plausible-looking indicator. Rejected narratives are dropped and the deterministic text stands.

The net effect is that with no provider configured the platform is fully functional and every
insight is deterministic; with one configured, the *wording* may improve and nothing else changes.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

MAX_NARRATIVE_CHARS = 1200


@dataclass(slots=True)
class NarrativeRequest:
    """Established facts, offered for rephrasing.

    ``facts`` is a list of short declarative statements produced by deterministic analysis. There is
    deliberately no way to ask a provider a question or to hand it raw evidence content: the only
    supported operation is "say this more clearly".
    """

    subject: str
    facts: list[str]
    audience: str = "investigator"
    style: str = "concise, factual, no speculation"
    permitted_terms: set[str] = field(default_factory=set)

    def prompt(self) -> str:
        """Render the request as a prompt.

        Kept here rather than in each provider so every adapter sends the same instruction and the
        constraint is auditable in one place.
        """
        bulleted = "\n".join(f"- {fact}" for fact in self.facts)
        return (
            "Rewrite the following established findings from a digital forensic investigation as "
            f"a short {self.style} summary for a {self.audience}.\n\n"
            "Absolute constraints:\n"
            "- Use only the facts listed. Do not add, infer or extrapolate anything.\n"
            "- Do not introduce any identifier, address, hash, filename or date that is not "
            "listed.\n"
            "- Do not speculate about intent, attribution or culpability.\n"
            "- Do not state conclusions the facts do not support.\n"
            "- If the facts are insufficient for a summary, reply with exactly: INSUFFICIENT\n\n"
            f"Subject: {self.subject}\n\nEstablished findings:\n{bulleted}"
        )


@dataclass(slots=True)
class NarrativeResult:
    """A provider's response: prose, and the metadata needed to attribute it.

    One text field, by design. Widening this type to carry structured output would remove the
    guarantee the whole module exists to provide, so it must not gain fields that describe evidence.
    """

    text: str
    model: str
    provider: str
    tokens_used: int | None = None


class LLMProvider(ABC):
    """A source of narrative phrasing, and nothing else."""

    name: str
    model: str

    @abstractmethod
    def narrate(
        self, request: NarrativeRequest
    ) -> NarrativeResult | None:  # pragma: no cover - interface
        """Return improved prose, or ``None`` if unavailable or unwilling.

        Returning ``None`` must always be safe: the caller keeps its deterministic text. That makes
        an unavailable model a cosmetic degradation rather than a functional failure.
        """

    def health(self) -> dict[str, Any]:
        return {"name": self.name, "model": self.model, "available": True}


class DisabledLLMProvider(LLMProvider):
    """The default: no model, no narration.

    Present so that "no LLM configured" is an ordinary configuration rather than a special case
    threaded through call sites with null checks.
    """

    name = "disabled"
    model = "none"

    def narrate(self, request: NarrativeRequest) -> NarrativeResult | None:
        return None

    def health(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "model": self.model,
            "available": False,
            "detail": (
                "No language model is configured. All insights are generated deterministically."
            ),
        }


# Token shapes that constitute a forensic claim. If prose contains one of these and the supplied
# facts do not, the model invented it - the single most dangerous failure mode, because an invented
# address looks exactly like a real one.
_CLAIM_PATTERNS = (
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b[0-9a-f]{32,64}\b", re.IGNORECASE),
    re.compile(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    re.compile(r"\b(?:bc1|[13])[a-km-zA-HJ-NP-Z0-9]{25,62}\b"),
    re.compile(r"\b[A-Z]{2,6}-\d{2,}\b"),
)

# Language that asserts something the facts cannot establish. A model asked for a summary will
# reach for these unprompted, and each one converts an observation into an allegation.
_SPECULATIVE_PHRASES = (
    "likely that",
    "probably",
    "appears to be the perpetrator",
    "is responsible for",
    "proves that",
    "confirms that the suspect",
    "guilty",
    "intended to",
    "must have",
    "clearly shows",
    "undoubtedly",
    "we believe",
    "suggests the suspect",
)


def validate_narrative(text: str, request: NarrativeRequest) -> tuple[bool, str | None]:
    """Check narrative prose against the facts it was given.

    Returns ``(accepted, reason_for_rejection)``. Rejection is not a fallback to be avoided - it is
    the mechanism working. A rejected narrative costs a slightly less elegant sentence; an accepted
    fabrication costs the credibility of the report.
    """
    stripped = text.strip()
    if not stripped or stripped == "INSUFFICIENT":
        return False, "provider declined to summarise"

    if len(stripped) > MAX_NARRATIVE_CHARS:
        return False, f"exceeds {MAX_NARRATIVE_CHARS} characters"

    haystack = " ".join(request.facts).lower()
    permitted = {term.lower() for term in request.permitted_terms}

    for pattern in _CLAIM_PATTERNS:
        for match in pattern.findall(stripped):
            token = match.lower()
            if token not in haystack and token not in permitted:
                return False, f"introduces an identifier absent from the facts: {match!r}"

    lowered = stripped.lower()
    for phrase in _SPECULATIVE_PHRASES:
        if phrase in lowered:
            return False, f"contains speculative language: {phrase!r}"

    return True, None


def narrate_safely(
    provider: LLMProvider, request: NarrativeRequest
) -> NarrativeResult | None:
    """Request narration and return it only if it survives validation.

    Every failure path - unavailable provider, exception, rejected content - returns ``None``, so a
    caller can use this without any error handling and cannot accidentally propagate unvalidated
    model output into the record.
    """
    try:
        result = provider.narrate(request)
    except Exception:
        logger.exception("llm_narration_failed", provider=provider.name)
        return None

    if result is None:
        return None

    accepted, reason = validate_narrative(result.text, request)
    if not accepted:
        logger.warning(
            "llm_narration_rejected",
            provider=provider.name,
            model=result.model,
            reason=reason,
            subject=request.subject,
        )
        return None

    return result


_provider: LLMProvider = DisabledLLMProvider()


def configure_provider(provider: LLMProvider) -> None:
    """Install the process-wide narration provider."""
    global _provider
    _provider = provider
    logger.info("llm_provider_configured", provider=provider.name, model=provider.model)


def get_provider() -> LLMProvider:
    """The configured provider, disabled unless an operator installed one."""
    return _provider
