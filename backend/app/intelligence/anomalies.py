"""Statistical anomaly detection over recorded observations.

Every detector here answers one question: is this unusual *for this case*, measured against a
baseline drawn from the case's own data? Fixed thresholds do not survive contact with real
evidence - "more than 50 events per hour" is meaningless without knowing whether the subject
normally produces five or five thousand - so each detector computes its own baseline and reports it.

What gets stored matters as much as what gets detected. Every anomaly records its ``method``,
``threshold``, ``observed_value``, ``baseline_value``, ``deviation`` and ``sample_size``. That is
not documentation for its own sake: an anomaly an analyst cannot interrogate is one they must either
take on faith or ignore, and both are failures. A defence expert must be able to recompute it.

Two deliberate restraints:

**Small samples produce nothing.** A z-score over four data points is arithmetic, not evidence.
Each detector states its minimum sample size and stays silent below it.

**Detectors read, never conclude.** They consume observations written by analyzers and write
anomalies. They cannot alter the underlying facts, which keeps the observed/interpretation boundary
intact by construction.
"""

from __future__ import annotations

import math
import statistics
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.analysis import AnalysisFinding, Anomaly, Observation
from app.models.enums import AnomalyKind, ObservationKind, Severity
from app.models.evidence import Evidence

logger = get_logger(__name__)

DETECTOR_VERSION = "1"

# A z-score of 3 means an hour further from the mean than 99.7% of hours, assuming an
# approximately normal distribution of activity. Event counts are not truly normal - they are
# bursty and right-skewed - so this is a screening threshold for analyst attention, not a
# statistical test, and the description says so.
BURST_Z_THRESHOLD = 3.0
MIN_BUCKETS_FOR_BURST = 8

# Outside these hours, activity is "off-hours" in the subject's assumed local time. Recorded as an
# assumption because most log formats give no timezone, so this can be wrong by hours.
BUSINESS_START = time(8, 0)
BUSINESS_END = time(19, 0)
MIN_EVENTS_FOR_OFF_HOURS = 12
OFF_HOURS_RATIO_THRESHOLD = 0.4

MIN_EVENTS_FOR_ORDERING = 5


@dataclass(slots=True)
class DetectedAnomaly:
    """A candidate anomaly, complete with the arithmetic that produced it."""

    kind: AnomalyKind
    title: str
    description: str
    severity: Severity
    method: str
    detector: str
    case_id: uuid.UUID | None = None
    evidence_id: uuid.UUID | None = None
    threshold: float | None = None
    observed_value: float | None = None
    baseline_value: float | None = None
    deviation: float | None = None
    sample_size: int | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def dedupe_key(self) -> tuple[Any, ...]:
        """Identity of this anomaly, so recomputation updates rather than duplicates."""
        return (
            self.kind,
            self.case_id,
            self.evidence_id,
            self.window_start,
            self.attributes.get("subject"),
        )


def _dispersion(mean: float, stdev: float) -> tuple[float, str]:
    """The spread to measure a deviation against, and where that spread came from.

    A perfectly regular baseline has a standard deviation of zero, and dividing by it would either
    error or - worse - silently score every deviation as zero, so a single enormous spike against an
    otherwise uniform background would go unreported. That is the most obvious anomaly there is.

    When the observed spread is zero, dispersion falls back to the Poisson expectation for count
    data (variance equals the mean, so the deviation is the square root of it), floored at one so a
    mean of zero still yields a usable divisor. Which estimate was used is recorded on the anomaly,
    because a z-score means something different under each.
    """
    if stdev > 0:
        return stdev, "sample standard deviation"
    return max(math.sqrt(max(mean, 1.0)), 1.0), "Poisson estimate (variance = mean)"


def _z_score(value: float, mean: float, stdev: float) -> float:
    return (value - mean) / stdev if stdev > 0 else 0.0


def detect_temporal_bursts(
    db: Session, case_id: uuid.UUID, *, bucket: timedelta = timedelta(hours=1)
) -> list[DetectedAnomaly]:
    """Find time buckets whose event count is far above the case's own average.

    The baseline excludes the bucket being tested. Including it would let a single enormous spike
    inflate the mean and standard deviation it is measured against, which is how a genuinely
    extreme outlier hides itself.
    """
    observations = db.scalars(
        select(Observation)
        .where(Observation.case_id == case_id)
        .order_by(Observation.occurred_at)
    ).all()
    if len(observations) < MIN_BUCKETS_FOR_BURST:
        return []

    seconds = int(bucket.total_seconds())
    buckets: Counter[int] = Counter()
    for observation in observations:
        stamp = int(observation.occurred_at.timestamp())
        buckets[stamp - (stamp % seconds)] += 1

    if len(buckets) < MIN_BUCKETS_FOR_BURST:
        return []

    counts = list(buckets.values())
    found: list[DetectedAnomaly] = []

    for start_epoch, count in sorted(buckets.items()):
        others = [value for key, value in buckets.items() if key != start_epoch]
        if len(others) < 2:
            continue
        mean = statistics.fmean(others)
        observed_stdev = statistics.stdev(others) if len(others) > 1 else 0.0
        spread, spread_source = _dispersion(mean, observed_stdev)
        score = _z_score(count, mean, spread)
        if score < BURST_Z_THRESHOLD:
            continue

        window_start = datetime.fromtimestamp(start_epoch, tz=UTC)
        window_end = window_start + bucket
        found.append(
            DetectedAnomaly(
                kind=AnomalyKind.temporal_burst,
                title=f"Activity spike: {count} events in one {_describe(bucket)}",
                description=(
                    f"{count} events were recorded between {window_start.isoformat()} and "
                    f"{window_end.isoformat()}, against a case average of {mean:.1f} per "
                    f"{_describe(bucket)} across {len(buckets)} active periods. Using a spread of "
                    f"{spread:.2f} ({spread_source}), the period sits {score:.1f} deviations above "
                    "the baseline."
                ),
                severity=Severity.medium if score < 5 else Severity.high,
                method=(
                    f"z-score of per-{_describe(bucket)} event count against the case mean, "
                    "excluding the bucket under test"
                ),
                detector="temporal_burst",
                case_id=case_id,
                threshold=BURST_Z_THRESHOLD,
                observed_value=float(count),
                baseline_value=round(mean, 3),
                deviation=round(score, 3),
                sample_size=len(counts),
                window_start=window_start,
                window_end=window_end,
                attributes={
                    "bucket_seconds": seconds,
                    "observed_standard_deviation": round(observed_stdev, 3),
                    "dispersion_used": round(spread, 3),
                    "dispersion_source": spread_source,
                    "active_buckets": len(buckets),
                    "method_caveat": (
                        "Event counts are bursty and right-skewed rather than normally "
                        "distributed, so this is a screening threshold for attention, not a test "
                        "of statistical significance."
                    ),
                    "subject": f"bucket:{start_epoch}",
                },
            )
        )

    return found


def detect_off_hours_activity(
    db: Session, case_id: uuid.UUID
) -> list[DetectedAnomaly]:
    """Flag a case whose activity is disproportionately outside business hours."""
    observations = db.scalars(
        select(Observation).where(Observation.case_id == case_id)
    ).all()
    if len(observations) < MIN_EVENTS_FOR_OFF_HOURS:
        return []

    off_hours = [
        observation
        for observation in observations
        if not (BUSINESS_START <= observation.occurred_at.time() <= BUSINESS_END)
        or observation.occurred_at.weekday() >= 5
    ]
    ratio = len(off_hours) / len(observations)
    if ratio < OFF_HOURS_RATIO_THRESHOLD:
        return []

    assumed = sum(1 for observation in observations if observation.timezone_assumed)
    return [
        DetectedAnomaly(
            kind=AnomalyKind.off_hours_activity,
            title=f"{ratio:.0%} of activity falls outside business hours",
            description=(
                f"{len(off_hours)} of {len(observations)} recorded events fall outside "
                f"{BUSINESS_START.strftime('%H:%M')}-{BUSINESS_END.strftime('%H:%M')} on a "
                f"weekday, a share of {ratio:.0%} against a threshold of "
                f"{OFF_HOURS_RATIO_THRESHOLD:.0%}."
                + (
                    f" {assumed} of these timestamps came from sources that recorded no timezone "
                    "and are stored as UTC, so the local-time classification rests on that "
                    "assumption."
                    if assumed
                    else " Every timestamp carried an explicit timezone."
                )
            ),
            severity=Severity.low,
            method=(
                "share of events outside 08:00-19:00 local weekday hours, timestamps assumed UTC"
            ),
            detector="off_hours",
            case_id=case_id,
            threshold=OFF_HOURS_RATIO_THRESHOLD,
            observed_value=round(ratio, 4),
            baseline_value=OFF_HOURS_RATIO_THRESHOLD,
            deviation=round(ratio - OFF_HOURS_RATIO_THRESHOLD, 4),
            sample_size=len(observations),
            attributes={
                "off_hours_events": len(off_hours),
                "total_events": len(observations),
                "timezone_assumed_events": assumed,
                "business_hours": f"{BUSINESS_START}-{BUSINESS_END}",
                "subject": "case",
            },
        )
    ]


def detect_failed_login_bursts(
    db: Session, case_id: uuid.UUID
) -> list[DetectedAnomaly]:
    """Group authentication failures by source and flag concentrated attempts.

    This overlaps deliberately with the log analyzer's per-file check. The analyzer sees one
    artifact; this sees the whole case, so an attacker spreading attempts thinly across ten hosts -
    invisible in any single log - becomes visible here.
    """
    failures = db.scalars(
        select(Observation)
        .where(
            Observation.case_id == case_id,
            Observation.kind == ObservationKind.login_failure,
        )
        .order_by(Observation.occurred_at)
    ).all()
    if len(failures) < 5:
        return []

    by_source: defaultdict[str, list[Observation]] = defaultdict(list)
    for failure in failures:
        key = failure.source_value or failure.actor_value or "unattributed"
        by_source[key].append(failure)

    successes = db.scalars(
        select(Observation).where(
            Observation.case_id == case_id,
            Observation.kind == ObservationKind.login_success,
        )
    ).all()
    success_sources = {
        observation.source_value for observation in successes if observation.source_value
    }

    found: list[DetectedAnomaly] = []
    for source, events in by_source.items():
        # Aggregated observations carry their own count, so a single row can represent thousands
        # of underlying log lines. Using the row count alone would understate the attempt volume
        # by orders of magnitude.
        attempts = sum(
            int(event.attributes.get("occurrence_count", 1) or 1) for event in events
        )
        if attempts < 5:
            continue

        first = events[0].occurred_at
        last = events[-1].occurred_at
        span = max((last - first).total_seconds(), 1.0)
        rate = attempts / (span / 60.0)
        followed_by_success = source in success_sources

        targets = {event.actor_value for event in events if event.actor_value}
        spraying = len(targets) >= 5

        if rate < 1.0 and attempts < 20 and not followed_by_success:
            continue

        found.append(
            DetectedAnomaly(
                kind=AnomalyKind.failed_login_burst,
                title=(
                    f"Credential attack from {source} succeeded"
                    if followed_by_success
                    else f"{attempts} failed authentication attempts from {source}"
                ),
                description=(
                    f"{attempts} failed authentication attempts are attributed to {source} "
                    f"between {first.isoformat()} and {last.isoformat()} "
                    f"({rate:.2f} per minute)"
                    + (
                        f", against {len(targets)} distinct accounts"
                        if spraying
                        else f", against {len(targets)} account(s)"
                        if targets
                        else ""
                    )
                    + "."
                    + (
                        " A successful authentication from the same source is also recorded within "
                        "the case."
                        if followed_by_success
                        else " No successful authentication from this source is recorded."
                    )
                ),
                severity=(
                    Severity.critical
                    if followed_by_success
                    else Severity.high
                    if spraying or rate >= 3
                    else Severity.medium
                ),
                method="failed authentication attempts grouped by source, with rate over span",
                detector="failed_login_burst",
                case_id=case_id,
                threshold=5.0,
                observed_value=float(attempts),
                baseline_value=1.0,
                deviation=round(rate, 3),
                sample_size=len(failures),
                window_start=first,
                window_end=last,
                attributes={
                    "source": source,
                    "attempts": attempts,
                    "attempts_per_minute": round(rate, 3),
                    "distinct_accounts": len(targets),
                    "accounts": sorted(value for value in targets if value)[:20],
                    "followed_by_success": followed_by_success,
                    "password_spraying": spraying,
                    "subject": f"source:{source}",
                },
            )
        )

    return found


def detect_timestamp_inconsistencies(
    db: Session, case_id: uuid.UUID
) -> list[DetectedAnomaly]:
    """Find evidence whose internal timestamps precede its own acquisition impossibly.

    Content cannot postdate its acquisition: if an artifact collected on Tuesday contains events
    from Friday, either a clock is wrong or the content was altered. Both are material to whether
    the evidence can be relied on.
    """
    rows = db.execute(
        select(
            Observation.evidence_id,
            Evidence.reference,
            Evidence.acquired_at,
            Observation.occurred_at,
            Observation.summary,
        )
        .join(Evidence, Evidence.id == Observation.evidence_id)
        .where(
            Observation.case_id == case_id,
            Evidence.acquired_at.is_not(None),
            Observation.occurred_at > Evidence.acquired_at,
        )
    ).all()
    if not rows:
        return []

    grouped: defaultdict[uuid.UUID, list[tuple[str, datetime, datetime]]] = defaultdict(
        list
    )
    for evidence_id, reference, acquired_at, occurred_at, _summary in rows:
        if acquired_at is None:  # pragma: no cover - excluded by the query
            continue
        grouped[evidence_id].append((reference, acquired_at, occurred_at))

    found: list[DetectedAnomaly] = []
    for evidence_id, entries in grouped.items():
        if len(entries) < MIN_EVENTS_FOR_ORDERING:
            continue
        reference, acquired_at, _first = entries[0]
        latest = max(entry[2] for entry in entries)
        drift = (latest - acquired_at).total_seconds()

        found.append(
            DetectedAnomaly(
                kind=AnomalyKind.timestamp_inconsistency,
                title=f"{reference} contains events dated after it was acquired",
                description=(
                    f"{len(entries)} events recovered from {reference} carry timestamps later "
                    f"than the item's recorded acquisition time of {acquired_at.isoformat()}. The "
                    f"latest is {latest.isoformat()}, {drift / 3600:.1f} hours after acquisition."
                ),
                severity=Severity.high,
                method="comparison of observation timestamps against recorded acquisition time",
                detector="timestamp_ordering",
                case_id=case_id,
                evidence_id=evidence_id,
                observed_value=round(drift, 1),
                baseline_value=0.0,
                deviation=round(drift, 1),
                sample_size=len(entries),
                window_start=acquired_at,
                window_end=latest,
                attributes={
                    "evidence_reference": reference,
                    "acquired_at": acquired_at.isoformat(),
                    "latest_event_at": latest.isoformat(),
                    "drift_seconds": int(drift),
                    "affected_events": len(entries),
                    "subject": f"evidence:{evidence_id}",
                },
            )
        )

    return found


def promote_analyzer_findings(
    db: Session, case_id: uuid.UUID
) -> list[DetectedAnomaly]:
    """Raise case-level anomalies for the per-file findings that warrant one.

    Certain analyzer findings are anomalies in their own right - a file whose type contradicts its
    extension, a localised high-entropy region - and belong on the case's anomaly list rather than
    only on the artifact's. This is a projection, not a re-detection: the analyzer's measurement is
    carried across unchanged so the two views can never disagree.

    The analyzer's own prose is *not* copied into the anomaly's description. Analyzer findings are
    written for a reader looking at one artifact and mix measurement with expert explanation
    ("SPF and DKIM both failed, which is consistent with spoofing"). An anomaly's description feeds
    the ``observed`` half of an insight, which may contain no inference at all, so the measurement
    is restated from the recorded attributes and the analyzer's explanation is carried separately in
    ``analyzer_narrative`` for the interpretation side to use.
    """
    mapping = {
        "file.mime_extension_mismatch": AnomalyKind.mime_extension_mismatch,
        "file.entropy_anomaly": AnomalyKind.high_entropy_content,
        "image.timestamp_inconsistency": AnomalyKind.timestamp_inconsistency,
        "document.timestamp_inconsistency": AnomalyKind.timestamp_inconsistency,
        "email.received_chain_out_of_order": AnomalyKind.timestamp_inconsistency,
        "email.date_header_implausible": AnomalyKind.email_spoofing_indicator,
        "email.authentication_failed": AnomalyKind.email_spoofing_indicator,
        "email.reply_to_mismatch": AnomalyKind.email_spoofing_indicator,
        "log.credential_attack": AnomalyKind.failed_login_burst,
        "log.enumeration_pattern": AnomalyKind.access_outside_scope,
        "archive.decompression_bomb": AnomalyKind.volume_outlier,
        "archive.path_traversal": AnomalyKind.access_outside_scope,
    }

    findings = db.scalars(
        select(AnalysisFinding).where(
            AnalysisFinding.case_id == case_id,
            AnalysisFinding.code.in_(mapping.keys()),
        )
    ).all()

    references: dict[uuid.UUID, str] = {
        evidence_id: reference
        for evidence_id, reference in db.execute(
            select(Evidence.id, Evidence.reference).where(
                Evidence.id.in_({finding.evidence_id for finding in findings})
            )
        ).all()
    }

    found: list[DetectedAnomaly] = []
    for finding in findings:
        attributes = dict(finding.attributes or {})
        found.append(
            DetectedAnomaly(
                kind=mapping[finding.code],
                title=finding.title,
                description=_measurement_prose(finding, references, attributes),
                severity=finding.severity,
                method=str(
                    attributes.get("method")
                    or f"structural check by the {finding.analyzer} analyzer"
                ),
                detector=finding.analyzer,
                case_id=case_id,
                evidence_id=finding.evidence_id,
                threshold=_as_float(attributes.get("threshold")),
                observed_value=_as_float(
                    attributes.get("overall")
                    or attributes.get("ratio")
                    or attributes.get("failure_count")
                ),
                attributes={
                    **attributes,
                    "source_finding_code": finding.code,
                    "source_analyzer": finding.analyzer,
                    "source_analyzer_version": finding.analyzer_version,
                    "analyzer_narrative": finding.description,
                    "locator": finding.locator,
                    "subject": f"finding:{finding.id}",
                },
            )
        )

    return found


# Attribute keys that are bookkeeping rather than measurement, and would only clutter the prose.
_UNINTERESTING_ATTRIBUTES = frozenset(
    {"method", "threshold", "analyzer", "analyzer_version", "locator"}
)


def _measurement_prose(
    finding: AnalysisFinding,
    references: dict[uuid.UUID, str],
    attributes: dict[str, Any],
) -> str:
    """State what the analyzer measured, without repeating what it concluded."""
    reference = references.get(finding.evidence_id, "the item")
    measured = [
        f"{key.replace('_', ' ')}: {_render(value)}"
        for key, value in attributes.items()
        if key not in _UNINTERESTING_ATTRIBUTES and value not in (None, "", [], {})
    ][:8]

    detail = f" Recorded values - {'; '.join(measured)}." if measured else ""
    locator = ""
    if finding.locator:
        rendered = ", ".join(
            f"{key}={_render(value)}" for key, value in list(finding.locator.items())[:4]
        )
        locator = f" Located at {rendered}."

    return (
        f"The {finding.analyzer} analyzer (version {finding.analyzer_version}) raised "
        f"{finding.code} against {reference}.{detail}{locator}"
    )


def _render(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value[:6])
    if isinstance(value, dict):
        return ", ".join(f"{key}={item}" for key, item in list(value.items())[:6])
    return str(value)


def _as_float(value: Any) -> float | None:
    if not isinstance(value, int | float | str):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _describe(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return "hour" if hours == 1 else f"{hours} hours"
    minutes = seconds // 60
    return "minute" if minutes == 1 else f"{minutes} minutes"


DETECTORS = (
    detect_temporal_bursts,
    detect_off_hours_activity,
    detect_failed_login_bursts,
    detect_timestamp_inconsistencies,
    promote_analyzer_findings,
)


def detect_for_case(db: Session, case_id: uuid.UUID) -> dict[str, Any]:
    """Run every detector over a case and persist the results.

    Each detector is isolated: one raising must not prevent the others from contributing, because
    a partial anomaly list is far more useful than none, and a silent total failure would look
    identical to a case with nothing unusual in it.
    """
    detected: list[DetectedAnomaly] = []
    failures: list[str] = []

    for detector in DETECTORS:
        try:
            detected.extend(detector(db, case_id))
        except Exception as exc:
            failures.append(f"{detector.__name__}: {type(exc).__name__}: {exc}")
            logger.exception("anomaly_detector_failed", detector=detector.__name__)

    written, updated = _persist(db, case_id, detected)

    logger.info(
        "anomalies_detected",
        case_id=str(case_id),
        created=written,
        updated=updated,
        detectors_failed=len(failures),
    )
    return {
        "detected": len(detected),
        "created": written,
        "updated": updated,
        "detector_failures": failures,
    }


def _persist(
    db: Session, case_id: uuid.UUID, detected: list[DetectedAnomaly]
) -> tuple[int, int]:
    """Insert new anomalies and refresh existing ones, preserving analyst dismissals.

    A dismissal is a judgement an investigator made and must survive recomputation. Deleting and
    reinserting would resurrect anomalies that were deliberately set aside, which trains people to
    stop dismissing anything.
    """
    existing = db.scalars(select(Anomaly).where(Anomaly.case_id == case_id)).all()
    by_key = {_existing_key(anomaly): anomaly for anomaly in existing}

    created = 0
    updated = 0
    seen: set[tuple[Any, ...]] = set()

    for candidate in detected:
        key = candidate.dedupe_key()
        seen.add(key)
        current = by_key.get(key)

        if current is None:
            db.add(
                Anomaly(
                    case_id=candidate.case_id,
                    evidence_id=candidate.evidence_id,
                    kind=candidate.kind,
                    severity=candidate.severity,
                    title=candidate.title[:240],
                    description=candidate.description,
                    method=candidate.method[:120],
                    threshold=candidate.threshold,
                    observed_value=candidate.observed_value,
                    baseline_value=candidate.baseline_value,
                    deviation=candidate.deviation,
                    sample_size=candidate.sample_size,
                    window_start=candidate.window_start,
                    window_end=candidate.window_end,
                    detector=candidate.detector[:64],
                    detector_version=DETECTOR_VERSION,
                    attributes=candidate.attributes,
                )
            )
            created += 1
            continue

        current.severity = candidate.severity
        current.title = candidate.title[:240]
        current.description = candidate.description
        current.method = candidate.method[:120]
        current.threshold = candidate.threshold
        current.observed_value = candidate.observed_value
        current.baseline_value = candidate.baseline_value
        current.deviation = candidate.deviation
        current.sample_size = candidate.sample_size
        current.window_end = candidate.window_end
        current.attributes = candidate.attributes
        current.detector_version = DETECTOR_VERSION
        updated += 1

    # Anomalies that no longer reproduce are removed, unless an analyst has dismissed them: a
    # dismissal is a record of a decision and deleting it would erase that history.
    for key, anomaly in by_key.items():
        if key not in seen and anomaly.dismissed_at is None:
            db.delete(anomaly)

    db.flush()
    return created, updated


def _existing_key(anomaly: Anomaly) -> tuple[Any, ...]:
    return (
        anomaly.kind,
        anomaly.case_id,
        anomaly.evidence_id,
        anomaly.window_start,
        (anomaly.attributes or {}).get("subject"),
    )
