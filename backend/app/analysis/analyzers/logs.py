"""Log file analyzer for the formats that actually turn up in cybercrime casework.

Handles syslog, Linux auth logs, Apache/Nginx combined access logs, Windows event exports and
generic ISO-8601 application logs. Each line that yields a timestamp becomes an observation, which
is what allows the investigation timeline to be assembled from log content rather than from upload
times.

The important design decision here is about time. Log formats are wildly inconsistent about
timezones: syslog omits the year *and* the offset, Apache includes an explicit offset, and
application logs vary line by line. Rather than guessing and producing a timeline that is quietly
wrong by hours, every parsed timestamp records whether an offset had to be assumed, and syslog
lines missing a year are resolved against the artifact's own acquisition date instead of defaulting
to the current one.

Line-level events are also *aggregated* before they become observations. A 200 MB access log would
otherwise generate millions of rows that no investigator can use; what matters is the pattern -
which source addresses failed to authenticate, how often, and when - so repeated events of the same
shape are collapsed into a single observation carrying its own count.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any

from app.analysis import indicators
from app.analysis.base import (
    AnalyzerOutput,
    ArtifactHandle,
    BaseAnalyzer,
    ExtractedEntity,
    ExtractedFinding,
    ExtractedObservation,
)
from app.analysis.registry import register
from app.models.enums import (
    Confidence,
    EntityType,
    EvidenceType,
    ObservationKind,
    Severity,
)

MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_LINES = 200_000
# Beyond this many distinct aggregated events, only the most significant are kept.
MAX_OBSERVATIONS = 400

_MONTHS = {
    month: index
    for index, month in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

_ISO = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?)"
)
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w.\-]+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_CLF = re.compile(
    r"^(?P<client>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^"\s]*)(?:\s+(?P<proto>[^"]*))?"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)
_CLF_TIME = re.compile(
    r"(?P<day>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<year>\d{4}):"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<offset>[+-]\d{4})"
)

# Message shapes that carry authentication meaning, mapped to an outcome and observation kind.
_AUTH_PATTERNS: tuple[tuple[re.Pattern[str], str, ObservationKind], ...] = (
    (
        re.compile(
            r"Failed (?:password|publickey|none) for (?:invalid user )?(?P<user>\S+) "
            r"from (?P<ip>\S+)",
            re.IGNORECASE,
        ),
        "failure",
        ObservationKind.login_failure,
    ),
    (
        re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE),
        "failure",
        ObservationKind.login_failure,
    ),
    (
        re.compile(
            r"Accepted (?:password|publickey|none) for (?P<user>\S+) from (?P<ip>\S+)",
            re.IGNORECASE,
        ),
        "success",
        ObservationKind.login_success,
    ),
    (
        re.compile(r"authentication failure.*?(?:user|rhost)=(?P<user>\S+)", re.IGNORECASE),
        "failure",
        ObservationKind.login_failure,
    ),
    (
        re.compile(r"session opened for user (?P<user>\S+)", re.IGNORECASE),
        "success",
        ObservationKind.login_success,
    ),
    (
        re.compile(r"(?P<user>\S+)\s+:\s+TTY=.*?COMMAND=(?P<command>.+)", re.IGNORECASE),
        "success",
        ObservationKind.privilege_change,
    ),
    (
        re.compile(r"An account failed to log on|Logon Type:\s*\d+", re.IGNORECASE),
        "failure",
        ObservationKind.login_failure,
    ),
)

_EXFIL_HINTS = re.compile(
    r"\b(?:scp|sftp|rsync|curl|wget|nc|ncat|socat|base64|tar\s+-c|zip\s+-r)\b", re.IGNORECASE
)


@dataclass(slots=True)
class _Aggregate:
    """One repeated event shape, collapsed across all the lines that produced it."""

    kind: ObservationKind
    summary: str
    outcome: str | None
    actor: str | None
    source: str | None
    target: str | None
    first_seen: datetime
    last_seen: datetime
    first_line: int
    count: int = 1
    excerpt: str = ""
    timezone_assumed: bool = False
    attributes: dict[str, Any] = field(default_factory=dict)

    def absorb(self, when: datetime, line: int) -> None:
        self.count += 1
        self.first_seen = min(self.first_seen, when)
        self.last_seen = max(self.last_seen, when)
        self.first_line = min(self.first_line, line)


class LogAnalyzer(BaseAnalyzer):
    name = "log_events"
    version = "1"
    description = "Timestamped events, authentication activity and access patterns from log files"
    mime_prefixes = ("text/plain", "text/x-log", "text/csv")
    evidence_types = (EvidenceType.system_log, EvidenceType.network_capture, EvidenceType.document)
    max_size_bytes = MAX_LOG_BYTES

    def applies_to(self, artifact: ArtifactHandle) -> bool:
        if artifact.size_bytes > MAX_LOG_BYTES:
            return False
        if artifact.evidence_type is EvidenceType.system_log:
            return True
        # A .txt or .csv file is only worth log parsing if its opening lines actually look like
        # log records; otherwise the text analyzer is the right handler.
        if not artifact.mime_type.startswith(self.mime_prefixes):
            return False
        head = artifact.head[:4096].decode("utf-8", errors="replace")
        return bool(_ISO.search(head) or _SYSLOG.search(head) or _CLF.search(head))

    def analyze(self, artifact: ArtifactHandle) -> AnalyzerOutput:
        output = AnalyzerOutput()
        text, truncated = artifact.read_text(MAX_LOG_BYTES)
        output.bytes_examined = len(text.encode("utf-8", errors="replace"))
        output.truncated = truncated

        lines = text.splitlines()
        if len(lines) > MAX_LINES:
            lines = lines[:MAX_LINES]
            output.truncated = True

        # Syslog omits the year, so it has to come from somewhere. Acquisition time is the closest
        # defensible anchor: a log collected two years ago belongs in that year, not this one.
        anchor = artifact.acquired_at or datetime.now(UTC)
        reference_year = anchor.year

        aggregates: dict[tuple[Any, ...], _Aggregate] = {}
        format_counts: Counter[str] = Counter()
        status_counts: Counter[str] = Counter()
        failures_by_ip: defaultdict[str, list[datetime]] = defaultdict(list)
        successes_by_ip: defaultdict[str, set[str]] = defaultdict(set)
        users_seen: Counter[str] = Counter()
        parsed_times: list[datetime] = []
        unparsed = 0

        for number, line in enumerate(lines, start=1):
            if not line.strip():
                continue

            record = self._parse_line(line, reference_year)
            if record is None:
                unparsed += 1
                continue

            format_counts[record["format"]] += 1
            when: datetime = record["when"]
            parsed_times.append(when)

            if record["format"] == "clf":
                status_counts[str(record.get("status", ""))] += 1

            self._aggregate(aggregates, record, number, line)

            if record.get("outcome") == "failure" and record.get("source"):
                failures_by_ip[str(record["source"])].append(when)
            if record.get("outcome") == "success" and record.get("source"):
                successes_by_ip[str(record["source"])].add(str(record.get("actor") or ""))
            if record.get("actor"):
                users_seen[str(record["actor"])] += 1

        self._emit_observations(output, aggregates)
        self._emit_entities(output, text, aggregates)

        output.metadata = {
            "line_count": len(lines),
            "parsed_lines": sum(format_counts.values()),
            "unparsed_lines": unparsed,
            "formats": dict(format_counts),
            "distinct_events": len(aggregates),
            "time_range": {
                "earliest": min(parsed_times).isoformat() if parsed_times else None,
                "latest": max(parsed_times).isoformat() if parsed_times else None,
            },
            "http_status_counts": dict(status_counts) or None,
            "top_users": dict(users_seen.most_common(20)) or None,
            "syslog_year_assumed": reference_year if format_counts.get("syslog") else None,
            "year_anchor_source": (
                "evidence acquisition time" if artifact.acquired_at else "analysis time"
            ),
        }

        if not format_counts:
            output.skip_reason = (
                f"No parseable log records found in {len(lines)} lines; the file may use a format "
                "this analyzer does not recognise."
            )
            return output

        self._check_brute_force(output, failures_by_ip, successes_by_ip)
        self._check_http_errors(output, status_counts)
        self._check_exfil_hints(output, lines)
        self._check_gaps(output, parsed_times)

        return output

    def _parse_line(self, line: str, reference_year: int) -> dict[str, Any] | None:
        clf = _CLF.match(line)
        if clf:
            return self._parse_clf(clf, line)

        syslog = _SYSLOG.match(line)
        if syslog:
            return self._parse_syslog(syslog, line, reference_year)

        iso = _ISO.search(line)
        if iso:
            return self._parse_iso(iso, line)

        return None

    def _parse_clf(self, match: re.Match[str], line: str) -> dict[str, Any] | None:
        stamp = _CLF_TIME.match(match.group("ts"))
        if stamp is None:
            return None
        offset = stamp.group("offset")
        try:
            when = datetime.strptime(
                f"{stamp.group('day')}/{stamp.group('mon')}/{stamp.group('year')}:"
                f"{stamp.group('time')} {offset}",
                "%d/%b/%Y:%H:%M:%S %z",
            ).astimezone(UTC)
        except ValueError:
            return None

        status = int(match.group("status"))
        record: dict[str, Any] = {
            "format": "clf",
            "when": when,
            "timezone_assumed": False,
            "kind": ObservationKind.network_connection,
            "source": match.group("client"),
            "actor": None if match.group("user") == "-" else match.group("user"),
            "target": match.group("path"),
            "status": status,
            "method": match.group("method"),
            "agent": match.group("agent"),
            "outcome": "success" if status < 400 else "failure",
            "summary": (
                f"HTTP {match.group('method')} {match.group('path')} returned {status} "
                f"from {match.group('client')}"
            ),
            "raw": line,
        }
        if status in (401, 403):
            record["kind"] = ObservationKind.login_failure
            record["summary"] = (
                f"HTTP {status} on {match.group('path')} from {match.group('client')}"
            )
        return record

    def _parse_syslog(
        self, match: re.Match[str], line: str, reference_year: int
    ) -> dict[str, Any]:
        month = _MONTHS.get(match.group("mon"), 1)
        hour, minute, second = (int(part) for part in match.group("time").split(":"))
        try:
            when = datetime(
                reference_year,
                month,
                int(match.group("day")),
                hour,
                minute,
                second,
                tzinfo=UTC,
            )
        except ValueError:  # 29 February in a non-leap reference year
            when = datetime(reference_year, month, 28, hour, minute, second, tzinfo=UTC)

        message = match.group("msg")
        record: dict[str, Any] = {
            "format": "syslog",
            "when": when,
            # Syslog carries neither year nor offset, so both were supplied by this parser.
            "timezone_assumed": True,
            "kind": ObservationKind.log_entry,
            "host": match.group("host"),
            "process": match.group("proc"),
            "pid": match.group("pid"),
            "summary": f"{match.group('proc')} on {match.group('host')}: {message[:200]}",
            "raw": line,
        }
        self._apply_auth_semantics(record, message)
        return record

    def _parse_iso(self, match: re.Match[str], line: str) -> dict[str, Any] | None:
        raw = match.group("ts").replace(",", ".").replace(" ", "T")
        assumed = match.group("tz") is None
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            when = datetime.fromisoformat(raw)
        except ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)

        record: dict[str, Any] = {
            "format": "iso",
            "when": when.astimezone(UTC),
            "timezone_assumed": assumed,
            "kind": ObservationKind.log_entry,
            "summary": line[match.end() :].strip()[:200] or line[:200],
            "raw": line,
        }
        self._apply_auth_semantics(record, line)
        return record

    def _apply_auth_semantics(self, record: dict[str, Any], message: str) -> None:
        """Upgrade a generic log line to a typed authentication event where the text supports it."""
        for pattern, outcome, kind in _AUTH_PATTERNS:
            found = pattern.search(message)
            if found is None:
                continue
            groups = found.groupdict()
            record["kind"] = kind
            record["outcome"] = outcome
            if groups.get("user"):
                record["actor"] = groups["user"]
            if groups.get("ip"):
                candidates = list(
                    indicators.iter_matches(groups["ip"], (EntityType.ip_address,))
                )
                record["source"] = candidates[0].value if candidates else groups["ip"]
            if groups.get("command"):
                record["target"] = groups["command"][:200]
                record["summary"] = (
                    f"{groups.get('user', 'unknown')} ran privileged command: "
                    f"{groups['command'][:150]}"
                )
            else:
                verb = "succeeded" if outcome == "success" else "failed"
                record["summary"] = (
                    f"Authentication {verb} for {record.get('actor', 'unknown user')}"
                    + (f" from {record['source']}" if record.get("source") else "")
                )
            return

    def _aggregate(
        self,
        aggregates: dict[tuple[Any, ...], _Aggregate],
        record: dict[str, Any],
        number: int,
        line: str,
    ) -> None:
        # Grouping on the event's shape rather than its text is what collapses ten thousand
        # identical failed logins into one countable observation.
        key = (
            record["kind"],
            record.get("outcome"),
            record.get("actor"),
            record.get("source"),
            record.get("target") if record["kind"] is not ObservationKind.network_connection
            else record.get("status"),
        )
        existing = aggregates.get(key)
        if existing is not None:
            existing.absorb(record["when"], number)
            return

        if len(aggregates) >= MAX_OBSERVATIONS * 4:
            return

        aggregates[key] = _Aggregate(
            kind=record["kind"],
            summary=record["summary"],
            outcome=record.get("outcome"),
            actor=record.get("actor"),
            source=record.get("source"),
            target=record.get("target"),
            first_seen=record["when"],
            last_seen=record["when"],
            first_line=number,
            excerpt=line[:500],
            timezone_assumed=bool(record.get("timezone_assumed")),
            attributes={
                "format": record["format"],
                "process": record.get("process"),
                "host": record.get("host"),
                "http_status": record.get("status"),
                "http_method": record.get("method"),
            },
        )

    def _emit_observations(
        self, output: AnalyzerOutput, aggregates: dict[tuple[Any, ...], _Aggregate]
    ) -> None:
        # When there are more distinct events than can reasonably be stored, keep the ones an
        # investigator would look at first: failures, then the most frequent.
        ranked = sorted(
            aggregates.values(),
            key=lambda agg: (agg.outcome != "failure", -agg.count, agg.first_seen),
        )
        for aggregate in ranked[:MAX_OBSERVATIONS]:
            summary = aggregate.summary
            if aggregate.count > 1:
                summary = f"{summary} (\u00d7{aggregate.count})"

            attributes = {
                key: value for key, value in aggregate.attributes.items() if value is not None
            }
            attributes.update(
                {
                    "occurrence_count": aggregate.count,
                    "first_seen": aggregate.first_seen.isoformat(),
                    "last_seen": aggregate.last_seen.isoformat(),
                    "first_line": aggregate.first_line,
                }
            )
            if aggregate.timezone_assumed:
                attributes["time_note"] = (
                    "Source format carried no UTC offset; timestamps are treated as UTC."
                )

            output.add_observation(
                ExtractedObservation(
                    kind=aggregate.kind,
                    occurred_at=aggregate.first_seen,
                    summary=summary,
                    locator={"line": aggregate.first_line},
                    excerpt=aggregate.excerpt,
                    actor_value=aggregate.actor,
                    source_value=aggregate.source,
                    target_value=aggregate.target,
                    outcome=aggregate.outcome,
                    time_confidence=(
                        Confidence.moderate if aggregate.timezone_assumed else Confidence.high
                    ),
                    timezone_assumed=aggregate.timezone_assumed,
                    attributes=attributes,
                    entity_values=tuple(
                        value
                        for value in (aggregate.source, aggregate.actor)
                        if value is not None
                    ),
                )
            )

    def _emit_entities(
        self,
        output: AnalyzerOutput,
        text: str,
        aggregates: dict[tuple[Any, ...], _Aggregate],
    ) -> None:
        for entity in indicators.extract(
            text,
            types=(
                EntityType.ip_address,
                EntityType.domain,
                EntityType.url,
                EntityType.email_address,
                EntityType.file_path,
                EntityType.user_agent,
                EntityType.cve,
            ),
            source_label="log",
        ):
            output.add_entity(entity)

        # Usernames are not pattern-detectable in free text, but the auth parsers identified them
        # positionally, which makes them reliable enough to record.
        seen: set[str] = set()
        for aggregate in aggregates.values():
            if aggregate.actor and aggregate.actor not in seen:
                seen.add(aggregate.actor)
                output.add_entity(
                    ExtractedEntity(
                        type=EntityType.username,
                        value=aggregate.actor,
                        locator={"line": aggregate.first_line},
                        excerpt=aggregate.excerpt[:200],
                        context="authentication_subject",
                        occurrence_count=aggregate.count,
                    )
                )

    def _check_brute_force(
        self,
        output: AnalyzerOutput,
        failures_by_ip: dict[str, list[datetime]],
        successes_by_ip: dict[str, set[str]],
    ) -> None:
        for address, times in failures_by_ip.items():
            if len(times) < 5:
                continue
            ordered = sorted(times)
            window = (ordered[-1] - ordered[0]).total_seconds()
            rate = len(times) / max(window / 60.0, 1.0)

            # Rate and volume both matter. A fast burst is obviously automated; so is a steady
            # drip of a dozen failures from one address inside an hour, which is what rate alone
            # would miss. Spread over a week, the same count is a user who forgot a password.
            sustained = len(times) >= 10 and window <= 3600
            if window <= 600 or rate >= 3.0 or sustained:
                followed_by_success = address in successes_by_ip
                output.add_finding(
                    ExtractedFinding(
                        code="log.credential_attack",
                        title=(
                            f"Authentication failures from {address} followed by a successful login"
                            if followed_by_success
                            else f"Repeated authentication failures from {address}"
                        ),
                        description=(
                            f"{len(times)} failed authentication attempts originated from "
                            f"{address} between {ordered[0].isoformat()} and "
                            f"{ordered[-1].isoformat()} ({rate:.1f} per minute). "
                            + (
                                "A successful authentication from the same address appears in the "
                                "same log, which is the pattern of a credential attack that "
                                "succeeded and warrants immediate review of that account's "
                                "activity."
                                if followed_by_success
                                else "This rate is consistent with automated credential guessing "
                                "rather than user error."
                            )
                        ),
                        severity=Severity.critical if followed_by_success else Severity.high,
                        confidence=0.9 if followed_by_success else 0.8,
                        locator={"scope": "aggregated"},
                        attributes={
                            "source_ip": address,
                            "failure_count": len(times),
                            "window_seconds": int(window),
                            "failures_per_minute": round(rate, 2),
                            "subsequent_success": followed_by_success,
                            "accounts_accessed": sorted(successes_by_ip.get(address, set())),
                            "method": "failure count and rate per source address",
                            "threshold": (
                                ">=5 failures within 10 minutes, or >=3 per minute, "
                                "or >=10 within an hour"
                            ),
                        },
                    )
                )

    def _check_http_errors(self, output: AnalyzerOutput, status_counts: Counter[str]) -> None:
        if not status_counts:
            return
        total = sum(status_counts.values())
        not_found = status_counts.get("404", 0)
        unauthorised = status_counts.get("401", 0) + status_counts.get("403", 0)
        server_errors = sum(
            count for status, count in status_counts.items() if status.startswith("5")
        )

        if total >= 50 and not_found / total >= 0.4:
            output.add_finding(
                ExtractedFinding(
                    code="log.enumeration_pattern",
                    title="High proportion of not-found responses",
                    description=(
                        f"{not_found} of {total} requests ({not_found / total:.0%}) returned 404. "
                        "A dominant share of not-found responses indicates directory or resource "
                        "enumeration rather than normal browsing, in which most requests resolve."
                    ),
                    severity=Severity.medium,
                    confidence=0.75,
                    locator={"scope": "aggregated"},
                    attributes={
                        "not_found": not_found,
                        "total_requests": total,
                        "ratio": round(not_found / total, 3),
                        "method": "404 share of total requests",
                        "threshold": "40% over at least 50 requests",
                    },
                )
            )

        if total >= 20 and unauthorised / total >= 0.25:
            output.add_finding(
                ExtractedFinding(
                    code="log.authorization_failures",
                    title="Substantial share of unauthorised responses",
                    description=(
                        f"{unauthorised} of {total} requests ({unauthorised / total:.0%}) were "
                        "rejected with 401 or 403. Sustained authorisation failures suggest "
                        "attempts to reach resources the client is not entitled to."
                    ),
                    severity=Severity.medium,
                    confidence=0.7,
                    locator={"scope": "aggregated"},
                    attributes={
                        "unauthorised": unauthorised,
                        "total_requests": total,
                        "ratio": round(unauthorised / total, 3),
                    },
                )
            )

        if total >= 20 and server_errors / total >= 0.2:
            output.add_finding(
                ExtractedFinding(
                    code="log.server_error_rate",
                    title="Elevated server error rate",
                    description=(
                        f"{server_errors} of {total} requests ({server_errors / total:.0%}) "
                        "returned a 5xx status. Beyond availability, a raised error rate can "
                        "accompany exploitation attempts that push malformed input at an "
                        "application."
                    ),
                    severity=Severity.low,
                    confidence=0.6,
                    locator={"scope": "aggregated"},
                    attributes={"server_errors": server_errors, "total_requests": total},
                )
            )

    def _check_exfil_hints(self, output: AnalyzerOutput, lines: list[str]) -> None:
        hits: list[tuple[int, str]] = []
        for number, line in enumerate(lines, start=1):
            if _EXFIL_HINTS.search(line):
                hits.append((number, line.strip()[:300]))
            if len(hits) >= 25:
                break
        if len(hits) < 3:
            return

        output.add_finding(
            ExtractedFinding(
                code="log.data_transfer_tooling",
                title="Repeated use of data transfer or encoding utilities",
                description=(
                    f"{len(hits)} log entries reference tools commonly used to move or encode "
                    "data (such as scp, rsync, curl, netcat or base64). These are standard "
                    "administrative utilities, so their presence is not itself evidence of "
                    "wrongdoing - but the specific commands and the accounts that ran them are "
                    "worth reviewing against expected activity for this host."
                ),
                severity=Severity.low,
                confidence=0.5,
                locator={"line": hits[0][0]},
                excerpt=hits[0][1],
                attributes={
                    "match_count": len(hits),
                    "sample_lines": [number for number, _ in hits[:10]],
                },
            )
        )

    def _check_gaps(self, output: AnalyzerOutput, times: list[datetime]) -> None:
        """Flag a silence long enough to suggest the log was interrupted or edited."""
        if len(times) < 20:
            return
        ordered = sorted(times)
        span = (ordered[-1] - ordered[0]).total_seconds()
        if span <= 0:
            return

        typical = span / len(ordered)
        largest = 0.0
        gap_at: datetime | None = None
        for earlier, later in pairwise(ordered):
            delta = (later - earlier).total_seconds()
            if delta > largest:
                largest = delta
                gap_at = earlier

        # Compared against the log's own average interval, so a busy log and a quiet one are each
        # judged on their own baseline rather than a fixed threshold.
        if largest >= max(3600.0, typical * 50) and gap_at is not None:
            output.add_finding(
                ExtractedFinding(
                    code="log.activity_gap",
                    title="Extended gap in log activity",
                    description=(
                        f"Logging stops for {largest / 3600:.1f} hours after "
                        f"{gap_at.isoformat()}, against an average interval of "
                        f"{typical:.1f} seconds across the file. A gap this far outside the "
                        "file's own rhythm can indicate the service stopped, the host was "
                        "offline, or entries were removed."
                    ),
                    severity=Severity.low,
                    confidence=0.55,
                    locator={"scope": "aggregated"},
                    attributes={
                        "gap_seconds": int(largest),
                        "gap_starts_at": gap_at.isoformat(),
                        "mean_interval_seconds": round(typical, 2),
                        "method": "largest inter-record interval versus file mean",
                        "threshold": "50x mean interval, minimum 1 hour",
                    },
                )
            )


register(LogAnalyzer())
