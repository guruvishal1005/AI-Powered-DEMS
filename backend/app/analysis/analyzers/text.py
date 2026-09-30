"""Plain text, CSV and chat-export analyzer.

The catch-all for textual evidence that is not a log, an email or an office document: notes,
pasted chat transcripts, ransom messages, exported contact lists, netflow and transaction CSVs.

CSV is handled structurally rather than as free text. Once a delimiter and header row are known,
each column can be profiled - a column of IP addresses, a column of amounts, a column of timestamps
- and that is far more useful than scanning the whole file as prose. When a timestamp column is
identified alongside other fields, rows become timeline observations, which is what makes an
exported transaction ledger or netflow capture participate in the investigation timeline.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from app.analysis import indicators
from app.analysis.base import (
    AnalyzerOutput,
    ArtifactHandle,
    BaseAnalyzer,
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

MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_CSV_ROWS = 50_000
MAX_ROW_OBSERVATIONS = 300

_TIMESTAMP_COLUMN_HINTS = (
    "time", "date", "timestamp", "when", "created", "modified", "sent", "received",
    "start", "end", "occurred", "logged", "seen",
)
_AMOUNT_COLUMN_HINTS = ("amount", "value", "total", "sum", "balance", "price", "fee", "qty")

# Language that indicates extortion. Matched case-insensitively across the whole document; a single
# hit is meaningless, so a threshold applies before anything is reported.
_EXTORTION_TERMS = (
    "bitcoin", "btc", "monero", "xmr", "wallet address", "ransom", "decrypt", "decryption key",
    "your files have been encrypted", "pay within", "deadline", "leak your data",
    "publish your data", "private key", "recovery key", "tor browser", ".onion",
)

_CREDENTIAL_PATTERNS = (
    re.compile(r"\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*\S{4,}", re.I),
    re.compile(r"\b(?:BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY)\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)


class TextAnalyzer(BaseAnalyzer):
    name = "text_content"
    version = "1"
    description = "Indicators, structured columns and threatening language in textual evidence"
    mime_prefixes = ("text/", "application/json", "application/xml", "application/csv")
    evidence_types = (
        EvidenceType.document,
        EvidenceType.spreadsheet,
        EvidenceType.chat_export,
        EvidenceType.database_export,
        EvidenceType.network_log,
        EvidenceType.other,
    )
    max_size_bytes = MAX_TEXT_BYTES

    def analyze(self, artifact: ArtifactHandle) -> AnalyzerOutput:
        output = AnalyzerOutput()
        text, truncated = artifact.read_text(MAX_TEXT_BYTES)
        output.bytes_examined = len(text.encode("utf-8", errors="replace"))
        output.truncated = truncated

        if not text.strip():
            output.skip_reason = "File contains no textual content"
            return output

        lines = text.splitlines()
        structure = self._csv_structure(text, artifact)

        output.metadata = {
            "line_count": len(lines),
            "character_count": len(text),
            "word_count": len(text.split()),
            "blank_line_count": sum(1 for line in lines if not line.strip()),
            "longest_line": max((len(line) for line in lines), default=0),
            "csv": structure,
            "replacement_char_count": text.count("\ufffd"),
        }

        for entity in indicators.extract(text, source_label="text"):
            output.add_entity(entity)

        if structure is not None:
            self._emit_csv_observations(output, text, structure)

        self._check_extortion_language(output, text)
        self._check_credentials(output, lines)
        self._check_encoding_damage(output, text)
        return output

    def _csv_structure(
        self, text: str, artifact: ArtifactHandle
    ) -> dict[str, Any] | None:
        """Detect delimiter, header and per-column content types.

        Returns ``None`` when the content is not usefully tabular, which is the common case for
        prose. Requiring a consistent field count across several rows is what keeps a paragraph
        containing commas from being treated as a spreadsheet.
        """
        sample = text[:64 * 1024]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            return None

        reader = csv.reader(io.StringIO(text), dialect)
        try:
            rows = [row for _, row in zip(range(MAX_CSV_ROWS), reader, strict=False)]
        except csv.Error:
            return None

        rows = [row for row in rows if row]
        if len(rows) < 3:
            return None

        widths = Counter(len(row) for row in rows)
        modal_width, modal_count = widths.most_common(1)[0]
        if modal_width < 2 or modal_count / len(rows) < 0.8:
            return None

        has_header = False
        try:
            has_header = csv.Sniffer().has_header(sample)
        except csv.Error:
            has_header = False

        header = (
            [name.strip() for name in rows[0]]
            if has_header
            else [f"column_{index + 1}" for index in range(modal_width)]
        )
        body = rows[1:] if has_header else rows
        body = [row for row in body if len(row) == modal_width]

        columns = self._profile_columns(header, body)
        return {
            "delimiter": dialect.delimiter,
            "has_header": has_header,
            "column_count": modal_width,
            "row_count": len(body),
            "header": header[:60],
            "columns": columns,
            "timestamp_column": self._pick_timestamp_column(columns),
            "source_filename": artifact.filename,
        }

    def _profile_columns(
        self, header: list[str], body: list[list[str]]
    ) -> list[dict[str, Any]]:
        profiles: list[dict[str, Any]] = []
        for index, name in enumerate(header[:60]):
            values = [row[index].strip() for row in body[:2000] if index < len(row)]
            non_empty = [value for value in values if value]
            if not non_empty:
                profiles.append({"index": index, "name": name, "inferred_type": "empty"})
                continue

            detected: Counter[str] = Counter()
            for value in non_empty[:500]:
                detected[self._value_type(value)] += 1
            inferred, hits = detected.most_common(1)[0]

            profiles.append(
                {
                    "index": index,
                    "name": name,
                    "inferred_type": inferred,
                    # Recorded so a column that is 60% addresses reads differently from one that
                    # is 100% addresses.
                    "type_agreement": round(hits / len(non_empty[:500]), 3),
                    "distinct_values": len({value.lower() for value in non_empty}),
                    "fill_ratio": round(len(non_empty) / len(values), 3) if values else 0.0,
                    "sample": non_empty[0][:120],
                }
            )
        return profiles

    def _value_type(self, value: str) -> str:
        if self._parse_time(value) is not None:
            return "timestamp"
        for entity_type in (
            EntityType.ip_address,
            EntityType.email_address,
            EntityType.url,
            EntityType.mac_address,
            EntityType.crypto_wallet,
            EntityType.file_hash,
        ):
            matches = list(indicators.iter_matches(value, (entity_type,)))
            if matches and matches[0].value == value:
                return entity_type.value
        stripped = value.replace(",", "").replace("$", "").replace("\u00a3", "").strip()
        try:
            float(stripped)
        except ValueError:
            return "text"
        return "number"

    def _pick_timestamp_column(self, columns: list[dict[str, Any]]) -> int | None:
        # A column whose values parse as timestamps is preferred over one that merely has a
        # time-like name, since names lie and values do not.
        typed = [
            column
            for column in columns
            if column.get("inferred_type") == "timestamp"
            and column.get("type_agreement", 0) >= 0.8
        ]
        if typed:
            return int(typed[0]["index"])
        named = [
            column
            for column in columns
            if any(hint in str(column["name"]).lower() for hint in _TIMESTAMP_COLUMN_HINTS)
        ]
        return int(named[0]["index"]) if named else None

    def _parse_time(self, value: str) -> datetime | None:
        raw = value.strip()
        if len(raw) < 8 or len(raw) > 40:
            return None
        candidate = raw.replace("Z", "+00:00").replace("/", "-")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            for fmt in ("%d-%m-%Y %H:%M:%S", "%m-%d-%Y %H:%M:%S", "%d-%m-%Y", "%Y-%m-%d %H:%M"):
                try:
                    parsed = datetime.strptime(candidate, fmt)
                    break
                except ValueError:
                    continue
            else:
                # A bare epoch is only accepted inside a plausible range, so an unrelated
                # ten-digit identifier is not silently reinterpreted as a date.
                if raw.isdigit() and 10 <= len(raw) <= 13:
                    seconds = int(raw) / (1000 if len(raw) == 13 else 1)
                    if 946_684_800 <= seconds <= 4_102_444_800:
                        return datetime.fromtimestamp(seconds, tz=UTC)
                return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    def _emit_csv_observations(
        self, output: AnalyzerOutput, text: str, structure: dict[str, Any]
    ) -> None:
        column_index = structure.get("timestamp_column")
        if column_index is None:
            return

        header: list[str] = structure["header"]
        columns: list[dict[str, Any]] = structure["columns"]
        reader = csv.reader(
            io.StringIO(text), delimiter=str(structure["delimiter"])
        )
        rows = list(zip(range(MAX_CSV_ROWS + 1), reader, strict=False))
        if structure["has_header"]:
            rows = rows[1:]

        # Which columns are worth naming in the summary: identifiers and amounts, not every field.
        interesting = [
            column
            for column in columns
            if column.get("inferred_type")
            in ("ip_address", "email_address", "url", "crypto_wallet", "mac_address")
            or any(hint in str(column["name"]).lower() for hint in _AMOUNT_COLUMN_HINTS)
        ][:4]

        emitted = 0
        for line_number, row in rows:
            if emitted >= MAX_ROW_OBSERVATIONS:
                output.truncated = True
                break
            if column_index >= len(row):
                continue
            when = self._parse_time(row[column_index])
            if when is None:
                continue

            details = []
            for column in interesting:
                index = int(column["index"])
                if index < len(row) and row[index].strip():
                    details.append(f"{column['name']}={row[index].strip()[:80]}")

            source_value = next(
                (
                    row[int(column["index"])].strip()
                    for column in columns
                    if column.get("inferred_type") == "ip_address"
                    and int(column["index"]) < len(row)
                    and row[int(column["index"])].strip()
                ),
                None,
            )

            output.add_observation(
                ExtractedObservation(
                    kind=ObservationKind.transaction
                    if any(
                        hint in " ".join(header).lower() for hint in _AMOUNT_COLUMN_HINTS
                    )
                    else ObservationKind.generic,
                    occurred_at=when,
                    summary=(
                        "; ".join(details)
                        if details
                        else f"Record at row {line_number + 1}"
                    )[:500],
                    locator={"row": line_number + 1, "column": column_index},
                    excerpt=str(structure["delimiter"]).join(row)[:500],
                    source_value=source_value,
                    time_confidence=Confidence.moderate,
                    timezone_assumed=True,
                    attributes={
                        "row": line_number + 1,
                        "timestamp_column": header[column_index]
                        if column_index < len(header)
                        else column_index,
                        "note": (
                            "Tabular export; timestamps carried no zone and are treated as UTC."
                        ),
                    },
                    entity_values=tuple(value for value in (source_value,) if value),
                )
            )
            emitted += 1

    def _check_extortion_language(self, output: AnalyzerOutput, text: str) -> None:
        lowered = text.lower()
        hits = [term for term in _EXTORTION_TERMS if term in lowered]
        # Terms overlap by design ("decrypt" inside "decryption key"), and counting both would
        # inflate a single phrase into two independent signals and trip the threshold on its own.
        matched = [
            term
            for term in hits
            if not any(other != term and term in other for other in hits)
        ]
        wallets = list(
            indicators.iter_matches(text, (EntityType.crypto_wallet,))
        )

        # A wallet address alongside extortion vocabulary is a far stronger signal than either
        # alone, so the threshold drops sharply when both are present. Without a payment address
        # the bar is deliberately high, because incident notes, policy documents and training
        # material all discuss ransom demands using exactly this vocabulary.
        threshold = 2 if wallets else 5
        if len(matched) < threshold:
            return

        output.add_finding(
            ExtractedFinding(
                code="text.extortion_language",
                title=(
                    "Extortion language with cryptocurrency payment details"
                    if wallets
                    else "Language consistent with an extortion demand"
                ),
                description=(
                    f"The text contains {len(matched)} term(s) associated with extortion "
                    f"({', '.join(matched[:8])})"
                    + (
                        f", together with {len(wallets)} cryptocurrency address(es) such as "
                        f"{wallets[0].value}. The combination of a payment address with demand "
                        "language is characteristic of a ransom note."
                        if wallets
                        else ". No payment address was found, so this may be a discussion of an "
                        "incident rather than a demand itself."
                    )
                ),
                severity=Severity.high if wallets else Severity.medium,
                confidence=0.8 if wallets else 0.55,
                locator={"scope": "document"},
                excerpt=self._first_context(text, matched[0]),
                attributes={
                    "matched_terms": matched[:20],
                    "wallet_addresses": [match.value for match in wallets[:10]],
                    "method": "keyword co-occurrence with payment address detection",
                    "threshold": f"{threshold} terms",
                },
            )
        )

    def _check_credentials(self, output: AnalyzerOutput, lines: list[str]) -> None:
        hits: list[tuple[int, str]] = []
        for number, line in enumerate(lines, start=1):
            for pattern in _CREDENTIAL_PATTERNS:
                if pattern.search(line):
                    hits.append((number, line.strip()[:200]))
                    break
            if len(hits) >= 50:
                break
        if not hits:
            return

        output.add_finding(
            ExtractedFinding(
                code="text.exposed_credentials",
                title=f"Possible credentials or API keys present ({len(hits)} line(s))",
                description=(
                    f"{len(hits)} line(s) match patterns for passwords, private keys or service "
                    "API tokens. If these are live credentials they should be treated as "
                    "compromised and rotated, independently of the investigation. The values "
                    "themselves are deliberately not reproduced in this finding."
                ),
                severity=Severity.high,
                confidence=0.6,
                locator={"line": hits[0][0]},
                # The matching values are withheld: copying live secrets into findings, reports and
                # exports would spread the exposure through the platform's own records.
                excerpt=None,
                attributes={
                    "match_count": len(hits),
                    "line_numbers": [number for number, _ in hits[:20]],
                    "note": "Matched values are withheld to avoid propagating live secrets.",
                },
            )
        )

    def _check_encoding_damage(self, output: AnalyzerOutput, text: str) -> None:
        replacements = text.count("\ufffd")
        if not text or replacements / len(text) < 0.01:
            return
        output.add_finding(
            ExtractedFinding(
                code="text.encoding_damage",
                title="Text contains a high proportion of undecodable bytes",
                description=(
                    f"{replacements} byte sequences ({replacements / len(text):.1%} of the file) "
                    "could not be decoded as UTF-8 and were replaced. The file may use a "
                    "different character encoding, be partially corrupt, or contain embedded "
                    "binary data. Extracted text from this artifact is incomplete."
                ),
                severity=Severity.low,
                confidence=0.8,
                locator={"scope": "document"},
                attributes={
                    "replacement_count": replacements,
                    "ratio": round(replacements / len(text), 4),
                },
            )
        )

    def _first_context(self, text: str, term: str) -> str:
        index = text.lower().find(term.lower())
        if index == -1:
            return ""
        start = max(0, index - 80)
        return text[start : index + len(term) + 80].replace("\n", " ").strip()


register(TextAnalyzer())
