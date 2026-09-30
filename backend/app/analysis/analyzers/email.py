"""RFC 5322 email analyzer: headers, Received chain and authentication results.

Email is the single richest artifact type in most cybercrime cases, and almost all of the value is
in the headers rather than the body. This analyzer reconstructs the delivery path from the
``Received`` chain, evaluates SPF/DKIM/DMARC results as *reported by the receiving infrastructure*,
and looks for the specific inconsistencies that characterise phishing and business email
compromise.

Two things it is careful about:

**Received headers are read bottom-up.** Each relay prepends its own, so the last header in the
file is the first hop. Getting this backwards inverts the delivery path, which is the kind of error
that survives review because the output still looks plausible.

**Sender addresses are compared by domain, not string.** ``From: "Accounts Payable"
<billing@vendor-invoices.net>`` versus a ``Reply-To`` at a different domain is the signature of a
redirect attempt, but a display name differing from the address is entirely normal and is not
flagged on its own.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from email import message_from_bytes, policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
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

MAX_EMAIL_BYTES = 64 * 1024 * 1024

# Extensions that execute or can carry macros. Attachment names ending in these are reported.
_DANGEROUS_EXTENSIONS = frozenset(
    {
        "exe", "scr", "pif", "com", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh",
        "ps1", "psm1", "msi", "msp", "hta", "cpl", "jar", "reg", "lnk", "inf", "iso", "img",
        "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "sldm", "vhd", "vhdx",
    }
)

_ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "gz", "tar", "bz2", "xz", "cab", "ace"})

_RECEIVED_FROM = re.compile(
    r"from\s+(?P<host>[^\s;(]+)(?:\s+\((?P<detail>[^)]*)\))?", re.IGNORECASE
)
_RECEIVED_BY = re.compile(r"\bby\s+(?P<host>[^\s;(]+)", re.IGNORECASE)
_AUTH_RESULT = re.compile(
    r"\b(?P<mech>spf|dkim|dmarc|compauth)=(?P<result>[a-z]+)", re.IGNORECASE
)


def _decoded(value: str | None) -> str:
    """Decode RFC 2047 encoded-words, which is how non-ASCII subjects arrive."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value))).strip()
    except (UnicodeDecodeError, LookupError, ValueError):
        return value.strip()


def _domain_of(address: str) -> str:
    _, _, domain = address.rpartition("@")
    return domain.lower().strip("[]> ")


def _registrable(domain: str) -> str:
    """Approximate the registrable domain by taking the final two labels.

    A full public-suffix list would be more accurate for multi-part suffixes such as
    ``co.uk``, and this is noted as a known limitation rather than papered over: the comparison is
    only used to decide whether to *report* a mismatch for an analyst to judge, never to assert
    that a message is malicious.
    """
    labels = domain.strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


class EmailAnalyzer(BaseAnalyzer):
    name = "email_headers"
    version = "1"
    description = "Email headers, delivery path, authentication results and attachment inventory"
    mime_prefixes = ("message/rfc822",)
    evidence_types = (EvidenceType.email_message,)
    max_size_bytes = MAX_EMAIL_BYTES

    def analyze(self, artifact: ArtifactHandle) -> AnalyzerOutput:
        output = AnalyzerOutput()
        raw, truncated = artifact.read_bytes(MAX_EMAIL_BYTES)
        output.bytes_examined = len(raw)
        output.truncated = truncated

        message = message_from_bytes(raw, policy=policy.default)
        if not isinstance(message, EmailMessage):  # pragma: no cover - policy.default guarantees
            output.skip_reason = "Content did not parse as an RFC 5322 message"
            return output

        headers = self._header_map(message)
        senders = self._addresses(message, "from")
        reply_to = self._addresses(message, "reply-to")
        return_path = self._addresses(message, "return-path")
        recipients = (
            self._addresses(message, "to")
            + self._addresses(message, "cc")
            + self._addresses(message, "bcc")
        )
        subject = _decoded(message.get("subject"))
        sent_at, tz_assumed = self._sent_at(message)
        hops = self._received_chain(message)
        auth = self._authentication(message)
        attachments = self._attachments(message, output)
        body_text = self._body_text(message)

        output.metadata = {
            "message_id": _decoded(message.get("message-id")),
            "subject": subject,
            "from": senders,
            "reply_to": reply_to,
            "return_path": return_path,
            "to": self._addresses(message, "to"),
            "cc": self._addresses(message, "cc"),
            "date_header": _decoded(message.get("date")),
            "sent_at": sent_at.isoformat() if sent_at else None,
            "timezone_assumed": tz_assumed,
            "hop_count": len(hops),
            "delivery_path": hops,
            "authentication": auth,
            "attachments": attachments,
            "header_names": list(headers),
            "x_mailer": _decoded(message.get("x-mailer")),
            "user_agent": _decoded(message.get("user-agent")),
            "body_bytes": len(body_text.encode("utf-8", errors="replace")),
        }

        self._record_participants(output, senders, recipients, reply_to, return_path)
        self._record_infrastructure(output, hops)
        self._record_body_indicators(output, body_text)

        if sent_at is not None:
            output.add_observation(
                ExtractedObservation(
                    kind=ObservationKind.email_sent,
                    occurred_at=sent_at,
                    summary=(
                        f"Email \u201c{subject or '(no subject)'}\u201d sent from "
                        f"{senders[0] if senders else 'unknown sender'}"
                    ),
                    locator={"header": "Date"},
                    excerpt=_decoded(message.get("date")),
                    actor_value=senders[0] if senders else None,
                    target_value=recipients[0] if recipients else None,
                    # The Date header is written by the sender's client, so it is only as
                    # trustworthy as the sender. The Received chain is the corroborating source.
                    time_confidence=Confidence.moderate if tz_assumed else Confidence.high,
                    timezone_assumed=tz_assumed,
                    attributes={
                        "subject": subject,
                        "recipients": recipients[:20],
                        "source": "Date header (sender-supplied)",
                    },
                    entity_values=tuple(senders + recipients[:20]),
                )
            )

        for hop in hops:
            if hop.get("timestamp"):
                output.add_observation(
                    ExtractedObservation(
                        kind=ObservationKind.email_received,
                        occurred_at=datetime.fromisoformat(hop["timestamp"]),
                        summary=(
                            f"Relayed by {hop.get('by') or 'unknown host'}"
                            + (f" from {hop['from']}" if hop.get("from") else "")
                        ),
                        locator={"header": "Received", "hop": hop["index"]},
                        excerpt=hop["raw"][:500],
                        source_value=hop.get("from_ip") or hop.get("from"),
                        target_value=hop.get("by"),
                        # Received headers are added by mail infrastructure rather than the
                        # sender, making them the more reliable timing source.
                        time_confidence=Confidence.high,
                        attributes={"hop_index": hop["index"], "protocol": hop.get("with")},
                        entity_values=tuple(
                            value for value in (hop.get("from_ip"), hop.get("by")) if value
                        ),
                    )
                )

        self._check_sender_alignment(output, senders, reply_to, return_path)
        self._check_authentication(output, auth, senders)
        self._check_attachments(output, attachments)
        self._check_timing(output, sent_at, hops)
        self._check_missing_headers(output, headers, hops)

        return output

    def _header_map(self, message: EmailMessage) -> dict[str, list[str]]:
        headers: dict[str, list[str]] = {}
        for name, value in message.items():
            headers.setdefault(name.lower(), []).append(str(value))
        return headers

    def _addresses(self, message: EmailMessage, header: str) -> list[str]:
        values = message.get_all(header, [])
        pairs = getaddresses([str(value) for value in values])
        return [addr.lower().strip("<> ") for _name, addr in pairs if "@" in addr]

    def _sent_at(self, message: EmailMessage) -> tuple[datetime | None, bool]:
        raw = message.get("date")
        if not raw:
            return None, False
        try:
            parsed = parsedate_to_datetime(str(raw))
        except (TypeError, ValueError):
            return None, False
        if parsed.tzinfo is None:
            # No offset given. UTC is assumed and the assumption is recorded, because silently
            # shifting an event by an unknown number of hours corrupts the timeline.
            return parsed.replace(tzinfo=UTC), True
        return parsed.astimezone(UTC), False

    def _received_chain(self, message: EmailMessage) -> list[dict[str, Any]]:
        """Parse Received headers into an ordered delivery path, first hop first."""
        raw_headers = [str(value) for value in message.get_all("received", [])]
        hops: list[dict[str, Any]] = []

        # Reversed: mail servers prepend, so the file's last Received header is the earliest hop.
        for index, raw in enumerate(reversed(raw_headers)):
            collapsed = " ".join(raw.split())
            hop: dict[str, Any] = {"index": index, "raw": collapsed}

            from_match = _RECEIVED_FROM.search(collapsed)
            if from_match:
                hop["from"] = from_match.group("host")
                detail = from_match.group("detail") or ""
                # The parenthesised detail is where the real connecting IP usually sits, since
                # the announced HELO hostname is attacker-controlled and often false.
                found = [
                    match.value
                    for match in indicators.iter_matches(
                        detail or collapsed, (EntityType.ip_address,)
                    )
                ]
                if found:
                    hop["from_ip"] = found[0]
                if detail:
                    hop["from_detail"] = detail

            by_match = _RECEIVED_BY.search(collapsed)
            if by_match:
                hop["by"] = by_match.group("host")

            with_match = re.search(r"\bwith\s+(?P<proto>[A-Za-z0-9/]+)", collapsed)
            if with_match:
                hop["with"] = with_match.group("proto")

            _, _, tail = collapsed.rpartition(";")
            if tail.strip():
                try:
                    stamp = parsedate_to_datetime(tail.strip())
                except (TypeError, ValueError):
                    stamp = None
                if stamp is not None:
                    if stamp.tzinfo is None:
                        stamp = stamp.replace(tzinfo=UTC)
                    hop["timestamp"] = stamp.astimezone(UTC).isoformat()

            hops.append(hop)
        return hops

    def _authentication(self, message: EmailMessage) -> dict[str, Any]:
        """Collect authentication verdicts recorded by the receiving infrastructure.

        These are read, never recomputed: SPF and DKIM can only be evaluated at delivery time
        against DNS as it was then, and re-checking now would produce a different and misleading
        answer. What the receiving server concluded is the forensically meaningful fact.
        """
        results: dict[str, Any] = {"raw": [], "spf": None, "dkim": None, "dmarc": None}

        for header in ("authentication-results", "arc-authentication-results"):
            for value in message.get_all(header, []):
                text = str(value)
                results["raw"].append(text)
                for match in _AUTH_RESULT.finditer(text):
                    mech = match.group("mech").lower()
                    if mech in results and results[mech] is None:
                        results[mech] = match.group("result").lower()

        received_spf = message.get("received-spf")
        if received_spf:
            results["raw"].append(str(received_spf))
            if results["spf"] is None:
                first = str(received_spf).strip().split()[0:1]
                if first:
                    results["spf"] = first[0].lower()

        results["dkim_signature_present"] = bool(message.get("dkim-signature"))
        if results["dkim_signature_present"]:
            signature = str(message.get("dkim-signature"))
            domain = re.search(r"\bd=([^;\s]+)", signature)
            selector = re.search(r"\bs=([^;\s]+)", signature)
            results["dkim_domain"] = domain.group(1).lower() if domain else None
            results["dkim_selector"] = selector.group(1) if selector else None

        return results

    def _attachments(self, message: EmailMessage, output: AnalyzerOutput) -> list[dict[str, Any]]:
        attachments: list[dict[str, Any]] = []
        for part in message.walk():
            if part.is_multipart():
                continue
            disposition = (part.get_content_disposition() or "").lower()
            filename = _decoded(part.get_filename())
            if disposition != "attachment" and not filename:
                continue

            payload = part.get_payload(decode=True)
            size = len(payload) if isinstance(payload, bytes) else 0
            extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

            record: dict[str, Any] = {
                "filename": filename or "(unnamed)",
                "content_type": part.get_content_type(),
                "size_bytes": size,
                "extension": extension,
                "disposition": disposition or "inline",
            }

            if isinstance(payload, bytes) and payload:
                from app.forensics.hashing import hash_bytes

                record["sha256"] = hash_bytes(payload).sha256
                output.add_entity(
                    ExtractedEntity(
                        type=EntityType.file_hash,
                        value=record["sha256"],
                        locator={"attachment": record["filename"]},
                        context="attachment_sha256",
                        excerpt=f"{record['filename']} ({size} bytes)",
                    )
                )

            if filename:
                output.add_entity(
                    ExtractedEntity(
                        type=EntityType.file_name,
                        value=filename,
                        locator={"attachment": filename},
                        context="attachment",
                    )
                )

            attachments.append(record)
        return attachments

    def _body_text(self, message: EmailMessage) -> str:
        try:
            body = message.get_body(preferencelist=("plain", "html"))
        except (AttributeError, KeyError):  # pragma: no cover - malformed structure
            body = None
        if body is None:
            return ""
        content = body.get_content()
        return content if isinstance(content, str) else ""

    def _record_participants(
        self,
        output: AnalyzerOutput,
        senders: list[str],
        recipients: list[str],
        reply_to: list[str],
        return_path: list[str],
    ) -> None:
        for role, addresses in (
            ("sender", senders),
            ("recipient", recipients),
            ("reply_to", reply_to),
            ("return_path", return_path),
        ):
            for address in addresses:
                output.add_entity(
                    ExtractedEntity(
                        type=EntityType.email_address,
                        value=address,
                        locator={"header": role},
                        context=role,
                    )
                )
                domain = _domain_of(address)
                if domain:
                    output.add_entity(
                        ExtractedEntity(
                            type=EntityType.domain,
                            value=domain,
                            locator={"header": role},
                            context=f"{role}_domain",
                        )
                    )

    def _record_infrastructure(self, output: AnalyzerOutput, hops: list[dict[str, Any]]) -> None:
        for hop in hops:
            if hop.get("from_ip"):
                output.add_entity(
                    ExtractedEntity(
                        type=EntityType.ip_address,
                        value=hop["from_ip"],
                        locator={"header": "Received", "hop": hop["index"]},
                        excerpt=hop["raw"][:300],
                        # Hop 0 is the originating relay, which is the address that actually
                        # matters when attributing a message.
                        context="originating_ip" if hop["index"] == 0 else "relay_ip",
                    )
                )
            for key, role in (("from", "helo_host"), ("by", "relay_host")):
                host = hop.get(key)
                if host and "." in host and indicators.plausible_domain(host):
                    output.add_entity(
                        ExtractedEntity(
                            type=EntityType.domain,
                            value=host.lower(),
                            locator={"header": "Received", "hop": hop["index"]},
                            context=role,
                        )
                    )

    def _record_body_indicators(self, output: AnalyzerOutput, body: str) -> None:
        for entity in indicators.extract(
            body,
            types=(
                EntityType.url,
                EntityType.ip_address,
                EntityType.email_address,
                EntityType.crypto_wallet,
                EntityType.phone_number,
                EntityType.cve,
            ),
            source_label="body",
        ):
            output.add_entity(entity)

    def _check_sender_alignment(
        self,
        output: AnalyzerOutput,
        senders: list[str],
        reply_to: list[str],
        return_path: list[str],
    ) -> None:
        if not senders:
            return
        from_domain = _registrable(_domain_of(senders[0]))

        if reply_to:
            reply_domain = _registrable(_domain_of(reply_to[0]))
            if reply_domain and reply_domain != from_domain:
                output.add_finding(
                    ExtractedFinding(
                        code="email.reply_to_mismatch",
                        title="Reply-To points to a different domain than From",
                        description=(
                            f"The message claims to be from {senders[0]} ({from_domain}) but "
                            f"replies would be directed to {reply_to[0]} ({reply_domain}). "
                            "Redirecting replies to an unrelated domain is a common technique in "
                            "business email compromise, though it also occurs legitimately with "
                            "mailing lists and ticketing systems."
                        ),
                        severity=Severity.medium,
                        confidence=0.75,
                        locator={"header": "Reply-To"},
                        excerpt=f"From: {senders[0]} | Reply-To: {reply_to[0]}",
                        attributes={
                            "from_domain": from_domain,
                            "reply_to_domain": reply_domain,
                        },
                    )
                )

        if return_path:
            envelope_domain = _registrable(_domain_of(return_path[0]))
            if envelope_domain and envelope_domain != from_domain:
                output.add_finding(
                    ExtractedFinding(
                        code="email.envelope_mismatch",
                        title="Envelope sender does not align with the From header",
                        description=(
                            f"The envelope sender is {return_path[0]} ({envelope_domain}) while "
                            f"the displayed sender is {senders[0]} ({from_domain}). This is what "
                            "SPF alignment checks examine; it is also normal for mail sent via "
                            "third-party providers and mailing lists."
                        ),
                        severity=Severity.low,
                        confidence=0.6,
                        locator={"header": "Return-Path"},
                        excerpt=f"From: {senders[0]} | Return-Path: {return_path[0]}",
                        attributes={
                            "from_domain": from_domain,
                            "envelope_domain": envelope_domain,
                        },
                    )
                )

    def _check_authentication(
        self, output: AnalyzerOutput, auth: dict[str, Any], senders: list[str]
    ) -> None:
        failures = {
            mech: auth.get(mech)
            for mech in ("spf", "dkim", "dmarc")
            if auth.get(mech) in {"fail", "softfail", "permerror", "temperror", "none"}
        }
        hard_failures = {
            mech: result for mech, result in failures.items() if result in {"fail", "permerror"}
        }

        if hard_failures:
            output.add_finding(
                ExtractedFinding(
                    code="email.authentication_failed",
                    title="Sender authentication failed at the receiving server",
                    description=(
                        "The receiving mail infrastructure recorded "
                        + ", ".join(f"{mech.upper()}={result}" for mech, result in
                                    sorted(hard_failures.items()))
                        + ". A hard failure means the sending server was not authorised to send "
                        f"for {_domain_of(senders[0]) if senders else 'the claimed domain'}, "
                        "which is consistent with spoofing. These verdicts are read from the "
                        "delivery headers, not recomputed, because they can only be evaluated "
                        "against DNS as it was at delivery time."
                    ),
                    severity=Severity.high,
                    confidence=0.9,
                    locator={"header": "Authentication-Results"},
                    excerpt="; ".join(auth.get("raw", []))[:500],
                    attributes={
                        "results": {k: v for k, v in auth.items() if k in ("spf", "dkim", "dmarc")},
                        "source": "receiving server verdict",
                    },
                )
            )
        elif not auth.get("raw") and not auth.get("dkim_signature_present"):
            output.add_finding(
                ExtractedFinding(
                    code="email.no_authentication_results",
                    title="No sender authentication results present",
                    description=(
                        "The message carries no Authentication-Results, Received-SPF or "
                        "DKIM-Signature header, so no verdict on sender authenticity can be "
                        "established from the artifact. This is expected for messages exported "
                        "before delivery or captured from a sender's own mailbox."
                    ),
                    severity=Severity.informational,
                    confidence=1.0,
                    locator={"scope": "headers"},
                )
            )

        dkim_domain = auth.get("dkim_domain")
        if dkim_domain and senders:
            if _registrable(str(dkim_domain)) != _registrable(_domain_of(senders[0])):
                output.add_finding(
                    ExtractedFinding(
                        code="email.dkim_domain_mismatch",
                        title="DKIM signing domain differs from the sender domain",
                        description=(
                            f"The message is DKIM-signed by {dkim_domain}, which does not align "
                            f"with the From domain {_domain_of(senders[0])}. A valid signature "
                            "from an unrelated domain proves only that the signing domain "
                            "handled the message, not that the displayed sender is genuine."
                        ),
                        severity=Severity.medium,
                        confidence=0.7,
                        locator={"header": "DKIM-Signature"},
                        attributes={
                            "dkim_domain": dkim_domain,
                            "from_domain": _domain_of(senders[0]),
                        },
                    )
                )

    def _check_attachments(
        self, output: AnalyzerOutput, attachments: list[dict[str, Any]]
    ) -> None:
        for attachment in attachments:
            extension = attachment["extension"]
            name = attachment["filename"]

            if extension in _DANGEROUS_EXTENSIONS:
                output.add_finding(
                    ExtractedFinding(
                        code="email.executable_attachment",
                        title=f"Executable or macro-enabled attachment: {name}",
                        description=(
                            f"The attachment {name} has a .{extension} extension, which can "
                            "execute code or carry macros when opened. Delivery of this file "
                            f"type by email is the initial access vector in a large share of "
                            "intrusions."
                        ),
                        severity=Severity.high,
                        confidence=0.95,
                        locator={"attachment": name},
                        attributes={
                            "extension": extension,
                            "content_type": attachment["content_type"],
                            "size_bytes": attachment["size_bytes"],
                            "sha256": attachment.get("sha256"),
                        },
                    )
                )
            elif extension in _ARCHIVE_EXTENSIONS:
                output.add_finding(
                    ExtractedFinding(
                        code="email.archive_attachment",
                        title=f"Archive attachment: {name}",
                        description=(
                            f"The attachment {name} is an archive. Archives are routinely used to "
                            "wrap executable payloads so that content scanning at the mail "
                            "gateway does not inspect them. The contents are not examined here; "
                            "extract and register them as separate evidence to analyse them."
                        ),
                        severity=Severity.low,
                        confidence=0.8,
                        locator={"attachment": name},
                        attributes={"extension": extension, "size_bytes": attachment["size_bytes"]},
                    )
                )

            # Right-to-left override reverses how the rest of the filename is displayed, so
            # "invoice\u202Efdp.exe" appears to the recipient as "invoiceexe.pdf".
            if any(char in name for char in ("\u202e", "\u202d", "\u200f", "\u2066", "\u2067")):
                output.add_finding(
                    ExtractedFinding(
                        code="email.filename_bidi_override",
                        title=f"Attachment filename contains a text-direction override: {name!r}",
                        description=(
                            "The filename contains a Unicode bidirectional override character, "
                            "which reverses the displayed order of the characters that follow it. "
                            "This is used to disguise an executable extension as a document "
                            "extension in the recipient's mail client. There is no legitimate "
                            "reason for a filename to contain these characters."
                        ),
                        severity=Severity.critical,
                        confidence=0.98,
                        locator={"attachment": name},
                        excerpt=name.encode("unicode_escape").decode("ascii"),
                        attributes={"raw_filename_escaped": name.encode("unicode_escape").decode()},
                    )
                )

            double = re.search(
                r"\.(pdf|docx?|xlsx?|jpe?g|png|txt|csv)\s*\.(\w{1,5})$", name, re.IGNORECASE
            )
            if double and double.group(2).lower() in _DANGEROUS_EXTENSIONS:
                output.add_finding(
                    ExtractedFinding(
                        code="email.double_extension",
                        title=f"Attachment uses a double extension: {name}",
                        description=(
                            f"The filename ends in .{double.group(1)}.{double.group(2)}. Systems "
                            "configured to hide known file extensions display only the first, so "
                            "the recipient sees a document while the operating system executes "
                            f"it as a .{double.group(2)} file."
                        ),
                        severity=Severity.high,
                        confidence=0.9,
                        locator={"attachment": name},
                        attributes={
                            "apparent_extension": double.group(1).lower(),
                            "effective_extension": double.group(2).lower(),
                        },
                    )
                )

    def _check_timing(
        self, output: AnalyzerOutput, sent_at: datetime | None, hops: list[dict[str, Any]]
    ) -> None:
        stamps = [
            datetime.fromisoformat(hop["timestamp"]) for hop in hops if hop.get("timestamp")
        ]
        if not stamps:
            return

        # Each relay should hand off later than the one before it. Time going backwards means a
        # header was forged or a server's clock is wrong; either is worth knowing.
        for earlier, later in pairwise(stamps):
            drift = (earlier - later).total_seconds()
            if drift > 120:
                output.add_finding(
                    ExtractedFinding(
                        code="email.received_chain_out_of_order",
                        title="Delivery timestamps run backwards through the relay chain",
                        description=(
                            f"A relay recorded a handoff {drift / 60:.1f} minutes earlier than "
                            "the hop preceding it. Received headers are appended in order, so "
                            "time cannot legitimately move backwards along the chain. This "
                            "indicates either a forged Received header or significant clock skew "
                            "on one of the servers."
                        ),
                        severity=Severity.medium,
                        confidence=0.7,
                        locator={"header": "Received"},
                        attributes={
                            "drift_seconds": int(drift),
                            "method": "monotonicity check across Received timestamps",
                            "threshold_seconds": 120,
                        },
                    )
                )
                break

        if sent_at is not None:
            first_receipt = min(stamps)
            skew = (first_receipt - sent_at).total_seconds()
            if abs(skew) > 86400:
                output.add_finding(
                    ExtractedFinding(
                        code="email.date_header_implausible",
                        title="Date header disagrees with the delivery path by over a day",
                        description=(
                            f"The Date header claims {sent_at.isoformat()} while the first relay "
                            f"recorded {first_receipt.isoformat()}, a difference of "
                            f"{abs(skew) / 3600:.1f} hours. The Date header is supplied by the "
                            "sender and is trivially falsified; the Received chain is written by "
                            "mail infrastructure and is the more reliable record."
                        ),
                        severity=Severity.medium,
                        confidence=0.85,
                        locator={"header": "Date"},
                        attributes={
                            "date_header": sent_at.isoformat(),
                            "first_received": first_receipt.isoformat(),
                            "skew_seconds": int(skew),
                            "threshold_seconds": 86400,
                        },
                    )
                )

    def _check_missing_headers(
        self, output: AnalyzerOutput, headers: dict[str, list[str]], hops: list[dict[str, Any]]
    ) -> None:
        if "message-id" not in headers:
            output.add_finding(
                ExtractedFinding(
                    code="email.missing_message_id",
                    title="Message-ID header is absent",
                    description=(
                        "Every mail client and server generates a Message-ID. Its absence "
                        "suggests the message was injected directly into a mail server by a "
                        "script rather than sent by a normal client."
                    ),
                    severity=Severity.low,
                    confidence=0.7,
                    locator={"scope": "headers"},
                )
            )

        if not hops:
            output.add_finding(
                ExtractedFinding(
                    code="email.no_delivery_path",
                    title="No Received headers present",
                    description=(
                        "The message contains no Received headers, so its delivery path cannot "
                        "be reconstructed and the sending infrastructure cannot be identified. "
                        "This is expected for a draft or an unsent message exported from a "
                        "client, and unexpected for a message that was actually delivered."
                    ),
                    severity=Severity.informational,
                    confidence=1.0,
                    locator={"scope": "headers"},
                )
            )


register(EmailAnalyzer())
