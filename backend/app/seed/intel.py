"""Curated offline threat-intelligence rows for the demo feed."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import IndicatorSeverity, IndicatorType
from app.models.intel import ThreatIndicator
from app.seed.indicators import ATTACKER_IP, C2_DOMAIN, C2_URL, SPOOFED_FROM, WALLET


def seed_indicators(session: Session) -> int:
    catalog = (
        (
            IndicatorType.ip_address,
            ATTACKER_IP,
            IndicatorSeverity.malicious,
            "Command-and-control address associated with the InvoiceLock ransomware cluster.",
            "InvoiceLock",
            "ransomware",
        ),
        (
            IndicatorType.domain,
            C2_DOMAIN,
            IndicatorSeverity.malicious,
            "Phishing and payload staging domain used in Globex-related campaigns.",
            "InvoiceLock",
            "bec",
        ),
        (
            IndicatorType.url,
            C2_URL,
            IndicatorSeverity.malicious,
            "Second-stage payload URL hosted on the InvoiceLock infrastructure.",
            "InvoiceLock",
            "ransomware",
        ),
        (
            IndicatorType.email_address,
            SPOOFED_FROM,
            IndicatorSeverity.suspicious,
            "Display-name spoof used in Globex accounts-payable BEC lures.",
            None,
            "bec",
        ),
        (
            IndicatorType.crypto_wallet,
            WALLET,
            IndicatorSeverity.malicious,
            "Bitcoin address quoted in InvoiceLock ransom notes.",
            "InvoiceLock",
            "ransomware",
        ),
    )
    created = 0
    for kind, value, severity, description, actor, family in catalog:
        exists = session.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.type == kind,
                ThreatIndicator.canonical_value == value,
                ThreatIndicator.source == "cybertrace-curated",
            )
        ).scalar_one_or_none()
        if exists is not None:
            continue
        session.add(
            ThreatIndicator(
                type=kind,
                canonical_value=value,
                severity=severity,
                confidence=0.86,
                source="cybertrace-curated",
                source_reference="CYBERTRACE demo feed 2026-08",
                description=description,
                tags=[family] if family else [],
                threat_actor=actor,
                malware_family=family,
                is_active=True,
            )
        )
        created += 1
    session.flush()
    return created
