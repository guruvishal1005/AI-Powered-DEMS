"""Human-readable reference identifiers.

Investigators quote references out loud, write them in reports and search for them, so
surrogate UUIDs are unusable as the primary handle. Every user-facing entity therefore
carries both a UUID primary key and a sortable display reference such as
``CT-2026-0042`` (case) or ``E-2026-00117`` (evidence).
"""

from __future__ import annotations

import re

CASE_REF_PATTERN = re.compile(r"^CT-\d{4}-\d{4,}$")
EVIDENCE_REF_PATTERN = re.compile(r"^E-\d{4}-\d{5,}$")
REPORT_REF_PATTERN = re.compile(r"^RPT-\d{4}-\d{4,}$")


def format_case_ref(year: int, sequence: int) -> str:
    return f"CT-{year:04d}-{sequence:04d}"


def format_evidence_ref(year: int, sequence: int) -> str:
    return f"E-{year:04d}-{sequence:05d}"


def format_report_ref(year: int, sequence: int) -> str:
    return f"RPT-{year:04d}-{sequence:04d}"


def format_alert_ref(year: int, sequence: int) -> str:
    return f"AL-{year:04d}-{sequence:05d}"
