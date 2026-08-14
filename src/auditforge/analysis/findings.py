"""
AuditForge security findings module.

Defines structured security findings generated from assessment evidence.

This module stores and organizes findings. It does not perform network
requests, exploitation, severity calculation, or final risk scoring.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# Finding Categories
# ---------------------------------------------------------------------------

FINDING_CATEGORIES: tuple[str, ...] = (
    "configuration",
    "exposure",
    "tls",
    "http",
    "technology",
    "dns",
    "authentication",
    "information_disclosure",
    "other",
)


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Finding:
    """Represents one structured security finding."""

    finding_id: str
    title: str
    asset: str
    category: str

    description: str = ""
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""

    severity: str | None = None
    score: float | None = None

    references: list[str] = field(
        default_factory=list
    )

    status: str = "open"


# ---------------------------------------------------------------------------
# Validation Helpers
# ---------------------------------------------------------------------------


def _normalize_required(
    value: str,
    field_name: str,
) -> str:
    """Validate and normalize a required string."""
    if not isinstance(value, str):
        raise TypeError(
            f"{field_name} must be a string."
        )

    normalized = value.strip()

    if not normalized:
        raise ValueError(
            f"{field_name} cannot be empty."
        )

    return normalized


def _normalize_category(
    category: str,
) -> str:
    """Validate and normalize finding category."""
    normalized = _normalize_required(
        category,
        "category",
    ).lower()

    if normalized not in FINDING_CATEGORIES:
        raise ValueError(
            f"Unsupported finding category: "
            f"{category!r}"
        )

    return normalized


def _unique_strings(
    values: Iterable[str],
) -> list[str]:
    """Normalize and deduplicate string values."""
    result: list[str] = []

    for value in values:
        normalized = _normalize_required(
            value,
            "list value",
        )

        if normalized not in result:
            result.append(normalized)

    return result


# ---------------------------------------------------------------------------
# Finding Creation
# ---------------------------------------------------------------------------


def create_finding(
    finding_id: str,
    title: str,
    asset: str,
    category: str,
    *,
    description: str = "",
    evidence: Iterable[str] = (),
    recommendation: str = "",
    severity: str | None = None,
    score: float | None = None,
    references: Iterable[str] = (),
    status: str = "open",
) -> Finding:
    """
    Create a validated Finding.

    Severity and score are accepted as optional values so later analysis
    modules can enrich the finding without changing its identity.
    """
    normalized_id = _normalize_required(
        finding_id,
        "finding_id",
    )

    normalized_title = _normalize_required(
        title,
        "title",
    )

    normalized_asset = _normalize_required(
        asset,
        "asset",
    )

    normalized_category = _normalize_category(
        category
    )

    normalized_status = _normalize_required(
        status,
        "status",
    ).lower()

    if severity is not None:
        severity = _normalize_required(
            severity,
            "severity",
        ).lower()

    if score is not None:
        if not isinstance(score, (int, float)):
            raise TypeError(
                "score must be numeric."
            )

        if score < 0:
            raise ValueError(
                "score cannot be negative."
            )

        score = float(score)

    return Finding(
        finding_id=normalized_id,
        title=normalized_title,
        asset=normalized_asset,
        category=normalized_category,
        description=description.strip(),
        evidence=_unique_strings(evidence),
        recommendation=recommendation.strip(),
        severity=severity,
        score=score,
        references=_unique_strings(references),
        status=normalized_status,
    )


# ---------------------------------------------------------------------------
# Finding Collection
# ---------------------------------------------------------------------------


def add_finding(
    findings: list[Finding],
    finding: Finding,
) -> Finding:
    """
    Add a finding to a collection.

    Finding IDs must be unique.
    """
    if not isinstance(findings, list):
        raise TypeError(
            "findings must be a list."
        )

    if not isinstance(finding, Finding):
        raise TypeError(
            "finding must be a Finding instance."
        )

    for existing in findings:
        if existing.finding_id == finding.finding_id:
            raise ValueError(
                f"Duplicate finding ID: "
                f"{finding.finding_id!r}"
            )

    findings.append(finding)

    return finding


def create_findings(
    findings: Iterable[Finding],
) -> list[Finding]:
    """
    Validate and build a unique finding collection.
    """
    result: list[Finding] = []

    for finding in findings:
        add_finding(
            result,
            finding,
        )

    return result


# ---------------------------------------------------------------------------
# Finding Updates
# ---------------------------------------------------------------------------


def set_severity(
    finding: Finding,
    severity: str,
) -> Finding:
    """
    Set a finding severity.

    The actual severity decision should be made by severity.py.
    """
    if not isinstance(finding, Finding):
        raise TypeError(
            "finding must be a Finding instance."
        )

    normalized = _normalize_required(
        severity,
        "severity",
    ).lower()

    finding.severity = normalized

    return finding


def set_score(
    finding: Finding,
    score: float,
) -> Finding:
    """
    Set a finding score.

    The actual scoring decision should be made by scoring.py.
    """
    if not isinstance(finding, Finding):
        raise TypeError(
            "finding must be a Finding instance."
        )

    if not isinstance(score, (int, float)):
        raise TypeError(
            "score must be numeric."
        )

    if score < 0:
        raise ValueError(
            "score cannot be negative."
        )

    finding.score = float(score)

    return finding


def close_finding(
    finding: Finding,
) -> Finding:
    """Mark a finding as closed."""
    if not isinstance(finding, Finding):
        raise TypeError(
            "finding must be a Finding instance."
        )

    finding.status = "closed"

    return finding


# ---------------------------------------------------------------------------
# Query Helpers
# ---------------------------------------------------------------------------


def find_by_id(
    findings: Iterable[Finding],
    finding_id: str,
) -> Finding | None:
    """Find a finding by ID."""
    normalized_id = _normalize_required(
        finding_id,
        "finding_id",
    )

    for finding in findings:
        if finding.finding_id == normalized_id:
            return finding

    return None


def filter_by_category(
    findings: Iterable[Finding],
    category: str,
) -> list[Finding]:
    """Return findings belonging to a category."""
    normalized_category = _normalize_category(
        category
    )

    return [
        finding
        for finding in findings
        if finding.category == normalized_category
    ]


def filter_by_status(
    findings: Iterable[Finding],
    status: str,
) -> list[Finding]:
    """Return findings matching a status."""
    normalized_status = _normalize_required(
        status,
        "status",
    ).lower()

    return [
        finding
        for finding in findings
        if finding.status == normalized_status
    ]


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def finding_to_dict(
    finding: Finding,
) -> dict[str, object]:
    """Convert one Finding into JSON-compatible data."""
    if not isinstance(finding, Finding):
        raise TypeError(
            "finding must be a Finding instance."
        )

    return asdict(finding)


def findings_to_dict(
    findings: Iterable[Finding],
) -> list[dict[str, object]]:
    """Convert multiple findings into JSON-compatible data."""
    return [
        finding_to_dict(finding)
        for finding in findings
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "FINDING_CATEGORIES",
    "Finding",
    "create_finding",
    "add_finding",
    "create_findings",
    "set_severity",
    "set_score",
    "close_finding",
    "find_by_id",
    "filter_by_category",
    "filter_by_status",
    "finding_to_dict",
    "findings_to_dict",
]