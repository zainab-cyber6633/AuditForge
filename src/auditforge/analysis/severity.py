"""
AuditForge finding severity module.

Provides centralized severity classification for structured findings.

This module does not perform network requests or exploitation.
It evaluates assessment context and produces a normalized severity level.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from src.auditforge.analysis.findings import Finding


# ---------------------------------------------------------------------------
# Severity Constants
# ---------------------------------------------------------------------------

SEVERITY_LEVELS: tuple[str, ...] = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
)

SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------------
# Severity Result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SeverityResult:
    """Represents the calculated severity of a finding."""

    finding_id: str
    severity: str
    score: int
    rationale: tuple[str, ...]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def normalize_severity(
    severity: str,
) -> str:
    """Normalize and validate a severity level."""
    if not isinstance(severity, str):
        raise TypeError(
            "severity must be a string."
        )

    normalized = severity.strip().lower()

    if normalized not in SEVERITY_LEVELS:
        raise ValueError(
            f"Invalid severity: {severity!r}"
        )

    return normalized


def _validate_factor(
    value: int,
    name: str,
) -> int:
    """Validate a severity factor."""
    if not isinstance(value, int):
        raise TypeError(
            f"{name} must be an integer."
        )

    if not 0 <= value <= 5:
        raise ValueError(
            f"{name} must be between 0 and 5."
        )

    return value


# ---------------------------------------------------------------------------
# Severity Calculation
# ---------------------------------------------------------------------------


def calculate_severity(
    *,
    impact: int,
    exposure: int,
    confidence: int,
) -> tuple[str, int, tuple[str, ...]]:
    """
    Calculate severity from normalized assessment factors.

    Each factor is rated from 0 to 5.

    impact:
        Potential business/security impact.

    exposure:
        Degree of external accessibility or attack-surface exposure.

    confidence:
        Confidence in the underlying evidence.

    The weighted score is normalized to 0-100.

    Weighting:

        Impact      50%
        Exposure    30%
        Confidence  20%
    """
    impact = _validate_factor(
        impact,
        "impact",
    )

    exposure = _validate_factor(
        exposure,
        "exposure",
    )

    confidence = _validate_factor(
        confidence,
        "confidence",
    )

    score = round(
        (
            (impact / 5) * 50
            + (exposure / 5) * 30
            + (confidence / 5) * 20
        )
    )

    rationale: list[str] = []

    if impact >= 4:
        rationale.append(
            "Potential impact is significant."
        )
    elif impact >= 2:
        rationale.append(
            "Potential impact is moderate."
        )
    else:
        rationale.append(
            "Potential impact is limited."
        )

    if exposure >= 4:
        rationale.append(
            "Exposure is high."
        )
    elif exposure >= 2:
        rationale.append(
            "Exposure is moderate."
        )
    else:
        rationale.append(
            "Exposure is limited."
        )

    if confidence >= 4:
        rationale.append(
            "Evidence confidence is high."
        )
    elif confidence >= 2:
        rationale.append(
            "Evidence confidence is moderate."
        )
    else:
        rationale.append(
            "Evidence confidence is limited."
        )

    if score >= 85:
        severity = "critical"
    elif score >= 65:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    elif score >= 15:
        severity = "low"
    else:
        severity = "info"

    return (
        severity,
        score,
        tuple(rationale),
    )


# ---------------------------------------------------------------------------
# Finding Severity
# ---------------------------------------------------------------------------


def assess_finding_severity(
    finding: Finding,
    *,
    impact: int,
    exposure: int,
    confidence: int,
) -> SeverityResult:
    """
    Calculate severity for a Finding.
    """
    if not isinstance(finding, Finding):
        raise TypeError(
            "finding must be a Finding instance."
        )

    severity, score, rationale = calculate_severity(
        impact=impact,
        exposure=exposure,
        confidence=confidence,
    )

    return SeverityResult(
        finding_id=finding.finding_id,
        severity=severity,
        score=score,
        rationale=rationale,
    )


def apply_severity(
    finding: Finding,
    *,
    impact: int,
    exposure: int,
    confidence: int,
) -> SeverityResult:
    """
    Calculate severity and apply it to a Finding.

    Returns the SeverityResult for traceability.
    """
    result = assess_finding_severity(
        finding,
        impact=impact,
        exposure=exposure,
        confidence=confidence,
    )

    finding.severity = result.severity
    finding.score = float(result.score)

    return result


# ---------------------------------------------------------------------------
# Comparison Helpers
# ---------------------------------------------------------------------------


def severity_at_least(
    severity: str,
    minimum: str,
) -> bool:
    """Return True if severity meets or exceeds minimum severity."""
    current = normalize_severity(severity)
    required = normalize_severity(minimum)

    return (
        SEVERITY_ORDER[current]
        >= SEVERITY_ORDER[required]
    )


def highest_severity(
    severities: Iterable[str],
) -> str:
    """Return the highest severity from a collection."""
    normalized = [
        normalize_severity(severity)
        for severity in severities
    ]

    if not normalized:
        return "info"

    return max(
        normalized,
        key=lambda value: SEVERITY_ORDER[value],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "SEVERITY_LEVELS",
    "SEVERITY_ORDER",
    "SeverityResult",
    "normalize_severity",
    "calculate_severity",
    "assess_finding_severity",
    "apply_severity",
    "severity_at_least",
    "highest_severity",
]