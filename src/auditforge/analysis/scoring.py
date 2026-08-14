"""
AuditForge risk scoring module.

Calculates normalized risk scores for findings and assessment results.

This module does not perform network requests or exploitation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from src.auditforge.analysis.findings import Finding
from src.auditforge.analysis.severity import (
    SEVERITY_ORDER,
    normalize_severity,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_SCORE = 100

SEVERITY_WEIGHTS: dict[str, int] = {
    "info": 0,
    "low": 20,
    "medium": 40,
    "high": 70,
    "critical": 90,
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScoreResult:
    """Represents a calculated risk score."""

    finding_id: str
    score: float
    severity: str
    priority: str
    rationale: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AssessmentScore:
    """Represents an aggregated assessment score."""

    score: float
    priority: str
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_factor(
    value: float,
    name: str,
) -> float:
    """Validate a scoring factor."""
    if not isinstance(value, (int, float)):
        raise TypeError(
            f"{name} must be numeric."
        )

    if not 0 <= value <= 1:
        raise ValueError(
            f"{name} must be between 0 and 1."
        )

    return float(value)


# ---------------------------------------------------------------------------
# Priority
# ---------------------------------------------------------------------------


def score_to_priority(
    score: float,
) -> str:
    """Convert a normalized score into a priority level."""
    if not isinstance(score, (int, float)):
        raise TypeError(
            "score must be numeric."
        )

    if not 0 <= score <= MAX_SCORE:
        raise ValueError(
            "score must be between 0 and 100."
        )

    if score >= 85:
        return "critical"

    if score >= 65:
        return "high"

    if score >= 40:
        return "medium"

    if score >= 15:
        return "low"

    return "info"


# ---------------------------------------------------------------------------
# Finding Scoring
# ---------------------------------------------------------------------------


def calculate_finding_score(
    finding: Finding,
    *,
    exposure_factor: float = 1.0,
    impact_factor: float = 1.0,
    confidence_factor: float = 1.0,
) -> ScoreResult:
    """
    Calculate a normalized risk score for a finding.

    Base score comes from finding severity.

    Exposure, impact, and confidence factors allow later assessment
    intelligence to refine the score without changing severity itself.
    """
    if not isinstance(finding, Finding):
        raise TypeError(
            "finding must be a Finding instance."
        )

    exposure_factor = _validate_factor(
        exposure_factor,
        "exposure_factor",
    )

    impact_factor = _validate_factor(
        impact_factor,
        "impact_factor",
    )

    confidence_factor = _validate_factor(
        confidence_factor,
        "confidence_factor",
    )

    severity = normalize_severity(
        finding.severity or "info"
    )

    base_score = SEVERITY_WEIGHTS[severity]

    # Average contextual factors.
    context_factor = (
        exposure_factor
        + impact_factor
        + confidence_factor
    ) / 3

    score = round(
        base_score * context_factor,
        2,
    )

    score = min(
        max(score, 0.0),
        float(MAX_SCORE),
    )

    priority = score_to_priority(score)

    rationale: list[str] = [
        f"Base severity: {severity}.",
        f"Base severity score: {base_score}.",
        f"Context factor: {context_factor:.2f}.",
    ]

    if exposure_factor >= 0.8:
        rationale.append(
            "Exposure context increases or preserves priority."
        )

    if impact_factor >= 0.8:
        rationale.append(
            "Impact context increases or preserves priority."
        )

    if confidence_factor < 0.5:
        rationale.append(
            "Low evidence confidence reduces score."
        )

    return ScoreResult(
        finding_id=finding.finding_id,
        score=score,
        severity=severity,
        priority=priority,
        rationale=tuple(rationale),
    )


# ---------------------------------------------------------------------------
# Apply Score
# ---------------------------------------------------------------------------


def apply_score(
    finding: Finding,
    *,
    exposure_factor: float = 1.0,
    impact_factor: float = 1.0,
    confidence_factor: float = 1.0,
) -> ScoreResult:
    """
    Calculate and store a finding score.
    """
    result = calculate_finding_score(
        finding,
        exposure_factor=exposure_factor,
        impact_factor=impact_factor,
        confidence_factor=confidence_factor,
    )

    finding.score = result.score

    return result


# ---------------------------------------------------------------------------
# Assessment Aggregation
# ---------------------------------------------------------------------------


def calculate_assessment_score(
    findings: Iterable[Finding],
) -> AssessmentScore:
    """
    Calculate an overall assessment score.

    The assessment score is based on the highest severity-weighted finding
    and the distribution of findings.
    """
    findings_list = list(findings)

    if not findings_list:
        return AssessmentScore(
            score=0.0,
            priority="info",
            finding_count=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=0,
        )

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    scores: list[float] = []

    for finding in findings_list:
        if not isinstance(finding, Finding):
            raise TypeError(
                "All items must be Finding instances."
            )

        severity = normalize_severity(
            finding.severity or "info"
        )

        counts[severity] += 1

        if finding.score is not None:
            scores.append(
                min(
                    max(float(finding.score), 0.0),
                    100.0,
                )
            )
        else:
            scores.append(
                float(
                    SEVERITY_WEIGHTS[severity]
                )
            )

    highest = max(
        SEVERITY_ORDER[
            normalize_severity(
                finding.severity or "info"
            )
        ]
        for finding in findings_list
    )

    average_score = sum(scores) / len(scores)

    # Give the highest severity meaningful influence.
    highest_severity = next(
        severity
        for severity, value in SEVERITY_ORDER.items()
        if value == highest
    )

    highest_score = float(
        SEVERITY_WEIGHTS[highest_severity]
    )

    overall_score = round(
        (
            highest_score * 0.60
            + average_score * 0.40
        ),
        2,
    )

    overall_score = min(
        max(overall_score, 0.0),
        100.0,
    )

    return AssessmentScore(
        score=overall_score,
        priority=score_to_priority(
            overall_score
        ),
        finding_count=len(findings_list),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        info_count=counts["info"],
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def score_result_to_dict(
    result: ScoreResult,
) -> dict[str, object]:
    """Convert ScoreResult to dictionary."""
    if not isinstance(result, ScoreResult):
        raise TypeError(
            "result must be a ScoreResult instance."
        )

    return asdict(result)


def assessment_score_to_dict(
    result: AssessmentScore,
) -> dict[str, object]:
    """Convert AssessmentScore to dictionary."""
    if not isinstance(
        result,
        AssessmentScore,
    ):
        raise TypeError(
            "result must be an AssessmentScore instance."
        )

    return asdict(result)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "MAX_SCORE",
    "SEVERITY_WEIGHTS",
    "ScoreResult",
    "AssessmentScore",
    "score_to_priority",
    "calculate_finding_score",
    "apply_score",
    "calculate_assessment_score",
    "score_result_to_dict",
    "assessment_score_to_dict",
]