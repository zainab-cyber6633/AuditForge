"""
AuditForge target domain operations.

This module provides domain-level operations for creating and normalizing
assessment targets.

Syntax validation is delegated to the validators module.
Authorization and scope enforcement are handled by scope.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Target
from ..utils.validators import validate_target, validate_target_type


# ---------------------------------------------------------------------------
# Target Specification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TargetSpec:
    """
    Normalized specification used to create an AuditForge Target.
    """

    value: str
    target_type: str


# ---------------------------------------------------------------------------
# Target Operations
# ---------------------------------------------------------------------------


def normalize_target(
    value: str,
    target_type: str,
) -> TargetSpec:
    """
    Validate and normalize a target.

    This function performs syntax validation only. It does not determine
    whether the target is authorized for assessment.
    """
    normalized_type = validate_target_type(target_type)

    normalized_value = validate_target(
        value,
        normalized_type,
    )

    return TargetSpec(
        value=normalized_value,
        target_type=normalized_type,
    )


def create_target(
    assessment_id: str,
    value: str,
    target_type: str,
) -> Target:
    """
    Create a validated Target model.

    Args:
        assessment_id: ID of the parent assessment.
        value: Target value such as a domain, hostname, IP, or URL.
        target_type: Target type.

    Returns:
        A validated Target instance.

    Raises:
        ValueError: If assessment ID or target data is invalid.
    """
    if not isinstance(assessment_id, str) or not assessment_id.strip():
        raise ValueError("assessment_id cannot be empty.")

    specification = normalize_target(
        value,
        target_type,
    )

    return Target(
        assessment_id=assessment_id.strip(),
        value=specification.value,
        target_type=specification.target_type,
    )


def target_identity(target: Target) -> str:
    """
    Return a stable human-readable identity for a target.
    """
    if not isinstance(target, Target):
        raise TypeError("target must be an AuditForge Target instance.")

    return f"{target.target_type}:{target.value}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "TargetSpec",
    "normalize_target",
    "create_target",
    "target_identity",
]