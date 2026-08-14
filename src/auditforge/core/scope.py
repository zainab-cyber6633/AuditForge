"""
AuditForge assessment scope management.

This module manages explicit assessment scope and prevents targets that
are not present in the authorized scope from being accepted for assessment.

This module does not perform network requests or discover additional
targets. Scope is defined explicitly by the assessment operator.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.target import normalize_target
from ..models import Target


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ScopeError(ValueError):
    """Base exception for scope-related validation errors."""


class TargetOutOfScopeError(ScopeError):
    """Raised when a target is not explicitly authorized."""


# ---------------------------------------------------------------------------
# Scope Entry
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScopeEntry:
    """
    Represents one explicitly authorized scope target.
    """

    value: str
    target_type: str


# ---------------------------------------------------------------------------
# Assessment Scope
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AssessmentScope:
    """
    Explicit allowlist for an authorized security assessment.

    Only targets added to this scope can be accepted by the assessment
    workflow.
    """

    entries: list[ScopeEntry] = field(default_factory=list)

    def add(
        self,
        value: str,
        target_type: str,
    ) -> ScopeEntry:
        """
        Validate and add a target to the authorized scope.

        Duplicate entries are not added twice.
        """
        specification = normalize_target(
            value,
            target_type,
        )

        entry = ScopeEntry(
            value=specification.value,
            target_type=specification.target_type,
        )

        if entry not in self.entries:
            self.entries.append(entry)

        return entry

    def remove(
        self,
        value: str,
        target_type: str,
    ) -> bool:
        """
        Remove a target from scope.

        Returns:
            True when an entry was removed, otherwise False.
        """
        specification = normalize_target(
            value,
            target_type,
        )

        entry = ScopeEntry(
            value=specification.value,
            target_type=specification.target_type,
        )

        if entry not in self.entries:
            return False

        self.entries.remove(entry)

        return True

    def contains(
        self,
        value: str,
        target_type: str,
    ) -> bool:
        """
        Return True when the normalized target is explicitly in scope.
        """
        specification = normalize_target(
            value,
            target_type,
        )

        entry = ScopeEntry(
            value=specification.value,
            target_type=specification.target_type,
        )

        return entry in self.entries

    def require_in_scope(
        self,
        value: str,
        target_type: str,
    ) -> ScopeEntry:
        """
        Require a target to be explicitly authorized.

        Raises:
            TargetOutOfScopeError: When target is not in scope.
        """
        specification = normalize_target(
            value,
            target_type,
        )

        entry = ScopeEntry(
            value=specification.value,
            target_type=specification.target_type,
        )

        if entry not in self.entries:
            raise TargetOutOfScopeError(
                f"Target is outside the authorized assessment scope: "
                f"{entry.target_type}:{entry.value}"
            )

        return entry


# ---------------------------------------------------------------------------
# Target Scope Helpers
# ---------------------------------------------------------------------------


def authorize_target(
    target: Target,
    scope: AssessmentScope,
) -> Target:
    """
    Verify that an existing Target is explicitly in scope.

    The target itself is not modified.

    Returns:
        The same Target instance after scope verification.

    Raises:
        TypeError: If target or scope has an invalid type.
        TargetOutOfScopeError: If target is not authorized.
    """
    if not isinstance(target, Target):
        raise TypeError(
            "target must be an AuditForge Target instance."
        )

    if not isinstance(scope, AssessmentScope):
        raise TypeError(
            "scope must be an AssessmentScope instance."
        )

    scope.require_in_scope(
        target.value,
        target.target_type,
    )

    return target


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ScopeError",
    "TargetOutOfScopeError",
    "ScopeEntry",
    "AssessmentScope",
    "authorize_target",
]