"""
AuditForge assessment orchestration engine.

The engine coordinates authorized security-assessment modules and returns
structured assessment results.

The engine does not contain individual reconnaissance implementations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping


# ---------------------------------------------------------------------------
# Engine Constants
# ---------------------------------------------------------------------------

ENGINE_NAME = "AuditForge Assessment Engine"
ENGINE_VERSION = "1.0.0"

ASSESSMENT_STATES = (
    "initialized",
    "running",
    "completed",
    "completed_with_errors",
    "failed",
)


# ---------------------------------------------------------------------------
# Module Result
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ModuleResult:
    """Result returned by one assessment module."""

    name: str
    success: bool
    data: Any = None
    error: str | None = None
    started_at: str | None = None
    completed_at: str | None = None


# ---------------------------------------------------------------------------
# Assessment Result
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AssessmentResult:
    """Complete result of an AuditForge assessment run."""

    assessment_id: str
    target: str

    state: str = "initialized"

    started_at: str | None = None
    completed_at: str | None = None

    modules: list[ModuleResult] = field(
        default_factory=list
    )

    errors: list[str] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AssessmentEngine:
    """
    Coordinates registered assessment modules.

    Modules are registered as callables receiving the target value.

    Example:

        engine = AssessmentEngine(
            assessment_id="assessment-001",
            target="example.com",
        )

        engine.register_module(
            "dns",
            dns_function,
        )

        result = engine.run()
    """

    def __init__(
        self,
        assessment_id: str,
        target: str,
    ) -> None:
        self.assessment_id = _required_string(
            assessment_id,
            "assessment_id",
        )

        self.target = _required_string(
            target,
            "target",
        )

        self._modules: list[
            tuple[str, Callable[[str], Any]]
        ] = []

    # ------------------------------------------------------------------
    # Module Registration
    # ------------------------------------------------------------------

    def register_module(
        self,
        name: str,
        function: Callable[[str], Any],
    ) -> None:
        """Register an assessment module."""
        module_name = _required_string(
            name,
            "module name",
        )

        if not callable(function):
            raise TypeError(
                "function must be callable."
            )

        if any(
            existing_name == module_name
            for existing_name, _ in self._modules
        ):
            raise ValueError(
                f"Module already registered: {module_name!r}"
            )

        self._modules.append(
            (
                module_name,
                function,
            )
        )

    def registered_modules(self) -> tuple[str, ...]:
        """Return registered module names."""
        return tuple(
            name
            for name, _ in self._modules
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(
        self,
        *,
        stop_on_error: bool = False,
    ) -> AssessmentResult:
        """
        Execute all registered modules sequentially.

        By default, one module failure does not stop the assessment.
        """
        result = AssessmentResult(
            assessment_id=self.assessment_id,
            target=self.target,
            state="running",
            started_at=_utc_now(),
            metadata={
                "engine": ENGINE_NAME,
                "engine_version": ENGINE_VERSION,
                "module_count": len(
                    self._modules
                ),
            },
        )

        for name, function in self._modules:
            module_result = self._run_module(
                name,
                function,
            )

            result.modules.append(
                module_result
            )

            if not module_result.success:
                result.errors.append(
                    module_result.error
                    or f"Module failed: {name}"
                )

                if stop_on_error:
                    result.state = "failed"
                    result.completed_at = _utc_now()
                    return result

        result.completed_at = _utc_now()

        if result.errors:
            result.state = (
                "completed_with_errors"
            )
        else:
            result.state = "completed"

        return result

    def _run_module(
        self,
        name: str,
        function: Callable[[str], Any],
    ) -> ModuleResult:
        """Execute one module safely."""
        started_at = _utc_now()

        try:
            data = function(
                self.target
            )

            return ModuleResult(
                name=name,
                success=True,
                data=data,
                started_at=started_at,
                completed_at=_utc_now(),
            )

        except Exception as exc:
            return ModuleResult(
                name=name,
                success=False,
                error=f"{type(exc).__name__}: {exc}",
                started_at=started_at,
                completed_at=_utc_now(),
            )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def result_to_dict(
        self,
        result: AssessmentResult,
    ) -> dict[str, Any]:
        """Convert an assessment result to a dictionary."""
        if not isinstance(
            result,
            AssessmentResult,
        ):
            raise TypeError(
                "result must be an AssessmentResult instance."
            )

        return asdict(result)


# ---------------------------------------------------------------------------
# Functional API
# ---------------------------------------------------------------------------


def create_engine(
    assessment_id: str,
    target: str,
) -> AssessmentEngine:
    """Create an AssessmentEngine instance."""
    return AssessmentEngine(
        assessment_id=assessment_id,
        target=target,
    )


def run_assessment(
    assessment_id: str,
    target: str,
    modules: Iterable[
        tuple[str, Callable[[str], Any]]
    ],
    *,
    stop_on_error: bool = False,
) -> AssessmentResult:
    """
    Convenience function for running an assessment.
    """
    engine = create_engine(
        assessment_id,
        target,
    )

    for name, function in modules:
        engine.register_module(
            name,
            function,
        )

    return engine.run(
        stop_on_error=stop_on_error
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _required_string(
    value: str,
    name: str,
) -> str:
    """Validate a required string."""
    if not isinstance(value, str):
        raise TypeError(
            f"{name} must be a string."
        )

    normalized = value.strip()

    if not normalized:
        raise ValueError(
            f"{name} cannot be empty."
        )

    return normalized


def _utc_now() -> str:
    """Return current UTC timestamp."""
    return datetime.now(
        timezone.utc
    ).isoformat()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ENGINE_NAME",
    "ENGINE_VERSION",
    "ASSESSMENT_STATES",
    "ModuleResult",
    "AssessmentResult",
    "AssessmentEngine",
    "create_engine",
    "run_assessment",
]