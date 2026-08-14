"""
AuditForge exposure correlation module.

Correlates asset exposure signals with observed services, technologies,
and asset characteristics to produce structured priority context.

This module does not perform exploitation and does not assign final
vulnerability severity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from src.auditforge.intelligence.asset_inventory import (
    Asset,
    AssetInventory,
)
from src.auditforge.intelligence.risk_map import (
    AssetRisk,
    RiskMap,
)


# ---------------------------------------------------------------------------
# Correlation Levels
# ---------------------------------------------------------------------------

CORRELATION_LEVELS: tuple[str, ...] = (
    "low",
    "medium",
    "high",
    "critical",
)

CORRELATION_ORDER: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExposureSignal:
    """Represents one correlated exposure signal."""

    name: str
    category: str
    weight: int
    description: str


@dataclass(frozen=True, slots=True)
class ExposureCorrelation:
    """Represents correlated exposure context for one asset."""

    hostname: str
    correlation_level: str
    correlation_score: int
    signals: tuple[ExposureSignal, ...]


@dataclass(slots=True)
class ExposureCorrelationMap:
    """Collection of exposure correlations."""

    entries: list[ExposureCorrelation]

    @property
    def count(self) -> int:
        """Return the number of correlation entries."""
        return len(self.entries)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize(value: str) -> str:
    """Normalize a string."""
    if not isinstance(value, str):
        raise TypeError("value must be a string.")

    return value.strip().lower()


def _add_signal(
    signals: list[ExposureSignal],
    seen: set[str],
    *,
    name: str,
    category: str,
    weight: int,
    description: str,
) -> None:
    """Add a unique exposure signal."""
    normalized_name = _normalize(name)

    if normalized_name in seen:
        return

    seen.add(normalized_name)

    signals.append(
        ExposureSignal(
            name=name,
            category=category,
            weight=weight,
            description=description,
        )
    )


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------


def correlate_asset(
    asset: Asset,
    *,
    risk: AssetRisk | None = None,
) -> ExposureCorrelation:
    """
    Correlate exposure signals for one asset.

    Signals include:

    - Internet exposure
    - External exposure
    - Observed services
    - Multiple technologies
    - API hostname
    - Administrative/authentication hostname
    - Development/staging hostname
    - Existing asset risk context
    """
    if not isinstance(asset, Asset):
        raise TypeError(
            "asset must be an Asset instance."
        )

    signals: list[ExposureSignal] = []
    seen: set[str] = set()

    hostname = asset.hostname.lower()

    # ---------------------------------------------------------------
    # Exposure
    # ---------------------------------------------------------------

    if asset.exposure == "internet":
        _add_signal(
            signals,
            seen,
            name="internet_exposure",
            category="exposure",
            weight=30,
            description=(
                "Asset is classified as directly internet exposed."
            ),
        )

    elif asset.exposure == "external":
        _add_signal(
            signals,
            seen,
            name="external_exposure",
            category="exposure",
            weight=20,
            description=(
                "Asset is classified as externally exposed."
            ),
        )

    # ---------------------------------------------------------------
    # Services
    # ---------------------------------------------------------------

    if asset.ports:
        _add_signal(
            signals,
            seen,
            name="observed_services",
            category="service",
            weight=10,
            description=(
                "One or more network services were observed."
            ),
        )

    # ---------------------------------------------------------------
    # Technology Diversity
    # ---------------------------------------------------------------

    if len(asset.technologies) >= 2:
        _add_signal(
            signals,
            seen,
            name="technology_diversity",
            category="technology",
            weight=10,
            description=(
                "Multiple technologies were observed on the asset."
            ),
        )

    # ---------------------------------------------------------------
    # API
    # ---------------------------------------------------------------

    if (
        hostname.startswith("api.")
        or ".api." in hostname
    ):
        _add_signal(
            signals,
            seen,
            name="api_service",
            category="application",
            weight=15,
            description=(
                "Hostname indicates an API-oriented service."
            ),
        )

    # ---------------------------------------------------------------
    # Administrative / Authentication
    # ---------------------------------------------------------------

    sensitive_terms = (
        "admin",
        "administrator",
        "auth",
        "login",
        "portal",
        "vpn",
    )

    if any(
        term in hostname
        for term in sensitive_terms
    ):
        _add_signal(
            signals,
            seen,
            name="sensitive_service",
            category="application",
            weight=20,
            description=(
                "Hostname suggests an administrative or "
                "authentication-related service."
            ),
        )

    # ---------------------------------------------------------------
    # Development / Staging
    # ---------------------------------------------------------------

    development_terms = (
        "dev",
        "development",
        "test",
        "testing",
        "stage",
        "staging",
        "uat",
    )

    if any(
        term in hostname
        for term in development_terms
    ):
        _add_signal(
            signals,
            seen,
            name="development_environment",
            category="environment",
            weight=15,
            description=(
                "Hostname suggests a development, testing, "
                "or staging environment."
            ),
        )

    # ---------------------------------------------------------------
    # Existing Risk Context
    # ---------------------------------------------------------------

    if risk is not None:
        if not isinstance(risk, AssetRisk):
            raise TypeError(
                "risk must be an AssetRisk instance."
            )

        if risk.risk_level in {
            "high",
            "critical",
        }:
            _add_signal(
                signals,
                seen,
                name="elevated_asset_risk",
                category="risk_context",
                weight=15,
                description=(
                    "Asset already has elevated contextual risk."
                ),
            )

    # ---------------------------------------------------------------
    # Calculate Correlation Score
    # ---------------------------------------------------------------

    score = min(
        sum(signal.weight for signal in signals),
        100,
    )

    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return ExposureCorrelation(
        hostname=asset.hostname,
        correlation_level=level,
        correlation_score=score,
        signals=tuple(signals),
    )


# ---------------------------------------------------------------------------
# Map Builder
# ---------------------------------------------------------------------------


def build_exposure_correlation(
    inventory: AssetInventory,
    risk_map: RiskMap | None = None,
) -> ExposureCorrelationMap:
    """
    Build exposure correlations for an asset inventory.

    If a RiskMap is supplied, matching asset-level risk information is
    included as additional context.
    """
    if not isinstance(inventory, AssetInventory):
        raise TypeError(
            "inventory must be an AssetInventory instance."
        )

    if risk_map is not None and not isinstance(
        risk_map,
        RiskMap,
    ):
        raise TypeError(
            "risk_map must be a RiskMap instance."
        )

    entries: list[ExposureCorrelation] = []

    for asset in inventory.assets:
        asset_risk = None

        if risk_map is not None:
            for risk in risk_map.entries:
                if risk.hostname == asset.hostname:
                    asset_risk = risk
                    break

        entries.append(
            correlate_asset(
                asset,
                risk=asset_risk,
            )
        )

    entries.sort(
        key=lambda entry: (
            -entry.correlation_score,
            entry.hostname,
        )
    )

    return ExposureCorrelationMap(
        entries=entries,
    )


# ---------------------------------------------------------------------------
# Query Helpers
# ---------------------------------------------------------------------------


def get_correlation(
    correlation_map: ExposureCorrelationMap,
    hostname: str,
) -> ExposureCorrelation | None:
    """Return correlation information for a hostname."""
    if not isinstance(
        correlation_map,
        ExposureCorrelationMap,
    ):
        raise TypeError(
            "correlation_map must be an "
            "ExposureCorrelationMap instance."
        )

    normalized = _normalize(hostname)

    for entry in correlation_map.entries:
        if entry.hostname == normalized:
            return entry

    return None


def filter_by_correlation(
    correlation_map: ExposureCorrelationMap,
    minimum_level: str,
) -> list[ExposureCorrelation]:
    """
    Return correlations at or above a requested level.
    """
    if not isinstance(
        correlation_map,
        ExposureCorrelationMap,
    ):
        raise TypeError(
            "correlation_map must be an "
            "ExposureCorrelationMap instance."
        )

    normalized = _normalize(minimum_level)

    if normalized not in CORRELATION_LEVELS:
        raise ValueError(
            f"Invalid correlation level: {minimum_level!r}"
        )

    minimum_score = CORRELATION_ORDER[normalized]

    return [
        entry
        for entry in correlation_map.entries
        if CORRELATION_ORDER[
            entry.correlation_level
        ] >= minimum_score
    ]


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def exposure_correlation_to_dict(
    correlation_map: ExposureCorrelationMap,
) -> dict[str, object]:
    """Convert correlation data into JSON-compatible data."""
    if not isinstance(
        correlation_map,
        ExposureCorrelationMap,
    ):
        raise TypeError(
            "correlation_map must be an "
            "ExposureCorrelationMap instance."
        )

    return {
        "count": correlation_map.count,
        "entries": [
            asdict(entry)
            for entry in correlation_map.entries
        ],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "CORRELATION_LEVELS",
    "CORRELATION_ORDER",
    "ExposureSignal",
    "ExposureCorrelation",
    "ExposureCorrelationMap",
    "correlate_asset",
    "build_exposure_correlation",
    "get_correlation",
    "filter_by_correlation",
    "exposure_correlation_to_dict",
]