"""
AuditForge asset risk mapping module.

Maps normalized assets to an initial asset-level risk classification.

This module provides contextual prioritization only. It does not declare
vulnerabilities, perform exploitation, or replace detailed finding severity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from src.auditforge.intelligence.asset_inventory import (
    Asset,
    AssetInventory,
)


# ---------------------------------------------------------------------------
# Risk Levels
# ---------------------------------------------------------------------------


RISK_LEVELS: tuple[str, ...] = (
    "low",
    "medium",
    "high",
    "critical",
)


RISK_ORDER: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssetRisk:
    """Represents the contextual risk assigned to one asset."""

    hostname: str
    asset_type: str
    risk_level: str
    risk_score: int
    reasons: tuple[str, ...]


@dataclass(slots=True)
class RiskMap:
    """Collection of asset-level risk assessments."""

    entries: list[AssetRisk]

    @property
    def count(self) -> int:
        """Return the number of risk entries."""
        return len(self.entries)


# ---------------------------------------------------------------------------
# Risk Calculation
# ---------------------------------------------------------------------------


def _validate_risk_level(
    risk_level: str,
) -> str:
    """Validate and normalize a risk level."""
    if not isinstance(risk_level, str):
        raise TypeError(
            "risk_level must be a string."
        )

    normalized = risk_level.strip().lower()

    if normalized not in RISK_LEVELS:
        raise ValueError(
            f"Invalid risk level: {risk_level!r}"
        )

    return normalized


def _calculate_asset_risk(
    asset: Asset,
) -> AssetRisk:
    """
    Calculate contextual risk for a single asset.

    Scoring signals:

    Internet exposure       +30
    External exposure       +20
    Observed ports          +10
    Multiple technologies   +10
    Sensitive hostname      +20
    Development hostname   +15
    API hostname            +10

    The score is capped at 100.

    These values represent asset prioritization, not vulnerability severity.
    """
    score = 0
    reasons: list[str] = []

    hostname = asset.hostname.lower()

    # Exposure
    if asset.exposure == "internet":
        score += 30
        reasons.append(
            "Internet-exposed asset."
        )

    elif asset.exposure == "external":
        score += 20
        reasons.append(
            "Externally exposed asset."
        )

    # Services / ports
    if asset.ports:
        score += 10
        reasons.append(
            "One or more services/ports observed."
        )

    # Technology diversity
    if len(asset.technologies) >= 2:
        score += 10
        reasons.append(
            "Multiple technologies observed."
        )

    # Sensitive naming signals
    sensitive_terms = (
        "admin",
        "administrator",
        "login",
        "auth",
        "portal",
        "vpn",
    )

    if any(
        term in hostname
        for term in sensitive_terms
    ):
        score += 20
        reasons.append(
            "Hostname suggests a security-sensitive service."
        )

    # Development signals
    development_terms = (
        "dev",
        "development",
        "test",
        "staging",
        "stage",
        "uat",
    )

    if any(
        term in hostname
        for term in development_terms
    ):
        score += 15
        reasons.append(
            "Hostname suggests a development or testing environment."
        )

    # API signal
    if (
        hostname.startswith("api.")
        or ".api." in hostname
    ):
        score += 10
        reasons.append(
            "API-related hostname detected."
        )

    score = min(score, 100)

    if score >= 80:
        risk_level = "critical"
    elif score >= 60:
        risk_level = "high"
    elif score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    if not reasons:
        reasons.append(
            "Limited risk signals observed."
        )

    return AssetRisk(
        hostname=asset.hostname,
        asset_type=asset.asset_type,
        risk_level=risk_level,
        risk_score=score,
        reasons=tuple(reasons),
    )


# ---------------------------------------------------------------------------
# Public Mapping API
# ---------------------------------------------------------------------------


def build_risk_map(
    inventory: AssetInventory,
) -> RiskMap:
    """
    Build an asset-level risk map from an AssetInventory.
    """
    if not isinstance(inventory, AssetInventory):
        raise TypeError(
            "inventory must be an AssetInventory instance."
        )

    entries = [
        _calculate_asset_risk(asset)
        for asset in inventory.assets
    ]

    entries.sort(
        key=lambda entry: (
            -entry.risk_score,
            entry.hostname,
        )
    )

    return RiskMap(
        entries=entries,
    )


# ---------------------------------------------------------------------------
# Query Helpers
# ---------------------------------------------------------------------------


def get_asset_risk(
    risk_map: RiskMap,
    hostname: str,
) -> AssetRisk | None:
    """
    Find risk information for a hostname.
    """
    if not isinstance(risk_map, RiskMap):
        raise TypeError(
            "risk_map must be a RiskMap instance."
        )

    normalized = hostname.strip().lower()

    return next(
        (
            entry
            for entry in risk_map.entries
            if entry.hostname == normalized
        ),
        None,
    )


def filter_by_risk(
    risk_map: RiskMap,
    minimum_level: str,
) -> list[AssetRisk]:
    """
    Return assets at or above the requested risk level.
    """
    if not isinstance(risk_map, RiskMap):
        raise TypeError(
            "risk_map must be a RiskMap instance."
        )

    normalized = _validate_risk_level(
        minimum_level
    )

    minimum_score = RISK_ORDER[normalized]

    return [
        entry
        for entry in risk_map.entries
        if RISK_ORDER[entry.risk_level] >= minimum_score
    ]


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def risk_map_to_dict(
    risk_map: RiskMap,
) -> dict[str, object]:
    """
    Convert RiskMap into JSON-compatible data.
    """
    if not isinstance(risk_map, RiskMap):
        raise TypeError(
            "risk_map must be a RiskMap instance."
        )

    return {
        "count": risk_map.count,
        "entries": [
            asdict(entry)
            for entry in risk_map.entries
        ],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "RISK_LEVELS",
    "RISK_ORDER",
    "AssetRisk",
    "RiskMap",
    "build_risk_map",
    "get_asset_risk",
    "filter_by_risk",
    "risk_map_to_dict",
]