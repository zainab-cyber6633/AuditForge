"""
AuditForge asset inventory intelligence module.

Builds a normalized inventory of discovered assets and their associated
security-assessment observations.

This module does not perform network requests. It transforms already
collected assessment data into structured intelligence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Asset:
    """
    Represents one normalized asset discovered during an assessment.
    """

    hostname: str
    asset_type: str = "hostname"
    addresses: tuple[str, ...] = ()
    technologies: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    protocols: tuple[str, ...] = ()
    exposure: str = "unknown"
    source_modules: tuple[str, ...] = ()


@dataclass(slots=True)
class AssetInventory:
    """
    Collection of normalized assessment assets.
    """

    assets: list[Asset] = field(default_factory=list)

    @property
    def count(self) -> int:
        """Return total number of unique assets."""
        return len(self.assets)


# ---------------------------------------------------------------------------
# Normalization Helpers
# ---------------------------------------------------------------------------


def _normalize_string(value: str) -> str:
    """Normalize a string value."""
    if not isinstance(value, str):
        raise TypeError("value must be a string.")

    return value.strip().lower()


def _unique_strings(
    values: Iterable[str],
) -> tuple[str, ...]:
    """Return normalized unique strings while preserving order."""
    result: list[str] = []

    for value in values:
        normalized = _normalize_string(value)

        if normalized and normalized not in result:
            result.append(normalized)

    return tuple(result)


def _unique_ports(
    values: Iterable[int],
) -> tuple[int, ...]:
    """Return unique valid TCP/UDP port numbers."""
    result: list[int] = []

    for value in values:
        if not isinstance(value, int):
            raise TypeError("port values must be integers.")

        if not 1 <= value <= 65535:
            raise ValueError(
                f"Invalid port number: {value}"
            )

        if value not in result:
            result.append(value)

    return tuple(result)


# ---------------------------------------------------------------------------
# Asset Creation
# ---------------------------------------------------------------------------


def create_asset(
    hostname: str,
    *,
    asset_type: str = "hostname",
    addresses: Iterable[str] = (),
    technologies: Iterable[str] = (),
    ports: Iterable[int] = (),
    protocols: Iterable[str] = (),
    exposure: str = "unknown",
    source_modules: Iterable[str] = (),
) -> Asset:
    """
    Create a normalized Asset.

    Args:
        hostname:
            Primary hostname or asset identifier.

        asset_type:
            Type of asset.

        addresses:
            Associated IP addresses.

        technologies:
            Detected technologies.

        ports:
            Observed ports.

        protocols:
            Observed protocols.

        exposure:
            Initial exposure classification.

        source_modules:
            Assessment modules that contributed the data.

    Returns:
        Normalized Asset.
    """
    normalized_hostname = _normalize_string(hostname)

    if not normalized_hostname:
        raise ValueError(
            "hostname cannot be empty."
        )

    normalized_asset_type = _normalize_string(
        asset_type
    )

    if not normalized_asset_type:
        raise ValueError(
            "asset_type cannot be empty."
        )

    normalized_exposure = _normalize_string(
        exposure
    )

    if normalized_exposure not in {
        "unknown",
        "internal",
        "external",
        "internet",
    }:
        raise ValueError(
            f"Invalid exposure classification: "
            f"{exposure!r}"
        )

    return Asset(
        hostname=normalized_hostname,
        asset_type=normalized_asset_type,
        addresses=_unique_strings(addresses),
        technologies=_unique_strings(technologies),
        ports=_unique_ports(ports),
        protocols=_unique_strings(protocols),
        exposure=normalized_exposure,
        source_modules=_unique_strings(source_modules),
    )


# ---------------------------------------------------------------------------
# Inventory Operations
# ---------------------------------------------------------------------------


def add_asset(
    inventory: AssetInventory,
    asset: Asset,
) -> Asset:
    """
    Add an asset to an inventory.

    Assets with the same hostname and asset type are merged rather than
    duplicated.
    """
    if not isinstance(inventory, AssetInventory):
        raise TypeError(
            "inventory must be an AssetInventory instance."
        )

    if not isinstance(asset, Asset):
        raise TypeError(
            "asset must be an Asset instance."
        )

    for index, existing in enumerate(inventory.assets):
        if (
            existing.hostname == asset.hostname
            and existing.asset_type == asset.asset_type
        ):
            merged = Asset(
                hostname=existing.hostname,
                asset_type=existing.asset_type,
                addresses=_unique_strings(
                    (*existing.addresses, *asset.addresses)
                ),
                technologies=_unique_strings(
                    (
                        *existing.technologies,
                        *asset.technologies,
                    )
                ),
                ports=_unique_ports(
                    (*existing.ports, *asset.ports)
                ),
                protocols=_unique_strings(
                    (
                        *existing.protocols,
                        *asset.protocols,
                    )
                ),
                exposure=(
                    asset.exposure
                    if asset.exposure != "unknown"
                    else existing.exposure
                ),
                source_modules=_unique_strings(
                    (
                        *existing.source_modules,
                        *asset.source_modules,
                    )
                ),
            )

            inventory.assets[index] = merged

            return merged

    inventory.assets.append(asset)

    return asset


def build_inventory(
    assets: Iterable[Asset],
) -> AssetInventory:
    """
    Build an inventory from multiple Asset objects.
    """
    inventory = AssetInventory()

    for asset in assets:
        add_asset(
            inventory,
            asset,
        )

    inventory.assets.sort(
        key=lambda item: (
            item.hostname,
            item.asset_type,
        )
    )

    return inventory


# ---------------------------------------------------------------------------
# Query Helpers
# ---------------------------------------------------------------------------


def find_asset(
    inventory: AssetInventory,
    hostname: str,
) -> Asset | None:
    """
    Find an asset by normalized hostname.
    """
    if not isinstance(inventory, AssetInventory):
        raise TypeError(
            "inventory must be an AssetInventory instance."
        )

    normalized_hostname = _normalize_string(
        hostname
    )

    for asset in inventory.assets:
        if asset.hostname == normalized_hostname:
            return asset

    return None


def assets_by_exposure(
    inventory: AssetInventory,
    exposure: str,
) -> list[Asset]:
    """
    Return assets matching an exposure classification.
    """
    if not isinstance(inventory, AssetInventory):
        raise TypeError(
            "inventory must be an AssetInventory instance."
        )

    normalized_exposure = _normalize_string(
        exposure
    )

    return [
        asset
        for asset in inventory.assets
        if asset.exposure == normalized_exposure
    ]


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def asset_inventory_to_dict(
    inventory: AssetInventory,
) -> dict[str, object]:
    """
    Convert AssetInventory into JSON-compatible data.
    """
    if not isinstance(inventory, AssetInventory):
        raise TypeError(
            "inventory must be an AssetInventory instance."
        )

    return {
        "count": inventory.count,
        "assets": [
            asdict(asset)
            for asset in inventory.assets
        ],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "Asset",
    "AssetInventory",
    "create_asset",
    "add_asset",
    "build_inventory",
    "find_asset",
    "assets_by_exposure",
    "asset_inventory_to_dict",
]