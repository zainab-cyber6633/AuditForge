"""
AuditForge branding and application identity.

This module contains centralized, immutable branding constants and
helpers for locating AuditForge branding assets.
"""

from __future__ import annotations

from pathlib import Path


# ---------------------------------------------------------------------------
# Product Identity
# ---------------------------------------------------------------------------

PRODUCT_NAME = "AuditForge"

PRODUCT_FULL_NAME = (
    "AuditForge — Automated Security Assessment & Reporting Platform"
)

PRODUCT_TAGLINE = "Assess. Analyze. Report."

PRODUCT_DESCRIPTION = (
    "AuditForge is a professional security assessment platform for "
    "authorized security testing, structured evidence collection, "
    "risk prioritization, and client-ready security reporting."
)

PRODUCT_VERSION = "1.0.0"

PRODUCT_STATUS = "Development"


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------

DEVELOPER_NAME = "Zainab Ijaz"

PRODUCT_AUTHOR = DEVELOPER_NAME


# ---------------------------------------------------------------------------
# Brand Colors
# ---------------------------------------------------------------------------

COLOR_BACKGROUND = "#080808"
COLOR_SURFACE = "#111111"
COLOR_SURFACE_2 = "#181818"

COLOR_PRIMARY_RED = "#D90429"
COLOR_DARK_RED = "#8B0000"

COLOR_TEXT = "#F5F5F5"
COLOR_SECONDARY_TEXT = "#A0A0A0"

COLOR_BORDER = "#292929"

COLOR_SUCCESS = "#22C55E"
COLOR_WARNING = "#F59E0B"
COLOR_CRITICAL = "#EF4444"


# ---------------------------------------------------------------------------
# Branding Assets
# ---------------------------------------------------------------------------

# Project root:
# AuditForge/
_PROJECT_ROOT = Path(__file__).resolve().parents[2]

ASSETS_DIR = _PROJECT_ROOT / "assets"
BRANDING_ASSETS_DIR = ASSETS_DIR / "branding"

LOGO_SVG = BRANDING_ASSETS_DIR / "auditforge-logo.svg"
LOGO_PNG = BRANDING_ASSETS_DIR / "auditforge-logo.png"
ICON_PNG = BRANDING_ASSETS_DIR / "auditforge-icon.png"


# ---------------------------------------------------------------------------
# Application Metadata
# ---------------------------------------------------------------------------

APPLICATION_NAME = PRODUCT_NAME

APPLICATION_DESCRIPTION = PRODUCT_DESCRIPTION

APPLICATION_VERSION = PRODUCT_VERSION

APPLICATION_ORGANIZATION = PRODUCT_AUTHOR


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "PRODUCT_NAME",
    "PRODUCT_FULL_NAME",
    "PRODUCT_TAGLINE",
    "PRODUCT_DESCRIPTION",
    "PRODUCT_VERSION",
    "PRODUCT_STATUS",
    "DEVELOPER_NAME",
    "PRODUCT_AUTHOR",
    "COLOR_BACKGROUND",
    "COLOR_SURFACE",
    "COLOR_SURFACE_2",
    "COLOR_PRIMARY_RED",
    "COLOR_DARK_RED",
    "COLOR_TEXT",
    "COLOR_SECONDARY_TEXT",
    "COLOR_BORDER",
    "COLOR_SUCCESS",
    "COLOR_WARNING",
    "COLOR_CRITICAL",
    "ASSETS_DIR",
    "BRANDING_ASSETS_DIR",
    "LOGO_SVG",
    "LOGO_PNG",
    "ICON_PNG",
    "APPLICATION_NAME",
    "APPLICATION_DESCRIPTION",
    "APPLICATION_VERSION",
    "APPLICATION_ORGANIZATION",
]