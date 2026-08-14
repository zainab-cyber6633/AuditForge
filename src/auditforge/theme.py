"""
AuditForge visual theme definitions.

This module centralizes the application's visual theme values and
provides reusable theme mappings for the user interface.
"""

from __future__ import annotations

from .branding import (
    COLOR_BACKGROUND,
    COLOR_BORDER,
    COLOR_CRITICAL,
    COLOR_DARK_RED,
    COLOR_PRIMARY_RED,
    COLOR_SECONDARY_TEXT,
    COLOR_SUCCESS,
    COLOR_SURFACE,
    COLOR_SURFACE_2,
    COLOR_TEXT,
    COLOR_WARNING,
)


# ---------------------------------------------------------------------------
# Theme Identity
# ---------------------------------------------------------------------------

THEME_NAME = "Dark Enterprise Security"

THEME_DESCRIPTION = (
    "Professional dark security interface using black, crimson red, "
    "white, and semantic status colors."
)


# ---------------------------------------------------------------------------
# Core Theme Colors
# ---------------------------------------------------------------------------

BACKGROUND = COLOR_BACKGROUND

SURFACE = COLOR_SURFACE

SURFACE_2 = COLOR_SURFACE_2

PRIMARY = COLOR_PRIMARY_RED

PRIMARY_DARK = COLOR_DARK_RED

TEXT = COLOR_TEXT

TEXT_SECONDARY = COLOR_SECONDARY_TEXT

BORDER = COLOR_BORDER


# ---------------------------------------------------------------------------
# Semantic Colors
# ---------------------------------------------------------------------------

SUCCESS = COLOR_SUCCESS

WARNING = COLOR_WARNING

CRITICAL = COLOR_CRITICAL


# ---------------------------------------------------------------------------
# Theme Mapping
# ---------------------------------------------------------------------------

THEME_COLORS: dict[str, str] = {
    "background": BACKGROUND,
    "surface": SURFACE,
    "surface_2": SURFACE_2,
    "primary": PRIMARY,
    "primary_dark": PRIMARY_DARK,
    "text": TEXT,
    "text_secondary": TEXT_SECONDARY,
    "border": BORDER,
    "success": SUCCESS,
    "warning": WARNING,
    "critical": CRITICAL,
}


# ---------------------------------------------------------------------------
# Severity Colors
# ---------------------------------------------------------------------------

SEVERITY_COLORS: dict[str, str] = {
    "critical": CRITICAL,
    "high": CRITICAL,
    "medium": WARNING,
    "low": PRIMARY,
    "info": TEXT_SECONDARY,
}


# ---------------------------------------------------------------------------
# Status Colors
# ---------------------------------------------------------------------------

STATUS_COLORS: dict[str, str] = {
    "success": SUCCESS,
    "warning": WARNING,
    "critical": CRITICAL,
    "info": TEXT_SECONDARY,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "THEME_NAME",
    "THEME_DESCRIPTION",
    "BACKGROUND",
    "SURFACE",
    "SURFACE_2",
    "PRIMARY",
    "PRIMARY_DARK",
    "TEXT",
    "TEXT_SECONDARY",
    "BORDER",
    "SUCCESS",
    "WARNING",
    "CRITICAL",
    "THEME_COLORS",
    "SEVERITY_COLORS",
    "STATUS_COLORS",
]