"""
AuditForge application configuration.

This module centralizes runtime configuration, project paths, storage
locations, and environment-based settings used by AuditForge.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ..branding import (
    APPLICATION_NAME,
    APPLICATION_VERSION,
)


# ---------------------------------------------------------------------------
# Project Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[3]

SRC_DIR = PROJECT_ROOT / "src"

PACKAGE_DIR = SRC_DIR / "auditforge"

ASSETS_DIR = PROJECT_ROOT / "assets"

DATA_DIR = PROJECT_ROOT / "data"

EVIDENCE_DIR = PROJECT_ROOT / "evidence"

REPORTS_DIR = PROJECT_ROOT / "reports"

DOCS_DIR = PROJECT_ROOT / "docs"

TESTS_DIR = PROJECT_ROOT / "tests"

BRANDING_DIR = ASSETS_DIR / "branding"


# ---------------------------------------------------------------------------
# Environment Helpers
# ---------------------------------------------------------------------------


def _get_env_bool(name: str, default: bool) -> bool:
    """
    Read a boolean value from an environment variable.

    Accepted true values:
        1, true, yes, on

    Accepted false values:
        0, false, no, off
    """
    value = os.getenv(name)

    if value is None:
        return default

    normalized = value.strip().lower()

    if normalized in {"1", "true", "yes", "on"}:
        return True

    if normalized in {"0", "false", "no", "off"}:
        return False

    return default


def _get_env_int(name: str, default: int) -> int:
    """Read an integer from an environment variable."""
    value = os.getenv(name)

    if value is None:
        return default

    try:
        return int(value.strip())
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Application Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AppConfig:
    """
    Immutable runtime configuration for AuditForge.
    """

    application_name: str = APPLICATION_NAME
    version: str = APPLICATION_VERSION

    debug: bool = False

    request_timeout: int = 10

    max_concurrent_tasks: int = 10

    user_agent: str = "AuditForge/1.0"

    data_dir: Path = DATA_DIR
    evidence_dir: Path = EVIDENCE_DIR
    reports_dir: Path = REPORTS_DIR


# ---------------------------------------------------------------------------
# Configuration Factory
# ---------------------------------------------------------------------------


def load_config() -> AppConfig:
    """
    Build the runtime configuration from environment variables.

    Supported environment variables:

        AUDITFORGE_DEBUG
        AUDITFORGE_REQUEST_TIMEOUT
        AUDITFORGE_MAX_CONCURRENT_TASKS
        AUDITFORGE_USER_AGENT
    """

    return AppConfig(
        debug=_get_env_bool("AUDITFORGE_DEBUG", False),
        request_timeout=max(
            1,
            _get_env_int("AUDITFORGE_REQUEST_TIMEOUT", 10),
        ),
        max_concurrent_tasks=max(
            1,
            _get_env_int("AUDITFORGE_MAX_CONCURRENT_TASKS", 10),
        ),
        user_agent=os.getenv(
            "AUDITFORGE_USER_AGENT",
            "AuditForge/1.0",
        ).strip()
        or "AuditForge/1.0",
    )


# ---------------------------------------------------------------------------
# Directory Initialization
# ---------------------------------------------------------------------------


def ensure_project_directories() -> None:
    """
    Ensure required runtime directories exist.

    Existing directories are left untouched.
    """
    directories = (
        DATA_DIR,
        EVIDENCE_DIR,
        REPORTS_DIR,
        DOCS_DIR,
        BRANDING_DIR,
    )

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Default Runtime Configuration
# ---------------------------------------------------------------------------

CONFIG = load_config()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "PROJECT_ROOT",
    "SRC_DIR",
    "PACKAGE_DIR",
    "ASSETS_DIR",
    "DATA_DIR",
    "EVIDENCE_DIR",
    "REPORTS_DIR",
    "DOCS_DIR",
    "TESTS_DIR",
    "BRANDING_DIR",
    "AppConfig",
    "load_config",
    "ensure_project_directories",
    "CONFIG",
]