"""
AuditForge logging utilities.

This module provides centralized application logging for AuditForge.
It supports console logging and optional file logging while preventing
duplicate handlers when loggers are requested multiple times.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOGGER_NAME = "auditforge"

LOG_FORMAT = (
    "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

DEFAULT_LOG_LEVEL = logging.INFO


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------


def create_formatter() -> logging.Formatter:
    """
    Create the standard AuditForge log formatter.
    """
    return logging.Formatter(
        fmt=LOG_FORMAT,
        datefmt=DATE_FORMAT,
    )


# ---------------------------------------------------------------------------
# Handler Creation
# ---------------------------------------------------------------------------


def create_console_handler(
    level: int = DEFAULT_LOG_LEVEL,
) -> logging.StreamHandler:
    """
    Create a console logging handler.
    """
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(create_formatter())

    return handler


def create_file_handler(
    path: Path | str,
    level: int = DEFAULT_LOG_LEVEL,
) -> logging.FileHandler:
    """
    Create a file logging handler.

    Parent directories are created automatically.
    """
    log_path = Path(path).expanduser().resolve()

    log_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    handler = logging.FileHandler(
        log_path,
        encoding="utf-8",
    )

    handler.setLevel(level)
    handler.setFormatter(create_formatter())

    return handler


# ---------------------------------------------------------------------------
# Logger Factory
# ---------------------------------------------------------------------------


def get_logger(
    name: Optional[str] = None,
    *,
    level: int = DEFAULT_LOG_LEVEL,
    log_file: Path | str | None = None,
) -> logging.Logger:
    """
    Return a configured AuditForge logger.

    Args:
        name:
            Optional logger name. When omitted, the root AuditForge logger
            is used.

        level:
            Logging level applied to the logger and handlers.

        log_file:
            Optional path for a file handler.

    Returns:
        Configured logging.Logger instance.
    """
    logger_name = LOGGER_NAME

    if name:
        logger_name = f"{LOGGER_NAME}.{name}"

    logger = logging.getLogger(logger_name)

    logger.setLevel(level)

    logger.propagate = False

    # ------------------------------------------------------------------
    # Console handler
    # ------------------------------------------------------------------

    has_console_handler = any(
        isinstance(handler, logging.StreamHandler)
        and not isinstance(handler, logging.FileHandler)
        for handler in logger.handlers
    )

    if not has_console_handler:
        logger.addHandler(
            create_console_handler(level)
        )

    # ------------------------------------------------------------------
    # Optional file handler
    # ------------------------------------------------------------------

    if log_file is not None:
        normalized_log_file = Path(log_file).expanduser().resolve()

        has_same_file_handler = any(
            isinstance(handler, logging.FileHandler)
            and Path(handler.baseFilename).resolve()
            == normalized_log_file
            for handler in logger.handlers
        )

        if not has_same_file_handler:
            logger.addHandler(
                create_file_handler(
                    normalized_log_file,
                    level,
                )
            )

    return logger


# ---------------------------------------------------------------------------
# Default Logger
# ---------------------------------------------------------------------------

logger = get_logger()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "LOGGER_NAME",
    "LOG_FORMAT",
    "DATE_FORMAT",
    "DEFAULT_LOG_LEVEL",
    "create_formatter",
    "create_console_handler",
    "create_file_handler",
    "get_logger",
    "logger",
]