"""
AuditForge filesystem utilities.

This module provides centralized and safe filesystem operations used by
AuditForge for data, evidence, reports, and other local project files.

This module does not contain scanning, security-analysis, or reporting logic.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SAFE_FILENAME_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")

_MAX_FILENAME_LENGTH = 255


# ---------------------------------------------------------------------------
# Directory Operations
# ---------------------------------------------------------------------------


def ensure_directory(path: Path | str) -> Path:
    """
    Ensure that a directory exists.

    Existing directories are left untouched.

    Args:
        path: Directory path.

    Returns:
        The resolved directory path.
    """
    directory = Path(path).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)

    return directory


def directory_exists(path: Path | str) -> bool:
    """Return True when path exists and is a directory."""
    return Path(path).expanduser().is_dir()


# ---------------------------------------------------------------------------
# Path Operations
# ---------------------------------------------------------------------------


def normalize_path(path: Path | str) -> Path:
    """
    Normalize a filesystem path without requiring it to exist.

    The path is expanded for the current user's home directory and
    converted to an absolute path.
    """
    return Path(path).expanduser().resolve(strict=False)


def file_exists(path: Path | str) -> bool:
    """Return True when path exists and is a regular file."""
    return Path(path).expanduser().is_file()


# ---------------------------------------------------------------------------
# Filename Operations
# ---------------------------------------------------------------------------


def safe_filename(
    filename: str,
    default: str = "file",
) -> str:
    """
    Convert arbitrary text into a filesystem-safe filename.

    Unsafe characters are replaced with underscores.

    Args:
        filename: Original filename.
        default: Fallback name when filename is empty.

    Returns:
        A sanitized filename.
    """
    if not isinstance(filename, str):
        raise TypeError("filename must be a string.")

    value = filename.strip()

    if not value:
        value = default

    value = _SAFE_FILENAME_PATTERN.sub("_", value)

    value = value.strip(" .")

    if not value:
        value = default

    return value[:_MAX_FILENAME_LENGTH]


# ---------------------------------------------------------------------------
# File Writing
# ---------------------------------------------------------------------------


def write_text(
    path: Path | str,
    content: str,
    *,
    encoding: str = "utf-8",
) -> Path:
    """
    Write text content to a file.

    Parent directories are created automatically.

    Args:
        path: Destination file path.
        content: Text to write.
        encoding: Text encoding.

    Returns:
        The normalized destination path.
    """
    if not isinstance(content, str):
        raise TypeError("content must be a string.")

    destination = normalize_path(path)

    destination.parent.mkdir(parents=True, exist_ok=True)

    destination.write_text(
        content,
        encoding=encoding,
    )

    return destination


def write_json(
    path: Path | str,
    data: Any,
    *,
    encoding: str = "utf-8",
    indent: int = 4,
) -> Path:
    """
    Serialize data as JSON and write it to a file.

    Parent directories are created automatically.
    """
    destination = normalize_path(path)

    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open(
        "w",
        encoding=encoding,
    ) as file:
        json.dump(
            data,
            file,
            indent=indent,
            ensure_ascii=False,
        )

    return destination


# ---------------------------------------------------------------------------
# File Reading
# ---------------------------------------------------------------------------


def read_text(
    path: Path | str,
    *,
    encoding: str = "utf-8",
) -> str:
    """
    Read and return text from a file.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    source = normalize_path(path)

    return source.read_text(encoding=encoding)


def read_json(
    path: Path | str,
    *,
    encoding: str = "utf-8",
) -> Any:
    """
    Read and deserialize JSON from a file.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file contains invalid JSON.
    """
    source = normalize_path(path)

    with source.open(
        "r",
        encoding=encoding,
    ) as file:
        return json.load(file)


# ---------------------------------------------------------------------------
# Directory Listing
# ---------------------------------------------------------------------------


def list_files(
    directory: Path | str,
    *,
    recursive: bool = False,
) -> list[Path]:
    """
    Return files contained in a directory.

    Args:
        directory: Directory to inspect.
        recursive: Include files from nested directories when True.

    Returns:
        Sorted list of file paths.
    """
    target = normalize_path(directory)

    if not target.is_dir():
        return []

    if recursive:
        files: Iterable[Path] = (
            path
            for path in target.rglob("*")
            if path.is_file()
        )
    else:
        files = (
            path
            for path in target.iterdir()
            if path.is_file()
        )

    return sorted(files)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ensure_directory",
    "directory_exists",
    "normalize_path",
    "file_exists",
    "safe_filename",
    "write_text",
    "write_json",
    "read_text",
    "read_json",
    "list_files",
]