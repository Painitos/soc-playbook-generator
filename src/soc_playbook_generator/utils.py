"""Utility helpers for filesystem and incident name handling."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path


def normalize_key(value: str) -> str:
    """Return a lowercase ASCII key suitable for incident lookup."""
    normalized = unicodedata.normalize("NFKD", value.strip().lower())
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "_", ascii_value).strip("_")


def slugify(value: str) -> str:
    """Return a filesystem-friendly slug."""
    return normalize_key(value).replace("__", "_")


def ensure_directory(path: str | Path) -> Path:
    """Create a directory when missing and return it as a Path."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write_text_file(path: str | Path, content: str) -> Path:
    """Write UTF-8 text content and return the written path."""
    destination = Path(path)
    ensure_directory(destination.parent)
    destination.write_text(content, encoding="utf-8")
    return destination
