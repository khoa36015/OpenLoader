"""
Utility helpers for terminal output, file validation, and checksums.
"""

from __future__ import annotations

import hashlib
import os
import random
import string
import sys
from datetime import datetime


def generate_random_hex(length: int = 32) -> str:
    """Generate a random hexadecimal string of *length* characters."""
    return "".join(random.choices("0123456789abcdef", k=length))


def timestamp() -> str:
    """Return the current UTC timestamp as ``YYYY-MM-DD HH:MM:SS``."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def colored_print(text: str, color: str = "") -> None:
    """Print *text* to stderr with an ANSI colour prefix.

    Supported colours: ``red``, ``green``, ``cyan``, ``yellow``.
    Falls back to plain text on unsupported terminals.
    """
    colors = {
        "red": "\033[0;31m",
        "green": "\033[0;32m",
        "cyan": "\033[0;36m",
        "yellow": "\033[1;33m",
    }
    reset = "\033[0m"
    code = colors.get(color, "")
    if code and sys.stderr.isatty():
        print(f"{code}{text}{reset}", file=sys.stderr)
    else:
        print(text, file=sys.stderr)


def create_output_directory(path: str) -> bool:
    """Ensure *path* exists, creating parent directories if needed.

    Returns ``True`` on success, ``False`` if the path could not be
    created or is an existing file.
    """
    try:
        os.makedirs(path, exist_ok=True)
        return os.path.isdir(path)
    except OSError:
        return False


def file_checksum(filepath: str) -> str:
    """Return the SHA-256 hex digest of *filepath*.

    Returns an empty string if the file cannot be read.
    """
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, FileNotFoundError):
        return ""


def validate_bin_file(filepath: str) -> bool:
    """Check that *filepath* exists, is a regular file, and is non-empty.

    This is a basic sanity check suitable for shellcode ``.bin`` files.
    """
    if not os.path.isfile(filepath):
        return False
    try:
        return os.path.getsize(filepath) > 0
    except OSError:
        return False
