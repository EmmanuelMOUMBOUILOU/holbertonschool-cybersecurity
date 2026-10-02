#!/usr/bin/env python3
"""Utility functions for the BreachCheck security tool."""

import hashlib
import logging
import re


def clean_data(lines: list) -> list:
    """Clean raw input lines and return valid data entries."""
    clean_lines = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        clean_lines.append(line)

    return clean_lines


def validate_line(line: str) -> bool:
    """Return True if line follows a valid email:password format."""
    logging.debug("Starting regex check on line: %s", line)
    pattern = r"^[^@\s:]+@[^@\s:]+\.[^@\s:]+:[^:\s]+$"
    return re.fullmatch(pattern, line) is not None


def hash_password(password: str, salt: str) -> str:
    """Return the SHA-256 hash of a password combined with a salt."""
    salted_password = (password + salt).encode("utf-8")
    return hashlib.sha256(salted_password).hexdigest()