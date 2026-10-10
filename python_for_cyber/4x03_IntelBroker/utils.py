#!/usr/bin/env python3
"""Provide JSON cache, report export, and display helpers."""

import json
import time
from typing import Optional

from models import TargetDossier


CACHE_FILE = "cache.json"
CACHE_TTL = 3600


def load_cache() -> dict:
    """Read the JSON cache, returning {} if it is missing or invalid."""
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as cache_file:
            cache = json.load(cache_file)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as error:
        print(f"[WARNING] Cannot read cache: {error}")
        return {}

    if not isinstance(cache, dict):
        print("[WARNING] Cache format is invalid.")
        return {}

    return cache


def save_cache(cache: dict) -> bool:
    """Save API responses to the JSON cache file."""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as cache_file:
            json.dump(cache, cache_file, indent=2)
            cache_file.write("\n")
    except (OSError, TypeError, ValueError) as error:
        print(f"[WARNING] Cannot save cache: {error}")
        return False

    return True


def get_cached_data(cache: dict, ip: str, service: str) -> Optional[dict]:
    """Return a cached API response if it is less than one hour old."""
    ip_cache = cache.get(ip)
    if not isinstance(ip_cache, dict):
        return None

    entry = ip_cache.get(service)
    if not isinstance(entry, dict):
        return None

    timestamp = entry.get("timestamp")
    data = entry.get("data")
    if isinstance(timestamp, bool):
        return None
    if not isinstance(timestamp, (int, float)):
        return None

    if not isinstance(data, dict) or not data:
        return None
    if data.get("error") == "Unavailable":
        return None

    age = time.time() - timestamp
    if 0 <= age < CACHE_TTL:
        return data

    return None


def save_report(dossier: TargetDossier, output: str) -> bool:
    """Write the complete target dossier to a JSON report file."""
    try:
        with open(output, "w", encoding="utf-8") as report_file:
            json.dump(
                dossier.to_report(),
                report_file,
                indent=2,
                ensure_ascii=False
            )
            report_file.write("\n")
    except (OSError, TypeError, ValueError) as error:
        print(f"[ERROR] Cannot save report: {error}")
        return False

    print(f"[OK] JSON report saved: {output}")
    return True


def format_intelligence(data: dict) -> str:
    """Display unavailable API sources without exposing error details."""
    if data.get("error") == "Unavailable":
        return "Unavailable"
    return str(data)
